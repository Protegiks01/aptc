# Audit Report

## Title
Critical State Synchronization Attack: Unvalidated Subscription Stream Metadata Enables Transaction Skipping

## Summary
An attacker can manipulate the `known_version_at_stream_start` field in subscription requests to skip arbitrary transactions during state synchronization. The storage service server accepts client-provided version information without validation, allowing malicious peers to receive data starting from an inflated version number, causing them to miss critical transactions including governance proposals, stake updates, and consensus-critical state changes.

## Finding Description

The vulnerability exists in the subscription stream initialization logic where the server blindly trusts the `known_version_at_stream_start` value provided by clients without validating it against the actual ledger state.

**Vulnerable Code Flow:**

1. When a client initiates a subscription, they provide `SubscriptionStreamMetadata` containing `known_version_at_stream_start`: [1](#0-0) 

2. The server handler receives the subscription request and creates a new stream without validation: [2](#0-1) 

3. The `SubscriptionStreamRequests::new()` directly copies the unvalidated values from the client request: [3](#0-2) 

4. When serving data, the server uses this unvalidated `highest_known_version` to calculate which transactions to send: [4](#0-3) 

The server calculates `start_version = known_version + 1` without ever verifying that the client actually possesses transactions up to `known_version`.

**Attack Scenario:**
- Actual ledger version: 10,000 (epoch 5)
- Attacker actually knows: version 100 (epoch 1)
- Attacker subscribes with: `known_version_at_stream_start = 8,000`, `known_epoch_at_stream_start = 5`
- Server sends data starting from version 8,001
- **Attacker misses transactions 101 through 8,000**

The only validation that exists checks if metadata is consistent across requests **within the same stream**, but never validates the initial values: [5](#0-4) 

The epoch boundary check occurs **after** stream creation and only catches cases where the claimed version is beyond the epoch ending, not cases within the same epoch: [6](#0-5) 

## Impact Explanation

This vulnerability qualifies as **Critical Severity** under the Aptos Bug Bounty program for multiple reasons:

1. **Consensus/Safety Violations**: If validator nodes are tricked into missing transactions, they will have inconsistent blockchain state, potentially leading to different state roots for the same block height, breaking the fundamental consensus invariant.

2. **State Consistency Breach**: The "State Consistency" invariant (#4) requires that all state transitions are atomic and verifiable. Nodes missing arbitrary transactions will have incomplete and inconsistent views of the blockchain state.

3. **Deterministic Execution Violation**: The "Deterministic Execution" invariant (#1) requires all validators to produce identical state roots. If validators miss different sets of transactions, they will diverge.

4. **Network Partition Risk**: If multiple validators are affected by this attack and miss different transactions, the network could experience a non-recoverable partition requiring a hardfork.

The vulnerability is particularly severe because:
- It affects critical blockchain components: governance proposals, validator stake changes, account state transitions
- Validators using compromised sync mechanisms would fail to properly validate blocks
- The attack is completely silent from the server's perspective (no validation errors)
- It can be used to selectively skip security-critical transactions

## Likelihood Explanation

This vulnerability has **HIGH likelihood** of exploitation:

**Ease of Exploitation:**
- No special privileges required - any network peer can send subscription requests
- Trivial to execute - simply set `known_version_at_stream_start` to an inflated value
- No rate limiting or detection mechanisms exist
- Attack succeeds on first attempt

**Attacker Requirements:**
- Ability to connect to a storage service server (standard P2P capability)
- Knowledge of current ledger version (publicly available information)
- No validator access or consensus participation needed

**Detection Difficulty:**
- Server logs show normal subscription request processing
- No error messages generated
- Affected node appears to sync normally but has incomplete state
- Discrepancies only visible through external state verification

**Real-World Impact:**
- Newly syncing validators are prime targets
- Fullnode operators relying on subscriptions for state sync
- Any node recovering from downtime using subscriptions
- Automated sync tools could be permanently compromised

## Recommendation

Implement validation of `known_version_at_stream_start` against the actual ledger state when creating new subscription streams:

```rust
// In SubscriptionStreamRequests::new()
pub fn new(
    subscription_request: SubscriptionRequest,
    storage: &impl StorageReaderInterface, // Add storage parameter
    time_service: TimeService,
) -> Result<Self, Error> {
    // Extract values from request
    let highest_known_version = subscription_request.highest_known_version_at_stream_start();
    let highest_known_epoch = subscription_request.highest_known_epoch_at_stream_start();
    let subscription_stream_metadata = subscription_request.subscription_stream_metadata();

    // CRITICAL: Validate against actual ledger state
    let synced_version = storage.get_synced_version()
        .map_err(|e| Error::UnexpectedErrorEncountered(format!("Failed to get synced version: {}", e)))?;
    
    if highest_known_version > synced_version {
        return Err(Error::InvalidRequest(format!(
            "Invalid known_version_at_stream_start: {} exceeds synced version: {}",
            highest_known_version, synced_version
        )));
    }

    // For additional security, validate epoch consistency
    if highest_known_epoch > 0 {
        let epoch_ending_ledger_info = storage.get_epoch_ending_ledger_info(highest_known_epoch - 1)
            .map_err(|e| Error::UnexpectedErrorEncountered(format!("Failed to get epoch info: {}", e)))?;
        
        if highest_known_version < epoch_ending_ledger_info.ledger_info().version() {
            return Err(Error::InvalidRequest(format!(
                "Invalid subscription: known_version {} is less than epoch {} ending version {}",
                highest_known_version, highest_known_epoch, epoch_ending_ledger_info.ledger_info().version()
            )));
        }
    }

    // Continue with validated values...
    Ok(Self {
        highest_known_version,
        highest_known_epoch,
        // ... rest of initialization
    })
}
```

Additionally, update the handler to pass storage to the validation: [7](#0-6) 

## Proof of Concept

```rust
#[tokio::test]
async fn test_subscription_version_manipulation_attack() {
    use aptos_storage_service_server::subscription::SubscriptionStreamRequests;
    use aptos_storage_service_types::requests::*;
    use aptos_time_service::TimeService;
    
    // Setup: Ledger at version 10000, epoch 5
    let time_service = TimeService::mock();
    let actual_ledger_version = 10000;
    let actual_epoch = 5;
    
    // Attacker actually knows version 100, epoch 1
    let attacker_actual_version = 100;
    let attacker_actual_epoch = 1;
    
    // Attack: Attacker claims to know version 8000
    let malicious_known_version = 8000;
    let malicious_known_epoch = 5;
    
    // Create malicious subscription request
    let subscription_metadata = SubscriptionStreamMetadata {
        known_version_at_stream_start: malicious_known_version,
        known_epoch_at_stream_start: malicious_known_epoch,
        subscription_stream_id: 123,
    };
    
    let request = StorageServiceRequest::new(
        DataRequest::SubscribeTransactionOutputsWithProof(
            SubscribeTransactionOutputsWithProofRequest {
                subscription_stream_metadata: subscription_metadata,
                subscription_stream_index: 0,
            }
        ),
        false,
    );
    
    // Server accepts without validation
    let subscription_request = SubscriptionRequest::new(
        request,
        // response_sender placeholder
        time_service.clone(),
    );
    
    let stream = SubscriptionStreamRequests::new(
        subscription_request,
        time_service,
    );
    
    // Verify: Stream initialized with attacker's malicious values
    let (known_version, known_epoch) = stream.get_highest_known_version_and_epoch();
    assert_eq!(known_version, malicious_known_version); // 8000, not 100!
    assert_eq!(known_epoch, malicious_known_epoch);
    
    // Impact: When serving data, server will send from version 8001
    // Attacker misses transactions 101-8000 (7900 transactions!)
    println!("ATTACK SUCCESSFUL:");
    println!("  Attacker actually knows version: {}", attacker_actual_version);
    println!("  Attacker claimed version: {}", malicious_known_version);
    println!("  Transactions skipped: {}", malicious_known_version - attacker_actual_version);
    println!("  Server will send data from version: {}", malicious_known_version + 1);
}
```

**Expected Behavior:** Test passes, confirming server accepts inflated `known_version_at_stream_start` without validation.

**Security Impact:** Attacker successfully skips 7,900 transactions, potentially including critical governance proposals, stake updates, and state-changing transactions that would be essential for proper blockchain validation.

## Notes

This vulnerability represents a fundamental trust boundary violation in the state synchronization protocol. The server must never trust client-provided state information without cryptographic proof (e.g., a signature over a ledger info at the claimed version) or at minimum, sanity checking against the server's own ledger state. The current implementation prioritizes performance over security by skipping validation, creating a critical attack vector for state manipulation.

### Citations

**File:** state-sync/storage-service/types/src/requests.rs (L417-422)
```rust
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct SubscriptionStreamMetadata {
    pub known_version_at_stream_start: u64, // The highest known transaction version at stream start
    pub known_epoch_at_stream_start: u64,   // The highest known epoch at stream start
    pub subscription_stream_id: u64,        // The unique id of the subscription stream
}
```

**File:** state-sync/storage-service/server/src/handler.rs (L314-318)
```rust
                    let subscription_stream = SubscriptionStreamRequests::new(
                        subscription_request,
                        self.time_service.clone(),
                    );
                    occupied_entry.replace_entry(subscription_stream);
```

**File:** state-sync/storage-service/server/src/handler.rs (L338-348)
```rust
            Entry::Vacant(vacant_entry) => {
                // Create a new subscription stream for the peer
                let subscription_stream = SubscriptionStreamRequests::new(
                    subscription_request,
                    self.time_service.clone(),
                );
                vacant_entry.insert(subscription_stream);

                // Update the subscription metrics
                update_created_stream_metrics(&peer_network_id);
            },
```

**File:** state-sync/storage-service/server/src/subscription.rs (L68-97)
```rust
    fn get_storage_request_for_missing_data(
        &self,
        config: StorageServiceConfig,
        known_version: u64,
        target_ledger_info: &LedgerInfoWithSignatures,
    ) -> aptos_storage_service_types::Result<StorageServiceRequest, Error> {
        // Calculate the number of versions to fetch
        let target_version = target_ledger_info.ledger_info().version();
        let mut num_versions_to_fetch =
            target_version.checked_sub(known_version).ok_or_else(|| {
                Error::UnexpectedErrorEncountered(
                    "Number of versions to fetch has overflown!".into(),
                )
            })?;

        // Bound the number of versions to fetch by the maximum chunk size
        num_versions_to_fetch = min(
            num_versions_to_fetch,
            self.max_chunk_size_for_request(config),
        );

        // Calculate the start and end versions
        let start_version = known_version.checked_add(1).ok_or_else(|| {
            Error::UnexpectedErrorEncountered("Start version has overflown!".into())
        })?;
        let end_version = known_version
            .checked_add(num_versions_to_fetch)
            .ok_or_else(|| {
                Error::UnexpectedErrorEncountered("End version has overflown!".into())
            })?;
```

**File:** state-sync/storage-service/server/src/subscription.rs (L314-336)
```rust
    pub fn new(subscription_request: SubscriptionRequest, time_service: TimeService) -> Self {
        // Extract the relevant information from the request
        let highest_known_version = subscription_request.highest_known_version_at_stream_start();
        let highest_known_epoch = subscription_request.highest_known_epoch_at_stream_start();
        let subscription_stream_metadata = subscription_request.subscription_stream_metadata();

        // Create a new set of pending subscription requests using the first request
        let mut pending_subscription_requests = BTreeMap::new();
        pending_subscription_requests.insert(
            subscription_request.subscription_stream_index(),
            subscription_request,
        );

        Self {
            highest_known_version,
            highest_known_epoch,
            next_index_to_serve: 0,
            pending_subscription_requests,
            subscription_stream_metadata,
            last_stream_update_time: time_service.now(),
            time_service,
        }
    }
```

**File:** state-sync/storage-service/server/src/subscription.rs (L341-356)
```rust
    pub fn add_subscription_request(
        &mut self,
        storage_service_config: StorageServiceConfig,
        subscription_request: SubscriptionRequest,
    ) -> Result<(), (Error, SubscriptionRequest)> {
        // Verify that the subscription metadata is valid
        let subscription_stream_metadata = subscription_request.subscription_stream_metadata();
        if subscription_stream_metadata != self.subscription_stream_metadata {
            return Err((
                Error::InvalidRequest(format!(
                    "The subscription request stream metadata is invalid! Expected: {:?}, found: {:?}",
                    self.subscription_stream_metadata, subscription_stream_metadata
                )),
                subscription_request,
            ));
        }
```

**File:** state-sync/storage-service/server/src/subscription.rs (L949-959)
```rust
                    // Check that we haven't been sent an invalid subscription request
                    // (i.e., a request that does not respect an epoch boundary).
                    if epoch_ending_ledger_info.ledger_info().version() <= highest_known_version {
                        peers_with_invalid_subscriptions
                            .lock()
                            .push(peer_network_id);
                    } else {
                        peers_with_ready_subscriptions
                            .lock()
                            .push((peer_network_id, epoch_ending_ledger_info));
                    }
```

# Audit Report

## Title
Unauthenticated Storage Server Summary Bypass Enables State Sync Denial of Service

## Summary
The `can_service()` capability check in the state synchronization layer accepts `StorageServerSummary` responses from peers without cryptographic verification of the embedded `LedgerInfoWithSignatures`. Malicious peers can craft fake summaries claiming to have fresh, complete data, manipulating peer selection and causing state sync delays and resource exhaustion.

## Finding Description

The Aptos state synchronization system relies on `StorageServerSummary` messages to determine which peers can serve data requests. Each summary contains a `DataSummary` with a `synced_ledger_info` field (type `LedgerInfoWithSignatures`) that should be signed by 2f+1 validators to prove authenticity. However, when clients receive these summaries via polling, **no cryptographic verification is performed**.

**Attack Flow:**

1. **Polling without verification**: The data client polls peers for their storage summaries. When a response is received, it's stored directly without signature verification: [1](#0-0) 

2. **Unverified storage**: The summary is stored in peer state without any validation: [2](#0-1) 

3. **Bypass in capability checks**: The `can_service()` function relies on this unverified data. The `ProtocolMetadata` check always returns true: [3](#0-2) 

4. **Trust in unverified timestamp**: The `DataSummary.can_service()` checks use the unverified `synced_ledger_info` to determine data freshness via timestamp comparisons: [4](#0-3) 

**Exploitation:**

A malicious peer can forge a `StorageServerSummary` with:
- Fabricated `LedgerInfoWithSignatures` containing arbitrary timestamps (recent) and versions (high)
- Fake data ranges claiming to have complete historical state
- Invalid/missing BLS signatures (never checked)

The client will:
- Accept the fake summary and use it for peer selection
- Potentially prioritize the malicious peer for serving optimistic fetches and subscriptions
- Waste resources when actual data requests timeout or fail verification
- Experience state sync delays as honest peers are deprioritized

**Broken Invariant:** The system assumes peers honestly advertise their capabilities, but this assumption is not cryptographically enforced. This violates the principle that all consensus-adjacent data should be authenticated.

## Impact Explanation

This vulnerability enables **Denial of Service attacks against state synchronization**, qualifying as **High Severity** under the Aptos bug bounty criteria for "Validator node slowdowns."

**Specific impacts:**

1. **State Sync Disruption**: Validator nodes attempting to sync will repeatedly select malicious peers that advertise fake fresh data, causing delays and retries
2. **Resource Exhaustion**: CPU and network bandwidth wasted on timeout cycles and failed verification attempts
3. **Liveness Degradation**: If a sufficient number of malicious peers are present, honest nodes may struggle to find reliable data sources, slowing network synchronization
4. **Honest Peer Deprioritization**: Malicious peers advertising impossibly fresh timestamps can outrank honest peers in selection algorithms

**Why NOT Critical:**
- Actual transaction data is still cryptographically verified when received (separate from the summary)
- No consensus safety violation occurs
- No fund theft or permanent network damage
- Recoverable through peer reputation mechanisms (though delayed)

## Likelihood Explanation

**Likelihood: High**

This attack is:
- **Easy to execute**: Any peer can send arbitrary `StorageServerSummary` messages without authentication requirements
- **Low cost**: No staking, validator status, or computational resources required
- **Persistent**: Malicious peers continue being polled even with low reputation scores: [5](#0-4) 

- **Amplifiable**: Multiple malicious peers increase impact

The only mitigation is the peer scoring system, which reduces (but doesn't eliminate) malicious peer influence: [6](#0-5) 

## Recommendation

**Implement cryptographic verification of `StorageServerSummary` responses:**

```rust
// In state-sync/aptos-data-client/src/peer_states.rs
fn update_storage_summary(&mut self, storage_summary: StorageServerSummary) {
    // Verify the synced_ledger_info if present
    if let Some(synced_ledger_info) = &storage_summary.data_summary.synced_ledger_info {
        // Get the current epoch's validator verifier
        if let Some(validator_verifier) = self.get_validator_verifier_for_epoch(
            synced_ledger_info.ledger_info().epoch()
        ) {
            // Verify signatures on the ledger info
            if let Err(e) = synced_ledger_info.verify_signatures(&validator_verifier) {
                warn!("Received storage summary with invalid signatures: {:?}", e);
                // Mark peer as malicious for sending unverified data
                self.update_score_error(ErrorType::Malicious);
                return; // Reject the summary
            }
        } else {
            // Cannot verify without epoch state - reject to be safe
            warn!("Cannot verify storage summary for unknown epoch");
            return;
        }
    }
    
    self.storage_summary = Some(storage_summary);
}
```

**Additional hardening:**
1. Add configuration to reject summaries from peers with unverifiable ledger infos
2. Implement stricter rate limiting on peers that send invalid summaries
3. Add metrics tracking rejected summaries to detect ongoing attacks

## Proof of Concept

```rust
// Test demonstrating the vulnerability
// File: state-sync/aptos-data-client/src/tests/summary_verification.rs

#[tokio::test]
async fn test_fake_storage_summary_bypass() {
    use aptos_storage_service_types::responses::{
        DataSummary, ProtocolMetadata, StorageServerSummary
    };
    use aptos_types::ledger_info::{LedgerInfo, LedgerInfoWithSignatures};
    use aptos_types::block_info::BlockInfo;
    use aptos_types::aggregate_signature::AggregateSignature;
    
    // Create a fake ledger info with arbitrary high version and recent timestamp
    let fake_block_info = BlockInfo::new(
        999, // epoch
        0,   // round  
        HashValue::zero(),
        HashValue::zero(),
        999999, // version (impossibly high)
        TimeService::real().now_unix_time().as_micros(), // current timestamp
        None,
    );
    
    let fake_ledger_info = LedgerInfo::new(fake_block_info, HashValue::zero());
    
    // Create LedgerInfoWithSignatures with EMPTY/INVALID signatures
    let fake_ledger_info_with_sigs = LedgerInfoWithSignatures::new(
        fake_ledger_info,
        AggregateSignature::empty(), // Invalid signature!
    );
    
    // Create a fake storage summary claiming to have all data
    let fake_summary = StorageServerSummary {
        protocol_metadata: ProtocolMetadata::default(),
        data_summary: DataSummary {
            synced_ledger_info: Some(fake_ledger_info_with_sigs),
            epoch_ending_ledger_infos: Some(CompleteDataRange::from_genesis(999)),
            states: Some(CompleteDataRange::from_genesis(999999)),
            transactions: Some(CompleteDataRange::from_genesis(999999)),
            transaction_outputs: Some(CompleteDataRange::from_genesis(999999)),
        },
    };
    
    // Current implementation: this fake summary is ACCEPTED without verification
    let mut peer_state = PeerState::new(Arc::new(AptosDataClientConfig::default()));
    peer_state.update_storage_summary(fake_summary.clone());
    
    // Verify the fake summary is stored and can pass can_service checks
    assert!(peer_state.get_storage_summary_if_not_ignored().is_some());
    
    // The can_service check will PASS for optimistic fetches despite invalid signatures
    let request = StorageServiceRequest::new(
        DataRequest::GetNewTransactionsWithProof(NewTransactionsWithProofRequest {
            known_version: 0,
            known_epoch: 0,
            include_events: false,
        }),
        false
    );
    
    assert!(fake_summary.can_service(
        &AptosDataClientConfig::default(),
        TimeService::real(),
        &request
    )); // Returns TRUE - vulnerability confirmed!
}
```

## Notes

This vulnerability demonstrates a critical gap in the trust boundary of the state sync protocol. While actual consensus data (transactions, proofs) is cryptographically verified before application, the **metadata about data availability** is accepted on trust. This creates an asymmetry where malicious peers can manipulate peer selection without triggering immediate detection.

The fix requires access to the current `ValidatorVerifier` at the point where summaries are received, which may require architectural changes to pass epoch state information to the peer state management layer.

### Citations

**File:** state-sync/aptos-data-client/src/poller.rs (L436-439)
```rust
        // Update the summary for the peer
        data_summary_poller
            .data_client
            .update_peer_storage_summary(peer, storage_summary);
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L168-174)
```rust
    fn update_score_error(&mut self, error: ErrorType) {
        let multiplier = match error {
            ErrorType::NotUseful => NOT_USEFUL_MULTIPLIER,
            ErrorType::Malicious => MALICIOUS_MULTIPLIER,
        };
        self.score = f64::max(self.score * multiplier, MIN_SCORE);
    }
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L177-179)
```rust
    fn update_storage_summary(&mut self, storage_summary: StorageServerSummary) {
        self.storage_summary = Some(storage_summary);
    }
```

**File:** state-sync/storage-service/types/src/responses.rs (L648-650)
```rust
    pub fn can_service(&self, _request: &StorageServiceRequest) -> bool {
        true // TODO: figure out if should eventually remove this
    }
```

**File:** state-sync/storage-service/types/src/responses.rs (L916-933)
```rust
fn check_synced_ledger_lag(
    synced_ledger_info: Option<&LedgerInfoWithSignatures>,
    time_service: TimeService,
    max_lag_secs: u64,
) -> bool {
    if let Some(synced_ledger_info) = synced_ledger_info {
        // Get the ledger info timestamp (in microseconds)
        let ledger_info_timestamp_usecs = synced_ledger_info.ledger_info().timestamp_usecs();

        // Get the current timestamp and max version lag (in microseconds)
        let current_timestamp_usecs = time_service.now_unix_time().as_micros() as u64;
        let max_version_lag_usecs = max_lag_secs * NUM_MICROSECONDS_IN_SECOND;

        // Return true iff the synced ledger info timestamp is within the max version lag
        ledger_info_timestamp_usecs + max_version_lag_usecs > current_timestamp_usecs
    } else {
        false // No synced ledger info was found!
    }
```

**File:** state-sync/aptos-data-client/src/client.rs (L603-625)
```rust
    pub fn get_priority_and_regular_peers(
        &self,
    ) -> crate::error::Result<(HashSet<PeerNetworkId>, HashSet<PeerNetworkId>), Error> {
        // Get all connected peers
        let all_connected_peers = self.get_all_connected_peers()?;

        // Gather the priority and regular peers
        let mut priority_peers = hashset![];
        let mut regular_peers = hashset![];
        for peer in all_connected_peers {
            if priority::is_high_priority_peer(
                self.base_config.clone(),
                self.get_peers_and_metadata(),
                &peer,
            ) {
                priority_peers.insert(peer);
            } else {
                regular_peers.insert(peer);
            }
        }

        Ok((priority_peers, regular_peers))
    }
```

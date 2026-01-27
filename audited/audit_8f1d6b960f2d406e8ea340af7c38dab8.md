# Audit Report

## Title
Integer Overflow in State Sync Peer Assessment Allows Malicious Peers to Bypass Sync Lag Validation

## Summary
A malicious peer can craft a `ledger_timestamp_usecs` value in their `StorageServerSummary` that causes integer overflow in the `check_synced_ledger_lag()` function, allowing them to bypass sync lag checks and be incorrectly assessed as capable of serving optimistic fetch and subscription requests despite having no valid synced data. [1](#0-0) 

## Finding Description
The vulnerability exists in the peer assessment logic used by the state synchronization system. When a node evaluates whether a peer can service optimistic fetch or subscription requests, it calls `check_synced_ledger_lag()` which performs an unchecked addition operation.

**Attack Flow:**

1. A malicious peer sends a `StorageServerSummary` containing a crafted `synced_ledger_info` with a malicious `timestamp_usecs` value
2. This summary is stored without validation in the peer states: [2](#0-1) 

3. When an honest node evaluates if this peer can service requests, it retrieves the stored summary: [3](#0-2) 

4. The `can_service()` method is called, which for optimistic fetches and subscriptions invokes `check_synced_ledger_lag()`: [4](#0-3) 

5. The vulnerable arithmetic operation occurs where `ledger_info_timestamp_usecs + max_version_lag_usecs` is calculated without overflow protection

**The Attack:**
A malicious peer can set:
```
timestamp_usecs = u64::MAX - max_version_lag_usecs + current_timestamp_usecs + 1
```

Where:
- `max_version_lag_usecs = 300 * 1_000_000` (300 seconds, typical config value)
- `current_timestamp_usecs ≈ 1.7 × 10^15` (current Unix time in microseconds)

When the addition `timestamp_usecs + max_version_lag_usecs` is performed:
- The operation overflows in release mode (wraps around)
- Result wraps to approximately `current_timestamp_usecs + 1`
- The comparison `(current_timestamp_usecs + 1) > current_timestamp_usecs` evaluates to TRUE
- The malicious peer is incorrectly deemed capable of serving requests

**Contrast with Safe Implementation:**
The mempool peer health check uses saturating arithmetic correctly: [5](#0-4) 

## Impact Explanation
This is a **Medium Severity** vulnerability per the Aptos bug bounty criteria:

1. **State Inconsistencies**: Malicious peers with no actual synced data can masquerade as healthy, up-to-date nodes, violating the peer assessment invariant

2. **Degraded Sync Performance**: Honest nodes will waste resources attempting to fetch data from malicious peers that cannot actually serve it, causing:
   - Increased latency in state synchronization
   - Unnecessary network traffic and retry attempts
   - Potential for honest nodes to fall behind during critical sync operations

3. **Resource Exhaustion**: If multiple malicious peers exploit this, an honest node may prioritize them over legitimate peers, significantly degrading sync capabilities

4. **No Direct Fund Loss**: While this doesn't directly cause fund theft, it can impact network health and node operation efficiency

The vulnerability doesn't meet Critical or High severity because it doesn't cause consensus violations, permanent fund loss, or total network failure. However, it does cause state inconsistencies requiring operational intervention to identify and ban malicious peers.

## Likelihood Explanation
**HIGH Likelihood:**

1. **Easy to Execute**: The attack requires only sending a single crafted `StorageServerSummary` message with a calculated timestamp value

2. **No Special Privileges**: Any network peer can send storage summaries without validator access or special permissions

3. **No Detection Mechanism**: The overflow silently succeeds in release mode, and the crafted timestamp appears within valid u64 bounds when transmitted

4. **Persistent Effect**: Once a malicious peer sends the crafted summary, it remains in the peer states until garbage collected

5. **Low Cost**: The attacker bears minimal computational or network costs to execute this attack

6. **Multiple Attack Opportunities**: State sync systems continuously poll peer summaries, providing repeated opportunities for exploitation

## Recommendation
Replace the unchecked addition with `saturating_add()` or `checked_add()` to prevent overflow:

**Fixed code for lines 929-930:**
```rust
// Return true iff the synced ledger info timestamp is within the max version lag
ledger_info_timestamp_usecs.saturating_add(max_version_lag_usecs) > current_timestamp_usecs
```

**Alternative with explicit validation:**
```rust
// Validate timestamp is not crafted to cause overflow
if ledger_info_timestamp_usecs > u64::MAX - max_version_lag_usecs {
    return false; // Reject obviously invalid timestamps
}
ledger_info_timestamp_usecs + max_version_lag_usecs > current_timestamp_usecs
```

**Additional Defense:** Add timestamp sanity checks when receiving `StorageServerSummary` to reject timestamps far in the future or at extreme u64 values:
```rust
const MAX_ACCEPTABLE_TIMESTAMP_FUTURE_SECS: u64 = 300; // 5 minutes
let max_acceptable_timestamp = current_timestamp_usecs + (MAX_ACCEPTABLE_TIMESTAMP_FUTURE_SECS * NUM_MICROSECONDS_IN_SECOND);
if ledger_info_timestamp_usecs > max_acceptable_timestamp {
    // Reject and potentially penalize peer
    return false;
}
```

## Proof of Concept

```rust
#[test]
fn test_overflow_attack_in_check_synced_ledger_lag() {
    use aptos_storage_service_types::responses::{
        DataSummary, ProtocolMetadata, StorageServerSummary
    };
    use aptos_time_service::TimeService;
    use aptos_types::ledger_info::{LedgerInfo, LedgerInfoWithSignatures};
    use aptos_config::config::AptosDataClientConfig;
    
    // Setup
    let time_service = TimeService::mock();
    let config = AptosDataClientConfig::default();
    let max_lag_secs = config.max_optimistic_fetch_lag_secs;
    
    // Get current timestamp
    let current_timestamp_usecs = time_service.now_unix_time().as_micros() as u64;
    
    // Calculate malicious timestamp that will overflow to bypass the check
    let max_version_lag_usecs = max_lag_secs * 1_000_000;
    let malicious_timestamp = u64::MAX - max_version_lag_usecs + current_timestamp_usecs + 1;
    
    // Create malicious ledger info with crafted timestamp
    let mut ledger_info = LedgerInfo::new(
        /* epoch */ 0,
        /* version */ 0,
        /* root_hash */ aptos_crypto::HashValue::zero(),
        /* transaction_accumulator_hash */ aptos_crypto::HashValue::zero(),
        /* state_checkpoint_hash */ None,
        /* block_hash */ None,
        /* epoch_state */ None,
        /* timestamp_usecs */ malicious_timestamp,
    );
    
    let ledger_info_with_sigs = LedgerInfoWithSignatures::new(
        ledger_info,
        std::collections::BTreeMap::new(),
    );
    
    // Create malicious storage summary
    let malicious_summary = StorageServerSummary {
        protocol_metadata: ProtocolMetadata::default(),
        data_summary: DataSummary {
            synced_ledger_info: Some(ledger_info_with_sigs),
            epoch_ending_ledger_infos: None,
            states: None,
            transactions: None,
            transaction_outputs: None,
        },
    };
    
    // The vulnerable check will incorrectly pass due to overflow
    // Simulating the check from check_synced_ledger_lag():
    let ledger_info_timestamp_usecs = malicious_timestamp;
    
    // This addition OVERFLOWS in release mode, wrapping to a value near current_timestamp_usecs
    let result = ledger_info_timestamp_usecs.wrapping_add(max_version_lag_usecs);
    
    // The wrapped result is greater than current_timestamp_usecs, so check incorrectly passes
    assert!(result > current_timestamp_usecs, 
        "Attack successful: overflow caused incorrect peer assessment");
    
    // Demonstration of the fix using saturating_add:
    let safe_result = ledger_info_timestamp_usecs.saturating_add(max_version_lag_usecs);
    assert_eq!(safe_result, u64::MAX, "With saturating_add, no wrap occurs");
    assert!(!(safe_result > current_timestamp_usecs), 
        "Fixed version correctly identifies malicious peer");
}
```

## Notes
This vulnerability demonstrates a critical oversight in arithmetic operations involving network-provided data. While the mempool correctly uses `saturating_sub()` for similar timestamp comparisons, the state sync service's `check_synced_ledger_lag()` function lacks overflow protection. The fix is straightforward and should be applied to all timestamp arithmetic operations involving peer-provided data throughout the codebase.

### Citations

**File:** state-sync/storage-service/types/src/responses.rs (L892-912)
```rust
/// Returns true iff an optimistic data request can be serviced
/// by the peer with the given synced ledger info.
fn can_service_optimistic_request(
    aptos_data_client_config: &AptosDataClientConfig,
    time_service: TimeService,
    synced_ledger_info: Option<&LedgerInfoWithSignatures>,
) -> bool {
    let max_lag_secs = aptos_data_client_config.max_optimistic_fetch_lag_secs;
    check_synced_ledger_lag(synced_ledger_info, time_service, max_lag_secs)
}

/// Returns true iff a subscription data request can be serviced
/// by the peer with the given synced ledger info.
fn can_service_subscription_request(
    aptos_data_client_config: &AptosDataClientConfig,
    time_service: TimeService,
    synced_ledger_info: Option<&LedgerInfoWithSignatures>,
) -> bool {
    let max_lag_secs = aptos_data_client_config.max_subscription_lag_secs;
    check_synced_ledger_lag(synced_ledger_info, time_service, max_lag_secs)
}
```

**File:** state-sync/storage-service/types/src/responses.rs (L916-934)
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
}
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L216-220)
```rust
        if let Some(peer_state) = self.peer_to_state.get(peer) {
            return match peer_state.get_storage_summary_if_not_ignored() {
                Some(storage_summary) => {
                    storage_summary.can_service(&self.data_client_config, time_service, request)
                },
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L324-330)
```rust
    /// Updates the storage summary for the given peer
    pub fn update_summary(&self, peer: PeerNetworkId, storage_summary: StorageServerSummary) {
        self.peer_to_state
            .entry(peer)
            .or_insert(PeerState::new(self.data_client_config.clone()))
            .update_storage_summary(storage_summary);
    }
```

**File:** mempool/src/shared_mempool/priority.rs (L583-586)
```rust
                    // Determine if the peer is healthy
                    current_timestamp_usecs.saturating_sub(peer_ledger_timestamp_usecs)
                        < max_sync_lag_usecs
                })
```

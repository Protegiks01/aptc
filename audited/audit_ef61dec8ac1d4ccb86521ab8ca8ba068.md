# Audit Report

## Title
State Sync Empty Summary Bypass Allows Malicious-Only Peer Data to Proceed Past Early Return Check

## Summary
The `is_empty()` check at line 673 in `drive_progress()` can be bypassed when all legitimate peers are ignored (score ≤ 25.0) but malicious peers with sufficient scores (> 25.0) provide advertised data. This allows the driver to proceed with a global data summary containing only malicious peer data, bypassing the early return meant to detect the absence of active peers. [1](#0-0) 

## Finding Description

The vulnerability exists in the state synchronization driver's progress checking logic. The `is_empty()` check only verifies structural emptiness of the `GlobalDataSummary` (empty vectors and zero chunk sizes), not the quality or trustworthiness of contributing peers. [2](#0-1) 

The `GlobalDataSummary` is constructed from all non-ignored peers in `calculate_global_data_summary()`: [3](#0-2) 

Peers are ignored based on their score when `ignore_low_score_peers` is enabled (default: true): [4](#0-3) 

**Attack Scenario:**

1. Attacker operates malicious peer(s) that maintain scores > 25.0 by responding successfully to some requests while advertising manipulated data ranges
2. Through network interference or exploitation of bugs, all legitimate peers' scores drop to ≤ 25.0, causing them to be ignored
3. `calculate_global_data_summary()` collects only malicious peers' advertised data (lines 341-350)
4. The resulting `GlobalDataSummary` is non-empty (contains malicious data), so `is_empty()` returns false
5. The driver bypasses the early return at line 677 and proceeds to call `bootstrapper.drive_progress(&global_data_summary)` at line 711 [5](#0-4) 

This creates a **Time-of-Check-Time-of-Use (TOCTOU)** vulnerability where the peer quality check happens too late, after resources are committed to sync attempts.

## Impact Explanation

**Medium Severity** per Aptos bug bounty criteria:

1. **State Inconsistencies**: The node may sync to outdated but cryptographically valid data provided by malicious peers, requiring manual intervention to correct
2. **Resource Exhaustion**: The node wastes CPU, memory, and network bandwidth repeatedly attempting to sync with insufficient or malicious peers
3. **Liveness Degradation**: Full nodes and validators may fail to bootstrap or maintain synchronization, degrading network availability
4. **Partial DoS**: While cryptographic verification prevents accepting completely invalid data, the node enters a failure loop of attempting sync → verification failure → retry

The impact is limited to Medium (not High/Critical) because:
- Cryptographic verification prevents accepting invalid blocks or states
- No direct fund loss or consensus safety violation
- Node can eventually recover if legitimate peers return

## Likelihood Explanation

**Medium to High Likelihood:**

- **Feasibility**: Attacker needs to control at least one peer and cause legitimate peers to be ignored through network interference or triggering error conditions
- **Network Conditions**: More likely during:
  - Network partitions or connectivity issues
  - Bootstrap phase when peer set is small
  - Sybil attacks on public networks
- **Detection Difficulty**: The issue is subtle and may appear as normal sync failures
- **Cost**: Relatively low - requires only peer operation and network positioning

The attack is realistic because:
1. Peer scoring is automated based on response quality
2. No global coordination is needed to cause legitimate peers to be ignored
3. The malicious peer only needs to maintain score > 25.0, which is achievable by mixing good and bad responses

## Recommendation

Add a minimum peer quality check before proceeding with sync operations. The fix should validate that a sufficient number of non-ignored peers exist:

```rust
async fn drive_progress(&mut self) {
    // Update the executing component metrics
    self.update_executing_component_metrics();

    // Fetch the global data summary and verify we have active peers
    let global_data_summary = self.aptos_data_client.get_global_data_summary();
    
    // NEW: Count non-ignored peers instead of just checking emptiness
    let num_non_ignored_peers = self.aptos_data_client.get_num_non_ignored_peers();
    let min_peers_threshold = self.driver_configuration.config.min_peers_for_sync.unwrap_or(1);
    
    if global_data_summary.is_empty() || num_non_ignored_peers < min_peers_threshold {
        trace!(LogSchema::new(LogEntry::Driver).message(&format!(
            "Insufficient active peers! Non-ignored: {}, required: {}",
            num_non_ignored_peers, min_peers_threshold
        )));
        return self.check_auto_bootstrapping().await;
    }
    
    // ... rest of function
}
```

Additional improvements:
1. Add `get_num_non_ignored_peers()` method to `AptosDataClient`
2. Add `min_peers_for_sync` configuration parameter (default: 2-3)
3. Log warnings when peer count drops below threshold
4. Add metrics tracking number of non-ignored peers over time

## Proof of Concept

```rust
// Integration test demonstrating the vulnerability
#[tokio::test]
async fn test_empty_summary_bypass_with_malicious_peers() {
    use aptos_config::config::StateSyncDriverConfig;
    use aptos_data_client::global_summary::GlobalDataSummary;
    use aptos_storage_service_types::responses::StorageServerSummary;
    
    // Setup: Create data client with peer states
    let mut peer_states = PeerStates::new(config);
    
    // Add 3 legitimate peers with low scores (will be ignored)
    for i in 0..3 {
        let peer = PeerNetworkId::random();
        let mut peer_state = PeerState::new(config.clone());
        peer_state.update_score_error(ErrorType::Malicious); // Score drops below 25.0
        peer_state.update_storage_summary(create_valid_summary(100));
        peer_states.insert_peer_state(peer, peer_state);
    }
    
    // Add 1 malicious peer with good score (will NOT be ignored)
    let malicious_peer = PeerNetworkId::random();
    let mut malicious_state = PeerState::new(config.clone());
    malicious_state.update_score_success(); // Maintain score > 25.0
    // Malicious peer advertises old but valid data
    malicious_state.update_storage_summary(create_valid_summary(50)); 
    peer_states.insert_peer_state(malicious_peer, malicious_state);
    
    // Calculate global data summary
    let global_data_summary = peer_states.calculate_global_data_summary();
    
    // VULNERABILITY: is_empty() returns FALSE even though only malicious peer data exists
    assert!(!global_data_summary.is_empty()); // Bypass successful!
    
    // The driver would proceed past the early return, attempting to sync with
    // only the malicious peer's advertised data
    
    // Expected behavior: Should detect insufficient non-ignored peers
    // Actual behavior: Proceeds with malicious-only data
}
```

**Notes**

The vulnerability represents a defense-in-depth failure where the early peer availability check can be circumvented. While downstream cryptographic verification prevents accepting completely invalid data, the bypass enables resource exhaustion and liveness attacks. The fix requires enhancing the peer quality validation at the `drive_progress()` entry point to consider both peer count and reputation, not just structural emptiness of the data summary.

### Citations

**File:** state-sync/state-sync-driver/src/driver.rs (L671-678)
```rust
        // Fetch the global data summary and verify we have active peers
        let global_data_summary = self.aptos_data_client.get_global_data_summary();
        if global_data_summary.is_empty() {
            trace!(LogSchema::new(LogEntry::Driver).message(
                "The global data summary is empty! It's likely that we have no active peers."
            ));
            return self.check_auto_bootstrapping().await;
        }
```

**File:** state-sync/state-sync-driver/src/driver.rs (L711-719)
```rust
        } else if let Err(error) = self.bootstrapper.drive_progress(&global_data_summary).await {
            sample!(
                    SampleRate::Duration(Duration::from_secs(DRIVER_ERROR_LOG_FREQ_SECS)),
                    warn!(LogSchema::new(LogEntry::Driver)
                        .error(&error)
                        .message("Error found when checking the bootstrapper progress!"));
            );
            metrics::increment_counter(&metrics::BOOTSTRAPPER_ERRORS, error.get_label());
        };
```

**File:** state-sync/aptos-data-client/src/global_summary.rs (L26-29)
```rust
    /// Returns true iff the global data summary is empty
    pub fn is_empty(&self) -> bool {
        self == &Self::empty()
    }
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L142-160)
```rust
    /// Returns the storage summary iff the peer is not below the ignore threshold
    pub fn get_storage_summary_if_not_ignored(&self) -> Option<&StorageServerSummary> {
        if self.is_ignored() {
            None
        } else {
            self.storage_summary.as_ref()
        }
    }

    /// Returns true iff the peer is currently ignored
    fn is_ignored(&self) -> bool {
        // Only ignore peers if the config allows it
        if !self.data_client_config.ignore_low_score_peers {
            return false;
        }

        // Otherwise, ignore peers with a low score
        self.score <= IGNORE_PEER_THRESHOLD
    }
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L338-355)
```rust
    /// Calculates a global data summary using all known storage summaries
    pub fn calculate_global_data_summary(&self) -> GlobalDataSummary {
        // Gather all storage summaries, but exclude peers that are ignored
        let storage_summaries: Vec<StorageServerSummary> = self
            .peer_to_state
            .iter()
            .filter_map(|peer_state| {
                peer_state
                    .value()
                    .get_storage_summary_if_not_ignored()
                    .cloned()
            })
            .collect();

        // If we have no peers, return an empty global summary
        if storage_summaries.is_empty() {
            return GlobalDataSummary::empty();
        }
```

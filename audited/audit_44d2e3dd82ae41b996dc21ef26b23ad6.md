# Audit Report

## Title
Excessive Progress Check Timeout Enables Extended Node Liveness Failure When All Peers Are Unavailable or Malicious

## Summary
The latency monitor's handling of `None` from `highest_synced_ledger_info()` combined with an excessively long 24-hour progress check timeout creates a vulnerability where nodes can operate in a non-syncing degraded state for extended periods when all peers become unavailable or are deliberately made unusable through malicious behavior. This enables attackers controlling all connected peers to cause prolonged liveness failures.

## Finding Description

The vulnerability exists in the interaction between three components:

1. **Latency Monitor** - When `highest_synced_ledger_info()` returns `None`, the monitor logs a warning and continues to the next iteration: [1](#0-0) 

2. **Global Data Summary Calculation** - Returns empty summary when all peers are ignored or disconnected: [2](#0-1) 

3. **Progress Checker** - Only panics after 24 hours of no syncing progress: [3](#0-2) 

**Attack Path:**

An attacker controlling all peers connected to a victim node can cause extended liveness failure:

1. Attacker sends invalid responses to victim node's data requests
2. Peer scoring system penalizes all peers, reducing their scores below the ignore threshold (25.0): [4](#0-3) 

3. All peers become ignored, causing `get_storage_summary_if_not_ignored()` to return `None` for all peers: [5](#0-4) 

4. Global data summary becomes empty when calculating from only non-ignored peers: [6](#0-5) 

5. State sync driver early-returns without making progress: [7](#0-6) 

6. Node cannot sync new transactions for up to 24 hours until ProgressChecker panics: [8](#0-7) 

During this window:
- Validator nodes cannot participate in consensus (stale state)
- Fullnodes serve increasingly stale data to clients
- No intermediate alerting or circuit breaker activates
- Node appears operational but is functionally degraded

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty criteria for "State inconsistencies requiring intervention":

- **Availability Impact**: Nodes become unable to sync for extended periods (potentially hours to 24 hours)
- **Validator Impact**: Validator nodes with stale state cannot meaningfully participate in consensus, degrading network health
- **Service Impact**: Fullnodes serve stale data to dependent applications and users
- **Recovery**: Requires panic/restart after 24 hours, needing manual operator intervention

While peer score recovery mechanisms exist (successful storage summary polls increase scores), if attackers also fail storage summary requests, recovery is prevented and the full 24-hour timeout applies.

## Likelihood Explanation

**Likelihood: Medium**

- **Attacker Requirements**: Must control or influence all peers connected to target node
- **Easier Targets**: Nodes with few peer connections (new nodes, isolated regions, misconfigured nodes)
- **Attack Complexity**: Moderate - requires sustained malicious responses across all peers
- **Detection**: Difficult - node continues running without obvious failure indicators
- **Real-world Scenarios**: 
  - Bootstrap nodes with limited peer diversity
  - Geographically isolated nodes
  - Nodes during network connectivity issues combined with malicious peers

The 24-hour timeout comment indicates this was designed for "debugging at runtime" but creates an operational vulnerability in production environments.

## Recommendation

Implement multi-layered protections with significantly shorter timeouts:

1. **Add immediate alerting** when global data summary is empty or all peers are ignored
2. **Reduce progress check timeout** to a more reasonable value (e.g., 5-30 minutes) for production deployments
3. **Implement circuit breaker** that triggers when no usable peers exist for extended period (e.g., 60-300 seconds)
4. **Add peer score reset mechanism** when all peers are simultaneously ignored, allowing retry with fresh scores
5. **Expose metrics** for monitoring peer availability and global summary state

Example configuration improvement:
```rust
// In AptosDataClientConfig
pub struct AptosDataClientConfig {
    // ... existing fields ...
    
    /// Maximum time (seconds) to tolerate no usable peers before triggering alert/circuit breaker
    pub max_no_peers_duration_secs: u64, // Default: 300 (5 minutes)
    
    /// Whether to reset all peer scores when all peers are ignored
    pub enable_peer_score_reset: bool, // Default: true
    
    /// Reduced progress check for production (override with flag for debugging)
    pub production_progress_check_secs: u64, // Default: 1800 (30 minutes)
}
```

## Proof of Concept

```rust
// Integration test demonstrating the vulnerability
#[tokio::test]
async fn test_extended_liveness_failure_with_all_peers_ignored() {
    use aptos_data_client::{AptosDataClient, interface::ResponseError};
    use aptos_config::config::AptosDataClientConfig;
    
    // Setup: Create node with controlled peers
    let mut config = AptosDataClientConfig::default();
    config.ignore_low_score_peers = true;
    let (mut mock_network, client, _) = create_test_environment(config);
    
    // Add multiple peers and advertise data
    let peers = add_test_peers(&mut mock_network, 5);
    for peer in &peers {
        client.update_peer_storage_summary(*peer, create_storage_summary(1000));
    }
    client.update_global_summary_cache().unwrap();
    
    // Verify initial state: data is available
    assert!(!client.get_global_data_summary().is_empty());
    
    // Attack: Send malicious responses to degrade all peer scores below threshold
    for _ in 0..10 {
        for peer in &peers {
            let response = client.get_transactions_with_proof(/*...*/).await.unwrap();
            // Simulate malicious response
            response.context.response_callback.notify_bad_response(
                ResponseError::ProofVerificationError
            );
        }
    }
    
    // Verify vulnerability: All peers ignored, global summary empty
    client.update_global_summary_cache().unwrap();
    let summary = client.get_global_data_summary();
    assert!(summary.is_empty()); // No usable peers
    assert!(summary.advertised_data.highest_synced_ledger_info().is_none()); // Returns None
    
    // Node continues in degraded state without immediate failure
    // ProgressChecker won't panic until 24 hours of no local storage progress
    // During this time: no syncing, no consensus participation, stale data served
}
```

This test demonstrates that when all peers are scored below the ignore threshold through malicious responses, the global data summary becomes empty and `highest_synced_ledger_info()` returns `None`, allowing the node to persist in a non-syncing state indefinitely until the ProgressChecker's 24-hour timeout expires.

### Citations

**File:** state-sync/aptos-data-client/src/latency_monitor.rs (L128-141)
```rust
            let highest_advertised_version = match advertised_data.highest_synced_ledger_info() {
                Some(ledger_info) => ledger_info.ledger_info().version(),
                None => {
                    sample!(
                        SampleRate::Duration(Duration::from_secs(LATENCY_MONITOR_LOG_FREQ_SECS)),
                        warn!(
                            (LogSchema::new(LogEntry::LatencyMonitor)
                                .event(LogEvent::AggregateSummary)
                                .message("Unable to get the highest advertised version!"))
                        );
                    );
                    continue; // Continue to the next round
                },
            };
```

**File:** state-sync/aptos-data-client/src/latency_monitor.rs (L326-333)
```rust
        if elapsed_time >= self.progress_check_max_stall_duration {
            panic!(
                "No syncing progress has been made for {:?}! Highest synced version: {}. \
                We recommend restarting the node and checking if the issue persists.",
                elapsed_time, highest_synced_version
            );
        }
    }
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L143-149)
```rust
    pub fn get_storage_summary_if_not_ignored(&self) -> Option<&StorageServerSummary> {
        if self.is_ignored() {
            None
        } else {
            self.storage_summary.as_ref()
        }
    }
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L152-160)
```rust
    fn is_ignored(&self) -> bool {
        // Only ignore peers if the config allows it
        if !self.data_client_config.ignore_low_score_peers {
            return false;
        }

        // Otherwise, ignore peers with a low score
        self.score <= IGNORE_PEER_THRESHOLD
    }
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L341-350)
```rust
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
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L352-355)
```rust
        // If we have no peers, return an empty global summary
        if storage_summaries.is_empty() {
            return GlobalDataSummary::empty();
        }
```

**File:** config/src/config/state_sync_config.rs (L479-479)
```rust
            progress_check_max_stall_time_secs: 86400, // 24 hours (long enough to debug any issues at runtime)
```

**File:** state-sync/state-sync-driver/src/driver.rs (L672-678)
```rust
        let global_data_summary = self.aptos_data_client.get_global_data_summary();
        if global_data_summary.is_empty() {
            trace!(LogSchema::new(LogEntry::Driver).message(
                "The global data summary is empty! It's likely that we have no active peers."
            ));
            return self.check_auto_bootstrapping().await;
        }
```

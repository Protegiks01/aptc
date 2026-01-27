# Audit Report

## Title
Latency Monitor Bypass via Unvalidated Peer Storage Summaries

## Summary
An attacker can prevent the latency monitoring system from ever marking a node as caught up by sending storage summaries with artificially inflated version numbers. The storage service accepts peer-advertised `synced_ledger_info` values without signature validation, allowing a malicious peer to maintain a version gap that keeps `caught_up_to_latest` permanently false.

## Finding Description
The latency monitor relies on comparing the node's local `highest_synced_version` against the `highest_advertised_version` from the global data summary aggregated from peer storage summaries. [1](#0-0) 

The condition to mark the node as caught up is:
```
if highest_synced_version + MAX_VERSION_LAG_TO_TOLERATE >= highest_advertised_version
```

However, the `highest_advertised_version` is derived from peer-provided storage summaries that are accepted without validating the signatures on the `synced_ledger_info` field. [2](#0-1) 

When a peer sends a storage summary, it is directly stored without validation: [3](#0-2) [4](#0-3) 

The global data summary aggregates these unvalidated ledger infos and selects the highest version: [5](#0-4) [6](#0-5) 

**Attack Path:**
1. Malicious peer connects to victim node
2. Attacker sends `GetStorageServerSummary` response with `synced_ledger_info` containing an arbitrarily high version (e.g., victim's current version + MAX_VERSION_LAG_TO_TOLERATE + 1000)
3. This inflated version is included in the global data summary as `highest_advertised_version`
4. The gap between `highest_synced_version` and `highest_advertised_version` remains > MAX_VERSION_LAG_TO_TOLERATE
5. The latency monitor never sets `caught_up_to_latest = true` and returns early without tracking metrics

## Impact Explanation
This vulnerability has **Limited** severity as it impacts monitoring and observability rather than core protocol functionality:

- **No consensus violation**: The node continues to sync correctly and participate in consensus
- **No funds at risk**: No financial impact
- **No availability impact**: Node operation is unaffected
- **Monitoring degradation**: Latency metrics are not collected, reducing visibility into sync performance

While the question suggests "(Medium)" severity, this does not clearly meet the defined bug bounty criteria:
- Not "Limited funds loss or manipulation"
- Not "State inconsistencies requiring intervention" in the operational sense

The impact is primarily operational observability degradation, which may delay detection of legitimate performance issues but does not directly compromise security guarantees.

## Likelihood Explanation
**Likelihood: Medium**

- **Attacker requirements**: Any connected peer can perform this attack
- **No special privileges needed**: No validator or operator access required
- **Detection**: Attack is detectable through monitoring of individual peer advertisements
- **Mitigation in practice**: Presence of multiple honest peers reduces effectiveness, though a single malicious peer with the highest fake version can still cause the issue
- **Continuous maintenance**: Attacker doesn't need to precisely track victim's progress; advertising an extremely high version (e.g., 1 billion) maintains the attack indefinitely

## Recommendation
Implement signature validation for `synced_ledger_info` received in peer storage summaries before including them in the global data summary. Add a method to verify ledger info signatures against the known validator set:

```rust
// In peer_states.rs, update_summary method
pub fn update_summary(&self, peer: PeerNetworkId, storage_summary: StorageServerSummary) {
    // Validate synced_ledger_info signatures if present
    if let Some(synced_ledger_info) = &storage_summary.data_summary.synced_ledger_info {
        if let Err(e) = verify_ledger_info_signatures(synced_ledger_info, &self.validator_verifier) {
            warn!("Invalid ledger info signatures from peer {:?}: {:?}", peer, e);
            // Optionally: update_score_error(peer, ErrorType::Malicious);
            return; // Reject the entire summary
        }
    }
    
    self.peer_to_state
        .entry(peer)
        .or_insert(PeerState::new(self.data_client_config.clone()))
        .update_storage_summary(storage_summary);
}
```

Additionally, implement bounds checking on advertised versions relative to the node's current sync state to detect and ignore obviously inflated values.

## Proof of Concept
```rust
#[tokio::test]
async fn test_latency_monitor_bypass_with_fake_version() {
    // Create a latency monitor and mock data client
    let (time_service, mut latency_monitor) = create_latency_monitor();
    
    // Simulate node at version 100
    let highest_synced_version = 100;
    
    // Malicious peer advertises fake version to maintain gap > MAX_VERSION_LAG_TO_TOLERATE
    let fake_advertised_version = highest_synced_version + MAX_VERSION_LAG_TO_TOLERATE + 100;
    
    // Create fake storage summary with inflated version
    let fake_ledger_info = create_fake_ledger_info(fake_advertised_version);
    let malicious_summary = StorageServerSummary {
        data_summary: DataSummary {
            synced_ledger_info: Some(fake_ledger_info),
            ..Default::default()
        },
        ..Default::default()
    };
    
    // Update with malicious peer's summary
    data_client.update_peer_storage_summary(malicious_peer, malicious_summary);
    data_client.update_global_summary_cache();
    
    // Update latency monitor - it should not mark as caught up
    latency_monitor.update_advertised_version_timestamps(
        highest_synced_version,
        fake_advertised_version,
    );
    
    // Verify that caught_up_to_latest is still false
    assert!(!latency_monitor.caught_up_to_latest);
    
    // Verify that no version timestamps were recorded (early return)
    assert_eq!(latency_monitor.advertised_versions.len(), 0);
}
```

## Notes
While this vulnerability technically allows an attacker to bypass the latency monitoring system, the practical security impact is limited to observability degradation. The core state sync, consensus, and transaction processing functionality remain unaffected. This would be more appropriately classified as a monitoring reliability issue rather than a security vulnerability under the strict criteria of the Aptos bug bounty program.

### Citations

**File:** state-sync/aptos-data-client/src/latency_monitor.rs (L242-264)
```rust
        if !self.caught_up_to_latest {
            if highest_synced_version + MAX_VERSION_LAG_TO_TOLERATE >= highest_advertised_version {
                info!(
                    (LogSchema::new(LogEntry::LatencyMonitor)
                        .event(LogEvent::CaughtUpToLatest)
                        .message(
                            "We've caught up to the latest version! Starting the latency monitor."
                        ))
                );
                self.caught_up_to_latest = true; // We've caught up
            } else {
                sample!(
                    SampleRate::Duration(Duration::from_secs(LATENCY_MONITOR_LOG_FREQ_SECS)),
                    info!(
                        (LogSchema::new(LogEntry::LatencyMonitor)
                            .event(LogEvent::WaitingForCatchup)
                            .message("Waiting for the node to catch up to the latest version before starting the latency monitor."))
                    );
                );

                return; // We're still catching up, so we shouldn't update the advertised version timestamps
            }
        }
```

**File:** state-sync/aptos-data-client/src/poller.rs (L436-439)
```rust
        // Update the summary for the peer
        data_summary_poller
            .data_client
            .update_peer_storage_summary(peer, storage_summary);
```

**File:** state-sync/aptos-data-client/src/client.rs (L213-215)
```rust
    pub fn update_peer_storage_summary(&self, peer: PeerNetworkId, summary: StorageServerSummary) {
        self.peer_states.update_summary(peer, summary)
    }
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

**File:** state-sync/aptos-data-client/src/peer_states.rs (L374-378)
```rust
            if let Some(synced_ledger_info) = summary.data_summary.synced_ledger_info.as_ref() {
                advertised_data
                    .synced_ledger_infos
                    .push(synced_ledger_info.clone());
            }
```

**File:** state-sync/aptos-data-client/src/global_summary.rs (L184-198)
```rust
    pub fn highest_synced_ledger_info(&self) -> Option<LedgerInfoWithSignatures> {
        let highest_synced_position = self
            .synced_ledger_infos
            .iter()
            .map(|ledger_info_with_sigs| ledger_info_with_sigs.ledger_info().version())
            .position_max();

        if let Some(highest_synced_position) = highest_synced_position {
            self.synced_ledger_infos
                .get(highest_synced_position)
                .cloned()
        } else {
            None
        }
    }
```

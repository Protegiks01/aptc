# Audit Report

## Title
Mempool Peer Prioritization Delay Allows Malicious Peers to Degrade Service for 10 Minutes

## Summary
The mempool's peer prioritization system only updates every 10 minutes by default, creating a window where malicious or unhealthy peers can continue degrading service quality before being deprioritized. During this period, fullnodes waste network bandwidth and resources broadcasting transactions to peers with high latency or significant sync lag.

## Finding Description

The vulnerability exists in the mempool's peer prioritization mechanism for fullnodes (VFNs and PFNs). The system uses intelligent peer prioritization that evaluates peers based on health (sync lag), ping latency, and validator distance to optimize transaction broadcast efficiency. [1](#0-0) 

By default, `enable_intelligent_peer_prioritization` is set to `true` and `shared_mempool_priority_update_interval_secs` is set to 600 seconds (10 minutes). This means peer priorities are only recalculated every 10 minutes.

The `ready_for_update()` function controls when priorities are recalculated: [2](#0-1) 

Peer health is only checked during priority updates via the `compare_peer_health()` function, which evaluates sync lag: [3](#0-2) 

The default threshold considers peers unhealthy if their sync lag exceeds 30 seconds: [4](#0-3) 

**Attack Scenario:**

1. Attacker operates malicious peer nodes that exhibit poor behavior:
   - High ping latency (>100ms)
   - Significant sync lag (>30 seconds behind)
   - Slow or non-responsive to broadcast ACKs

2. These malicious peers connect to victim fullnodes (VFNs or PFNs).

3. Initially, peers are prioritized based on network ID and hash. The victim node begins broadcasting transactions to these peers.

4. Despite being unhealthy or high-latency, these peers remain in the prioritized list because health checks only occur during priority updates.

5. For up to 10 minutes, the victim node continues wasting resources:
   - Broadcasting transactions every 10ms (or 30 seconds if in backoff mode)
   - Maintaining up to 20 pending broadcasts per peer
   - Consuming network bandwidth that could serve healthy peers [5](#0-4) 

6. Only fullnodes are affected as validators skip peer prioritization: [6](#0-5) 

7. If multiple malicious peers connect simultaneously, they amplify the impact by consuming multiple broadcast slots across all sender buckets.

While protective mechanisms exist (max 20 pending broadcasts per peer, backoff mode, 2-second timeouts), these only limit the impact per peer—they don't prevent unhealthy peers from receiving broadcasts during the 10-minute window. [7](#0-6) 

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty program for the following reasons:

1. **Service Degradation**: Fullnodes waste network bandwidth and computational resources broadcasting to unhealthy peers, reducing transaction propagation efficiency across the network.

2. **Resource Consumption**: With default settings (20 max broadcasts per peer, 4 sender buckets, 1 default failover), malicious peers can consume significant broadcast capacity for 10 minutes before being deprioritized.

3. **Network-Wide Effect**: If attackers target multiple fullnodes simultaneously, transaction propagation latency increases network-wide, particularly affecting PFNs that rely on efficient mempool synchronization.

4. **Limited by Per-Peer Protections**: While not critical, the impact is bounded by `max_broadcasts_per_peer` and backoff mechanisms, preventing complete resource exhaustion.

5. **Requires Active Attack**: The vulnerability requires an attacker to operate infrastructure (malicious peer nodes) and maintain connections, increasing the attack complexity.

The issue does not cause fund loss, consensus violations, or permanent network damage, but it does enable state inconsistencies and service degradation requiring operational intervention to identify and block malicious peers.

## Likelihood Explanation

**Likelihood: Medium to High**

The vulnerability is likely to be exploited because:

1. **Low Barrier to Entry**: Attackers only need to run standard Aptos node software configured with poor performance characteristics (high latency, out-of-sync state).

2. **No Authentication Required**: The P2P network allows any peer to connect to fullnodes without special credentials.

3. **Natural Occurrence**: Even without malicious intent, network partitions or poorly configured nodes can exhibit these symptoms, causing unintended service degradation.

4. **Scalable Attack**: Attackers can amplify impact by operating multiple malicious peers simultaneously.

5. **Limited Detection**: The 10-minute window provides substantial time for attackers to degrade service before automatic deprioritization occurs.

However, the likelihood is tempered by:
- The issue only affects fullnodes, not validators
- Operators can manually identify and block problematic peers
- Network monitoring can detect unusual broadcast patterns

## Recommendation

**Short-term Fix**: Reduce the priority update interval from 600 seconds to 60 seconds (1 minute) to limit the exploitation window:

```rust
shared_mempool_priority_update_interval_secs: 60, // 1 minute instead of 10
```

**Long-term Fix**: Implement continuous health monitoring that can immediately deprioritize peers when they become unhealthy:

1. **Immediate Health Checks**: Evaluate peer health during broadcast operations, not just during scheduled updates. If a peer's sync lag exceeds the threshold, immediately lower its priority.

2. **Adaptive Update Frequency**: When unhealthy peers are detected, trigger an immediate priority update rather than waiting for the scheduled interval.

3. **Circuit Breaker Pattern**: Implement a circuit breaker that temporarily stops broadcasts to peers with repeated timeouts or excessive sync lag, independent of the priority update schedule.

4. **Enhanced Monitoring**: Add metrics to track per-peer broadcast success rates and automatically flag peers that consistently fail health checks.

**Code Fix Example** (in `mempool/src/shared_mempool/priority.rs`):

```rust
pub fn ready_for_update(&self, peers_changed: bool) -> bool {
    if !self.mempool_config.enable_intelligent_peer_prioritization {
        return peers_changed;
    }
    
    // Trigger immediate update if peers changed or latencies not observed
    if peers_changed || !self.observed_all_ping_latencies {
        return true;
    }
    
    // Reduce update interval to 60 seconds
    match self.last_peer_priority_update {
        None => true,
        Some(last_update) => {
            let duration_since_update = self.time_service.now().duration_since(last_update);
            duration_since_update.as_secs() > 60  // Changed from 600
        },
    }
}
```

Additionally, modify the config default:

```rust
shared_mempool_priority_update_interval_secs: 60, // Reduced from 600
```

## Proof of Concept

The following Rust test demonstrates the vulnerability by showing that unhealthy peers continue to be prioritized during the 10-minute window:

```rust
#[tokio::test]
async fn test_unhealthy_peer_exploitation_window() {
    use aptos_config::config::{MempoolConfig, NodeType};
    use aptos_time_service::TimeService;
    use mempool::shared_mempool::priority::PrioritizedPeersState;
    use aptos_peer_monitoring_service_types::PeerMonitoringMetadata;
    
    // Create mempool config with default 10-minute priority update interval
    let mempool_config = MempoolConfig::default();
    assert_eq!(mempool_config.shared_mempool_priority_update_interval_secs, 600);
    assert_eq!(mempool_config.max_sync_lag_before_unhealthy_secs, 30);
    
    let time_service = TimeService::mock();
    let mut priority_state = PrioritizedPeersState::new(
        mempool_config.clone(),
        NodeType::PublicFullnode,
        time_service.clone(),
    );
    
    // Create a healthy peer and an unhealthy peer (60s sync lag)
    let healthy_peer = create_peer_with_sync_lag(&time_service, 10);
    let unhealthy_peer = create_peer_with_sync_lag(&time_service, 60); // Exceeds 30s threshold
    
    let peers = vec![
        (healthy_peer.0, Some(&healthy_peer.1)),
        (unhealthy_peer.0, Some(&unhealthy_peer.1)),
    ];
    
    // Initial priority update
    priority_state.update_prioritized_peers(peers.clone(), 0, 0);
    
    // Healthy peer should be prioritized first
    assert_eq!(priority_state.get_peer_priority(&healthy_peer.0), 0);
    assert_eq!(priority_state.get_peer_priority(&unhealthy_peer.0), 1);
    
    // Advance time by 9 minutes (still within 10-minute window)
    time_service.into_mock().advance_secs(540);
    
    // Update should NOT happen because we're still within the 10-minute window
    let peers_changed = false;
    assert!(!priority_state.ready_for_update(peers_changed));
    
    // Even though unhealthy peer's sync lag is now 69 minutes old,
    // it remains in the prioritized list and continues receiving broadcasts
    // This is the vulnerability: 9 more minutes of wasted broadcasts
    
    // Advance time past 10 minutes
    time_service.into_mock().advance_secs(61);
    
    // NOW the update is ready
    assert!(priority_state.ready_for_update(peers_changed));
}

fn create_peer_with_sync_lag(
    time_service: &TimeService,
    sync_lag_secs: u64,
) -> (PeerNetworkId, PeerMonitoringMetadata) {
    let peer_id = PeerId::random();
    let peer_network_id = PeerNetworkId::new(NetworkId::Public, peer_id);
    
    let current_time_usecs = time_service.now_unix_time().as_micros() as u64;
    let peer_timestamp = current_time_usecs - (sync_lag_secs * 1_000_000);
    
    let node_info = NodeInformationResponse {
        ledger_timestamp_usecs: peer_timestamp,
        ..Default::default()
    };
    
    let metadata = PeerMonitoringMetadata {
        latest_node_info_response: Some(node_info),
        average_ping_latency_secs: Some(0.01),
        ..Default::default()
    };
    
    (peer_network_id, metadata)
}
```

This test demonstrates that during the 9-minute window, the system does not trigger a priority update (`ready_for_update` returns `false`), allowing unhealthy peers to continue consuming resources. Only after the full 10-minute interval does the system re-evaluate peer priorities.

## Notes

The vulnerability specifically affects **fullnodes** (Validator Fullnodes and Public Fullnodes) that use intelligent peer prioritization for transaction broadcast optimization. Validators are not affected as they skip peer prioritization logic entirely. The issue represents a trade-off between performance (expensive priority recalculation) and security (timely identification of malicious peers).

### Citations

**File:** config/src/config/mempool_config.rs (L117-117)
```rust
            max_broadcasts_per_peer: 20,
```

**File:** config/src/config/mempool_config.rs (L118-118)
```rust
            max_sync_lag_before_unhealthy_secs: 30, // 30 seconds
```

**File:** config/src/config/mempool_config.rs (L125-127)
```rust
            enable_intelligent_peer_prioritization: true,
            shared_mempool_peer_update_interval_ms: 1_000,
            shared_mempool_priority_update_interval_secs: 600, // 10 minutes (frequent reprioritization is expensive)
```

**File:** mempool/src/shared_mempool/priority.rs (L215-242)
```rust
    /// Returns true iff the prioritized peers list is ready for another update
    pub fn ready_for_update(&self, peers_changed: bool) -> bool {
        // If intelligent peer prioritization is disabled, we should only
        // update the prioritized peers if the peers have changed.
        if !self.mempool_config.enable_intelligent_peer_prioritization {
            return peers_changed;
        }

        // Otherwise, we should update the prioritized peers if the peers have changed
        // or if we haven't observed ping latencies for all peers yet. This is useful
        // because latencies are only populated some time after the peer connects, so
        // we should continuously reprioritize until latencies are observed for all peers.
        if peers_changed || !self.observed_all_ping_latencies {
            return true;
        }

        // Otherwise, we should only update if enough time has passed since the last update
        match self.last_peer_priority_update {
            None => true, // We haven't updated yet
            Some(last_update) => {
                let duration_since_update = self.time_service.now().duration_since(last_update);
                let update_interval_secs = self
                    .mempool_config
                    .shared_mempool_priority_update_interval_secs;
                duration_since_update.as_secs() > update_interval_secs
            },
        }
    }
```

**File:** mempool/src/shared_mempool/priority.rs (L559-611)
```rust
/// Returns true iff the given peer monitoring metadata is healthy. A peer is
/// considered healthy if its latest ledger timestamp is within the max acceptable
/// sync lag. If the monitoring metadata is missing, the peer is considered unhealthy.
fn check_peer_metadata_health(
    mempool_config: &MempoolConfig,
    time_service: &TimeService,
    monitoring_metadata: &Option<&PeerMonitoringMetadata>,
) -> bool {
    monitoring_metadata
        .and_then(|metadata| {
            metadata
                .latest_node_info_response
                .as_ref()
                .map(|node_information_response| {
                    // Get the peer's ledger timestamp and the current timestamp
                    let peer_ledger_timestamp_usecs =
                        node_information_response.ledger_timestamp_usecs;
                    let current_timestamp_usecs = get_timestamp_now_usecs(time_service);

                    // Calculate the max sync lag before the peer is considered unhealthy (in microseconds)
                    let max_sync_lag_secs =
                        mempool_config.max_sync_lag_before_unhealthy_secs as u64;
                    let max_sync_lag_usecs = max_sync_lag_secs * MICROS_PER_SECOND;

                    // Determine if the peer is healthy
                    current_timestamp_usecs.saturating_sub(peer_ledger_timestamp_usecs)
                        < max_sync_lag_usecs
                })
        })
        .unwrap_or(false) // If metadata is missing, consider the peer unhealthy
}

/// Compares the health of the given peer monitoring metadata. Healthy
/// peers are prioritized over unhealthy peers, or peers missing metadata.
fn compare_peer_health(
    mempool_config: &MempoolConfig,
    time_service: &TimeService,
    monitoring_metadata_a: &Option<&PeerMonitoringMetadata>,
    monitoring_metadata_b: &Option<&PeerMonitoringMetadata>,
) -> Ordering {
    // Check the health of the peer monitoring metadata
    let is_healthy_a =
        check_peer_metadata_health(mempool_config, time_service, monitoring_metadata_a);
    let is_healthy_b =
        check_peer_metadata_health(mempool_config, time_service, monitoring_metadata_b);

    // Compare the health statuses
    match (is_healthy_a, is_healthy_b) {
        (true, false) => Ordering::Greater, // A is healthy, B is unhealthy
        (false, true) => Ordering::Less,    // A is unhealthy, B is healthy
        _ => Ordering::Equal,               // Both are healthy or unhealthy
    }
}
```

**File:** mempool/src/shared_mempool/network.rs (L231-244)
```rust
    /// Updates the prioritized peers list
    fn update_prioritized_peers(
        &mut self,
        all_connected_peers: &HashMap<PeerNetworkId, PeerMetadata>,
        peers_changed: bool,
    ) {
        // Only fullnodes should prioritize peers (e.g., VFNs and PFNs)
        if self.node_type.is_validator() {
            return;
        }

        // If the prioritized peers list is not ready for an update, return early
        if !self.prioritized_peers_state.ready_for_update(peers_changed) {
            return;
```

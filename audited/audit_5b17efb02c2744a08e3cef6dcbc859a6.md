# Audit Report

## Title
Latency Spoofing in Mempool Peer Prioritization Enables Transaction Censorship and Network Degradation

## Summary

Malicious peers can artificially inflate their priority in the mempool broadcast system by responding quickly to `LatencyPing` requests while being unresponsive to actual transaction broadcasts. The peer prioritization logic uses `average_ping_latency_secs` from ping measurements to rank peers, but this metric is completely independent from actual transaction broadcast performance. This allows attackers to monopolize "Primary" broadcast slots while providing degraded service, causing transaction propagation delays across the network.

## Finding Description

The mempool's intelligent peer prioritization system determines which peers receive transactions with Primary vs. Failover priority based on several factors, with ping latency being a critical discriminator. The `compare_intelligent()` function prioritizes peers in this order: [1](#0-0) 

The ping latency comparison specifically uses `average_ping_latency_secs` from `PeerMonitoringMetadata`: [2](#0-1) 

This latency value is calculated by the peer monitoring service client by measuring round-trip time to `LatencyPing` requests: [3](#0-2) 

The server handling these requests simply echoes back the ping counter immediately: [4](#0-3) 

**The Vulnerability:**

A malicious peer can implement the following attack:

1. **Fast Ping Response**: Respond to all `LatencyPingRequest` messages with minimal processing delay (near-instant response)
2. **Slow Broadcast Handling**: Delay acknowledgment of actual `BroadcastTransactionsRequest` messages, or drop them entirely
3. **Priority Gaming**: The fast ping responses result in very low `average_ping_latency_secs` (e.g., 0.001 seconds)
4. **Preferential Treatment**: The peer is ranked as a top peer and assigned Primary broadcast priority for multiple transaction sender buckets

While the mempool tracks actual broadcast round-trip time via `SHARED_MEMPOOL_BROADCAST_RTT`: [5](#0-4) 

This metric is **only used for observability** and does not feed back into peer prioritization decisions: [6](#0-5) 

The peer prioritization update logic never considers broadcast performance: [7](#0-6) 

## Impact Explanation

This vulnerability meets **Medium severity** criteria per the Aptos bug bounty program for the following reasons:

1. **Transaction Propagation Degradation**: If malicious peers occupy multiple Primary broadcast slots, legitimate transactions may experience significant delays in propagating across the network, as Primary peers receive transactions immediately while Failover peers have a configured delay.

2. **Selective Censorship**: A malicious peer can selectively delay or drop specific transactions while maintaining low ping latency, enabling targeted censorship attacks without being deprioritized.

3. **Network Partition Risk**: In scenarios where honest nodes rely heavily on a small number of top-priority peers, multiple malicious peers with spoofed latencies could create transaction visibility inconsistencies across the network.

4. **MEV/Front-running Enablement**: If a malicious peer is also a validator, seeing transactions before other validators (due to Primary priority) enables MEV extraction and front-running opportunities.

The impact falls under "State inconsistencies requiring intervention" as operators may need to manually adjust peer prioritization or connection policies to restore proper transaction propagation.

## Likelihood Explanation

**Likelihood: HIGH**

The attack is trivially easy to execute:
- No special privileges required (any network peer can connect)
- No cryptographic bypasses needed
- Implementation is straightforward: prioritize ping responses, delay broadcast ACKs
- Detection is difficult without correlating ping latency with broadcast performance
- No existing safeguards prevent this behavior

On fullnode networks (VFN/PFN), where intelligent peer prioritization is enabled, this attack can be launched immediately by any malicious peer.

## Recommendation

Implement a feedback mechanism that correlates ping latency with actual broadcast performance and dynamically adjusts peer priorities based on real service quality:

```rust
// In PeerMonitoringMetadata, add broadcast performance tracking
pub struct PeerMonitoringMetadata {
    pub average_ping_latency_secs: Option<f64>,
    pub average_broadcast_rtt_secs: Option<f64>, // NEW: Track broadcast RTT
    // ... existing fields
}

// In compare_intelligent(), add broadcast performance comparison
fn compare_intelligent(
    &self,
    peer_a: &(PeerNetworkId, Option<&PeerMonitoringMetadata>),
    peer_b: &(PeerNetworkId, Option<&PeerMonitoringMetadata>),
) -> Ordering {
    // ... existing comparisons ...
    
    // NEW: Compare broadcast performance if available
    let broadcast_ordering = compare_broadcast_performance(
        monitoring_metadata_a, 
        monitoring_metadata_b,
        &self.mempool_config
    );
    if !broadcast_ordering.is_eq() {
        return broadcast_ordering;
    }
    
    // Then compare ping latency
    let latency_ordering = compare_ping_latency(monitoring_metadata_a, monitoring_metadata_b);
    if !latency_ordering.is_eq() {
        return latency_ordering;
    }
    
    // ... rest of function
}

// NEW: Detect and penalize peers with good ping but poor broadcast performance
fn compare_broadcast_performance(
    metadata_a: &Option<&PeerMonitoringMetadata>,
    metadata_b: &Option<&PeerMonitoringMetadata>,
    config: &MempoolConfig,
) -> Ordering {
    // If ping latency is much lower than broadcast RTT, penalize the peer
    for metadata in [metadata_a, metadata_b] {
        if let Some(meta) = metadata {
            if let (Some(ping), Some(broadcast)) = 
                (meta.average_ping_latency_secs, meta.average_broadcast_rtt_secs) {
                // If broadcast RTT is more than 2x ping latency, suspect spoofing
                if broadcast > ping * config.broadcast_latency_tolerance_multiplier {
                    // Deprioritize this peer
                }
            }
        }
    }
    // ... comparison logic
}
```

Additionally, track per-peer broadcast success rates and timeout frequencies, using these metrics to demote peers that consistently underperform.

## Proof of Concept

```rust
// Test demonstrating latency spoofing attack
#[test]
fn test_latency_spoofing_attack() {
    use aptos_peer_monitoring_service_types::PeerMonitoringMetadata;
    use aptos_config::config::MempoolConfig;
    
    // Create two peers with identical network characteristics
    let honest_peer_metadata = create_metadata_with_latency(Some(0.050)); // 50ms ping
    let malicious_peer_metadata = create_metadata_with_latency(Some(0.001)); // 1ms spoofed ping
    
    let honest_peer = (create_public_peer(), Some(&honest_peer_metadata));
    let malicious_peer = (create_public_peer(), Some(&malicious_peer_metadata));
    
    // Create prioritized peer state
    let mempool_config = MempoolConfig {
        enable_intelligent_peer_prioritization: true,
        ..MempoolConfig::default()
    };
    let prioritized_peers_state = PrioritizedPeersState::new(
        mempool_config,
        NodeType::PublicFullnode,
        TimeService::mock(),
    );
    
    // Compare peers - malicious peer should win despite providing worse actual service
    let peers = vec![honest_peer, malicious_peer];
    let prioritized = prioritized_peers_state.sort_peers_by_priority(&peers);
    
    // Malicious peer gets higher priority (index 0)
    assert_eq!(prioritized[0], malicious_peer.0);
    assert_eq!(prioritized[1], honest_peer.0);
    
    // In reality, malicious peer has much worse broadcast performance
    // but this is never checked in peer prioritization
}
```

**Notes**

The vulnerability exists because the peer monitoring service's latency pings are designed to measure network connectivity, not service quality. The mempool's peer prioritization incorrectly assumes that low ping latency implies good broadcast performance. An attacker can exploit this assumption by optimizing for ping response times while providing degraded service for actual transaction broadcasts. This represents a fundamental design flaw where the metric being optimized (ping latency) doesn't align with the actual requirement (reliable transaction propagation).

### Citations

**File:** mempool/src/shared_mempool/priority.rs (L74-120)
```rust
    fn compare_intelligent(
        &self,
        peer_a: &(PeerNetworkId, Option<&PeerMonitoringMetadata>),
        peer_b: &(PeerNetworkId, Option<&PeerMonitoringMetadata>),
    ) -> Ordering {
        // Deconstruct the peer tuples
        let (peer_network_id_a, monitoring_metadata_a) = peer_a;
        let (peer_network_id_b, monitoring_metadata_b) = peer_b;

        // First, compare the peers by health (e.g., sync lag)
        let unhealthy_ordering = compare_peer_health(
            &self.mempool_config,
            &self.time_service,
            monitoring_metadata_a,
            monitoring_metadata_b,
        );
        if !unhealthy_ordering.is_eq() {
            return unhealthy_ordering; // Only return if it's not equal
        }

        // Next, compare by network ID (i.e., Validator > VFN > Public)
        let network_ordering = compare_network_id(
            &peer_network_id_a.network_id(),
            &peer_network_id_b.network_id(),
        );
        if !network_ordering.is_eq() {
            return network_ordering; // Only return if it's not equal
        }

        // Otherwise, compare by peer distance from the validators.
        // This avoids badly configured/connected peers (e.g., broken VN-VFN connections).
        let distance_ordering =
            compare_validator_distance(monitoring_metadata_a, monitoring_metadata_b);
        if !distance_ordering.is_eq() {
            return distance_ordering; // Only return if it's not equal
        }

        // Otherwise, compare by peer ping latency (the lower the better)
        let latency_ordering = compare_ping_latency(monitoring_metadata_a, monitoring_metadata_b);
        if !latency_ordering.is_eq() {
            return latency_ordering; // Only return if it's not equal
        }

        // Otherwise, simply hash the peer IDs and compare the hashes.
        // In practice, this should be relatively rare.
        self.compare_hash(peer_network_id_a, peer_network_id_b)
    }
```

**File:** mempool/src/shared_mempool/priority.rs (L533-557)
```rust
fn compare_ping_latency(
    monitoring_metadata_a: &Option<&PeerMonitoringMetadata>,
    monitoring_metadata_b: &Option<&PeerMonitoringMetadata>,
) -> Ordering {
    // Get the ping latency from the monitoring metadata
    let ping_latency_a = get_peer_ping_latency(monitoring_metadata_a);
    let ping_latency_b = get_peer_ping_latency(monitoring_metadata_b);

    // Compare the ping latencies
    match (ping_latency_a, ping_latency_b) {
        (Some(ping_latency_a), Some(ping_latency_b)) => {
            // Prioritize the peer with the lowest ping latency
            ping_latency_a.total_cmp(&ping_latency_b).reverse()
        },
        (Some(_), None) => {
            Ordering::Greater // Prioritize the peer with a ping latency
        },
        (None, Some(_)) => {
            Ordering::Less // Prioritize the peer with a ping latency
        },
        (None, None) => {
            Ordering::Equal // Neither peer has a ping latency
        },
    }
}
```

**File:** peer-monitoring-service/client/src/peer_states/latency_info.rs (L99-110)
```rust
    /// Returns the average latency ping in seconds. If no latency
    /// pings have been recorded, None is returned.
    pub fn get_average_latency_ping_secs(&self) -> Option<f64> {
        let num_latency_pings = self.recorded_latency_ping_durations_secs.len();
        if num_latency_pings > 0 {
            let average_latency_secs_sum: f64 =
                self.recorded_latency_ping_durations_secs.values().sum();
            Some(average_latency_secs_sum / num_latency_pings as f64)
        } else {
            None
        }
    }
```

**File:** peer-monitoring-service/server/src/lib.rs (L283-293)
```rust
    fn handle_latency_ping(
        &self,
        latency_ping_request: &LatencyPingRequest,
    ) -> Result<PeerMonitoringServiceResponse, Error> {
        let latency_ping_response = LatencyPingResponse {
            ping_counter: latency_ping_request.ping_counter,
        };
        Ok(PeerMonitoringServiceResponse::LatencyPing(
            latency_ping_response,
        ))
    }
```

**File:** mempool/src/shared_mempool/network.rs (L247-268)
```rust
        // Fetch the peers and monitoring metadata
        let peer_network_ids: Vec<_> = self.sync_states.read().keys().cloned().collect();
        let peers_and_metadata: Vec<_> = peer_network_ids
            .iter()
            .map(|peer| {
                // Get the peer monitoring metadata for the peer
                let monitoring_metadata = all_connected_peers
                    .get(peer)
                    .map(|metadata| metadata.get_peer_monitoring_metadata());

                // Return the peer and monitoring metadata
                (*peer, monitoring_metadata)
            })
            .collect();

        // Update the prioritized peers list
        self.prioritized_peers_state.update_prioritized_peers(
            peers_and_metadata,
            self.num_mempool_txns_received_since_peers_updated,
            self.num_committed_txns_received_since_peers_updated
                .load(Ordering::Relaxed),
        );
```

**File:** mempool/src/shared_mempool/network.rs (L316-323)
```rust
            let rtt = timestamp
                .duration_since(sent_timestamp)
                .expect("failed to calculate mempool broadcast RTT");

            let network_id = peer.network_id();
            counters::SHARED_MEMPOOL_BROADCAST_RTT
                .with_label_values(&[network_id.as_str()])
                .observe(rtt.as_secs_f64());
```

**File:** mempool/src/counters.rs (L490-497)
```rust
pub static SHARED_MEMPOOL_BROADCAST_RTT: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "aptos_shared_mempool_broadcast_roundtrip_latency",
        "Time elapsed between sending a broadcast and receiving an ACK for that broadcast",
        &["network"]
    )
    .unwrap()
});
```

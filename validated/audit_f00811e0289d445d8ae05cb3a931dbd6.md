# Audit Report

## Title
Selective Latency Ping Response Manipulation Enables Peer Selection Priority Bypass

## Summary
Malicious network peers can artificially deflate their measured average latency by selectively responding only to ping requests during favorable network conditions while ignoring requests during unfavorable conditions. Since failed pings are excluded from average latency calculations, attackers gain unfair priority in peer selection algorithms used by mempool transaction forwarding and state sync data requests.

## Finding Description

The peer monitoring service implements latency measurement through periodic ping requests with a monotonically increasing counter. The client sends `LatencyPingRequest` messages and expects peers to echo back the `ping_counter` value. [1](#0-0) 

The server-side handler is stateless and simply echoes back the received counter without maintaining any history or validation state: [2](#0-1) 

The client validates that response counters match request counters, rejecting mismatches: [3](#0-2) 

**The Critical Vulnerability:**

The average latency calculation only includes successful ping responses, completely excluding failed or timed-out requests: [4](#0-3) 

When pings fail, the failure counter increments but the failed ping does NOT contribute to the latency average: [5](#0-4) 

Critically, automatic disconnection on failures is explicitly NOT implemented (see TODO comment at line 64). Only a warning is logged when failures exceed the threshold. [6](#0-5) 

**Attack Execution:**

1. A malicious peer receives `LatencyPingRequest` messages
2. The peer measures its current actual network latency conditions
3. If conditions are favorable (low latency): Respond immediately with correct `ping_counter`
4. If conditions are unfavorable (high latency): Ignore the request and let it timeout
5. Only successful low-latency pings are recorded in `recorded_latency_ping_durations_secs`
6. The calculated `average_ping_latency_secs` is artificially deflated

By maintaining a pattern like "respond, respond, timeout, respond, respond, timeout," the attacker avoids exceeding 3 consecutive failures while excluding high-latency measurements from their average.

**Impact on Peer Selection:**

This manipulated average latency directly affects critical peer selection systems:

**Mempool Transaction Forwarding:** The intelligent peer comparator uses `average_ping_latency_secs` for prioritization, with lower latency peers receiving higher priority: [7](#0-6) [8](#0-7) [9](#0-8) 

**State Sync Data Client:** Peer selection is weighted by latency, with lower latency yielding higher selection probability: [10](#0-9) [11](#0-10) 

## Impact Explanation

This vulnerability represents a **protocol violation** in peer selection mechanisms. According to Aptos bug bounty criteria, this qualifies as **Medium Severity** ("Limited Protocol Violations").

**Specific Impacts:**

1. **Suboptimal Peer Selection**: Honest nodes preferentially connect to and communicate with manipulated peers that appear fast but are actually unreliable, degrading network efficiency.

2. **Resource Waste**: Nodes allocate bandwidth, connections, and state sync requests to dishonest peers based on false latency metrics, wasting resources that should be directed to genuinely reliable peers.

3. **Transaction Propagation Manipulation**: Attackers gain priority in mempool transaction forwarding, potentially enabling them to observe transactions before other peers and influence transaction ordering (though they cannot directly manipulate consensus without validator credentials).

4. **Network Health Degradation**: The fundamental security guarantee of peer selection—that reliable, low-latency peers are correctly identified and prioritized—is broken, undermining the network's ability to maintain optimal connectivity.

While this does not directly compromise consensus, steal funds, or cause network partition, it does violate protocol assumptions about peer trustworthiness and can degrade overall network performance.

## Likelihood Explanation

**Likelihood: High**

This attack is easily exploitable with minimal requirements:

1. **No Special Access**: Any network peer can execute this attack without validator credentials or stake
2. **Simple Implementation**: Requires only basic packet inspection and conditional response logic
3. **Low Detectability**: Selective timeouts appear as normal network variability, making malicious behavior difficult to distinguish from legitimate network issues
4. **No Cryptographic Bypass**: Works within the protocol's design without requiring signature forgery
5. **Low Cost**: Attacker only needs to maintain network connectivity and selectively respond
6. **Effective Evasion**: By maintaining a pattern that keeps consecutive failures below the threshold (default: 3), attackers can avoid even triggering warnings while significantly deflating their average latency

## Recommendation

Implement one or more of the following mitigations:

1. **Include Failed Pings in Average Calculation**: Treat timed-out pings as measurements at the maximum timeout value (e.g., 20 seconds) rather than excluding them entirely:

```rust
// In record_new_latency_and_reset_failures, also track timeouts
// In get_average_latency_ping_secs, include timeout values in calculation
```

2. **Implement Automatic Disconnection**: Complete the TODO at line 64 by actually disconnecting peers that exceed the failure threshold:

```rust
if num_consecutive_failures >= self.latency_monitoring_config.max_latency_ping_failures {
    // Disconnect the peer instead of just logging a warning
    self.disconnect_peer(peer_network_id);
}
```

3. **Use Percentile Metrics**: Instead of simple averages, use p50/p90/p99 latency percentiles that are more resistant to manipulation.

4. **Implement Outlier Detection**: Track the variance in latency measurements and flag peers with suspiciously low variance (always low latency) or patterns suggesting selective response behavior.

## Proof of Concept

The following demonstrates the vulnerability:

```rust
// Simulated attack pattern showing average latency manipulation
// Attacker responds to 2 pings, timeouts 1 ping, repeat

// Real latency distribution: 50ms (favorable), 150ms (unfavorable) 
// Attacker only responds during 50ms conditions
// 2 responses at 50ms, 1 timeout (excluded from average)
// Result: average = (50 + 50) / 2 = 50ms
// Actual average if timeouts included: (50 + 50 + timeout) / 3 >> 50ms

// The consecutive failure counter stays at 1 (below threshold of 3)
// No disconnection occurs, attacker maintains artificially low average
```

A full implementation would require:
1. Setting up a malicious peer monitoring service server
2. Implementing conditional response logic based on measured network conditions
3. Demonstrating the resulting artificially low `average_ping_latency_secs` value
4. Showing the peer gains priority in mempool or state sync peer selection

## Notes

This vulnerability exists due to a design decision to exclude failed measurements from average calculations, likely intended to avoid penalizing peers for transient network issues. However, this creates an exploitable asymmetry where malicious peers can selectively report only their best performance while honest peers report all measurements, leading to unfair prioritization.

The TODO comment at line 64 explicitly acknowledges that automatic disconnection is not implemented, confirming that the only consequence of repeated failures is logging warnings. This makes the attack sustainable over extended periods.

### Citations

**File:** peer-monitoring-service/client/src/peer_states/latency_info.rs (L29-30)
```rust
    latency_ping_counter: u64, // The monotonically increasing counter for each ping
    recorded_latency_ping_durations_secs: BTreeMap<u64, f64>, // Successful ping durations by counter (secs)
```

**File:** peer-monitoring-service/client/src/peer_states/latency_info.rs (L60-72)
```rust
    fn handle_request_failure(&self, peer_network_id: &PeerNetworkId) {
        // Update the number of ping failures for the request tracker
        self.request_tracker.write().record_response_failure();

        // TODO: If the number of ping failures is too high, disconnect from the node
        let num_consecutive_failures = self.request_tracker.read().get_num_consecutive_failures();
        if num_consecutive_failures >= self.latency_monitoring_config.max_latency_ping_failures {
            warn!(LogSchema::new(LogEntry::LatencyPing)
                .event(LogEvent::TooManyPingFailures)
                .peer(peer_network_id)
                .message("Too many ping failures occurred for the peer!"));
        }
    }
```

**File:** peer-monitoring-service/client/src/peer_states/latency_info.rs (L101-109)
```rust
    pub fn get_average_latency_ping_secs(&self) -> Option<f64> {
        let num_latency_pings = self.recorded_latency_ping_durations_secs.len();
        if num_latency_pings > 0 {
            let average_latency_secs_sum: f64 =
                self.recorded_latency_ping_durations_secs.values().sum();
            Some(average_latency_secs_sum / num_latency_pings as f64)
        } else {
            None
        }
```

**File:** peer-monitoring-service/client/src/peer_states/latency_info.rs (L178-191)
```rust
        // Verify the latency ping response contains the correct counter
        let request_ping_counter = latency_ping_request.ping_counter;
        let response_ping_counter = latency_ping_response.ping_counter;
        if request_ping_counter != response_ping_counter {
            warn!(LogSchema::new(LogEntry::LatencyPing)
                .event(LogEvent::PeerPingError)
                .peer(peer_network_id)
                .message(&format!(
                    "Peer responded with the incorrect ping counter! Expected: {:?}, found: {:?}",
                    request_ping_counter, response_ping_counter
                )));
            self.handle_request_failure(peer_network_id);
            return;
        }
```

**File:** peer-monitoring-service/server/src/lib.rs (L283-292)
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
```

**File:** config/src/config/peer_monitoring_config.rs (L52-52)
```rust
            max_latency_ping_failures: 3,
```

**File:** mempool/src/shared_mempool/priority.rs (L111-115)
```rust
        // Otherwise, compare by peer ping latency (the lower the better)
        let latency_ordering = compare_ping_latency(monitoring_metadata_a, monitoring_metadata_b);
        if !latency_ordering.is_eq() {
            return latency_ordering; // Only return if it's not equal
        }
```

**File:** mempool/src/shared_mempool/priority.rs (L520-522)
```rust
fn get_peer_ping_latency(monitoring_metadata: &Option<&PeerMonitoringMetadata>) -> Option<f64> {
    monitoring_metadata.and_then(|metadata| metadata.average_ping_latency_secs)
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

**File:** state-sync/aptos-data-client/src/utils.rs (L175-183)
```rust
fn convert_latency_to_weight(latency: f64) -> f64 {
    // If the latency is <= 0, something has gone wrong, so return 0.
    if latency <= 0.0 {
        return 0.0;
    }

    // Otherwise, invert the latency to get the weight
    1000.0 / latency
}
```

**File:** state-sync/aptos-data-client/src/utils.rs (L210-228)
```rust
fn get_latency_for_peer(
    peers_and_metadata: &Arc<PeersAndMetadata>,
    peer: PeerNetworkId,
) -> Option<f64> {
    if let Some(peer_metadata) = get_metadata_for_peer(peers_and_metadata, peer) {
        let peer_monitoring_metadata = peer_metadata.get_peer_monitoring_metadata();
        if let Some(latency) = peer_monitoring_metadata.average_ping_latency_secs {
            return Some(latency); // The latency was found
        }
    }

    // Otherwise, no latency was found
    log_warning_with_sample(
        LogSchema::new(LogEntry::PeerStates)
            .event(LogEvent::PeerSelectionError)
            .message(&format!("Unable to get latency for peer! Peer: {:?}", peer)),
    );
    None
}
```

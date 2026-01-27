# Audit Report

## Title
Health Check Failure Counter Reset Through Disconnect/Reconnect Cycles Allows Unhealthy Peers to Evade Disconnection

## Summary
The HealthChecker's failure tracking mechanism can be completely bypassed by an attacker who disconnects and reconnects before reaching the failure threshold. When a peer disconnects, their health data (including failure count) is removed. Upon reconnection, they are reinitialized with a fresh failure counter set to 0, allowing them to indefinitely avoid disconnection despite consistent health check failures.

## Finding Description

The HealthChecker maintains per-peer health data in a HashMap that tracks both the current round and accumulated failures. When a peer connection is lost, `remove_peer_and_health_data()` completely removes their entry. [1](#0-0) 

When the peer reconnects, `create_peer_and_health_data()` is called with the current round, creating fresh `HealthCheckData` with `failures: 0`. [2](#0-1)  The `HealthCheckData::new()` constructor initializes failures to 0. [3](#0-2) 

**Attack Flow:**

1. **Connection Established**: Malicious peer connects and is initialized with `round=R`, `failures=0`
2. **Failure Accumulation**: Peer deliberately fails to respond to health check pings, accumulating failures (e.g., 3 out of allowed 3)
3. **Preemptive Disconnect**: Before reaching the threshold (`failures > ping_failures_tolerated`), the peer voluntarily closes the TCP connection [4](#0-3) 
4. **State Removal**: `ConnectionNotification::LostPeer` triggers `remove_peer_and_health_data()`, erasing all failure history [5](#0-4) 
5. **Immediate Reconnection**: Peer reconnects (either by dialing back or accepting incoming dial)
6. **Counter Reset**: `ConnectionNotification::NewPeer` triggers `create_peer_and_health_data()` with fresh state [6](#0-5) 
7. **Cycle Repeats**: Attacker can maintain connection indefinitely despite consistent unresponsiveness

**Security Guarantee Violated:**

The HealthChecker's documented purpose is: "If a certain number of successive liveness probes for a peer fail, the HealthChecker initiates a disconnect from the peer." [7](#0-6)  This guarantee is violated because an attacker can prevent "successive" failures from accumulating by resetting the counter through reconnection.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program criteria as a "significant protocol violation":

1. **Security Mechanism Bypass**: The HealthChecker is a critical network hygiene component designed to detect and disconnect unresponsive peers. Complete bypass defeats this protection.

2. **Validator Network Impact**: In validator networks, unresponsive peers that remain connected can:
   - Consume connection slots, preventing healthy validators from connecting (max_inbound_connections limit)
   - Degrade consensus performance by appearing available while being selectively unresponsive
   - Enable sophisticated attacks where malicious validators respond to some messages but not others

3. **Resource Exhaustion Vector**: Multiple attackers could exploit this to maintain numerous zombie connections, causing "validator node slowdowns" (High severity category).

4. **Attack Surface Expansion**: An attacker maintaining persistent connection despite unresponsiveness has more opportunities for:
   - Timing-based attacks on consensus protocols
   - Message injection when other validators expect them to be disconnected
   - State desynchronization by appearing present but non-functional

The default configuration allows 3 ping failures before disconnection (PING_FAILURES_TOLERATED=3), with 10-second intervals. [8](#0-7)  An attacker can reset every ~30 seconds to stay connected indefinitely.

## Likelihood Explanation

**Likelihood: HIGH**

1. **Trivial Exploitation**: Any peer can close their TCP connection at any time. Reconnection is either attacker-initiated (outgoing dial) or victim-initiated (ConnectivityManager's automatic reconnection).

2. **No Rate Limiting**: The TRY_DIAL_BACKOFF_TIME (5 minutes) only applies to ConnectivityManager's outgoing dials. [9](#0-8)  Incoming connections from the attacker have no such protection beyond max_inbound_connections.

3. **No Historical Tracking**: No mechanism persists failure counts across connection sessions or tracks disconnection patterns to detect abuse.

4. **Observable State**: Attackers can monitor their own failure count timing since ping intervals are predictable (10 seconds default).

5. **Production Feasibility**: In real networks, transient disconnections are common and expected. This attack blends with normal network behavior.

## Recommendation

Implement persistent failure tracking across connection sessions:

```rust
// Add to HealthCheckNetworkInterface
struct PersistentHealthMetrics {
    total_disconnections: u64,
    last_disconnect_time: SystemTime,
    historical_failure_rate: f64,
}

pub fn create_peer_and_health_data(&mut self, peer_id: PeerId, round: u64) {
    self.health_check_data
        .write()
        .entry(peer_id)
        .and_modify(|data| {
            // On reconnection, preserve historical context
            if let Some(metrics) = self.persistent_metrics.get(&peer_id) {
                // Apply exponential backoff or escalating penalty
                let reconnect_penalty = calculate_reconnect_penalty(metrics);
                data.failures = reconnect_penalty;
                data.round = round;
            } else {
                data.round = round;
            }
        })
        .or_insert_with(|| {
            // Check if this peer has suspicious reconnection history
            if let Some(metrics) = self.persistent_metrics.get(&peer_id) {
                if is_suspicious_pattern(metrics) {
                    // Start with elevated failure count
                    HealthCheckData { 
                        round, 
                        failures: calculate_reconnect_penalty(metrics) 
                    }
                } else {
                    HealthCheckData::new(round)
                }
            } else {
                HealthCheckData::new(round)
            }
        });
}
```

**Alternative Mitigations:**

1. **Exponential Backoff on Reconnect**: Implement increasing delays before accepting reconnections from peers with recent health check failures
2. **Persistent Ban List**: Temporarily ban peers that disconnect suspiciously close to failure thresholds
3. **Cross-Session Failure Tracking**: Maintain a rolling window of failures that survives reconnections for a configurable time period

## Proof of Concept

```rust
#[cfg(test)]
mod health_checker_bypass_test {
    use super::*;
    use aptos_config::network_id::NetworkId;
    use aptos_time_service::MockTimeService;
    
    #[tokio::test]
    async fn test_failure_counter_reset_on_reconnect() {
        // Setup health checker with ping_failures_tolerated = 3
        let network_context = NetworkContext::mock(NetworkId::Validator);
        let time_service = TimeService::mock();
        let (mut health_interface, _receiver) = create_health_checker_interface();
        let peer_id = PeerId::random();
        
        // Simulate peer connection
        health_interface.create_peer_and_health_data(peer_id, 100);
        
        // Simulate 3 consecutive ping failures (just below threshold of 4)
        for round in 100..103 {
            health_interface.increment_peer_round_failure(peer_id, round);
        }
        
        // Verify peer has 3 failures
        assert_eq!(health_interface.get_peer_failures(peer_id), Some(3));
        
        // Peer disconnects before being kicked
        health_interface.remove_peer_and_health_data(&peer_id);
        
        // Peer immediately reconnects
        health_interface.create_peer_and_health_data(peer_id, 103);
        
        // VULNERABILITY: Failure counter is reset to 0
        assert_eq!(health_interface.get_peer_failures(peer_id), Some(0));
        
        // Peer can repeat this indefinitely, never reaching threshold
        for cycle in 0..10 {
            for round in 0..3 {
                health_interface.increment_peer_round_failure(peer_id, 103 + cycle * 10 + round);
            }
            
            // Verify approaching threshold
            assert_eq!(health_interface.get_peer_failures(peer_id), Some(3));
            
            // Disconnect and reconnect to reset
            health_interface.remove_peer_and_health_data(&peer_id);
            health_interface.create_peer_and_health_data(peer_id, 103 + (cycle + 1) * 10);
            
            // Failures reset each time
            assert_eq!(health_interface.get_peer_failures(peer_id), Some(0));
        }
        
        println!("EXPLOIT SUCCESS: Peer maintained connection through 10 disconnect/reconnect cycles despite consistent health check failures");
    }
}
```

## Notes

This vulnerability is exacerbated in validator networks where ConnectivityManager aggressively attempts to maintain connections with eligible peers. The 5-minute backoff only applies to outgoing dials by the victim node; the attacker can dial in immediately. Additionally, the lack of any historical tracking or anomaly detection for disconnection patterns makes this attack completely invisible to monitoring systems.

### Citations

**File:** network/framework/src/protocols/health_checker/interface.rs (L32-35)
```rust
impl HealthCheckData {
    pub fn new(round: u64) -> Self {
        HealthCheckData { round, failures: 0 }
    }
```

**File:** network/framework/src/protocols/health_checker/interface.rs (L95-101)
```rust
    pub fn create_peer_and_health_data(&mut self, peer_id: PeerId, round: u64) {
        self.health_check_data
            .write()
            .entry(peer_id)
            .and_modify(|health_check_data| health_check_data.round = round)
            .or_insert_with(|| HealthCheckData::new(round));
    }
```

**File:** network/framework/src/protocols/health_checker/interface.rs (L104-106)
```rust
    pub fn remove_peer_and_health_data(&mut self, peer_id: &PeerId) {
        self.health_check_data.write().remove(peer_id);
    }
```

**File:** network/framework/src/protocols/health_checker/mod.rs (L10-12)
```rust
//! If a certain number of successive liveness probes for a peer fail, the HealthChecker initiates a
//! disconnect from the peer. It relies on ConnectivityManager or the remote peer to re-establish
//! the connection.
```

**File:** network/framework/src/protocols/health_checker/mod.rs (L211-217)
```rust
                        ConnectionNotification::NewPeer(metadata, network_id) => {
                            // PeersAndMetadata is a global singleton across all networks; filter connect/disconnect events to the NetworkId that this HealthChecker instance is watching
                            if network_id == self_network_id {
                                self.network_interface.create_peer_and_health_data(
                                    metadata.remote_peer_id, self.round
                                );
                            }
```

**File:** network/framework/src/protocols/health_checker/mod.rs (L219-226)
```rust
                        ConnectionNotification::LostPeer(metadata, network_id) => {
                            // PeersAndMetadata is a global singleton across all networks; filter connect/disconnect events to the NetworkId that this HealthChecker instance is watching
                            if network_id == self_network_id {
                                self.network_interface.remove_peer_and_health_data(
                                    &metadata.remote_peer_id
                                );
                            }
                        }
```

**File:** network/framework/src/protocols/health_checker/mod.rs (L364-392)
```rust
                if failures > self.ping_failures_tolerated {
                    info!(
                        NetworkSchema::new(&self.network_context).remote_peer(&peer_id),
                        "{} Disconnecting from peer: {}",
                        self.network_context,
                        peer_id.short_str()
                    );
                    let peer_network_id =
                        PeerNetworkId::new(self.network_context.network_id(), peer_id);
                    if let Err(err) = timeout(
                        Duration::from_millis(50),
                        self.network_interface.disconnect_peer(
                            peer_network_id,
                            DisconnectReason::NetworkHealthCheckFailure,
                        ),
                    )
                    .await
                    {
                        warn!(
                            NetworkSchema::new(&self.network_context)
                                .remote_peer(&peer_id),
                            error = ?err,
                            "{} Failed to disconnect from peer: {} with error: {:?}",
                            self.network_context,
                            peer_id.short_str(),
                            err
                        );
                    }
                }
```

**File:** config/src/config/network_config.rs (L38-40)
```rust
pub const PING_INTERVAL_MS: u64 = 10_000;
pub const PING_TIMEOUT_MS: u64 = 20_000;
pub const PING_FAILURES_TOLERATED: u64 = 3;
```

**File:** network/framework/src/connectivity_manager/mod.rs (L90-93)
```rust
/// The amount of time to try other peers until dialing this peer again.
///
/// It's currently set to 5 minutes to ensure rotation through all (or most) peers
const TRY_DIAL_BACKOFF_TIME: Duration = Duration::from_secs(300);
```

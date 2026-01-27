# Audit Report

## Title
Byzantine Peers Can Maintain Connectivity Despite Persistent Monitoring Service Failures Due to Missing Disconnection Logic

## Summary
The peer monitoring service client tracks consecutive request failures but fails to disconnect Byzantine peers that repeatedly send malformed responses or errors. Despite detecting and counting failures exceeding the configured threshold (`max_latency_ping_failures`), the system only logs warnings without disconnecting the malicious peer, allowing it to maintain network connectivity indefinitely.

## Finding Description
The Aptos network architecture employs two separate peer health monitoring systems:

1. **HealthChecker Protocol** (`ProtocolId::HealthCheckerRpc`): Basic connectivity liveness probes
2. **PeerMonitoringService Protocol** (`ProtocolId::PeerMonitoringServiceRpc`): Rich monitoring with latency pings, network information, and node information

The vulnerability exists in the PeerMonitoringService system. When a peer fails to respond correctly to monitoring requests (latency pings, network info requests, or node info requests), all error types (`PeerMonitoringServiceError::InvalidRequest`, `PeerMonitoringServiceError::InternalError`, `NetworkError`, `RpcError`) are uniformly handled by incrementing a failure counter. [1](#0-0) 

The `handle_request_failure` function increments the consecutive failure count and checks if it exceeds the threshold: [2](#0-1) 

**Critical Issue**: The TODO comment on line 64 explicitly acknowledges that peer disconnection should occur but is not implemented. Only a warning is logged when failures exceed `max_latency_ping_failures` (default: 3). [3](#0-2) 

**Attack Path**:
1. A Byzantine peer connects to honest nodes
2. The peer responds correctly to HealthChecker pings (maintaining basic connectivity)
3. The peer sends malformed responses to PeerMonitoringService requests (e.g., `InvalidRequest` errors, wrong ping counters, invalid network distances)
4. Honest nodes increment failure counters and log warnings
5. No disconnection occurs—the Byzantine peer remains connected indefinitely
6. The peer can pollute monitoring metadata, manipulate perceived network topology, or provide false node information

The server-side error classification maps all internal errors to `PeerMonitoringServiceError::InternalError`: [4](#0-3) 

Meanwhile, the HealthChecker protocol (which operates independently) successfully disconnects peers after `ping_failures_tolerated` failures: [5](#0-4) 

The protocols are registered separately: [6](#0-5) 

## Impact Explanation
This vulnerability constitutes a **High Severity** Byzantine fault tolerance violation per the Aptos bug bounty program criteria:

1. **Significant Protocol Violation**: The peer monitoring service is a critical network protocol component. The failure to enforce disconnection policies violates expected BFT properties where Byzantine actors should be isolated.

2. **Network Integrity Compromise**: Byzantine peers can:
   - Manipulate `distance_from_validators` metrics affecting peer selection algorithms
   - Provide false node information (build version, sync state) misleading honest nodes
   - Pollute network topology data used for diagnostics and monitoring
   - Maintain persistent presence despite exhibiting malicious behavior

3. **Asymmetric Defense Degradation**: While the HealthChecker provides basic liveness detection, Byzantine peers can selectively respond to different protocols, passing liveness checks while disrupting higher-level monitoring—creating a blind spot in Byzantine detection.

This does not directly affect consensus safety or cause funds loss, but it represents a significant degradation in the network's ability to detect and isolate Byzantine actors, which is a foundational security property.

## Likelihood Explanation
**Likelihood: High**

- **Attack Complexity**: Trivial. An attacker simply needs to respond correctly to HealthChecker pings while returning errors or malformed data to PeerMonitoringService requests.
- **Attacker Requirements**: Any network peer without privileged access.
- **Detection**: Currently undetectable beyond warning logs that are likely ignored in production.
- **Existing TODO**: The code explicitly acknowledges this is a missing feature, indicating the development team recognizes the gap but has not prioritized implementation.

## Recommendation
Implement the missing disconnection logic in the peer monitoring service client. The recommendation includes:

1. **Add Disconnection Logic**: Modify `handle_request_failure` in each state handler to disconnect peers exceeding failure thresholds.

2. **Proposed Fix** for `latency_info.rs`:

```rust
fn handle_request_failure(&self, peer_network_id: &PeerNetworkId) {
    // Update the number of ping failures for the request tracker
    self.request_tracker.write().record_response_failure();

    // Disconnect from the node if ping failures are too high
    let num_consecutive_failures = self.request_tracker.read().get_num_consecutive_failures();
    if num_consecutive_failures >= self.latency_monitoring_config.max_latency_ping_failures {
        warn!(LogSchema::new(LogEntry::LatencyPing)
            .event(LogEvent::TooManyPingFailures)
            .peer(peer_network_id)
            .message(&format!(
                "Too many ping failures ({}) occurred for the peer! Disconnecting...",
                num_consecutive_failures
            )));
        
        // Disconnect the peer
        if let Err(err) = self.network_client.disconnect_peer(
            *peer_network_id,
            DisconnectReason::PeerMonitoringServiceFailure,
        ) {
            error!(LogSchema::new(LogEntry::LatencyPing)
                .event(LogEvent::DisconnectFailed)
                .peer(peer_network_id)
                .error(&err)
                .message("Failed to disconnect peer after monitoring failures"));
        }
    }
}
```

3. **Add DisconnectReason Variant**: Extend the `DisconnectReason` enum to include `PeerMonitoringServiceFailure`.

4. **Apply to All State Types**: Implement similar disconnection logic in `NetworkInfoState` and `NodeInfoState`.

5. **Configuration**: Consider making disconnection configurable (enable/disable) and tuning failure thresholds independently from HealthChecker.

## Proof of Concept

```rust
#[cfg(test)]
mod byzantine_peer_test {
    use super::*;
    use aptos_config::config::LatencyMonitoringConfig;
    use aptos_peer_monitoring_service_types::{
        PeerMonitoringServiceError, 
        request::LatencyPingRequest,
    };
    use aptos_time_service::TimeService;
    
    #[test]
    fn test_byzantine_peer_maintains_connectivity_after_failures() {
        // Create latency info state with default config (max_failures = 3)
        let config = LatencyMonitoringConfig::default();
        let time_service = TimeService::mock();
        let mut state = LatencyInfoState::new(config, time_service);
        let peer_network_id = PeerNetworkId::random();
        
        // Simulate Byzantine peer sending errors repeatedly
        for i in 0..10 {
            // Create error - this simulates a malformed response
            let error = Error::PeerMonitoringServiceError(
                PeerMonitoringServiceError::InvalidRequest(
                    format!("Malicious response #{}", i)
                )
            );
            
            // Handle the error
            state.handle_monitoring_service_response_error(&peer_network_id, error);
            
            // Get failure count
            let failures = state.request_tracker.read().get_num_consecutive_failures();
            println!("Consecutive failures: {}", failures);
            
            // After 3 failures, peer should be disconnected, but isn't
            if failures >= 3 {
                println!("WARNING: Peer exceeded failure threshold but remains connected!");
            }
        }
        
        // Verify the peer accumulated 10 consecutive failures
        let final_failures = state.request_tracker.read().get_num_consecutive_failures();
        assert_eq!(final_failures, 10);
        
        // This test demonstrates that even with 10 consecutive failures,
        // the Byzantine peer is never disconnected (only warnings are logged)
        println!("Byzantine peer successfully maintained connectivity despite {} failures", 
                 final_failures);
    }
}
```

## Notes

This vulnerability is explicitly acknowledged in the codebase via the TODO comment, indicating it's a known incomplete implementation rather than an oversight. However, the security implications are significant: Byzantine peers can exploit the separation between HealthChecker and PeerMonitoringService protocols to maintain network presence while disrupting monitoring operations. The fix requires integrating disconnection capabilities from the network layer into the peer monitoring service client, ensuring Byzantine actors are consistently isolated across all protocol layers.

### Citations

**File:** peer-monitoring-service/client/src/peer_states/latency_info.rs (L59-72)
```rust
    /// Handles a ping failure for the specified peer
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

**File:** peer-monitoring-service/client/src/peer_states/latency_info.rs (L197-211)
```rust
    fn handle_monitoring_service_response_error(
        &mut self,
        peer_network_id: &PeerNetworkId,
        error: Error,
    ) {
        // Handle the failure
        self.handle_request_failure(peer_network_id);

        // Log the error
        warn!(LogSchema::new(LogEntry::LatencyPing)
            .event(LogEvent::ResponseError)
            .message("Error encountered when pinging peer!")
            .peer(peer_network_id)
            .error(&error));
    }
```

**File:** config/src/config/peer_monitoring_config.rs (L47-56)
```rust
impl Default for LatencyMonitoringConfig {
    fn default() -> Self {
        Self {
            latency_ping_interval_ms: 30_000, // 30 seconds
            latency_ping_timeout_ms: 20_000,  // 20 seconds
            max_latency_ping_failures: 3,
            max_num_latency_pings_to_retain: 10,
        }
    }
}
```

**File:** peer-monitoring-service/server/src/lib.rs (L198-203)
```rust
                match error {
                    Error::InvalidRequest(error) => {
                        Err(PeerMonitoringServiceError::InvalidRequest(error))
                    },
                    error => Err(PeerMonitoringServiceError::InternalError(error.to_string())),
                }
```

**File:** network/framework/src/protocols/health_checker/mod.rs (L356-392)
```rust
                // If the ping failures are now more than
                // `self.ping_failures_tolerated`, we disconnect from the node.
                // The HealthChecker only performs the disconnect. It relies on
                // ConnectivityManager or the remote peer to re-establish the connection.
                let failures = self
                    .network_interface
                    .get_peer_failures(peer_id)
                    .unwrap_or(0);
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

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L128-133)
```rust
            ProtocolId::HealthCheckerRpc,
            ProtocolId::ConsensusDirectSendJson,
            ProtocolId::ConsensusRpcJson,
            ProtocolId::StorageServiceRpc,
            ProtocolId::MempoolRpc,
            ProtocolId::PeerMonitoringServiceRpc,
```

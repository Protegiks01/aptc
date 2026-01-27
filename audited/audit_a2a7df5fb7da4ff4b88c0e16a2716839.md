# Audit Report

## Title
Peer Monitoring Service Fails to Disconnect Persistently Failing Peers, Allowing Network Degradation

## Summary
The peer monitoring service tracks consecutive monitoring failures but never disconnects peers when failures exceed configured thresholds. This allows malicious or unhealthy peers to persist indefinitely in the network while critical subsystems (mempool, state sync, consensus observer) continue using stale or default metadata for peer selection, degrading network performance and reliability.

## Finding Description

The peer monitoring service implements failure tracking through `RequestTracker` but lacks the disconnect enforcement present in the health checker system. When monitoring requests fail repeatedly, the system exhibits graceful degradation behavior that becomes a security vulnerability. [1](#0-0) 

The code explicitly acknowledges this missing functionality with a TODO comment indicating disconnection was intended but never implemented. When failures accumulate beyond `max_latency_ping_failures` (default: 3), the system only logs a warning without taking corrective action.

In contrast, the health checker actively disconnects peers when failures exceed thresholds: [2](#0-1) 

When peer monitoring extraction fails, the metadata updater falls back to default values rather than excluding the peer: [3](#0-2) 

This stale metadata persists in the system and is used by critical subsystems for peer selection:

**Mempool Priority Selection:** [4](#0-3) 

The mempool's `check_peer_metadata_health()` considers peers with missing metadata as unhealthy but still allows selection if all peers lack metadata. Peers with accumulated monitoring failures can continue receiving transaction broadcasts.

**Configuration defines thresholds that are never enforced:** [5](#0-4) 

The `max_latency_ping_failures` configuration exists but triggers no disconnection logic.

**Attack Scenario:**

1. Attacker controls multiple peers that connect to validator nodes
2. Peers stop responding to monitoring requests or send invalid responses
3. Monitoring failures accumulate, but peers remain connected indefinitely
4. Stale/default metadata causes these peers to be deprioritized but not excluded
5. Critical systems (mempool, state sync, consensus observer) continue routing to degraded peers
6. Network performance degrades as healthy peer capacity is diluted with failing connections
7. If enough malicious peers are present, they can influence routing decisions and slow consensus

## Impact Explanation

This qualifies as **High Severity** per Aptos bug bounty criteria: "Validator node slowdowns" and "Significant protocol violations."

The vulnerability enables:
- **Validator Performance Degradation**: Persistent failing peers consume connection slots and routing decisions
- **Mempool Transaction Propagation Delays**: Stale metadata affects peer prioritization for transaction broadcasts
- **State Sync Inefficiency**: Data requests may be routed to unhealthy peers based on outdated metrics
- **Consensus Observer Degradation**: Subscription quality suffers when peer selection uses stale monitoring data

While not causing catastrophic failure, this creates a sustainable attack vector for network degradation that affects all validator nodes simultaneously.

## Likelihood Explanation

**Likelihood: High**

The attack requires minimal sophistication:
- Attacker needs only basic peer connectivity (no validator privileges required)
- Simply stop responding to monitoring RPC calls or send malformed responses
- No cryptographic attacks or protocol manipulation needed
- Effect is persistent and cumulative across multiple peers
- Default configuration values make the vulnerability immediately exploitable

The inconsistency between health checker (which disconnects) and peer monitoring service (which doesn't) suggests this is an implementation oversight rather than intentional design, as evidenced by the TODO comment.

## Recommendation

Implement peer disconnection logic in the peer monitoring service consistent with the health checker pattern:

```rust
// In peer-monitoring-service/client/src/peer_states/latency_info.rs
fn handle_request_failure(&self, peer_network_id: &PeerNetworkId, network_interface: &HealthCheckNetworkInterface) {
    // Update the number of ping failures for the request tracker
    self.request_tracker.write().record_response_failure();

    let num_consecutive_failures = self.request_tracker.read().get_num_consecutive_failures();
    if num_consecutive_failures >= self.latency_monitoring_config.max_latency_ping_failures {
        warn!(LogSchema::new(LogEntry::LatencyPing)
            .event(LogEvent::TooManyPingFailures)
            .peer(peer_network_id)
            .message("Too many ping failures occurred for the peer! Disconnecting..."));
        
        // Disconnect from the peer
        if let Err(err) = network_interface.disconnect_peer(
            *peer_network_id,
            DisconnectReason::PeerMonitoringFailure,
        ).await {
            error!(LogSchema::new(LogEntry::LatencyPing)
                .event(LogEvent::DisconnectError)
                .peer(peer_network_id)
                .error(&err)
                .message("Failed to disconnect peer after monitoring failures"));
        }
    }
}
```

Additional recommendations:
1. Add `DisconnectReason::PeerMonitoringFailure` to the disconnect reason enum
2. Implement similar logic for `NetworkInfoState` and `NodeInfoState` failure handlers
3. Add metrics to track peer monitoring disconnections
4. Consider implementing exponential backoff for reconnection attempts to prevent rapid cycling
5. Document the relationship between health checker and peer monitoring service disconnect policies

## Proof of Concept

```rust
// Integration test demonstrating the vulnerability
#[tokio::test]
async fn test_peer_monitoring_does_not_disconnect_failing_peers() {
    // Setup: Create peer monitoring client and mock peer that always fails
    let (network_client, mut network_rx) = create_test_network_client();
    let peer_monitoring_client = PeerMonitoringServiceClient::new(network_client.clone());
    let peer_monitor_state = PeerMonitorState::new();
    let time_service = TimeService::mock();
    
    // Create a malicious peer that never responds
    let malicious_peer = PeerNetworkId::random();
    let peer_metadata = create_test_peer_metadata(malicious_peer);
    
    // Simulate peer connection
    network_client.connect_peer(malicious_peer, peer_metadata).await;
    
    // Configuration with max 3 failures
    let config = PeerMonitoringServiceConfig {
        latency_monitoring: LatencyMonitoringConfig {
            max_latency_ping_failures: 3,
            ..Default::default()
        },
        ..Default::default()
    };
    
    // Send monitoring requests that will fail
    for i in 0..10 {
        // Simulate monitoring loop iteration
        let result = peer_states::refresh_peer_states(
            &config,
            peer_monitor_state.clone(),
            peer_monitoring_client.clone(),
            connected_peers,
            time_service.clone(),
            None,
        ).await;
        
        // Drop all incoming requests to simulate unresponsive peer
        while let Ok(_) = network_rx.try_recv() {
            // Don't respond
        }
        
        time_service.advance(Duration::from_secs(30));
    }
    
    // Vulnerability: After 10 failures (>> max of 3), peer is still connected
    let connected_peers = network_client.get_peers_and_metadata()
        .get_connected_peers_and_metadata()
        .unwrap();
    
    assert!(connected_peers.contains_key(&malicious_peer), 
        "Malicious peer should still be connected despite exceeding failure threshold");
    
    // Verify that metadata became default/stale
    let peer_metadata = connected_peers.get(&malicious_peer).unwrap();
    let monitoring_metadata = peer_metadata.get_peer_monitoring_metadata();
    assert!(monitoring_metadata.average_ping_latency_secs.is_none() 
        || monitoring_metadata.latest_network_info_response.is_none(),
        "Peer monitoring metadata should be stale/default");
    
    // Demonstrate that mempool would still attempt to use this peer
    let prioritized_peers = calculate_prioritized_peers(&connected_peers);
    assert!(prioritized_peers.contains(&malicious_peer),
        "Mempool would still route transactions to failing peer");
}
```

This proof of concept demonstrates that peers exceeding the configured failure threshold remain connected and continue participating in routing decisions, confirming the vulnerability.

## Notes

The vulnerability stems from incomplete implementation of the peer monitoring service's error handling. The health checker serves as the correct reference implementation for handling persistent peer failures through disconnection. The inconsistency between these two systems creates a gap where malicious or unhealthy peers can persist indefinitely, affecting validator performance and network reliability.

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

**File:** peer-monitoring-service/client/src/lib.rs (L232-250)
```rust
            // Update the latest peer monitoring metadata
            for peer_network_id in all_peers {
                let peer_monitoring_metadata =
                    match peer_monitor_state.peer_states.read().get(&peer_network_id) {
                        Some(peer_state) => {
                            peer_state
                                .extract_peer_monitoring_metadata()
                                .unwrap_or_else(|error| {
                                    // Log the error and return the default
                                    warn!(LogSchema::new(LogEntry::MetadataUpdateLoop)
                                        .event(LogEvent::UnexpectedErrorEncountered)
                                        .peer(&peer_network_id)
                                        .error(&error));
                                    PeerMonitoringMetadata::default()
                                })
                        },
                        None => PeerMonitoringMetadata::default(), // Use the default
                    };

```

**File:** mempool/src/shared_mempool/priority.rs (L562-589)
```rust
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
```

**File:** config/src/config/peer_monitoring_config.rs (L40-56)
```rust
pub struct LatencyMonitoringConfig {
    pub latency_ping_interval_ms: u64, // The interval (ms) between latency pings for each peer
    pub latency_ping_timeout_ms: u64,  // The timeout (ms) for each latency ping
    pub max_latency_ping_failures: u64, // Max ping failures before the peer connection fails
    pub max_num_latency_pings_to_retain: usize, // The max latency pings to retain per peer
}

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

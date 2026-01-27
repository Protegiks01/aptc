# Audit Report

## Title
Permanent State Desynchronization Between PeersAndMetadata and HealthChecker on Disconnect Failure

## Summary
A state inconsistency vulnerability exists in the HealthChecker's `disconnect_peer()` function where failed disconnection attempts can leave peers permanently in a "Disconnecting" state in PeersAndMetadata while still tracked in the health checker's internal data structures, causing resource leaks and state corruption.

## Finding Description

The vulnerability occurs in the disconnect flow when the HealthChecker attempts to disconnect an unhealthy peer. The issue stems from the error handling logic in `disconnect_peer()`: [1](#0-0) 

The problematic sequence is:

1. **Line 71**: `update_connection_state()` is called to mark the peer as `Disconnecting` in PeersAndMetadata. The result is ignored with `let _ =`, so whether it succeeds or fails is not checked.

2. **Lines 72-75**: `disconnect_from_peer()` is called and awaited. This can fail for multiple reasons:
   - Timeout (50ms timeout imposed by caller)
   - Peer already disconnected (`NotConnected` error)
   - Channel send failures
   - Oneshot receiver errors

3. **Lines 77-79**: Only if `disconnect_from_peer()` succeeds is the peer removed from `health_check_data`.

**Critical flaw**: If `update_connection_state()` succeeds but `disconnect_from_peer()` fails, the system enters an inconsistent state where:
- PeersAndMetadata has the peer marked as `ConnectionState::Disconnecting` [2](#0-1) 
- The health checker's internal `health_check_data` still contains the peer
- No `LostPeer` notification is broadcast (since `remove_peer_metadata` was never called) [3](#0-2) 

This desynchronization is **permanent** because:

1. The HealthChecker continues to include this peer in `connected_peers()` which reads from its internal `health_check_data`: [4](#0-3) 

2. Every ping interval, the HealthChecker attempts to ping this ghost peer: [5](#0-4) 

3. The only cleanup mechanism is through `LostPeer` notifications, which are never sent: [6](#0-5) 

4. There is no periodic garbage collection or reconciliation to detect and fix this desynchronization.

## Impact Explanation

This vulnerability causes **Medium severity** impact based on the Aptos bug bounty criteria:

**State Inconsistencies Requiring Intervention**: The desynchronization between PeersAndMetadata and HealthChecker state persists until node restart, meeting the "state inconsistencies requiring intervention" criterion for Medium severity.

The specific impacts are:
1. **Memory Leak**: Peers accumulate in `health_check_data` HashMap (bounded by max connections ~100, minimal memory impact)
2. **CPU Waste**: HealthChecker continuously pings unreachable ghost peers every `ping_interval`
3. **State Corruption**: PeersAndMetadata contains peers permanently stuck in `Disconnecting` state
4. **Resource Inefficiency**: Peer monitoring service wastes cycles updating metadata for ghost peers [7](#0-6) 

**Why Not High Severity**: This does not meet High severity criteria because:
- It does not cause validator node slowdowns (bounded impact)
- It does not crash APIs or nodes
- It does not constitute a significant protocol violation
- Consensus and critical operations filter out `Disconnecting` peers via `is_connected()` checks [8](#0-7) 

## Likelihood Explanation

**Likelihood: Medium to High**

The failure conditions are realistic and can occur in production:

1. **Timeout scenario**: The disconnect call has a strict 50ms timeout: [9](#0-8) 
   - If PeerManager is processing many requests, the disconnect may timeout
   - Network congestion or system load can cause timeouts

2. **Race condition**: If another component (ConnectivityManager, manual disconnect) disconnects the peer first, `disconnect_from_peer()` returns `NotConnected` error: [10](#0-9) 

3. **Channel failures**: The disconnect request channel can be full or closed under load.

## Recommendation

**Fix 1: Ensure atomic state transitions**
```rust
pub async fn disconnect_peer(
    &mut self,
    peer_network_id: PeerNetworkId,
    disconnect_reason: DisconnectReason,
) -> Result<(), Error> {
    let peer_id = peer_network_id.peer_id();
    
    // Attempt disconnection first
    let result = self
        .network_client
        .disconnect_from_peer(peer_network_id, disconnect_reason)
        .await;
    
    // Only update state and clean up if disconnect succeeded
    match result {
        Ok(()) => {
            // Update connection state after successful disconnect
            let _ = self.update_connection_state(peer_network_id, ConnectionState::Disconnecting);
            // Clean up health check data
            self.health_check_data.write().remove(&peer_id);
            Ok(())
        }
        Err(e) => {
            // On disconnect failure, ensure we don't have orphaned state
            // Try to clean up health_check_data if peer is truly gone
            if matches!(e, Error::PeerManagerError(PeerManagerError::NotConnected(_))) {
                self.health_check_data.write().remove(&peer_id);
            }
            Err(e)
        }
    }
}
```

**Fix 2: Add periodic reconciliation**
Implement a background task that periodically checks for desynchronization between `health_check_data` and actual connected peers in PeersAndMetadata, cleaning up any ghost entries.

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use crate::testutils::test_node::TestNode;
    
    #[tokio::test]
    async fn test_disconnect_desynchronization() {
        // Setup test node and health checker
        let mut test_node = TestNode::new();
        let peer_id = test_node.add_peer();
        
        // Simulate scenario where update_connection_state succeeds
        // but disconnect_from_peer fails (e.g., peer already disconnected)
        
        // First, ensure peer is in health_check_data
        test_node.health_checker.network_interface
            .create_peer_and_health_data(peer_id, 1);
        
        // Cause disconnect_from_peer to fail by disconnecting peer externally first
        test_node.disconnect_peer_externally(peer_id).await;
        
        // Now call disconnect_peer - update_connection_state may succeed
        // but disconnect_from_peer will fail with NotConnected
        let result = test_node.health_checker.network_interface
            .disconnect_peer(
                PeerNetworkId::new(NetworkId::Validator, peer_id),
                DisconnectReason::NetworkHealthCheckFailure
            )
            .await;
        
        assert!(result.is_err());
        
        // Verify desynchronization: peer still in health_check_data
        let connected = test_node.health_checker.network_interface.connected_peers();
        assert!(connected.contains(&peer_id), "Ghost peer remains in health_check_data");
        
        // Verify peer in PeersAndMetadata is in Disconnecting state
        let metadata = test_node.peers_and_metadata
            .get_metadata_for_peer(PeerNetworkId::new(NetworkId::Validator, peer_id))
            .unwrap();
        assert_eq!(metadata.get_connection_state(), ConnectionState::Disconnecting);
        
        // Verify no LostPeer notification was sent (state permanently inconsistent)
        // This ghost peer will be pinged every round indefinitely
    }
}
```

## Notes

While the original question rates this as "High" severity, the actual impact aligns with **Medium severity** per Aptos bug bounty criteria. The vulnerability causes state inconsistencies and resource waste but does not directly impact consensus safety, validator performance at scale, or API availability. The bounded nature of the leak (max ~100 peers) and the filtering of `Disconnecting` peers by critical components limit the practical impact.

### Citations

**File:** network/framework/src/protocols/health_checker/interface.rs (L59-61)
```rust
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.health_check_data.read().keys().cloned().collect()
    }
```

**File:** network/framework/src/protocols/health_checker/interface.rs (L65-81)
```rust
    pub async fn disconnect_peer(
        &mut self,
        peer_network_id: PeerNetworkId,
        disconnect_reason: DisconnectReason,
    ) -> Result<(), Error> {
        // Possibly already disconnected, but try anyways
        let _ = self.update_connection_state(peer_network_id, ConnectionState::Disconnecting);
        let result = self
            .network_client
            .disconnect_from_peer(peer_network_id, disconnect_reason)
            .await;
        let peer_id = peer_network_id.peer_id();
        if result.is_ok() {
            self.health_check_data.write().remove(&peer_id);
        }
        result
    }
```

**File:** network/framework/src/application/metadata.rs (L14-18)
```rust
pub enum ConnectionState {
    Connected,
    Disconnecting,
    Disconnected, // Currently unused (TODO: fix this!)
}
```

**File:** network/framework/src/application/metadata.rs (L50-53)
```rust
    /// Returns true iff the peer is still connected
    pub fn is_connected(&self) -> bool {
        self.connection_state == ConnectionState::Connected
    }
```

**File:** network/framework/src/peer_manager/mod.rs (L468-486)
```rust
            ConnectionRequest::DisconnectPeer(peer_id, disconnect_reason, resp_tx) => {
                // Update the connection disconnect metrics
                counters::update_network_connection_operation_metrics(
                    &self.network_context,
                    counters::DISCONNECT_LABEL.into(),
                    disconnect_reason.get_label(),
                );

                // Send a CloseConnection request to Peer and drop the send end of the
                // PeerRequest channel.
                if let Some((conn_metadata, sender)) = self.active_peers.remove(&peer_id) {
                    let connection_id = conn_metadata.connection_id;
                    self.remove_peer_from_metadata(conn_metadata.remote_peer_id, connection_id);

                    // This triggers a disconnect.
                    drop(sender);
                    // Add to outstanding disconnect requests.
                    self.outstanding_disconnect_requests
                        .insert(connection_id, resp_tx);
```

**File:** network/framework/src/peer_manager/mod.rs (L488-494)
```rust
                    info!(
                        NetworkSchema::new(&self.network_context).remote_peer(&peer_id),
                        "{} Connection with peer: {} was already closed",
                        self.network_context,
                        peer_id.short_str(),
                    );
                    if let Err(err) = resp_tx.send(Err(PeerManagerError::NotConnected(peer_id))) {
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

**File:** network/framework/src/protocols/health_checker/mod.rs (L229-263)
```rust
                _ = ticker.select_next_some() => {
                    self.round += 1;
                    let connected = self.network_interface.connected_peers();
                    if connected.is_empty() {
                        trace!(
                            NetworkSchema::new(&self.network_context),
                            round = self.round,
                            "{} No connected peer to ping round: {}",
                            self.network_context,
                            self.round
                        );
                        continue
                    }

                    for peer_id in connected {
                        let nonce = self.rng.r#gen::<u32>();
                        trace!(
                            NetworkSchema::new(&self.network_context),
                            round = self.round,
                            "{} Will ping: {} for round: {} nonce: {}",
                            self.network_context,
                            peer_id.short_str(),
                            self.round,
                            nonce
                        );

                        tick_handlers.push(Self::ping_peer(
                            self.network_context,
                            self.network_interface.network_client(),
                            peer_id,
                            self.round,
                            nonce,
                            self.ping_timeout,
                        ));
                    }
```

**File:** network/framework/src/protocols/health_checker/mod.rs (L373-380)
```rust
                    if let Err(err) = timeout(
                        Duration::from_millis(50),
                        self.network_interface.disconnect_peer(
                            peer_network_id,
                            DisconnectReason::NetworkHealthCheckFailure,
                        ),
                    )
                    .await
```

**File:** peer-monitoring-service/client/src/lib.rs (L229-250)
```rust
            // Get all peers
            let all_peers = peers_and_metadata.get_all_peers();

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

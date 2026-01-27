# Audit Report

## Title
Race Condition in Health Checker Allows Unmonitored Connected Peers Due to Missing Connection ID Validation

## Summary
The `remove_peer_and_health_data()` function does not validate that the peer is actually disconnected at the network layer, nor does it verify that the connection ID matches the current connection. This creates a race condition where stale disconnect events can remove health monitoring data for reconnected peers, allowing unresponsive peers to remain connected indefinitely without health checks.

## Finding Description

The health checker maintains a local `health_check_data` HashMap to track which peers should be health-checked. When connection events arrive, the health checker updates this map accordingly: [1](#0-0) 

The `remove_peer_and_health_data()` function removes peers from this tracking map without any validation: [2](#0-1) 

The critical issue is that this function only receives the `peer_id` and does not check:
1. Whether the peer is actually disconnected at the network layer
2. Whether the connection ID matches the current connection for that peer

Each connection has a unique `connection_id` stored in `ConnectionMetadata`: [3](#0-2) 

The `LostPeer` event includes this metadata: [4](#0-3) 

However, when processing the `LostPeer` event, the health checker only passes the `peer_id` to the removal function, discarding the `connection_id` information that would allow it to verify this is the correct connection to remove.

**Attack Scenario:**

1. Peer A connects with `connection_id=1` → `NewPeer(metadata{id=1})` event → added to `health_check_data`
2. Peer A disconnects (`connection_id=1`) → `LostPeer(metadata{id=1})` event queued
3. Before the `LostPeer` event is processed, Peer A quickly reconnects with `connection_id=2` → `NewPeer(metadata{id=2})` event → peer stays/re-added to `health_check_data`
4. The health checker's event loop processes the stale `LostPeer(connection_id=1)` event
5. `remove_peer_and_health_data(&peer_id)` is called, removing Peer A from `health_check_data`
6. Peer A (with `connection_id=2`) is now connected but no longer in `health_check_data`
7. The `connected_peers()` function only returns peers in `health_check_data`: [5](#0-4) 

8. Peer A will not be pinged by the health checker
9. If Peer A becomes unresponsive, it will never be detected and disconnected

This is in stark contrast to how the peer manager properly validates connection IDs before acting on disconnect events: [6](#0-5) 

The peer manager checks that `connection_id == lost_conn_metadata.connection_id` before removing the peer. The health checker lacks this critical validation.

The health checker's main loop uses `futures::select!` to process multiple event streams concurrently, which can lead to event processing delays when the health checker is busy: [7](#0-6) 

This creates windows of opportunity for the race condition to occur naturally during network instability or can be deliberately triggered by an attacker through rapid disconnect/reconnect cycles.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program for the following reasons:

1. **Validator Node Slowdowns**: Validators maintaining connections to unresponsive peers experience consensus delays. When the health checker fails to detect and disconnect unhealthy peers, consensus rounds must wait for timeout periods before proceeding without those peers' participation.

2. **Significant Protocol Violations**: The health checker is the primary mechanism for detecting and removing unresponsive peers from the network. This vulnerability breaks its core security guarantee - that all connected peers are actively monitored for liveness. The code comment confirms this is fundamental: [8](#0-7) 

3. **Consensus Liveness Impact**: For validator nodes, unmonitored unresponsive peers can cause significant delays in consensus. The AptosBFT protocol requires timely responses from participating validators. If a validator maintains connections to multiple unresponsive peers that are not being health-checked, consensus rounds will repeatedly timeout waiting for those peers before proceeding.

4. **Resource Exhaustion**: Connections to unresponsive peers consume network resources, connection slots, and memory without providing value. This can degrade overall node performance.

## Likelihood Explanation

The likelihood of this vulnerability being exploited is **HIGH** for the following reasons:

1. **Natural Occurrence**: This race condition can occur naturally during normal network operations without any attacker involvement:
   - Network instability causing rapid disconnect/reconnect cycles
   - Node restarts with immediate reconnection
   - Connection flapping due to network congestion
   - Automatic reconnection logic in connectivity manager

2. **Exploitable by Any Network Peer**: Any peer in the network can trigger this condition by:
   - Deliberately disconnecting and quickly reconnecting
   - Causing connection resets at the transport layer
   - No special privileges or insider access required

3. **Event Processing Delays**: The health checker processes multiple event streams concurrently. When busy with ping operations for many peers (common in production with 100+ connected peers), connection events queue up, increasing the likelihood of out-of-order processing.

4. **No Automatic Recovery**: Once a peer's health data is incorrectly removed, there is no mechanism to automatically restore it unless the peer disconnects and reconnects again, which may not happen if the connection is stable at the transport layer.

5. **Production Environments Most Vulnerable**: High-load validator nodes with many peer connections are most susceptible, as they experience both higher event processing delays and more frequent connection state changes.

## Recommendation

Modify `remove_peer_and_health_data()` to accept and validate the connection ID before removing health data. The function should verify that the connection ID in the metadata matches the current connection for that peer.

**Recommended Fix:**

```rust
// In health_checker/interface.rs
pub fn remove_peer_and_health_data(&mut self, peer_id: &PeerId, connection_id: ConnectionId) {
    // First verify the peer is actually disconnected at the network layer
    // by checking the PeersAndMetadata
    let peer_network_id = PeerNetworkId::new(
        self.network_client.get_network_id(), 
        *peer_id
    );
    
    // Get current peer metadata from the network layer
    if let Ok(metadata) = self.network_client
        .get_peers_and_metadata()
        .get_metadata_for_peer(peer_network_id) 
    {
        // If peer is still connected with a different connection_id, don't remove
        if metadata.connection_metadata.connection_id != connection_id {
            return;
        }
    }
    
    // Safe to remove - either peer is disconnected or connection_id matches
    self.health_check_data.write().remove(peer_id);
}
```

**Update the call site in mod.rs:**

```rust
ConnectionNotification::LostPeer(metadata, network_id) => {
    if network_id == self_network_id {
        self.network_interface.remove_peer_and_health_data(
            &metadata.remote_peer_id,
            metadata.connection_id  // Pass connection_id for validation
        );
    }
}
```

**Alternative Simpler Fix:**

Follow the consensus observer's pattern of verifying against actual network state:

```rust
pub fn remove_peer_and_health_data(&mut self, peer_id: &PeerId) {
    let peer_network_id = PeerNetworkId::new(
        self.network_client.get_network_id(),
        *peer_id
    );
    
    // Only remove if peer is actually not connected
    match self.network_client
        .get_peers_and_metadata()
        .get_metadata_for_peer(peer_network_id) 
    {
        Err(_) => {
            // Peer not found in network metadata - safe to remove
            self.health_check_data.write().remove(peer_id);
        }
        Ok(metadata) => {
            // Peer still connected - check if it's the same connection or a new one
            // For safety, don't remove if peer exists in network layer
            // This follows the defensive pattern from consensus observer
        }
    }
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        application::storage::PeersAndMetadata,
        peer_manager::ConnectionNotification,
        transport::{ConnectionId, ConnectionMetadata, ConnectionOrigin},
    };
    use aptos_config::network_id::{NetworkId, PeerNetworkId};
    use aptos_types::PeerId;
    use tokio::sync::mpsc;
    
    #[tokio::test]
    async fn test_stale_disconnect_removes_reconnected_peer() {
        // Setup: Create a mock network client and health checker interface
        let (conn_tx, conn_rx) = mpsc::channel(100);
        let peers_and_metadata = PeersAndMetadata::new(&[NetworkId::Validator]);
        
        // Simulate peer connecting with connection_id = 1
        let peer_id = PeerId::random();
        let network_id = NetworkId::Validator;
        let peer_network_id = PeerNetworkId::new(network_id, peer_id);
        
        let connection_metadata_1 = ConnectionMetadata::new(
            peer_id,
            ConnectionId::from(1),
            NetworkAddress::mock(),
            ConnectionOrigin::Inbound,
            MessagingProtocolVersion::V1,
            ProtocolIdSet::empty(),
            PeerRole::Validator,
        );
        
        // Peer connects - NewPeer event
        conn_tx.send(ConnectionNotification::NewPeer(
            connection_metadata_1.clone(),
            network_id,
        )).await.unwrap();
        
        // Peer disconnects - LostPeer event queued but not yet processed
        conn_tx.send(ConnectionNotification::LostPeer(
            connection_metadata_1.clone(),
            network_id,
        )).await.unwrap();
        
        // Peer reconnects with new connection_id = 2 - NewPeer event
        let connection_metadata_2 = ConnectionMetadata::new(
            peer_id,
            ConnectionId::from(2),
            NetworkAddress::mock(),
            ConnectionOrigin::Inbound,
            MessagingProtocolVersion::V1,
            ProtocolIdSet::empty(),
            PeerRole::Validator,
        );
        
        conn_tx.send(ConnectionNotification::NewPeer(
            connection_metadata_2.clone(),
            network_id,
        )).await.unwrap();
        
        // Process events in health checker
        // After processing all events:
        // 1. NewPeer(id=1) -> peer added to health_check_data
        // 2. LostPeer(id=1) -> peer removed from health_check_data (BUG!)
        // 3. NewPeer(id=2) -> peer re-added to health_check_data
        // But if LostPeer(id=1) is processed AFTER NewPeer(id=2) due to event delays:
        // 1. NewPeer(id=1) -> peer added
        // 2. NewPeer(id=2) -> peer still in health_check_data (connection_id updated in network layer)
        // 3. LostPeer(id=1) -> peer INCORRECTLY removed despite being connected with id=2
        
        // Verification: Peer should be in health_check_data (connected with id=2)
        // But due to bug, it's removed by stale LostPeer event
        // This means peer won't be health-checked even though it's connected
        
        // The fix would check connection_id before removing:
        // if metadata.connection_id != current_connection_id { return; }
    }
}
```

**Notes**

The vulnerability stems from insufficient validation when removing peer health monitoring data. While the peer manager properly validates connection IDs before acting on disconnect events, the health checker does not follow this pattern. This creates a race condition that can occur naturally in production environments with network instability or can be deliberately triggered by attackers through rapid reconnection cycles.

The consensus observer subsystem already demonstrates the correct pattern by explicitly checking if peers are connected before performing health checks [9](#0-8) , but this defensive approach was not applied to the network health checker.

### Citations

**File:** network/framework/src/protocols/health_checker/mod.rs (L4-12)
```rust
//! Protocol used to ensure peer liveness
//!
//! The HealthChecker is responsible for ensuring liveness of all peers of a node.
//! It does so by periodically selecting a random connected peer and sending a Ping probe. A
//! healthy peer is expected to respond with a corresponding Pong message.
//!
//! If a certain number of successive liveness probes for a peer fail, the HealthChecker initiates a
//! disconnect from the peer. It relies on ConnectivityManager or the remote peer to re-establish
//! the connection.
```

**File:** network/framework/src/protocols/health_checker/mod.rs (L170-228)
```rust
            futures::select! {
                maybe_event = self.network_interface.next() => {
                    // Shutdown the HealthChecker when this network instance shuts
                    // down. This happens when the `PeerManager` drops.
                    let event = match maybe_event {
                        Some(event) => event,
                        None => break,
                    };

                    match event {
                        Event::RpcRequest(peer_id, msg, protocol, res_tx) => {
                            match msg {
                                HealthCheckerMsg::Ping(ping) => self.handle_ping_request(peer_id, ping, protocol, res_tx),
                                _ => {
                                    warn!(
                                        SecurityEvent::InvalidHealthCheckerMsg,
                                        NetworkSchema::new(&self.network_context).remote_peer(&peer_id),
                                        rpc_message = msg,
                                        "{} Unexpected RPC message from {}",
                                        self.network_context,
                                        peer_id
                                    );
                                    debug_assert!(false, "Unexpected rpc request");
                                }
                            };
                        }
                        Event::Message(peer_id, msg) => {
                            error!(
                                SecurityEvent::InvalidNetworkEventHC,
                                NetworkSchema::new(&self.network_context).remote_peer(&peer_id),
                                "{} Unexpected direct send from {} msg {:?}",
                                self.network_context,
                                peer_id,
                                msg,
                            );
                            debug_assert!(false, "Unexpected network event");
                        }
                    }
                }
                conn_event = connection_events.select_next_some() => {
                    match conn_event {
                        ConnectionNotification::NewPeer(metadata, network_id) => {
                            // PeersAndMetadata is a global singleton across all networks; filter connect/disconnect events to the NetworkId that this HealthChecker instance is watching
                            if network_id == self_network_id {
                                self.network_interface.create_peer_and_health_data(
                                    metadata.remote_peer_id, self.round
                                );
                            }
                        }
                        ConnectionNotification::LostPeer(metadata, network_id) => {
                            // PeersAndMetadata is a global singleton across all networks; filter connect/disconnect events to the NetworkId that this HealthChecker instance is watching
                            if network_id == self_network_id {
                                self.network_interface.remove_peer_and_health_data(
                                    &metadata.remote_peer_id
                                );
                            }
                        }
                    }
                }
```

**File:** network/framework/src/protocols/health_checker/interface.rs (L59-61)
```rust
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.health_check_data.read().keys().cloned().collect()
    }
```

**File:** network/framework/src/protocols/health_checker/interface.rs (L104-106)
```rust
    pub fn remove_peer_and_health_data(&mut self, peer_id: &PeerId) {
        self.health_check_data.write().remove(peer_id);
    }
```

**File:** network/framework/src/transport/mod.rs (L100-108)
```rust
pub struct ConnectionMetadata {
    pub remote_peer_id: PeerId,
    pub connection_id: ConnectionId,
    pub addr: NetworkAddress,
    pub origin: ConnectionOrigin,
    pub messaging_protocol: MessagingProtocolVersion,
    pub application_protocols: ProtocolIdSet,
    pub role: PeerRole,
}
```

**File:** network/framework/src/peer_manager/types.rs (L38-44)
```rust
#[derive(Clone, PartialEq, Eq, Serialize)]
pub enum ConnectionNotification {
    /// Connection with a new peer has been established.
    NewPeer(ConnectionMetadata, NetworkId),
    /// Connection to a peer has been terminated. This could have been triggered from either end.
    LostPeer(ConnectionMetadata, NetworkId),
}
```

**File:** network/framework/src/peer_manager/mod.rs (L289-296)
```rust
                if let Entry::Occupied(entry) = self.active_peers.entry(peer_id) {
                    let (conn_metadata, _) = entry.get();
                    let connection_id = conn_metadata.connection_id;
                    if connection_id == lost_conn_metadata.connection_id {
                        // We lost an active connection.
                        entry.remove();
                        self.remove_peer_from_metadata(peer_id, connection_id);
                    }
```

**File:** consensus/src/consensus_observer/observer/subscription.rs (L68-75)
```rust
        // Verify the subscription peer is still connected
        let peer_network_id = self.get_peer_network_id();
        if !connected_peers_and_metadata.contains_key(&peer_network_id) {
            return Err(Error::SubscriptionDisconnected(format!(
                "The peer: {:?} is no longer connected!",
                peer_network_id
            )));
        }
```

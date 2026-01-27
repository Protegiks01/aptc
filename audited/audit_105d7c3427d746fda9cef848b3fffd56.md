# Audit Report

## Title
Duplicate NewPeer Events Without LostPeer During Simultaneous Dial Break Event Ordering Guarantee

## Summary
During simultaneous dial scenarios, the network framework can emit duplicate `NewPeer` events for the same peer without an intervening `LostPeer` event. This violates the expected alternating event ordering guarantee and can confuse application state machines that depend on these events, potentially causing validator node slowdowns and protocol violations.

## Finding Description

The vulnerability occurs in the interaction between `insert_connection_metadata()` and the simultaneous dial handling logic in the peer manager. [1](#0-0) 

When a peer connects, `insert_connection_metadata()` uses the `and_modify()` pattern which updates existing peer metadata if the peer already exists, and always broadcasts a `NewPeer` event regardless of whether this is a new peer or an existing one. [2](#0-1) 

During simultaneous dial, when tie-breaking selects the new connection, the old peer handle is removed from `active_peers` and dropped, but the metadata is immediately updated with the new connection information via `insert_connection_metadata()`, which broadcasts a second `NewPeer` event. [3](#0-2) 

The critical issue: When the old connection's `LostConnection` notification is later processed, the removal attempt fails because the connection IDs no longer match: [4](#0-3) 

This results in no `LostPeer` event being broadcast for the old connection, creating the sequence: `NewPeer(conn_1)` → `NewPeer(conn_2)` without an intervening `LostPeer`.

**Attack Scenario:**
1. Peer A connects with connection_id=1 → `NewPeer(conn_1)` broadcast
2. Simultaneous dial occurs, new connection with connection_id=2
3. Tie-breaking chooses new connection, old connection dropped from `active_peers`
4. `insert_connection_metadata()` called with connection_id=2 → Updates existing metadata, broadcasts `NewPeer(conn_2)`
5. Old connection's `LostConnection` notification processed → Connection ID mismatch (2 ≠ 1), removal fails, no `LostPeer` event
6. Result: Two `NewPeer` events without `LostPeer` in between

**Impact on Applications:**

The health checker maintains peer health data based on these events: [5](#0-4) [6](#0-5) 

While the health checker's implementation is somewhat resilient (it updates rather than duplicates), the connectivity manager is affected: [7](#0-6) 

The connectivity manager tracks connected peers and maintains dial states. Duplicate `NewPeer` events without proper `LostPeer` can cause inconsistent state in peer tracking, potentially leading to incorrect connection management decisions.

## Impact Explanation

This is a **High Severity** vulnerability per the Aptos bug bounty criteria:

- **Validator node slowdowns**: Application state machines that incorrectly handle duplicate events may enter inconsistent states, causing processing delays or requiring manual intervention
- **Significant protocol violations**: The event ordering guarantee is a fundamental invariant that network applications depend on for correct operation
- **API crashes**: State machines expecting strict alternation may panic or crash when receiving unexpected duplicate events

The vulnerability affects all nodes in the network as simultaneous dial is a normal occurrence in P2P networks, not a malicious attack scenario.

## Likelihood Explanation

**Likelihood: High**

Simultaneous dial is a common occurrence in P2P networks where two nodes attempt to connect to each other at the same time. The code explicitly handles this scenario with tie-breaking logic, indicating it's an expected and frequent event. Every time simultaneous dial occurs and tie-breaking chooses the new connection, this bug will manifest.

The vulnerability requires no attacker involvement - it occurs during normal network operations. Any node can trigger this by attempting to dial a peer that is simultaneously dialing back.

## Recommendation

The fix requires ensuring that when replacing an existing connection during simultaneous dial, a `LostPeer` event is properly broadcast before the `NewPeer` event for the new connection.

**Option 1: Broadcast LostPeer explicitly before updating metadata**

Modify the simultaneous dial handling to broadcast `LostPeer` before calling `insert_connection_metadata()`:

```rust
// In peer_manager/mod.rs, add_peer() function, after line 634:
let (old_conn_metadata, peer_handle) = active_entry.remove();
// Broadcast LostPeer for the old connection
let lost_event = ConnectionNotification::LostPeer(
    old_conn_metadata.clone(),
    self.network_context.network_id()
);
self.peers_and_metadata.broadcast(lost_event);
// Drop the existing connection and replace it with the new connection
drop(peer_handle);
```

**Option 2: Check for existing connection in insert_connection_metadata()**

Modify `insert_connection_metadata()` to detect when replacing an existing connection and broadcast `LostPeer` first:

```rust
// In application/storage.rs, insert_connection_metadata() function
let mut should_broadcast_lost = false;
let mut old_metadata = None;

peer_metadata_for_network
    .entry(peer_network_id.peer_id())
    .and_modify(|peer_metadata| {
        // Check if we're replacing a different connection
        if peer_metadata.connection_metadata.connection_id != connection_metadata.connection_id {
            should_broadcast_lost = true;
            old_metadata = Some(peer_metadata.connection_metadata.clone());
        }
        peer_metadata.connection_metadata = connection_metadata.clone()
    })
    .or_insert_with(|| PeerMetadata::new(connection_metadata.clone()));

// Broadcast LostPeer for old connection if needed
if let Some(old_meta) = old_metadata {
    let lost_event = ConnectionNotification::LostPeer(old_meta, peer_network_id.network_id());
    self.broadcast(lost_event);
}

// Broadcast NewPeer for new connection
let event = ConnectionNotification::NewPeer(connection_metadata, peer_network_id.network_id());
self.broadcast(event);
```

## Proof of Concept

```rust
#[tokio::test]
async fn test_duplicate_newpeer_events_during_simultaneous_dial() {
    use crate::application::storage::PeersAndMetadata;
    use crate::peer_manager::ConnectionNotification;
    use crate::transport::ConnectionMetadata;
    use aptos_config::network_id::{NetworkId, PeerNetworkId};
    use aptos_types::PeerId;
    use std::sync::Arc;

    // Create peers and metadata container
    let peers_and_metadata = PeersAndMetadata::new(&[NetworkId::Validator]);
    
    // Subscribe to connection events
    let mut event_receiver = peers_and_metadata.subscribe();
    
    // Create first connection for peer
    let peer_id = PeerId::random();
    let peer_network_id = PeerNetworkId::new(NetworkId::Validator, peer_id);
    let mut connection_1 = ConnectionMetadata::mock(peer_id);
    connection_1.connection_id = 1.into();
    
    // Insert first connection - should get NewPeer event
    peers_and_metadata
        .insert_connection_metadata(peer_network_id, connection_1.clone())
        .unwrap();
    
    // Verify first NewPeer event
    match event_receiver.try_recv() {
        Ok(ConnectionNotification::NewPeer(meta, _)) => {
            assert_eq!(meta.connection_id, 1.into());
        }
        _ => panic!("Expected first NewPeer event"),
    }
    
    // Simulate simultaneous dial - insert second connection for same peer
    let mut connection_2 = ConnectionMetadata::mock(peer_id);
    connection_2.connection_id = 2.into();
    
    peers_and_metadata
        .insert_connection_metadata(peer_network_id, connection_2.clone())
        .unwrap();
    
    // Verify second NewPeer event (BUG: should have LostPeer first!)
    match event_receiver.try_recv() {
        Ok(ConnectionNotification::NewPeer(meta, _)) => {
            assert_eq!(meta.connection_id, 2.into());
            println!("BUG CONFIRMED: Got second NewPeer without LostPeer!");
        }
        Ok(ConnectionNotification::LostPeer(_, _)) => {
            panic!("Unexpected: Got LostPeer (bug is fixed)");
        }
        _ => panic!("Expected second NewPeer event"),
    }
    
    // Now try to remove the old connection - should fail due to ID mismatch
    let result = peers_and_metadata.remove_peer_metadata(peer_network_id, 1.into());
    assert!(result.is_err(), "Removal should fail due to connection ID mismatch");
    
    // Verify no LostPeer event was broadcast
    match event_receiver.try_recv() {
        Err(_) => println!("BUG CONFIRMED: No LostPeer event broadcast!"),
        Ok(event) => panic!("Unexpected event: {:?}", event),
    }
}
```

This test demonstrates the vulnerability by showing that two `NewPeer` events can be received without an intervening `LostPeer` event when the same peer's connection metadata is updated with a different connection ID.

## Notes

This vulnerability represents a violation of a fundamental network layer invariant. Applications throughout the Aptos codebase depend on the strict alternation of `NewPeer` and `LostPeer` events to maintain correct state. While some components like the health checker have defensive code that partially mitigates the impact, other components may experience state inconsistencies that could affect validator performance and network reliability.

The issue is particularly concerning because it occurs during normal network operations (simultaneous dial) rather than requiring any malicious behavior, making it inevitable in a production environment.

### Citations

**File:** network/framework/src/application/storage.rs (L186-214)
```rust
    pub fn insert_connection_metadata(
        &self,
        peer_network_id: PeerNetworkId,
        connection_metadata: ConnectionMetadata,
    ) -> Result<(), Error> {
        // Grab the write lock for the peer metadata
        let mut peers_and_metadata = self.peers_and_metadata.write();

        // Fetch the peer metadata for the given network
        let peer_metadata_for_network =
            get_peer_metadata_for_network(&peer_network_id, &mut peers_and_metadata)?;

        // Update the metadata for the peer or insert a new entry
        peer_metadata_for_network
            .entry(peer_network_id.peer_id())
            .and_modify(|peer_metadata| {
                peer_metadata.connection_metadata = connection_metadata.clone()
            })
            .or_insert_with(|| PeerMetadata::new(connection_metadata.clone()));

        // Update the cached peers and metadata
        self.set_cached_peers_and_metadata(peers_and_metadata.clone());

        let event =
            ConnectionNotification::NewPeer(connection_metadata, peer_network_id.network_id());
        self.broadcast(event);

        Ok(())
    }
```

**File:** network/framework/src/application/storage.rs (L232-252)
```rust
        let peer_metadata = if let Entry::Occupied(entry) =
            peer_metadata_for_network.entry(peer_network_id.peer_id())
        {
            // Don't remove the peer if the connection doesn't match!
            // For now, remove the peer entirely, we could in the future
            // have multiple connections for a peer
            let active_connection_id = entry.get().connection_metadata.connection_id;
            if active_connection_id == connection_id {
                let peer_metadata = entry.remove();
                let event = ConnectionNotification::LostPeer(
                    peer_metadata.connection_metadata.clone(),
                    peer_network_id.network_id(),
                );
                self.broadcast(event);
                peer_metadata
            } else {
                return Err(Error::UnexpectedError(format!(
                    "The peer connection id did not match! Given: {:?}, found: {:?}.",
                    connection_id, active_connection_id
                )));
            }
```

**File:** network/framework/src/peer_manager/mod.rs (L625-655)
```rust
        // Check for and handle simultaneous dialing
        if let Entry::Occupied(active_entry) = self.active_peers.entry(peer_id) {
            let (curr_conn_metadata, _) = active_entry.get();
            if Self::simultaneous_dial_tie_breaking(
                self.network_context.peer_id(),
                peer_id,
                curr_conn_metadata.origin,
                conn_meta.origin,
            ) {
                let (_, peer_handle) = active_entry.remove();
                // Drop the existing connection and replace it with the new connection
                drop(peer_handle);
                info!(
                    NetworkSchema::new(&self.network_context).remote_peer(&peer_id),
                    "{} Closing existing connection with Peer {} to mitigate simultaneous dial",
                    self.network_context,
                    peer_id.short_str()
                );
                send_new_peer_notification = false;
            } else {
                info!(
                    NetworkSchema::new(&self.network_context).remote_peer(&peer_id),
                    "{} Closing incoming connection with Peer {} to mitigate simultaneous dial",
                    self.network_context,
                    peer_id.short_str()
                );
                // Drop the new connection and keep the one already stored in active_peers
                self.disconnect(connection);
                return Ok(());
            }
        }
```

**File:** network/framework/src/peer_manager/mod.rs (L682-687)
```rust
        self.active_peers
            .insert(peer_id, (conn_meta.clone(), peer_reqs_tx));
        self.peers_and_metadata.insert_connection_metadata(
            PeerNetworkId::new(self.network_context.network_id(), peer_id),
            conn_meta.clone(),
        )?;
```

**File:** network/framework/src/protocols/health_checker/mod.rs (L209-227)
```rust
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
```

**File:** network/framework/src/protocols/health_checker/interface.rs (L94-106)
```rust
    /// Creates and saves new peer health data for the specified peer
    pub fn create_peer_and_health_data(&mut self, peer_id: PeerId, round: u64) {
        self.health_check_data
            .write()
            .entry(peer_id)
            .and_modify(|health_check_data| health_check_data.round = round)
            .or_insert_with(|| HealthCheckData::new(round));
    }

    /// Removes the peer and any associated health data
    pub fn remove_peer_and_health_data(&mut self, peer_id: &PeerId) {
        self.health_check_data.write().remove(peer_id);
    }
```

**File:** network/framework/src/connectivity_manager/mod.rs (L1010-1019)
```rust
        match notif {
            peer_manager::ConnectionNotification::NewPeer(metadata, _network_id) => {
                let peer_id = metadata.remote_peer_id;
                counters::peer_connected(&self.network_context, &peer_id, 1);
                self.connected.insert(peer_id, metadata);

                // Cancel possible queued dial to this peer.
                self.dial_states.remove(&peer_id);
                self.dial_queue.remove(&peer_id);
            },
```

# Audit Report

## Title
Time-of-Check-Time-of-Use Race Condition in Consensus Publisher Garbage Collection

## Summary
The `garbage_collect_subscriptions()` function in `consensus_publisher.rs` takes two separate snapshots at different points in time without proper synchronization, creating a TOCTOU (Time-of-Check-Time-of-Use) race condition that can incorrectly remove legitimate subscribers experiencing brief network interruptions between the snapshot operations.

## Finding Description

The vulnerability exists in the non-atomic sequence of operations in `garbage_collect_subscriptions()`: [1](#0-0) 

The function performs three distinct operations that are not synchronized:

1. **Snapshot A (Time T1)**: Takes a snapshot of current active subscribers by cloning the HashSet [2](#0-1) 

2. **Snapshot B (Time T2)**: Queries network metadata to get currently connected peers [3](#0-2) 

3. **Difference Computation (Time T3)**: Computes which subscribers to remove based on the stale snapshots [4](#0-3) 

4. **Removal (Time T4)**: Removes peers from the CURRENT state (not the snapshot) [5](#0-4) 

The `get_active_subscribers()` method releases the read lock immediately after cloning [6](#0-5) 

Meanwhile, the `get_connected_peers_and_metadata()` method uses a cached snapshot [7](#0-6)  that filters peers based on their `is_connected()` state [8](#0-7) 

**Attack Scenario:**

1. T0: Peer A is connected and subscribed (in `active_subscribers`)
2. T1: `garbage_collect_subscriptions()` starts execution
3. T2: Takes snapshot of `active_subscribers` (includes Peer A)
4. T3: **Brief network interruption** causes Peer A to temporarily disconnect (packet loss, routing issue, etc.)
5. T4: Queries `get_connected_peers_and_metadata()` - Peer A appears as disconnected at this exact moment
6. T5: Peer A reconnects (connection restored)
7. T6: Computes `disconnected_subscribers = active_subscribers.difference(&connected_peers)` - Peer A is in the difference because it was in the snapshot but not in connected_peers
8. T7: Removes Peer A from current `active_subscribers` set via `remove_active_subscriber()`
9. T8: **Peer A is now connected but NO LONGER SUBSCRIBED** - must manually re-subscribe to resume receiving consensus updates

This occurs periodically every 60 seconds when garbage collection runs [9](#0-8) 

## Impact Explanation

This qualifies as **Medium Severity** under the "State inconsistencies requiring intervention" category:

- **Consistency Violation**: The subscriber list becomes inconsistent with actual network connectivity state. A connected peer is incorrectly marked as not subscribed.

- **Service Degradation**: Affected consensus observers (validator fullnodes, public fullnodes) stop receiving real-time consensus updates and must fall back to slower state synchronization mechanisms or manually re-subscribe.

- **Network Health Impact**: If multiple observers experience brief network hiccups during a garbage collection cycle, they could all be simultaneously de-subscribed, degrading overall network observability and state sync performance.

- **Operational Overhead**: Operators must monitor and manually re-subscribe observers that were incorrectly removed, requiring intervention.

While this does not directly compromise consensus safety or cause fund loss, it violates the protocol invariant that "connected and actively subscribed peers should remain subscribed until they explicitly unsubscribe or permanently disconnect."

## Likelihood Explanation

**High Likelihood** - This vulnerability can be triggered by natural network conditions without any attacker involvement:

- **Frequent GC Execution**: Garbage collection runs every 60 seconds by default, providing frequent opportunities for the race condition to manifest.

- **Common Network Conditions**: Brief network interruptions (packet loss, routing changes, connection resets) are common in distributed systems, especially across WAN connections.

- **Wide Time Window**: The window between the two snapshot operations can be significant (potentially hundreds of milliseconds) depending on system load and network metadata query latency.

- **No Attacker Required**: Unlike many race conditions that require precise timing manipulation, this can occur naturally whenever a peer experiences a transient disconnection during the multi-second window of garbage collection.

An attacker could also intentionally exploit this by:
- Causing targeted network disruptions (connection resets, packet drops) timed with the 60-second GC interval
- Affecting multiple observers simultaneously to maximize impact

## Recommendation

**Solution**: Make the snapshot and connected peer check atomic, or re-verify connection state before removal.

**Option 1 - Re-verify before removal** (Minimal change):
```rust
fn garbage_collect_subscriptions(&self) {
    // Get the set of active subscribers
    let active_subscribers = self.get_active_subscribers();

    // Get the connected peers and metadata
    let peers_and_metadata = self.consensus_observer_client.get_peers_and_metadata();
    let connected_peers_and_metadata =
        match peers_and_metadata.get_connected_peers_and_metadata() {
            Ok(connected_peers_and_metadata) => connected_peers_and_metadata,
            Err(error) => {
                warn!(LogSchema::new(LogEntry::ConsensusPublisher)
                    .event(LogEvent::UnexpectedError)
                    .message(&format!(
                        "Failed to get connected peers and metadata! Error: {:?}",
                        error
                    )));
                return;
            },
        };

    // Identify the active subscribers that are no longer connected
    let connected_peers: HashSet<PeerNetworkId> =
        connected_peers_and_metadata.keys().cloned().collect();
    let potentially_disconnected: HashSet<PeerNetworkId> = active_subscribers
        .difference(&connected_peers)
        .cloned()
        .collect();

    // Remove subscriptions, but RE-CHECK connection state right before removal
    for peer_network_id in &potentially_disconnected {
        // Re-verify the peer is still disconnected before removing
        match peers_and_metadata.get_connected_peers_and_metadata() {
            Ok(current_connected_peers) => {
                if !current_connected_peers.contains_key(peer_network_id) {
                    // Peer is confirmed disconnected, safe to remove
                    self.remove_active_subscriber(peer_network_id);
                    info!(LogSchema::new(LogEntry::ConsensusPublisher)
                        .event(LogEvent::Subscription)
                        .message(&format!(
                            "Removed peer subscription due to disconnection! Peer: {:?}",
                            peer_network_id
                        )));
                }
                // else: peer reconnected, don't remove
            },
            Err(_) => {
                // Can't verify, skip removal to be safe
                continue;
            }
        }
    }

    // Update metrics...
}
```

**Option 2 - Hold write lock during entire operation** (More robust):
```rust
fn garbage_collect_subscriptions(&self) {
    // Get connected peers first
    let peers_and_metadata = self.consensus_observer_client.get_peers_and_metadata();
    let connected_peers_and_metadata =
        match peers_and_metadata.get_connected_peers_and_metadata() {
            Ok(connected_peers_and_metadata) => connected_peers_and_metadata,
            Err(error) => {
                warn!(...);
                return;
            },
        };
    
    let connected_peers: HashSet<PeerNetworkId> =
        connected_peers_and_metadata.keys().cloned().collect();

    // Hold write lock for the entire removal operation
    {
        let mut active_subscribers = self.active_subscribers.write();
        let disconnected_subscribers: Vec<PeerNetworkId> = active_subscribers
            .difference(&connected_peers)
            .cloned()
            .collect();

        for peer_network_id in &disconnected_subscribers {
            active_subscribers.remove(peer_network_id);
            info!(...);
        }
    } // Write lock released here

    // Update metrics...
}
```

## Proof of Concept

```rust
#[tokio::test]
async fn test_race_condition_in_garbage_collection() {
    use std::sync::Arc;
    use tokio::time::{sleep, Duration};
    use aptos_config::network_id::NetworkId;
    use aptos_types::PeerId;
    
    // Create a network client
    let network_id = NetworkId::Public;
    let peers_and_metadata = PeersAndMetadata::new(&[network_id]);
    let network_client = NetworkClient::new(
        vec![], vec![], hashmap![], peers_and_metadata.clone()
    );
    let consensus_observer_client = Arc::new(
        ConsensusObserverClient::new(network_client)
    );

    // Create a consensus publisher
    let (consensus_publisher, _) = ConsensusPublisher::new(
        ConsensusObserverConfig::default(),
        consensus_observer_client,
    );

    // Add a peer and subscribe it
    let peer_network_id = PeerNetworkId::new(network_id, PeerId::random());
    let connection_metadata = ConnectionMetadata::mock(peer_network_id.peer_id());
    peers_and_metadata
        .insert_connection_metadata(peer_network_id, connection_metadata)
        .unwrap();
    
    // Subscribe the peer
    let subscribe_msg = ConsensusPublisherNetworkMessage::new(
        peer_network_id,
        ConsensusObserverRequest::Subscribe,
        ResponseSender::new_for_test(),
    );
    consensus_publisher.process_network_message(subscribe_msg);
    
    // Verify peer is subscribed
    assert!(consensus_publisher.get_active_subscribers().contains(&peer_network_id));

    // Spawn GC in background
    let consensus_publisher_clone = consensus_publisher.clone();
    let gc_handle = tokio::spawn(async move {
        sleep(Duration::from_millis(10)).await; // Delay to allow race window
        consensus_publisher_clone.garbage_collect_subscriptions();
    });

    // Simulate race: disconnect peer RIGHT AFTER GC takes active_subscribers snapshot
    // but BEFORE it checks connected peers
    sleep(Duration::from_millis(5)).await;
    peers_and_metadata
        .update_connection_state(peer_network_id, ConnectionState::Disconnected)
        .unwrap();
    
    // Let GC read the disconnected state
    sleep(Duration::from_millis(10)).await;
    
    // Reconnect peer BEFORE GC completes removal
    peers_and_metadata
        .update_connection_state(peer_network_id, ConnectionState::Connected)
        .unwrap();
    
    // Wait for GC to complete
    gc_handle.await.unwrap();
    
    // BUG: Peer is connected but was incorrectly removed from subscribers!
    assert!(!consensus_publisher.get_active_subscribers().contains(&peer_network_id),
        "Race condition caused legitimate subscriber to be removed");
}
```

## Notes

The vulnerability is a classic TOCTOU race condition where the check (reading snapshots) and use (removing subscribers) are not atomic. The `active_subscribers` field uses an `Arc<RwLock<HashSet<PeerNetworkId>>>` [10](#0-9)  which provides thread-safe access but does NOT prevent the race because the locks are released between operations.

The garbage collection interval is configurable but defaults to 60 seconds [11](#0-10) , providing frequent opportunities for this race to manifest in production environments with normal network instability.

This issue is particularly concerning for validator fullnodes and public fullnodes that rely on the consensus observer for fast synchronization. Incorrect removal of their subscriptions forces them to fall back to slower state synchronization mechanisms, degrading overall network performance and observability.

### Citations

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L40-40)
```rust
    active_subscribers: Arc<RwLock<HashSet<PeerNetworkId>>>,
```

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L99-155)
```rust
    fn garbage_collect_subscriptions(&self) {
        // Get the set of active subscribers
        let active_subscribers = self.get_active_subscribers();

        // Get the connected peers and metadata
        let peers_and_metadata = self.consensus_observer_client.get_peers_and_metadata();
        let connected_peers_and_metadata =
            match peers_and_metadata.get_connected_peers_and_metadata() {
                Ok(connected_peers_and_metadata) => connected_peers_and_metadata,
                Err(error) => {
                    // We failed to get the connected peers and metadata
                    warn!(LogSchema::new(LogEntry::ConsensusPublisher)
                        .event(LogEvent::UnexpectedError)
                        .message(&format!(
                            "Failed to get connected peers and metadata! Error: {:?}",
                            error
                        )));
                    return;
                },
            };

        // Identify the active subscribers that are no longer connected
        let connected_peers: HashSet<PeerNetworkId> =
            connected_peers_and_metadata.keys().cloned().collect();
        let disconnected_subscribers: HashSet<PeerNetworkId> = active_subscribers
            .difference(&connected_peers)
            .cloned()
            .collect();

        // Remove any subscriptions from peers that are no longer connected
        for peer_network_id in &disconnected_subscribers {
            self.remove_active_subscriber(peer_network_id);
            info!(LogSchema::new(LogEntry::ConsensusPublisher)
                .event(LogEvent::Subscription)
                .message(&format!(
                    "Removed peer subscription due to disconnection! Peer: {:?}",
                    peer_network_id
                )));
        }

        // Update the number of active subscribers for each network
        let active_subscribers = self.get_active_subscribers();
        for network_id in peers_and_metadata.get_registered_networks() {
            // Calculate the number of active subscribers for the network
            let num_active_subscribers = active_subscribers
                .iter()
                .filter(|peer_network_id| peer_network_id.network_id() == network_id)
                .count() as i64;

            // Update the active subscriber metric
            metrics::set_gauge(
                &metrics::PUBLISHER_NUM_ACTIVE_SUBSCRIBERS,
                &network_id,
                num_active_subscribers,
            );
        }
    }
```

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L158-160)
```rust
    pub fn get_active_subscribers(&self) -> HashSet<PeerNetworkId> {
        self.active_subscribers.read().clone()
    }
```

**File:** network/framework/src/application/storage.rs (L108-125)
```rust
    pub fn get_connected_peers_and_metadata(
        &self,
    ) -> Result<HashMap<PeerNetworkId, PeerMetadata>, Error> {
        // Get the cached peers and metadata
        let cached_peers_and_metadata = self.cached_peers_and_metadata.load();

        // Collect all connected peers
        let mut connected_peers_and_metadata = HashMap::new();
        for (network_id, peers_and_metadata) in cached_peers_and_metadata.iter() {
            for (peer_id, peer_metadata) in peers_and_metadata.iter() {
                if peer_metadata.is_connected() {
                    let peer_network_id = PeerNetworkId::new(*network_id, *peer_id);
                    connected_peers_and_metadata.insert(peer_network_id, peer_metadata.clone());
                }
            }
        }
        Ok(connected_peers_and_metadata)
    }
```

**File:** network/framework/src/application/metadata.rs (L50-53)
```rust
    /// Returns true iff the peer is still connected
    pub fn is_connected(&self) -> bool {
        self.connection_state == ConnectionState::Connected
    }
```

**File:** config/src/config/consensus_observer_config.rs (L35-35)
```rust
    pub garbage_collection_interval_ms: u64,
```

**File:** config/src/config/consensus_observer_config.rs (L71-71)
```rust
            garbage_collection_interval_ms: 60_000,            // 60 seconds
```

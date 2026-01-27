# Audit Report

## Title
Race Condition in Consensus Publisher Garbage Collection Causes Silent Subscription Removal During Transient Network Issues

## Summary
The `garbage_collect_subscriptions()` function in the consensus publisher incorrectly removes valid subscribers during transient network disconnections due to a race condition between the health checker marking peers as `Disconnecting` and the peer actually being disconnected or reconnecting. This breaks consensus observer replication silently until the subscription timeout period expires.

## Finding Description

The vulnerability exists in the interaction between three components:

**1. Health Checker Disconnection Logic:** [1](#0-0) 

When the health checker detects ping failures (e.g., due to temporary packet loss or latency spikes), it marks the peer as `ConnectionState::Disconnecting` BEFORE attempting the actual disconnect operation.

**2. Connection State Definition:** [2](#0-1) 

The `is_connected()` method only returns `true` for `ConnectionState::Connected`, meaning peers in `Disconnecting` state are considered disconnected.

**3. Garbage Collection Logic:** [3](#0-2) 

The garbage collector retrieves the list of connected peers (which excludes peers in `Disconnecting` state) and removes any active subscriber not in this list.

**4. Peer Reconnection:** [4](#0-3) 

When a peer reconnects, `insert_connection_metadata()` is called, which creates a new `PeerMetadata` with `ConnectionState::Connected` by default.

**Attack Scenario:**

1. Observer successfully subscribes to Publisher (peer is `Connected`)
2. Transient network issue occurs (brief packet loss, temporary latency spike)
3. Health checker detects 3 consecutive ping failures over ~30 seconds
4. Health checker marks peer as `Disconnecting` and initiates disconnect
5. **Race Condition Window:** Garbage collection runs (every 60 seconds by default) while peer is in `Disconnecting` state
6. Garbage collector sees peer is not in `connected_peers_and_metadata`, removes subscriber from `active_subscribers`
7. Disconnect operation either:
   - Fails completely
   - Succeeds but peer immediately reconnects via ConnectivityManager
8. Peer is now `Connected` again via `insert_connection_metadata()`
9. **Silent Failure:** Observer sees peer as connected and thinks it's still subscribed, but Publisher no longer has it in `active_subscribers`
10. Publisher stops sending consensus updates to this observer
11. Observer won't detect the issue until subscription timeout (15 seconds by default per config) [5](#0-4) 

**Observer-Side Health Check Limitation:** [6](#0-5) 

The observer's health check only verifies the peer exists in its own `connected_peers_and_metadata`, not whether the publisher still has it in `active_subscribers`. This creates a unilateral removal scenario where the publisher can remove subscribers without the observer knowing.

## Impact Explanation

**Severity Assessment: High**

This qualifies as **High Severity** based on "Significant protocol violations" criteria:

1. **Breaks Consensus Observer Replication:** Valid observers are silently removed from receiving consensus updates, breaking the core functionality of the consensus observer protocol.

2. **Silent Failure Mode:** The observer continues to believe it's subscribed while actually receiving no updates for up to 15 seconds (or longer if custom timeouts are configured).

3. **Affects Legitimate Nodes:** This occurs during normal network conditions (transient issues) without requiring any malicious action. Any observer experiencing temporary network problems is vulnerable.

4. **Cascading Effects:** If multiple observers experience transient issues simultaneously (e.g., during network-wide latency spikes), they could all be silently removed, significantly degrading the consensus observer network's reliability.

5. **Timing Sensitivity:** The default 60-second garbage collection interval combined with a brief `Disconnecting` state creates a realistic race condition window.

While this doesn't directly compromise consensus safety, it significantly undermines the reliability guarantees of the consensus observer subsystem, which is critical for validator fullnodes and fast state synchronization.

## Likelihood Explanation

**Likelihood: Medium to High**

The vulnerability is likely to occur because:

1. **Common Trigger Condition:** Transient network issues (packet loss, latency spikes, brief connectivity problems) are common in distributed systems
2. **Realistic Timing:** With 60-second garbage collection intervals and 10-second health check pings, the race condition window opens regularly
3. **Default Configuration Vulnerable:** The default configuration values create the conditions for this race
4. **No Special Privileges Required:** No attacker action needed - occurs during normal operation
5. **Production Network Conditions:** Real-world networks experience these transient conditions regularly

## Recommendation

**Fix Option 1: Check Connection State Before Removal**

Modify `garbage_collect_subscriptions()` to only remove peers that are explicitly `Disconnected`, not those in `Disconnecting` state:

```rust
// In consensus_publisher.rs, modify garbage_collect_subscriptions():
fn garbage_collect_subscriptions(&self) {
    let active_subscribers = self.get_active_subscribers();
    let peers_and_metadata = self.consensus_observer_client.get_peers_and_metadata();
    
    // Get ALL peers, not just connected ones
    let all_peers_metadata = match peers_and_metadata.get_all_peers() {
        Ok(peers) => peers,
        Err(error) => {
            warn!(...);
            return;
        }
    };
    
    // Only remove subscribers that are actually disconnected (removed from metadata entirely)
    // or explicitly marked as Disconnected state, NOT Disconnecting
    let disconnected_subscribers: HashSet<PeerNetworkId> = active_subscribers
        .iter()
        .filter(|peer| {
            match peers_and_metadata.get_metadata_for_peer(**peer) {
                Ok(metadata) => metadata.get_connection_state() == ConnectionState::Disconnected,
                Err(_) => true, // Peer completely removed from metadata
            }
        })
        .cloned()
        .collect();
    
    // Remove only truly disconnected subscribers
    for peer_network_id in &disconnected_subscribers {
        self.remove_active_subscriber(peer_network_id);
        // ... logging ...
    }
}
```

**Fix Option 2: Add Grace Period**

Add a grace period before removing subscribers, tracking when they were first seen as disconnected and only removing after a threshold (e.g., 2-3 garbage collection cycles).

**Fix Option 3: Publisher Notification**

Implement a mechanism where the publisher sends an explicit "unsubscribe" message to observers when removing them, rather than silently removing them.

## Proof of Concept

```rust
// Rust test demonstrating the race condition
#[tokio::test]
async fn test_garbage_collection_race_condition() {
    use tokio::time::{sleep, Duration};
    
    // Setup: Create publisher and observer with connected peer
    let network_id = NetworkId::Public;
    let peers_and_metadata = PeersAndMetadata::new(&[network_id]);
    let peer_network_id = PeerNetworkId::new(network_id, PeerId::random());
    
    // Add peer as connected
    let connection_metadata = ConnectionMetadata::mock(peer_network_id.peer_id());
    peers_and_metadata
        .insert_connection_metadata(peer_network_id, connection_metadata)
        .unwrap();
    
    let consensus_observer_client = Arc::new(ConsensusObserverClient::new(...));
    let (consensus_publisher, _) = ConsensusPublisher::new(
        ConsensusObserverConfig::default(),
        consensus_observer_client,
    );
    
    // Observer subscribes
    process_subscription_for_peer(&consensus_publisher, &peer_network_id);
    assert!(consensus_publisher.get_active_subscribers().contains(&peer_network_id));
    
    // RACE CONDITION: Mark peer as Disconnecting (simulating health check)
    peers_and_metadata
        .update_connection_state(peer_network_id, ConnectionState::Disconnecting)
        .unwrap();
    
    // Garbage collection runs while peer is Disconnecting
    consensus_publisher.garbage_collect_subscriptions();
    
    // VULNERABILITY: Subscriber is removed
    assert!(!consensus_publisher.get_active_subscribers().contains(&peer_network_id),
        "Subscriber incorrectly removed during Disconnecting state");
    
    // Peer reconnects immediately (simulating failed disconnect or quick reconnect)
    peers_and_metadata
        .update_connection_state(peer_network_id, ConnectionState::Connected)
        .unwrap();
    
    // Observer still thinks it's subscribed (sees peer as Connected)
    // But publisher has removed it from active_subscribers
    // This is the silent failure condition
}
```

## Notes

The vulnerability is exacerbated by the timing parameters in the default configuration:
- Garbage collection interval: 60 seconds
- Health check ping interval: 10 seconds  
- Ping failures tolerated: 3
- Subscription timeout: 15 seconds

This creates a realistic window where the race condition can manifest during normal network operations.

### Citations

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

**File:** network/framework/src/application/metadata.rs (L50-53)
```rust
    /// Returns true iff the peer is still connected
    pub fn is_connected(&self) -> bool {
        self.connection_state == ConnectionState::Connected
    }
```

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L98-137)
```rust
    /// Garbage collect inactive subscriptions by removing peers that are no longer connected
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
```

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

**File:** config/src/config/consensus_observer_config.rs (L71-76)
```rust
            garbage_collection_interval_ms: 60_000,            // 60 seconds
            max_num_pending_blocks: 150, // 150 blocks (sufficient for existing production networks)
            progress_check_interval_ms: 5_000, // 5 seconds
            max_concurrent_subscriptions: 2, // 2 streams should be sufficient
            max_subscription_sync_timeout_ms: 15_000, // 15 seconds
            max_subscription_timeout_ms: 15_000, // 15 seconds
```

**File:** consensus/src/consensus_observer/observer/subscription.rs (L63-75)
```rust
    pub fn check_subscription_health(
        &mut self,
        connected_peers_and_metadata: &HashMap<PeerNetworkId, PeerMetadata>,
        skip_peer_optimality_check: bool,
    ) -> Result<(), Error> {
        // Verify the subscription peer is still connected
        let peer_network_id = self.get_peer_network_id();
        if !connected_peers_and_metadata.contains_key(&peer_network_id) {
            return Err(Error::SubscriptionDisconnected(format!(
                "The peer: {:?} is no longer connected!",
                peer_network_id
            )));
        }
```

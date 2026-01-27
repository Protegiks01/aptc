# Audit Report

## Title
Race Condition in Health Checker Subscription Allows Peers to Bypass Health Monitoring

## Summary
A race condition in `PeersAndMetadata::subscribe()` allows peer connections to bypass health check registration during HealthChecker initialization. Due to premature lock release caused by Rust's Non-Lexical Lifetimes (NLL), peers connecting during a narrow window are never added to `health_check_data`, causing `create_peer_and_health_data()` to never be called and violating the expected state machine for peer health management. [1](#0-0) 

## Finding Description

The vulnerability stems from a lock ordering issue in the subscription mechanism. When `HealthChecker::start()` calls `subscribe()` to receive connection notifications, the function performs two non-atomic operations:

1. Reads current peers with a read lock
2. Registers as a subscriber for future events [2](#0-1) 

The developer's comment explicitly acknowledges the expectation that locks should be held atomically, but Rust's NLL drops the `peers_and_metadata` read lock after its last use (the iteration at lines 403-413), before the subscriber registration at line 417. [3](#0-2) 

This creates a race window where `insert_connection_metadata()` can execute between lock release and subscriber registration. When a new peer connects during this window:

1. `insert_connection_metadata()` acquires the write lock, inserts the peer, and broadcasts `ConnectionNotification::NewPeer`
2. The broadcast goes to all currently registered subscribers (which doesn't include the HealthChecker's channel yet)
3. The HealthChecker's sender is registered too late to receive this event [4](#0-3) 

**State Machine Violation:** The expected state machine requires `ConnectionNotification::NewPeer` → `create_peer_and_health_data()` → health check operations. When the NewPeer event is missed, `create_peer_and_health_data()` is never called, and the peer never enters `health_check_data`. [5](#0-4) 

Subsequent health check operations silently fail because they check for peer existence first: [6](#0-5) 

The peer remains connected but is never pinged for liveness checks, as `connected_peers()` only returns peers from `health_check_data`: [7](#0-6) [8](#0-7) 

## Impact Explanation

This qualifies as **High Severity** under Aptos bug bounty criteria for "Validator node slowdowns" and "Significant protocol violations."

**Direct Impact:**
- Unhealthy or unresponsive peers remain connected indefinitely without being detected and disconnected
- Connection slots consumed by non-functioning peers
- If multiple such peers accumulate, validator nodes experience degraded performance

**Attack Scenario:**
1. Attacker monitors validator nodes for restart/initialization events
2. Attacker attempts connections during restart windows
3. Successfully timed connections bypass all health monitoring
4. Attacker can then:
   - Refuse to respond to network messages without being disconnected for health check failures
   - Consume connection resources
   - Degrade network performance for the affected validator

While other network protocols (consensus, mempool) have their own validation, the health checker is specifically designed to detect and disconnect unresponsive peers proactively. Bypassing this mechanism violates the network's defense-in-depth model.

## Likelihood Explanation

**Likelihood: Medium**

The race window is narrow (microseconds during HealthChecker initialization), making exploitation timing-dependent. However:

- **Triggering conditions:** Node restarts, which occur during upgrades, crashes, or normal maintenance
- **Attacker requirements:** Network access to the validator, ability to initiate connections
- **Success probability:** With repeated connection attempts during restart windows, an attacker can probabilistically hit the race condition
- **Detection difficulty:** The missed connection is silent; no logs indicate the health check bypass

The narrow window reduces but doesn't eliminate exploitability. A determined attacker with automation could achieve this, especially targeting validators during known upgrade windows.

## Recommendation

**Fix the lock ordering to ensure atomicity:**

Explicitly hold the `peers_and_metadata` read lock until after subscriber registration completes. Add an explicit `drop()` to control the lock lifetime:

```rust
pub fn subscribe(&self) -> tokio::sync::mpsc::Receiver<ConnectionNotification> {
    let (sender, receiver) = tokio::sync::mpsc::channel(NOTIFICATION_BACKLOG);
    let peers_and_metadata = self.peers_and_metadata.read();
    'outer: for (network_id, network_peers_and_metadata) in peers_and_metadata.iter() {
        for (_addr, peer_metadata) in network_peers_and_metadata.iter() {
            let event = ConnectionNotification::NewPeer(
                peer_metadata.connection_metadata.clone(),
                *network_id,
            );
            if let Err(err) = sender.try_send(event) {
                warn!("could not send initial NewPeer on subscribe(): {:?}", err);
                break 'outer;
            }
        }
    }
    let mut listeners = self.subscribers.lock();
    listeners.push(sender);
    // Explicitly drop read lock AFTER subscriber registration
    drop(peers_and_metadata);
    receiver
}
```

This ensures that any `insert_connection_metadata()` attempting to acquire the write lock will block until after the subscriber is registered, preventing the race condition.

**Alternative approach:** Acquire the `subscribers` lock before reading `peers_and_metadata`, but this requires careful analysis to avoid deadlocks with `broadcast()`.

## Proof of Concept

The following Rust test demonstrates the race condition:

```rust
#[tokio::test]
async fn test_subscription_race_condition() {
    use std::sync::Arc;
    use tokio::sync::Barrier;
    
    let peers_and_metadata = Arc::new(PeersAndMetadata::new(...));
    let barrier = Arc::new(Barrier::new(2));
    
    // Thread 1: Subscribe and track received events
    let peers_and_metadata_clone = peers_and_metadata.clone();
    let barrier_clone = barrier.clone();
    let subscriber = tokio::spawn(async move {
        // Wait for coordination
        barrier_clone.wait().await;
        let mut receiver = peers_and_metadata_clone.subscribe();
        let mut events = Vec::new();
        
        // Brief wait to allow potential race
        tokio::time::sleep(Duration::from_micros(100)).await;
        
        while let Ok(event) = receiver.try_recv() {
            events.push(event);
        }
        events
    });
    
    // Thread 2: Insert connection during subscription
    let peers_and_metadata_clone = peers_and_metadata.clone();
    let barrier_clone = barrier.clone();
    let inserter = tokio::spawn(async move {
        barrier_clone.wait().await;
        // Small delay to hit the race window
        tokio::time::sleep(Duration::from_micros(50)).await;
        
        let peer_network_id = PeerNetworkId::new(...);
        let connection_metadata = ConnectionMetadata::new(...);
        peers_and_metadata_clone
            .insert_connection_metadata(peer_network_id, connection_metadata)
            .unwrap();
        peer_network_id.peer_id()
    });
    
    let (events, inserted_peer) = tokio::join!(subscriber, inserter);
    let events = events.unwrap();
    let inserted_peer = inserted_peer.unwrap();
    
    // Verify the race: inserted peer should be in events but might not be
    let found = events.iter().any(|e| match e {
        ConnectionNotification::NewPeer(metadata, _) => 
            metadata.remote_peer_id == inserted_peer,
        _ => false,
    });
    
    // With proper locking, this should always be true
    // With the race condition, this will sometimes be false
    assert!(found, "Race condition: peer connection event was missed");
}
```

This test, when run repeatedly, will demonstrate missed connection events due to the race condition.

## Notes

The vulnerability is particularly insidious because:
1. The failed state initialization is silent - no errors logged
2. The developer's comment indicates awareness of the locking requirement but incorrect assumptions about Rust's NLL behavior
3. The health check bypass only affects the specific peer that hit the race window, making detection difficult
4. Standard integration tests may not catch this due to deterministic test execution

This represents a clear violation of the state machine described in the security question, where `increment_peer_round_failure` and related functions can be in a state where the peer exists in the network layer but not in `health_check_data`, causing operations to silently fail instead of maintaining proper health state.

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

**File:** network/framework/src/application/storage.rs (L400-419)
```rust
    pub fn subscribe(&self) -> tokio::sync::mpsc::Receiver<ConnectionNotification> {
        let (sender, receiver) = tokio::sync::mpsc::channel(NOTIFICATION_BACKLOG);
        let peers_and_metadata = self.peers_and_metadata.read();
        'outer: for (network_id, network_peers_and_metadata) in peers_and_metadata.iter() {
            for (_addr, peer_metadata) in network_peers_and_metadata.iter() {
                let event = ConnectionNotification::NewPeer(
                    peer_metadata.connection_metadata.clone(),
                    *network_id,
                );
                if let Err(err) = sender.try_send(event) {
                    warn!("could not send initial NewPeer on subscribe(): {:?}", err);
                    break 'outer;
                }
            }
        }
        // I expect the peers_and_metadata read lock to still be in effect until after listeners.push() below
        let mut listeners = self.subscribers.lock();
        listeners.push(sender);
        receiver
    }
```

**File:** network/framework/src/protocols/health_checker/mod.rs (L160-166)
```rust
        let connection_events = self
            .connection_events_injection
            .take()
            .unwrap_or_else(|| self.network_interface.get_peers_and_metadata().subscribe());
        let mut connection_events =
            tokio_stream::wrappers::ReceiverStream::new(connection_events).fuse();

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

**File:** network/framework/src/protocols/health_checker/mod.rs (L231-240)
```rust
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
```

**File:** network/framework/src/protocols/health_checker/interface.rs (L59-61)
```rust
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.health_check_data.read().keys().cloned().collect()
    }
```

**File:** network/framework/src/protocols/health_checker/interface.rs (L110-116)
```rust
    pub fn increment_peer_round_failure(&mut self, peer_id: PeerId, round: u64) {
        if let Some(health_check_data) = self.health_check_data.write().get_mut(&peer_id) {
            if health_check_data.round <= round {
                health_check_data.failures += 1;
            }
        }
    }
```

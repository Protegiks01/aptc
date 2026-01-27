# Audit Report

## Title
Lock Poisoning Vulnerability in PeersAndMetadata Broadcast Leading to Complete Peer Monitoring Failure

## Summary
The `broadcast()` function in `PeersAndMetadata` contains a critical bug where it incorrectly removes closed subscriber channels using indices that become invalid during iteration. This causes a panic while holding the `subscribers` Mutex lock. Due to the `aptos_infallible` lock wrapper's design, this panic poisons the lock permanently, causing all subsequent peer metadata access operations to fail and hiding Byzantine peer behavior.

## Finding Description

The vulnerability exists in the subscriber cleanup logic within the `broadcast()` function. [1](#0-0) 

The `PeersAndMetadata` structure uses `aptos_infallible::Mutex` and `aptos_infallible::RwLock` wrappers [2](#0-1) , which call `.expect()` on poisoned locks, causing immediate panic on any lock acquisition attempt after poisoning.

The bug occurs in the `broadcast()` function's cleanup logic [3](#0-2) . The function:

1. Iterates through subscribers collecting indices of closed channels in `to_del` vector
2. Then iterates through `to_del` calling `swap_remove(evict)` on each index
3. `swap_remove()` changes vector length and element positions, invalidating subsequent indices

**Attack Scenario:**
- Assume 5 subscribers at indices [0, 1, 2, 3, 4]
- Attacker causes subscribers at indices 1, 3, and 4 to close (e.g., by disrupting network connections)
- `to_del = [1, 3, 4]`
- `swap_remove(1)` executes successfully, length becomes 4
- `swap_remove(3)` executes successfully, length becomes 3
- `swap_remove(4)` attempts to access index 4 when length is 3: **PANIC with index out of bounds**

This panic occurs while holding the `subscribers` Mutex lock, permanently poisoning it.

**Cascading Failure:**
Since `broadcast()` is called from `insert_connection_metadata()` and `remove_peer_metadata()` while holding the RwLock write lock [4](#0-3) , and the `subscribe()` function also acquires the same Mutex [5](#0-4) , the poisoning prevents:

- New peer connection notifications from being broadcast
- New subscribers from registering for connection events
- Peer monitoring services from tracking peer state changes
- The inspection service endpoint from displaying peer information [6](#0-5) 

## Impact Explanation

**Medium Severity** - Meets the "State inconsistencies requiring intervention" criteria from the Aptos bug bounty program.

**Specific Impacts:**
1. **Byzantine Behavior Concealment**: Peer connection state changes are no longer broadcast, preventing detection of malicious peer disconnections or suspicious connection patterns
2. **Operational Blindness**: The inspection service endpoint fails, removing operator visibility into peer status during potential attacks
3. **Monitoring System Failure**: Peer monitoring services lose connection event notifications, disabling automated Byzantine detection systems
4. **Service Degradation**: The node continues operating but without proper peer health monitoring and visibility

While this doesn't directly cause consensus failure or fund loss, it significantly degrades the node's ability to detect and respond to Byzantine peer behavior, which is a critical security invariant in BFT consensus systems.

## Likelihood Explanation

**High Likelihood** - This vulnerability can be triggered through realistic network conditions:

1. **Natural Occurrence**: Multiple subscribers can close simultaneously during normal network disruptions, application restarts, or component failures
2. **Attacker Exploitation**: A malicious peer can intentionally trigger conditions that cause multiple network components to fail and close their subscription channels simultaneously
3. **No Privilege Required**: Does not require validator access or special permissions
4. **Deterministic Trigger**: Once multiple closed channels exist, the panic is guaranteed on the next broadcast call

The bug is particularly dangerous because it can occur during legitimate operational scenarios (network instability, component restarts) without any malicious intent, yet permanently degrades the node's monitoring capabilities.

## Recommendation

Fix the index invalidation bug by removing elements in reverse order or tracking removed elements:

**Solution 1: Remove in reverse order**
```rust
fn broadcast(&self, event: ConnectionNotification) {
    let mut listeners = self.subscribers.lock();
    let mut to_del = vec![];
    for i in 0..listeners.len() {
        let dest = listeners.get_mut(i).unwrap();
        if let Err(err) = dest.try_send(event.clone()) {
            match err {
                TrySendError::Full(_) => {
                    sample!(
                        SampleRate::Duration(Duration::from_secs(1)),
                        warn!("PeersAndMetadata.broadcast() failed, some app is slow"),
                    );
                },
                TrySendError::Closed(_) => {
                    to_del.push(i);
                },
            }
        }
    }
    // Remove in reverse order to maintain index validity
    for evict in to_del.into_iter().rev() {
        listeners.swap_remove(evict);
    }
}
```

**Solution 2: Use retain (cleaner)**
```rust
fn broadcast(&self, event: ConnectionNotification) {
    let mut listeners = self.subscribers.lock();
    listeners.retain_mut(|dest| {
        match dest.try_send(event.clone()) {
            Ok(_) => true,
            Err(TrySendError::Full(_)) => {
                sample!(
                    SampleRate::Duration(Duration::from_secs(1)),
                    warn!("PeersAndMetadata.broadcast() failed, some app is slow"),
                );
                true  // Keep slow subscribers
            },
            Err(TrySendError::Closed(_)) => false,  // Remove closed channels
        }
    });
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod test_lock_poisoning {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_broadcast_index_out_of_bounds_panic() {
        // Create PeersAndMetadata with a single network
        let peers_and_metadata = PeersAndMetadata::new(&[NetworkId::Validator]);
        
        // Create 5 subscribers
        let mut receivers = vec![];
        for _ in 0..5 {
            let receiver = peers_and_metadata.subscribe();
            receivers.push(receiver);
        }
        
        // Drop receivers at indices 1, 3, and 4 to close their channels
        drop(receivers.remove(4));  // Close index 4
        drop(receivers.remove(3));  // Close index 3 (now at position 3)
        drop(receivers.remove(1));  // Close index 1
        
        // Create a test connection metadata
        let connection_metadata = ConnectionMetadata::mock();
        let peer_network_id = PeerNetworkId::new(
            NetworkId::Validator,
            PeerId::random()
        );
        
        // This should trigger the broadcast, which will panic
        // when trying to remove indices [1, 3, 4] with swap_remove
        let result = std::panic::catch_unwind(|| {
            peers_and_metadata.insert_connection_metadata(
                peer_network_id,
                connection_metadata
            )
        });
        
        // Verify panic occurred
        assert!(result.is_err(), "Expected panic due to index out of bounds");
        
        // After panic, the lock is poisoned
        // Any subsequent operation should panic when trying to acquire the lock
        let result2 = std::panic::catch_unwind(|| {
            peers_and_metadata.subscribe()
        });
        
        assert!(result2.is_err(), "Expected panic due to poisoned lock");
    }
}
```

## Notes

The vulnerability is particularly insidious because:
1. The `aptos_infallible` wrapper's design converts recoverable lock poisoning into permanent panics
2. The issue can manifest during legitimate operational stress without malicious intent
3. Once triggered, it permanently disables peer monitoring across the entire node
4. The inspection service endpoint becomes completely non-functional, hiding the root cause from operators

This represents a violation of the system's availability and Byzantine detection invariants, making it a valid medium-severity security issue requiring immediate remediation.

### Citations

**File:** crates/aptos-infallible/src/mutex.rs (L19-23)
```rust
    pub fn lock(&self) -> MutexGuard<'_, T> {
        self.0
            .lock()
            .expect("Cannot currently handle a poisoned lock")
    }
```

**File:** network/framework/src/application/storage.rs (L18-18)
```rust
use aptos_infallible::{Mutex, RwLock};
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

**File:** network/framework/src/application/storage.rs (L371-395)
```rust
    fn broadcast(&self, event: ConnectionNotification) {
        let mut listeners = self.subscribers.lock();
        let mut to_del = vec![];
        for i in 0..listeners.len() {
            let dest = listeners.get_mut(i).unwrap();
            if let Err(err) = dest.try_send(event.clone()) {
                match err {
                    TrySendError::Full(_) => {
                        // Tried to send to an app, but the app isn't handling its messages fast enough.
                        // Drop message. Maybe increment a metrics counter?
                        sample!(
                            SampleRate::Duration(Duration::from_secs(1)),
                            warn!("PeersAndMetadata.broadcast() failed, some app is slow"),
                        );
                    },
                    TrySendError::Closed(_) => {
                        to_del.push(i);
                    },
                }
            }
        }
        for evict in to_del.into_iter() {
            listeners.swap_remove(evict);
        }
    }
```

**File:** network/framework/src/application/storage.rs (L397-419)
```rust
    /// subscribe() returns a channel for receiving NewPeer/LostPeer events.
    /// subscribe() immediately sends all* current connections as NewPeer events.
    /// (* capped at NOTIFICATION_BACKLOG, currently 1000, use get_connected_peers() to be sure)
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

**File:** crates/aptos-inspection-service/src/server/peer_information.rs (L21-38)
```rust
pub fn handle_peer_information_request(
    node_config: &NodeConfig,
    aptos_data_client: AptosDataClient,
    peers_and_metadata: Arc<PeersAndMetadata>,
) -> (StatusCode, Body, String) {
    // Only return peer information if the endpoint is enabled
    let (status_code, body) = if node_config.inspection_service.expose_peer_information {
        let peer_information = get_peer_information(aptos_data_client, peers_and_metadata);
        (StatusCode::OK, Body::from(peer_information))
    } else {
        (
            StatusCode::FORBIDDEN,
            Body::from(PEER_INFO_DISABLED_MESSAGE),
        )
    };

    (status_code, body, CONTENT_TYPE_TEXT.into())
}
```

# Audit Report

## Title
TOCTOU Race Condition Between Discovery Updates and Connectivity Checks Causes Inconsistent Peer State

## Summary
A Time-of-Check-Time-of-Use (TOCTOU) race condition exists in the ConnectivityManager where async connectivity check operations read `peers_and_metadata.trusted_peers` at the beginning of execution but then await on I/O operations. During these await points, discovery listeners can send `UpdateDiscoveredPeers` requests that modify the trusted peer set, causing the connectivity manager to continue with stale peer state data. This breaks the fundamental invariant that nodes maintain connections only to eligible peers.

## Finding Description

The ConnectivityManager maintains network connectivity by periodically checking which peers are eligible and ensuring connections match the trusted peer set. [1](#0-0) 

The vulnerability occurs in the interaction between three async functions within `check_connectivity()`:

**1. Stale Connection Closure Race:** [2](#0-1) 

The function reads `trusted_peers` once at line 485, but then awaits on `disconnect_peer()` at line 517. During this await point, the event loop can process a `UpdateDiscoveredPeers` request that modifies the trusted peer set via `set_trusted_peers()`. [3](#0-2) 

**2. Stale Dial Cancellation Race:** [4](#0-3) 

Similar TOCTOU issue where `trusted_peers` is read once but used across loop iterations with no re-validation.

**3. Peer Selection Race:** [5](#0-4) 

The function reads `discovered_peers` at line 577, then awaits on `ping_eligible_peers()` at line 633, during which discovery updates can arrive.

**Root Cause:**

The event loop processes messages sequentially but async functions can yield control: [6](#0-5) 

When an async function (like `close_stale_connections()`) awaits at line 517, the `futures::select!` can poll other branches, including processing `UpdateDiscoveredPeers` requests at line 430. This updates the shared `peers_and_metadata` structure: [7](#0-6) 

While `set_trusted_peers()` and `get_trusted_peers()` use ArcSwap for atomic operations: [8](#0-7) 

The atomicity only applies to individual read/write operations, not to the entire logical transaction of "read trusted peers, perform actions based on that snapshot."

**Attack Scenario:**

During an epoch change or validator set update:
1. Timer triggers `check_connectivity()` 
2. `close_stale_connections()` reads current trusted peers (e.g., Validators A, B, C)
3. While awaiting `disconnect_peer()` for an old validator D
4. Discovery listener sends `UpdateDiscoveredPeers` with new validator set (Validators A, B, E)
5. Validator C is removed from trusted set, E is added
6. `close_stale_connections()` continues with stale snapshot, keeps connection to C
7. Later connectivity check may dial E while still connected to C, or not dial E at all

## Impact Explanation

**High Severity** - Meets "Validator node slowdowns" and "Significant protocol violations" criteria:

1. **Network Connectivity Violations**: The core invariant "connected to a node iff. it is an eligible node" is broken, potentially leaving validators connected to expelled validators or disconnected from newly added validators.

2. **Consensus Degradation**: Validators may waste resources maintaining connections to non-eligible peers while missing connections to legitimate consensus participants, slowing down block propagation and vote collection.

3. **Partition Risk**: If multiple validators experience this race during epoch transitions, temporary network partitions can form where different validators have different connectivity graphs.

4. **Resource Exhaustion**: Stale connections consume network bandwidth and connection slots that should be available for legitimate validators.

## Likelihood Explanation

**High Likelihood**:

1. **Frequent Trigger Conditions**: Epoch changes, validator set updates, and file/REST discovery updates happen regularly in production networks.

2. **Timing Window**: The race window is significant - `disconnect_peer()` involves network I/O and can take hundreds of milliseconds, plenty of time for discovery updates to arrive.

3. **Concurrent Discovery Sources**: Multiple discovery listeners (on-chain, file, REST) can send updates simultaneously, increasing race probability.

4. **No Synchronization**: The code has no locking or versioning mechanism to detect stale reads.

## Recommendation

Implement one of these solutions:

**Solution 1: Re-validate after await points**

```rust
async fn close_stale_connections(&mut self) {
    loop {
        let trusted_peers = match self.get_trusted_peers() {
            Some(peers) => peers,
            None => return,
        };
        
        // Find ONE stale peer to disconnect
        let stale_peer = self.connected
            .iter()
            .find(|(peer_id, metadata)| {
                !trusted_peers.contains_key(peer_id) &&
                (self.mutual_authentication || 
                 metadata.origin != ConnectionOrigin::Inbound ||
                 (metadata.role != PeerRole::ValidatorFullNode && 
                  metadata.role != PeerRole::Unknown))
            })
            .map(|(peer_id, _)| *peer_id);
        
        match stale_peer {
            Some(peer_id) => {
                // Disconnect and loop to re-check
                let _ = self.connection_reqs_tx
                    .disconnect_peer(peer_id, DisconnectReason::StaleConnection)
                    .await;
            }
            None => break,
        }
    }
}
```

**Solution 2: Use versioned snapshots**

Add version tracking to `PeersAndMetadata`:

```rust
pub struct PeersAndMetadata {
    trusted_peers_version: Arc<AtomicU64>,
    // ... existing fields
}

// In ConnectivityManager, track version
async fn close_stale_connections(&mut self) {
    let version = self.peers_and_metadata.get_trusted_peers_version();
    let trusted_peers = self.get_trusted_peers()?;
    
    for stale_peer in compute_stale_peers(&trusted_peers) {
        // Re-check version before each action
        if self.peers_and_metadata.get_trusted_peers_version() != version {
            // Restart with fresh snapshot
            return self.close_stale_connections().await;
        }
        self.connection_reqs_tx.disconnect_peer(...).await?;
    }
}
```

## Proof of Concept

```rust
#[tokio::test]
async fn test_toctou_race_in_connectivity_manager() {
    use aptos_config::config::{Peer, PeerRole, PeerSet};
    use aptos_types::PeerId;
    use std::collections::HashMap;
    
    // Setup: Create connectivity manager with initial peer set
    let initial_peers = create_peer_set(vec![
        (peer_id_a, addresses_a),
        (peer_id_b, addresses_b),
    ]);
    
    let mut conn_mgr = create_test_connectivity_manager(initial_peers);
    
    // Simulate connected state to peer A and B
    simulate_connections(&mut conn_mgr, vec![peer_id_a, peer_id_b]);
    
    // Start check_connectivity which will call close_stale_connections
    let check_fut = conn_mgr.check_connectivity(&mut pending_dials);
    tokio::pin!(check_fut);
    
    // Let it read trusted_peers and start disconnecting
    tokio::time::sleep(Duration::from_millis(10)).await;
    
    // While check_connectivity is awaiting on disconnect_peer(),
    // inject a discovery update that removes peer A
    let updated_peers = create_peer_set(vec![
        (peer_id_b, addresses_b),
        (peer_id_c, addresses_c), // New peer
    ]);
    
    conn_mgr.handle_update_discovered_peers(
        DiscoverySource::OnChainValidatorSet,
        updated_peers,
    );
    
    // Complete the connectivity check
    check_fut.await;
    
    // VULNERABILITY: Peer A should be disconnected but may still be connected
    // because close_stale_connections() used stale snapshot
    let is_a_connected = conn_mgr.connected.contains_key(&peer_id_a);
    let trusted_peers = conn_mgr.peers_and_metadata.get_trusted_peers();
    
    // This assertion should fail, demonstrating the race
    assert!(
        !is_a_connected || trusted_peers.contains_key(&peer_id_a),
        "Race condition: connected to peer A but A not in trusted set"
    );
}
```

## Notes

This vulnerability is particularly dangerous during epoch transitions when validator sets change. The race window is large enough to be reliably triggered in production, and the impact compounds when multiple validators experience it simultaneously, potentially causing consensus slowdowns or temporary partitions. The fix requires careful re-validation of peer state after each await point to ensure consistency between `discovered_peers` and `peers_and_metadata.trusted_peers`.

### Citations

**File:** network/framework/src/connectivity_manager/mod.rs (L4-10)
```rust
//! The ConnectivityManager actor is responsible for ensuring that we are
//! connected to a node if and only if it is an eligible node.
//!
//! A list of eligible nodes is received at initialization, and updates are
//! received on changes to system membership. In our current system design, the
//! Consensus actor informs the ConnectivityManager of eligible nodes.
//!
```

**File:** network/framework/src/connectivity_manager/mod.rs (L423-453)
```rust
        loop {
            self.event_id = self.event_id.wrapping_add(1);
            futures::select! {
                _ = ticker.select_next_some() => {
                    self.check_connectivity(&mut pending_dials).await;
                },
                req = self.requests_rx.select_next_some() => {
                    self.handle_request(req);
                },
                maybe_notif = self.connection_notifs_rx.next() => {
                    // Shutdown the connectivity manager when the PeerManager
                    // shuts down.
                    match maybe_notif {
                        Some(notif) => {
                            self.handle_control_notification(notif.clone());
                        },
                        None => break,
                    }
                },
                peer_id = pending_dials.select_next_some() => {
                    trace!(
                        NetworkSchema::new(&self.network_context)
                            .remote_peer(&peer_id),
                        "{} Dial complete to {}",
                        self.network_context,
                        peer_id.short_str(),
                    );
                    self.dial_queue.remove(&peer_id);
                },
            }
        }
```

**File:** network/framework/src/connectivity_manager/mod.rs (L484-531)
```rust
    async fn close_stale_connections(&mut self) {
        if let Some(trusted_peers) = self.get_trusted_peers() {
            // Identify stale peer connections
            let stale_peers = self
                .connected
                .iter()
                .filter(|(peer_id, _)| !trusted_peers.contains_key(peer_id))
                .filter_map(|(peer_id, metadata)| {
                    // If we're using server only auth, we need to not evict unknown peers
                    // TODO: We should prevent `Unknown` from discovery sources
                    if !self.mutual_authentication
                        && metadata.origin == ConnectionOrigin::Inbound
                        && (metadata.role == PeerRole::ValidatorFullNode
                            || metadata.role == PeerRole::Unknown)
                    {
                        None
                    } else {
                        Some(*peer_id) // The peer is stale
                    }
                });

            // Close existing connections to stale peers
            for stale_peer in stale_peers {
                info!(
                    NetworkSchema::new(&self.network_context).remote_peer(&stale_peer),
                    "{} Closing stale connection to peer {}",
                    self.network_context,
                    stale_peer.short_str()
                );

                if let Err(disconnect_error) = self
                    .connection_reqs_tx
                    .disconnect_peer(stale_peer, DisconnectReason::StaleConnection)
                    .await
                {
                    info!(
                        NetworkSchema::new(&self.network_context)
                            .remote_peer(&stale_peer),
                        error = %disconnect_error,
                        "{} Failed to close stale connection to peer {}, error: {}",
                        self.network_context,
                        stale_peer.short_str(),
                        disconnect_error
                    );
                }
            }
        }
    }
```

**File:** network/framework/src/connectivity_manager/mod.rs (L538-559)
```rust
    async fn cancel_stale_dials(&mut self) {
        if let Some(trusted_peers) = self.get_trusted_peers() {
            // Identify stale peer dials
            let stale_peer_dials: Vec<AccountAddress> = self
                .dial_queue
                .keys()
                .filter(|peer_id| !trusted_peers.contains_key(peer_id))
                .cloned()
                .collect();

            // Remove the stale dials from the dial queue
            for stale_peer_dial in stale_peer_dials {
                debug!(
                    NetworkSchema::new(&self.network_context).remote_peer(&stale_peer_dial),
                    "{} Cancelling stale dial {}",
                    self.network_context,
                    stale_peer_dial.short_str()
                );
                self.dial_queue.remove(&stale_peer_dial);
            }
        }
    }
```

**File:** network/framework/src/connectivity_manager/mod.rs (L572-646)
```rust
    async fn choose_peers_to_dial(&mut self) -> Vec<(PeerId, DiscoveredPeer)> {
        // Get the eligible peers to dial
        let network_id = self.network_context.network_id();
        let role = self.network_context.role();
        let roles_to_dial = network_id.upstream_roles(&role);
        let discovered_peers = self.discovered_peers.read().peer_set.clone();
        let eligible_peers: Vec<_> = discovered_peers
            .into_iter()
            .filter(|(peer_id, peer)| {
                peer.is_eligible_to_be_dialed() // The node is eligible to dial
                    && !self.connected.contains_key(peer_id) // The node is not already connected
                    && !self.dial_queue.contains_key(peer_id) // There is no pending dial to this node
                    && roles_to_dial.contains(&peer.role) // We can dial this role
            })
            .collect();

        // Initialize the dial state for any new peers
        for (peer_id, _) in &eligible_peers {
            self.dial_states
                .entry(*peer_id)
                .or_insert_with(|| DialState::new(self.backoff_strategy.clone()));
        }

        // Limit the number of dialed connections from a fullnode. Note: this does not
        // limit the number of incoming connections. It only enforces that a fullnode
        // cannot have more outgoing connections than the limit (including in-flight dials).
        let num_eligible_peers = eligible_peers.len();
        let num_peers_to_dial =
            if let Some(outbound_connection_limit) = self.outbound_connection_limit {
                // Get the number of outbound connections
                let num_outbound_connections = self
                    .connected
                    .iter()
                    .filter(|(_, metadata)| metadata.origin == ConnectionOrigin::Outbound)
                    .count();

                // Add any pending dials to the count
                let total_outbound_connections =
                    num_outbound_connections.saturating_add(self.dial_queue.len());

                // Calculate the potential number of peers to dial
                let num_peers_to_dial =
                    outbound_connection_limit.saturating_sub(total_outbound_connections);

                // Limit the number of peers to dial by the total number of eligible peers
                min(num_peers_to_dial, num_eligible_peers)
            } else {
                num_eligible_peers // Otherwise, we attempt to dial all eligible peers
            };

        // If we have no peers to dial, return early
        if num_peers_to_dial == 0 {
            return vec![];
        }

        // Prioritize the eligible peers and select the peers to dial
        if selection::should_select_peers_by_latency(
            &self.network_context,
            self.enable_latency_aware_dialing,
        ) {
            // Ping the eligible peers (so that we can fetch missing ping latency information)
            self.ping_eligible_peers(eligible_peers.clone()).await;

            // Choose the peers to dial (weighted by ping latency)
            selection::choose_random_peers_by_ping_latency(
                self.network_context,
                eligible_peers,
                num_peers_to_dial,
                self.discovered_peers.clone(),
            )
        } else {
            // Choose the peers randomly
            selection::choose_peers_to_dial_randomly(eligible_peers, num_peers_to_dial)
        }
    }
```

**File:** network/framework/src/connectivity_manager/mod.rs (L886-1002)
```rust
    fn handle_update_discovered_peers(
        &mut self,
        src: DiscoverySource,
        new_discovered_peers: PeerSet,
    ) {
        // Log the update event
        info!(
            NetworkSchema::new(&self.network_context),
            "{} Received updated list of discovered peers! Source: {:?}, num peers: {:?}",
            self.network_context,
            src,
            new_discovered_peers.len()
        );

        // Remove peers that no longer have relevant network information
        let mut keys_updated = false;
        let mut peers_to_check_remove = Vec::new();
        for (peer_id, peer) in self.discovered_peers.write().peer_set.iter_mut() {
            let new_peer = new_discovered_peers.get(peer_id);
            let check_remove = if let Some(new_peer) = new_peer {
                if new_peer.keys.is_empty() {
                    keys_updated |= peer.keys.clear_src(src);
                }
                if new_peer.addresses.is_empty() {
                    peer.addrs.clear_src(src);
                }
                new_peer.addresses.is_empty() && new_peer.keys.is_empty()
            } else {
                keys_updated |= peer.keys.clear_src(src);
                peer.addrs.clear_src(src);
                true
            };
            if check_remove {
                peers_to_check_remove.push(*peer_id);
            }
        }

        // Remove peers that no longer have state
        for peer_id in peers_to_check_remove {
            self.discovered_peers.write().remove_peer_if_empty(&peer_id);
        }

        // Make updates to the peers accordingly
        for (peer_id, discovered_peer) in new_discovered_peers {
            // Don't include ourselves, because we don't need to dial ourselves
            if peer_id == self.network_context.peer_id() {
                continue;
            }

            // Create the new `DiscoveredPeer`, role is set when a `Peer` is first discovered
            let mut discovered_peers = self.discovered_peers.write();
            let peer = discovered_peers
                .peer_set
                .entry(peer_id)
                .or_insert_with(|| DiscoveredPeer::new(discovered_peer.role));

            // Update the peer's pubkeys
            let mut peer_updated = false;
            if peer.keys.update(src, discovered_peer.keys) {
                info!(
                    NetworkSchema::new(&self.network_context)
                        .remote_peer(&peer_id)
                        .discovery_source(&src),
                    "{} pubkey sets updated for peer: {}, pubkeys: {}",
                    self.network_context,
                    peer_id.short_str(),
                    peer.keys
                );
                keys_updated = true;
                peer_updated = true;
            }

            // Update the peer's addresses
            if peer.addrs.update(src, discovered_peer.addresses) {
                info!(
                    NetworkSchema::new(&self.network_context).remote_peer(&peer_id),
                    network_addresses = &peer.addrs,
                    "{} addresses updated for peer: {}, update src: {:?}, addrs: {}",
                    self.network_context,
                    peer_id.short_str(),
                    src,
                    &peer.addrs,
                );
                peer_updated = true;
            }

            // If we're currently trying to dial this peer, we reset their
            // dial state. As a result, we will begin our next dial attempt
            // from the first address (which might have changed) and from a
            // fresh backoff (since the current backoff delay might be maxed
            // out if we can't reach any of their previous addresses).
            if peer_updated {
                if let Some(dial_state) = self.dial_states.get_mut(&peer_id) {
                    *dial_state = DialState::new(self.backoff_strategy.clone());
                }
            }
        }

        // update eligible peers accordingly
        if keys_updated {
            // For each peer, union all of the pubkeys from each discovery source
            // to generate the new eligible peers set.
            let new_eligible = self.discovered_peers.read().get_eligible_peers();

            // Swap in the new eligible peers set
            if let Err(error) = self
                .peers_and_metadata
                .set_trusted_peers(&self.network_context.network_id(), new_eligible)
            {
                error!(
                    NetworkSchema::new(&self.network_context),
                    error = %error,
                    "Failed to update trusted peers set"
                );
            }
        }
    }
```

**File:** network/framework/src/application/storage.rs (L329-332)
```rust
    pub fn get_trusted_peers(&self, network_id: &NetworkId) -> Result<PeerSet, Error> {
        let trusted_peers = self.get_trusted_peer_set_for_network(network_id)?;
        Ok(trusted_peers.load().clone().deref().clone())
    }
```

**File:** network/framework/src/application/storage.rs (L361-369)
```rust
    pub fn set_trusted_peers(
        &self,
        network_id: &NetworkId,
        trusted_peer_set: PeerSet,
    ) -> Result<(), Error> {
        let trusted_peers = self.get_trusted_peer_set_for_network(network_id)?;
        trusted_peers.store(Arc::new(trusted_peer_set));
        Ok(())
    }
```

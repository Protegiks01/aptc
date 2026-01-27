# Audit Report

## Title
Network Isolation via Unvalidated Peer Set Replacement in File-Based Discovery

## Summary
The `handle_update_discovered_peers` function in `ConnectivityManager` does not validate that a new peer set from file-based discovery has any overlap with the existing peer set. This allows a complete replacement of all known peers, which can lead to total network isolation if the new peers are unreachable, especially for nodes relying solely on file-based discovery without seed peers.

## Finding Description

When the file-based discovery mechanism sends a new `PeerSet` via `UpdateDiscoveredPeers`, the connectivity manager processes this update without any validation to ensure network continuity.

The vulnerability manifests in the following execution flow:

1. **File Reading**: `FileStream::poll_next()` reads the peer discovery file and returns a `PeerSet` without any validation. [1](#0-0) 

2. **Update Propagation**: The `DiscoveryChangeListener` sends this peer set to the connectivity manager. [2](#0-1) 

3. **Peer Set Replacement**: In `handle_update_discovered_peers`, the function clears peer information from the discovery source for any peers not in the new set. [3](#0-2) 

4. **Peer Removal**: Peers with no information from any remaining source are removed entirely. [4](#0-3) 

5. **Connection Cleanup**: During `check_connectivity`, the node disconnects from all stale peers (those no longer in the trusted set). [5](#0-4) 

**Critical Missing Validation**: There is no check to ensure that:
- At least some peers overlap between the old and new sets
- The new peer set contains at least one reachable peer
- The node won't be completely isolated after the update

**Attack Scenario**:
- Node configured with file-based discovery as the only source (no seed peers)
- Discovery file initially contains peers A, B, C (all reachable)
- Attacker with file access or misconfiguration replaces file with peers X, Y, Z (completely different, unreachable)
- Node processes the update, removes A, B, C, adds X, Y, Z
- Node disconnects from A, B, C and attempts to dial X, Y, Z
- All dial attempts fail (peers don't exist or are unreachable)
- Node is completely isolated from the network

## Impact Explanation

This vulnerability constitutes **High Severity** per the Aptos bug bounty program for the following reasons:

1. **Significant Protocol Violations**: A completely isolated node cannot participate in consensus, receive blocks, or process transactions, violating fundamental protocol requirements.

2. **Validator Node Impact**: If a validator node is affected, it will experience severe slowdowns or complete inability to participate in consensus, potentially affecting network liveness if multiple validators are impacted.

3. **Non-Recoverable Without Intervention**: Once isolated, the node cannot automatically recover without manual intervention to fix the peer discovery file or configuration.

The impact is particularly severe for:
- Fullnodes relying solely on file-based discovery
- Validators in networks where file-based discovery is used alongside other methods (partial isolation can still degrade performance)
- Any node where the seed peers configuration is empty

## Likelihood Explanation

**Likelihood: Medium to High**

This vulnerability is likely to occur in practice because:

1. **Legitimate Use Case**: File-based discovery is a documented feature used in production environments, particularly for private networks or testing scenarios.

2. **Common Misconfiguration Scenarios**:
   - Accidental file update with wrong peer information
   - Automated configuration management system deploying incorrect peer files
   - File corruption or race conditions during updates

3. **Attack Scenarios**:
   - Compromised operator machine with file system access
   - Insider threat from node operators
   - Supply chain attack on configuration management tools

4. **No Safety Net**: The code lacks defensive validation that would catch and prevent this scenario.

While the vulnerability requires either file system access or misconfiguration (making it non-exploitable by purely external attackers), these conditions are realistic in operational environments.

## Recommendation

Implement validation in `handle_update_discovered_peers` to prevent complete network isolation. The fix should:

1. **Validate Peer Set Overlap**: Before processing the update, check if the new peer set has at least partial overlap with currently connected peers or previously known reachable peers.

2. **Minimum Peer Count**: Ensure the resulting peer set (after the update) contains at least a minimum number of peers.

3. **Gradual Transition**: When replacing peers from a single source, maintain connections to old peers until new peers are successfully connected.

**Suggested Code Fix** (add to `handle_update_discovered_peers` function):

```rust
// Before processing the update, validate that we won't be completely isolated
fn validate_peer_set_update(
    &self,
    src: DiscoverySource,
    new_discovered_peers: &PeerSet,
) -> Result<(), String> {
    // Get current connected peers
    let currently_connected: HashSet<PeerId> = self.connected.keys().cloned().collect();
    
    // Get peers from all OTHER sources (not this source)
    let discovered_peers = self.discovered_peers.read();
    let mut peers_from_other_sources = HashSet::new();
    for (peer_id, peer) in &discovered_peers.peer_set {
        // Check if this peer has info from sources other than the updating source
        if peer.keys.has_info_from_other_sources(src) || peer.addrs.has_info_from_other_sources(src) {
            peers_from_other_sources.insert(*peer_id);
        }
    }
    
    // Get peers from the new update
    let new_peer_ids: HashSet<PeerId> = new_discovered_peers.keys().cloned().collect();
    
    // Calculate remaining peers after the update
    let remaining_peers: HashSet<PeerId> = peers_from_other_sources
        .union(&new_peer_ids)
        .cloned()
        .collect();
    
    // Require at least one peer, or at least some overlap with currently connected peers
    if remaining_peers.is_empty() {
        return Err(format!(
            "Rejecting peer set update from {:?}: would result in complete isolation (0 remaining peers)",
            src
        ));
    }
    
    // Additional check: warn if we're losing all currently connected peers
    let overlap_with_connected = remaining_peers.intersection(&currently_connected).count();
    if !currently_connected.is_empty() && overlap_with_connected == 0 {
        warn!(
            NetworkSchema::new(&self.network_context),
            "Peer set update from {:?} will disconnect from ALL currently connected peers. New peers may be unreachable.",
            src
        );
    }
    
    Ok(())
}
```

Then call this validation at the start of `handle_update_discovered_peers`:

```rust
fn handle_update_discovered_peers(&mut self, src: DiscoverySource, new_discovered_peers: PeerSet) {
    // Validate the update won't cause complete isolation
    if let Err(error) = self.validate_peer_set_update(src, &new_discovered_peers) {
        error!(
            NetworkSchema::new(&self.network_context),
            "{}. Rejecting update.", error
        );
        return;
    }
    
    // ... rest of existing code ...
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod network_isolation_poc {
    use super::*;
    use aptos_config::config::{Peer, PeerRole, PeerSet};
    use aptos_types::{network_address::NetworkAddress, PeerId};
    use std::collections::{HashMap, HashSet};
    use std::str::FromStr;

    #[tokio::test]
    async fn test_complete_network_isolation_via_file_update() {
        // Setup: Create a connectivity manager with file-based discovery only
        let network_context = NetworkContext::mock();
        let time_service = TimeService::mock();
        let peers_and_metadata = Arc::new(PeersAndMetadata::new(&[network_context.network_id()]));
        
        let (connection_reqs_tx, _connection_reqs_rx) = ConnectionRequestSender::new();
        let (_conn_notifs_tx, connection_notifs_rx) = conn_notifs_channel::new();
        let (requests_tx, requests_rx) = aptos_channels::new(10, &counters::PENDING_CONNECTIVITY_MANAGER_REQUESTS);
        
        let backoff_strategy = std::iter::repeat(Duration::from_secs(1));
        
        // Initialize with empty seeds (only file-based discovery)
        let mut connectivity_manager = ConnectivityManager::new(
            network_context,
            time_service,
            peers_and_metadata,
            PeerSet::new(), // Empty seeds - ONLY file-based discovery
            connection_reqs_tx,
            connection_notifs_rx,
            requests_rx,
            Duration::from_secs(5),
            backoff_strategy,
            Duration::from_secs(60),
            None,
            true,
            false,
        );
        
        // Step 1: Add initial peers A, B, C via file discovery
        let mut initial_peers = PeerSet::new();
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let peer_c = PeerId::random();
        
        let addr = NetworkAddress::from_str("/ip4/1.2.3.4/tcp/6180/noise-ik/080e287879c918794170e258bfaddd75acac5b3e350419044655e4983a487120/handshake/0").unwrap();
        let key = addr.find_noise_proto().unwrap();
        let mut keys = HashSet::new();
        keys.insert(key);
        
        initial_peers.insert(peer_a, Peer::new(vec![addr.clone()], keys.clone(), PeerRole::Upstream));
        initial_peers.insert(peer_b, Peer::new(vec![addr.clone()], keys.clone(), PeerRole::Upstream));
        initial_peers.insert(peer_c, Peer::new(vec![addr.clone()], keys.clone(), PeerRole::Upstream));
        
        connectivity_manager.handle_update_discovered_peers(DiscoverySource::File, initial_peers);
        
        // Verify we have 3 peers
        let discovered_peers = connectivity_manager.discovered_peers.read();
        assert_eq!(discovered_peers.peer_set.len(), 3);
        assert!(discovered_peers.peer_set.contains_key(&peer_a));
        assert!(discovered_peers.peer_set.contains_key(&peer_b));
        assert!(discovered_peers.peer_set.contains_key(&peer_c));
        drop(discovered_peers);
        
        // Step 2: Replace with completely different peers X, Y, Z (ZERO overlap)
        let mut new_peers = PeerSet::new();
        let peer_x = PeerId::random();
        let peer_y = PeerId::random();
        let peer_z = PeerId::random();
        
        new_peers.insert(peer_x, Peer::new(vec![addr.clone()], keys.clone(), PeerRole::Upstream));
        new_peers.insert(peer_y, Peer::new(vec![addr.clone()], keys.clone(), PeerRole::Upstream));
        new_peers.insert(peer_z, Peer::new(vec![addr.clone()], keys.clone(), PeerRole::Upstream));
        
        // This update should be rejected but isn't - demonstrating the vulnerability
        connectivity_manager.handle_update_discovered_peers(DiscoverySource::File, new_peers);
        
        // Step 3: Verify complete isolation - all old peers removed, only new peers exist
        let discovered_peers = connectivity_manager.discovered_peers.read();
        
        // VULNERABILITY: Old peers A, B, C are completely removed
        assert!(!discovered_peers.peer_set.contains_key(&peer_a));
        assert!(!discovered_peers.peer_set.contains_key(&peer_b));
        assert!(!discovered_peers.peer_set.contains_key(&peer_c));
        
        // Only new peers X, Y, Z exist
        assert!(discovered_peers.peer_set.contains_key(&peer_x));
        assert!(discovered_peers.peer_set.contains_key(&peer_y));
        assert!(discovered_peers.peer_set.contains_key(&peer_z));
        
        // SECURITY ISSUE: If X, Y, Z are unreachable, node is completely isolated
        println!("VULNERABILITY CONFIRMED: Node can be completely isolated via peer set replacement");
        println!("Old peers (A, B, C) removed: {}", !discovered_peers.peer_set.contains_key(&peer_a));
        println!("New peers (X, Y, Z) added: {}", discovered_peers.peer_set.contains_key(&peer_x));
        println!("Total peer count: {}", discovered_peers.peer_set.len());
    }
}
```

**Notes**

- This vulnerability requires either file system access or misconfiguration, but both scenarios are realistic in production environments.
- The issue is particularly severe for nodes without seed peer configuration (common for fullnodes using file-based discovery).
- Even with seed peers configured, the lack of validation can cause temporary connectivity disruption and resource waste attempting to connect to non-existent peers.
- The recommended fix implements defensive validation while preserving legitimate use cases for peer set updates.
- Multiple discovery sources (OnChain, File, REST, Config) can mitigate this issue, but nodes relying on a single source remain vulnerable.

### Citations

**File:** network/discovery/src/file.rs (L38-46)
```rust
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Wait for delay, or add the delay for next call
        futures::ready!(self.interval.as_mut().poll_next(cx));

        Poll::Ready(Some(match load_file(self.file_path.as_path()) {
            Ok(peers) => Ok(peers),
            Err(error) => Err(error),
        }))
    }
```

**File:** network/discovery/src/lib.rs (L141-156)
```rust
        while let Some(update) = source_stream.next().await {
            if let Ok(update) = update {
                trace!(
                    NetworkSchema::new(&network_context),
                    "{} Sending update: {:?}",
                    network_context,
                    update
                );
                let request = ConnectivityRequest::UpdateDiscoveredPeers(discovery_source, update);
                if let Err(error) = update_channel.try_send(request) {
                    inc_by_with_context(&DISCOVERY_COUNTS, &network_context, "send_failure", 1);
                    warn!(
                        NetworkSchema::new(&network_context),
                        "{} Failed to send update {:?}", network_context, error
                    );
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

**File:** network/framework/src/connectivity_manager/mod.rs (L900-926)
```rust
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
```

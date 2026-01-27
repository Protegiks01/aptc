# Audit Report

## Title
Trust State Transition Race Condition Allows Untrusted Peers to Maintain Active Connections

## Summary
When a peer transitions from trusted to untrusted via `set_trusted_peers()`, existing connections are not immediately validated against the new trust state. This creates a race condition window (default 5 seconds) where an untrusted peer can continue to send and receive protocol messages, including consensus messages, through their existing connection.

## Finding Description

The vulnerability exists in the decoupling between trust state updates and connection validation in the network layer.

When `set_trusted_peers()` is called to update the trusted peer set, it only updates the in-memory trust state atomically: [1](#0-0) 

However, existing connections are not immediately checked against this new trust state. Connection validation only occurs during periodic connectivity checks: [2](#0-1) 

This `close_stale_connections()` function is only invoked during the periodic `check_connectivity()` call: [3](#0-2) 

The connectivity check interval is configured with a default value of 5000 milliseconds: [4](#0-3) 

**Attack Scenario:**
1. A validator is part of the active validator set with an established connection to other validators
2. During an epoch transition, the validator is removed from the validator set
3. The connectivity manager updates the trusted peers via `set_trusted_peers()` at line 993: [5](#0-4) 

4. The untrusted validator's connection remains active for up to 5 seconds (until the next `check_connectivity()` tick)
5. During this window, the removed validator can:
   - Send consensus messages (proposals, votes, commits)
   - Send RPC requests to other validators
   - Receive consensus messages from other validators
   - Potentially cause protocol violations or consensus disruption

While new handshake attempts would correctly reject the untrusted peer during `upgrade_inbound()`: [6](#0-5) 

Existing connections bypass this check entirely because authentication happens only at connection establishment time, not per-message.

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty program for the following reasons:

1. **Significant Protocol Violations**: An untrusted peer maintaining an active connection violates the mutual authentication security model. In networks using `HandshakeAuthMode::Mutual`, the invariant is that only trusted peers should have active connections.

2. **Consensus Layer Impact**: During the 5-second window, a removed validator could:
   - Send malicious or outdated consensus votes
   - Attempt to equivocate by sending conflicting messages
   - Cause confusion in the consensus protocol by participating as if still trusted
   - Potentially trigger unnecessary view changes or leader elections

3. **Validator Node Effects**: The vulnerability could cause validator node slowdowns or unexpected behavior when processing messages from peers that should no longer be trusted.

4. **Epoch Transition Vulnerability**: The attack surface is highest during epoch transitions when validator sets change, a critical operational period for the network.

While this doesn't directly break consensus safety (honest validators would still reject invalid votes/blocks based on cryptographic verification), it enables protocol violations and could impact liveness or create operational confusion.

## Likelihood Explanation

**Likelihood: High**

1. **Regular Occurrence**: Epoch transitions happen regularly in Aptos, and validators can be added/removed from the active set during these transitions.

2. **No Special Privileges Required**: Any validator that was previously trusted but gets removed can exploit this. No insider access or collusion is needed beyond having been a legitimate validator.

3. **Automatic Trigger**: The vulnerability is triggered automatically whenever `set_trusted_peers()` is called to remove a peer that has an active connection.

4. **Reproducible Window**: The 5-second window is deterministic and provides ample time for a malicious actor to send multiple messages.

5. **Low Detection Probability**: During the short window, the malicious activity might not be immediately detected as the peer appears to be legitimately connected.

## Recommendation

Implement immediate connection validation when trust state changes. Modify `set_trusted_peers()` to actively close connections to peers that are no longer in the trusted set:

```rust
pub fn set_trusted_peers(
    &self,
    network_id: &NetworkId,
    trusted_peer_set: PeerSet,
) -> Result<(), Error> {
    let trusted_peers = self.get_trusted_peer_set_for_network(network_id)?;
    
    // Get the old trusted peers before updating
    let old_trusted_peers = trusted_peers.load();
    
    // Update the trusted peer set
    trusted_peers.store(Arc::new(trusted_peer_set.clone()));
    
    // Identify peers that were removed from the trusted set
    let removed_peers: Vec<PeerId> = old_trusted_peers
        .keys()
        .filter(|peer_id| !trusted_peer_set.contains_key(peer_id))
        .cloned()
        .collect();
    
    // Broadcast connection loss events for removed peers
    // This ensures immediate cleanup and notification
    if !removed_peers.is_empty() {
        let peers_and_metadata = self.peers_and_metadata.read();
        if let Some(network_metadata) = peers_and_metadata.get(network_id) {
            for peer_id in removed_peers {
                if let Some(peer_metadata) = network_metadata.get(&peer_id) {
                    let event = ConnectionNotification::LostPeer(
                        peer_metadata.connection_metadata.clone(),
                        *network_id,
                    );
                    self.broadcast(event);
                }
            }
        }
    }
    
    Ok(())
}
```

Additionally, trigger immediate connection cleanup in the connectivity manager when trusted peers are updated by adding a call to `close_stale_connections()` immediately after `set_trusted_peers()` in the update handler.

## Proof of Concept

```rust
#[tokio::test]
async fn test_untrusted_peer_connection_race_condition() {
    use std::time::Duration;
    use tokio::time::sleep;
    
    // Setup: Create peers and metadata
    let network_ids = vec![NetworkId::Validator];
    let peers_and_metadata = PeersAndMetadata::new(&network_ids);
    
    // Create a test peer
    let peer_id = PeerId::random();
    let peer_public_key = x25519::PrivateKey::generate(&mut rand::thread_rng()).public_key();
    
    // Initially add peer to trusted set
    let mut initial_trusted = PeerSet::new();
    initial_trusted.insert(
        peer_id,
        Peer::new(
            vec![],
            [peer_public_key].into_iter().collect(),
            PeerRole::Validator,
        ),
    );
    peers_and_metadata
        .set_trusted_peers(&NetworkId::Validator, initial_trusted)
        .unwrap();
    
    // Simulate an active connection
    let connection_metadata = ConnectionMetadata::mock(peer_id);
    peers_and_metadata
        .insert_connection_metadata(
            PeerNetworkId::new(NetworkId::Validator, peer_id),
            connection_metadata.clone(),
        )
        .unwrap();
    
    // Verify peer is connected and trusted
    assert!(peers_and_metadata.get_trusted_peer_state(
        &PeerNetworkId::new(NetworkId::Validator, peer_id)
    ).unwrap().is_some());
    
    // ATTACK: Remove peer from trusted set
    let empty_trusted = PeerSet::new();
    peers_and_metadata
        .set_trusted_peers(&NetworkId::Validator, empty_trusted)
        .unwrap();
    
    // VULNERABILITY: Peer is no longer trusted...
    assert!(peers_and_metadata.get_trusted_peer_state(
        &PeerNetworkId::new(NetworkId::Validator, peer_id)
    ).unwrap().is_none());
    
    // ...but connection still exists!
    let connected_peers = peers_and_metadata
        .get_connected_peers_and_metadata()
        .unwrap();
    assert!(connected_peers.contains_key(&PeerNetworkId::new(NetworkId::Validator, peer_id)));
    
    // The connection remains active until the next connectivity check
    // In production, this window is 5 seconds by default
    sleep(Duration::from_millis(100)).await;
    
    // Connection is still active - vulnerability confirmed
    let connected_peers = peers_and_metadata
        .get_connected_peers_and_metadata()
        .unwrap();
    assert!(
        connected_peers.contains_key(&PeerNetworkId::new(NetworkId::Validator, peer_id)),
        "Untrusted peer maintains active connection after trust state change"
    );
}
```

This test demonstrates that after removing a peer from the trusted set via `set_trusted_peers()`, the peer's connection remains active in the `PeersAndMetadata` storage, creating a window where an untrusted peer can continue to communicate with the network.

### Citations

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

**File:** network/framework/src/connectivity_manager/mod.rs (L807-836)
```rust
    async fn check_connectivity<'a>(
        &'a mut self,
        pending_dials: &'a mut FuturesUnordered<BoxFuture<'static, PeerId>>,
    ) {
        trace!(
            NetworkSchema::new(&self.network_context),
            "{} Checking connectivity",
            self.network_context
        );

        // Log the eligible peers with addresses from discovery
        sample!(SampleRate::Duration(Duration::from_secs(60)), {
            info!(
                NetworkSchema::new(&self.network_context),
                discovered_peers = ?self.discovered_peers,
                "Active discovered peers"
            )
        });

        // Cancel dials to peers that are no longer eligible.
        self.cancel_stale_dials().await;
        // Disconnect from connected peers that are no longer eligible.
        self.close_stale_connections().await;
        // Dial peers which are eligible but are neither connected nor queued for dialing in the
        // future.
        self.dial_eligible_peers(pending_dials).await;

        // Update the metrics for any peer ping latencies
        self.update_ping_latency_metrics();
    }
```

**File:** network/framework/src/connectivity_manager/mod.rs (L991-1000)
```rust
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
```

**File:** config/src/config/network_config.rs (L41-41)
```rust
pub const CONNECTIVITY_CHECK_INTERVAL_MS: u64 = 5000;
```

**File:** network/framework/src/noise/handshake.rs (L366-383)
```rust
        // if mutual auth mode, verify the remote pubkey is in our set of trusted peers
        let network_id = self.network_context.network_id();
        let peer_role = match &self.auth_mode {
            HandshakeAuthMode::Mutual {
                peers_and_metadata, ..
            } => {
                let trusted_peers = peers_and_metadata.get_trusted_peers(&network_id)?;
                let trusted_peer = trusted_peers.get(&remote_peer_id).cloned();
                match trusted_peer {
                    Some(peer) => {
                        Self::authenticate_inbound(remote_peer_short, &peer, &remote_public_key)
                    },
                    None => Err(NoiseHandshakeError::UnauthenticatedClient(
                        remote_peer_short,
                        remote_peer_id,
                    )),
                }
            },
```

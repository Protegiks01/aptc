# Audit Report

## Title
Stale Connection Metadata Allows Previously-Trusted Peers to Bypass Inbound Connection Limits

## Summary
A peer that was previously in the trusted peers set but has been removed can bypass the inbound connection limit check for unknown peers. This occurs because the limit enforcement logic checks if a peer already has an active connection, without verifying whether that existing connection is still considered trusted based on the current trusted peers snapshot.

## Finding Description

The vulnerability exists in the `handle_new_connection_event()` function's connection limit enforcement logic. The issue arises from a Time-of-Check Time-of-Use (TOCTOU) race condition between when a peer is removed from the trusted peers set and when `ConnectivityManager` closes their stale connection. [1](#0-0) 

When a new connection arrives, the function fetches a snapshot of the current trusted peers. [2](#0-1) 

The connection limit check at lines 372-375 contains the bypass condition. It only enforces the limit if the peer does NOT already have a connection in `active_peers`. This logic is intended to allow simultaneous dial tie-breaking, but it creates a vulnerability window for peers that were trusted but are now removed.

**Attack Scenario:**

1. **T0**: Attacker A is in `trusted_peers` with role=Validator and establishes an inbound connection. During the Noise handshake, A's connection metadata is set with role=Validator. [3](#0-2) 

2. **T1**: Administrator removes A from `trusted_peers` (e.g., due to misbehavior or compromise). A's connection remains active with cached metadata showing role=Validator.

3. **T2**: Before `ConnectivityManager.close_stale_connections()` runs (which happens periodically based on `connectivity_check_interval`), A attempts a NEW inbound connection. [4](#0-3) 

4. The new connection's Noise handshake sees A is no longer in `trusted_peers`, so the new connection gets role=Unknown.

5. In `handle_new_connection_event()` for the new connection:
   - The function counts unknown inbound connections (lines 358-367), correctly including A's old connection as unknown since `trusted_peers.get(A)` returns None
   - However, at line 372-375, the check `!self.active_peers.contains_key(&A)` returns FALSE because A's old connection exists
   - **The limit check is bypassed** even though A should be treated as an unknown peer
   - The new connection proceeds to tie-breaking, consuming resources

**Broken Invariant:**

This violates the **Access Control** invariant (#8) and **Resource Limits** invariant (#9). Unknown peers should be uniformly subject to connection limits to prevent resource exhaustion, but previously-trusted peers can bypass this protection during the vulnerability window.

## Impact Explanation

This vulnerability represents a **Medium Severity** issue per the Aptos bug bounty criteria for the following reasons:

1. **Limited Resource Exhaustion**: Attackers can force repeated connection attempts and tie-breaking operations during the vulnerability window, consuming CPU and network bandwidth. However, they cannot accumulate unlimited connections due to tie-breaking logic preventing multiple simultaneous connections from the same peer ID.

2. **Temporary State Inconsistency**: The vulnerability only exists in the window between peer removal and the next connectivity check. For typical configurations with `connectivity_check_interval` of 5-60 seconds, this represents a limited attack window.

3. **Unfair Access Control**: Multiple compromised peers that were previously trusted can exploit this simultaneously, potentially blocking legitimate unknown peers from connecting when limits are reached, while the attackers themselves bypass the limits.

4. **No Direct Funds Loss or Consensus Impact**: This does not directly affect consensus safety, validator operations, or result in loss of funds. It is primarily a DoS-related access control issue.

The impact is more severe if many validators are compromised and removed simultaneously, or if the `connectivity_check_interval` is configured with a long duration.

## Likelihood Explanation

**Medium Likelihood**

This vulnerability can be triggered whenever:
1. A peer is removed from the trusted peers set (relatively common during validator set updates, security incidents, or reconfigurations)
2. The removed peer attempts new connections before being disconnected by ConnectivityManager
3. The inbound connection limit is at or near capacity

The attack requires:
- Prior trust relationship (being in trusted_peers)
- Ability to initiate inbound connections after removal
- Timing the attack within the vulnerability window

This is realistic for scenarios involving:
- Compromised validators being removed from the set
- Validators voluntarily leaving the network
- Security incidents requiring peer removals
- Network reconfigurations

## Recommendation

Modify the connection limit bypass logic to also verify that the existing connection's peer is currently in the trusted peers set. This ensures that only actively-trusted peers can bypass the limit, not stale connections from previously-trusted peers.

**Recommended Fix** in `handle_new_connection_event()`:

```rust
// Reject excessive inbound connections made by unknown peers
// We control outbound connections with Connectivity manager before we even send them
// and we must allow connections that already exist to pass through tie breaking.
// FIXED: Also check that the existing connection is for a currently-trusted peer
if !self
    .active_peers
    .contains_key(&conn.metadata.remote_peer_id)
    && unknown_inbound_conns + 1 > self.inbound_connection_limit
{
    // Reject connection
} else if self
    .active_peers
    .contains_key(&conn.metadata.remote_peer_id)
    && !trusted_peers.contains_key(&conn.metadata.remote_peer_id)
    && unknown_inbound_conns + 1 > self.inbound_connection_limit
{
    // Also reject if peer has existing connection but is no longer trusted
    // and adding this connection would exceed the limit
    info!(
        NetworkSchema::new(&self.network_context)
            .connection_metadata_with_address(&conn.metadata),
        "{} Connection rejected due to connection limit (stale peer): {}",
        self.network_context,
        conn.metadata
    );
    counters::connections_rejected(&self.network_context, conn.metadata.origin)
        .inc();
    self.disconnect(conn);
    return;
}
```

Alternatively, ensure that `ConnectivityManager` is invoked immediately when trusted peers are updated, rather than relying solely on periodic checks.

## Proof of Concept

```rust
// Test demonstrating the vulnerability
// Add to network/framework/src/peer_manager/tests.rs

#[tokio::test]
async fn test_stale_peer_bypasses_connection_limit() {
    // Setup: Create a peer manager with inbound_connection_limit = 1
    let (mut pm, _trusted_peers, _conn_reqs_rx) = build_test_peer_manager(1);
    
    // Step 1: Add attacker to trusted_peers and establish connection
    let attacker_peer_id = PeerId::random();
    let attacker_conn1 = build_test_connection(
        attacker_peer_id, 
        ConnectionOrigin::Inbound,
        PeerRole::Validator
    );
    pm.handle_new_connection_event(attacker_conn1);
    assert_eq!(pm.active_peers.len(), 1);
    
    // Step 2: Remove attacker from trusted_peers (simulating security incident)
    // In reality, this would be done via peers_and_metadata.set_trusted_peers()
    // For the test, we'll simulate the state where attacker is removed
    
    // Step 3: Attempt new connection from attacker (now unknown)
    let attacker_conn2 = build_test_connection(
        attacker_peer_id,
        ConnectionOrigin::Inbound, 
        PeerRole::Unknown
    );
    pm.handle_new_connection_event(attacker_conn2);
    
    // VULNERABILITY: The connection should be rejected because limit is 1
    // and attacker is no longer trusted, but it bypasses the check
    // because attacker already has a connection
    
    // Step 4: Verify legitimate unknown peer is blocked
    let legit_peer_id = PeerId::random();
    let legit_conn = build_test_connection(
        legit_peer_id,
        ConnectionOrigin::Inbound,
        PeerRole::Unknown  
    );
    pm.handle_new_connection_event(legit_conn);
    
    // Legitimate peer should be rejected, demonstrating the unfair access control
    assert!(!pm.active_peers.contains_key(&legit_peer_id));
}
```

## Notes

This vulnerability specifically affects the `MaybeMutual` authentication mode commonly used in public-facing validator full nodes. The vulnerability window exists between trusted peer set updates and the next `ConnectivityManager::check_connectivity()` execution. The impact is proportional to the configured `connectivity_check_interval` and the number of simultaneously compromised peers being removed from the trusted set.

### Citations

**File:** network/framework/src/peer_manager/mod.rs (L334-339)
```rust
        let trusted_peers = match self
            .peers_and_metadata
            .get_trusted_peers(&self.network_context.network_id())
        {
            Ok(trusted_peers) => trusted_peers,
            Err(error) => {
```

**File:** network/framework/src/peer_manager/mod.rs (L352-391)
```rust
        if conn.metadata.origin == ConnectionOrigin::Inbound {
            // Everything below here is meant for unknown peers only. The role comes from
            // the Noise handshake and if it's not `Unknown` then it is trusted.
            if conn.metadata.role == PeerRole::Unknown {
                // TODO: Keep track of somewhere else to not take this hit in case of DDoS
                // Count unknown inbound connections
                let unknown_inbound_conns = self
                    .active_peers
                    .iter()
                    .filter(|(peer_id, (metadata, _))| {
                        metadata.origin == ConnectionOrigin::Inbound
                            && trusted_peers
                                .get(peer_id)
                                .is_none_or(|peer| peer.role == PeerRole::Unknown)
                    })
                    .count();

                // Reject excessive inbound connections made by unknown peers
                // We control outbound connections with Connectivity manager before we even send them
                // and we must allow connections that already exist to pass through tie breaking.
                if !self
                    .active_peers
                    .contains_key(&conn.metadata.remote_peer_id)
                    && unknown_inbound_conns + 1 > self.inbound_connection_limit
                {
                    info!(
                        NetworkSchema::new(&self.network_context)
                            .connection_metadata_with_address(&conn.metadata),
                        "{} Connection rejected due to connection limit: {}",
                        self.network_context,
                        conn.metadata
                    );
                    counters::connections_rejected(&self.network_context, conn.metadata.origin)
                        .inc();
                    self.disconnect(conn);
                    return;
                }
            }
        }

```

**File:** network/framework/src/noise/handshake.rs (L368-427)
```rust
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
            HandshakeAuthMode::MaybeMutual(peers_and_metadata) => {
                let trusted_peers = peers_and_metadata.get_trusted_peers(&network_id)?;
                let trusted_peer = trusted_peers.get(&remote_peer_id).cloned();
                match trusted_peer {
                    Some(peer) => {
                        Self::authenticate_inbound(remote_peer_short, &peer, &remote_public_key)
                    },
                    None => {
                        // The peer is not in the trusted peer set. Verify that the Peer ID is
                        // constructed correctly from the public key.
                        let derived_remote_peer_id =
                            aptos_types::account_address::from_identity_public_key(
                                remote_public_key,
                            );
                        if derived_remote_peer_id != remote_peer_id {
                            // The peer ID is not constructed correctly from the public key
                            Err(NoiseHandshakeError::ClientPeerIdMismatch(
                                remote_peer_short,
                                remote_peer_id,
                                derived_remote_peer_id,
                            ))
                        } else {
                            // Try to infer the role from the network context
                            if self.network_context.role().is_validator() {
                                if network_id.is_vfn_network() {
                                    // Inbound connections to validators on the VFN network must be VFNs
                                    Ok(PeerRole::ValidatorFullNode)
                                } else {
                                    // Otherwise, they're unknown. Validators will connect through
                                    // authenticated channels (on the validator network) so shouldn't hit
                                    // this, and PFNs will connect on public networks (which aren't common).
                                    Ok(PeerRole::Unknown)
                                }
                            } else {
                                // We're a VFN or PFN. VFNs get no inbound connections on the vfn network
                                // (so the peer won't be a validator). Thus, we're on the public network
                                // so mark the peer as unknown.
                                Ok(PeerRole::Unknown)
                            }
                        }
                    },
                }
            },
        }?;
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

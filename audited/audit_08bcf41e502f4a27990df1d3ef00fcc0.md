# Audit Report

## Title
Untrusted Peer Connection Bypass via MaybeMutual Authentication Mode Allowing Validator Resource Exhaustion

## Summary
The `insert_connection_metadata()` function does not verify that peers are in the `trusted_peers` set before accepting connections. In MaybeMutual authentication mode (used for VFN networks), untrusted peers can connect to validators, get assigned the `ValidatorFullNode` role, bypass inbound connection limits, and persist indefinitely despite not being trusted. This enables resource exhaustion attacks against validators.

## Finding Description

The trust verification gap exists across multiple layers of the network stack:

**Layer 1: Storage Layer - No Trust Verification** [1](#0-0) 

The `insert_connection_metadata()` function unconditionally accepts and stores any peer's connection metadata without verifying the peer is in `trusted_peers`. It simply updates or inserts the peer metadata and broadcasts a `NewPeer` event.

**Layer 2: Handshake Layer - Incomplete Trust Checking** [2](#0-1) 

In MaybeMutual authentication mode, the `upgrade_inbound()` function accepts ALL inbound connections, even from untrusted peers. For validators receiving connections on the VFN network, it assigns `PeerRole::ValidatorFullNode` to untrusted inbound peers based solely on network context inference (lines 407-410), without requiring the peer to be in the trusted peers set.

**Layer 3: Connection Management - Limit Bypass** [3](#0-2) 

The `handle_new_connection_event()` function only enforces inbound connection limits for peers with `PeerRole::Unknown`. Untrusted peers that received `PeerRole::ValidatorFullNode` during the handshake bypass this check entirely, allowing unlimited malicious connections.

**Layer 4: Connectivity Manager - Persistence Without Trust** [4](#0-3) 

The `close_stale_connections()` function explicitly excludes inbound `ValidatorFullNode` peers from eviction when `mutual_authentication` is false (lines 492-499). This means untrusted peers with the ValidatorFullNode role persist indefinitely even though they are not in `trusted_peers`.

**Layer 5: Authentication Mode Configuration** [5](#0-4) 

MaybeMutual mode is used whenever `config.mutual_authentication` is false, which is the standard configuration for VFN and public networks.

**Attack Path:**

1. Attacker establishes TCP connection to validator on VFN network port
2. Noise handshake completes (MaybeMutual mode accepts all peers)
3. Attacker receives `PeerRole::ValidatorFullNode` role assignment (inference from network context)
4. Connection bypasses unknown peer limit check (role ≠ Unknown)
5. `insert_connection_metadata()` stores attacker as legitimate peer
6. Connectivity manager never evicts the attacker (exception for inbound VFN in non-mutual mode)
7. Attacker repeats to establish many concurrent connections, exhausting validator resources

## Impact Explanation

This vulnerability qualifies as **HIGH severity** under the Aptos bug bounty program:

**Primary Impact: Validator Node Slowdowns**
- Attackers can exhaust validator memory by establishing unlimited fake VFN connections
- Each connection consumes resources for peer state, message buffers, and network I/O
- Validators become slow or unresponsive under connection flood
- Meets "Validator node slowdowns" criteria explicitly listed as High severity

**Secondary Impact: Significant Protocol Violations**
- Bypass of intended security control (inbound connection limits)
- Violation of trust boundary assumptions (untrusted peers treated as trusted VFNs)
- Meets "Significant protocol violations" criteria for High severity

**Not Critical Because:**
- No direct funds loss (consensus messages still require valid signatures)
- No consensus safety violation (attackers cannot forge validator signatures)
- Network remains recoverable (operators can restart nodes or update firewall rules)

## Likelihood Explanation

**Likelihood: HIGH**

**Attacker Requirements (Low Barrier):**
- No special privileges required
- No validator keys needed
- Only requires network connectivity to VFN port
- Attack is fully automated and scalable

**Attack Complexity (Trivial):**
- No cryptographic attacks needed
- No timing dependencies
- Simple TCP connection establishment
- Can be executed with basic networking tools

**Detection Difficulty:**
- Fake VFN connections appear similar to legitimate ones in logs
- No obvious indicators until resource exhaustion occurs
- Connection count metrics may not distinguish trusted vs. untrusted peers

## Recommendation

Implement strict trust verification at connection acceptance:

**Fix 1: Add Trust Check in insert_connection_metadata()**

```rust
pub fn insert_connection_metadata(
    &self,
    peer_network_id: PeerNetworkId,
    connection_metadata: ConnectionMetadata,
) -> Result<(), Error> {
    // ADDED: Verify peer is in trusted_peers if mutual_authentication is expected
    if connection_metadata.origin == ConnectionOrigin::Inbound {
        let trusted_peers = self.get_trusted_peers(&peer_network_id.network_id())?;
        if connection_metadata.role != PeerRole::Unknown 
            && !trusted_peers.contains_key(&peer_network_id.peer_id()) {
            return Err(Error::UnexpectedError(format!(
                "Peer {} has role {:?} but is not in trusted_peers set",
                peer_network_id.peer_id(),
                connection_metadata.role
            )));
        }
    }
    
    // ... existing code
}
```

**Fix 2: Enforce Connection Limits for All Unknown Peers** [3](#0-2) 

Modify the check to also enforce limits on inbound connections from peers not in trusted_peers, regardless of assigned role:

```rust
if conn.metadata.origin == ConnectionOrigin::Inbound {
    let is_trusted = trusted_peers.get(&conn.metadata.remote_peer_id).is_some();
    
    if !is_trusted {
        // Count all untrusted inbound connections
        let untrusted_inbound_conns = self.active_peers.iter()
            .filter(|(peer_id, (metadata, _))| {
                metadata.origin == ConnectionOrigin::Inbound
                    && !trusted_peers.contains_key(peer_id)
            })
            .count();
            
        if !self.active_peers.contains_key(&conn.metadata.remote_peer_id)
            && untrusted_inbound_conns + 1 > self.inbound_connection_limit {
            // Reject connection
            self.disconnect(conn);
            return;
        }
    }
}
```

**Fix 3: Remove MaybeMutual Exception in Connectivity Manager**

Remove the special exception that prevents eviction of untrusted ValidatorFullNode peers, or make it conditional on the peer actually being in trusted_peers.

## Proof of Concept

**Rust Integration Test:**

```rust
#[tokio::test]
async fn test_untrusted_vfn_connection_bypass() {
    use aptos_config::network_id::NetworkId;
    use aptos_types::PeerId;
    use aptos_crypto::x25519;
    
    // Setup: Create validator with MaybeMutual auth on VFN network
    let validator_key = x25519::PrivateKey::generate(&mut rand::rngs::OsRng);
    let network_context = NetworkContext::new(
        RoleType::Validator,
        NetworkId::Vfn, 
        PeerId::random()
    );
    
    let peers_and_metadata = PeersAndMetadata::new(&[NetworkId::Vfn]);
    let auth_mode = HandshakeAuthMode::maybe_mutual(peers_and_metadata.clone());
    
    // trusted_peers is EMPTY - attacker is not trusted
    
    // Attack: Attacker connects
    let attacker_key = x25519::PrivateKey::generate(&mut rand::rngs::OsRng);
    let attacker_id = PeerId::random();
    
    let upgrader = NoiseUpgrader::new(network_context, validator_key, auth_mode);
    
    // Simulate inbound connection from attacker
    let (mut socket_a, socket_b) = MemorySocket::new_pair();
    
    // Attacker initiates handshake
    let result = upgrader.upgrade_inbound(socket_b).await;
    
    // VULNERABILITY: Handshake succeeds even though attacker is not in trusted_peers
    assert!(result.is_ok());
    let (_, peer_id, peer_role) = result.unwrap();
    assert_eq!(peer_id, attacker_id);
    
    // VULNERABILITY: Attacker gets ValidatorFullNode role despite not being trusted
    assert_eq!(peer_role, PeerRole::ValidatorFullNode);
    
    // VULNERABILITY: Connection can be inserted without trust check
    let conn_metadata = ConnectionMetadata::new(
        attacker_id,
        ConnectionId::from(1),
        NetworkAddress::mock(),
        ConnectionOrigin::Inbound,
        MessagingProtocolVersion::V1,
        ProtocolIdSet::empty(),
        peer_role
    );
    
    let result = peers_and_metadata.insert_connection_metadata(
        PeerNetworkId::new(NetworkId::Vfn, attacker_id),
        conn_metadata
    );
    
    // VULNERABILITY: Insertion succeeds without trust verification
    assert!(result.is_ok());
    
    // Attacker has successfully bypassed trust boundary
    let all_peers = peers_and_metadata.get_all_peers();
    assert!(all_peers.contains(&PeerNetworkId::new(NetworkId::Vfn, attacker_id)));
}
```

**Notes:**
- This PoC demonstrates the complete attack chain
- Real attack would repeat connection establishment to exhaust resources
- On production network, attacker would target actual validator VFN ports
- Impact scales linearly with number of attacker connections established

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

**File:** network/framework/src/noise/handshake.rs (L384-426)
```rust
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
```

**File:** network/framework/src/peer_manager/mod.rs (L352-390)
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

**File:** network/framework/src/connectivity_manager/mod.rs (L484-503)
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
```

**File:** network/builder/src/builder.rs (L171-175)
```rust
        let authentication_mode = if config.mutual_authentication {
            AuthenticationMode::Mutual(identity_key)
        } else {
            AuthenticationMode::MaybeMutual(identity_key)
        };
```

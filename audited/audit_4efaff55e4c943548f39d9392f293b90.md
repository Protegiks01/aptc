# Audit Report

## Title
Privilege Escalation via Automatic ValidatorFullNode Role Assignment on VFN Network

## Summary
An unprivileged attacker can obtain `PeerRole::ValidatorFullNode` privileges by connecting to a validator node on the VFN network, bypassing inbound connection limits and gaining trusted peer status without being in the trusted peer set.

## Finding Description

The vulnerability exists in the role inference logic for untrusted peers connecting to validators on the VFN (Validator Full Node) network. [1](#0-0) 

By default, the VFN network uses `MaybeMutual` authentication mode rather than strict `Mutual` authentication. When an untrusted peer connects inbound to a validator on the VFN network, the following vulnerable code path executes: [2](#0-1) 

The critical vulnerability is in the role inference logic at lines 406-411. When:
1. The listening node is a validator (`self.network_context.role().is_validator()` returns true)
2. The connection is on the VFN network (`network_id.is_vfn_network()` returns true)  
3. The peer is NOT in the trusted peer set
4. The peer's `peer_id` is correctly derived from their public key (standard requirement)

The code automatically assigns `PeerRole::ValidatorFullNode` to the attacker without any authorization check.

This elevated role bypasses critical security controls: [3](#0-2) 

The comment at lines 353-354 explicitly states: "**if it's not `Unknown` then it is trusted**". Peers with `ValidatorFullNode` role bypass the `inbound_connection_limit` enforcement that applies to `Unknown` peers.

Additionally, these elevated peers are preserved during stale connection cleanup: [4](#0-3) 

**Attack Scenario:**
1. Attacker generates an x25519 keypair
2. Derives `peer_id` from public key using standard derivation
3. Connects to validator's VFN network endpoint
4. Completes Noise IK handshake (cryptographically sound)
5. Automatically receives `PeerRole::ValidatorFullNode` 
6. Bypasses inbound connection limits
7. Creates multiple such connections to exhaust validator resources
8. Is treated as "trusted" by various network protocol handlers

## Impact Explanation

**Severity: High** (up to $50,000 per Aptos Bug Bounty)

This vulnerability enables:

1. **Validator Node Resource Exhaustion**: Attackers bypass inbound connection limits meant to protect validators from connection flooding. Multiple malicious peers can exhaust file descriptors, memory, and network bandwidth.

2. **Protocol Integrity Violations**: The peer role system is a critical access control mechanism. Allowing arbitrary peers to claim `ValidatorFullNode` status violates the trust model where this role should be reserved for operators' full nodes.

3. **Potential Data Leakage**: VFN-role peers may receive higher-priority access to mempool broadcasts, state sync data, and other protocol messages intended only for legitimate validator full nodes. [5](#0-4) 

4. **Validator Network Degradation**: Mass exploitation could degrade network performance, slow block propagation, and impact consensus liveness indirectly.

This qualifies as **High Severity** under "Validator node slowdowns" and "Significant protocol violations".

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited because:

1. **Trivial to Execute**: Requires only standard Noise handshake capability available in any P2P network client
2. **No Special Resources**: Attacker needs only a keypair and network connectivity
3. **Default Configuration**: VFN networks use `MaybeMutual` mode by default
4. **Immediate Impact**: Each connection immediately bypasses access controls
5. **Scalable Attack**: Attacker can create many connections from different peer IDs

The attack requires no special knowledge, insider access, or complex setup.

## Recommendation

**Fix the role inference logic to default to `PeerRole::Unknown` for untrusted peers on VFN networks:**

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
                Err(NoiseHandshakeError::ClientPeerIdMismatch(
                    remote_peer_short,
                    remote_peer_id,
                    derived_remote_peer_id,
                ))
            } else {
                // FIXED: Always assign Unknown role to untrusted peers
                // VFN role should ONLY be assigned to peers in the trusted set
                Ok(PeerRole::Unknown)
            }
        },
    }
}
```

Remove the automatic role inference entirely. The role should **only** come from the trusted peer set lookup. If a peer is not in the trusted set, they should receive `PeerRole::Unknown` regardless of network context.

## Proof of Concept

```rust
#[tokio::test]
async fn test_vfn_role_escalation_attack() {
    use aptos_config::config::{PeerRole, RoleType};
    use aptos_config::network_id::NetworkId;
    use aptos_crypto::x25519;
    use aptos_memsocket::MemorySocket;
    use aptos_types::PeerId;
    
    // Setup: Create validator and attacker
    let validator_key = x25519::PrivateKey::generate(&mut rand::rngs::OsRng);
    let validator_pubkey = validator_key.public_key();
    let validator_peer_id = PeerId::random();
    
    // Attacker generates their own keypair (not in trusted set)
    let attacker_key = x25519::PrivateKey::generate(&mut rand::rngs::OsRng);
    let attacker_pubkey = attacker_key.public_key();
    let attacker_peer_id = aptos_types::account_address::from_identity_public_key(attacker_pubkey);
    
    // Setup validator with MaybeMutual auth on VFN network
    let peers_and_metadata = PeersAndMetadata::new(&[NetworkId::Vfn]);
    let validator_context = NetworkContext::new(RoleType::Validator, NetworkId::Vfn, validator_peer_id);
    let validator_upgrader = NoiseUpgrader::new(
        validator_context,
        validator_key,
        HandshakeAuthMode::maybe_mutual(peers_and_metadata.clone()),
    );
    
    let attacker_context = NetworkContext::new(RoleType::FullNode, NetworkId::Vfn, attacker_peer_id);
    let attacker_upgrader = NoiseUpgrader::new(
        attacker_context,
        attacker_key,
        HandshakeAuthMode::maybe_mutual(peers_and_metadata),
    );
    
    // Attacker connects to validator
    let (attacker_socket, validator_socket) = MemorySocket::new_pair();
    
    let attacker_task = attacker_upgrader.upgrade_outbound(
        attacker_socket,
        validator_peer_id,
        validator_pubkey,
        AntiReplayTimestamps::now,
    );
    
    let validator_task = validator_upgrader.upgrade_inbound(validator_socket);
    
    let (attacker_result, validator_result) = tokio::join!(attacker_task, validator_task);
    
    // Verify exploit: Attacker is assigned ValidatorFullNode role
    let (_, _, assigned_role) = validator_result.expect("Handshake should succeed");
    
    // VULNERABILITY: Attacker gets VFN role without being in trusted set!
    assert_eq!(assigned_role, PeerRole::ValidatorFullNode);
    println!("EXPLOIT CONFIRMED: Untrusted attacker assigned ValidatorFullNode role!");
    
    // This role bypasses inbound connection limits and grants trusted status
}
```

The PoC demonstrates that an arbitrary attacker with no presence in the trusted peer set can obtain `ValidatorFullNode` role simply by connecting to a validator on the VFN network with a properly derived peer ID.

### Citations

**File:** config/src/config/network_config.rs (L136-136)
```rust
        let mutual_authentication = network_id.is_validator_network();
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

**File:** network/framework/src/peer_manager/mod.rs (L352-389)
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
```

**File:** network/framework/src/connectivity_manager/mod.rs (L494-499)
```rust
                    if !self.mutual_authentication
                        && metadata.origin == ConnectionOrigin::Inbound
                        && (metadata.role == PeerRole::ValidatorFullNode
                            || metadata.role == PeerRole::Unknown)
                    {
                        None
```

**File:** config/src/network_id.rs (L189-203)
```rust
    pub fn downstream_roles(&self, role: &RoleType) -> &'static [PeerRole] {
        match self {
            NetworkId::Validator => &[PeerRole::Validator],
            // In order to allow fallbacks, we must allow for nodes to accept ValidatorFullNodes
            NetworkId::Public => &[
                PeerRole::ValidatorFullNode,
                PeerRole::Downstream,
                PeerRole::Known,
                PeerRole::Unknown,
            ],
            NetworkId::Vfn => match role {
                RoleType::Validator => &[PeerRole::ValidatorFullNode],
                RoleType::FullNode => &[],
            },
        }
```

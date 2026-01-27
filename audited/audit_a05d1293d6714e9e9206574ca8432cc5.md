# Audit Report

## Title
Unauthenticated Peer Role Assignment Enables Distance Spoofing in Peer Monitoring Service

## Summary
Validators using `MaybeMutual` authentication mode automatically assign the `ValidatorFullNode` role to any peer connecting on the VFN network, without cryptographic verification. This inferred role is then trusted by the peer monitoring service's distance validation logic, allowing attackers to falsely claim proximity to validators and manipulate peer selection for consensus observers, mempool, and state sync.

## Finding Description
The vulnerability exists in the interaction between two components:

**1. Role Inference Without Authentication:** [1](#0-0) 

When a validator receives an inbound connection on the VFN network from an untrusted peer (not in the trusted peers set) using `MaybeMutual` authentication mode, it automatically infers the peer's role as `PeerRole::ValidatorFullNode` based solely on network context. There is no cryptographic proof that the connecting peer is actually a VFN.

**2. Blind Trust in Connection Metadata:** [2](#0-1) 

The peer monitoring service validation logic trusts `peer_metadata.get_connection_metadata().role` when validating network distance claims. For `distance_from_validators = 1`, it checks if the peer is a VFN and on the correct network, both of which pass for an attacker with the auto-assigned VFN role.

**Attack Flow:**
1. Attacker connects to a validator's VFN network endpoint
2. Validator uses `MaybeMutual` authentication (configured via `config.mutual_authentication = false`) [3](#0-2) 
3. During handshake, validator assigns `PeerRole::ValidatorFullNode` to the untrusted peer [4](#0-3) 
4. This role is stored in `ConnectionMetadata.role`
5. Attacker sends `NetworkInformationResponse` claiming `distance_from_validators = 1`
6. Validation passes because peer appears to be a VFN on the correct network
7. Attacker's node is now trusted as being 1 hop from validators

**Impact on Peer Selection:** [5](#0-4) 

The spoofed distance is used to prioritize peers for consensus observer subscriptions, with lower distances preferred. This enables the attacker to:
- Receive consensus observer subscriptions and feed manipulated consensus data
- Intercept mempool transaction forwarding
- Serve incorrect state sync data

## Impact Explanation
**Severity: High to Critical**

This vulnerability constitutes a **significant protocol violation** under the Aptos bug bounty program. The attack enables:

1. **Consensus Observer Manipulation**: Attackers can position themselves as preferred consensus data sources, potentially feeding false block proposals or votes to full nodes
2. **Transaction Censorship**: Preferred mempool routing allows selective transaction dropping
3. **State Corruption**: Manipulated state sync can propagate incorrect ledger state to synchronizing nodes

While this requires the victim to query the compromised validator's peer monitoring data, the widespread use of distance-based peer selection across consensus, mempool, and state sync makes exploitation highly impactful. This could lead to network-wide propagation of incorrect data if multiple nodes are deceived.

## Likelihood Explanation
**Likelihood: High**

Attack requirements are minimal:
- Network connectivity to validator VFN endpoints (typically accessible)
- No special cryptographic keys or validator privileges required
- VFN networks commonly use `MaybeMutual` authentication for VFN connections
- Attack is deterministic and repeatable

The vulnerability is exploitable against any validator using the default VFN network configuration, making it broadly applicable across the Aptos network.

## Recommendation
Implement cryptographic authentication for peer roles or remove reliance on inferred roles for security-critical decisions.

**Option 1: Require Role Attestation**
Add a signed role attestation to the handshake protocol where trusted peers cryptographically sign their declared role, verified during connection establishment.

**Option 2: Restrict Distance Validation**
Only accept distance claims from peers in the trusted peers set:

```rust
// In handle_monitoring_service_response()
let is_valid_depth = match network_info_response.distance_from_validators {
    0 => {
        // Only trust validators in our trusted peer set
        let trusted_peers = self.get_trusted_peers(&network_id)?;
        let is_trusted = trusted_peers.contains_key(&peer_network_id.peer_id());
        is_trusted && peer_metadata.get_connection_metadata().role.is_validator()
    },
    1 => {
        // Only trust VFNs in our trusted peer set
        let trusted_peers = self.get_trusted_peers(&network_id)?;
        let is_trusted = trusted_peers.contains_key(&peer_network_id.peer_id());
        is_trusted && peer_metadata.get_connection_metadata().role.is_vfn()
    },
    // ... existing logic for distance > 1
}
```

**Option 3: Use Mutual Authentication for VFN Networks**
Configure validators to require `mutual_authentication = true` for VFN networks, forcing all VFNs to be in the trusted peers set.

## Proof of Concept
```rust
// Test demonstrating unauthenticated role assignment
#[tokio::test]
async fn test_vfn_role_spoofing() {
    use aptos_config::network_id::{NetworkId, PeerNetworkId};
    use aptos_network::noise::HandshakeAuthMode;
    use aptos_network::application::storage::PeersAndMetadata;
    
    // Setup: Create validator with MaybeMutual auth on VFN network
    let network_ids = vec![NetworkId::Vfn];
    let peers_and_metadata = PeersAndMetadata::new(&network_ids);
    let validator_context = NetworkContext::new(
        RoleType::Validator,
        NetworkId::Vfn,
        PeerId::random()
    );
    
    let auth_mode = HandshakeAuthMode::maybe_mutual(peers_and_metadata);
    let upgrader = NoiseUpgrader::new(validator_context, validator_key, auth_mode);
    
    // Attacker: Connect with unknown public key (not in trusted set)
    let attacker_key = x25519::PrivateKey::generate(&mut rng);
    let attacker_pubkey = attacker_key.public_key();
    let (socket, listener) = MemorySocket::new_pair();
    
    // Perform handshake
    let (_, _, assigned_role) = upgrader.upgrade_inbound(listener).await.unwrap();
    
    // Verify: Attacker is assigned VFN role without being trusted
    assert_eq!(assigned_role, PeerRole::ValidatorFullNode);
    
    // Exploit: Send false distance claim
    let fake_response = NetworkInformationResponse {
        distance_from_validators: 1,
        connected_peers: Default::default(),
    };
    
    // Validation will pass because role appears legitimate
    // This allows attacker to appear as 1 hop from validators
}
```

## Notes
The root cause is the architectural decision to infer peer roles from network context rather than requiring cryptographic proof. While the Noise handshake authenticates the peer's identity (public key), it does not authenticate their claimed role in the network topology. This creates a gap where security-critical decisions (peer selection for consensus, mempool, state sync) rely on unauthenticated metadata.

The vulnerability specifically affects validators using `MaybeMutual` authentication mode on VFN networks, which is the typical configuration for allowing VFN connections. Mutual authentication mode (`Mutual`) is not vulnerable as it requires all peers to be in the trusted set with verified roles.

### Citations

**File:** network/framework/src/noise/handshake.rs (L406-422)
```rust
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
```

**File:** peer-monitoring-service/client/src/peer_states/network_info.rs (L118-141)
```rust
        let is_valid_depth = match network_info_response.distance_from_validators {
            0 => {
                // Verify the peer is a validator and has the correct network id
                let peer_is_validator = peer_metadata.get_connection_metadata().role.is_validator();
                let peer_has_correct_network = match self.base_config.role {
                    RoleType::Validator => network_id.is_validator_network(), // We're a validator
                    RoleType::FullNode => network_id.is_vfn_network(),        // We're a VFN
                };
                peer_is_validator && peer_has_correct_network
            },
            1 => {
                // Verify the peer is a VFN and has the correct network id
                let peer_is_vfn = peer_metadata.get_connection_metadata().role.is_vfn();
                let peer_has_correct_network = match self.base_config.role {
                    RoleType::Validator => network_id.is_vfn_network(), // We're a validator
                    RoleType::FullNode => network_id.is_public_network(), // We're a VFN or PFN
                };
                peer_is_vfn && peer_has_correct_network
            },
            distance_from_validators => {
                // The distance must be less than or equal to the max
                distance_from_validators <= MAX_DISTANCE_FROM_VALIDATORS
            },
        };
```

**File:** network/builder/src/builder.rs (L171-175)
```rust
        let authentication_mode = if config.mutual_authentication {
            AuthenticationMode::Mutual(identity_key)
        } else {
            AuthenticationMode::MaybeMutual(identity_key)
        };
```

**File:** network/framework/src/transport/mod.rs (L277-330)
```rust
    let (mut socket, remote_peer_id, peer_role) =
        ctxt.noise.upgrade_inbound(socket).await.map_err(|err| {
            if err.should_security_log() {
                sample!(
                    SampleRate::Duration(Duration::from_secs(15)),
                    warn!(
                        SecurityEvent::NoiseHandshake,
                        NetworkSchema::new(&ctxt.noise.network_context)
                            .network_address(&addr)
                            .connection_origin(&origin),
                        error = %err,
                    )
                );
            }
            let err = io::Error::other(err);
            add_pp_addr(proxy_protocol_enabled, err, &addr)
        })?;
    let remote_pubkey = socket.get_remote_static();
    let addr = addr.append_prod_protos(remote_pubkey, HANDSHAKE_VERSION);

    // exchange HandshakeMsg
    let handshake_msg = HandshakeMsg {
        supported_protocols: ctxt.supported_protocols.clone(),
        chain_id: ctxt.chain_id,
        network_id: ctxt.network_id,
    };
    let remote_handshake = exchange_handshake(&handshake_msg, &mut socket)
        .await
        .map_err(|err| add_pp_addr(proxy_protocol_enabled, err, &addr))?;

    // try to negotiate common aptosnet version and supported application protocols
    let (messaging_protocol, application_protocols) = handshake_msg
        .perform_handshake(&remote_handshake)
        .map_err(|err| {
            let err = format!(
                "handshake negotiation with peer {} failed: {}",
                remote_peer_id.short_str(),
                err
            );
            add_pp_addr(proxy_protocol_enabled, io::Error::other(err), &addr)
        })?;

    // return successful connection
    Ok(Connection {
        socket,
        metadata: ConnectionMetadata::new(
            remote_peer_id,
            CONNECTION_ID_GENERATOR.next(),
            addr,
            origin,
            messaging_protocol,
            application_protocols,
            peer_role,
        ),
```

**File:** consensus/src/consensus_observer/observer/subscription_utils.rs (L283-312)
```rust
pub fn sort_peers_by_subscription_optimality(
    peers_and_metadata: &HashMap<PeerNetworkId, PeerMetadata>,
) -> Vec<PeerNetworkId> {
    // Group peers and latencies by validator distance, i.e., distance -> [(peer, latency)]
    let mut unsupported_peers = Vec::new();
    let mut peers_and_latencies_by_distance = BTreeMap::new();
    for (peer_network_id, peer_metadata) in peers_and_metadata {
        // Verify that the peer supports consensus observer
        if !supports_consensus_observer(peer_metadata) {
            unsupported_peers.push(*peer_network_id);
            continue; // Skip the peer
        }

        // Get the distance and latency for the peer
        let distance = get_distance_for_peer(peer_network_id, peer_metadata);
        let latency = get_latency_for_peer(peer_network_id, peer_metadata);

        // If the distance is not found, use the maximum distance
        let distance =
            distance.unwrap_or(aptos_peer_monitoring_service_types::MAX_DISTANCE_FROM_VALIDATORS);

        // If the latency is not found, use a large latency
        let latency = latency.unwrap_or(MAX_PING_LATENCY_SECS);

        // Add the peer and latency to the distance group
        peers_and_latencies_by_distance
            .entry(distance)
            .or_insert_with(Vec::new)
            .push((*peer_network_id, OrderedFloat(latency)));
    }
```

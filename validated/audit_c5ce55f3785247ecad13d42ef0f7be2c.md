# Audit Report

## Title
Sybil Attack on State Sync Peer Selection via Unauthenticated VFN Role Inference

## Summary
Validators on VFN networks auto-assign `PeerRole::ValidatorFullNode` to untrusted inbound peers due to `MaybeMutual` authentication mode. These peers can report `distance_from_validators = 1` without verification, bypassing inbound connection limits and dominating peer selection algorithms used by state sync, consensus observer, and mempool. This enables Sybil attacks that can cause validator slowdowns and eclipse attacks.

## Finding Description

The vulnerability exists in the interaction between five system components:

**1. VFN Network Authentication Default**

VFN networks default to `mutual_authentication = false` because the network ID is not a validator network. [1](#0-0) 

This configuration is converted to `AuthenticationMode::MaybeMutual` during network initialization, which allows connections from peers not in the trusted peer set.

**2. Automatic Role Assignment Without Authentication**

When an untrusted peer (not in the trusted peer set) establishes an inbound connection to a validator on the VFN network in `MaybeMutual` mode, the handshake logic automatically infers the peer's role as `PeerRole::ValidatorFullNode` based solely on network context, without cryptographic proof of identity. [2](#0-1) 

The code path shows that when a peer is not found in the trusted peer set (line 391: "None => { // The peer is not in the trusted peer set"), the system still assigns `PeerRole::ValidatorFullNode` if the validator is on a VFN network (lines 407-410).

**3. Insufficient Distance Validation**

When peers report `distance_from_validators = 1` through the peer monitoring service, the validation logic only verifies that the peer's role is VFN and the network ID is correct. [3](#0-2) 

The validation checks `peer_is_vfn` and `peer_has_correct_network` but does NOT verify that the peer is actually in the trusted peer set or has legitimate connections to validators.

**4. Distance-Priority Peer Selection**

The state sync peer selection algorithm groups peers by distance from validators using a BTreeMap, which automatically sorts by distance in ascending order, then selects from the lowest distance group first. [4](#0-3) 

Similarly, the consensus observer uses the same distance-based prioritization pattern. [5](#0-4) 

**5. Connection Limit Bypass (Critical Amplification)**

The inbound connection limiting logic only applies to peers with `PeerRole::Unknown`. [6](#0-5) 

The code explicitly states at line 354: "Everything below here is meant for unknown peers only. The role comes from the Noise handshake and if it's not `Unknown` then it is trusted." This creates a **false trust assumption** when roles are auto-assigned without authentication, as demonstrated in the handshake code.

The connection limit check at line 375 only triggers when `conn.metadata.role == PeerRole::Unknown` (line 355), exempting all auto-assigned VFN roles from the 100 connection limit defined at [7](#0-6) 

**Attack Execution:**

1. Attacker generates multiple x25519 keypairs and derives PeerIDs
2. Establishes unlimited inbound connections to validators on VFN network (bypasses 100 connection limit due to auto-assigned VFN role)
3. Each connection receives `PeerRole::ValidatorFullNode` without authentication
4. Attacker's peer monitoring service responds with `distance_from_validators = 1`
5. Distance validation passes (only checks role and network ID, not trusted peer set membership)
6. All Sybil identities are grouped in the distance=1 tier by BTreeMap sorting
7. Peer selection algorithms (state sync, consensus observer, mempool) prioritize distance=1 peers
8. Attacker dominates peer selection across critical protocol components

## Impact Explanation

**Severity: High**

This vulnerability qualifies as High severity under the Aptos bug bounty criteria:

1. **Validator Node Slowdowns** (explicitly High severity): Malicious peers selected for state sync can provide slow or incomplete responses, degrading synchronization performance. The attack affects multiple protocol components (state sync, consensus observer, mempool) that use distance-based peer selection.

2. **Significant Protocol Violations** (explicitly High severity): The distance-based peer prioritization is a core protocol mechanism designed to optimize data propagation through the network. The vulnerability allows unauthenticated peers to manipulate this metric across multiple critical systems, violating fundamental trust assumptions embedded in the peer selection algorithms.

3. **Eclipse Attack Potential**: By establishing unlimited connections (bypassing the 100 connection limit) and dominating the distance=1 peer group, attackers can control what state data victim nodes receive. While Merkle proofs prevent invalid state injection, attackers can selectively withhold valid data, consume validator resources, and position themselves for sophisticated eclipse attacks.

The impact does not reach Critical severity because:
- Consensus safety remains intact (validator-to-validator consensus is on a separate mutually authenticated network)
- Funds cannot be directly stolen or frozen
- Cryptographic validation (Merkle proofs) prevents invalid state acceptance

## Likelihood Explanation

**Likelihood: High**

1. **Minimal Barrier**: Any network participant can establish connections to validators on VFN networks without privileged access or special credentials
2. **Simple Execution**: Requires only x25519 keypair generation, standard TCP connections, and a basic peer monitoring service implementation
3. **Default Vulnerability**: VFN networks use `MaybeMutual` mode by default, affecting all validators running standard configurations
4. **Unlimited Scale**: The connection limit bypass allows attackers to create an arbitrary number of Sybil identities, limited only by network bandwidth
5. **No Detection**: The system lacks validation mechanisms to verify that distance=1 claims correspond to actual trusted peer relationships
6. **Economic Incentive**: Enables validator performance degradation, potential MEV extraction opportunities during eclipse attacks, and competitive advantages in network disruption scenarios

## Recommendation

**Short-term Fix:**

1. Modify the distance validation logic to verify that peers claiming `distance_from_validators = 1` are actually in the trusted peer set:

```rust
// In peer-monitoring-service/client/src/peer_states/network_info.rs
1 => {
    // Verify the peer is a VFN, has the correct network id, AND is in trusted peers
    let peer_is_vfn = peer_metadata.get_connection_metadata().role.is_vfn();
    let peer_has_correct_network = match self.base_config.role {
        RoleType::Validator => network_id.is_vfn_network(),
        RoleType::FullNode => network_id.is_public_network(),
    };
    let peer_is_trusted = trusted_peers.contains_key(&peer_network_id.peer_id());
    peer_is_vfn && peer_has_correct_network && peer_is_trusted
},
```

2. Apply connection limits to all non-authenticated peers, regardless of inferred role:

```rust
// In network/framework/src/peer_manager/mod.rs
if conn.metadata.origin == ConnectionOrigin::Inbound {
    let is_authenticated = trusted_peers.contains_key(&conn.metadata.remote_peer_id);
    if !is_authenticated {
        // Count ALL unauthenticated inbound connections
        let unauthenticated_inbound_conns = self
            .active_peers
            .iter()
            .filter(|(peer_id, (metadata, _))| {
                metadata.origin == ConnectionOrigin::Inbound
                    && !trusted_peers.contains_key(peer_id)
            })
            .count();
        
        if !self.active_peers.contains_key(&conn.metadata.remote_peer_id)
            && unauthenticated_inbound_conns + 1 > self.inbound_connection_limit
        {
            // Reject connection
        }
    }
}
```

**Long-term Fix:**

Decouple role inference from authentication status. Introduce an `AuthenticationStatus` field separate from `PeerRole`, and use authentication status (not inferred role) for security-critical decisions like connection limiting and trust-based peer selection.

## Proof of Concept

```rust
// Conceptual PoC demonstrating the attack flow
// This would need to be integrated into the Aptos test framework

#[test]
fn test_sybil_attack_via_vfn_role_inference() {
    // Setup: Create a validator node with VFN network
    let validator = create_validator_node();
    let vfn_network = NetworkId::Vfn;
    
    // Attacker: Generate multiple Sybil identities
    let mut sybil_peers = vec![];
    for i in 0..200 {  // More than 100 connection limit
        let keypair = x25519::PrivateKey::generate_for_testing();
        let peer_id = from_identity_public_key(keypair.public_key());
        sybil_peers.push((peer_id, keypair));
    }
    
    // Attack: Establish connections from all Sybil identities
    for (peer_id, keypair) in &sybil_peers {
        let conn = establish_connection(
            validator,
            vfn_network,
            peer_id,
            keypair,
            /* in_trusted_set= */ false
        );
        
        // Verify role is auto-assigned to ValidatorFullNode
        assert_eq!(conn.metadata.role, PeerRole::ValidatorFullNode);
        
        // Verify connection is accepted (bypasses limit)
        assert!(conn.is_accepted());
    }
    
    // Attack: Report false distance metrics
    for (peer_id, _) in &sybil_peers {
        let response = NetworkInformationResponse {
            distance_from_validators: 1,  // False claim
            ..
        };
        validator.handle_peer_monitoring_response(peer_id, response);
    }
    
    // Verify: Sybil peers dominate peer selection
    let selected_peers = validator.state_sync.select_peers_for_request(10);
    let sybil_count = selected_peers.iter()
        .filter(|p| sybil_peers.iter().any(|(id, _)| id == &p.peer_id()))
        .count();
    
    assert!(sybil_count >= 8, "Sybil peers should dominate selection due to distance=1 priority");
}
```

## Notes

This vulnerability represents a **design flaw in the trust model** where role inference is conflated with authentication status. The system assumes that any peer with a non-Unknown role is trusted (per the comment at line 354 of peer_manager/mod.rs), but this assumption breaks down in `MaybeMutual` authentication mode where roles can be assigned without verifying membership in the trusted peer set.

The vulnerability is particularly severe because it affects multiple critical protocol components simultaneously (state sync, consensus observer, mempool), all of which rely on the distance-based peer prioritization mechanism.

### Citations

**File:** config/src/config/network_config.rs (L44-44)
```rust
pub const MAX_INBOUND_CONNECTIONS: usize = 100;
```

**File:** config/src/config/network_config.rs (L136-136)
```rust
        let mutual_authentication = network_id.is_validator_network();
```

**File:** network/framework/src/noise/handshake.rs (L391-410)
```rust
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
```

**File:** peer-monitoring-service/client/src/peer_states/network_info.rs (L128-136)
```rust
            1 => {
                // Verify the peer is a VFN and has the correct network id
                let peer_is_vfn = peer_metadata.get_connection_metadata().role.is_vfn();
                let peer_has_correct_network = match self.base_config.role {
                    RoleType::Validator => network_id.is_vfn_network(), // We're a validator
                    RoleType::FullNode => network_id.is_public_network(), // We're a VFN or PFN
                };
                peer_is_vfn && peer_has_correct_network
            },
```

**File:** state-sync/aptos-data-client/src/utils.rs (L32-60)
```rust
    let mut peers_and_latencies_by_distance = BTreeMap::new();
    for peer in peers {
        if let Some((distance, latency)) =
            get_distance_and_latency_for_peer(&peers_and_metadata, peer)
        {
            let latency_weight = convert_latency_to_weight(latency);
            peers_and_latencies_by_distance
                .entry(distance)
                .or_insert_with(Vec::new)
                .push((peer, latency_weight));
        }
    }

    // Select the peers by distance and latency weights. Note: BTreeMaps are
    // sorted by key, so the entries will be sorted by distance in ascending order.
    let mut selected_peers = HashSet::new();
    for (_, peers_and_latencies) in peers_and_latencies_by_distance {
        // Select the peers by latency weights
        let num_peers_remaining = num_peers_to_choose.saturating_sub(selected_peers.len()) as u64;
        let peers = choose_random_peers_by_weight(num_peers_remaining, peers_and_latencies);

        // Add the peers to the entire set
        selected_peers.extend(peers);

        // If we have selected enough peers, return early
        if selected_peers.len() >= num_peers_to_choose {
            return selected_peers;
        }
    }
```

**File:** consensus/src/consensus_observer/observer/subscription_utils.rs (L286-330)
```rust
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

    // If there are peers that don't support consensus observer, log them
    if !unsupported_peers.is_empty() {
        info!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Found {} peers that don't support consensus observer! Peers: {:?}",
                unsupported_peers.len(),
                unsupported_peers
            ))
        );
    }

    // Sort the peers by distance and latency. Note: BTreeMaps are
    // sorted by key, so the entries will be sorted by distance in ascending order.
    let mut sorted_peers_and_latencies = Vec::new();
    for (_, mut peers_and_latencies) in peers_and_latencies_by_distance {
        // Sort the peers by latency
        peers_and_latencies.sort_by_key(|(_, latency)| *latency);
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

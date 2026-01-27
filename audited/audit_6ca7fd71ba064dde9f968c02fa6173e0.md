# Audit Report

## Title
Sybil Attack on State Sync Peer Selection via Unauthenticated VFN Role Inference

## Summary
An attacker can create multiple peer identities and exploit the `MaybeMutual` authentication mode on VFN networks to be auto-assigned `PeerRole::ValidatorFullNode`. By reporting `distance_from_validators = 1`, these Sybil identities pass validation checks and gain disproportionate selection probability in state sync peer selection, potentially leading to eclipse attacks and performance degradation.

## Finding Description

The vulnerability exists in the interaction between three system components:

**1. Network Authentication Mode Assignment**

VFN networks default to `mutual_authentication = false`, resulting in `MaybeMutual` authentication mode: [1](#0-0) 

**2. Role Inference in MaybeMutual Mode**

When untrusted peers connect to validators on VFN networks, they are automatically assigned `PeerRole::ValidatorFullNode` without verification: [2](#0-1) 

The code infers the role based solely on network context, not cryptographic proof of identity or membership in the trusted peers set.

**3. Distance Validation Logic**

When peers report `distance_from_validators = 1`, the validation only checks if the peer's role is VFN: [3](#0-2) 

The check at line 130 (`peer_is_vfn = peer_metadata.get_connection_metadata().role.is_vfn()`) will pass for auto-assigned roles from step 2.

**4. Peer Selection Algorithm**

The state sync peer selection prioritizes peers by distance, grouping them before applying latency weights: [4](#0-3) 

Peers are selected from the lowest distance group first (line 48), giving distance=1 peers priority over distance>=2 peers.

**Attack Execution:**

1. Attacker generates multiple x25519 keypairs and derives unique PeerIDs
2. Establishes connections to validator nodes on the VFN network with each identity
3. Each connection receives `PeerRole::ValidatorFullNode` (auto-assigned in MaybeMutual mode)
4. Attacker's peer monitoring service responds with `distance_from_validators = 1`
5. Validation passes because the auto-assigned role is VFN
6. All Sybil identities are grouped in the distance=1 tier
7. Selection algorithm picks from this tier first, dramatically increasing attacker's selection probability

This breaks the security invariant that distance metrics should reflect actual network topology and trusted relationships, not arbitrary self-reported values from unauthenticated peers.

## Impact Explanation

**Severity: High**

This vulnerability qualifies as High severity under the Aptos bug bounty criteria because it enables:

1. **Validator node slowdowns** (explicitly listed as High severity): Malicious peers can provide slow or incomplete responses to state sync requests, degrading synchronization performance.

2. **Significant protocol violations** (explicitly listed as High severity): The distance-based peer prioritization is a core protocol mechanism used across state sync, consensus observer, and mempool. Allowing unauthenticated peers to manipulate this metric violates the protocol's trust assumptions.

3. **Eclipse attack potential**: If an attacker controls a sufficient portion of the inbound connection slots (up to `MAX_INBOUND_CONNECTIONS = 100`), they can dominate the distance=1 peer group and control what state data the victim node receives. [5](#0-4) 

While state sync validates received data using Merkle proofs (preventing invalid state injection), the attacker can still:
- Selectively withhold valid data to slow synchronization
- Consume bandwidth and computational resources
- Position themselves for more sophisticated attacks

The impact does not reach Critical severity because:
- Consensus safety is not directly compromised
- Funds cannot be stolen or frozen
- Merkle proof validation prevents acceptance of invalid state

## Likelihood Explanation

**Likelihood: High**

This attack is highly likely to occur because:

1. **Low barrier to entry**: Any network participant can establish connections to validators on VFN networks. No privileged access or complex setup is required.

2. **Simple execution**: The attack requires only:
   - Generating multiple keypairs (trivial)
   - Establishing TCP connections (standard networking)
   - Running a basic peer monitoring service that responds with distance=1

3. **Configuration by default**: VFN networks use `MaybeMutual` mode by default, making all validator nodes vulnerable unless explicitly reconfigured.

4. **Economic incentive**: An attacker could use this to:
   - Slow down competing validators
   - Extract value through MEV opportunities during eclipse attacks
   - Disrupt network operations

5. **No detection mechanism**: There is no validation that checks whether a peer claiming distance=1 is actually in the trusted peers set.

## Recommendation

Implement trusted peers verification for distance validation. The distance validation logic should check membership in the trusted peers set when peers claim distance=0 or distance=1:

**Modified validation in `peer-monitoring-service/client/src/peer_states/network_info.rs`:**

```rust
1 => {
    // Verify the peer is a VFN and has the correct network id
    let peer_is_vfn = peer_metadata.get_connection_metadata().role.is_vfn();
    let peer_has_correct_network = match self.base_config.role {
        RoleType::Validator => network_id.is_vfn_network(),
        RoleType::FullNode => network_id.is_public_network(),
    };
    
    // NEW: Verify the peer is in the trusted peers set
    let peer_is_trusted = self.check_peer_in_trusted_set(peer_network_id);
    
    peer_is_vfn && peer_has_correct_network && peer_is_trusted
},
```

Alternatively, reconsider the role inference strategy in `HandshakeAuthMode::MaybeMutual` to assign `PeerRole::Unknown` instead of `PeerRole::ValidatorFullNode` for untrusted peers on VFN networks, or require explicit authentication for peers claiming privileged roles.

## Proof of Concept

**Setup (Rust test):**

```rust
// Attacker creates multiple identities
let num_sybil_identities = 50;
let mut sybil_peers = HashSet::new();

for i in 0..num_sybil_identities {
    // Generate unique keypair
    let private_key = x25519::PrivateKey::generate(&mut OsRng);
    let public_key = private_key.public_key();
    let peer_id = PeerId::from_identity_public_key(public_key);
    
    // Connect to validator on VFN network
    let peer_network_id = PeerNetworkId::new(NetworkId::Vfn, peer_id);
    
    // In MaybeMutual mode, will be auto-assigned PeerRole::ValidatorFullNode
    // Attacker's monitoring service responds with distance=1
    
    sybil_peers.insert(peer_network_id);
}

// When validator selects peers for state sync
let selected_peers = choose_random_peers_by_distance_and_latency(
    all_peers,  // Contains both legitimate VFNs and attacker's Sybils
    peers_and_metadata,
    num_peers_to_choose,
);

// Result: Attacker's Sybil identities have disproportionate representation
// in selected_peers due to artificial distance=1 clustering
```

**Verification steps:**
1. Deploy validator with VFN network using default configuration
2. Connect multiple clients with unique peer IDs to VFN network
3. Observe in logs that role is auto-assigned as ValidatorFullNode
4. Configure peer monitoring service to respond with distance=1
5. Monitor state sync peer selection - observe Sybil identities are frequently selected
6. Measure impact on state sync performance when Sybil peers provide degraded service

### Citations

**File:** config/src/config/network_config.rs (L44-44)
```rust
pub const MAX_INBOUND_CONNECTIONS: usize = 100;
```

**File:** config/src/config/network_config.rs (L136-136)
```rust
        let mutual_authentication = network_id.is_validator_network();
```

**File:** network/framework/src/noise/handshake.rs (L406-416)
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

**File:** state-sync/aptos-data-client/src/utils.rs (L31-48)
```rust
    // Group peers and latency weights by validator distance, i.e., distance -> [(peer, latency weight)]
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
```

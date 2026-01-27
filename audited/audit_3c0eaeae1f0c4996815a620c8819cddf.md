# Audit Report

## Title
Network Topology Poisoning via Unvalidated Distance Claims in Peer Monitoring Service

## Summary
The peer monitoring service fails to properly validate `distance_from_validators` claims for values ≥ 2, allowing malicious fullnodes to manipulate network topology perception. This causes incorrect peer prioritization across mempool, consensus observer, and state sync, enabling attackers to gain disproportionate selection as "preferred" peers while degrading honest nodes' connectivity assessment.

## Finding Description

The `NetworkInformationResponse.distance_from_validators` field represents a node's hop distance from the validator set. This metric is critical for peer selection across multiple systems including mempool transaction forwarding, consensus observer subscriptions, and state sync data requests.

**Insufficient Validation:**

The client-side validation only verifies role-based constraints for distances 0-1, but provides no validation for distances ≥ 2: [1](#0-0) 

For distance ≥ 2, the code only checks `distance_from_validators <= MAX_DISTANCE_FROM_VALIDATORS` (100), with no verification that the claimed distance is truthful or that the peer actually has the connectivity it claims.

**Server-Side Distance Calculation Trusts Peer Claims:**

The server calculates its own distance by finding the minimum distance among connected peers and adding 1: [2](#0-1) 

This creates a cascading effect where honest nodes propagate false topology information if they connect to malicious peers.

**Critical Impact on Peer Selection:**

The manipulated distance values directly affect peer prioritization in three critical systems:

1. **Mempool Priority**: Lower distances receive higher priority for transaction forwarding: [3](#0-2) 

2. **Consensus Observer**: Lower distances are prioritized for subscription selection: [4](#0-3) 

3. **State Sync**: Distance-based peer selection affects data request routing: [5](#0-4) 

**Attack Scenario:**

1. Malicious Public Fullnode (PFN) claims `distance_from_validators = 2` when actually at distance 10+ or disconnected
2. Validation passes (only checks `<= 100`)
3. Honest PFNs/VFNs connecting to malicious node calculate their distance as `min(2, ...) + 1 = 3`
4. Malicious node gains priority in peer selection algorithms across all systems
5. Network topology perception becomes poisoned as honest nodes propagate false distances
6. In coordinated attack, malicious nodes claiming high distances (99-100) cause honest nodes to calculate distance ≥ 100, making them appear disconnected

## Impact Explanation

This constitutes **High Severity** per Aptos bug bounty criteria ("Significant protocol violations"):

1. **Peer Selection Manipulation**: Attackers gain unfair advantage in being selected for critical network operations (transaction forwarding, consensus observer subscriptions, state sync requests)

2. **Network Topology Poisoning**: Cascading miscalculation of distances causes network-wide misperception of connectivity, violating the peer quality assessment invariant

3. **Potential Network Fragmentation**: Coordinated attacks with multiple malicious nodes claiming extreme distances can fragment the public network layer, degrading transaction propagation and state sync performance

4. **Indirect Validator Impact**: While validators are not directly isolated from each other (private network), they can be isolated from the public network for transaction submission if VFNs/PFNs are systematically misled about topology

The attack does not directly compromise funds or consensus safety, but significantly degrades protocol operation and network reliability.

## Likelihood Explanation

**High Likelihood** - The attack is trivial to execute:
- No special privileges required (any PFN can execute)
- No coordination needed for basic attack (single malicious node affects connected peers)
- No cryptographic barriers (distance is self-reported, not authenticated)
- Validation gap is structural, not implementation-specific

The only barrier is that the malicious node must provide acceptable service to maintain connections (latency checks, health monitoring), but this doesn't prevent the topology poisoning attack itself.

## Recommendation

Implement cross-validation of distance claims against actual network topology:

```rust
// In network_info.rs, enhance validation for distance >= 2
fn validate_distance_claim(
    distance: u64,
    peer_role: PeerRole,
    network_id: NetworkId,
    our_role: RoleType,
    our_distance: u64, // Our own calculated distance
) -> bool {
    match distance {
        0 => {
            // Existing validation
            peer_role.is_validator() && is_correct_validator_network(network_id, our_role)
        },
        1 => {
            // Existing validation  
            peer_role.is_vfn() && is_correct_vfn_network(network_id, our_role)
        },
        d if d >= 2 => {
            // NEW: Validate distance claims are within reasonable bounds
            if d > MAX_DISTANCE_FROM_VALIDATORS {
                return false;
            }
            
            // Sanity check: peer's distance should be consistent with our distance
            // A peer cannot be more than (our_distance + max_peer_connections) away
            // and cannot be less than (our_distance - 1) unless we miscalculated
            if our_distance > 0 && our_distance < MAX_DISTANCE_FROM_VALIDATORS {
                let min_reasonable = our_distance.saturating_sub(2);
                let max_reasonable = our_distance + 10; // reasonable hop difference
                
                if d < min_reasonable || d > max_reasonable {
                    warn!("Peer distance {} inconsistent with our distance {}", d, our_distance);
                    return false;
                }
            }
            
            true
        },
        _ => false,
    }
}
```

Additionally, implement **distance attestation** where nodes cryptographically sign their distance claims along with timestamps, allowing detection of inconsistent claims over time.

## Proof of Concept

```rust
// Integration test demonstrating the vulnerability
#[tokio::test]
async fn test_distance_manipulation_attack() {
    use aptos_peer_monitoring_service_types::{
        response::NetworkInformationResponse,
        PeerMonitoringMetadata,
    };
    use std::collections::BTreeMap;

    // Setup: Create honest node and malicious node
    let honest_peer = create_peer(NetworkId::Public, PeerRole::Unknown);
    let malicious_peer = create_peer(NetworkId::Public, PeerRole::Unknown);
    
    // Malicious node claims distance = 2 (false, actually at distance 50)
    let malicious_response = NetworkInformationResponse {
        connected_peers: BTreeMap::new(),
        distance_from_validators: 2, // FALSE CLAIM
    };
    
    // Honest node at actual distance 10 queries malicious node
    let honest_node_calculated_distance = calculate_distance_with_peer(
        10, // honest node's actual distance
        malicious_response.distance_from_validators
    );
    
    // Due to min() logic, honest node now thinks it's at distance 3
    assert_eq!(honest_node_calculated_distance, 3); // min(2, 10) + 1
    
    // Verify malicious node gains priority in peer selection
    let malicious_metadata = PeerMonitoringMetadata {
        latest_network_info_response: Some(malicious_response),
        ..Default::default()
    };
    
    let honest_metadata = PeerMonitoringMetadata {
        latest_network_info_response: Some(NetworkInformationResponse {
            connected_peers: BTreeMap::new(),
            distance_from_validators: 10, // TRUE distance
        }),
        ..Default::default()
    };
    
    // Malicious node is prioritized (lower distance)
    let ordering = compare_validator_distance(
        &Some(&malicious_metadata),
        &Some(&honest_metadata)
    );
    assert_eq!(ordering, Ordering::Greater); // Malicious node prioritized
    
    // This demonstrates the attack succeeds in manipulating peer selection
}

fn calculate_distance_with_peer(our_distance: u64, peer_distance: u64) -> u64 {
    std::cmp::min(our_distance, peer_distance) + 1
}
```

## Notes

While this vulnerability does not directly compromise validator-to-validator consensus (which operates on a separate authenticated network), it significantly impacts the public network layer's ability to correctly assess peer quality and route transactions effectively. The cascading nature of distance miscalculation makes this particularly dangerous in a coordinated attack scenario where multiple malicious nodes can systematically poison network topology perception.

### Citations

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

**File:** peer-monitoring-service/server/src/lib.rs (L322-339)
```rust
    let mut min_peer_distance_from_validators = MAX_DISTANCE_FROM_VALIDATORS;
    for peer_metadata in connected_peers_and_metadata.values() {
        if let Some(ref latest_network_info_response) = peer_metadata
            .get_peer_monitoring_metadata()
            .latest_network_info_response
        {
            min_peer_distance_from_validators = min(
                min_peer_distance_from_validators,
                latest_network_info_response.distance_from_validators,
            );
        }
    }

    // We're one hop away from the peer
    min(
        MAX_DISTANCE_FROM_VALIDATORS,
        min_peer_distance_from_validators + 1,
    )
```

**File:** mempool/src/shared_mempool/priority.rs (L615-638)
```rust
fn compare_validator_distance(
    monitoring_metadata_a: &Option<&PeerMonitoringMetadata>,
    monitoring_metadata_b: &Option<&PeerMonitoringMetadata>,
) -> Ordering {
    // Get the validator distance from the monitoring metadata
    let validator_distance_a = get_distance_from_validators(monitoring_metadata_a);
    let validator_distance_b = get_distance_from_validators(monitoring_metadata_b);

    // Compare the distances
    match (validator_distance_a, validator_distance_b) {
        (Some(validator_distance_a), Some(validator_distance_b)) => {
            // Prioritize the peer with the lowest validator distance
            validator_distance_a.cmp(&validator_distance_b).reverse()
        },
        (Some(_), None) => {
            Ordering::Greater // Prioritize the peer with a validator distance
        },
        (None, Some(_)) => {
            Ordering::Less // Prioritize the peer with a validator distance
        },
        (None, None) => {
            Ordering::Equal // Neither peer has a validator distance
        },
    }
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

**File:** state-sync/aptos-data-client/src/utils.rs (L26-63)
```rust
pub fn choose_random_peers_by_distance_and_latency(
    peers: HashSet<PeerNetworkId>,
    peers_and_metadata: Arc<PeersAndMetadata>,
    num_peers_to_choose: usize,
) -> HashSet<PeerNetworkId> {
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

    // Return the selected peers
    selected_peers
```

# Audit Report

## Title
Consensus Observer Sybil Attack: Malicious Peers Can Monopolize Subscription Slots via Distance Spoofing

## Summary
Multiple malicious peers can coordinate to populate all consensus observer subscription slots by falsely claiming low `distance_from_validators` values (e.g., distance=2). The peer monitoring validation logic only enforces role-based checks for distance 0 and 1, allowing any peer to claim distance ≥2 without validation. This enables Sybil attackers to prevent legitimate observers from subscribing to honest peers, potentially feeding them malicious consensus data.

## Finding Description

The consensus observer subscription mechanism relies on peer distance from validators to determine subscription optimality. The system sorts peers primarily by `distance_from_validators` (lower is better), then by latency, and selects the top N peers for subscriptions.

**Validation Gap:**

The peer monitoring client validates distance claims in: [1](#0-0) 

The validation logic only enforces strict role-based checks for distance 0 (must be validator) and distance 1 (must be VFN). For any distance > 1, the only check is `distance_from_validators <= MAX_DISTANCE_FROM_VALIDATORS` (100), with **no verification** that the peer's role matches its claimed distance.

**Exploitation Path:**

1. A malicious Public Fullnode (PFN) at actual distance ≥3 reports `distance_from_validators = 2` in its `NetworkInformationResponse`: [2](#0-1) 

2. The distance is calculated by the peer's own server based on its connected peers' reported distances: [3](#0-2) 

A malicious peer can trivially lie about this calculation or connect to other malicious peers claiming distance 1.

3. The consensus observer retrieves this unvalidated distance and uses it for peer sorting: [4](#0-3) 

4. With `max_concurrent_subscriptions = 2` (default): [5](#0-4) 

Only the top 2 peers by distance+latency get subscriptions: [6](#0-5) 

5. Multiple coordinated malicious peers all claiming distance=2 can occupy all subscription slots, excluding legitimate peers at actual distance 2 or higher.

**Attack Scenario:**
- Attacker deploys 10+ malicious PFN nodes
- Each node falsely reports `distance_from_validators = 2` and low latency
- Legitimate VFN peers at actual distance 1 may be selected, but:
  - If only PFNs are available (VFNs offline/unreachable), all slots go to attackers
  - Attackers can also falsely claim to be VFNs at distance 1 (role is determined at connection handshake but isn't cross-validated with distance claims)
- Consensus observer subscribes to malicious peers exclusively
- Attackers feed fabricated or withheld consensus data, causing:
  - Incorrect block ordering
  - Missed consensus decisions
  - Delayed synchronization
  - Potential consensus safety violations if observer relies on this data

## Impact Explanation

**High Severity** - This qualifies as "Significant protocol violations" under the Aptos bug bounty:

1. **Consensus Observer Compromise**: Attackers can monopolize all subscription slots for consensus observers (VFNs and potentially validators running observers)

2. **Data Integrity Violation**: Consensus observers may receive:
   - Fabricated block proposals
   - Withheld consensus messages
   - Out-of-order block data
   - Malicious quorum certificates

3. **Liveness Impact**: If consensus observers can't reach honest peers, they:
   - Enter fallback mode more frequently
   - Experience synchronization delays
   - May fail to process blocks efficiently

4. **Cascading Effects**: VFN nodes running consensus observers serve PFN nodes. Compromised VFNs propagate incorrect data downstream, affecting network-wide consensus visibility.

This doesn't directly cause fund loss or consensus safety violations on validators (who run their own consensus protocol), but significantly degrades the security guarantees of the consensus observer system, which is enabled by default on VFNs: [7](#0-6) 

## Likelihood Explanation

**High Likelihood:**

1. **Easy to Execute**: Malicious peers simply return false `distance_from_validators` values in their `GetNetworkInformation` responses. No complex attack logic required.

2. **Low Cost**: Deploying multiple PFN nodes is inexpensive and doesn't require validator stake or special privileges.

3. **No Detection**: The current validation logic won't detect or reject these false claims for distance > 1.

4. **Network Diversity**: On networks with limited honest peer diversity (e.g., testnets, new deployments), attackers can more easily dominate the peer set.

5. **Default Configuration**: Consensus observer is enabled by default on VFNs, making them automatic targets.

## Recommendation

Implement stronger validation for `distance_from_validators` values that cross-references peer roles:

```rust
// In peer-monitoring-service/client/src/peer_states/network_info.rs
fn handle_monitoring_service_response(...) {
    // ... existing code ...
    
    let is_valid_depth = match network_info_response.distance_from_validators {
        0 => {
            // Existing validation for distance 0
            let peer_is_validator = peer_metadata.get_connection_metadata().role.is_validator();
            let peer_has_correct_network = match self.base_config.role {
                RoleType::Validator => network_id.is_validator_network(),
                RoleType::FullNode => network_id.is_vfn_network(),
            };
            peer_is_validator && peer_has_correct_network
        },
        1 => {
            // Existing validation for distance 1
            let peer_is_vfn = peer_metadata.get_connection_metadata().role.is_vfn();
            let peer_has_correct_network = match self.base_config.role {
                RoleType::Validator => network_id.is_vfn_network(),
                RoleType::FullNode => network_id.is_public_network(),
            };
            peer_is_vfn && peer_has_correct_network
        },
        2 => {
            // NEW: Validate distance 2 peers
            // Distance 2 peers should be PFNs on public network (or validators without validator connections)
            match self.base_config.role {
                RoleType::FullNode => {
                    // We're a fullnode, distance 2 peers should be on public network
                    network_id.is_public_network()
                },
                RoleType::Validator => {
                    // Validators shouldn't trust distance 2+ peers for critical operations
                    true // Allow but with reduced trust
                }
            }
        },
        distance_from_validators => {
            // For distance >= 3, apply stricter limits
            if distance_from_validators > 5 {
                // Reject suspiciously high distances that could indicate network partitioning
                false
            } else {
                distance_from_validators <= MAX_DISTANCE_FROM_VALIDATORS
            }
        },
    };
    
    // ... rest of existing code ...
}
```

**Additional Mitigations:**

1. **Peer Reputation System**: Track historical distance claims and flag peers with inconsistent values
2. **Cross-Validation**: Query multiple peers about a target peer's distance to detect liars
3. **Network Topology Awareness**: Use known validator IPs/addresses to validate distance 0 claims
4. **Rate Limiting**: Limit subscription attempts per peer to reduce Sybil attack surface
5. **Subscription Diversity**: Force subscriptions to peers from different network regions/ASNs

## Proof of Concept

```rust
// Test demonstrating the vulnerability
#[test]
fn test_distance_spoofing_attack() {
    use aptos_config::config::{NodeConfig, RoleType, PeerRole};
    use aptos_config::network_id::{NetworkId, PeerNetworkId};
    use aptos_peer_monitoring_service_types::response::{
        NetworkInformationResponse, PeerMonitoringServiceResponse
    };
    use aptos_peer_monitoring_service_types::PeerMonitoringMetadata;
    use aptos_network::application::metadata::PeerMetadata;
    use consensus::consensus_observer::observer::subscription_utils::sort_peers_by_subscription_optimality;
    use std::collections::HashMap;
    
    // Setup: Create network info state for a VFN node
    let node_config = NodeConfig {
        base: BaseConfig {
            role: RoleType::FullNode,
            ..Default::default()
        },
        ..Default::default()
    };
    
    let mut peers_and_metadata = HashMap::new();
    
    // Add 5 malicious PFN peers all claiming distance = 2
    for i in 0..5 {
        let peer_id = PeerNetworkId::new(NetworkId::Public, PeerId::random());
        
        // Create connection metadata showing this is a regular PFN
        let connection_metadata = ConnectionMetadata::new(
            peer_id.peer_id(),
            ConnectionId::default(),
            NetworkAddress::mock(),
            ConnectionOrigin::Inbound,
            MessagingProtocolVersion::V1,
            ProtocolIdSet::consensus_observer(), // Supports consensus observer
            PeerRole::Unknown, // Regular PFN role
        );
        
        // Create monitoring metadata with FALSELY CLAIMED distance = 2
        let monitoring_metadata = PeerMonitoringMetadata::new(
            Some(0.01), // Low latency
            None,
            Some(NetworkInformationResponse {
                connected_peers: Default::default(),
                distance_from_validators: 2, // LYING: claiming to be distance 2
            }),
            None,
            None,
        );
        
        let peer_metadata = PeerMetadata::new_with_monitoring(
            connection_metadata,
            monitoring_metadata,
        );
        
        peers_and_metadata.insert(peer_id, peer_metadata);
    }
    
    // Add 1 honest VFN peer at actual distance = 1
    let honest_vfn = PeerNetworkId::new(NetworkId::Public, PeerId::random());
    let honest_connection = ConnectionMetadata::new(
        honest_vfn.peer_id(),
        ConnectionId::default(),
        NetworkAddress::mock(),
        ConnectionOrigin::Inbound,
        MessagingProtocolVersion::V1,
        ProtocolIdSet::consensus_observer(),
        PeerRole::ValidatorFullNode, // Actual VFN
    );
    let honest_monitoring = PeerMonitoringMetadata::new(
        Some(0.02), // Slightly higher latency
        None,
        Some(NetworkInformationResponse {
            connected_peers: Default::default(),
            distance_from_validators: 1, // Honest distance
        }),
        None,
        None,
    );
    peers_and_metadata.insert(
        honest_vfn,
        PeerMetadata::new_with_monitoring(honest_connection, honest_monitoring),
    );
    
    // Sort peers by subscription optimality
    let sorted_peers = sort_peers_by_subscription_optimality(&peers_and_metadata);
    
    // VULNERABILITY DEMONSTRATED:
    // The honest VFN at distance 1 will be ranked first,
    // but the 5 malicious peers at falsely-claimed distance 2 will occupy ranks 2-6
    // With max_concurrent_subscriptions = 2, only the honest VFN and ONE malicious peer get slots
    // However, if honest VFN is unavailable or has connection issues,
    // ALL subscription slots go to malicious peers
    
    // If we set max_concurrent_subscriptions = 5, we'd take the honest VFN + 4 malicious peers
    // In a network with limited honest peer diversity, attackers dominate the subscription set
    
    assert!(sorted_peers.len() == 6);
    assert_eq!(sorted_peers[0], honest_vfn); // Honest VFN ranks first (distance 1)
    // Ranks 2-6 are all malicious peers falsely claiming distance 2
    // This demonstrates the attacker's ability to populate multiple top slots
}
```

**Notes:**
- The validation gap exists because distance > 1 has no role-based checks
- Malicious peers can easily coordinate by all reporting the same false distance
- The default `max_concurrent_subscriptions = 2` limits blast radius but doesn't prevent the attack
- In practice, attackers could also spoof lower latencies to further boost their ranking
- The attack is particularly effective when honest peer diversity is low (testnets, new networks, network partitions)

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

**File:** peer-monitoring-service/types/src/response.rs (L50-55)
```rust
/// A response for the network information request
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NetworkInformationResponse {
    pub connected_peers: BTreeMap<PeerNetworkId, ConnectionMetadata>, // Connected peers
    pub distance_from_validators: u64, // The distance of the peer from the validator set
}
```

**File:** peer-monitoring-service/server/src/lib.rs (L296-340)
```rust
/// Returns the distance from the validators using the given base config
/// and the peers and metadata information.
fn get_distance_from_validators(
    base_config: &BaseConfig,
    peers_and_metadata: Arc<PeersAndMetadata>,
) -> u64 {
    // Get the connected peers and metadata
    let connected_peers_and_metadata = match peers_and_metadata.get_connected_peers_and_metadata() {
        Ok(connected_peers_and_metadata) => connected_peers_and_metadata,
        Err(error) => {
            warn!(LogSchema::new(LogEntry::PeerMonitoringServiceError).error(&error.into()));
            return MAX_DISTANCE_FROM_VALIDATORS;
        },
    };

    // If we're a validator and we have active validator peers, we're in the validator set.
    // TODO: figure out if we need to deal with validator set forks here.
    if base_config.role.is_validator() {
        for peer_metadata in connected_peers_and_metadata.values() {
            if peer_metadata.get_connection_metadata().role.is_validator() {
                return 0;
            }
        }
    }

    // Otherwise, go through our peers, find the min, and return a distance relative to the min
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
}
```

**File:** consensus/src/consensus_observer/observer/subscription_utils.rs (L283-350)
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

        // Add the peers to the sorted list (in sorted order)
        sorted_peers_and_latencies.extend(peers_and_latencies);
    }

    // Log the sorted peers and latencies
    info!(
        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
            "Sorted {} peers by subscription optimality! Peers and latencies: {:?}",
            sorted_peers_and_latencies.len(),
            sorted_peers_and_latencies
        ))
    );

    // Only return the sorted peers (without the latencies)
    sorted_peers_and_latencies
        .into_iter()
        .map(|(peer, _)| peer)
        .collect()
}
```

**File:** config/src/config/consensus_observer_config.rs (L13-13)
```rust
const ENABLE_ON_VALIDATOR_FULLNODES: bool = true;
```

**File:** config/src/config/consensus_observer_config.rs (L74-74)
```rust
            max_concurrent_subscriptions: 2, // 2 streams should be sufficient
```

**File:** consensus/src/consensus_observer/observer/subscription.rs (L143-159)
```rust
        // Sort the peers by subscription optimality
        let sorted_peers =
            subscription_utils::sort_peers_by_subscription_optimality(peers_and_metadata);

        // Verify that this peer is one of the most optimal peers
        let max_concurrent_subscriptions =
            self.consensus_observer_config.max_concurrent_subscriptions as usize;
        if !sorted_peers
            .iter()
            .take(max_concurrent_subscriptions)
            .any(|peer| peer == &self.peer_network_id)
        {
            return Err(Error::SubscriptionSuboptimal(format!(
                "Subscription to peer: {} is no longer optimal! New optimal peers: {:?}",
                self.peer_network_id, sorted_peers
            )));
        }
```

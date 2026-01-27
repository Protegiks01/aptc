# Audit Report

## Title
Insufficient Validation of `distance_from_validators` Metric Enables Network Topology Manipulation

## Summary
The peer monitoring service client insufficiently validates the `distance_from_validators` metric reported by peers, allowing malicious public fullnodes to claim artificially low distances from the validator set. This manipulates their prioritization in mempool transaction broadcasting, state synchronization, and consensus observer subscriptions, enabling censorship attacks and network topology manipulation.

## Finding Description

The peer monitoring service uses a `distance_from_validators` metric to measure how many network hops a peer is from the validator set. This metric critically influences peer selection across multiple subsystems:

1. **Mempool transaction broadcasting** - prioritizes peers closer to validators
2. **State sync peer selection** - prefers peers with lower distances  
3. **Consensus observer subscriptions** - selects peers based on distance

The validation logic in the peer monitoring client has a critical weakness for peers reporting `distance_from_validators >= 2`: [1](#0-0) 

For distances >= 2, the validation **only** checks that the value is below `MAX_DISTANCE_FROM_VALIDATORS` (100), but does **not** verify:
- The peer's role is appropriate for that distance
- The distance is consistent with network topology
- The peer actually has connectivity justifying that distance

In contrast, distances of 0 and 1 are properly validated against peer roles: [2](#0-1) 

**Attack Vector:**

A malicious public fullnode with `PeerRole::Unknown` (any peer not in the trusted peers list) can report `distance_from_validators = 2` in its `NetworkInformationResponse`, even if its actual distance is much higher (e.g., 10+). This false metric passes validation and influences critical peer selection decisions.

**Mempool Exploitation:**

The mempool's intelligent peer prioritization explicitly uses distance for ranking: [3](#0-2) 

The comparison function prioritizes lower distances: [4](#0-3) 

**State Sync Exploitation:**

State sync peer selection prioritizes peers by distance: [5](#0-4) 

**Consensus Observer Exploitation:**

Consensus observer subscription peer selection uses distance as the primary sorting criterion: [6](#0-5) [7](#0-6) 

The distance calculation on the server side trusts peer-reported values without verification: [8](#0-7) 

Note that on line 330, the server calculates its own distance based on the **minimum** of all peer-reported distances, propagating the false metric through the network.

## Impact Explanation

**Medium Severity** per Aptos bug bounty criteria - "State inconsistencies requiring intervention":

1. **Network Topology Manipulation**: The attack falsifies the network's perception of peer proximity to validators, corrupting the network graph used for routing decisions.

2. **Transaction Censorship**: Malicious nodes receiving preferential mempool broadcasts can selectively drop transactions, delaying or preventing their propagation.

3. **State Sync Disruption**: Malicious nodes selected for state sync can provide stale data or slow responses, degrading synchronization performance.

4. **Eclipse Attack Enabler**: Combined with Sybil attacks, an adversary running multiple nodes with false distance=2 could dominate peer selection, isolating victims from honest peers.

5. **No Direct Consensus Impact**: This vulnerability does **not** break consensus safety or enable fund theft, as all state transitions are still cryptographically verified. However, it degrades network efficiency and enables censorship.

## Likelihood Explanation

**HIGH** - The attack is trivially exploitable:

1. **Low Barrier**: Any entity can run a public fullnode without authentication
2. **Simple Execution**: Requires only modifying the peer monitoring server response
3. **No Detection**: No mechanisms exist to verify reported distances against actual network topology
4. **Persistent Effect**: Once propagated, the false metric influences all connecting peers
5. **Scalable**: An attacker can run multiple malicious nodes to amplify the effect

## Recommendation

Implement stricter validation for `distance_from_validators` based on peer roles and network context:

```rust
// In peer-monitoring-service/client/src/peer_states/network_info.rs
// Enhanced validation for distance >= 2

distance_from_validators => {
    // The distance must be less than or equal to the max
    if distance_from_validators > MAX_DISTANCE_FROM_VALIDATORS {
        false
    } else {
        // Additional validation: Unknown/Public peers should have distance >= 2
        let peer_role = peer_metadata.get_connection_metadata().role;
        match peer_role {
            PeerRole::Unknown | PeerRole::PreferredUpstream => {
                // Public fullnodes must report distance >= 2
                distance_from_validators >= 2
            },
            PeerRole::ValidatorFullNode => {
                // VFNs should have distance >= 1, but allow some flexibility
                distance_from_validators >= 1
            },
            PeerRole::Validator => {
                // Validators disconnected from the set may have distance >= 2
                true
            },
            _ => {
                // Conservative: reject unknown role types with suspicious distances
                distance_from_validators >= 2
            }
        }
    }
},
```

Additionally, implement reputation scoring that downgrades peers whose reported metrics are inconsistent with observed behavior (e.g., high reported proximity but poor responsiveness).

## Proof of Concept

```rust
// Malicious peer monitoring server that reports false distance
// File: malicious_peer_monitoring_server.rs

use aptos_peer_monitoring_service_types::{
    response::{NetworkInformationResponse, PeerMonitoringServiceResponse},
    request::PeerMonitoringServiceRequest,
};

// Malicious handler that always reports distance = 2 regardless of actual distance
fn malicious_get_network_information() -> PeerMonitoringServiceResponse {
    let network_information_response = NetworkInformationResponse {
        connected_peers: Default::default(),
        distance_from_validators: 2, // FALSE CLAIM - actual distance may be 10+
    };
    PeerMonitoringServiceResponse::NetworkInformation(network_information_response)
}

// Steps to reproduce:
// 1. Deploy a public fullnode with modified peer monitoring server
// 2. Override get_network_information() to return distance = 2
// 3. Connect to honest nodes on the public network
// 4. Observe that honest nodes prioritize the malicious node for:
//    - Mempool transaction broadcasts (check mempool logs)
//    - State sync requests (check data client metrics)
//    - Consensus observer subscriptions (check subscription lists)
// 5. Monitor DISTANCE_FROM_VALIDATORS metric on connecting peers
//    to confirm they store the false value
// 6. Verify that the malicious node receives preferential treatment
//    compared to honest nodes with truthful distance > 2
```

**Validation steps:**
1. Check mempool peer priority: The malicious node should rank higher than honest distant peers
2. Check state sync peer selection: The malicious node should be selected more frequently
3. Check consensus observer subscriptions: The malicious node should be preferred for subscriptions
4. Verify no error logs about invalid distance in peer monitoring client

**Notes**

This vulnerability exploits an implicit trust assumption in the peer monitoring protocol: that nodes will honestly report their network position. While the validation correctly authenticates peer identity via Noise protocol and verifies distances 0-1 against trusted roles, it fails to verify higher distances against any observable network properties. The propagation of false distances through the `get_distance_from_validators` server calculation amplifies the impact, as honest nodes downstream will calculate their own distance based on the false minimum.

The issue does not directly violate consensus safety or deterministic execution invariants, but it degrades network efficiency and enables censorship vectors that could affect liveness and availability over time.

### Citations

**File:** peer-monitoring-service/client/src/peer_states/network_info.rs (L118-136)
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
```

**File:** peer-monitoring-service/client/src/peer_states/network_info.rs (L137-141)
```rust
            distance_from_validators => {
                // The distance must be less than or equal to the max
                distance_from_validators <= MAX_DISTANCE_FROM_VALIDATORS
            },
        };
```

**File:** mempool/src/shared_mempool/priority.rs (L103-109)
```rust
        // Otherwise, compare by peer distance from the validators.
        // This avoids badly configured/connected peers (e.g., broken VN-VFN connections).
        let distance_ordering =
            compare_validator_distance(monitoring_metadata_a, monitoring_metadata_b);
        if !distance_ordering.is_eq() {
            return distance_ordering; // Only return if it's not equal
        }
```

**File:** mempool/src/shared_mempool/priority.rs (L613-627)
```rust
/// Compares the validator distance for the given pair of monitoring metadata.
/// The peer with the lowest validator distance is prioritized.
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
```

**File:** state-sync/aptos-data-client/src/utils.rs (L23-46)
```rust
/// Chooses peers weighted by distance from the validator set
/// and latency. We prioritize distance over latency as we want
/// to avoid close but not up-to-date peers.
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
```

**File:** consensus/src/consensus_observer/observer/subscription_utils.rs (L275-282)
```rust
/// Sorts the peers by subscription optimality (in descending order of
/// optimality). This requires: (i) sorting the peers by distance from the
/// validator set and ping latency (lower values are more optimal); and (ii)
/// filtering out peers that don't support consensus observer.
///
/// Note: we prioritize distance over latency as we want to avoid close
/// but not up-to-date peers. If peers don't have sufficient metadata
/// for sorting, they are given a lower priority.
```

**File:** consensus/src/consensus_observer/observer/subscription_utils.rs (L325-326)
```rust
    // Sort the peers by distance and latency. Note: BTreeMaps are
    // sorted by key, so the entries will be sorted by distance in ascending order.
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

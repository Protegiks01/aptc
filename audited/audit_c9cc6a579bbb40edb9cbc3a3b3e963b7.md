# Audit Report

## Title
Distance Spoofing in Peer Monitoring Service Enables Eclipse Attacks and Preferential Peer Selection Manipulation

## Summary
Malicious peers can spoof their `distance_from_validators` metadata to appear closer to the validator set than they actually are. This spoofed distance is accepted without cryptographic validation and used across critical subsystems (state-sync, mempool, consensus observer) to preferentially select peers, enabling eclipse attacks and data poisoning.

## Finding Description

The Aptos peer monitoring service allows peers to self-report their distance from the validator set via `NetworkInformationResponse`. This distance metric is then used to prioritize peer selection across three critical subsystems:

1. **State-sync data client** - Selects peers for blockchain data requests
2. **Mempool** - Prioritizes peers for transaction forwarding  
3. **Consensus observer** - Selects peers for consensus subscriptions

The vulnerability exists because:

**Server-side calculation trusts peer-reported distances:** [1](#0-0) 

The `get_distance_from_validators` function calculates a node's own distance by taking the minimum `distance_from_validators` from all connected peers (which is a **self-reported value** from those peers) and adding 1. This creates a circular trust dependency.

**Client-side validation is insufficient for distances ≥ 2:** [2](#0-1) 

The validation only performs role-based checks for distances 0 and 1. For distances ≥ 2, it merely checks if the value is ≤ MAX_DISTANCE_FROM_VALIDATORS (100), with **no validation** that the peer's claimed distance is accurate.

**State-sync preferentially selects closer peers:** [3](#0-2) 

The `choose_random_peers_by_distance_and_latency` function groups peers by distance (using a BTreeMap which sorts by key), then selects from lower distances first. This means a peer claiming distance=2 will always be selected before a legitimate peer at distance=3.

**Mempool prioritizes closer peers:** [4](#0-3) 

The `compare_validator_distance` function prioritizes peers with lower validator distances for transaction forwarding.

**Attack Scenario:**

1. Malicious PFN connects to honest nodes on the public network
2. Attacker claims `distance_from_validators = 2` (or any low value ≥ 2)
3. This passes validation because distances ≥ 2 only require distance ≤ 100
4. State-sync on honest nodes preferentially selects the attacker for data requests
5. Attacker serves stale, forked, or invalid blockchain data
6. Mempool forwards transactions to the attacker preferentially
7. Consensus observer subscribes to attacker for consensus updates
8. If attacker controls multiple such peers, they can eclipse victims

## Impact Explanation

This vulnerability qualifies as **HIGH severity** under the Aptos bug bounty program for the following reasons:

**Significant Protocol Violations:**
- Breaks the assumption that peer selection is based on verifiable network topology
- Enables manipulation of critical subsystems (state-sync, mempool, consensus observer)
- Violates the trust model by allowing unverified self-reported metrics to influence security-critical decisions

**Eclipse Attack Vector:**
- Attackers can position themselves as "closest to validators" and monopolize serving blockchain data
- Victims may sync to incorrect/stale chain state
- Can lead to double-spend acceptance if victim receives conflicting transaction data

**State Sync Manipulation:**
- Honest nodes will preferentially request blockchain data from malicious peers
- Attackers can serve invalid proofs, stale data, or selectively withhold data
- Could cause honest nodes to fall behind in sync or accept invalid state

**Mempool Transaction Routing:**
- Transaction propagation can be manipulated to favor attacker peers
- Could enable transaction censorship or selective forwarding

**Consensus Observer Impact:**
- Consensus observers (used by fullnodes) will preferentially subscribe to malicious peers
- Could receive incorrect consensus updates or miss critical blocks

## Likelihood Explanation

This vulnerability has **HIGH likelihood** of exploitation:

**Low Attack Complexity:**
- Attacker only needs to run a modified node that claims low distance
- No cryptographic keys, validator access, or stake required
- Attack works from any public fullnode position

**Immediate Effect:**
- The spoofed distance is immediately used for peer selection
- No time delay or complex multi-step attack required

**Wide Attack Surface:**
- Affects all fullnodes using state-sync, mempool, or consensus observer
- Any peer can be a target
- Multiple attackers can coordinate for stronger eclipse attacks

**Detection Difficulty:**
- No cryptographic proof to verify claimed distances
- Legitimate network topology variations make anomaly detection challenging
- Honest nodes have no way to cross-validate distance claims

## Recommendation

Implement cryptographic validation of distance claims through one of these approaches:

**Option 1: Validator-Signed Distance Attestations**
- Validators periodically sign attestations for their direct peers (VFNs at distance 1)
- These attestations form a chain of trust
- Nodes at distance N must provide N-1 signed attestations proving the path to validators
- Distance claims without valid attestation chains are rejected or assigned maximum distance

**Option 2: Cross-Validation with Multiple Peers**
- Don't trust a single peer's reported distance
- Require consensus from multiple independent peers about a peer's distance
- Use statistical analysis to detect outliers claiming suspiciously low distances
- Implement reputation scoring based on distance claim consistency

**Option 3: Remove Distance-Based Prioritization**
- Rely solely on latency and connection quality metrics (which are harder to spoof)
- Use random peer selection with quality-based weighting
- Implement stake-weighted selection for certain operations

**Immediate Mitigation:** [5](#0-4) 

Add stronger validation for distances ≥ 2:
```rust
distance_from_validators => {
    // For PFN connections, validate distance is reasonable
    // Don't allow claims of very low distances without proper network position
    match (peer_metadata.get_connection_metadata().role, network_id) {
        (PeerRole::Unknown, NetworkId::Public) if distance_from_validators < 3 => false,
        _ => distance_from_validators <= MAX_DISTANCE_FROM_VALIDATORS,
    }
}
```

However, this is only a partial mitigation. Full fix requires cryptographic attestation.

## Proof of Concept

```rust
// Integration test demonstrating distance spoofing attack
// File: peer-monitoring-service/client/src/tests/distance_spoofing.rs

#[tokio::test]
async fn test_malicious_peer_spoofs_low_distance() {
    use aptos_peer_monitoring_service_types::{
        response::{NetworkInformationResponse, PeerMonitoringServiceResponse},
    };
    use aptos_config::network_id::{NetworkId, PeerNetworkId};
    use aptos_types::PeerId;
    use std::collections::HashMap;

    // Setup: Honest node is a PFN at actual distance 4
    let honest_node_config = create_pfn_config();
    
    // Malicious peer claims distance = 2 (spoofed)
    let malicious_peer_id = PeerNetworkId::new(NetworkId::Public, PeerId::random());
    let spoofed_response = NetworkInformationResponse {
        connected_peers: HashMap::new(),
        distance_from_validators: 2, // SPOOFED - should be 4+
    };

    // The spoofed response passes validation
    let mut network_info_state = NetworkInfoState::new(
        honest_node_config,
        TimeService::mock()
    );
    
    let peer_metadata = create_pfn_peer_metadata();
    network_info_state.handle_monitoring_service_response(
        &malicious_peer_id,
        peer_metadata,
        PeerMonitoringServiceRequest::GetNetworkInformation,
        PeerMonitoringServiceResponse::NetworkInformation(spoofed_response),
        0.0,
    );

    // Verify spoofed distance is stored
    let stored_response = network_info_state.get_latest_network_info_response().unwrap();
    assert_eq!(stored_response.distance_from_validators, 2);
    
    // Now demonstrate preferential selection in state-sync
    let data_client = setup_data_client();
    let serviceable_peers = hashset![malicious_peer_id, create_legitimate_peer()];
    
    // Malicious peer will be selected first due to lower distance
    let selected = data_client.choose_random_peers_by_distance_and_latency(
        serviceable_peers,
        1
    );
    
    // Attacker is preferentially selected
    assert!(selected.contains(&malicious_peer_id));
}
```

## Notes

This vulnerability demonstrates a fundamental trust issue in the peer monitoring architecture. The self-reported nature of distance metrics, combined with their use in security-critical peer selection algorithms, creates an exploitable attack surface. The circular dependency (nodes calculate their distance based on peer-reported distances, which are themselves calculated from other peer-reported distances) propagates false information throughout the network.

The impact is amplified because the same spoofed metric affects multiple critical subsystems: state synchronization, transaction propagation, and consensus observation. An attacker exploiting this vulnerability can position themselves as a "trusted" peer across all these systems simultaneously.

### Citations

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

**File:** peer-monitoring-service/client/src/peer_states/network_info.rs (L116-154)
```rust
        // Sanity check the response depth from the peer metadata
        let network_id = peer_network_id.network_id();
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

        // If the depth did not pass our sanity checks, handle a failure
        if !is_valid_depth {
            warn!(LogSchema::new(LogEntry::NetworkInfoRequest)
                .event(LogEvent::InvalidResponse)
                .peer(peer_network_id)
                .message(&format!(
                    "Peer returned invalid depth from validators: {}",
                    network_info_response.distance_from_validators
                )));
            self.handle_request_failure();
            return;
        }
```

**File:** state-sync/aptos-data-client/src/utils.rs (L26-64)
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
}
```

**File:** mempool/src/shared_mempool/priority.rs (L613-639)
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
}
```

# Audit Report

## Title
Peer Monitoring Metadata Poisoning Enables Eclipse Attacks and State Sync Manipulation via False Distance Claims

## Summary
Malicious peers can inject false `distance_from_validators` metadata by exploiting insufficient validation in the peer monitoring service. The validation logic only performs strict role-based checks for distances 0 and 1, but accepts any self-reported distance from 2 to 100 without verification. This enables peer selection manipulation affecting state synchronization, mempool transaction forwarding, and consensus observer subscriptions on full nodes.

## Finding Description
The peer monitoring service's validation logic contains an asymmetry that enables distance metadata poisoning. When a peer responds to `GetNetworkInformation` requests, the client validates the response based on the claimed distance: [1](#0-0) 

For distances 0 and 1, strict validation checks peer role and network type. However, for distances ≥ 2, only a maximum threshold check is performed with no role consistency validation. This allows any peer to claim an arbitrary distance between 2 and 100.

This false metadata directly influences critical peer selection mechanisms:

**State Synchronization**: Peers are grouped by distance using a BTreeMap (sorted ascending), prioritizing lower distances for data requests: [2](#0-1) 

**Mempool Transaction Forwarding**: Validator distance is compared to prioritize peers with lower distances: [3](#0-2) 

**Consensus Observer Subscriptions**: Peers are sorted by distance for subscription optimality, with distance explicitly prioritized over latency: [4](#0-3) 

**Attack Scenario**: A malicious PFN connects to public networks using `MaybeMutual` authentication (which allows unknown peers). When queried via `GetNetworkInformation`, it responds with `distance_from_validators = 2`. Honest PFNs at actual distances 5-10 report truthful values. The malicious peer is now prioritized across all peer selection mechanisms, enabling:
- Eclipse attacks by monopolizing peer connections
- State sync degradation by serving stale but valid data
- Transaction censorship by selectively dropping forwarded transactions  
- Consensus observer disruption by monopolizing subscriptions

## Impact Explanation
This vulnerability enables multiple attack vectors against full node infrastructure:

1. **Eclipse Attacks**: By claiming optimal distance, malicious peers monopolize peer selection for state sync and consensus observer, potentially isolating victims from honest peers. While not complete isolation, this significantly degrades connection diversity.

2. **Data Availability Degradation**: Malicious peers can serve stale blockchain data that passes Merkle proof verification but delays state sync progress, causing operational disruptions.

3. **Transaction Censorship**: In mempool priority forwarding, transactions are sent to low-distance peers first. Malicious peers can selectively drop transactions before forwarding, enabling temporary censorship attacks.

4. **Consensus Observer Disruption**: Full nodes rely on consensus observer for block propagation. Monopolizing these subscriptions disrupts full node participation in the network.

**Severity Assessment**: This is **MEDIUM to HIGH** severity. While it does not directly compromise validator consensus safety (validators use `Mutual` authentication), it severely impacts full node security and reliability, which are critical for ecosystem health. The attack requires no privileged access and affects production networks using `MaybeMutual` authentication (all public PFN-PFN and VFN-PFN connections).

## Likelihood Explanation
**High Likelihood** - The attack is trivially executable:

1. **Low Barrier**: Any entity can deploy a malicious full node and connect to public networks without authentication
2. **Simple Exploitation**: The attacker only needs to return a false distance value in a standard RPC response
3. **Immediate Effect**: False metadata is immediately incorporated into all peer selection algorithms with no additional validation
4. **No Detection**: The system provides no mechanism to detect or flag inconsistent distance claims
5. **Persistent Impact**: Once accepted, false metadata continues influencing routing decisions until peer disconnection

The validation logic's explicit structure treating distances ≥ 2 differently from 0 and 1 suggests this gap may be unintentional rather than by design.

## Recommendation
Implement distance validation for all claimed distances, not just 0 and 1:

1. **Role-Consistency Validation**: For distance ≥ 2, verify the peer's role is consistent with the claimed distance (e.g., PFN cannot legitimately claim distance 2)

2. **Cryptographic Attestation**: Require peers to provide cryptographic proof of their distance claim, signed by upstream peers

3. **Outlier Detection**: Implement anomaly detection to flag peers claiming suspiciously low distances compared to their observed connectivity patterns

4. **Distance Verification Protocol**: Add a verification protocol where peers can cross-check distance claims with other peers to detect inconsistencies

5. **Fallback to Conservative Defaults**: When distance metadata is missing or suspicious, use `MAX_DISTANCE_FROM_VALIDATORS` instead of accepting unverified claims

## Proof of Concept
The vulnerability can be demonstrated by:

1. Deploying a malicious full node that responds to `GetNetworkInformation` with `distance_from_validators = 2` regardless of actual topology
2. Connecting to an honest full node on the public network
3. Observing that the malicious peer is prioritized in peer selection for state sync, mempool, and consensus observer
4. Monitoring that honest peers at higher distances are deprioritized

The test cases in the validation logic confirm distances ≥ 2 are accepted without role validation: [5](#0-4) 

## Notes
This vulnerability primarily affects full node security rather than validator consensus safety. Validators use `Mutual` authentication which prevents this attack vector. However, full nodes are critical infrastructure for ecosystem health, providing RPC services, transaction submission, and network participation for non-validator participants. Degrading full node security has cascading effects on user experience and network decentralization. The attack's simplicity and broad applicability across all public network connections warrant prioritized remediation despite not directly impacting validator consensus.

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

**File:** peer-monitoring-service/client/src/peer_states/network_info.rs (L369-427)
```rust
    #[test]
    fn test_sanity_check_distance_pfn() {
        // Create the network info state for a PFN
        let mut network_info_state = create_network_info_state(RoleType::FullNode);

        // Verify there is no latest network info response
        verify_empty_network_response(&network_info_state);

        // Attempt to store a network response with an invalid depth of
        // 0 (the peer is a PFN, not a validator).
        handle_response_and_verify_distance(
            &mut network_info_state,
            NetworkId::Public,
            PeerRole::Unknown,
            0,
            None,
        );

        // Attempt to store a network response with an invalid depth of
        // 1 (the peer is a PFN, not a VFN).
        handle_response_and_verify_distance(
            &mut network_info_state,
            NetworkId::Public,
            PeerRole::PreferredUpstream,
            1,
            None,
        );

        // Attempt to store a network response with a valid depth of
        // 2 (the peer is a VFN that has no validator connection).
        handle_response_and_verify_distance(
            &mut network_info_state,
            NetworkId::Public,
            PeerRole::ValidatorFullNode,
            2,
            Some(2),
        );

        // Attempt to store a network response with a valid depth of
        // 1 (the peer is a VFN).
        handle_response_and_verify_distance(
            &mut network_info_state,
            NetworkId::Public,
            PeerRole::ValidatorFullNode,
            1,
            Some(1),
        );

        // Handle two valid responses from a PFN
        for distance_from_validators in [2, 3] {
            handle_response_and_verify_distance(
                &mut network_info_state,
                NetworkId::Public,
                PeerRole::Unknown,
                distance_from_validators,
                Some(distance_from_validators),
            );
        }
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

**File:** mempool/src/shared_mempool/priority.rs (L615-639)
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
}
```

**File:** consensus/src/consensus_observer/observer/subscription_utils.rs (L283-349)
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
```

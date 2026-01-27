# Audit Report

## Title
Transitive Trust Vulnerability in Peer Distance Metric Calculation Enables Network Topology Manipulation

## Summary
The peer monitoring service accepts self-reported `distance_from_validators` metrics from peers without sufficient validation, enabling malicious validators to inject false network topology information. This false data propagates through transitive trust as other nodes calculate their own distance based on corrupted peer metrics, affecting peer prioritization in mempool and potentially enabling eclipse attacks.

## Finding Description

The peer monitoring system has three implementations of `StateValueInterface::update_peer_state_metrics()` that collect and expose metrics about peer health. While latency metrics are measured locally and cannot be spoofed, the `distance_from_validators` metric is self-reported by peers and insufficiently validated.

**Vulnerable Data Flow:**

1. **Server-side calculation** [1](#0-0) 
   The server calculates its own distance by trusting peers' self-reported distances and taking the minimum value plus one.

2. **Client-side validation** [2](#0-1) 
   The client only validates that the peer's claimed distance is consistent with its role (validator=0, VFN=1), not whether the distance is truthful.

3. **Metric propagation** [3](#0-2) 
   The accepted (but potentially false) metrics are recorded and exposed via Prometheus metrics.

4. **Usage in peer prioritization** [4](#0-3) 
   The `compare_validator_distance()` function uses these metrics to prioritize peers, with lower distances being preferred.

**Attack Scenario:**

A malicious validator that is partitioned from the active validator set can connect to another malicious validator and both claim `distance_from_validators = 0` because they see each other as validators. The server code at line 311-318 only checks if there exists ANY validator peer, not if that peer is in the active validator set. The client accepts this claim because the peer IS a validator (role check passes). When honest nodes calculate their own distance based on this corrupted information, they compute `distance = 1` and prioritize the malicious validators for transaction forwarding.

## Impact Explanation

This qualifies as **High Severity** under "Significant protocol violations" because:

1. **Peer Selection Manipulation**: Malicious validators gain priority in mempool transaction forwarding, allowing them to receive transactions first
2. **Eclipse Attack Vector**: False topology metrics enable attackers to position themselves as preferred peers
3. **Network-Wide Metric Pollution**: False distances propagate through transitive trust as nodes calculate their own distance based on corrupted peer data
4. **Monitoring System Compromise**: Operators relying on distance metrics for network health monitoring receive misleading information

While this doesn't directly break consensus safety, it violates the integrity of the network's peer selection protocol and creates vectors for transaction censorship and network partitioning attacks.

## Likelihood Explanation

**Likelihood: Medium**

**Requirements:**
- Attacker must control at least one validator node (requires stake but not >1/3)
- Victim nodes must establish connections to the malicious validator
- No insider access to honest validators required

**Complexity:**
- Attack is straightforward once a validator node is controlled
- The false metrics naturally propagate without additional effort
- Detection is difficult as the metrics appear valid based on role checks

The TODO comment at line 312 ("TODO: figure out if we need to deal with validator set forks here") suggests this is a known limitation rather than an oversight, but the transitive trust propagation and peer prioritization impact may not have been fully analyzed.

## Recommendation

Implement cryptographic validation of the validator set membership:

1. **Verify Active Validator Set**: When a validator claims `distance_from_validators = 0`, verify it has connections to validators that are in the current on-chain validator set, not just any peer with the validator role.

2. **Add Proof-of-Membership**: Require peers to provide cryptographic proof (e.g., signed by on-chain validator public keys) that they are connected to active validators.

3. **Bound Trust Propagation**: Limit how far self-reported metrics can propagate. Consider only trusting distance metrics from authenticated validator set members.

4. **Cross-Validation**: Validate distance claims against multiple independent sources and reject outliers.

**Code Fix Example:**
```rust
// In get_distance_from_validators(), check against on-chain validator set
if base_config.role.is_validator() {
    for peer_metadata in connected_peers_and_metadata.values() {
        let peer_role = peer_metadata.get_connection_metadata().role;
        if peer_role.is_validator() {
            // NEW: Verify peer is in active validator set
            if is_in_active_validator_set(peer_metadata.peer_id(), storage) {
                return 0;
            }
        }
    }
}
```

## Proof of Concept

```rust
// Test scenario demonstrating the vulnerability
#[test]
fn test_distance_metric_injection() {
    // Setup: Create two malicious validators M1 and M2, partitioned from main set
    let malicious_validator_1 = create_validator_peer("M1");
    let malicious_validator_2 = create_validator_peer("M2");
    
    // M1 and M2 connect to each other
    // Both calculate distance = 0 because they see each other as validators
    let m1_distance = calculate_distance_with_peer(malicious_validator_2);
    let m2_distance = calculate_distance_with_peer(malicious_validator_1);
    assert_eq!(m1_distance, 0); // Both return 0
    assert_eq!(m2_distance, 0);
    
    // Honest node H connects to M1
    let honest_node = create_fullnode("H");
    connect_peers(&honest_node, &malicious_validator_1);
    
    // H requests network info from M1
    let response = honest_node.request_network_info(&malicious_validator_1);
    
    // Response claims distance = 0 (false, but passes validation)
    assert_eq!(response.distance_from_validators, 0);
    
    // H accepts this and calculates its own distance as 1
    let h_distance = honest_node.calculate_own_distance();
    assert_eq!(h_distance, 1);
    
    // H now prioritizes M1 in mempool over legitimate peers at distance 2+
    let peer_priority = honest_node.get_mempool_peer_priority(&malicious_validator_1);
    assert!(peer_priority < honest_node.get_mempool_peer_priority(&legitimate_peer));
    
    // M1 receives transactions first, enabling censorship
}
```

**Note:** This vulnerability relies on the assumption that the question's premise about "causing good peers to be disconnected or bad peers retained" includes peer prioritization effects. While automatic disconnection based on distance metrics is not implemented, the false metrics do cause malicious peers to be "retained" at high priority, achieving a similar adverse outcome.

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

**File:** peer-monitoring-service/client/src/peer_states/network_info.rs (L176-194)
```rust
    fn update_peer_state_metrics(&self, peer_network_id: &PeerNetworkId) {
        if let Some(network_info_response) = self.get_latest_network_info_response() {
            // Update the distance from the validators metric
            let distance_from_validators = network_info_response.distance_from_validators;
            metrics::observe_value(
                &metrics::DISTANCE_FROM_VALIDATORS,
                peer_network_id,
                distance_from_validators as f64,
            );

            // Update the number of connected peers metric
            let num_connected_peers = network_info_response.connected_peers.len();
            metrics::observe_value(
                &metrics::NUM_CONNECTED_PEERS,
                peer_network_id,
                num_connected_peers as f64,
            );
        }
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

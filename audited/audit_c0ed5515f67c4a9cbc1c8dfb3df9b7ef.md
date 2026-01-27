# Audit Report

## Title
Network ID Validation Bypass via Distance Manipulation in Peer Monitoring Service

## Summary
Peers can bypass strict network ID and role validation by reporting `distance_from_validators >= 2` in the peer monitoring service, allowing validators and VFNs to misrepresent their network proximity and potentially disrupt peer selection algorithms used in state synchronization.

## Finding Description

The peer monitoring service validates network information responses with inconsistent strictness based on the reported `distance_from_validators` value. The validation logic in `handle_monitoring_service_response` has three branches: [1](#0-0) 

**The vulnerability:** For `distance_from_validators >= 2`, the validation **only** checks if the distance is below `MAX_DISTANCE_FROM_VALIDATORS` (100). It does NOT validate:
- The peer's role (validator, VFN, or PFN)
- The consistency between network_id and the claimed distance [2](#0-1) 

In contrast, for `distance_from_validators = 0` or `1`, the code performs strict validation: [3](#0-2) 

**Attack scenarios:**

1. **Validator claiming high distance:** A validator connecting on `NetworkId::Validator` should always report `distance_from_validators = 0` (they ARE validators). However, by claiming `distance_from_validators = 3` (or any value 2-100), they bypass the validator role verification that would occur at distance 0.

2. **VFN claiming inflated distance:** A VFN connecting to a validator on `NetworkId::Vfn` should report `distance_from_validators = 1`. By claiming `distance_from_validators = 2+`, they bypass the VFN role verification.

The validated network information is stored and used for peer selection in state synchronization: [4](#0-3) [5](#0-4) 

## Impact Explanation

**Severity: Medium to Low**

While the security question labels this as "High", the actual exploitable impact is limited:

1. **Peer Selection Manipulation:** Malicious peers can artificially inflate their distance to avoid being selected for state sync operations, potentially causing denial of service if enough peers do this.

2. **Metrics Corruption:** Network topology metrics become unreliable, making it difficult to monitor network health and diagnose issues.

3. **Not Cross-Network Contamination:** The initial handshake protocol validates network_id and chain_id: [6](#0-5) 

This prevents true cross-network contamination (e.g., testnet peers connecting to mainnet). The vulnerability is limited to distance misrepresentation within the same network.

4. **No Direct Consensus/Fund Impact:** This does not directly compromise consensus safety, state integrity, or fund security.

**Assessment:** This falls between **Medium** (state inconsistencies requiring intervention) and **Low** (non-critical implementation bug) severity per the Aptos bug bounty criteria.

## Likelihood Explanation

**Likelihood: Medium**

- **Low barrier to entry:** Any peer can exploit this by simply responding to `GetNetworkInformation` requests with manipulated distance values.
- **Detection difficulty:** The validation accepts these responses as valid, logging no warnings.
- **Limited motivation:** Attackers would primarily use this for DoS (making peers unavailable) or metric pollution rather than direct profit.
- **Partial mitigation:** The handshake validation prevents the most severe forms of network contamination.

## Recommendation

Add consistent validation for all distance values by checking network_id and role appropriateness:

```rust
let is_valid_depth = match network_info_response.distance_from_validators {
    0 => {
        let peer_is_validator = peer_metadata.get_connection_metadata().role.is_validator();
        let peer_has_correct_network = match self.base_config.role {
            RoleType::Validator => network_id.is_validator_network(),
            RoleType::FullNode => network_id.is_vfn_network(),
        };
        peer_is_validator && peer_has_correct_network
    },
    1 => {
        let peer_is_vfn = peer_metadata.get_connection_metadata().role.is_vfn();
        let peer_has_correct_network = match self.base_config.role {
            RoleType::Validator => network_id.is_vfn_network(),
            RoleType::FullNode => network_id.is_public_network(),
        };
        peer_is_vfn && peer_has_correct_network
    },
    distance_from_validators => {
        // NEW: Add validation for distance >= 2
        let is_valid_network_for_distance = match (self.base_config.role, network_id) {
            // Validators on Validator network should NEVER report distance >= 2
            (RoleType::Validator, _) if network_id.is_validator_network() => false,
            // VFNs on Vfn network connecting to validators should NEVER report distance >= 2
            (RoleType::Validator, _) if network_id.is_vfn_network() && 
                peer_metadata.get_connection_metadata().role.is_vfn() => false,
            // Otherwise, just check distance is within bounds
            _ => distance_from_validators <= MAX_DISTANCE_FROM_VALIDATORS,
        };
        is_valid_network_for_distance
    },
};
```

## Proof of Concept

The existing test suite demonstrates this vulnerability is already present and accepted: [7](#0-6) 

These tests show validators claiming distance 3 and VFNs claiming distance 10 are accepted without validation of whether such distances are appropriate for their network type and role.

## Notes

After thorough investigation, while this validation inconsistency exists and could be exploited for limited attacks, the actual security impact is **lower than initially suggested**:

1. The connection-level handshake already prevents true cross-network contamination between different blockchain networks (testnet vs mainnet).

2. The exploit only allows peers to make themselves **less attractive** for state sync by claiming higher distance (lower priority in peer selection).

3. Test cases suggest this behavior may be partially intentional to handle edge cases like "disconnected validators."

4. No critical invariants (consensus, state integrity, fund security) are broken.

The issue is better characterized as a **robustness concern** affecting network topology metrics and peer selection fairness, rather than a high-severity security vulnerability requiring immediate patching.

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

**File:** peer-monitoring-service/client/src/peer_states/network_info.rs (L259-277)
```rust
        // Attempt to store a network response with a valid depth of
        // 3 (the peer is a validator that is disconnected from the set).
        handle_response_and_verify_distance(
            &mut network_info_state,
            NetworkId::Validator,
            PeerRole::Validator,
            3,
            Some(3),
        );

        // Attempt to store a network response with a valid depth of
        // 10 (the peer is a VFN that has poor connections).
        handle_response_and_verify_distance(
            &mut network_info_state,
            NetworkId::Vfn,
            PeerRole::ValidatorFullNode,
            10,
            Some(10),
        );
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

**File:** state-sync/aptos-data-client/src/utils.rs (L231-260)
```rust
fn get_distance_and_latency_for_peer(
    peers_and_metadata: &Arc<PeersAndMetadata>,
    peer: PeerNetworkId,
) -> Option<(u64, f64)> {
    if let Some(peer_metadata) = get_metadata_for_peer(peers_and_metadata, peer) {
        // Get the distance and latency for the peer
        let peer_monitoring_metadata = peer_metadata.get_peer_monitoring_metadata();
        let distance = peer_monitoring_metadata
            .latest_network_info_response
            .as_ref()
            .map(|response| response.distance_from_validators);
        let latency = peer_monitoring_metadata.average_ping_latency_secs;

        // Return the distance and latency if both were found
        if let (Some(distance), Some(latency)) = (distance, latency) {
            return Some((distance, latency));
        }
    }

    // Otherwise, no distance and latency was found
    log_warning_with_sample(
        LogSchema::new(LogEntry::PeerStates)
            .event(LogEvent::PeerSelectionError)
            .message(&format!(
                "Unable to get distance and latency for peer! Peer: {:?}",
                peer
            )),
    );
    None
}
```

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L431-449)
```rust
    pub fn perform_handshake(
        &self,
        other: &HandshakeMsg,
    ) -> Result<(MessagingProtocolVersion, ProtocolIdSet), HandshakeError> {
        // verify that both peers are on the same chain
        if self.chain_id != other.chain_id {
            return Err(HandshakeError::InvalidChainId(
                other.chain_id,
                self.chain_id,
            ));
        }

        // verify that both peers are on the same network
        if self.network_id != other.network_id {
            return Err(HandshakeError::InvalidNetworkId(
                other.network_id,
                self.network_id,
            ));
        }
```

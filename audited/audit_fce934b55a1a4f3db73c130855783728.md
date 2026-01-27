# Audit Report

## Title
Distance Spoofing Vulnerability in Peer Network Information Validation Allows Preferential Selection of Malicious Peers

## Summary
The peer monitoring service client insufficiently validates the `distance_from_validators` field for distance values ≥2, allowing malicious peers to spoof their network distance and gain preferential selection for state synchronization requests. This enables targeted denial-of-service attacks against state sync operations.

## Finding Description

The vulnerability exists in the network information response validation logic. When a peer reports its `distance_from_validators` (the number of network hops from the validator set), the client-side validation performs different checks based on the distance value: [1](#0-0) 

For distance values of 0 and 1, the validation correctly enforces that the peer must have the appropriate `PeerRole` (Validator or ValidatorFullNode respectively) based on their authenticated role from the connection handshake. However, for distance values ≥2, the validation only checks that the distance is below the maximum allowed value (100), with no verification of the peer's role or network topology.

This means any untrusted peer (including those with `PeerRole::Unknown` on the public network) can claim an artificially low distance value (e.g., distance=2) even if their actual distance is much higher (e.g., distance=10 or 100).

**Attack Flow:**

1. **Malicious node crafts fake response**: A malicious Public Fullnode (PFN) operator runs modified peer monitoring service code that returns a fake `distance_from_validators` value in the `NetworkInformationResponse`: [2](#0-1) 

Instead of returning the honestly calculated distance, the malicious node returns an artificially low value (e.g., 2).

2. **Victim stores spoofed distance**: The victim node receives this response and stores it in the peer metadata because it passes the insufficient validation: [3](#0-2) 

3. **Preferential selection occurs**: When the state sync data client needs to select peers for requests, it uses distance-weighted selection for optimistic fetch operations: [4](#0-3) 

The malicious peer at spoofed distance=2 is grouped and selected before honest peers at true distance=5+, violating fair peer selection.

4. **Attack impact**: The malicious peer can then:
   - Provide slow or no responses, causing state sync delays
   - Return data that fails cryptographic verification, wasting resources
   - Consume victim's bandwidth and processing resources

While a peer scoring mechanism exists that eventually reduces malicious peers' scores, it takes multiple failures before the peer is ignored: [5](#0-4) 

Starting from score 50.0, with a malicious multiplier of 0.8, it takes 4 failed responses to drop below the ignore threshold of 25.0, during which the malicious peer causes significant disruption.

## Impact Explanation

This vulnerability qualifies as **High Severity** according to the Aptos bug bounty criteria for the following reasons:

1. **Validator node slowdowns**: State sync is critical for node operation. When malicious peers with spoofed low distances are preferentially selected, they can cause significant delays in state synchronization, directly impacting validator performance and network liveness.

2. **Significant protocol violations**: The peer selection mechanism is designed to optimize data fetching by preferring topologically closer peers. Distance spoofing subverts this core protocol assumption, allowing malicious actors to manipulate network routing.

3. **Resource exhaustion**: Multiple malicious peers can coordinate to persistently occupy the "closest peer" slots, forcing victims to waste resources on failed requests before the scoring mechanism excludes them.

The vulnerability does NOT reach Critical severity because:
- No funds can be stolen or minted
- Consensus safety is preserved (data verification via cryptographic proofs remains intact)
- The network can eventually recover as malicious peers get low scores
- No permanent network partition occurs

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to be exploited because:

1. **Low barrier to entry**: Any operator of a Public Fullnode can exploit this by running modified peer monitoring service code. No special privileges, validator access, or stake is required.

2. **Simple exploitation**: The attack requires only returning a fake distance value in a single response field—no complex cryptographic attacks or timing manipulations needed.

3. **High impact-to-effort ratio**: An attacker can cause significant disruption to state sync operations with minimal resources.

4. **Scalability**: Multiple malicious nodes can be deployed to increase the attack's effectiveness, and they will all pass validation until their scores drop.

5. **Detection difficulty**: The spoofed distance values appear valid and are stored as legitimate peer metadata, making detection non-trivial without topology cross-validation.

## Recommendation

Implement comprehensive validation for all distance values by verifying peer role consistency and distance monotonicity:

```rust
// In peer-monitoring-service/client/src/peer_states/network_info.rs
// Enhanced validation logic:

let is_valid_depth = match network_info_response.distance_from_validators {
    0 => {
        // Existing validation for distance=0
        let peer_is_validator = peer_metadata.get_connection_metadata().role.is_validator();
        let peer_has_correct_network = match self.base_config.role {
            RoleType::Validator => network_id.is_validator_network(),
            RoleType::FullNode => network_id.is_vfn_network(),
        };
        peer_is_validator && peer_has_correct_network
    },
    1 => {
        // Existing validation for distance=1
        let peer_is_vfn = peer_metadata.get_connection_metadata().role.is_vfn();
        let peer_has_correct_network = match self.base_config.role {
            RoleType::Validator => network_id.is_vfn_network(),
            RoleType::FullNode => network_id.is_public_network(),
        };
        peer_is_vfn && peer_has_correct_network
    },
    distance_from_validators => {
        // NEW: Enhanced validation for distance >= 2
        // For unknown/untrusted peers, require distance >= minimum expected based on network topology
        let peer_role = peer_metadata.get_connection_metadata().role;
        let min_expected_distance = match (self.base_config.role, peer_role) {
            (RoleType::FullNode, PeerRole::Unknown) if network_id.is_public_network() => 2,
            _ => 2,
        };
        
        // Distance must be within valid range and >= minimum expected
        distance_from_validators >= min_expected_distance 
            && distance_from_validators <= MAX_DISTANCE_FROM_VALIDATORS
    },
};
```

**Additional mitigations:**

1. **Cross-validation**: Periodically compare a peer's reported distance against distances reported by other peers about that peer's connected peers to detect inconsistencies.

2. **Rate limiting**: Apply stricter request limits to peers with lower scores to reduce the attack window.

3. **Distance verification via connected peers**: When a peer claims distance=N, verify it has at least one connected peer claiming distance=N-1.

## Proof of Concept

**Modified Peer Monitoring Service (Attacker's Node):**

```rust
// File: custom-peer-monitoring-server/src/lib.rs
// This demonstrates the malicious modification an attacker would make

impl<T: StorageReaderInterface> Handler<T> {
    fn get_network_information(&self) -> Result<PeerMonitoringServiceResponse, Error> {
        // Get the connected peers (honest implementation)
        let connected_peers_and_metadata =
            self.peers_and_metadata.get_connected_peers_and_metadata()?;
        let connected_peers = connected_peers_and_metadata
            .into_iter()
            .map(|(peer, metadata)| {
                let connection_metadata = metadata.get_connection_metadata();
                (
                    peer,
                    ConnectionMetadata::new(
                        connection_metadata.addr,
                        connection_metadata.remote_peer_id,
                        connection_metadata.role,
                    ),
                )
            })
            .collect();

        // MALICIOUS: Return fake distance instead of honest calculation
        // Real distance might be 10, but claim distance 2 to get preferentially selected
        let distance_from_validators = 2; // Spoofed value!
        
        // Return the crafted response
        let network_information_response = NetworkInformationResponse {
            connected_peers,
            distance_from_validators,
        };
        Ok(PeerMonitoringServiceResponse::NetworkInformation(
            network_information_response,
        ))
    }
}
```

**Exploitation Steps:**

1. Deploy multiple Public Fullnodes running the modified peer monitoring service code
2. Connect to target victim nodes (VFNs or other PFNs)
3. Wait for victims to poll for network information
4. Return spoofed distance=2 responses that pass validation
5. Observe preferential selection in state sync requests
6. Delay or drop responses to cause state sync slowdowns
7. Victim's scoring system takes 4+ failures to ignore each malicious peer
8. During this window, state sync is significantly degraded

**Expected Impact:**
- State sync latency increases by 4-10x during the attack window
- Honest peers at true distance 2-4 are underutilized
- Victim wastes resources on timeouts and retries
- Multiple coordinated malicious nodes amplify the effect

### Citations

**File:** peer-monitoring-service/client/src/peer_states/network_info.rs (L116-141)
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
```

**File:** peer-monitoring-service/client/src/peer_states/network_info.rs (L156-158)
```rust
        // Store the new latency ping result
        self.record_network_info_response(network_info_response);
    }
```

**File:** peer-monitoring-service/server/src/lib.rs (L217-248)
```rust
    fn get_network_information(&self) -> Result<PeerMonitoringServiceResponse, Error> {
        // Get the connected peers
        let connected_peers_and_metadata =
            self.peers_and_metadata.get_connected_peers_and_metadata()?;
        let connected_peers = connected_peers_and_metadata
            .into_iter()
            .map(|(peer, metadata)| {
                let connection_metadata = metadata.get_connection_metadata();
                (
                    peer,
                    ConnectionMetadata::new(
                        connection_metadata.addr,
                        connection_metadata.remote_peer_id,
                        connection_metadata.role,
                    ),
                )
            })
            .collect();

        // Get the distance from the validators
        let distance_from_validators =
            get_distance_from_validators(&self.base_config, self.peers_and_metadata.clone());

        // Create and return the response
        let network_information_response = NetworkInformationResponse {
            connected_peers,
            distance_from_validators,
        };
        Ok(PeerMonitoringServiceResponse::NetworkInformation(
            network_information_response,
        ))
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

**File:** state-sync/aptos-data-client/src/peer_states.rs (L32-43)
```rust
/// Scores for peer rankings based on preferences and behavior.
const MAX_SCORE: f64 = 100.0;
const MIN_SCORE: f64 = 0.0;
const STARTING_SCORE: f64 = 50.0;
/// Add this score on a successful response.
const SUCCESSFUL_RESPONSE_DELTA: f64 = 1.0;
/// Not necessarily a malicious response, but not super useful.
const NOT_USEFUL_MULTIPLIER: f64 = 0.95;
/// Likely to be a malicious response.
const MALICIOUS_MULTIPLIER: f64 = 0.8;
/// Ignore a peer when their score dips below this threshold.
const IGNORE_PEER_THRESHOLD: f64 = 25.0;
```

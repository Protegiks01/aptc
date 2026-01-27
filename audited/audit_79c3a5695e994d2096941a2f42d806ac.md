# Audit Report

## Title
Peer Distance Misrepresentation Attack via Stateless GetNetworkInformation Requests

## Summary
The `GetNetworkInformation` request lacks freshness guarantees (no timestamps, nonces, or request-specific parameters), allowing malicious peers to respond with fabricated or stale network distance information. This false data is then used for security-critical peer selection in state synchronization and consensus observer subscriptions, enabling attackers to gain preferential selection despite being poorly positioned in the network topology.

## Finding Description

The peer monitoring service uses stateless `GetNetworkInformation` requests to gather topology information from peers. The request creation is trivial: [1](#0-0) 

The response contains `distance_from_validators`, which indicates network proximity to the validator set. The server calculates this distance by querying connected peers and taking the minimum reported distance plus one: [2](#0-1) 

This creates a transitive trust chain where each node trusts peer-reported distances. The client-side validation only performs basic sanity checks on peer roles for distances 0 and 1: [3](#0-2) 

**The vulnerability:** For distances ≥ 2, there is no verification that the claimed distance reflects the peer's actual topology position. A malicious peer at actual distance 10 can claim distance 2, passing validation, and this false information is stored: [4](#0-3) 

This false distance data is then used for **critical peer selection decisions** in:

1. **State Sync**: Peers are prioritized by distance, with comment "we prioritize distance over latency as we want to avoid close but not up-to-date peers": [5](#0-4) 

The distance is extracted from peer monitoring metadata: [6](#0-5) 

2. **Consensus Observer**: Peers are sorted by "subscription optimality" which prioritizes distance: [7](#0-6) 

**Attack Scenario:**
1. Attacker connects as a full node at actual distance 10 from validators
2. Attacker fabricates a `NetworkInformationResponse` claiming `distance_from_validators: 2`
3. When victims request `GetNetworkInformation`, attacker responds with fabricated data
4. Victims store this data and preferentially select the attacker for state sync and consensus observer subscriptions
5. Attacker can then provide stale data, delay synchronization, or cause consensus observer subscription issues

**Why RPC-layer protections are insufficient:** While the underlying RPC protocol uses request_id matching to correlate responses to requests: [8](#0-7) 

This only prevents response routing errors. A malicious peer receiving a legitimate request with request_id X can respond with any content they choose, including cached or fabricated network information, as long as they include the correct request_id in the response message.

## Impact Explanation

**Severity: Medium** - This meets the Medium severity criteria ("State inconsistencies requiring intervention") because:

1. **Subverts Security-Critical Peer Selection**: The distance metric is explicitly used to avoid "close but not up-to-date peers" in state sync and to achieve "subscription optimality" in consensus observer
2. **Affects Multiple Critical Subsystems**: Both state synchronization and consensus observer are foundational to network operation
3. **No Cryptographic Protection**: The false data cannot be detected without external verification
4. **Persistent Impact**: Once stored, the false distance remains until the next successful update, affecting all peer selection decisions during that period

While this does not directly break consensus safety (as actual consensus messages are validated), it undermines the security model by allowing adversaries to manipulate the peer selection algorithm that determines which nodes are trusted for critical data propagation.

## Likelihood Explanation

**Likelihood: High** - This attack is:
- **Easy to execute**: Requires only a malicious peer implementation responding to standard requests
- **No special privileges required**: Any connected peer can claim false distances
- **Difficult to detect**: Without cross-validation mechanisms, nodes cannot distinguish false from legitimate distance claims
- **Low resource cost**: No computational or network overhead beyond normal operation

## Recommendation

Implement freshness guarantees for `GetNetworkInformation` responses through one or more of:

1. **Add Request Nonces**: Include a random nonce in the request that must be echoed in the response
2. **Add Timestamps**: Include client timestamp in request and validate response timeliness  
3. **Cross-Validation**: Periodically verify claimed distances by checking if peers have connections consistent with their reported distance
4. **Reputation System**: Track peer distance claim consistency over time and penalize inconsistent reporters

Example fix for adding nonces:

```rust
// In request type
pub enum PeerMonitoringServiceRequest {
    GetNetworkInformation { nonce: u64 },
    // ...
}

// In response validation
fn handle_monitoring_service_response(&mut self, ..., request_nonce: u64, response: NetworkInformationResponse) {
    if response.nonce != request_nonce {
        // Reject mismatched nonce
        return;
    }
    // ... existing validation
}
```

Additionally, implement **distance verification heuristics**:
- If a peer claims distance D, verify they have connections to peers at distance D-1
- Reject claims that are inconsistent with the peer's connection graph
- Implement gradual trust: newly claimed distances take multiple confirmations to accept

## Proof of Concept

```rust
// Malicious peer server implementation
impl Handler {
    fn get_network_information(&self) -> Result<PeerMonitoringServiceResponse> {
        // Instead of calculating actual distance, always claim distance 2
        let fabricated_response = NetworkInformationResponse {
            connected_peers: self.get_actual_connected_peers(), // Use real connections to appear legitimate
            distance_from_validators: 2, // LIE about distance (actual might be 10+)
        };
        Ok(PeerMonitoringServiceResponse::NetworkInformation(fabricated_response))
    }
}

// Test scenario:
// 1. Deploy malicious peer at actual distance 10
// 2. Connect to victim nodes
// 3. Respond to GetNetworkInformation with distance 2
// 4. Observe victim's peer selection prioritizing the malicious peer
// 5. Victim's state sync and consensus observer will preferentially subscribe to attacker
```

## Notes

The core issue is that `GetNetworkInformation` requests have no application-layer freshness guarantees beyond RPC-layer request_id matching. While the RPC layer correctly correlates responses to requests via request_id, it cannot prevent a malicious peer from responding with fabricated content. The distance metric is security-critical for peer selection but lacks verification mechanisms, violating the principle of "trust but verify" in distributed systems.

### Citations

**File:** peer-monitoring-service/client/src/peer_states/network_info.rs (L55-64)
```rust
    pub fn record_network_info_response(
        &mut self,
        network_info_response: NetworkInformationResponse,
    ) {
        // Update the request tracker with a successful response
        self.request_tracker.write().record_response_success();

        // Save the network info
        self.recorded_network_info_response = Some(network_info_response);
    }
```

**File:** peer-monitoring-service/client/src/peer_states/network_info.rs (L78-80)
```rust
    fn create_monitoring_service_request(&mut self) -> PeerMonitoringServiceRequest {
        PeerMonitoringServiceRequest::GetNetworkInformation
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

**File:** state-sync/aptos-data-client/src/utils.rs (L23-64)
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

**File:** state-sync/aptos-data-client/src/utils.rs (L230-260)
```rust
/// Gets the distance from the validators and measured latency (for the specified peer)
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

**File:** consensus/src/consensus_observer/observer/subscription_utils.rs (L275-312)
```rust
/// Sorts the peers by subscription optimality (in descending order of
/// optimality). This requires: (i) sorting the peers by distance from the
/// validator set and ping latency (lower values are more optimal); and (ii)
/// filtering out peers that don't support consensus observer.
///
/// Note: we prioritize distance over latency as we want to avoid close
/// but not up-to-date peers. If peers don't have sufficient metadata
/// for sorting, they are given a lower priority.
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

**File:** network/framework/src/protocols/rpc/mod.rs (L432-476)
```rust
    /// Handle a new outbound rpc request from the application layer.
    pub fn handle_outbound_request(
        &mut self,
        request: OutboundRpcRequest,
        write_reqs_tx: &mut aptos_channel::Sender<(), NetworkMessage>,
    ) -> Result<(), RpcError> {
        let network_context = &self.network_context;
        let peer_id = &self.remote_peer_id;

        // Unpack request.
        let OutboundRpcRequest {
            protocol_id,
            data: request_data,
            timeout,
            res_tx: mut application_response_tx,
        } = request;
        let req_len = request_data.len() as u64;

        // Drop the outbound request if the application layer has already canceled.
        if application_response_tx.is_canceled() {
            counters::rpc_messages(
                network_context,
                REQUEST_LABEL,
                OUTBOUND_LABEL,
                CANCELED_LABEL,
            )
            .inc();
            return Err(RpcError::UnexpectedResponseChannelCancel);
        }

        // Drop new outbound requests if our completion queue is at capacity.
        if self.outbound_rpc_tasks.len() == self.max_concurrent_outbound_rpcs as usize {
            counters::rpc_messages(
                network_context,
                REQUEST_LABEL,
                OUTBOUND_LABEL,
                DECLINED_LABEL,
            )
            .inc();
            // Notify application that their request was dropped due to capacity.
            let err = Err(RpcError::TooManyPending(self.max_concurrent_outbound_rpcs));
            let _ = application_response_tx.send(err);
            return Err(RpcError::TooManyPending(self.max_concurrent_outbound_rpcs));
        }

```

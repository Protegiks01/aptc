# Audit Report

## Title
Consensus Observer Peer Optimality Manipulation via Insufficient Distance Validation

## Summary
Malicious peers can provide false `distance_from_validators` values in their `NetworkInformationResponse` that bypass validation checks, causing consensus observers to subscribe to suboptimal or malicious peers. The validation only enforces role-based checks for distances 0-1 but allows any distance ≥2 up to MAX_DISTANCE_FROM_VALIDATORS (100), enabling peers to misrepresent their network position and manipulate subscription priority.

## Finding Description

The vulnerability exists in how peer monitoring metadata is validated and used for consensus observer subscription decisions. The attack flow is:

**1. False Metadata Injection**: A malicious peer responds to `GetNetworkInformation` requests with a falsified `distance_from_validators` value in the `NetworkInformationResponse`. While the server-side honestly calculates distance based on actual peer connections [1](#0-0) , nothing prevents a malicious peer from sending arbitrary values.

**2. Insufficient Validation**: The client-side validation performs role-based checks only for distances 0 and 1. For distance 0, it verifies the peer is a validator with the correct network. For distance 1, it verifies the peer is a VFN with the correct network. However, for any distance ≥2, the validation only checks that the value doesn't exceed `MAX_DISTANCE_FROM_VALIDATORS` (100): [2](#0-1) 

There is no verification that the claimed distance matches the peer's actual network topology position.

**3. Metadata Storage**: The false distance is accepted and stored in `PeerMonitoringMetadata` for later use: [3](#0-2) 

**4. Subscription Sorting Manipulation**: When the consensus observer evaluates peer optimality, it sorts peers primarily by distance (ascending), then by latency. The sorting function retrieves distance directly from the stored metadata: [4](#0-3) 

The distance extraction function pulls the value from peer monitoring metadata without additional validation: [5](#0-4) 

**5. Subscription Decision Impact**: The sorted peer list determines which peers are considered "optimal" for subscriptions. The subscription health check verifies that the current peer is in the top N peers (where N = `max_concurrent_subscriptions`): [6](#0-5) 

If the peer is not in the top N, a `SubscriptionSuboptimal` error is returned, causing the observer to terminate the subscription.

**Attack Scenario:**
- Honest PFN at true distance 5 reports distance = 5
- Malicious PFN at true distance 10 reports distance = 2 (passes validation since 2 ≤ 100)
- Consensus observer sorts peers and ranks malicious peer higher than honest peers
- Observer terminates subscription to honest peer, subscribes to malicious peer
- Malicious peer can provide stale data, slow responses, or no consensus data at all

## Impact Explanation

This qualifies as **High Severity** under the Aptos Bug Bounty program for the following reasons:

**1. Consensus Observer Infrastructure Degradation**: Consensus observers are part of the consensus layer infrastructure. When they subscribe to slow or malicious peers, they experience degraded performance as they receive stale or delayed consensus information. This aligns with the "Validator node slowdowns" category in the HIGH severity tier, as consensus observers can run on validator infrastructure and their degradation affects overall network synchronization capabilities.

**2. Liveness Issues**: If malicious peers stop sending valid consensus data after being subscribed to, observers lose liveness until the subscription times out. The subscription timeout mechanism eventually detects this: [7](#0-6)  However, during this timeout period, the observer is effectively non-functional.

**3. Resource Exhaustion**: Observers waste network bandwidth and processing cycles on suboptimal peers. They undergo repeated subscription churn as they detect and terminate unhealthy subscriptions, then attempt to create new ones, consuming additional resources.

**4. Protocol Violation**: The consensus observer protocol assumes honest distance reporting for optimal peer selection. This vulnerability violates that security guarantee, enabling malicious actors to manipulate the peer selection mechanism.

The impact does NOT reach CRITICAL severity because:
- It does not cause fund loss or theft
- It does not violate consensus safety (validators continue to operate correctly)
- It does not cause permanent network partition
- It affects availability/performance rather than safety

## Likelihood Explanation

This vulnerability is **highly likely** to be exploited:

- **Low Barrier to Entry**: Any peer that can connect to the network can exploit this by simply lying in their peer monitoring responses. No special privileges or credentials are required.
  
- **No Authentication**: The distance value in `NetworkInformationResponse` is self-reported and not authenticated or verified against network topology.

- **Difficult to Detect**: The false metadata appears legitimate and passes all validation checks. The only way to detect the manipulation would be to independently verify the network topology, which the current implementation does not do.

- **High Attacker Motivation**: Adversaries can use this to disrupt consensus observer networks, gain unfair advantage by being preferentially selected for subscriptions, perform targeted DoS against specific observers, or position themselves as man-in-the-middle for consensus data.

- **Exploitable in Normal Operation**: The attack requires only standard network peer interactions, not special conditions or timing.

## Recommendation

Implement cryptographic or topological verification of distance claims:

**Option 1 - Chain of Trust**: Require peers to provide signed attestations from validators or VFNs about their distance, creating a verifiable chain of trust back to the validator set.

**Option 2 - Topology Verification**: Cross-reference claimed distances with observed network topology. If a peer claims distance=2 but all known paths to validators are longer, flag the peer as suspicious.

**Option 3 - Distance Probing**: Actively probe the network path to validators through the peer's claimed connections to verify their distance claim.

**Option 4 - Stricter Validation**: For distance ≥2, require additional metadata that can be verified (e.g., list of intermediate peers that can be queried for confirmation).

**Minimum Fix**: Add explicit warnings in logs when peers report suspiciously low distances without corresponding network topology evidence, and implement rate-limiting or deprioritization for peers with inconsistent distance claims.

## Proof of Concept

The vulnerability can be demonstrated by modifying a peer monitoring service client to send false distance values:

```rust
// Malicious peer sends false distance in response
let fake_response = NetworkInformationResponse {
    connected_peers: actual_connected_peers,
    distance_from_validators: 2, // Lying - actual distance is 10+
};

// This passes validation at network_info.rs line 139:
// distance_from_validators <= MAX_DISTANCE_FROM_VALIDATORS
// 2 <= 100 ✓ PASSES

// The false distance is stored and used for sorting
// The malicious peer is now ranked higher than honest peers
// at true distances 3-10, causing suboptimal subscriptions
```

To fully demonstrate this requires:
1. Setting up a test network with multiple peers at varying distances
2. Implementing a malicious peer that reports false distance=2
3. Observing that consensus observers preferentially subscribe to the malicious peer
4. Monitoring the degraded performance as the malicious peer provides slow/no data

The vulnerability exists in the validation logic at: [2](#0-1) 

**Notes**

This is a valid HIGH severity vulnerability that affects consensus observer infrastructure in the Aptos Core codebase. The insufficient validation of distance claims enables malicious peers to manipulate subscription priority, leading to degraded performance and availability issues for consensus observers. While not CRITICAL (no fund loss or consensus safety violation), it represents a significant protocol violation that can be exploited by any network peer with minimal effort.

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

**File:** peer-monitoring-service/client/src/peer_states/network_info.rs (L54-64)
```rust
    /// Records the new network info response for the peer
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

**File:** peer-monitoring-service/client/src/peer_states/network_info.rs (L137-141)
```rust
            distance_from_validators => {
                // The distance must be less than or equal to the max
                distance_from_validators <= MAX_DISTANCE_FROM_VALIDATORS
            },
        };
```

**File:** consensus/src/consensus_observer/observer/subscription_utils.rs (L195-218)
```rust
/// Gets the distance from the validators for the specified peer from the peer metadata
fn get_distance_for_peer(
    peer_network_id: &PeerNetworkId,
    peer_metadata: &PeerMetadata,
) -> Option<u64> {
    // Get the distance for the peer
    let peer_monitoring_metadata = peer_metadata.get_peer_monitoring_metadata();
    let distance = peer_monitoring_metadata
        .latest_network_info_response
        .as_ref()
        .map(|response| response.distance_from_validators);

    // If the distance is missing, log a warning
    if distance.is_none() {
        warn!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Unable to get distance for peer! Peer: {:?}",
                peer_network_id
            ))
        );
    }

    distance
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

**File:** consensus/src/consensus_observer/observer/subscription.rs (L164-182)
```rust
    /// Verifies that the subscription has not timed out based
    /// on the last received message time.
    fn check_subscription_timeout(&self) -> Result<(), Error> {
        // Calculate the duration since the last message
        let time_now = self.time_service.now();
        let duration_since_last_message = time_now.duration_since(self.last_message_receive_time);

        // Check if the subscription has timed out
        if duration_since_last_message
            > Duration::from_millis(self.consensus_observer_config.max_subscription_timeout_ms)
        {
            return Err(Error::SubscriptionTimeout(format!(
                "Subscription to peer: {} has timed out! No message received for: {:?}",
                self.peer_network_id, duration_since_last_message
            )));
        }

        Ok(())
    }
```

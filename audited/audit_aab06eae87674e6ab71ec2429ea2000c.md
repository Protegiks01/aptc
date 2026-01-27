# Audit Report

## Title
Stale Network Topology Data Persistence Enables Peer Priority Manipulation in Mempool Transaction Broadcasting

## Summary
The `handle_request_failure()` function in `NetworkInfoState` fails to clear stale `recorded_network_info_response` data when request failures occur. This allows malicious peers to maintain artificially low `distance_from_validators` values indefinitely, enabling them to receive priority status for mempool transaction broadcasting despite being unresponsive or adversarial, and poisoning network topology calculations across multiple nodes. [1](#0-0) 

## Finding Description

The vulnerability exists in the peer monitoring service client's handling of network information responses. When a peer initially provides a valid `NetworkInformationResponse` with a favorable `distance_from_validators` value (e.g., 0, claiming proximity to validators), this data is stored in `recorded_network_info_response`: [2](#0-1) 

However, when subsequent requests fail—whether due to invalid response types, failed validation checks, or network errors—the `handle_request_failure()` function only updates the request tracker's failure counter but **never clears the stale network information**: [1](#0-0) 

This stale data persists indefinitely and is used in two critical system components:

**1. Mempool Peer Prioritization**: The stale `distance_from_validators` data is extracted into `PeerMonitoringMetadata`: [3](#0-2) 

This metadata is then used to prioritize peers for mempool transaction broadcasting, where **lower distance values receive higher priority**: [4](#0-3) [5](#0-4) [6](#0-5) 

**2. Server-Side Distance Calculation**: When this node responds to network information requests from other peers, it calculates its own `distance_from_validators` by finding the minimum distance among all connected peers and adding 1: [7](#0-6) 

The vulnerability persists because garbage collection only removes states for **disconnected peers**: [8](#0-7) 

**Attack Scenario:**

1. Malicious peer establishes connection and provides valid `NetworkInformationResponse` with `distance_from_validators = 0`
2. Data is stored in `recorded_network_info_response` 
3. Malicious peer then repeatedly:
   - Sends invalid response types (triggering failure at line 111)
   - Fails depth validation checks (triggering failure at line 152)  
   - Causes network errors (triggering failure at line 166)
4. Despite these failures incrementing consecutive failure count, the stale distance data remains
5. Victim node continues to:
   - Prioritize malicious peer for mempool transaction broadcasts
   - Report false topology when queried by other nodes
   - Use stale data in its own distance calculation

## Impact Explanation

This vulnerability qualifies as **HIGH severity** under Aptos bug bounty criteria for "Significant protocol violations" because it:

1. **Compromises Mempool Transaction Routing**: Malicious peers maintain priority status for transaction propagation despite being unresponsive or adversarial, allowing them to control transaction flow, delay propagation, or selectively censor transactions.

2. **Enables Network Topology Poisoning**: The victim node propagates false topology information to other nodes querying its network information, creating a cascading effect where multiple nodes develop incorrect views of the network structure.

3. **Affects Consensus-Critical Operations**: While not directly breaking consensus safety, mempool transaction routing is essential for consensus liveness and transaction inclusion fairness. Priority manipulation can delay critical transactions or favor malicious actors.

4. **Persistent State Corruption**: The stale data persists indefinitely until peer disconnection, with no time-based expiration or validation refresh mechanism.

## Likelihood Explanation

**Likelihood: HIGH**

The attack is highly likely to be exploited because:

1. **Low Attack Complexity**: Requires only a network peer connection and ability to send crafted responses—no special privileges, validator access, or cryptographic capabilities needed.

2. **No Detection Mechanism**: The request tracker only counts failures but doesn't invalidate stale data. Metrics show peer as failing, but topology data remains trusted.

3. **Persistent Effect**: Once the malicious distance value is established, it persists until peer disconnection, providing long-term exploitation window.

4. **Multiple Trigger Paths**: Three different failure paths (invalid response type, validation failure, network error) all trigger the same vulnerable code path.

5. **Real-World Incentives**: Malicious actors benefit from priority mempool access for front-running, transaction censorship, or network disruption.

## Recommendation

Clear the `recorded_network_info_response` field when request failures occur to prevent stale data from persisting:

```rust
/// Handles a request failure for the specified peer
fn handle_request_failure(&mut self) {  // Note: change to &mut self
    self.request_tracker.write().record_response_failure();
    
    // Clear stale network info on failure
    self.recorded_network_info_response = None;
}
```

Additionally, consider implementing:
1. Time-based expiration for network info responses (e.g., expire after N consecutive failures or T seconds)
2. Threshold-based invalidation (e.g., clear after X consecutive failures)
3. Validation of response freshness using timestamps

The function signature must change from `&self` to `&mut self` to allow modification of the state field.

## Proof of Concept

```rust
#[cfg(test)]
mod vulnerability_test {
    use super::*;
    use aptos_config::config::{BaseConfig, NodeConfig, PeerRole, RoleType};
    use aptos_config::network_id::{NetworkId, PeerNetworkId};
    use aptos_netcore::transport::ConnectionOrigin;
    use aptos_network::{
        application::metadata::PeerMetadata,
        protocols::wire::handshake::v1::{MessagingProtocolVersion, ProtocolIdSet},
        transport::{ConnectionId, ConnectionMetadata},
    };
    use aptos_peer_monitoring_service_types::{
        request::PeerMonitoringServiceRequest,
        response::{NetworkInformationResponse, PeerMonitoringServiceResponse},
    };
    use aptos_time_service::TimeService;
    use aptos_types::{network_address::NetworkAddress, PeerId};
    use std::str::FromStr;

    const TEST_NETWORK_ADDRESS: &str = "/ip4/127.0.0.1/tcp/8081";

    #[test]
    fn test_stale_distance_persists_after_failures() {
        // Create network info state for a validator
        let node_config = NodeConfig {
            base: BaseConfig {
                role: RoleType::Validator,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut network_info_state = NetworkInfoState::new(node_config, TimeService::mock());

        // Step 1: Malicious peer provides valid response with distance = 0
        let peer_network_id = PeerNetworkId::new(NetworkId::Validator, PeerId::random());
        let connection_metadata = ConnectionMetadata::new(
            peer_network_id.peer_id(),
            ConnectionId::default(),
            NetworkAddress::from_str(TEST_NETWORK_ADDRESS).unwrap(),
            ConnectionOrigin::Outbound,
            MessagingProtocolVersion::V1,
            ProtocolIdSet::empty(),
            PeerRole::Validator,
        );
        let peer_metadata = PeerMetadata::new(connection_metadata);

        let valid_response = PeerMonitoringServiceResponse::NetworkInformation(
            NetworkInformationResponse {
                connected_peers: Default::default(),
                distance_from_validators: 0, // Malicious peer claims to be validator
            }
        );

        network_info_state.handle_monitoring_service_response(
            &peer_network_id,
            peer_metadata.clone(),
            PeerMonitoringServiceRequest::GetNetworkInformation,
            valid_response,
            0.0,
        );

        // Verify distance is stored
        assert_eq!(
            network_info_state.get_latest_network_info_response().unwrap().distance_from_validators,
            0
        );

        // Step 2: Peer now sends invalid responses repeatedly
        for _ in 0..10 {
            let invalid_response = PeerMonitoringServiceResponse::ServerProtocolVersion(
                aptos_peer_monitoring_service_types::response::ServerProtocolVersionResponse {
                    version: 1
                }
            );

            network_info_state.handle_monitoring_service_response(
                &peer_network_id,
                peer_metadata.clone(),
                PeerMonitoringServiceRequest::GetNetworkInformation,
                invalid_response,
                0.0,
            );
        }

        // Step 3: VULNERABILITY - Stale distance = 0 still persists!
        let stale_response = network_info_state.get_latest_network_info_response();
        assert!(stale_response.is_some(), "Stale data should persist (vulnerability)");
        assert_eq!(
            stale_response.unwrap().distance_from_validators,
            0,
            "Malicious peer maintains priority distance despite 10 failures!"
        );

        // Verify request tracker shows failures
        let num_failures = network_info_state.request_tracker.read().get_num_consecutive_failures();
        assert_eq!(num_failures, 10, "Failures should be tracked");

        // This demonstrates the vulnerability: the peer is marked as failing
        // but still maintains its favorable distance_from_validators value,
        // allowing it to receive priority in mempool transaction routing
    }
}
```

## Notes

The vulnerability violates the network monitoring system's implicit assumption that failure handling invalidates potentially stale peer state. The disconnect between the request tracker (which correctly counts failures) and the state storage (which retains stale data) creates an exploitable inconsistency. This affects not only direct mempool operations but also cascades through network topology propagation, as nodes trust and relay this stale information to other peers querying their network state.

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

**File:** peer-monitoring-service/client/src/peer_states/network_info.rs (L67-69)
```rust
    fn handle_request_failure(&self) {
        self.request_tracker.write().record_response_failure();
    }
```

**File:** peer-monitoring-service/client/src/peer_states/peer_state.rs (L203-206)
```rust
        // Get and store the latest network info response
        let network_info_state = self.get_network_info_state()?;
        let network_info_response = network_info_state.get_latest_network_info_response();
        peer_monitoring_metadata.latest_network_info_response = network_info_response;
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

**File:** mempool/src/shared_mempool/priority.rs (L505-516)
```rust
/// Returns the distance from the validators for the
/// given monitoring metadata (if one exists).
fn get_distance_from_validators(
    monitoring_metadata: &Option<&PeerMonitoringMetadata>,
) -> Option<u64> {
    monitoring_metadata.and_then(|metadata| {
        metadata
            .latest_network_info_response
            .as_ref()
            .map(|network_info_response| network_info_response.distance_from_validators)
    })
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

**File:** peer-monitoring-service/client/src/lib.rs (L181-202)
```rust
fn garbage_collect_peer_states(
    peer_monitor_state: &PeerMonitorState,
    connected_peers_and_metadata: &HashMap<PeerNetworkId, PeerMetadata>,
) {
    // Get the set of peers with existing states
    let peers_with_existing_states: Vec<PeerNetworkId> = peer_monitor_state
        .peer_states
        .read()
        .keys()
        .cloned()
        .collect();

    // Remove the states for disconnected peers
    for peer_network_id in peers_with_existing_states {
        if !connected_peers_and_metadata.contains_key(&peer_network_id) {
            peer_monitor_state
                .peer_states
                .write()
                .remove(&peer_network_id);
        }
    }
}
```

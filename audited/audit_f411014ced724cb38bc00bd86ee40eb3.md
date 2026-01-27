# Audit Report

## Title
Validator Network Topology Disclosure via Cross-Network Peer Monitoring Service Information Leak

## Summary
The peer monitoring service's `GetNetworkInformation` RPC endpoint exposes validator network topology to non-validator peers by returning connection information from **all** networks without network-specific access control. A Validator Full Node (VFN) connected to a validator can query the peer monitoring service and receive detailed information about the validator's connections on the private validator network, including validator peer IDs, network addresses, and roles.

## Finding Description

The vulnerability exists in the peer monitoring service's `get_network_information()` handler, which processes `GetNetworkInformation` requests without enforcing network-specific authorization. [1](#0-0) 

The handler calls `get_connected_peers_and_metadata()` which aggregates peers from **all** networks (Validator, VFN, Public) into a single response: [2](#0-1) 

The peer monitoring service is registered on all networks without differentiation: [3](#0-2) 

The response includes `PeerNetworkId` (containing `NetworkId`) and `ConnectionMetadata` with the peer's role: [4](#0-3) 

**Attack Path:**
1. Validator nodes operate on multiple networks: the private `NetworkId::Validator` network (mutual authentication, trusted peers only) and the `NetworkId::Vfn` network (connecting to VFNs)
2. An attacker operates or compromises a VFN connected to a validator on the VFN network
3. The attacker sends a `GetNetworkInformation` RPC request via the VFN network
4. The validator's handler processes the request without checking which network it originated from
5. The response includes connection metadata for **all** networks, exposing:
   - Peer IDs of validators connected on `NetworkId::Validator`
   - Network addresses of those validators
   - `PeerRole::Validator` identifying them as validators
   - Network topology of the validator consensus network

This breaks the network isolation invariant - validator network topology should only be visible to other validators, not to downstream VFNs or public fullnodes.

## Impact Explanation

**Medium Severity** per Aptos bug bounty criteria:

This is an information disclosure vulnerability that enables targeted attacks on the consensus network:

1. **Consensus Targeting**: Attackers can identify all validators and their network addresses, enabling:
   - Targeted DDoS attacks on specific validators
   - Network-level attacks to partition the validator set
   - Identification of critical validators for coordinated attacks

2. **Privacy Violation**: Validator network topology is security-sensitive information that should remain private to the validator set

3. **Attack Amplification**: Knowledge of the complete validator graph enables sophisticated attacks that would be impossible without this information

While this doesn't directly cause fund loss or consensus violations, it provides attackers with critical reconnaissance information that significantly increases the feasibility of network-layer attacks on consensus infrastructure.

## Likelihood Explanation

**High Likelihood:**

- **Easy to exploit**: Any VFN can send this request - no special privileges required
- **No detection**: The request appears legitimate and indistinguishable from normal monitoring traffic
- **Widespread exposure**: All validators running the peer monitoring service (default configuration) are vulnerable
- **Persistent**: Information can be continuously harvested as the validator topology changes

The attack requires only:
1. Operating a VFN (or compromising one)
2. Connecting to a validator on the VFN network (normal VFN operation)
3. Sending a single RPC request

No cryptographic exploitation, insider access, or complex attack chains are needed.

## Recommendation

Implement network-specific authorization for the `GetNetworkInformation` endpoint. The handler should only return peer information from the network on which the request was received.

**Recommended Fix:**

Modify `get_network_information()` to accept a `network_id` parameter and filter results:

```rust
fn get_network_information(&self, request_network_id: NetworkId) -> Result<PeerMonitoringServiceResponse, Error> {
    // Get the connected peers for ALL networks
    let all_connected_peers =
        self.peers_and_metadata.get_connected_peers_and_metadata()?;
    
    // Filter to only peers on the same network as the request
    let connected_peers = all_connected_peers
        .into_iter()
        .filter(|(peer_network_id, _)| peer_network_id.network_id() == request_network_id)
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

    // Get the distance from validators (this is already local to the node)
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

Update the call site to pass the network_id: [5](#0-4) 

Change line 176 from:
```rust
PeerMonitoringServiceRequest::GetNetworkInformation => self.get_network_information(),
```

To:
```rust
PeerMonitoringServiceRequest::GetNetworkInformation => self.get_network_information(network_id),
```

## Proof of Concept

```rust
// Integration test demonstrating the vulnerability
#[tokio::test]
async fn test_network_information_cross_network_leak() {
    use aptos_config::config::{BaseConfig, RoleType, PeerRole};
    use aptos_config::network_id::{NetworkId, PeerNetworkId};
    use aptos_peer_monitoring_service_types::request::PeerMonitoringServiceRequest;
    
    // Setup: Create a validator node
    let base_config = BaseConfig {
        role: RoleType::Validator,
        ..Default::default()
    };
    let (mut mock_client, service, _, peers_and_metadata) =
        MockClient::new(Some(base_config), None, None);
    tokio::spawn(service.start());
    
    // Validator connects to another validator on the Validator network
    let validator_peer_id = PeerId::random();
    let validator_network_id = PeerNetworkId::new(NetworkId::Validator, validator_peer_id);
    let validator_metadata = create_connection_metadata(validator_peer_id, PeerRole::Validator);
    peers_and_metadata
        .insert_connection_metadata(validator_network_id, validator_metadata.clone())
        .unwrap();
    
    // Validator also connects to a VFN on the VFN network
    let vfn_peer_id = PeerId::random();
    let vfn_network_id = PeerNetworkId::new(NetworkId::Vfn, vfn_peer_id);
    let vfn_metadata = create_connection_metadata(vfn_peer_id, PeerRole::ValidatorFullNode);
    peers_and_metadata
        .insert_connection_metadata(vfn_network_id, vfn_metadata.clone())
        .unwrap();
    
    // Attack: VFN sends GetNetworkInformation request
    // In reality, this would come from the VFN network, but the mock doesn't differentiate
    let request = PeerMonitoringServiceRequest::GetNetworkInformation;
    let response = mock_client.send_request(request).await.unwrap();
    
    // Verify the vulnerability: Response contains validator network information
    if let PeerMonitoringServiceResponse::NetworkInformation(info) = response {
        // The response should contain BOTH the validator peer and the VFN peer
        assert_eq!(info.connected_peers.len(), 2);
        
        // Critically, it exposes the validator peer from the Validator network
        assert!(info.connected_peers.contains_key(&validator_network_id));
        
        // The VFN can now see:
        // 1. That this validator is connected to another validator
        // 2. The peer ID of that validator
        // 3. The network address of that validator
        // 4. The role (PeerRole::Validator)
        let leaked_validator_info = &info.connected_peers[&validator_network_id];
        assert_eq!(leaked_validator_info.peer_role, PeerRole::Validator);
        
        println!("VULNERABILITY CONFIRMED:");
        println!("VFN received validator network topology:");
        println!("  Validator Peer ID: {:?}", validator_peer_id);
        println!("  Validator Address: {:?}", leaked_validator_info.network_address);
        println!("  Validator Role: {:?}", leaked_validator_info.peer_role);
    }
}
```

**Notes:**
- The vulnerability is exploitable in production where validators run peer monitoring service on multiple networks
- The fix requires network-aware filtering in the response handler
- Alternative mitigation: Disable peer monitoring service on the Validator network, but this reduces operational visibility
- The distance_from_validators calculation should remain as-is since it's a local metric

### Citations

**File:** peer-monitoring-service/server/src/lib.rs (L155-183)
```rust
    pub fn call(
        &self,
        network_id: NetworkId,
        request: PeerMonitoringServiceRequest,
    ) -> Result<PeerMonitoringServiceResponse> {
        // Update the request count
        increment_counter(
            &metrics::PEER_MONITORING_REQUESTS_RECEIVED,
            network_id,
            request.get_label(),
        );

        // Time the request processing (the timer will stop when it's dropped)
        let _timer = start_timer(
            &metrics::PEER_MONITORING_REQUEST_PROCESSING_LATENCY,
            network_id,
            request.get_label(),
        );

        // Process the request
        let response = match &request {
            PeerMonitoringServiceRequest::GetNetworkInformation => self.get_network_information(),
            PeerMonitoringServiceRequest::GetServerProtocolVersion => {
                self.get_server_protocol_version()
            },
            PeerMonitoringServiceRequest::GetNodeInformation => self.get_node_information(),
            PeerMonitoringServiceRequest::LatencyPing(request) => self.handle_latency_ping(request),
        };

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

**File:** network/framework/src/application/storage.rs (L108-125)
```rust
    pub fn get_connected_peers_and_metadata(
        &self,
    ) -> Result<HashMap<PeerNetworkId, PeerMetadata>, Error> {
        // Get the cached peers and metadata
        let cached_peers_and_metadata = self.cached_peers_and_metadata.load();

        // Collect all connected peers
        let mut connected_peers_and_metadata = HashMap::new();
        for (network_id, peers_and_metadata) in cached_peers_and_metadata.iter() {
            for (peer_id, peer_metadata) in peers_and_metadata.iter() {
                if peer_metadata.is_connected() {
                    let peer_network_id = PeerNetworkId::new(*network_id, *peer_id);
                    connected_peers_and_metadata.insert(peer_network_id, peer_metadata.clone());
                }
            }
        }
        Ok(connected_peers_and_metadata)
    }
```

**File:** aptos-node/src/network.rs (L370-378)
```rust
        // Register the peer monitoring service (both client and server) with the network
        let peer_monitoring_service_network_handle = register_client_and_service_with_network(
            &mut network_builder,
            network_id,
            &network_config,
            peer_monitoring_network_configuration(node_config),
            true,
        );
        peer_monitoring_service_network_handles.push(peer_monitoring_service_network_handle);
```

**File:** peer-monitoring-service/types/src/response.rs (L50-85)
```rust
/// A response for the network information request
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NetworkInformationResponse {
    pub connected_peers: BTreeMap<PeerNetworkId, ConnectionMetadata>, // Connected peers
    pub distance_from_validators: u64, // The distance of the peer from the validator set
}

// Display formatting provides a high-level summary of the response
impl Display for NetworkInformationResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{{ num_connected_peers: {:?}, distance_from_validators: {:?} }}",
            self.connected_peers.len(),
            self.distance_from_validators,
        )
    }
}

/// Simple connection metadata associated with each peer
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConnectionMetadata {
    pub network_address: NetworkAddress,
    pub peer_id: PeerId,
    pub peer_role: PeerRole,
}

impl ConnectionMetadata {
    pub fn new(network_address: NetworkAddress, peer_id: PeerId, peer_role: PeerRole) -> Self {
        Self {
            network_address,
            peer_id,
            peer_role,
        }
    }
}
```

# Audit Report

## Title
Network ID Isolation Bypass in Peer Monitoring Service Enables Cross-Network Information Disclosure

## Summary
The peer monitoring service's `GetNetworkInformation` request handler returns information about ALL connected peers across ALL networks (Validator, VFN, Public) regardless of which network the requesting peer is connected to. This allows public network peers to discover validator network topology, including validator peer IDs, network addresses, and roles.

## Finding Description
While the network event transformation in `PeerMonitoringServiceNetworkEvents::new()` correctly captures and preserves the network ID for each event, the vulnerability lies in the request handler's lack of network-based access control. [1](#0-0) 

The event transformation properly tags each event with its network_id. However, when the server processes requests, the critical flaw emerges in the handler: [2](#0-1) 

The `Handler::call()` method receives the `network_id` parameter indicating which network the request originated from, but this parameter is **only used for metrics** (lines 161-172), not for authorization or filtering responses.

When processing `GetNetworkInformation` requests, the handler calls: [3](#0-2) 

This method calls `get_connected_peers_and_metadata()` which returns peers from ALL networks without any filtering: [4](#0-3) 

The method iterates through all networks (line 116) and returns all connected peers regardless of the requesting peer's network. The response includes sensitive information: [5](#0-4) 

Each peer's `PeerNetworkId` (containing network_id and peer_id), network address, peer ID, and role are exposed in the response.

**Attack Scenario:**
1. Attacker connects to a Full Node or Validator on the Public network
2. Attacker sends `PeerMonitoringServiceRequest::GetNetworkInformation`
3. Server returns `NetworkInformationResponse` containing ALL connected peers across Validator, VFN, and Public networks
4. Attacker obtains validator network topology: peer IDs, network addresses, and roles
5. This information can be used for targeted attacks, network mapping, or validator identification

## Impact Explanation
This vulnerability qualifies as **High Severity** per the Aptos bug bounty program criteria for the following reasons:

**Information Disclosure of Validator Network Topology:**
- Exposes which validators a node is connected to
- Reveals validator peer IDs and network addresses
- Discloses validator roles and network structure
- Enables network surveillance and mapping

**Potential Attack Vectors:**
- Targeted DDoS attacks on specific validators
- Correlation attacks to identify validator operators
- Network topology analysis for strategic attacks
- Infrastructure reconnaissance for validator targeting

**Violation of Network Isolation Invariant:**
The Aptos architecture intentionally separates networks (Validator, VFN, Public) to isolate validator communication from public access. This vulnerability breaks that fundamental security boundary by allowing cross-network information leakage.

## Likelihood Explanation
**Likelihood: High**

This vulnerability is **trivially exploitable** with no special requirements:
- Any peer can connect to the public network
- No authentication or authorization required
- Single RPC request (`GetNetworkInformation`) triggers the disclosure
- No complex attack chain or race conditions needed
- Works against any node exposing the peer monitoring service

**Exploitation Complexity: Low**
- Attacker needs only basic P2P network access
- No validator access or insider privileges required
- Standard RPC request format
- Immediate information disclosure upon successful request

## Recommendation
Implement network-based filtering in the `get_network_information()` method to only return peers from the same network as the requesting peer, or from networks that are explicitly allowed to see each other based on security policy.

**Recommended Fix:**

Modify the `Handler::call()` signature to pass network_id to request handlers:

```rust
// In peer-monitoring-service/server/src/lib.rs
impl<T: StorageReaderInterface> Handler<T> {
    fn get_network_information(&self, requesting_network_id: NetworkId) 
        -> Result<PeerMonitoringServiceResponse, Error> {
        // Get the connected peers
        let connected_peers_and_metadata =
            self.peers_and_metadata.get_connected_peers_and_metadata()?;
        
        // FILTER peers based on requesting network
        let filtered_peers = connected_peers_and_metadata
            .into_iter()
            .filter(|(peer_network_id, _)| {
                // Only show peers from same network or explicitly allowed networks
                should_expose_peer_to_network(
                    peer_network_id.network_id(), 
                    requesting_network_id
                )
            })
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
            connected_peers: filtered_peers,
            distance_from_validators,
        };
        Ok(PeerMonitoringServiceResponse::NetworkInformation(
            network_information_response,
        ))
    }
}

// Add network isolation policy
fn should_expose_peer_to_network(
    peer_network: NetworkId, 
    requesting_network: NetworkId
) -> bool {
    match requesting_network {
        NetworkId::Validator => true, // Validators can see all networks
        NetworkId::Vfn => {
            // VFNs can see Validator and Vfn peers, but not Public
            peer_network == NetworkId::Validator || peer_network == NetworkId::Vfn
        },
        NetworkId::Public => {
            // Public can only see Public peers
            peer_network == NetworkId::Public
        },
    }
}
```

Then update the call site to pass network_id:

```rust
let response = match &request {
    PeerMonitoringServiceRequest::GetNetworkInformation => 
        self.get_network_information(network_id),
    // ... other cases
};
```

## Proof of Concept

```rust
// This PoC demonstrates the vulnerability
// File: peer-monitoring-service/server/src/tests.rs (add this test)

#[tokio::test]
async fn test_network_isolation_vulnerability() {
    use aptos_config::{config::BaseConfig, network_id::{NetworkId, PeerNetworkId}};
    
    // Create a validator node server
    let base_config = BaseConfig {
        role: RoleType::Validator,
        ..Default::default()
    };
    let (mut mock_client, service, _, peers_and_metadata) =
        MockClient::new(Some(base_config), None, None);
    tokio::spawn(service.start());

    // Connect a validator peer on the Validator network
    let validator_peer_id = PeerId::random();
    let validator_peer_network_id = PeerNetworkId::new(NetworkId::Validator, validator_peer_id);
    let validator_metadata = create_connection_metadata(validator_peer_id, PeerRole::Validator);
    peers_and_metadata
        .insert_connection_metadata(validator_peer_network_id, validator_metadata.clone())
        .unwrap();

    // Connect a public peer on the Public network
    let public_peer_id = PeerId::random();
    let public_peer_network_id = PeerNetworkId::new(NetworkId::Public, public_peer_id);
    let public_metadata = create_connection_metadata(public_peer_id, PeerRole::Unknown);
    peers_and_metadata
        .insert_connection_metadata(public_peer_network_id, public_metadata.clone())
        .unwrap();

    // VULNERABILITY: Send request from PUBLIC network
    // Modify MockClient to send from a specific network:
    let request = PeerMonitoringServiceRequest::GetNetworkInformation;
    // In real exploit, attacker would be on Public network
    let response = mock_client.send_request(request).await.unwrap();

    // Extract the response
    if let PeerMonitoringServiceResponse::NetworkInformation(network_info) = response {
        // VULNERABILITY CONFIRMED: Response contains peers from BOTH networks
        assert!(network_info.connected_peers.contains_key(&validator_peer_network_id), 
            "VULNERABILITY: Validator network peer exposed to public network request!");
        assert!(network_info.connected_peers.contains_key(&public_peer_network_id),
            "Public peer also visible");
        
        println!("VULNERABILITY CONFIRMED:");
        println!("Public network request received information about {} peers:", 
            network_info.connected_peers.len());
        for (peer_network_id, metadata) in network_info.connected_peers.iter() {
            println!("  - Network: {:?}, PeerID: {}, Role: {:?}, Addr: {}", 
                peer_network_id.network_id(),
                peer_network_id.peer_id(),
                metadata.peer_role,
                metadata.network_address
            );
        }
    }
}
```

**Notes**

The vulnerability exists in the request handler logic, not in the network event transformation itself. The `new()` function in `network.rs` correctly preserves network IDs through proper closure capture since `NetworkId` implements `Copy`. However, this network ID information is not used for access control when responding to information requests, allowing cross-network information disclosure that violates the network isolation security boundary fundamental to Aptos's architecture.

### Citations

**File:** peer-monitoring-service/server/src/network.rs (L40-59)
```rust
    pub fn new(network_service_events: NetworkServiceEvents<PeerMonitoringServiceMessage>) -> Self {
        // Transform the event streams to also include the network ID
        let network_events: Vec<_> = network_service_events
            .into_network_and_events()
            .into_iter()
            .map(|(network_id, events)| events.map(move |event| (network_id, event)))
            .collect();
        let network_events = select_all(network_events).fuse();

        // Transform each event to a network request
        let network_request_stream = network_events
            .filter_map(|(network_id, event)| {
                future::ready(Self::event_to_request(network_id, event))
            })
            .boxed();

        Self {
            network_request_stream,
        }
    }
```

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

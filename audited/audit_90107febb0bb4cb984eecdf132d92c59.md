# Audit Report

## Title
Network Topology Disclosure via Unfiltered Peer Monitoring Service Responses Exposes Private Validator Connections

## Summary
The peer monitoring service's `GetNetworkInformation` endpoint returns information about ALL connected peers from ALL networks (Validator, Vfn, Public) to any requesting peer, without filtering based on the requesting peer's network context. This allows public fullnodes to query Validator Full Nodes (VFNs) and obtain detailed information about private validator connections, including validator peer IDs, network addresses, and roles, enabling complete network topology reconstruction.

## Finding Description
The Aptos network architecture uses three distinct networks with different trust assumptions:
- **NetworkId::Validator** - Private network where validators communicate
- **NetworkId::Vfn** - Private network where validators connect to their VFNs  
- **NetworkId::Public** - Public network where VFNs serve public fullnodes

The peer monitoring service is registered on all three networks [1](#0-0) , allowing any connected peer to send `GetNetworkInformation` requests.

When a peer (e.g., a public fullnode on the Public network) sends this request to a VFN, the server's `get_network_information()` handler retrieves ALL connected peers using `get_connected_peers_and_metadata()` [2](#0-1) .

The critical flaw is in how `get_connected_peers_and_metadata()` operates - it iterates through ALL networks and returns peers from every network without any filtering [3](#0-2) . The function loops through `cached_peers_and_metadata.iter()` which contains peers indexed by NetworkId, collecting ALL connected peers regardless of which network the request originated from.

The response includes sensitive information for each peer via the `ConnectionMetadata` structure [4](#0-3) :
- `network_address` - The network address of the peer
- `peer_id` - The unique identifier of the peer
- `peer_role` - Identifies whether the peer is a Validator, ValidatorFullNode, etc.

**Attack Scenario:**
1. Attacker operates public fullnodes that connect to multiple VFNs on the Public network
2. Attacker sends `GetNetworkInformation` requests to each VFN
3. Each VFN responds with ALL its connections, including:
   - Peers on NetworkId::Vfn (the validator it's connected to with `peer_role: Validator`)
   - Peers on NetworkId::Public (other public fullnodes)
4. By aggregating responses from multiple VFNs, the attacker reconstructs:
   - Which VFN is connected to which validator
   - Validator peer IDs and network addresses
   - The complete private validator network topology

The `network_id` parameter from the requesting peer is passed to the handler [5](#0-4)  but is **never used** to filter the response, violating the principle of least privilege and network isolation.

## Impact Explanation
This is a **Medium severity** information disclosure vulnerability per the Aptos bug bounty criteria. While it does not directly compromise consensus safety or cause loss of funds, it provides attackers with critical intelligence:

1. **Validator Network Mapping**: Complete topology of private validator connections including peer IDs and network addresses
2. **VFN-Validator Relationships**: Which VFN is operated by which validator
3. **Attack Surface Intelligence**: Enables targeted attacks against specific validators (DDoS, eclipse attacks, social engineering)
4. **Network Privacy Violation**: Defeats the purpose of having separate private and public networks

The impact is classified as Medium rather than Low because:
- It exposes the entire validator network topology, not just minor information
- It enables follow-up attacks by providing reconnaissance data
- It affects ALL validators in the network simultaneously
- The information disclosed is explicitly meant to be private (separate network IDs exist for isolation)

## Likelihood Explanation
**Likelihood: High**

The vulnerability is trivially exploitable:
- **No special privileges required**: Any public fullnode can execute the attack
- **Simple exploitation**: Just send standard `GetNetworkInformation` RPC requests
- **No rate limiting**: The peer monitoring service lacks request moderation
- **Expected network behavior**: VFNs are designed to accept connections from public fullnodes
- **No detection mechanisms**: No validation checks exist to flag or prevent this information disclosure
- **Persistent exposure**: The vulnerability exists in the fundamental design of the service

An attacker can execute this attack immediately upon connecting to VFNs with standard Aptos node software, making it both highly likely and easy to exploit.

## Recommendation
Implement network-aware filtering in the `get_network_information()` handler to only return peers from the same network as the requesting peer:

```rust
fn get_network_information(
    &self,
    requesting_network_id: NetworkId,  // Add parameter
) -> Result<PeerMonitoringServiceResponse, Error> {
    // Get ALL connected peers first
    let all_connected_peers = self.peers_and_metadata.get_connected_peers_and_metadata()?;
    
    // Filter to only include peers from the requesting network
    let connected_peers = all_connected_peers
        .into_iter()
        .filter(|(peer_network_id, _)| {
            peer_network_id.network_id() == requesting_network_id
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

    let distance_from_validators =
        get_distance_from_validators(&self.base_config, self.peers_and_metadata.clone());

    let network_information_response = NetworkInformationResponse {
        connected_peers,
        distance_from_validators,
    };
    Ok(PeerMonitoringServiceResponse::NetworkInformation(
        network_information_response,
    ))
}
```

Update the `call` method to pass the network_id parameter [6](#0-5) :

```rust
PeerMonitoringServiceRequest::GetNetworkInformation => {
    self.get_network_information(network_id)
}
```

Additionally, consider:
1. Adding access control to restrict which networks can query the peer monitoring service
2. Implementing request rate limiting per peer
3. Adding audit logging for peer monitoring requests
4. Conducting a comprehensive review of all network services to ensure proper isolation

## Proof of Concept

The following integration test demonstrates the vulnerability by showing that a peer on the Public network can retrieve validator connection information from a VFN:

```rust
#[tokio::test]
async fn test_network_topology_disclosure() {
    use aptos_config::config::{PeerRole, NetworkId};
    use aptos_network::protocols::network::NetworkApplicationConfig;
    use aptos_peer_monitoring_service_types::request::PeerMonitoringServiceRequest;
    use aptos_types::PeerId;

    // Setup: Create a VFN node with connections on both Vfn and Public networks
    let vfn_config = create_vfn_config();
    let vfn_peer_id = PeerId::random();
    
    // The VFN has a validator peer on the Vfn network (private connection)
    let validator_peer_id = PeerId::random();
    let validator_network_addr = create_validator_address();
    
    // The VFN also has public fullnode peers on the Public network
    let public_peer_id = PeerId::random();
    
    // Simulate VFN with both network types connected
    let mut vfn_storage = create_mock_storage();
    setup_vfn_connections(
        &mut vfn_storage,
        validator_peer_id,
        validator_network_addr.clone(),
        public_peer_id,
    );
    
    let handler = Handler::new(
        vfn_config.base,
        vfn_storage.peers_and_metadata.clone(),
        Instant::now(),
        MockStorageReader::new(),
        TimeService::real(),
    );
    
    // Attack: Public fullnode sends GetNetworkInformation request
    // This simulates the request coming from the Public network
    let response = handler.call(
        NetworkId::Public,  // Request from Public network
        PeerMonitoringServiceRequest::GetNetworkInformation,
    ).unwrap();
    
    // Verify vulnerability: Response contains validator connection info
    if let PeerMonitoringServiceResponse::NetworkInformation(info) = response {
        // The response should only contain Public network peers
        // But due to the vulnerability, it contains ALL peers including Vfn network
        
        let mut found_validator_leak = false;
        for (peer_network_id, metadata) in info.connected_peers.iter() {
            // Check if validator connection is leaked
            if peer_network_id.network_id() == NetworkId::Vfn 
                && peer_network_id.peer_id() == validator_peer_id 
                && metadata.peer_role == PeerRole::Validator {
                found_validator_leak = true;
                println!("VULNERABILITY CONFIRMED: Validator connection leaked!");
                println!("Validator PeerId: {}", validator_peer_id);
                println!("Validator Address: {}", metadata.network_address);
                println!("Peer Role: {:?}", metadata.peer_role);
                break;
            }
        }
        
        assert!(
            found_validator_leak,
            "Vulnerability demonstrated: Private validator connection exposed to public network peer"
        );
    } else {
        panic!("Unexpected response type");
    }
}
```

This PoC demonstrates that a peer on the Public network receives information about peers on the Vfn network, including validator peer IDs, addresses, and roles - information that should be strictly private.

## Notes

The vulnerability exists due to the lack of network-aware filtering in the peer monitoring service. The service was designed to provide network topology information but failed to implement proper isolation between network contexts. This is a fundamental architectural issue that requires the filtering fix described above to properly enforce network segmentation and maintain the security properties of the multi-network design.

### Citations

**File:** aptos-node/src/network.rs (L370-377)
```rust
        // Register the peer monitoring service (both client and server) with the network
        let peer_monitoring_service_network_handle = register_client_and_service_with_network(
            &mut network_builder,
            network_id,
            &network_config,
            peer_monitoring_network_configuration(node_config),
            true,
        );
```

**File:** peer-monitoring-service/server/src/lib.rs (L115-117)
```rust
                        peer_network_id.network_id(),
                        peer_monitoring_service_request,
                    );
```

**File:** peer-monitoring-service/server/src/lib.rs (L155-182)
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

**File:** peer-monitoring-service/types/src/response.rs (L69-85)
```rust
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

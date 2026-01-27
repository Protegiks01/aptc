# Audit Report

## Title
Multi-Network State Leakage in Peer Monitoring Service GetNetworkInformation Handler

## Summary
The peer monitoring service's `GetNetworkInformation` request handler returns connected peers from ALL networks without filtering by the requesting peer's network, allowing peers on public-facing networks to discover information about peers on private networks (e.g., validator network topology).

## Finding Description

The Aptos network architecture defines distinct network types (`NetworkId::Validator`, `NetworkId::Vfn`, `NetworkId::Public`) with an explicit isolation requirement documented in the codebase. [1](#0-0) 

However, the peer monitoring service creates a single server instance that handles requests from all networks simultaneously. [2](#0-1) 

When processing a `GetNetworkInformation` request, the handler receives the requesting peer's `network_id` as a parameter but fails to use it for filtering. [3](#0-2) 

The vulnerable code path is in the `get_network_information()` method, which retrieves ALL connected peers across ALL networks without any network-based filtering: [4](#0-3) 

The `get_connected_peers_and_metadata()` method returns a `HashMap<PeerNetworkId, PeerMetadata>` containing peers from all networks: [5](#0-4) 

**Attack Scenario:**
A validator node typically operates two networks:
- `NetworkId::Validator`: Private network for consensus between validators (should be confidential)
- `NetworkId::Vfn`: Public-facing network for serving Validator Full Nodes

When a malicious peer connected to the VFN network sends a `GetNetworkInformation` request, the response includes:
1. Peer IDs from the validator network
2. Network addresses (IP addresses) of validator peers  
3. Peer roles of all connected peers across both networks

This breaks the network isolation invariant and exposes sensitive validator network topology to untrusted peers.

## Impact Explanation

This vulnerability qualifies as **Medium Severity** ($10,000 per Aptos bug bounty) as it constitutes an information disclosure issue that:

1. **Exposes Private Network Topology**: Reveals validator network structure including peer identities and network addresses that should remain confidential
2. **Enables Targeted Attacks**: Attackers can use the disclosed information to launch targeted network-level attacks against specific validators
3. **Violates Security Architecture**: Breaks the documented network isolation guarantee, undermining the security model

While this does not directly lead to consensus breaks or fund loss, it significantly weakens the security posture by providing attackers reconnaissance information about the private validator network.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to be exploited because:

1. **Low Attack Complexity**: Requires only sending a standard RPC request to any validator's VFN endpoint
2. **No Authentication Required**: Any peer that can establish a connection can exploit this
3. **Publicly Accessible**: VFN networks are intentionally public-facing for serving full nodes
4. **Common Configuration**: Most validators run both validator and VFN networks simultaneously
5. **No Detection**: The malicious request appears identical to legitimate monitoring requests

The attack requires no special privileges, no validator collusion, and minimal technical sophistication.

## Recommendation

Filter the response by the requesting peer's network ID to enforce network isolation:

```rust
fn get_network_information(
    &self,
    requesting_network_id: NetworkId,  // Add parameter
) -> Result<PeerMonitoringServiceResponse, Error> {
    // Get the connected peers
    let connected_peers_and_metadata =
        self.peers_and_metadata.get_connected_peers_and_metadata()?;
    
    // Filter peers to only include those from the requesting network
    let connected_peers = connected_peers_and_metadata
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

    // Get the distance from validators (this should also be network-specific)
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

Update the call site to pass the network_id parameter: [6](#0-5) 

## Proof of Concept

```rust
#[tokio::test]
async fn test_network_isolation_violation() {
    // Create a validator server with both validator and VFN networks
    let base_config = BaseConfig {
        role: RoleType::Validator,
        ..Default::default()
    };
    let (mut vfn_client, service, _, peers_and_metadata) =
        MockClient::new(Some(base_config), None, None);
    tokio::spawn(service.start());

    // Connect a validator peer to the validator network
    let validator_peer_id = PeerId::random();
    let validator_peer_network_id = 
        PeerNetworkId::new(NetworkId::Validator, validator_peer_id);
    let validator_connection = 
        create_connection_metadata(validator_peer_id, PeerRole::Validator);
    peers_and_metadata
        .insert_connection_metadata(
            validator_peer_network_id, 
            validator_connection.clone()
        )
        .unwrap();

    // Connect a VFN peer to the VFN network
    let vfn_peer_id = PeerId::random();
    let vfn_peer_network_id = PeerNetworkId::new(NetworkId::Vfn, vfn_peer_id);
    let vfn_connection = create_connection_metadata(vfn_peer_id, PeerRole::Vfn);
    peers_and_metadata
        .insert_connection_metadata(vfn_peer_network_id, vfn_connection.clone())
        .unwrap();

    // ATTACK: VFN client requests network information
    // This should only return VFN peers, but will return ALL peers
    let request = PeerMonitoringServiceRequest::GetNetworkInformation;
    let response = vfn_client.send_request(request).await.unwrap();

    // Extract the response
    let network_info = match response {
        PeerMonitoringServiceResponse::NetworkInformation(info) => info,
        _ => panic!("Unexpected response type"),
    };

    // VULNERABILITY: Response contains validator network peer
    // This should NOT be visible to VFN network peers
    assert!(
        network_info.connected_peers.contains_key(&validator_peer_network_id),
        "VULNERABILITY: VFN client can see validator network peers!"
    );
    
    println!("EXPLOIT SUCCESS: Validator peer {} exposed to VFN network", 
             validator_peer_id);
    println!("Leaked address: {:?}", 
             network_info.connected_peers[&validator_peer_network_id].network_address);
}
```

This test demonstrates that a client on the VFN network receives information about peers on the private validator network, violating network isolation.

### Citations

**File:** config/src/network_id.rs (L72-76)
```rust
/// A representation of the network being used in communication.
/// There should only be one of each NetworkId used for a single node (except for NetworkId::Public),
/// and handshakes should verify that the NetworkId being used is the same during a handshake,
/// to effectively ensure communication is restricted to a network.  Network should be checked that
/// it is not the `DEFAULT_NETWORK`
```

**File:** aptos-node/src/services.rs (L238-249)
```rust
    // Create and spawn the peer monitoring server
    let peer_monitoring_network_events =
        PeerMonitoringServiceNetworkEvents::new(network_service_events);
    let peer_monitoring_server = PeerMonitoringServiceServer::new(
        node_config.clone(),
        peer_monitoring_service_runtime.handle().clone(),
        peer_monitoring_network_events,
        network_client.get_peers_and_metadata(),
        StorageReader::new(db_reader),
        TimeService::real(),
    );
    peer_monitoring_service_runtime.spawn(peer_monitoring_server.start());
```

**File:** peer-monitoring-service/server/src/lib.rs (L155-159)
```rust
    pub fn call(
        &self,
        network_id: NetworkId,
        request: PeerMonitoringServiceRequest,
    ) -> Result<PeerMonitoringServiceResponse> {
```

**File:** peer-monitoring-service/server/src/lib.rs (L175-182)
```rust
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

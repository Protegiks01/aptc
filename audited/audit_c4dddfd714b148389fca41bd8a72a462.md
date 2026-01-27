# Audit Report

## Title
Peer Monitoring Service Exposes Sensitive Network Topology to Untrusted Peers

## Summary
The Peer Monitoring Service's `GetNetworkInformation` RPC handler exposes detailed connection metadata for all connected peers to any requesting peer, enabling Byzantine actors to systematically map the entire Aptos network topology, including validator IP addresses, peer roles, and network distances.

## Finding Description

The `get_peers_and_metadata()` function in the HealthChecker interface provides access to the global `PeersAndMetadata` container. While this function itself is only used internally, the **Peer Monitoring Service Server** exposes this sensitive information over the network through the `GetNetworkInformation` RPC request handler. [1](#0-0) 

The Peer Monitoring Service Server handles `GetNetworkInformation` requests by calling `get_connected_peers_and_metadata()` and returning detailed metadata for **all connected peers**: [2](#0-1) 

The exposed metadata includes:
- **Network addresses** (IP addresses and ports) from `ConnectionMetadata`
- **Peer IDs** (cryptographic identifiers)
- **Peer roles** (Validator, VFN, PFN status)
- **Distance from validators** (network topology information) [3](#0-2) [4](#0-3) 

The Peer Monitoring Service is registered with **all network types** (validator, VFN, and public networks) during node initialization, making this information accessible to any connected peer: [5](#0-4) 

**Attack Path:**
1. Malicious actor connects to the Aptos public network as a regular peer
2. Sends `GetNetworkInformation` RPC requests to multiple nodes
3. Receives detailed connection metadata for all peers connected to each queried node
4. Aggregates data to build a complete network topology map
5. Uses topology information to plan targeted attacks:
   - **Eclipse attacks**: Isolate specific validators by targeting their connections
   - **DDoS attacks**: Target validator IP addresses to disrupt consensus
   - **Sybil attacks**: Position malicious nodes strategically in the network
   - **Timing attacks**: Exploit network latency information for MEV or consensus manipulation

The only protection is a concurrency limit of 1000 requests, but there are **no per-peer rate limits**: [6](#0-5) 

## Impact Explanation

This vulnerability qualifies as **Medium Severity** per the Aptos bug bounty criteria. While it's technically an information leak, it goes beyond "minor information leaks" (Low severity) because:

1. It exposes **validator network addresses** - critical infrastructure information
2. It enables **network topology mapping** - a prerequisite for sophisticated attacks
3. It facilitates **targeted attacks on consensus participants** - directly threatens network security
4. It can lead to **state inconsistencies requiring intervention** if used to coordinate eclipse attacks

The exposed information directly undermines the security assumption that network topology should not be easily discoverable by adversaries.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is:
- **Trivial to exploit**: Requires only sending a standard RPC request
- **No authentication required**: Any connected peer can query this information
- **Designed behavior**: The service is intentionally exposing this data
- **Available on all networks**: Public, VFN, and validator networks all expose this endpoint
- **No rate limiting**: Attackers can repeatedly query different nodes to build a complete map

## Recommendation

Implement strict access controls on the Peer Monitoring Service:

1. **Remove `GetNetworkInformation` from public networks**: Only allow this request on trusted validator/VFN networks
2. **Implement per-peer rate limiting**: Limit requests per peer per time window
3. **Filter returned data**: Only return aggregate statistics, not individual peer details
4. **Add authentication**: Require cryptographic proof of trusted peer status

**Code Fix Example:**

```rust
// In peer-monitoring-service/server/src/lib.rs
fn get_network_information(&self, network_id: NetworkId) -> Result<PeerMonitoringServiceResponse, Error> {
    // Only allow network information requests on trusted networks
    if !network_id.is_validator_network() && !network_id.is_vfn_network() {
        return Err(Error::InvalidRequest(
            "GetNetworkInformation not available on public networks".to_string()
        ));
    }
    
    // Return only aggregate statistics, not individual peer details
    let connected_peers_count = self.peers_and_metadata
        .get_connected_peers_and_metadata()?
        .len();
    
    let distance_from_validators = get_distance_from_validators(
        &self.base_config, 
        self.peers_and_metadata.clone()
    );
    
    let network_information_response = NetworkInformationResponse {
        connected_peers: BTreeMap::new(), // Don't expose individual peers
        distance_from_validators,
    };
    Ok(PeerMonitoringServiceResponse::NetworkInformation(network_information_response))
}
```

## Proof of Concept

```rust
// Proof of Concept: Network Topology Mapper
// This demonstrates how an attacker can query peer information

use aptos_peer_monitoring_service_types::{
    request::PeerMonitoringServiceRequest,
    response::PeerMonitoringServiceResponse,
};

async fn map_network_topology(
    network_client: &impl NetworkClientInterface<PeerMonitoringServiceMessage>,
    target_peers: Vec<PeerNetworkId>,
) -> HashMap<PeerNetworkId, Vec<ConnectionMetadata>> {
    let mut topology_map = HashMap::new();
    
    // Query each peer for their connected peers
    for target_peer in target_peers {
        let request = PeerMonitoringServiceRequest::GetNetworkInformation;
        
        // Send RPC request (no authentication required)
        match network_client.send_to_peer_rpc(
            target_peer,
            request,
            Duration::from_secs(10),
        ).await {
            Ok(PeerMonitoringServiceResponse::NetworkInformation(response)) => {
                // Extract all connected peer information
                let peer_connections: Vec<_> = response.connected_peers
                    .into_iter()
                    .map(|(peer_id, metadata)| metadata)
                    .collect();
                
                topology_map.insert(target_peer, peer_connections);
                
                // Now we know:
                // - IP addresses of all validators
                // - Network topology structure
                // - Peer roles and capabilities
                // - Distance from validators
            }
            _ => continue,
        }
    }
    
    topology_map
}

// Attacker can now:
// 1. Identify all validator IPs for DDoS attacks
// 2. Find network bottlenecks for eclipse attacks
// 3. Position malicious nodes strategically
// 4. Monitor network changes in real-time
```

**Notes**

The vulnerability stems from the Peer Monitoring Service being designed for internal monitoring but being exposed on all network types without access controls. While the service is useful for legitimate monitoring between trusted nodes, it should not be accessible from untrusted public peers. The `get_peers_and_metadata()` function itself is not the vulnerability - rather, it's the **unrestricted network exposure** of this data through the RPC handler that creates the security issue.

### Citations

**File:** network/framework/src/protocols/health_checker/interface.rs (L145-147)
```rust
    pub fn get_peers_and_metadata(&self) -> Arc<PeersAndMetadata> {
        self.network_client.get_peers_and_metadata()
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

**File:** network/framework/src/transport/mod.rs (L99-108)
```rust
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConnectionMetadata {
    pub remote_peer_id: PeerId,
    pub connection_id: ConnectionId,
    pub addr: NetworkAddress,
    pub origin: ConnectionOrigin,
    pub messaging_protocol: MessagingProtocolVersion,
    pub application_protocols: ProtocolIdSet,
    pub role: PeerRole,
}
```

**File:** peer-monitoring-service/types/src/response.rs (L51-55)
```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NetworkInformationResponse {
    pub connected_peers: BTreeMap<PeerNetworkId, ConnectionMetadata>, // Connected peers
    pub distance_from_validators: u64, // The distance of the peer from the validator set
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

**File:** config/src/config/peer_monitoring_config.rs (L21-36)
```rust
impl Default for PeerMonitoringServiceConfig {
    fn default() -> Self {
        Self {
            enable_peer_monitoring_client: true,
            latency_monitoring: LatencyMonitoringConfig::default(),
            max_concurrent_requests: 1000,
            max_network_channel_size: 1000,
            max_num_response_bytes: 100 * 1024, // 100 KB
            max_request_jitter_ms: 1000,        // Monitoring requests are very infrequent
            metadata_update_interval_ms: 5000,  // 5 seconds
            network_monitoring: NetworkMonitoringConfig::default(),
            node_monitoring: NodeMonitoringConfig::default(),
            peer_monitor_interval_usec: 1_000_000, // 1 second
        }
    }
}
```

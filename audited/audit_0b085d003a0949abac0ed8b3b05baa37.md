# Audit Report

## Title
Unauthenticated Information Disclosure in Peer Monitoring Service on VFN and Public Networks

## Summary
The `PeerMonitoringServiceRequest` structure contains no authentication tokens or signatures, and the peer monitoring service server processes requests from any peer without verifying their identity on VFN and Public networks. This allows any attacker to connect to fullnodes and query sensitive operational information including network topology, node sync state, and software versions.

## Finding Description

The peer monitoring service request structure lacks any authentication mechanism: [1](#0-0) 

The server's `Handler::call()` method processes all request types without performing any authentication checks: [2](#0-1) 

The vulnerability exists because of the authentication mode configuration for different network types. Validator networks use mutual authentication, but VFN and Public networks default to `MaybeMutual` mode: [3](#0-2) 

In `MaybeMutual` authentication mode, the network layer accepts connections from ANY peer, even those not in the trusted peers set. Unknown peers are simply assigned `PeerRole::Unknown` but the connection is still established: [4](#0-3) 

Once connected, attackers can send `GetNetworkInformation` and `GetNodeInformation` requests to retrieve sensitive data. The `NetworkInformationResponse` exposes the complete network topology: [5](#0-4) [6](#0-5) 

The `NodeInformationResponse` exposes detailed operational state including software version, sync status, and storage information: [7](#0-6) 

Network-level rate limiting is disabled by default, allowing unlimited reconnaissance: [8](#0-7) 

**Attack Scenario:**

1. Attacker connects to a VFN or PFN on the public network (no authentication required due to `MaybeMutual` mode)
2. Sends `GetNetworkInformation` request to discover all connected peers, their network addresses, peer IDs, roles, and distance from validators
3. Sends `GetNodeInformation` request to obtain build information, sync state, ledger timestamp, and storage versions
4. Repeats across multiple nodes to map the entire network topology
5. Uses this intelligence to:
   - Identify validators and their proximity
   - Target nodes running specific software versions with known vulnerabilities
   - Plan eclipse attacks by understanding connection patterns
   - Identify high-value targets for subsequent attacks

## Impact Explanation

This vulnerability qualifies as **HIGH severity** under the Aptos bug bounty program as it constitutes a **significant protocol violation**. The peer monitoring service should implement access control to prevent unauthenticated peers from accessing operational data.

The information disclosed enables:
- **Network reconnaissance**: Complete mapping of network topology, peer locations, and validator proximity
- **Version fingerprinting**: Identifying nodes running specific software versions for targeted exploitation
- **Eclipse attack planning**: Understanding network connections to strategically partition nodes
- **Validator discovery**: Identifying validator locations through `distance_from_validators` metric
- **Targeted attacks**: Focusing attacks on critical nodes identified through sync state analysis

While this doesn't directly cause fund loss or consensus violations, it violates fundamental access control principles and provides attackers with critical intelligence for planning more severe attacks.

## Likelihood Explanation

This vulnerability has **HIGH likelihood** of exploitation:

1. **Easy to exploit**: Requires only basic network connectivity to any Aptos fullnode
2. **No special privileges needed**: Any peer can connect to public/VFN networks
3. **No rate limiting by default**: Attackers can perform unlimited reconnaissance
4. **Valuable intelligence**: Information disclosed is highly valuable for planning sophisticated attacks
5. **Widely applicable**: Affects all VFN and PFN nodes accepting public connections

The attack requires minimal resources and expertise, making it accessible to even unsophisticated attackers.

## Recommendation

Implement request-level authentication in the peer monitoring service to verify peer identity before disclosing sensitive information. The service should check the peer's role and only respond to authenticated, trusted peers.

**Option 1: Add role-based access control**

Modify the `Handler::call()` method to check peer authentication status:

```rust
pub fn call(
    &self,
    network_id: NetworkId,
    peer_network_id: PeerNetworkId,
    request: PeerMonitoringServiceRequest,
) -> Result<PeerMonitoringServiceResponse> {
    // Verify peer is authenticated for sensitive requests
    if matches!(request, 
        PeerMonitoringServiceRequest::GetNetworkInformation | 
        PeerMonitoringServiceRequest::GetNodeInformation
    ) {
        // Check if peer is in trusted peers set
        let trusted_peers = self.peers_and_metadata
            .get_trusted_peers(&network_id)?;
        
        if !trusted_peers.contains_key(&peer_network_id.peer_id()) {
            return Err(PeerMonitoringServiceError::PermissionDenied(
                "Only authenticated peers can access this information".to_string()
            ));
        }
    }
    
    // Continue with existing request processing...
}
```

**Option 2: Add authentication token to request structure**

Add a signature field to `PeerMonitoringServiceRequest` that proves the requester controls their private key and include a timestamp to prevent replay attacks.

**Option 3: Enable mutual authentication on all networks**

Configure VFN and Public networks to use mutual authentication, rejecting connections from peers not in the trusted set. However, this may break legitimate use cases where unknown peers need to connect.

## Proof of Concept

```rust
// peer-monitoring-service/server/src/tests.rs
#[tokio::test]
async fn test_unauthenticated_information_disclosure() {
    use aptos_config::network_id::{NetworkId, PeerNetworkId};
    use aptos_peer_monitoring_service_types::request::PeerMonitoringServiceRequest;
    use aptos_types::PeerId;
    
    // Create a peer monitoring server with default config (MaybeMutual auth)
    let (server, mut network_requests) = create_test_server();
    
    // Simulate an UNKNOWN peer (not in trusted peers set) connecting
    let unknown_peer_id = PeerId::random();
    let peer_network_id = PeerNetworkId::new(NetworkId::Public, unknown_peer_id);
    
    // Send GetNetworkInformation request from unknown peer
    let request = PeerMonitoringServiceRequest::GetNetworkInformation;
    let (response_tx, response_rx) = oneshot::channel();
    
    network_requests.send(NetworkRequest {
        peer_network_id,
        protocol_id: ProtocolId::PeerMonitoringServiceRpc,
        peer_monitoring_service_request: request.clone(),
        response_sender: ResponseSender::new(response_tx),
    }).await.unwrap();
    
    // Receive response - should succeed even though peer is unauthenticated
    let response = response_rx.await.unwrap().unwrap();
    
    match response {
        PeerMonitoringServiceResponse::NetworkInformation(info) => {
            // Unknown peer successfully retrieved sensitive network topology!
            assert!(!info.connected_peers.is_empty());
            println!("Disclosed connected peers: {:?}", info.connected_peers);
            println!("Disclosed validator distance: {}", info.distance_from_validators);
        },
        _ => panic!("Unexpected response type"),
    }
    
    // Send GetNodeInformation request from unknown peer
    let request = PeerMonitoringServiceRequest::GetNodeInformation;
    let (response_tx, response_rx) = oneshot::channel();
    
    network_requests.send(NetworkRequest {
        peer_network_id,
        protocol_id: ProtocolId::PeerMonitoringServiceRpc,
        peer_monitoring_service_request: request.clone(),
        response_sender: ResponseSender::new(response_tx),
    }).await.unwrap();
    
    let response = response_rx.await.unwrap().unwrap();
    
    match response {
        PeerMonitoringServiceResponse::NodeInformation(info) => {
            // Unknown peer successfully retrieved sensitive node state!
            println!("Disclosed build info: {:?}", info.build_information);
            println!("Disclosed sync state: epoch={}, version={}", 
                info.highest_synced_epoch, info.highest_synced_version);
            println!("Disclosed storage range: {} to {}", 
                info.lowest_available_version, info.highest_synced_version);
        },
        _ => panic!("Unexpected response type"),
    }
}
```

## Notes

This vulnerability affects only VFN and Public networks where `mutual_authentication` is disabled. Validator networks are protected by mutual authentication requirements enforced by the config sanitizer. The issue demonstrates a failure to implement defense-in-depth: while the network layer provides peer authentication, the application layer (peer monitoring service) does not verify peer identity before disclosing sensitive operational data.

### Citations

**File:** peer-monitoring-service/types/src/request.rs (L6-13)
```rust
/// A peer monitoring service request
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum PeerMonitoringServiceRequest {
    GetNetworkInformation,    // Returns relevant network information for the peer
    GetNodeInformation,       // Returns relevant node information about the peer
    GetServerProtocolVersion, // Fetches the protocol version run by the server
    LatencyPing(LatencyPingRequest), // A simple message used by the client to ensure liveness and measure latency
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

**File:** config/src/config/network_config.rs (L135-142)
```rust
    pub fn network_with_id(network_id: NetworkId) -> NetworkConfig {
        let mutual_authentication = network_id.is_validator_network();
        let mut config = Self {
            discovery_method: DiscoveryMethod::None,
            discovery_methods: Vec::new(),
            identity: Identity::None,
            listen_address: "/ip4/0.0.0.0/tcp/6180".parse().unwrap(),
            mutual_authentication,
```

**File:** config/src/config/network_config.rs (L158-159)
```rust
            inbound_rate_limit_config: None,
            outbound_rate_limit_config: None,
```

**File:** network/framework/src/noise/handshake.rs (L384-426)
```rust
            HandshakeAuthMode::MaybeMutual(peers_and_metadata) => {
                let trusted_peers = peers_and_metadata.get_trusted_peers(&network_id)?;
                let trusted_peer = trusted_peers.get(&remote_peer_id).cloned();
                match trusted_peer {
                    Some(peer) => {
                        Self::authenticate_inbound(remote_peer_short, &peer, &remote_public_key)
                    },
                    None => {
                        // The peer is not in the trusted peer set. Verify that the Peer ID is
                        // constructed correctly from the public key.
                        let derived_remote_peer_id =
                            aptos_types::account_address::from_identity_public_key(
                                remote_public_key,
                            );
                        if derived_remote_peer_id != remote_peer_id {
                            // The peer ID is not constructed correctly from the public key
                            Err(NoiseHandshakeError::ClientPeerIdMismatch(
                                remote_peer_short,
                                remote_peer_id,
                                derived_remote_peer_id,
                            ))
                        } else {
                            // Try to infer the role from the network context
                            if self.network_context.role().is_validator() {
                                if network_id.is_vfn_network() {
                                    // Inbound connections to validators on the VFN network must be VFNs
                                    Ok(PeerRole::ValidatorFullNode)
                                } else {
                                    // Otherwise, they're unknown. Validators will connect through
                                    // authenticated channels (on the validator network) so shouldn't hit
                                    // this, and PFNs will connect on public networks (which aren't common).
                                    Ok(PeerRole::Unknown)
                                }
                            } else {
                                // We're a VFN or PFN. VFNs get no inbound connections on the vfn network
                                // (so the peer won't be a validator). Thus, we're on the public network
                                // so mark the peer as unknown.
                                Ok(PeerRole::Unknown)
                            }
                        }
                    },
                }
            },
```

**File:** peer-monitoring-service/types/src/response.rs (L50-55)
```rust
/// A response for the network information request
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NetworkInformationResponse {
    pub connected_peers: BTreeMap<PeerNetworkId, ConnectionMetadata>, // Connected peers
    pub distance_from_validators: u64, // The distance of the peer from the validator set
}
```

**File:** peer-monitoring-service/types/src/response.rs (L69-75)
```rust
/// Simple connection metadata associated with each peer
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConnectionMetadata {
    pub network_address: NetworkAddress,
    pub peer_id: PeerId,
    pub peer_role: PeerRole,
}
```

**File:** peer-monitoring-service/types/src/response.rs (L93-102)
```rust
/// A response for the node information request
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeInformationResponse {
    pub build_information: BTreeMap<String, String>, // The build information of the node
    pub highest_synced_epoch: u64,                   // The highest synced epoch of the node
    pub highest_synced_version: u64,                 // The highest synced version of the node
    pub ledger_timestamp_usecs: u64, // The latest timestamp of the blockchain (in microseconds)
    pub lowest_available_version: u64, // The lowest stored version of the node (in storage)
    pub uptime: Duration,            // The amount of time the peer has been running
}
```

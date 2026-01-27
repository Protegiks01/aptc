# Audit Report

## Title
Cross-Network Information Disclosure in Peer Monitoring Service Leaks Validator Topology

## Summary
The peer monitoring service's `GetNetworkInformation` handler returns information about ALL connected peers across ALL networks (Validator, VFN, Public) without filtering based on the requesting peer's network. This allows peers on less privileged networks (VFN or Public) to probe and learn the topology of the private Validator network, violating network isolation boundaries.

## Finding Description

Aptos nodes operate multiple isolated networks simultaneously:
- **Validator network** (`NetworkId::Validator`): Private network where validators communicate for consensus
- **VFN network** (`NetworkId::Vfn`): Semi-private network connecting validators to their Validator Full Nodes
- **Public network** (`NetworkId::Public`): Public network for general peer connectivity

The peer monitoring service is registered on all networks a node participates in and uses a single shared `PeersAndMetadata` instance to track peers across all networks. [1](#0-0) 

When a peer sends a `GetNetworkInformation` request, the server's handler calls `get_connected_peers_and_metadata()` which returns ALL connected peers across ALL networks without any filtering: [2](#0-1) 

The `get_connected_peers_and_metadata()` implementation iterates through all networks and returns all connected peers: [3](#0-2) 

The response includes `BTreeMap<PeerNetworkId, ConnectionMetadata>` where `PeerNetworkId` contains both the `NetworkId` and `PeerId`, explicitly revealing which network each peer is on: [4](#0-3) [5](#0-4) 

The `ConnectionMetadata` also exposes the peer's role and network address: [6](#0-5) 

Although the server's `call()` method receives the requesting peer's `network_id`, it only uses it for metrics and does NOT pass it to the response handlers for filtering: [7](#0-6) 

**Attack Scenario:**
1. A Validator node runs both the Validator network and VFN network
2. A malicious VFN (or compromised node on the VFN network) sends a `GetNetworkInformation` request to the validator
3. The validator responds with ALL connected peers, including:
   - Other validators connected on the Validator network (exposed via `PeerNetworkId` with `NetworkId::Validator`)
   - Their `PeerRole::Validator` designation
   - Their network addresses
4. The attacker now knows the validator network topology, which they should not have access to

The `send_request_to_peer()` function in the client does not perform any validation either: [8](#0-7) 

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty program criteria. While it doesn't directly cause funds loss or consensus violations, it represents a significant information disclosure that:

1. **Breaks Network Isolation**: The Validator network is designed to be private and isolated from VFN and Public networks. This leak violates that security boundary.

2. **Enables Reconnaissance**: Attackers can map the entire validator network topology, including:
   - Number of validators and their peer IDs
   - Network addresses of validators
   - Connection patterns between validators

3. **Facilitates Advanced Attacks**: Knowledge of validator topology can enable:
   - Targeted network-layer attacks against specific validators
   - Eclipse attacks by identifying and isolating validators
   - More effective DDoS strategies
   - Social engineering attacks with knowledge of validator infrastructure

4. **Violates Security Design**: The existence of separate `NetworkId` types (Validator, VFN, Public) indicates intentional network segregation. This leak undermines that design.

This is more than a "minor information leak" (Low severity) because it exposes critical infrastructure topology that is explicitly designed to be private.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited because:

1. **No Special Privileges Required**: Any peer that can connect to a validator's VFN network can exploit this. VFNs are often operated by third parties.

2. **Trivial to Exploit**: The attack requires only sending a standard `GetNetworkInformation` request - no complex manipulation or timing attacks needed.

3. **High Value Target**: Validator network topology is valuable intelligence for sophisticated attackers planning network-layer attacks.

4. **Current Deployment**: This code is in production across all Aptos validators that run VFN networks.

5. **Passive Attack**: The reconnaissance can be performed passively without triggering obvious alarms.

## Recommendation

Modify the `get_network_information()` handler to filter the response based on the requesting peer's network. Only return peers from the same network as the requester.

**Recommended Fix:**

```rust
fn get_network_information(&self, requesting_network_id: NetworkId) -> Result<PeerMonitoringServiceResponse, Error> {
    // Get the connected peers
    let connected_peers_and_metadata =
        self.peers_and_metadata.get_connected_peers_and_metadata()?;
    
    // Filter to only include peers from the same network as the requester
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

Update the `call()` method to pass the `network_id` parameter:

```rust
let response = match &request {
    PeerMonitoringServiceRequest::GetNetworkInformation => self.get_network_information(network_id),
    // ... other cases
};
```

## Proof of Concept

**Setup:**
1. Run a validator node with both Validator and VFN networks configured
2. Connect a VFN to the validator's VFN network
3. Ensure the validator is connected to other validators on the Validator network

**Exploitation Steps:**

```rust
// On the VFN node, send a GetNetworkInformation request
let peer_monitoring_client = PeerMonitoringServiceClient::new(network_client);
let validator_peer_network_id = PeerNetworkId::new(NetworkId::Vfn, validator_peer_id);

let response = send_request_to_peer(
    peer_monitoring_client,
    &validator_peer_network_id,
    1, // request_id
    PeerMonitoringServiceRequest::GetNetworkInformation,
    5000, // timeout_ms
).await.unwrap();

// Extract the response
if let PeerMonitoringServiceResponse::NetworkInformation(network_info) = response {
    // The response will contain peers from ALL networks
    for (peer_network_id, connection_metadata) in network_info.connected_peers {
        println!("Network: {:?}", peer_network_id.network_id());
        println!("Peer ID: {:?}", peer_network_id.peer_id());
        println!("Role: {:?}", connection_metadata.peer_role);
        println!("Address: {:?}", connection_metadata.network_address);
        
        // Check if we can see Validator network peers (we shouldn't!)
        if peer_network_id.network_id() == NetworkId::Validator {
            println!("VULNERABILITY CONFIRMED: Can see Validator network peer!");
        }
    }
}
```

**Expected (Vulnerable) Behavior:**
- The response includes peers with `NetworkId::Validator` in their `PeerNetworkId`
- VFN can see the entire validator network topology

**Expected (Secure) Behavior:**
- The response only includes peers with `NetworkId::Vfn` (matching the requester's network)
- Validator network topology remains hidden

### Citations

**File:** aptos-node/src/network.rs (L240-241)
```rust
    let network_ids = extract_network_ids(node_config);
    PeersAndMetadata::new(&network_ids)
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

**File:** peer-monitoring-service/types/src/response.rs (L50-55)
```rust
/// A response for the network information request
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NetworkInformationResponse {
    pub connected_peers: BTreeMap<PeerNetworkId, ConnectionMetadata>, // Connected peers
    pub distance_from_validators: u64, // The distance of the peer from the validator set
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

**File:** config/src/network_id.rs (L235-248)
```rust
#[derive(Clone, Copy, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
/// Identifier of a node, represented as (network_id, peer_id)
pub struct PeerNetworkId {
    network_id: NetworkId,
    peer_id: PeerId,
}

impl PeerNetworkId {
    pub fn new(network_id: NetworkId, peer_id: PeerId) -> Self {
        Self {
            network_id,
            peer_id,
        }
    }
```

**File:** peer-monitoring-service/client/src/network.rs (L68-133)
```rust
/// Sends a request to a specific peer
pub async fn send_request_to_peer(
    peer_monitoring_client: PeerMonitoringServiceClient<
        NetworkClient<PeerMonitoringServiceMessage>,
    >,
    peer_network_id: &PeerNetworkId,
    request_id: u64,
    request: PeerMonitoringServiceRequest,
    request_timeout_ms: u64,
) -> Result<PeerMonitoringServiceResponse, Error> {
    trace!(
        (LogSchema::new(LogEntry::SendRequest)
            .event(LogEvent::SendRequest)
            .request_type(request.get_label())
            .request_id(request_id)
            .peer(peer_network_id)
            .request(&request))
    );
    metrics::increment_request_counter(
        &metrics::SENT_REQUESTS,
        request.get_label(),
        peer_network_id,
    );

    // Send the request and process the result
    let result = peer_monitoring_client
        .send_request(
            *peer_network_id,
            request.clone(),
            Duration::from_millis(request_timeout_ms),
        )
        .await;
    match result {
        Ok(response) => {
            trace!(
                (LogSchema::new(LogEntry::SendRequest)
                    .event(LogEvent::ResponseSuccess)
                    .request_type(request.get_label())
                    .request_id(request_id)
                    .peer(peer_network_id))
            );
            metrics::increment_request_counter(
                &metrics::SUCCESS_RESPONSES,
                request.clone().get_label(),
                peer_network_id,
            );
            Ok(response)
        },
        Err(error) => {
            warn!(
                (LogSchema::new(LogEntry::SendRequest)
                    .event(LogEvent::ResponseError)
                    .request_type(request.get_label())
                    .request_id(request_id)
                    .peer(peer_network_id)
                    .error(&error))
            );
            metrics::increment_request_counter(
                &metrics::ERROR_RESPONSES,
                error.get_label(),
                peer_network_id,
            );
            Err(error)
        },
    }
}
```

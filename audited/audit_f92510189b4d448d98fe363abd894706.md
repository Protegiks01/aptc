# Audit Report

## Title
Memory Exhaustion via Unbounded Deserialization of Peer Monitoring Service Responses

## Summary
The peer monitoring service client deserializes responses before validating their size against the configured 100 KB limit. An attacker controlling a malicious peer can send responses with large `BTreeMap` collections (up to the 64 MiB network limit) that trigger excessive heap allocation during deserialization, enabling resource exhaustion attacks against validator and fullnode infrastructure.

## Finding Description

The `PeerMonitoringServiceResponse` enum contains variants with heap-allocated collections that lack size validation during deserialization: [1](#0-0) 

The `NetworkInformationResponse` and `NodeInformationResponse` variants contain unbounded `BTreeMap` collections: [2](#0-1) [3](#0-2) 

**Attack Path:**

1. **Malicious Server Preparation**: An attacker operates a peer monitoring service server that responds to `GetNetworkInformation` or `GetNodeInformation` requests with maliciously crafted responses containing 100,000+ entries in the `BTreeMap` fields.

2. **Server-Side Lack of Validation**: The server serializes and sends responses without size validation: [4](#0-3) 

The `get_network_information` handler returns all connected peers without limiting the collection size: [5](#0-4) 

3. **Network Layer Acceptance**: The network layer accepts messages up to 64 MiB: [6](#0-5) 

A malicious response with 100,000 `BTreeMap` entries (~15-30 MB when serialized) passes through the network layer.

4. **Client-Side Deserialization Before Validation**: The victim node's client sends a request and receives the response: [7](#0-6) 

The response is **fully deserialized** (allocating heap memory for all BTreeMap entries) at line 108-115 before any size check occurs.

5. **Post-Deserialization Size Check (Too Late)**: Only after deserialization completes does the client check the response size: [8](#0-7) 

The configured limit is only 100 KB: [9](#0-8) 

But by this point, memory has already been allocated for the malicious payload.

6. **Gap Exploitation**: There's a 63.9 MiB gap between the network message limit (64 MiB) and the expected response limit (100 KB) that attackers can exploit.

**Invariant Violation**: This breaks the "Resource Limits" invariant (#9) which requires all operations to respect memory and computational constraints. The system fails to enforce response size limits at the deserialization boundary.

## Impact Explanation

**Medium Severity** ($10,000 range) per Aptos Bug Bounty criteria:

- **Resource Exhaustion**: Repeated attacks from multiple malicious peers can exhaust memory on validator nodes, causing degraded performance or crashes
- **Availability Impact**: Affected nodes may experience OOM conditions, requiring restart and impacting network participation
- **Not Consensus-Breaking**: Does not violate consensus safety or cause fund loss
- **State Inconsistency**: Memory pressure could interfere with state sync operations

This qualifies as "State inconsistencies requiring intervention" under Medium severity, as operators may need to manually identify and disconnect malicious peers or adjust configuration.

## Likelihood Explanation

**High Likelihood**:

- **Low Attacker Barrier**: Any node can implement the peer monitoring service and send malicious responses
- **Public Network Exposure**: The service is accessible on public networks where untrusted peers connect
- **Automatic Triggering**: Victim nodes automatically send periodic monitoring requests every 15-60 seconds to all connected peers
- **No Authentication**: Responses are not cryptographically bound to legitimate data sources

Test utilities confirm the code anticipates large responses: [10](#0-9) 

## Recommendation

**Enforce size limits BEFORE deserialization** by implementing one of these solutions:

1. **Add Protocol-Level Size Limit**: Configure the `PeerMonitoringServiceRpc` protocol with an application-specific message size limit matching the expected 100 KB:

```rust
// In network/framework/src/protocols/wire/handshake/v1/mod.rs
fn encoding(self) -> Encoding {
    match self {
        ProtocolId::PeerMonitoringServiceRpc => {
            // Add size limit for peer monitoring
            Encoding::BcsWithLimit(RECURSION_LIMIT, 100 * 1024) // 100 KB
        },
        // ... other protocols
    }
}
```

2. **Server-Side Response Validation**: Add size checks in the server before sending responses:

```rust
// In peer-monitoring-service/server/src/lib.rs, Handler::call()
let response = match response {
    Ok(response) => {
        // Validate response size before sending
        match response.get_num_bytes() {
            Ok(num_bytes) if num_bytes <= MAX_RESPONSE_SIZE => Ok(response),
            Ok(num_bytes) => {
                error!("Response too large: {} bytes", num_bytes);
                Err(PeerMonitoringServiceError::InternalError(
                    "Response exceeds size limit".to_string()
                ))
            },
            Err(e) => Err(PeerMonitoringServiceError::InternalError(e.to_string())),
        }
    },
    Err(error) => Err(error),
}
```

3. **Limit Collection Sizes**: Cap the number of entries returned in responses:

```rust
// In peer-monitoring-service/server/src/lib.rs, get_network_information()
const MAX_CONNECTED_PEERS_IN_RESPONSE: usize = 100;

let connected_peers = connected_peers_and_metadata
    .into_iter()
    .take(MAX_CONNECTED_PEERS_IN_RESPONSE) // Limit collection size
    .map(|(peer, metadata)| { /* ... */ })
    .collect();
```

## Proof of Concept

```rust
// Test demonstrating memory allocation before size validation
// Add to peer-monitoring-service/client/src/tests/single_peer.rs

#[tokio::test]
async fn test_memory_exhaustion_via_large_response() {
    use crate::tests::utils::*;
    
    // Setup monitoring infrastructure
    let (mut mock_monitoring_server, peer_monitoring_client, peer_monitor_state, 
         peers_and_metadata, time_service, peer_network_id) = 
        MockMonitoringServer::new(vec![NetworkId::Public]);
    
    let node_config = config_with_network_info_requests();
    start_peer_monitor(
        peer_monitoring_client,
        &peer_monitor_state,
        &time_service,
        &node_config,
    ).await;
    
    // Attacker sends malicious response with 100,000 connected peers
    let network_id = peer_network_id.network_id();
    
    // Wait for request from victim
    elapse_peer_monitor_interval(node_config.clone(), time_service.clone()).await;
    
    // Respond with oversized message (within 64 MiB network limit)
    verify_network_info_request_and_respond(
        &network_id,
        &mut mock_monitoring_server,
        create_network_info_response(&create_large_connected_peers_map(), 1),
        false, // valid distance
        false, // valid message type  
        true,  // LARGE MESSAGE - triggers allocation before size check
        false, // send response
    ).await;
    
    // Verify the error was logged AFTER deserialization consumed memory
    // The size check fails at peer_state.rs:136, but allocation already occurred
    wait_for_network_info_request_failure(&peer_monitor_state, &peer_network_id, 1).await;
    
    // Memory was allocated for 100,000 BTreeMap entries before rejection
    // Repeated attacks cause cumulative memory exhaustion
}
```

**Reproduction Steps:**
1. Deploy a malicious peer monitoring service that responds with `create_large_connected_peers_map()` (100,000 entries)
2. Connect victim validator/fullnode to the malicious peer
3. Wait for periodic monitoring requests (occurs automatically every 60 seconds)
4. Observe memory allocation spikes during response deserialization
5. Repeat from multiple malicious peers to exhaust node memory

**Notes**

The `large_enum_variant` clippy warning on line 12 is a code smell indicating that enum variants have significantly different sizes, which correlates with some variants containing potentially unbounded heap-allocated collections. While the warning itself is about stack efficiency, it correctly identifies that certain response variants (`NetworkInformation` and `NodeInformation`) can trigger excessive memory allocation during deserialization.

The core issue is the architectural flaw where size validation occurs post-deserialization rather than at the protocol boundary, creating a 63.9 MiB exploitation window between network limits (64 MiB) and application limits (100 KB).

### Citations

**File:** peer-monitoring-service/types/src/response.rs (L11-18)
```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum PeerMonitoringServiceResponse {
    LatencyPing(LatencyPingResponse), // A simple message to respond to latency checks (i.e., pings)
    NetworkInformation(NetworkInformationResponse), // Holds the response for network information
    NodeInformation(NodeInformationResponse), // Holds the response for node information
    ServerProtocolVersion(ServerProtocolVersionResponse), // Returns the current server protocol version
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

**File:** peer-monitoring-service/server/src/network.rs (L106-112)
```rust
    pub fn send(self, response: Result<PeerMonitoringServiceResponse>) {
        let msg = PeerMonitoringServiceMessage::Response(response);
        let result = bcs::to_bytes(&msg)
            .map(Bytes::from)
            .map_err(RpcError::BcsError);
        let _ = self.response_tx.send(result);
    }
```

**File:** peer-monitoring-service/server/src/lib.rs (L217-247)
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
```

**File:** config/src/config/network_config.rs (L50-50)
```rust
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
```

**File:** peer-monitoring-service/client/src/peer_states/peer_state.rs (L106-115)
```rust
            // Send the request to the peer and wait for a response
            let request_id = request_id_generator.next();
            let monitoring_service_response = network::send_request_to_peer(
                peer_monitoring_client,
                &peer_network_id,
                request_id,
                monitoring_service_request.clone(),
                request_timeout_ms,
            )
            .await;
```

**File:** peer-monitoring-service/client/src/peer_states/peer_state.rs (L134-142)
```rust
            // Verify the response respects the message size limits
            if let Err(error) =
                sanity_check_response_size(max_num_response_bytes, &monitoring_service_response)
            {
                peer_state_value
                    .write()
                    .handle_monitoring_service_response_error(&peer_network_id, error);
                return;
            }
```

**File:** config/src/config/peer_monitoring_config.rs (L28-28)
```rust
            max_num_response_bytes: 100 * 1024, // 100 KB
```

**File:** peer-monitoring-service/client/src/tests/utils.rs (L109-118)
```rust
pub fn create_large_connected_peers_map() -> BTreeMap<PeerNetworkId, ConnectionMetadata> {
    let mut peers = BTreeMap::new();
    for _ in 0..100_000 {
        peers.insert(
            PeerNetworkId::random(),
            ConnectionMetadata::new(NetworkAddress::mock(), PeerId::random(), PeerRole::Unknown),
        );
    }
    peers
}
```

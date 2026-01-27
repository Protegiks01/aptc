# Audit Report

## Title
Missing Peer Identity Logging in Peer Monitoring Service Enables Unaudited Reconnaissance

## Summary
The peer monitoring service server's `LogSchema` lacks a structured field for logging the requesting peer's identity (`peer_id` or `peer_network_id`), allowing malicious actors to gather network topology, node version information, and synchronization state without leaving a proper audit trail. This deviates from security best practices used in similar Aptos services.

## Finding Description

The `LogSchema` struct in the peer monitoring service server does not include a dedicated field for peer identity: [1](#0-0) 

In contrast, comparable services properly include structured peer identity fields in their logging schemas:

**Storage Service Server** includes `peer_network_id` field: [2](#0-1) 

**Consensus Observer** includes `peer` field: [3](#0-2) 

**Peer Monitoring Service Client** includes `peer` field: [4](#0-3) 

The peer monitoring server only logs peer identity in an unstructured message field at TRACE level: [5](#0-4) 

Error logging omits peer identity entirely: [6](#0-5) 

The default production log level is INFO, which excludes TRACE logs: [7](#0-6) 

**Attack Scenario:**
1. Attacker connects to target node via standard P2P networking
2. Sends `GetNetworkInformation` requests to map network topology and discover connected validators
3. Sends `GetNodeInformation` requests to identify node versions, sync state, and uptime
4. With default INFO logging, only request types are logged—not the requesting peer
5. If errors occur during reconnaissance, no peer identity is logged at all
6. Attacker repeats reconnaissance across multiple nodes without leaving proper audit trails

The exposed information includes:
- Network topology via `NetworkInformationResponse.connected_peers` 
- Node build information, sync status, and uptime via `NodeInformationResponse` [8](#0-7) 

## Impact Explanation

This vulnerability falls under **Low Severity** per Aptos bug bounty criteria: "Minor information leaks" (up to $1,000). While the security question suggests Medium severity, the actual impact aligns with Low severity because:

1. It does not cause direct funds loss or manipulation
2. It does not create state inconsistencies requiring intervention  
3. It is an information disclosure issue that enables reconnaissance but doesn't directly compromise consensus, execution, or storage integrity

The vulnerability enables network mapping and version fingerprinting, which could facilitate more sophisticated attacks, but the information leak itself is minor relative to the bounty program's Medium severity requirements.

## Likelihood Explanation

**High likelihood**: Any peer that connects to the network can send peer monitoring requests without authentication or rate limiting (beyond the default `max_concurrent_requests` of 1000). The attack requires no special privileges and exploits legitimate service functionality.

## Recommendation

Add a structured `peer_network_id` field to the server's `LogSchema` and populate it in all logging calls:

```rust
#[derive(Schema)]
pub struct LogSchema<'a> {
    name: LogEntry,
    error: Option<&'a Error>,
    message: Option<&'a str>,
    peer_network_id: Option<&'a PeerNetworkId>,  // Add this field
    response: Option<&'a str>,
    request: Option<&'a PeerMonitoringServiceRequest>,
}
```

Update request logging to include peer identity at INFO level:
```rust
info!(LogSchema::new(LogEntry::ReceivedPeerMonitoringRequest)
    .peer_network_id(&peer_network_id)  // Add structured field
    .request(&peer_monitoring_service_request));
```

Update error logging to include peer identity:
```rust
error!(LogSchema::new(LogEntry::PeerMonitoringServiceError)
    .error(&error)
    .peer_network_id(&peer_network_id)  // Add this
    .request(&request));
```

Consider implementing per-peer rate limiting to prevent excessive reconnaissance attempts.

## Proof of Concept

**Reconnaissance Script** (conceptual Rust code):
```rust
// Connect to target node as legitimate peer
let peer_monitoring_client = PeerMonitoringServiceClient::new(network_config);

// Query network topology without leaving audit trail
let network_info = peer_monitoring_client
    .get_network_information(target_peer)
    .await?;

println!("Discovered {} connected peers:", network_info.connected_peers.len());
for (peer_id, metadata) in network_info.connected_peers {
    println!("  - Peer: {}, Role: {:?}", peer_id, metadata.peer_role);
}

// Query node information
let node_info = peer_monitoring_client
    .get_node_information(target_peer)
    .await?;

println!("Target version: {:?}", node_info.build_information);
println!("Sync state: epoch {}, version {}", 
    node_info.highest_synced_epoch,
    node_info.highest_synced_version);

// With default logging, only TRACE messages (disabled) contain peer_id
// Error logs contain no peer identity at all
```

## Notes

This issue represents a deviation from security best practices consistently followed by other Aptos network services (storage service, consensus observer). While the peer identity information is technically available in the code, it's not properly logged in a structured, queryable format at appropriate log levels for security auditing and incident response.

The peer monitoring service lacks authentication mechanisms and relies solely on P2P network access controls, making proper audit logging particularly important for detecting and investigating malicious reconnaissance activities.

### Citations

**File:** peer-monitoring-service/server/src/logging.rs (L9-16)
```rust
#[derive(Schema)]
pub struct LogSchema<'a> {
    name: LogEntry,
    error: Option<&'a Error>,
    message: Option<&'a str>,
    response: Option<&'a str>,
    request: Option<&'a PeerMonitoringServiceRequest>,
}
```

**File:** state-sync/storage-service/server/src/logging.rs (L10-19)
```rust
#[derive(Schema)]
pub struct LogSchema<'a> {
    name: LogEntry,
    error: Option<&'a Error>,
    message: Option<&'a str>,
    optimistic_fetch_related: Option<bool>,
    peer_network_id: Option<&'a PeerNetworkId>,
    response: Option<&'a str>,
    request: Option<&'a StorageServiceRequest>,
}
```

**File:** consensus/src/consensus_observer/common/logging.rs (L9-21)
```rust
#[derive(Schema)]
pub struct LogSchema<'a> {
    name: LogEntry,
    #[schema(debug)]
    error: Option<&'a Error>,
    event: Option<LogEvent>,
    message: Option<&'a str>,
    message_type: Option<&'a str>,
    #[schema(display)]
    peer: Option<&'a PeerNetworkId>,
    request_id: Option<u64>,
    request_type: Option<&'a str>,
}
```

**File:** peer-monitoring-service/client/src/logging.rs (L10-23)
```rust
#[derive(Schema)]
pub struct LogSchema<'a> {
    name: LogEntry,
    #[schema(debug)]
    error: Option<&'a Error>,
    event: Option<LogEvent>,
    message: Option<&'a str>,
    #[schema(display)]
    peer: Option<&'a PeerNetworkId>,
    #[schema(debug)]
    request: Option<&'a PeerMonitoringServiceRequest>,
    request_id: Option<u64>,
    request_type: Option<&'a str>,
}
```

**File:** peer-monitoring-service/server/src/lib.rs (L91-96)
```rust
            trace!(LogSchema::new(LogEntry::ReceivedPeerMonitoringRequest)
                .request(&peer_monitoring_service_request)
                .message(&format!(
                    "Received peer monitoring request. Peer: {:?}",
                    peer_network_id,
                )));
```

**File:** peer-monitoring-service/server/src/lib.rs (L193-195)
```rust
                error!(LogSchema::new(LogEntry::PeerMonitoringServiceError)
                    .error(&error)
                    .request(&request));
```

**File:** config/src/config/logger_config.rs (L46-46)
```rust
            level: Level::Info,
```

**File:** peer-monitoring-service/types/src/response.rs (L50-102)
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

/// A response for the server protocol version request
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServerProtocolVersionResponse {
    pub version: u64, // The version of the peer monitoring service run by the server
}

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

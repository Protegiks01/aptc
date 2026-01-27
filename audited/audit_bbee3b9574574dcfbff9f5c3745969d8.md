# Audit Report

## Title
Authorization Bypass in Peer Monitoring Service Allows Unauthorized Network Reconnaissance

## Summary
The peer monitoring service does not perform authorization checks when processing requests from connected peers. On non-validator networks (VFN and Public) that use `AuthenticationMode::MaybeMutual`, any peer can connect and query sensitive network topology information without restriction.

## Finding Description

The `send_request_to_peer()` function in the client and the `Handler::call()` method in the server both lack authorization checks. [1](#0-0) 

The server's `Handler::call()` method processes all requests without verifying the requesting peer's role or trust status: [2](#0-1) 

On VFN and Public networks, the default authentication mode is `MaybeMutual`, which allows connections from untrusted peers with `PeerRole::Unknown`: [3](#0-2)  and [4](#0-3) 

The `MaybeMutual` authentication mode accepts connections from peers not in the trusted set, assigning them `PeerRole::Unknown`: [5](#0-4) 

The peer monitoring service is registered on **all** network types without restrictions: [6](#0-5) 

Exposed information includes connected peers (IDs, addresses, roles) and distance from validators: [7](#0-6) 

And node operational data including sync status and build information: [8](#0-7) 

## Impact Explanation

**Assessment: Low Severity** (Minor information leak)

While this allows unauthorized network reconnaissance, the impact is limited because:
1. **Validator networks are protected**: The Validator network uses `AuthenticationMode::Mutual` with mandatory mutual authentication, preventing unauthorized access to actual validator internals
2. **Information exposure is operational**: The exposed data (network topology, sync status) is operational/diagnostic rather than cryptographic secrets
3. **No direct security harm**: This does not enable fund theft, consensus violations, or network availability attacks
4. **Design ambiguity**: The peer monitoring service may be intentionally public for network health monitoring purposes

Per Aptos bug bounty criteria, this qualifies as **Low Severity**: "Minor information leaks" rather than Medium severity which requires "State inconsistencies requiring intervention."

## Likelihood Explanation

**Likelihood: High** - Easy to exploit with standard network tools. Any attacker with network connectivity to VFN or Public full nodes can connect and send RPC requests without restriction.

However, the practical impact is limited since validator-specific information remains protected by the Validator network's mutual authentication requirement.

## Recommendation

**Option 1: Add role-based access control** to the server handler to restrict sensitive endpoints based on peer role. Add configuration to specify which peer roles can access each endpoint.

**Option 2: Document the public nature** of the peer monitoring service if this is intentional design, and ensure no sensitive validator-specific information is exposed through VFN/Public network instances.

**Option 3: Implement request filtering** at the network event layer to reject requests from `PeerRole::Unknown` peers before they reach the handler.

## Proof of Concept

```rust
// Connect to a public full node's peer monitoring service
// Send GetNetworkInformation request without being in trusted peer set
// Receive response with connected peers and network topology
// No authorization check prevents this reconnaissance

// This can be demonstrated by:
// 1. Setting up a test node with Public network
// 2. Connecting as untrusted peer (MaybeMutual allows this)
// 3. Sending PeerMonitoringServiceRequest::GetNetworkInformation
// 4. Observing successful response without authorization check
```

## Notes

**Critical Clarification**: Upon deeper analysis, this issue does **not** expose "validator internals" as the security question suggests, because:
- Validators use the Validator network with mutual authentication
- VFN and Public networks only expose their own network's topology, not validator connections
- The separation of network contexts prevents cross-network information leakage

The vulnerability is limited to **reconnaissance of non-validator network topology**, which while undesirable, does not directly compromise validator security or consensus operations. The severity assessment reflects this limited scope.

### Citations

**File:** peer-monitoring-service/client/src/network.rs (L69-133)
```rust
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

**File:** peer-monitoring-service/server/src/lib.rs (L155-215)
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

        // Process the response and handle any errors
        match response {
            Err(error) => {
                // Log the error and update the counters
                increment_counter(
                    &metrics::PEER_MONITORING_ERRORS_ENCOUNTERED,
                    network_id,
                    error.get_label(),
                );
                error!(LogSchema::new(LogEntry::PeerMonitoringServiceError)
                    .error(&error)
                    .request(&request));

                // Return an appropriate response to the client
                match error {
                    Error::InvalidRequest(error) => {
                        Err(PeerMonitoringServiceError::InvalidRequest(error))
                    },
                    error => Err(PeerMonitoringServiceError::InternalError(error.to_string())),
                }
            },
            Ok(response) => {
                // The request was successful
                increment_counter(
                    &metrics::PEER_MONITORING_RESPONSES_SENT,
                    network_id,
                    response.get_label(),
                );
                Ok(response)
            },
        }
    }
```

**File:** config/src/network_id.rs (L168-170)
```rust
    pub fn is_validator_network(&self) -> bool {
        self == &NetworkId::Validator
    }
```

**File:** config/src/config/network_config.rs (L136-142)
```rust
        let mutual_authentication = network_id.is_validator_network();
        let mut config = Self {
            discovery_method: DiscoveryMethod::None,
            discovery_methods: Vec::new(),
            identity: Identity::None,
            listen_address: "/ip4/0.0.0.0/tcp/6180".parse().unwrap(),
            mutual_authentication,
```

**File:** network/framework/src/peer_manager/builder.rs (L37-46)
```rust
pub enum AuthenticationMode {
    /// Inbound connections will first be checked against the known peers set, and
    /// if the `PeerId` is known it will be authenticated against it's `PublicKey`
    /// Otherwise, the incoming connections will be allowed through in the common
    /// pool of unknown peers.
    MaybeMutual(x25519::PrivateKey),
    /// Both dialer and listener will verify public keys of each other in the
    /// handshake.
    Mutual(x25519::PrivateKey),
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

**File:** peer-monitoring-service/types/src/response.rs (L51-55)
```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NetworkInformationResponse {
    pub connected_peers: BTreeMap<PeerNetworkId, ConnectionMetadata>, // Connected peers
    pub distance_from_validators: u64, // The distance of the peer from the validator set
}
```

**File:** peer-monitoring-service/types/src/response.rs (L94-102)
```rust
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

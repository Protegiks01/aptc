# Audit Report

## Title
Memory Exhaustion via Oversized Peer Monitoring Responses Leading to Validator OOM

## Summary
The peer monitoring service client performs response size validation **after** the network layer has fully assembled large responses in memory. A malicious peer can send responses up to 64 MiB (640x larger than the expected 100 KB limit), and with concurrent requests, can cause validators to allocate multiple gigabytes of memory before size checks occur, leading to OOM conditions and validator crashes.

## Finding Description

The vulnerability exists in the ordering of operations between the network layer's message assembly and the application layer's size validation.

**Architecture Flow:**

1. The peer monitoring client sends requests to peers via `send_request_to_peer()` [1](#0-0) 

2. Responses can be streamed in fragments if they exceed `max_frame_size` (4 MiB). The `InboundStream` assembles fragments by appending raw data without total size validation [2](#0-1) 

3. The network layer allows messages up to `MAX_MESSAGE_SIZE` (64 MiB) [3](#0-2) 

4. Only **after** the full response is assembled in memory does the application perform size validation [4](#0-3) 

**The Critical Gap:**

The peer monitoring service expects responses ≤ 100 KB [5](#0-4) , but the network layer permits and assembles messages up to 64 MiB before this check occurs.

**Attack Scenario:**

1. A validator's peer monitoring client monitors connected peers, sending `GetNetworkInformation` or `GetNodeInformation` requests
2. A malicious peer crafts a response containing a large `NetworkInformationResponse` with thousands of fake `connected_peers` entries [6](#0-5) 
3. The network layer streams and assembles the full 64 MiB response in memory
4. With up to 100 concurrent outbound RPCs allowed per peer [7](#0-6) , this can allocate 6.4 GB before any size check
5. The size check eventually detects the violation, but memory is already exhausted
6. Repeated requests from multiple malicious peers can trigger OOM, crashing the validator

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty program:

- **Validator Stability Impact**: Can cause validator nodes to experience memory exhaustion and crash, affecting network participation
- **Availability Impact**: Validators may become unavailable, reducing consensus participation
- **Limited Scope**: Requires the validator to monitor malicious peers, but peer connections happen automatically in the P2P network
- **No Direct Fund Loss**: Does not directly steal or freeze funds, but affects network health

The impact aligns with the Medium severity category: "State inconsistencies requiring intervention" and High severity's "Validator node slowdowns."

## Likelihood Explanation

**Likelihood: Medium-High**

- **Automatic Triggering**: Validators automatically monitor connected peers; no manual configuration needed
- **Low Attack Complexity**: Malicious peer only needs to respond with oversized messages to legitimate monitoring requests
- **No Special Privileges**: Any peer in the network can execute this attack
- **Repeatable**: The attack can be executed repeatedly to maintain pressure on validator memory
- **Concurrent Amplification**: Multiple concurrent requests amplify the memory allocation

The attack is realistic and practical for any peer connected to a validator.

## Recommendation

**Enforce application-level size limits at the network layer before message assembly:**

1. **Immediate Fix**: Add a protocol-specific maximum message size parameter that applications can set. For the peer monitoring service, enforce the 100 KB limit at the network layer during fragment assembly:

```rust
// In InboundStream::append_fragment()
fn append_fragment(&mut self, mut fragment: StreamFragment) -> anyhow::Result<bool> {
    // ... existing validation ...
    
    // NEW: Check accumulated size against protocol limit
    let accumulated_size = self.message.data_len() + fragment.raw_data.len();
    if let Some(max_size) = self.max_message_size_override {
        ensure!(
            accumulated_size <= max_size,
            "Accumulated message size {} exceeds protocol limit {}",
            accumulated_size,
            max_size
        );
    }
    
    // ... rest of method ...
}
```

2. **Alternative Fix**: Implement early validation in the RPC handler before forwarding to application:

```rust
// In OutboundRpcs::handle_inbound_response()
pub fn handle_inbound_response(&mut self, response: RpcResponse) {
    // NEW: Check response size against protocol-specific limits
    if let Some((protocol_id, max_response_size)) = 
        self.get_protocol_response_size_limit(protocol_id) 
    {
        if response.raw_response.len() > max_response_size {
            warn!("Response size {} exceeds protocol limit {}", 
                  response.raw_response.len(), max_response_size);
            return; // Discard oversized response early
        }
    }
    // ... existing logic ...
}
```

3. **Configuration Update**: Align network-level and application-level limits for peer monitoring:

```rust
// Enforce stricter limits for peer monitoring protocol
pub const PEER_MONITORING_MAX_MESSAGE_SIZE: usize = 128 * 1024; // 128 KB safety margin
```

## Proof of Concept

```rust
// Rust test demonstrating the vulnerability
#[tokio::test]
async fn test_oversized_response_memory_exhaustion() {
    // Setup: Create peer monitoring client and mock malicious peer
    let (peer_monitoring_client, mock_network) = setup_test_client();
    
    // Configure mock peer to respond with 64 MiB response
    let oversized_response = create_oversized_network_info_response(64 * 1024 * 1024);
    mock_network.set_response(oversized_response);
    
    // Execute: Send monitoring request
    let request = PeerMonitoringServiceRequest::GetNetworkInformation;
    let result = send_request_to_peer(
        peer_monitoring_client,
        &test_peer_network_id(),
        1,
        request,
        10_000, // 10 second timeout
    ).await;
    
    // Verify: Response is assembled in memory before size check fails
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::UnexpectedError(msg) 
        if msg.contains("too large")));
    
    // The vulnerability: By the time the error is returned,
    // 64 MiB has already been allocated in memory
    // With 100 concurrent requests, this becomes 6.4 GB
}

fn create_oversized_network_info_response(target_size: usize) -> NetworkInformationResponse {
    let mut connected_peers = BTreeMap::new();
    
    // Add fake peers until we reach target size
    let metadata = ConnectionMetadata::new(
        test_network_address(),
        test_peer_id(),
        PeerRole::Validator,
    );
    
    let bytes_per_entry = bcs::to_bytes(&metadata).unwrap().len() + 32;
    let num_entries = target_size / bytes_per_entry;
    
    for i in 0..num_entries {
        let peer_network_id = create_fake_peer_network_id(i);
        connected_peers.insert(peer_network_id, metadata.clone());
    }
    
    NetworkInformationResponse {
        connected_peers,
        distance_from_validators: 0,
    }
}
```

## Notes

This vulnerability demonstrates a common pattern where application-level validation occurs too late in the processing pipeline. The network layer's generic design allows 64 MiB messages for legitimate use cases (like state synchronization), but individual protocols like peer monitoring need stricter enforcement before memory allocation. The fix requires either protocol-specific size limits enforced during fragment assembly or early validation at the RPC layer before forwarding to applications.

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

**File:** network/framework/src/protocols/stream/mod.rs (L163-214)
```rust
    /// Append a fragment to the stream (returns true if the stream is complete)
    fn append_fragment(&mut self, mut fragment: StreamFragment) -> anyhow::Result<bool> {
        // Verify the stream request ID and fragment request ID
        ensure!(
            self.request_id == fragment.request_id,
            "Stream fragment from a different request! Expected {}, got {}.",
            self.request_id,
            fragment.request_id
        );

        // Verify the fragment ID
        let fragment_id = fragment.fragment_id;
        ensure!(fragment_id > 0, "Fragment ID must be greater than zero!");
        ensure!(
            fragment_id <= self.num_fragments,
            "Fragment ID {} exceeds number of fragments {}!",
            fragment_id,
            self.num_fragments
        );

        // Verify the fragment ID is the expected next fragment
        let expected_fragment_id = self.received_fragment_id.checked_add(1).ok_or_else(|| {
            anyhow::anyhow!(
                "Current fragment ID overflowed when adding 1: {}",
                self.received_fragment_id
            )
        })?;
        ensure!(
            expected_fragment_id == fragment_id,
            "Unexpected fragment ID, expected {}, got {}!",
            expected_fragment_id,
            fragment_id
        );

        // Update the received fragment ID
        self.received_fragment_id = expected_fragment_id;

        // Append the fragment data to the message
        let raw_data = &mut fragment.raw_data;
        match &mut self.message {
            NetworkMessage::Error(_) => {
                panic!("StreamHeader for NetworkMessage::Error(_) should be rejected!")
            },
            NetworkMessage::RpcRequest(request) => request.raw_request.append(raw_data),
            NetworkMessage::RpcResponse(response) => response.raw_response.append(raw_data),
            NetworkMessage::DirectSendMsg(message) => message.raw_msg.append(raw_data),
        }

        // Return whether the stream is complete
        let is_stream_complete = self.received_fragment_id == self.num_fragments;
        Ok(is_stream_complete)
    }
```

**File:** config/src/config/network_config.rs (L50-50)
```rust
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
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

**File:** peer-monitoring-service/types/src/response.rs (L50-55)
```rust
/// A response for the network information request
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NetworkInformationResponse {
    pub connected_peers: BTreeMap<PeerNetworkId, ConnectionMetadata>, // Connected peers
    pub distance_from_validators: u64, // The distance of the peer from the validator set
}
```

**File:** network/framework/src/constants.rs (L13-13)
```rust
pub const MAX_CONCURRENT_OUTBOUND_RPCS: u32 = 100;
```

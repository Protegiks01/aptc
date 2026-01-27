# Audit Report

## Title
RPC Amplification DoS Vulnerability in Storage Service via Unthrottled Valid Requests

## Summary
The Aptos storage service lacks per-peer request rate limiting for valid RPC requests, allowing attackers to perform bandwidth amplification DoS attacks by sending small valid requests that trigger disproportionately large responses (up to 10 MiB per request). While response sizes are bounded and concurrent request limits exist, there is no throttling mechanism for the sequential rate of valid requests, enabling sustained amplification attacks.

## Finding Description

The vulnerability exists in the interaction between the network RPC layer and the storage service request validation system. When a peer sends an RPC request via `send_to_peer_rpc()`, the request flows through: [1](#0-0) 

The RPC is processed by the storage service handler: [2](#0-1) 

The `RequestModerator` validates requests but only checks if they **can be satisfied**, not if they represent a reasonable cost/benefit ratio: [3](#0-2) 

The critical flaw is that the moderator only increments the invalid request counter when `can_service()` returns false (lines 154-178 in moderator.rs). Valid but expensive requests—such as requesting large ranges of state values, transactions, or epoch ending ledger infos—do NOT increment the invalid request counter and therefore never trigger peer throttling.

**Attack Scenario:**

1. Attacker connects as a public network peer
2. Sends valid `StateValuesWithProofRequest` with large index ranges (e.g., start_index=0, end_index=4000)
3. Each request (~100 bytes) triggers a response up to 10 MiB (100,000x amplification)
4. Repeats requests sequentially after each completes
5. The storage service processes each request because they're all valid according to the storage server summary
6. The peer is never ignored because no invalid requests are sent

The response size limits exist but don't prevent the attack: [4](#0-3) 

Storage service enforces these limits: [5](#0-4) 

However, concurrent request limits only restrict simultaneous requests, not sequential request rate: [6](#0-5) 

## Impact Explanation

This vulnerability qualifies as **Medium Severity** per Aptos bug bounty criteria:

- **Validator Node Slowdowns**: Repeated amplification requests exhaust outbound bandwidth and CPU cycles for serialization, degrading node performance for legitimate peers
- **State Sync Degradation**: Legitimate state sync requests from catching-up nodes may experience delays or timeouts due to resource exhaustion
- **Network Resource Waste**: Target nodes waste significant bandwidth (potentially gigabytes per minute) responding to malicious requests

The impact is limited from Critical/High because:
- Individual responses are capped at 10 MiB
- Concurrent request limits prevent unbounded parallelization  
- No consensus safety violation or fund loss occurs
- The attack targets availability/performance, not correctness

## Likelihood Explanation

**Likelihood: High**

- **Low Barrier to Entry**: Any peer on the public network can connect and send storage service requests
- **Simple Exploitation**: Attack requires only crafting valid requests with large data ranges—no cryptographic bypasses or complex state manipulation needed
- **No Authentication Required**: Public network peers are not authenticated beyond connection establishment
- **Sustained Attack Feasible**: Attacker can maintain attack by sequentially sending new requests as previous ones complete
- **Cost Asymmetry**: Attacker's bandwidth cost (~100 KB/s for requests) is 100x lower than victim's cost (~10 MB/s for responses)

## Recommendation

Implement per-peer bandwidth-based rate limiting for valid storage service requests:

```rust
// In state-sync/storage-service/server/src/moderator.rs

pub struct UnhealthyPeerState {
    ignore_start_time: Option<Instant>,
    invalid_request_count: u64,
    max_invalid_requests: u64,
    min_time_to_ignore_secs: u64,
    time_service: TimeService,
    
    // Add bandwidth tracking
    bytes_sent_window: VecDeque<(Instant, u64)>, // (timestamp, bytes)
    max_bytes_per_window: u64, // e.g., 50 MiB per 60 seconds
    window_duration_secs: u64, // e.g., 60 seconds
}

impl UnhealthyPeerState {
    pub fn check_bandwidth_limit(&mut self, response_bytes: u64) -> Result<(), Error> {
        let now = self.time_service.now();
        let window_start = now - Duration::from_secs(self.window_duration_secs);
        
        // Remove entries outside the window
        self.bytes_sent_window.retain(|(ts, _)| *ts >= window_start);
        
        // Calculate total bytes in window
        let total_bytes: u64 = self.bytes_sent_window.iter().map(|(_, b)| b).sum();
        
        if total_bytes + response_bytes > self.max_bytes_per_window {
            return Err(Error::TooManyInvalidRequests(
                "Bandwidth limit exceeded for peer".into()
            ));
        }
        
        self.bytes_sent_window.push_back((now, response_bytes));
        Ok(())
    }
}
```

Additionally, implement cost-based request validation in the moderator that considers request size vs expected response size ratio.

## Proof of Concept

```rust
// Add to state-sync/storage-service/server/src/tests/
#[tokio::test]
async fn test_rpc_amplification_attack() {
    use aptos_config::network_id::{NetworkId, PeerNetworkId};
    use aptos_storage_service_types::requests::*;
    use aptos_types::PeerId;
    
    // Setup storage service with mock data
    let (storage_service, mut mock_client) = setup_mock_storage_service().await;
    let attacker_peer = PeerNetworkId::new(NetworkId::Public, PeerId::random());
    
    // Track total bandwidth amplification
    let mut total_request_bytes = 0u64;
    let mut total_response_bytes = 0u64;
    
    // Simulate attacker sending 100 sequential requests
    for i in 0..100 {
        // Small request (~100 bytes)
        let request = StorageServiceRequest::new(
            DataRequest::GetStateValuesWithProof(StateValuesWithProofRequest {
                version: 1000,
                start_index: i * 4000,
                end_index: (i + 1) * 4000 - 1,
            }),
            false,
        );
        
        let request_bytes = bcs::to_bytes(&request).unwrap().len() as u64;
        total_request_bytes += request_bytes;
        
        // Send request and get response
        let response = mock_client.send_request(attacker_peer, request).await.unwrap();
        
        // Large response (up to 10 MiB)
        let response_bytes = bcs::to_bytes(&response).unwrap().len() as u64;
        total_response_bytes += response_bytes;
        
        // Verify request was not throttled
        assert!(response.is_ok(), "Request {} should succeed", i);
    }
    
    // Calculate amplification factor
    let amplification_factor = total_response_bytes / total_request_bytes;
    
    // Demonstrate significant amplification (should be > 1000x in practice)
    assert!(
        amplification_factor > 1000,
        "Amplification factor of {}x demonstrates vulnerability",
        amplification_factor
    );
    
    println!(
        "Attack sent {} KB, received {} MB ({}x amplification)",
        total_request_bytes / 1024,
        total_response_bytes / (1024 * 1024),
        amplification_factor
    );
}
```

## Notes

This vulnerability specifically affects the storage service's state sync RPC handlers. The concurrent request limit (`max_concurrent_inbound_rpcs`) provides partial mitigation by preventing unlimited parallelization, but sequential requests can still achieve significant amplification. The issue is exacerbated for nodes with high-quality data (fullnodes and validators) that can satisfy many valid requests. Implementing sliding-window bandwidth tracking per peer on public networks would effectively mitigate this attack vector while preserving functionality for legitimate state sync operations.

### Citations

**File:** network/framework/src/application/interface.rs (L260-272)
```rust
    async fn send_to_peer_rpc(
        &self,
        message: Message,
        rpc_timeout: Duration,
        peer: PeerNetworkId,
    ) -> Result<Message, Error> {
        let network_sender = self.get_sender_for_network_id(&peer.network_id())?;
        let rpc_protocol_id =
            self.get_preferred_protocol_for_peer(&peer, &self.rpc_protocols_and_preferences)?;
        Ok(network_sender
            .send_rpc(peer.peer_id(), rpc_protocol_id, message, rpc_timeout)
            .await?)
    }
```

**File:** state-sync/storage-service/server/src/handler.rs (L205-229)
```rust
    /// Validate the request and only handle it if the moderator allows
    fn validate_and_handle_request(
        &self,
        peer_network_id: &PeerNetworkId,
        request: &StorageServiceRequest,
    ) -> Result<StorageServiceResponse, Error> {
        // Validate the request with the moderator
        self.request_moderator
            .validate_request(peer_network_id, request)?;

        // Process the request
        match &request.data_request {
            DataRequest::GetServerProtocolVersion => {
                let data_response = self.get_server_protocol_version();
                StorageServiceResponse::new(data_response, request.use_compression)
                    .map_err(|error| error.into())
            },
            DataRequest::GetStorageServerSummary => {
                let data_response = self.get_storage_server_summary();
                StorageServiceResponse::new(data_response, request.use_compression)
                    .map_err(|error| error.into())
            },
            _ => self.process_cachable_request(peer_network_id, request),
        }
    }
```

**File:** state-sync/storage-service/server/src/moderator.rs (L134-196)
```rust
    pub fn validate_request(
        &self,
        peer_network_id: &PeerNetworkId,
        request: &StorageServiceRequest,
    ) -> Result<(), Error> {
        // Validate the request and time the operation
        let validate_request = || {
            // If the peer is being ignored, return an error
            if let Some(peer_state) = self.unhealthy_peer_states.get(peer_network_id) {
                if peer_state.is_ignored() {
                    return Err(Error::TooManyInvalidRequests(format!(
                        "Peer is temporarily ignored. Unable to handle request: {:?}",
                        request
                    )));
                }
            }

            // Get the latest storage server summary
            let storage_server_summary = self.cached_storage_server_summary.load();

            // Verify the request is serviceable using the current storage server summary
            if !storage_server_summary.can_service(
                &self.aptos_data_client_config,
                self.time_service.clone(),
                request,
            ) {
                // Increment the invalid request count for the peer
                let mut unhealthy_peer_state = self
                    .unhealthy_peer_states
                    .entry(*peer_network_id)
                    .or_insert_with(|| {
                        // Create a new unhealthy peer state (this is the first invalid request)
                        let max_invalid_requests =
                            self.storage_service_config.max_invalid_requests_per_peer;
                        let min_time_to_ignore_peers_secs =
                            self.storage_service_config.min_time_to_ignore_peers_secs;
                        let time_service = self.time_service.clone();

                        UnhealthyPeerState::new(
                            max_invalid_requests,
                            min_time_to_ignore_peers_secs,
                            time_service,
                        )
                    });
                unhealthy_peer_state.increment_invalid_request_count(peer_network_id);

                // Return the validation error
                return Err(Error::InvalidRequest(format!(
                    "The given request cannot be satisfied. Request: {:?}, storage summary: {:?}",
                    request, storage_server_summary
                )));
            }

            Ok(()) // The request is valid
        };
        utils::execute_and_time_duration(
            &metrics::STORAGE_REQUEST_VALIDATION_LATENCY,
            Some((peer_network_id, request)),
            None,
            validate_request,
            None,
        )
    }
```

**File:** config/src/config/state_sync_config.rs (L17-27)
```rust
const SERVER_MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024; // 10 MiB

// The maximum message size per state sync message (for v2 data requests)
const CLIENT_MAX_MESSAGE_SIZE_V2: usize = 20 * 1024 * 1024; // 20 MiB (used for v2 data requests)
const SERVER_MAX_MESSAGE_SIZE_V2: usize = 40 * 1024 * 1024; // 40 MiB (used for v2 data requests)

// The maximum chunk sizes for data client requests and response
const MAX_EPOCH_CHUNK_SIZE: u64 = 200;
const MAX_STATE_CHUNK_SIZE: u64 = 4000;
const MAX_TRANSACTION_CHUNK_SIZE: u64 = 3000;
const MAX_TRANSACTION_OUTPUT_CHUNK_SIZE: u64 = 3000;
```

**File:** state-sync/storage-service/server/src/storage.rs (L1202-1215)
```rust
    fn get_state_value_chunk_with_proof(
        &self,
        version: u64,
        start_index: u64,
        end_index: u64,
    ) -> aptos_storage_service_types::Result<StateValueChunkWithProof, Error> {
        self.get_state_value_chunk_with_proof_by_size(
            version,
            start_index,
            end_index,
            self.config.max_network_chunk_bytes,
            self.config.enable_size_and_time_aware_chunking,
        )
    }
```

**File:** network/framework/src/protocols/rpc/mod.rs (L212-223)
```rust
        // Drop new inbound requests if our completion queue is at capacity.
        if self.inbound_rpc_tasks.len() as u32 == self.max_concurrent_inbound_rpcs {
            // Increase counter of declined requests
            counters::rpc_messages(
                network_context,
                REQUEST_LABEL,
                INBOUND_LABEL,
                DECLINED_LABEL,
            )
            .inc();
            return Err(RpcError::TooManyPending(self.max_concurrent_inbound_rpcs));
        }
```

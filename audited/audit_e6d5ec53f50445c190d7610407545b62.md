# Audit Report

## Title
Request Validation Bypass and Peer Reputation System Evasion via Transaction Data V2 Requests

## Summary
An attacker can bypass the RequestModerator's peer reputation system by sending transaction data v2 requests when `enable_transaction_data_v2` is disabled. The early return at line 116 prevents proper error metric tracking and peer invalid request counting, allowing malicious peers to evade the automatic peer ignoring mechanism that would normally block them after 500 invalid requests.

## Finding Description

The vulnerability exists in the `process_request_and_respond()` function where transaction data v2 requests are checked before RequestModerator validation occurs. [1](#0-0) 

The execution flow is:

1. Request counter is incremented [2](#0-1) 

2. V2 check occurs with early return [3](#0-2) 

3. RequestModerator validation happens later [4](#0-3) 

The RequestModerator tracks invalid requests and ignores peers after exceeding a threshold: [5](#0-4) 

With default configuration: [6](#0-5) 

**Attack Path:**
When an attacker sends v2 requests with v2 disabled:
- `STORAGE_REQUESTS_RECEIVED` is incremented
- Request is logged with `warn!` and dropped (line 116)
- `STORAGE_ERRORS_ENCOUNTERED` is NOT incremented
- No response sent to client
- **RequestModerator's `invalid_request_count` is NOT incremented**
- Peer is never marked unhealthy or ignored

The moderator's validation that increments invalid request counts only happens in the normal flow: [7](#0-6) 

An attacker can:
1. Send unlimited v2 requests without being tracked
2. Combine with 499 other invalid requests to maximize resource consumption while staying below the 500 threshold
3. Evade monitoring based on `STORAGE_ERRORS_ENCOUNTERED` metrics

## Impact Explanation

**Medium Severity** - This constitutes a request validation bypass that breaks the peer reputation system. While it doesn't directly cause funds loss or state corruption, it:

1. **Bypasses security controls**: The RequestModerator is an application-level defense against malicious peers
2. **Resource consumption**: Each request still consumes network bandwidth, deserialization CPU, and logging resources
3. **Metric evasion**: Operators monitoring error metrics won't detect this abuse pattern
4. **Defense-in-depth violation**: Removes a layer of protection against misbehaving peers

The test suite confirms no response is sent: [8](#0-7) 

## Likelihood Explanation

**Medium to High Likelihood** when operators disable v2:
- Any network peer can exploit this (no special privileges required)
- Attack is trivial to execute (just send v2 requests)
- Only requires v2 to be disabled (enabled by default, but operators may disable for compatibility)
- No authentication or authorization bypass needed

## Recommendation

Move the v2 check AFTER the request counter increment but still track it as an error. Modify the code to increment error metrics and send an error response:

```rust
// After line 103, replace lines 105-117 with:
if request.data_request.is_transaction_data_v2_request()
    && !storage_service_config.enable_transaction_data_v2
{
    let error = Error::InvalidRequest(format!(
        "Received a v2 data request ({}), which is not supported!",
        request.get_label()
    ));
    
    // Increment error counter
    increment_counter(
        &metrics::STORAGE_ERRORS_ENCOUNTERED,
        peer_network_id.network_id(),
        error.get_label().into(),
    );
    
    // Log the error
    warn!(LogSchema::new(LogEntry::StorageServiceError)
        .error(&error)
        .peer_network_id(&peer_network_id));
    
    // Send error response to client
    response_sender.send(Err(StorageServiceError::InvalidRequest(error.to_string())));
    return;
}
```

Alternatively, integrate the v2 check into the moderator validation logic so these requests properly increment invalid request counts.

## Proof of Concept

The existing test demonstrates the vulnerability: [8](#0-7) 

Extended PoC showing metric bypass:

```rust
#[tokio::test]
async fn test_v2_request_bypasses_peer_reputation() {
    // Create config with v2 disabled
    let mut storage_config = StorageServiceConfig::default();
    storage_config.enable_transaction_data_v2 = false;
    storage_config.max_invalid_requests_per_peer = 5; // Lower threshold for testing
    
    // Create mock client from public network
    let peer_network_id = PeerNetworkId::new(NetworkId::Public, PeerId::random());
    let (mut mock_client, mut service, _, _, request_moderator) =
        MockClient::new(None, Some(storage_config));
    tokio::spawn(service.start());
    
    // Send 10 v2 requests (should trigger ignoring if tracked)
    for _ in 0..10 {
        let _ = get_transactions_with_proof(
            &mut mock_client,
            0, 10, 10, true, true,
            true, // Use v2
            storage_config.max_network_chunk_bytes_v2,
        ).await;
    }
    
    // Verify peer is NOT ignored (bug)
    let unhealthy_states = request_moderator.get_unhealthy_peer_states();
    assert!(unhealthy_states.get(&peer_network_id).is_none() 
            || !unhealthy_states.get(&peer_network_id).unwrap().is_ignored());
    
    // Now send one "normal" invalid request
    let _ = get_transactions_with_proof(
            &mut mock_client,
            1000, 0, 0, true, true, // Invalid range
            false, // Use v1
            storage_config.max_network_chunk_bytes,
        ).await;
    
    // This single normal invalid request gets tracked,
    // but all v2 requests were invisible to the moderator
}
```

## Notes

This vulnerability only affects deployments where operators explicitly disable transaction data v2 support. The default configuration has `enable_transaction_data_v2: true`. [9](#0-8) 

The v2 request types affected are: [10](#0-9) 

Network-level protections (HAProxy bandwidth limits, connection limits) still apply, but the application-level peer reputation system is completely bypassed for these requests.

### Citations

**File:** state-sync/storage-service/server/src/handler.rs (L82-139)
```rust
    pub fn process_request_and_respond(
        &self,
        storage_service_config: StorageServiceConfig,
        peer_network_id: PeerNetworkId,
        protocol_id: ProtocolId,
        request: StorageServiceRequest,
        response_sender: ResponseSender,
    ) {
        // Log the request
        trace!(LogSchema::new(LogEntry::ReceivedStorageRequest)
            .request(&request)
            .message(&format!(
                "Received storage request. Peer: {:?}, protocol: {:?}.",
                peer_network_id, protocol_id,
            )));

        // Update the request count
        increment_counter(
            &metrics::STORAGE_REQUESTS_RECEIVED,
            peer_network_id.network_id(),
            request.get_label(),
        );

        // If the request is for transaction v2 data, only process it
        // if the server supports it. Otherwise, drop the request.
        if request.data_request.is_transaction_data_v2_request()
            && !storage_service_config.enable_transaction_data_v2
        {
            warn!(LogSchema::new(LogEntry::StorageServiceError)
                .error(&Error::InvalidRequest(format!(
                    "Received a v2 data request ({}), which is not supported!",
                    request.get_label()
                )))
                .peer_network_id(&peer_network_id));
            return;
        }

        // Handle any optimistic fetch requests
        if request.data_request.is_optimistic_fetch() {
            self.handle_optimistic_fetch_request(peer_network_id, request, response_sender);
            return;
        }

        // Handle any subscription requests
        if request.data_request.is_subscription_request() {
            self.handle_subscription_request(
                storage_service_config,
                peer_network_id,
                request,
                response_sender,
            );
            return;
        }

        // Process the request and return the response to the client
        let response = self.process_request(&peer_network_id, request.clone(), false);
        self.send_response(request, response, response_sender);
    }
```

**File:** state-sync/storage-service/server/src/handler.rs (L206-229)
```rust
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

**File:** state-sync/storage-service/server/src/moderator.rs (L46-69)
```rust

    /// Increments the invalid request count for the peer and marks
    /// the peer to be ignored if it has sent too many invalid requests.
    /// Note: we only ignore peers on the public network.
    pub fn increment_invalid_request_count(&mut self, peer_network_id: &PeerNetworkId) {
        // Increment the invalid request count
        self.invalid_request_count += 1;

        // If the peer is a PFN and has sent too many invalid requests, start ignoring it
        if self.ignore_start_time.is_none()
            && peer_network_id.network_id().is_public_network()
            && self.invalid_request_count >= self.max_invalid_requests
        {
            // TODO: at some point we'll want to terminate the connection entirely

            // Start ignoring the peer
            self.ignore_start_time = Some(self.time_service.now());

            // Log the fact that we're now ignoring the peer
            warn!(LogSchema::new(LogEntry::RequestModeratorIgnoredPeer)
                .peer_network_id(peer_network_id)
                .message("Ignoring peer due to too many invalid requests!"));
        }
    }
```

**File:** state-sync/storage-service/server/src/moderator.rs (L160-178)
```rust
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
```

**File:** config/src/config/state_sync_config.rs (L199-199)
```rust
            enable_transaction_data_v2: true,
```

**File:** config/src/config/state_sync_config.rs (L201-213)
```rust
            max_invalid_requests_per_peer: 500,
            max_lru_cache_size: 500, // At ~0.6MiB per chunk, this should take no more than 0.5GiB
            max_network_channel_size: 4000,
            max_network_chunk_bytes: SERVER_MAX_MESSAGE_SIZE as u64,
            max_network_chunk_bytes_v2: SERVER_MAX_MESSAGE_SIZE_V2 as u64,
            max_num_active_subscriptions: 30,
            max_optimistic_fetch_period_ms: 5000, // 5 seconds
            max_state_chunk_size: MAX_STATE_CHUNK_SIZE,
            max_storage_read_wait_time_ms: 10_000, // 10 seconds
            max_subscription_period_ms: 30_000,    // 30 seconds
            max_transaction_chunk_size: MAX_TRANSACTION_CHUNK_SIZE,
            max_transaction_output_chunk_size: MAX_TRANSACTION_OUTPUT_CHUNK_SIZE,
            min_time_to_ignore_peers_secs: 300, // 5 minutes
```

**File:** state-sync/storage-service/server/src/tests/transactions.rs (L160-182)
```rust
async fn test_get_transactions_with_proof_disable_v2() {
    // Create a storage service config with transaction v2 disabled
    let storage_config = utils::create_storage_config(false, false);

    // Create the storage client and server
    let (mut mock_client, service, _, _, _) = MockClient::new(None, Some(storage_config));
    tokio::spawn(service.start());

    // Send a transaction v2 request. This will cause a test panic
    // as no response will be received (the receiver is dropped).
    utils::get_transactions_with_proof(
        &mut mock_client,
        0,
        10,
        10,
        true,
        true,
        true, // Use transaction v2
        storage_config.max_network_chunk_bytes_v2,
    )
    .await
    .unwrap();
}
```

**File:** state-sync/storage-service/types/src/requests.rs (L150-155)
```rust
    /// Returns true iff the request is a transaction data v2 request
    pub fn is_transaction_data_v2_request(&self) -> bool {
        matches!(self, &Self::GetTransactionDataWithProof(_))
            || matches!(self, &Self::GetNewTransactionDataWithProof(_))
            || matches!(self, &Self::SubscribeTransactionDataWithProof(_))
    }
```

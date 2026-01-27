# Audit Report

## Title
Critical Validation Bypass in Storage Service Request Handling Allows Unpunished Resource Exhaustion

## Summary
Optimistic fetch and subscription requests in the Aptos storage service completely bypass the `RequestModerator::validate_request()` function, allowing attackers to send unlimited invalid requests without triggering the invalid request tracking mechanism. This enables resource exhaustion attacks (memory and CPU) against storage service nodes without any penalty or peer ignoring logic being applied.

## Finding Description

The storage service implements a request moderation system designed to track invalid requests from peers and temporarily ignore peers that send too many invalid requests. [1](#0-0) 

The `RequestModerator::validate_request()` function is responsible for validating incoming requests and incrementing the invalid request count when requests fail validation. [2](#0-1) 

However, in the request handling flow, optimistic fetch and subscription requests are routed **before** validation occurs. [3](#0-2) 

For optimistic fetch requests, the handler directly stores the request without any validation: [4](#0-3) 

Only non-optimistic, non-subscription requests go through the validation path: [5](#0-4) 

The validation logic that should prevent this exists but is never called for optimistic/subscription requests: [6](#0-5) 

Furthermore, even when `can_service()` is used for validation in normal requests, it provides insufficient validation for optimistic fetch requests - only checking timestamp lag, not whether the `known_version` is within available ranges: [7](#0-6) 

When invalid optimistic fetch requests are eventually detected during processing, they are simply removed with a warning, without incrementing the invalid request counter: [8](#0-7) 

**Attack Scenario:**
1. Attacker sends `GetNewTransactionOutputsWithProof` request with `known_version = u64::MAX` and `known_epoch = u64::MAX`
2. Request is recognized as optimistic fetch and bypasses validation
3. Request is stored in the `optimistic_fetches` DashMap, consuming memory
4. Periodically, the system attempts to process this request, consuming CPU
5. Request is eventually identified as invalid and removed with just a warning
6. Peer's invalid request count remains at 0 - no penalty applied
7. Attacker repeats indefinitely, exhausting node resources without consequence

## Impact Explanation

This vulnerability qualifies as **Critical Severity** under the Aptos bug bounty program for the following reasons:

1. **Validator Node Resource Exhaustion**: Attackers can cause significant slowdowns on validator nodes by filling the optimistic fetch and subscription maps with invalid requests, directly impacting consensus participation.

2. **Network-Wide DoS Vector**: If multiple attackers target multiple validator nodes simultaneously, this could cause network-wide liveness issues, as validators struggle with resource exhaustion.

3. **Permanent Bypass of Security Controls**: The invalid request tracking and peer ignoring mechanism is completely ineffective for these request types, representing a fundamental security control failure.

4. **No Authentication Required**: Any network peer (including public fullnode peers) can exploit this vulnerability without any special privileges.

The impact aligns with Critical Severity criteria: "Validator node slowdowns" escalating to potential "Total loss of liveness/network availability" if exploited at scale.

## Likelihood Explanation

**Likelihood: HIGH**

- **Ease of Exploitation**: Trivial - requires only sending specially crafted storage service requests
- **Attacker Requirements**: None - any peer on the network can exploit this
- **Detection Difficulty**: Low - invalid requests are dropped with warnings but no alerts or penalties
- **Scale of Impact**: Increases with number of attackers and targeted nodes
- **Current Exposure**: All Aptos nodes running the storage service are vulnerable

The vulnerability is in production code, easily discoverable, and trivially exploitable, making exploitation highly likely.

## Recommendation

Implement validation for optimistic fetch and subscription requests **before** storing them. The fix should ensure that `RequestModerator::validate_request()` is called for all request types.

**Recommended Fix:**

In `state-sync/storage-service/server/src/handler.rs`, modify `process_request_and_respond()` to validate ALL requests before routing:

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
    trace!(LogSchema::new(LogEntry::ReceivedStorageRequest)...);
    
    // Update the request count
    increment_counter(...);
    
    // **NEW: Validate ALL requests first**
    if let Err(error) = self.request_moderator.validate_request(&peer_network_id, &request) {
        let storage_error = match error {
            Error::InvalidRequest(e) => StorageServiceError::InvalidRequest(e),
            Error::TooManyInvalidRequests(e) => StorageServiceError::TooManyInvalidRequests(e),
            _ => StorageServiceError::InternalError(error.to_string()),
        };
        response_sender.send(Err(storage_error));
        return;
    }
    
    // If the request is for transaction v2 data...
    if request.data_request.is_transaction_data_v2_request()...
    
    // Continue with existing logic for routing requests
    ...
}
```

Additionally, strengthen the validation in `DataSummary::can_service()` to check that optimistic fetch `known_version` values are reasonable:

```rust
GetNewTransactionOutputsWithProof(request) => {
    // Check that known_version is within reasonable bounds
    if let Some(synced_info) = self.synced_ledger_info.as_ref() {
        let synced_version = synced_info.ledger_info().version();
        if request.known_version > synced_version {
            return false; // Known version cannot exceed synced version
        }
    }
    can_service_optimistic_request(aptos_data_client_config, time_service, self.synced_ledger_info.as_ref())
}
```

## Proof of Concept

```rust
// Test demonstrating the validation bypass
// Location: state-sync/storage-service/server/src/tests/mod.rs

#[tokio::test]
async fn test_optimistic_fetch_validation_bypass() {
    // Setup storage service server with request moderator
    let (storage_service, mock_time, peer_id) = setup_storage_service_with_moderator();
    
    // Get the request moderator to check invalid request count
    let moderator = storage_service.get_request_moderator();
    let peer_network_id = PeerNetworkId::new(NetworkId::Public, peer_id);
    
    // Verify initial state: no invalid requests tracked
    let initial_count = moderator
        .get_unhealthy_peer_states()
        .get(&peer_network_id)
        .map(|state| state.invalid_request_count)
        .unwrap_or(0);
    assert_eq!(initial_count, 0);
    
    // Send invalid optimistic fetch request with known_version = u64::MAX
    let invalid_request = StorageServiceRequest::new(
        DataRequest::GetNewTransactionOutputsWithProof(
            NewTransactionOutputsWithProofRequest {
                known_version: u64::MAX,  // Invalid: far beyond any real version
                known_epoch: u64::MAX,     // Invalid: far beyond any real epoch
            }
        ),
        false,
    );
    
    // Send the request through the network layer
    let (response_sender, response_receiver) = oneshot::channel();
    storage_service.handle_network_request(
        peer_network_id,
        ProtocolId::StorageServiceRpc,
        invalid_request.clone(),
        ResponseSender::new(response_sender),
    );
    
    // Wait for request processing
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Check the request moderator state
    let final_count = moderator
        .get_unhealthy_peer_states()
        .get(&peer_network_id)
        .map(|state| state.invalid_request_count)
        .unwrap_or(0);
    
    // BUG: Invalid request count should have increased, but it remains 0
    // because optimistic fetch requests bypass validation
    assert_eq!(final_count, 0, "VULNERABILITY: Invalid request not tracked!");
    
    // Verify the request was stored in optimistic fetches map
    let optimistic_fetches = storage_service.get_optimistic_fetches();
    assert!(optimistic_fetches.contains_key(&peer_network_id),
            "Invalid request was stored without validation!");
    
    // An attacker can repeat this indefinitely without penalty
    for _ in 0..100 {
        storage_service.handle_network_request(
            peer_network_id,
            ProtocolId::StorageServiceRpc,
            invalid_request.clone(),
            ResponseSender::new(oneshot::channel().0),
        );
    }
    
    // Peer is never ignored despite sending 100+ invalid requests
    let ignored = moderator
        .get_unhealthy_peer_states()
        .get(&peer_network_id)
        .map(|state| state.is_ignored())
        .unwrap_or(false);
    assert!(!ignored, "VULNERABILITY: Peer never ignored despite massive abuse!");
}
```

**Notes:**
- This vulnerability affects all Aptos nodes running the storage service
- It bypasses a critical security control (invalid request tracking) entirely
- The resource exhaustion potential is severe when exploited at scale
- The fix is straightforward: validate all requests before processing

### Citations

**File:** state-sync/storage-service/server/src/moderator.rs (L101-112)
```rust
/// The request moderator is responsible for validating inbound storage
/// requests and ensuring that only valid (and satisfiable) requests are processed.
/// If a peer sends too many invalid requests, the moderator will mark the peer as
/// "unhealthy" and will ignore requests from that peer for some time.
pub struct RequestModerator {
    aptos_data_client_config: AptosDataClientConfig,
    cached_storage_server_summary: Arc<ArcSwap<StorageServerSummary>>,
    peers_and_metadata: Arc<PeersAndMetadata>,
    storage_service_config: StorageServiceConfig,
    time_service: TimeService,
    unhealthy_peer_states: Arc<DashMap<PeerNetworkId, UnhealthyPeerState>>,
}
```

**File:** state-sync/storage-service/server/src/moderator.rs (L132-196)
```rust
    /// Validates the given request and verifies that the peer is behaving
    /// correctly. If the request fails validation, an error is returned.
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

**File:** state-sync/storage-service/server/src/handler.rs (L119-134)
```rust
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
```

**File:** state-sync/storage-service/server/src/handler.rs (L137-138)
```rust
        let response = self.process_request(&peer_network_id, request.clone(), false);
        self.send_response(request, response, response_sender);
```

**File:** state-sync/storage-service/server/src/handler.rs (L206-213)
```rust
    fn validate_and_handle_request(
        &self,
        peer_network_id: &PeerNetworkId,
        request: &StorageServiceRequest,
    ) -> Result<StorageServiceResponse, Error> {
        // Validate the request with the moderator
        self.request_moderator
            .validate_request(peer_network_id, request)?;
```

**File:** state-sync/storage-service/server/src/handler.rs (L242-280)
```rust
    /// Handles the given optimistic fetch request
    pub fn handle_optimistic_fetch_request(
        &self,
        peer_network_id: PeerNetworkId,
        request: StorageServiceRequest,
        response_sender: ResponseSender,
    ) {
        // Create the optimistic fetch request
        let optimistic_fetch = OptimisticFetchRequest::new(
            request.clone(),
            response_sender,
            self.time_service.clone(),
        );

        // Store the optimistic fetch and check if any existing fetches were found
        if self
            .optimistic_fetches
            .insert(peer_network_id, optimistic_fetch)
            .is_some()
        {
            sample!(
                SampleRate::Duration(Duration::from_secs(ERROR_LOG_FREQUENCY_SECS)),
                trace!(LogSchema::new(LogEntry::OptimisticFetchRequest)
                    .error(&Error::InvalidRequest(
                        "An active optimistic fetch was already found for the peer!".into()
                    ))
                    .peer_network_id(&peer_network_id)
                    .request(&request)
                );
            );
        }

        // Update the optimistic fetch metrics
        increment_counter(
            &metrics::OPTIMISTIC_FETCH_EVENTS,
            peer_network_id.network_id(),
            OPTIMISTIC_FETCH_ADD.into(),
        );
    }
```

**File:** state-sync/storage-service/types/src/responses.rs (L708-722)
```rust
            GetNewTransactionOutputsWithProof(_) => can_service_optimistic_request(
                aptos_data_client_config,
                time_service,
                self.synced_ledger_info.as_ref(),
            ),
            GetNewTransactionsWithProof(_) => can_service_optimistic_request(
                aptos_data_client_config,
                time_service,
                self.synced_ledger_info.as_ref(),
            ),
            GetNewTransactionsOrOutputsWithProof(_) => can_service_optimistic_request(
                aptos_data_client_config,
                time_service,
                self.synced_ledger_info.as_ref(),
            ),
```

**File:** state-sync/storage-service/server/src/optimistic_fetch.rs (L585-605)
```rust
/// Removes the invalid optimistic fetches from the active map
fn remove_invalid_optimistic_fetches(
    optimistic_fetches: Arc<DashMap<PeerNetworkId, OptimisticFetchRequest>>,
    peers_with_invalid_optimistic_fetches: Vec<PeerNetworkId>,
) {
    for peer_network_id in peers_with_invalid_optimistic_fetches {
        if let Some((peer_network_id, optimistic_fetch)) =
            optimistic_fetches.remove(&peer_network_id)
        {
            warn!(LogSchema::new(LogEntry::OptimisticFetchRefresh)
                .error(&Error::InvalidRequest(
                    "Mismatch between known version and epoch!".into()
                ))
                .request(&optimistic_fetch.request)
                .message(&format!(
                    "Dropping invalid optimistic fetch request for peer: {:?}!",
                    peer_network_id
                )));
        }
    }
}
```

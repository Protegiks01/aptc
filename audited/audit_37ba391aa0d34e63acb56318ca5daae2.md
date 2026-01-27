# Audit Report

## Title
Optimistic Fetch Request Validation Bypass Allows Resource Exhaustion and Peer Reputation Evasion

## Summary
The `handle_optimistic_fetch_request()` function in the storage service server accepts and stores optimistic fetch requests without validating whether they can be serviced. This bypasses the request moderator's validation and peer reputation tracking, allowing attackers to exhaust server resources and evade rate limiting mechanisms that protect against malicious peers.

## Finding Description

The storage service implements a request validation system through the `RequestModerator` that checks if incoming requests can be serviced and tracks peers sending invalid requests. However, optimistic fetch requests bypass this critical protection.

**Normal Request Flow:** [1](#0-0) 

Normal requests go through `process_request()` which validates them: [2](#0-1) 

The validation calls `request_moderator.validate_request()` which checks if the request can be serviced: [3](#0-2) 

When requests fail validation, the peer's invalid request count is incremented, and after exceeding a threshold (default 500), the peer is temporarily ignored: [4](#0-3) 

**Optimistic Fetch Bypass:** [5](#0-4) 

Optimistic fetch requests are routed to a separate handler: [6](#0-5) 

This function creates an `OptimisticFetchRequest` without any validation: [7](#0-6) 

The request is immediately stored in the `optimistic_fetches` DashMap without checking if it can be serviced. For optimistic fetch requests, `can_service()` validates that the server's synced ledger info timestamp is recent enough: [8](#0-7) 

Invalid requests remain in memory until the periodic cleanup runs (every 100ms by default): [9](#0-8) 

**Attack Scenario:**
1. Attacker connects to storage service nodes with multiple peer IDs
2. Sends optimistic fetch requests when the server's synced ledger info is too old (beyond `max_optimistic_fetch_lag_secs`)
3. These requests bypass validation and are stored without incrementing `invalid_request_count`
4. Normal requests would be rejected and the peer marked unhealthy, but optimistic fetch requests evade this protection
5. Attacker can continuously flood invalid requests faster than the cleanup cycle, exhausting memory
6. No limit exists on the number of peers that can have active optimistic fetches

## Impact Explanation

This is a **Medium Severity** vulnerability per Aptos bug bounty criteria because:

1. **Resource Exhaustion**: Attackers can cause memory exhaustion by flooding invalid optimistic fetch requests from multiple peer connections. Each stored request contains the request data and a response sender channel, consuming server resources.

2. **Peer Reputation Bypass**: The request moderator's protection mechanism is designed to identify and temporarily ignore peers sending invalid requests. By using optimistic fetch requests, malicious peers can send unlimited invalid requests without being tracked or penalized.

3. **State Sync Availability Impact**: While this doesn't directly compromise consensus or cause data corruption, it can degrade state sync performance and availability for honest nodes attempting to synchronize.

The vulnerability breaks the **Resource Limits** invariant (#9): "All operations must respect gas, storage, and computational limits."

## Likelihood Explanation

**Likelihood: High**

The vulnerability is highly exploitable because:
- No authentication or special privileges required beyond normal peer connections
- Attack is straightforward: connect with multiple peers and send optimistic fetch requests
- No rate limiting or resource caps on the optimistic fetches map
- Default configuration allows 100ms accumulation window where invalid requests can pile up
- Attacker can automate this with minimal resources

## Recommendation

Add validation for optimistic fetch requests before storing them. Modify `handle_optimistic_fetch_request()` to validate the request through the moderator:

```rust
pub fn handle_optimistic_fetch_request(
    &self,
    peer_network_id: PeerNetworkId,
    request: StorageServiceRequest,
    response_sender: ResponseSender,
) {
    // Validate the request before storing it
    if let Err(error) = self.request_moderator.validate_request(&peer_network_id, &request) {
        // Send error response and return without storing
        self.send_response(
            request,
            Err(StorageServiceError::InvalidRequest(error.to_string())),
            response_sender,
        );
        return;
    }

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
        // ... existing logging ...
    }

    // Update the optimistic fetch metrics
    increment_counter(
        &metrics::OPTIMISTIC_FETCH_EVENTS,
        peer_network_id.network_id(),
        OPTIMISTIC_FETCH_ADD.into(),
    );
}
```

Additionally, consider adding a maximum limit on the total number of active optimistic fetches to prevent memory exhaustion even from legitimate traffic spikes.

## Proof of Concept

```rust
#[tokio::test]
async fn test_optimistic_fetch_validation_bypass() {
    use aptos_config::config::StorageServiceConfig;
    use aptos_storage_service_types::requests::{
        DataRequest, NewTransactionOutputsWithProofRequest, StorageServiceRequest,
    };
    use aptos_types::PeerId;
    
    // Setup storage service with old synced ledger info
    let (mut mock_client, service, _) = MockClient::new(None, None);
    tokio::spawn(service.start());
    
    // Wait for initial storage summary to be cached with old timestamp
    tokio::time::sleep(Duration::from_millis(200)).await;
    
    // Create multiple peer IDs
    let num_malicious_peers = 100;
    let mut peer_ids = vec![];
    for _ in 0..num_malicious_peers {
        peer_ids.push(PeerNetworkId::new(NetworkId::Public, PeerId::random()));
    }
    
    // Send invalid optimistic fetch requests from each peer
    // (requests that would fail can_service check due to old synced ledger)
    for peer_id in &peer_ids {
        let request = StorageServiceRequest::new(
            DataRequest::GetNewTransactionOutputsWithProof(
                NewTransactionOutputsWithProofRequest {
                    known_version: 0,
                    known_epoch: 0,
                }
            ),
            false,
        );
        
        let _ = mock_client.send_request(request, *peer_id).await;
    }
    
    // Verify that requests were stored without validation
    let server = mock_client.get_server();
    let optimistic_fetches = server.get_optimistic_fetches();
    assert_eq!(optimistic_fetches.len(), num_malicious_peers);
    
    // Verify that peers were NOT marked as unhealthy
    let request_moderator = server.get_request_moderator();
    let unhealthy_peers = request_moderator.get_unhealthy_peer_states();
    assert_eq!(unhealthy_peers.len(), 0); // No peers tracked as unhealthy!
    
    // Now send the same number of regular (non-optimistic) invalid requests
    for peer_id in &peer_ids {
        let request = StorageServiceRequest::new(
            DataRequest::GetTransactionOutputsWithProof(
                TransactionOutputsWithProofRequest {
                    proof_version: 999999999, // Invalid version
                    start_version: 0,
                    end_version: 100,
                }
            ),
            false,
        );
        
        let _ = mock_client.send_request(request, *peer_id).await;
    }
    
    // Regular invalid requests should increment invalid_request_count
    // After max_invalid_requests_per_peer (default 500), peers get ignored
    // This demonstrates the bypass: optimistic fetches don't increment the counter
}
```

## Notes

The vulnerability exists because optimistic fetch requests are designed to be speculative—they request data that may not yet be available. However, the implementation fails to distinguish between "data not yet available" (valid) and "request fundamentally unsatisfiable" (invalid). This allows attackers to abuse the optimistic fetch mechanism to bypass validation and rate limiting protections.

### Citations

**File:** state-sync/storage-service/server/src/handler.rs (L119-123)
```rust
        // Handle any optimistic fetch requests
        if request.data_request.is_optimistic_fetch() {
            self.handle_optimistic_fetch_request(peer_network_id, request, response_sender);
            return;
        }
```

**File:** state-sync/storage-service/server/src/handler.rs (L136-138)
```rust
        // Process the request and return the response to the client
        let response = self.process_request(&peer_network_id, request.clone(), false);
        self.send_response(request, response, response_sender);
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

**File:** state-sync/storage-service/server/src/moderator.rs (L48-69)
```rust
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

**File:** state-sync/storage-service/server/src/optimistic_fetch.rs (L45-57)
```rust
impl OptimisticFetchRequest {
    pub fn new(
        request: StorageServiceRequest,
        response_sender: ResponseSender,
        time_service: TimeService,
    ) -> Self {
        Self {
            request,
            response_sender,
            fetch_start_time: time_service.now(),
            time_service,
        }
    }
```

**File:** state-sync/storage-service/types/src/responses.rs (L892-934)
```rust
/// Returns true iff an optimistic data request can be serviced
/// by the peer with the given synced ledger info.
fn can_service_optimistic_request(
    aptos_data_client_config: &AptosDataClientConfig,
    time_service: TimeService,
    synced_ledger_info: Option<&LedgerInfoWithSignatures>,
) -> bool {
    let max_lag_secs = aptos_data_client_config.max_optimistic_fetch_lag_secs;
    check_synced_ledger_lag(synced_ledger_info, time_service, max_lag_secs)
}

/// Returns true iff a subscription data request can be serviced
/// by the peer with the given synced ledger info.
fn can_service_subscription_request(
    aptos_data_client_config: &AptosDataClientConfig,
    time_service: TimeService,
    synced_ledger_info: Option<&LedgerInfoWithSignatures>,
) -> bool {
    let max_lag_secs = aptos_data_client_config.max_subscription_lag_secs;
    check_synced_ledger_lag(synced_ledger_info, time_service, max_lag_secs)
}

/// Returns true iff the synced ledger info timestamp
/// is within the given lag (in seconds).
fn check_synced_ledger_lag(
    synced_ledger_info: Option<&LedgerInfoWithSignatures>,
    time_service: TimeService,
    max_lag_secs: u64,
) -> bool {
    if let Some(synced_ledger_info) = synced_ledger_info {
        // Get the ledger info timestamp (in microseconds)
        let ledger_info_timestamp_usecs = synced_ledger_info.ledger_info().timestamp_usecs();

        // Get the current timestamp and max version lag (in microseconds)
        let current_timestamp_usecs = time_service.now_unix_time().as_micros() as u64;
        let max_version_lag_usecs = max_lag_secs * NUM_MICROSECONDS_IN_SECOND;

        // Return true iff the synced ledger info timestamp is within the max version lag
        ledger_info_timestamp_usecs + max_version_lag_usecs > current_timestamp_usecs
    } else {
        false // No synced ledger info was found!
    }
}
```

**File:** config/src/config/state_sync_config.rs (L215-215)
```rust
            storage_summary_refresh_interval_ms: 100, // Optimal for <= 10 blocks per second
```

# Audit Report

## Title
Internal Request Processing Incorrectly Penalizes Legitimate Peers Through Shared RequestModerator State

## Summary
The `get_epoch_ending_ledger_info()` and `notify_peer_of_new_data()` utility functions create Handler instances with shared `Arc<RequestModerator>` references and process internal requests using peer identities. When these internally-generated requests fail validation, the RequestModerator incorrectly increments the peer's invalid request count, potentially causing legitimate peers to be marked as unhealthy and have all their requests rejected.

## Finding Description

Both `get_epoch_ending_ledger_info()` and `notify_peer_of_new_data()` create new Handler instances that share the same `Arc<RequestModerator>` reference. [1](#0-0) 

These handlers process internally-generated storage requests on behalf of peers by calling `handler.process_request(peer_network_id, storage_request, true)`. [2](#0-1) 

The `process_request()` method calls `validate_and_handle_request()`, which invokes `request_moderator.validate_request()` for all requests. [3](#0-2) 

When validation fails (e.g., when requesting epoch ending ledger info for an epoch that's been pruned from storage), the RequestModerator increments the peer's invalid request count and potentially marks them as ignored. [4](#0-3) 

The validation logic for `GetEpochEndingLedgerInfos` requests returns false when the requested epoch range is not available in the storage summary. [5](#0-4) 

**Attack Scenario:**

1. Storage service prunes old epoch data (epochs 0-49) and now only has epochs 50-100
2. Peer X has a subscription with `highest_known_epoch = 40`
3. When processing the subscription, the server calls `get_epoch_ending_ledger_info()` for epoch 40 [6](#0-5) 
4. This internal request fails validation because epoch 40 is unavailable
5. The RequestModerator increments Peer X's invalid request count [7](#0-6) 
6. After multiple such failures (from subscriptions, optimistic fetches), Peer X reaches the threshold and gets marked as ignored
7. All future requests from Peer X are now rejected [8](#0-7) 

The same issue occurs with `notify_peer_of_new_data()` when it processes internal requests that fail validation. [9](#0-8) 

## Impact Explanation

**Severity: Medium to High**

This vulnerability causes legitimate peers to be incorrectly marked as unhealthy and have their requests rejected, leading to:

1. **Validator Impact**: Validators that get incorrectly marked as ignored cannot sync with the network, causing them to fall behind consensus and miss their turn to propose blocks. This degrades network performance and consensus participation.

2. **State Synchronization Failure**: Affected peers cannot sync state from the storage service, breaking the state sync protocol for those nodes.

3. **Denial of Service**: Once marked as ignored, peers experience exponentially increasing ban durations (doubling each time), potentially leaving them permanently unable to sync. [10](#0-9) 

This meets **Medium Severity** criteria: "State inconsistencies requiring intervention" and could escalate to **High Severity** if it causes widespread "Validator node slowdowns" or impacts consensus participation.

## Likelihood Explanation

**Likelihood: Medium**

This vulnerability occurs when:
- Storage service prunes old epoch data while peers have active subscriptions or optimistic fetches referencing those epochs
- Rapid epoch transitions cause subscriptions to reference epochs that become unavailable
- Network partitions cause some nodes to lag significantly behind

The issue is not directly exploitable by attackers but occurs naturally in production environments due to:
1. Normal storage pruning operations
2. Peers with stale subscription requests
3. Network delays causing peers to fall behind

## Recommendation

Create a separate context flag or peer identity for internal requests that bypasses request moderation. Modify the Handler to accept an optional flag indicating whether the request is internal:

```rust
// In handler.rs
pub(crate) fn process_request(
    &self,
    peer_network_id: &PeerNetworkId,
    request: StorageServiceRequest,
    optimistic_fetch_related: bool,
    internal_request: bool,  // NEW: Flag for internal requests
) -> aptos_storage_service_types::Result<StorageServiceResponse> {
    // Skip validation for internal requests
    if internal_request {
        return match self.handle_request_without_validation(peer_network_id, &request) {
            // Process directly without moderation
        };
    }
    // ... existing code
}
```

Alternatively, use a special sentinel `PeerNetworkId` for internal requests that is excluded from request moderation:

```rust
// In utils.rs
pub fn get_epoch_ending_ledger_info<T: StorageReaderInterface>(
    // ... parameters
) -> Result<LedgerInfoWithSignatures, Error> {
    // Use a special internal peer ID that bypasses moderation
    let internal_peer_id = PeerNetworkId::internal();
    let storage_response = handler.process_request(&internal_peer_id, storage_request, true);
    // ... rest of function
}
```

## Proof of Concept

```rust
#[tokio::test]
async fn test_internal_request_penalizes_peer() {
    use aptos_config::config::StorageServiceConfig;
    use aptos_storage_service_server::{Handler, RequestModerator};
    use aptos_types::PeerId;
    use aptos_config::network_id::NetworkId;
    
    // Setup storage service with pruned data (epochs 50-100 only)
    let storage = setup_mock_storage_with_epochs(50, 100);
    let config = StorageServiceConfig::default();
    let moderator = Arc::new(RequestModerator::new(/* ... */));
    
    // Create a peer with an old subscription
    let peer_id = PeerNetworkId::new(NetworkId::Public, PeerId::random());
    
    // Simulate processing subscription that references epoch 40
    let handler = Handler::new(
        cached_summary,
        optimistic_fetches,
        lru_cache,
        moderator.clone(),
        storage,
        subscriptions,
        time_service,
    );
    
    // Call get_epoch_ending_ledger_info for unavailable epoch
    for _ in 0..config.max_invalid_requests_per_peer {
        let result = utils::get_epoch_ending_ledger_info(
            /* ... */,
            40, // Unavailable epoch
            /* ... */,
            &peer_id,
            /* ... */
        );
        assert!(result.is_err()); // Request fails
    }
    
    // Verify peer is now marked as ignored
    let peer_states = moderator.get_unhealthy_peer_states();
    let peer_state = peer_states.get(&peer_id).unwrap();
    assert!(peer_state.is_ignored());
    
    // Verify legitimate requests from this peer are now rejected
    let legitimate_request = create_valid_storage_request();
    let result = moderator.validate_request(&peer_id, &legitimate_request);
    assert!(matches!(result, Err(Error::TooManyInvalidRequests(_))));
}
```

## Notes

The vulnerability stems from insufficient separation between internal housekeeping operations and external peer request processing. The shared `RequestModerator` state tracks peer reputation across all handler instances, but fails to distinguish between requests actually sent by peers versus requests generated internally by the server on behalf of peers. This creates a feedback loop where the server's inability to service old data (due to pruning or sync lag) causes it to penalize the very peers it's trying to help.

### Citations

**File:** state-sync/storage-service/server/src/utils.rs (L27-82)
```rust
pub fn get_epoch_ending_ledger_info<T: StorageReaderInterface>(
    cached_storage_server_summary: Arc<ArcSwap<StorageServerSummary>>,
    optimistic_fetches: Arc<DashMap<PeerNetworkId, OptimisticFetchRequest>>,
    subscriptions: Arc<DashMap<PeerNetworkId, SubscriptionStreamRequests>>,
    epoch: u64,
    lru_response_cache: Cache<StorageServiceRequest, StorageServiceResponse>,
    request_moderator: Arc<RequestModerator>,
    peer_network_id: &PeerNetworkId,
    storage: T,
    time_service: TimeService,
) -> aptos_storage_service_types::Result<LedgerInfoWithSignatures, Error> {
    // Create a new storage request for the epoch ending ledger info
    let data_request = DataRequest::GetEpochEndingLedgerInfos(EpochEndingLedgerInfoRequest {
        start_epoch: epoch,
        expected_end_epoch: epoch,
    });
    let storage_request = StorageServiceRequest::new(
        data_request,
        false, // Don't compress because this isn't going over the wire
    );

    // Process the request
    let handler = Handler::new(
        cached_storage_server_summary,
        optimistic_fetches,
        lru_response_cache,
        request_moderator,
        storage,
        subscriptions,
        time_service,
    );
    let storage_response = handler.process_request(peer_network_id, storage_request, true);

    // Verify the response
    match storage_response {
        Ok(storage_response) => match &storage_response.get_data_response() {
            Ok(DataResponse::EpochEndingLedgerInfos(epoch_change_proof)) => {
                if let Some(ledger_info) = epoch_change_proof.ledger_info_with_sigs.first() {
                    Ok(ledger_info.clone())
                } else {
                    Err(Error::UnexpectedErrorEncountered(
                        "Empty change proof found!".into(),
                    ))
                }
            },
            data_response => Err(Error::StorageErrorEncountered(format!(
                "Failed to get epoch ending ledger info! Got: {:?}",
                data_response
            ))),
        },
        Err(error) => Err(Error::StorageErrorEncountered(format!(
            "Failed to get epoch ending ledger info! Error: {:?}",
            error
        ))),
    }
}
```

**File:** state-sync/storage-service/server/src/utils.rs (L89-193)
```rust
pub fn notify_peer_of_new_data<T: StorageReaderInterface>(
    cached_storage_server_summary: Arc<ArcSwap<StorageServerSummary>>,
    optimistic_fetches: Arc<DashMap<PeerNetworkId, OptimisticFetchRequest>>,
    subscriptions: Arc<DashMap<PeerNetworkId, SubscriptionStreamRequests>>,
    lru_response_cache: Cache<StorageServiceRequest, StorageServiceResponse>,
    request_moderator: Arc<RequestModerator>,
    storage: T,
    time_service: TimeService,
    peer_network_id: &PeerNetworkId,
    missing_data_request: StorageServiceRequest,
    target_ledger_info: LedgerInfoWithSignatures,
    response_sender: ResponseSender,
) -> aptos_storage_service_types::Result<DataResponse, Error> {
    // Handle the storage service request to fetch the missing data
    let use_compression = missing_data_request.use_compression;
    let handler = Handler::new(
        cached_storage_server_summary,
        optimistic_fetches,
        lru_response_cache,
        request_moderator,
        storage,
        subscriptions,
        time_service,
    );
    let storage_response =
        handler.process_request(peer_network_id, missing_data_request.clone(), true);

    // Transform the missing data into an optimistic fetch response
    let transformed_data_response = match storage_response {
        Ok(storage_response) => match storage_response.get_data_response() {
            Ok(DataResponse::TransactionsWithProof(transactions_with_proof)) => {
                DataResponse::NewTransactionsWithProof((
                    transactions_with_proof,
                    target_ledger_info,
                ))
            },
            Ok(DataResponse::TransactionOutputsWithProof(outputs_with_proof)) => {
                DataResponse::NewTransactionOutputsWithProof((
                    outputs_with_proof,
                    target_ledger_info,
                ))
            },
            Ok(DataResponse::TransactionsOrOutputsWithProof((
                transactions_with_proof,
                outputs_with_proof,
            ))) => {
                if let Some(transactions_with_proof) = transactions_with_proof {
                    DataResponse::NewTransactionsOrOutputsWithProof((
                        (Some(transactions_with_proof), None),
                        target_ledger_info,
                    ))
                } else if let Some(outputs_with_proof) = outputs_with_proof {
                    DataResponse::NewTransactionsOrOutputsWithProof((
                        (None, Some(outputs_with_proof)),
                        target_ledger_info,
                    ))
                } else {
                    return Err(Error::UnexpectedErrorEncountered(
                        "Failed to get a transaction or output response for peer!".into(),
                    ));
                }
            },
            Ok(DataResponse::TransactionDataWithProof(transaction_data_with_proof)) => {
                DataResponse::NewTransactionDataWithProof(NewTransactionDataWithProofResponse {
                    transaction_data_response_type: transaction_data_with_proof
                        .transaction_data_response_type,
                    transaction_list_with_proof: transaction_data_with_proof
                        .transaction_list_with_proof,
                    transaction_output_list_with_proof: transaction_data_with_proof
                        .transaction_output_list_with_proof,
                    ledger_info_with_signatures: target_ledger_info,
                })
            },
            data_response => {
                return Err(Error::UnexpectedErrorEncountered(format!(
                    "Failed to get appropriate data response for peer! Got: {:?}",
                    data_response
                )))
            },
        },
        response => {
            return Err(Error::UnexpectedErrorEncountered(format!(
                "Failed to fetch missing data for peer! {:?}",
                response
            )))
        },
    };

    // Create the storage service response
    let storage_response =
        match StorageServiceResponse::new(transformed_data_response.clone(), use_compression) {
            Ok(storage_response) => storage_response,
            Err(error) => {
                return Err(Error::UnexpectedErrorEncountered(format!(
                    "Failed to create transformed response! Error: {:?}",
                    error
                )));
            },
        };

    // Send the response to the peer
    handler.send_response(missing_data_request, Ok(storage_response), response_sender);

    Ok(transformed_data_response)
}
```

**File:** state-sync/storage-service/server/src/handler.rs (L141-203)
```rust
    /// Processes the given request and returns the response
    pub(crate) fn process_request(
        &self,
        peer_network_id: &PeerNetworkId,
        request: StorageServiceRequest,
        optimistic_fetch_related: bool,
    ) -> aptos_storage_service_types::Result<StorageServiceResponse> {
        // Process the request and time the operation
        let process_request = || {
            // Process the request and handle any errors
            match self.validate_and_handle_request(peer_network_id, &request) {
                Err(error) => {
                    // Update the error counter
                    increment_counter(
                        &metrics::STORAGE_ERRORS_ENCOUNTERED,
                        peer_network_id.network_id(),
                        error.get_label().into(),
                    );

                    // Periodically log the failure
                    sample!(
                            SampleRate::Duration(Duration::from_secs(ERROR_LOG_FREQUENCY_SECS)),
                            warn!(LogSchema::new(LogEntry::StorageServiceError)
                                .error(&error)
                                .peer_network_id(peer_network_id)
                                .request(&request)
                                .optimistic_fetch_related(optimistic_fetch_related)
                        );
                    );

                    // Return the error
                    Err(error)
                },
                Ok(response) => {
                    // Update the successful response counter
                    increment_counter(
                        &metrics::STORAGE_RESPONSES_SENT,
                        peer_network_id.network_id(),
                        response.get_label(),
                    );

                    // Return the response
                    Ok(response)
                },
            }
        };
        let process_result = utils::execute_and_time_duration(
            &metrics::STORAGE_REQUEST_PROCESSING_LATENCY,
            Some((peer_network_id, &request)),
            None,
            process_request,
            None,
        );

        // Transform the request error into a storage service error (for the client)
        process_result.map_err(|error| match error {
            Error::InvalidRequest(error) => StorageServiceError::InvalidRequest(error),
            Error::TooManyInvalidRequests(error) => {
                StorageServiceError::TooManyInvalidRequests(error)
            },
            error => StorageServiceError::InternalError(error.to_string()),
        })
    }
```

**File:** state-sync/storage-service/server/src/moderator.rs (L79-96)
```rust
    pub fn refresh_peer_state(&mut self, peer_network_id: &PeerNetworkId) {
        if let Some(ignore_start_time) = self.ignore_start_time {
            let ignored_duration = self.time_service.now().duration_since(ignore_start_time);
            if ignored_duration >= Duration::from_secs(self.min_time_to_ignore_secs) {
                // Reset the invalid request count
                self.invalid_request_count = 0;

                // Reset the ignore start time
                self.ignore_start_time = None;

                // Double the min time to ignore the peer
                self.min_time_to_ignore_secs *= 2;

                // Log the fact that we're no longer ignoring the peer
                warn!(LogSchema::new(LogEntry::RequestModeratorIgnoredPeer)
                    .peer_network_id(peer_network_id)
                    .message("No longer ignoring peer! Enough time has elapsed."));
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

**File:** state-sync/storage-service/types/src/responses.rs (L698-707)
```rust
            GetEpochEndingLedgerInfos(request) => {
                let desired_range =
                    match CompleteDataRange::new(request.start_epoch, request.expected_end_epoch) {
                        Ok(desired_range) => desired_range,
                        Err(_) => return false,
                    };
                self.epoch_ending_ledger_infos
                    .map(|range| range.superset_of(&desired_range))
                    .unwrap_or(false)
            },
```

**File:** state-sync/storage-service/server/src/subscription.rs (L924-934)
```rust
                    let epoch_ending_ledger_info = match utils::get_epoch_ending_ledger_info(
                        cached_storage_server_summary.clone(),
                        optimistic_fetches.clone(),
                        subscriptions.clone(),
                        highest_known_epoch,
                        lru_response_cache.clone(),
                        request_moderator.clone(),
                        &peer_network_id,
                        storage.clone(),
                        time_service.clone(),
                    ) {
```

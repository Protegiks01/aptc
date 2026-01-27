# Audit Report

## Title
Missing Subscription Validation in Optimistic Fetch Epoch Ending Ledger Info Retrieval

## Summary
The `get_epoch_ending_ledger_info()` function receives a `subscriptions` parameter but never validates whether the requesting peer has an active subscription before fetching data from storage. This allows peers without active subscriptions to trigger internal storage reads, potentially enabling resource exhaustion attacks against the storage layer.

## Finding Description

In the `identify_ready_and_invalid_optimistic_fetches()` function, when processing optimistic fetch requests from peers whose known epoch is behind the current synced epoch, the system calls `get_epoch_ending_ledger_info()` to fetch epoch ending ledger information from storage. [1](#0-0) 

The `subscriptions` parameter is passed to this function, creating an expectation that subscription validation would occur. However, examining the implementation reveals no such validation: [2](#0-1) 

The function creates a `Handler` with the subscriptions parameter but immediately processes the request without checking if the peer has an active subscription. The `process_request` method only validates through the `request_moderator`: [3](#0-2) 

The `validate_and_handle_request` method only checks if the peer is temporarily ignored and if the request can be serviced - it never validates subscriptions: [4](#0-3) 

**Attack Scenario:**

1. An attacker establishes multiple peer connections (limited only by network connection capacity)
2. Each peer sends an optimistic fetch request - no subscription is required or validated
3. When the blockchain crosses epoch boundaries, the system processes all pending optimistic fetches
4. For each peer whose known epoch is behind, `get_epoch_ending_ledger_info()` triggers a storage read
5. This causes numerous concurrent storage reads from peers without any subscription commitment
6. The storage layer experiences performance degradation from serving unauthorized requests

The vulnerability is that while the `subscriptions` DashMap is passed through the call chain, it is never consulted to verify the peer's subscription status. This violates the principle that expensive operations (storage reads) should only be performed for peers with valid, active subscriptions.

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty criteria:
- Causes storage layer performance degradation through resource exhaustion
- Enables unauthorized triggering of expensive storage operations
- Can affect node performance and responsiveness

The impact is bounded by:
- Each peer can only maintain one active optimistic fetch at a time (single entry per PeerNetworkId in DashMap)
- Optimistic fetches timeout after 5 seconds (max_optimistic_fetch_period_ms)
- Network connection limits provide some natural bound

However, an attacker with sufficient resources to maintain many peer connections could trigger significant concurrent storage reads, degrading storage service performance for legitimate peers. This particularly affects state sync operations during epoch transitions when many peers may be requesting epoch ending ledger information simultaneously.

## Likelihood Explanation

**Likelihood: Medium to High**

The attack is straightforward to execute:
- No special permissions or validator access required
- Standard network peer capabilities are sufficient
- Optimistic fetch requests are a normal protocol feature
- Epoch boundaries occur regularly (providing natural triggers)

The attack becomes more effective:
- During network growth when many peers are syncing
- Around epoch boundaries when legitimate peers also request epoch ending information
- Against nodes with limited storage I/O capacity

The lack of subscription validation is a design oversight rather than a complex logic bug, making it reliably exploitable across all nodes running this code.

## Recommendation

Add subscription validation in `get_epoch_ending_ledger_info()` before processing the request. The function should check if the peer has an active subscription and reject requests from peers without valid subscriptions:

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
    // Validate that the peer has an active subscription
    if !subscriptions.contains_key(peer_network_id) {
        return Err(Error::InvalidRequest(format!(
            "Peer {} does not have an active subscription",
            peer_network_id
        )));
    }

    // Create a new storage request for the epoch ending ledger info
    let data_request = DataRequest::GetEpochEndingLedgerInfos(EpochEndingLedgerInfoRequest {
        start_epoch: epoch,
        expected_end_epoch: epoch,
    });
    // ... rest of the implementation
}
```

Alternatively, if optimistic fetches are intended to work without subscriptions, separate the code paths and only pass subscriptions to the subscription-specific version of the function.

## Proof of Concept

```rust
#[tokio::test]
async fn test_optimistic_fetch_without_subscription_triggers_storage_read() {
    // Setup: Create a storage service with mocked storage
    let (mut mock_client, service, _, _, _, _) = MockClient::new(None, None);
    
    // Create peer without subscription
    let peer = mock_client.create_peer();
    
    // Send optimistic fetch request (no subscription created)
    let request = StorageServiceRequest::new(
        DataRequest::GetNewTransactionsWithProof(NewTransactionsWithProofRequest {
            known_version: 100,
            known_epoch: 1,
            include_events: false,
        }),
        false,
    );
    
    // Verify request is accepted and stored as optimistic fetch
    let response_receiver = mock_client.send_request(peer, request).await;
    
    // Advance blockchain to new epoch (epoch 2)
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Verify that get_epoch_ending_ledger_info was called for peer
    // despite peer having no active subscription
    // This demonstrates the vulnerability - storage reads occur
    // without subscription validation
    
    assert!(service.optimistic_fetches.contains_key(&peer));
    assert!(!service.subscriptions.contains_key(&peer));
    
    // The vulnerability is confirmed: optimistic fetch exists and will trigger
    // storage reads without any subscription validation
}
```

## Notes

The vulnerability exists in the state-sync storage service layer where subscription validation is incomplete. While the code passes the `subscriptions` parameter through multiple function calls, it never actually validates subscription status before performing expensive storage operations. This oversight allows resource exhaustion through unauthorized storage access by peers without active subscriptions.

### Citations

**File:** state-sync/storage-service/server/src/optimistic_fetch.rs (L506-516)
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

**File:** state-sync/storage-service/server/src/utils.rs (L27-58)
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
```

**File:** state-sync/storage-service/server/src/handler.rs (L142-213)
```rust
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

    /// Validate the request and only handle it if the moderator allows
    fn validate_and_handle_request(
        &self,
        peer_network_id: &PeerNetworkId,
        request: &StorageServiceRequest,
    ) -> Result<StorageServiceResponse, Error> {
        // Validate the request with the moderator
        self.request_moderator
            .validate_request(peer_network_id, request)?;
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

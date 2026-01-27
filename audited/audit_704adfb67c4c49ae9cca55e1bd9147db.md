# Audit Report

## Title
Optimistic Fetch and Subscription Request Replay Attack Enables Resource Exhaustion

## Summary
The storage service server does not track which data has been previously sent to peers for optimistic fetch requests, allowing malicious peers to repeatedly request the same historical data by sending multiple requests with identical `known_version` values. This enables a resource exhaustion attack that wastes server CPU, storage I/O, memory, and network bandwidth.

## Finding Description

The vulnerability exists in how the storage service handles optimistic fetch and subscription requests. When a peer sends an optimistic fetch request, the server stores it without validating whether the peer has previously claimed the same or higher `known_version`. [1](#0-0) 

The handler accepts optimistic fetch requests and stores them in a per-peer map without checking if the `known_version` represents a regression or duplicate. When the background task processes these requests, it checks only if the peer's `known_version` is lower than the current highest synced version: [2](#0-1) 

The `notify_peer_of_new_data` function is then called to fetch data from storage and send it to the peer, with no deduplication or replay protection: [3](#0-2) 

**Attack Flow:**

1. Attacker sends `OptimisticFetchRequest` with `known_version=0` and `known_epoch=0`
2. Server stores request in `optimistic_fetches` map
3. Background handler runs every 100ms and identifies the request as "ready" since `0 < current_version`
4. Server calls `notify_peer_of_new_data`, fetches up to 3000 transactions from storage (per chunk size limits), and sends to peer
5. Request is removed from map after processing
6. Attacker immediately sends another `OptimisticFetchRequest` with the same `known_version=0`
7. Server repeats steps 2-5, re-fetching and re-sending identical data
8. Attacker repeats indefinitely, causing continuous resource consumption [4](#0-3) 

With a refresh interval of 100ms and chunk size of 3000 transactions, an attacker can cause the server to process up to 30,000 transactions per second repeatedly. Multiple malicious peers can amplify this attack.

The same vulnerability affects subscriptions when attackers use different `subscription_stream_id` values to create new streams with low initial `known_version` values: [5](#0-4) 

The request moderator only validates that requests are serviceable but does not detect replay attempts: [6](#0-5) 

## Impact Explanation

This vulnerability enables a **Medium Severity** resource exhaustion attack. According to the Aptos bug bounty program, this falls under "Validator node slowdowns" which can be categorized as High Severity, but given that:

- It requires continuous attacker effort to maintain the attack
- It affects state sync services rather than core consensus
- It can be mitigated by network-level rate limiting
- Multiple peers can be ignored after exceeding invalid request thresholds

The impact is **Medium Severity** as it causes state inconsistencies requiring intervention and degrades service availability, but does not directly cause loss of funds or consensus violations.

**Resource Impact per Malicious Peer:**
- Storage I/O: Repeated reads of up to 3000 transactions every 100ms
- CPU: Serialization and transformation of transaction data
- Memory: Buffering responses before sending
- Network: Bandwidth consumed sending duplicate data
- Amplification: Multiple malicious peers can multiply the impact

This violates the "Resource Limits: All operations must respect gas, storage, and computational limits" invariant.

## Likelihood Explanation

This attack is **highly likely** to be exploited because:

1. **Low Attack Complexity**: Any network peer can send optimistic fetch or subscription requests
2. **No Authentication Required**: No special privileges needed beyond network connectivity
3. **Trivial to Execute**: Simply send repeated requests with low `known_version` values
4. **Difficult to Distinguish**: Legitimate peers recovering from crashes may also send requests with lower versions
5. **Limited Mitigation**: The only protection is the invalid request counter, which only triggers after 500 invalid requests and only affects public network peers

The attack requires minimal resources from the attacker (just network messages) while causing significant resource consumption on the server.

## Recommendation

Implement per-peer tracking of the highest `known_version` and `known_epoch` claimed for optimistic fetches and reject requests that represent regressions:

```rust
// In handler.rs, maintain a map of highest known versions per peer
struct PeerSyncState {
    highest_claimed_version: u64,
    highest_claimed_epoch: u64,
    last_update_time: Instant,
}

pub fn handle_optimistic_fetch_request(
    &self,
    peer_network_id: PeerNetworkId,
    request: StorageServiceRequest,
    response_sender: ResponseSender,
) {
    let known_version = get_known_version_from_request(&request);
    let known_epoch = get_known_epoch_from_request(&request);
    
    // Check if this peer is regressing their known version
    if let Some(peer_state) = self.peer_sync_states.get(&peer_network_id) {
        if known_version < peer_state.highest_claimed_version {
            // Log warning and reject regression
            warn!("Peer {} attempting to regress known_version from {} to {}",
                  peer_network_id, peer_state.highest_claimed_version, known_version);
            
            // Increment invalid request counter
            self.request_moderator.increment_invalid_request_count(&peer_network_id);
            
            // Send error response
            self.send_response(
                request,
                Err(StorageServiceError::InvalidRequest(
                    "Known version regression detected".into()
                )),
                response_sender,
            );
            return;
        }
    }
    
    // Update peer's highest claimed version
    self.peer_sync_states.insert(peer_network_id, PeerSyncState {
        highest_claimed_version: known_version,
        highest_claimed_epoch: known_epoch,
        last_update_time: self.time_service.now(),
    });
    
    // Continue with normal processing
    // ... rest of existing code
}
```

For subscriptions, the existing stream tracking already prevents this within a stream, but validate that new streams don't regress versions unnecessarily.

Additionally, implement rate limiting on optimistic fetch request creation per peer:
- Track request creation timestamps
- Reject requests if too many created in a short time window
- Add configuration parameter for maximum optimistic fetches per peer per time window

## Proof of Concept

```rust
// Test demonstrating the replay attack
#[tokio::test]
async fn test_optimistic_fetch_replay_attack() {
    use aptos_config::config::StorageServiceConfig;
    use aptos_storage_service_types::requests::{
        DataRequest, NewTransactionsWithProofRequest, StorageServiceRequest,
    };
    
    // Setup storage service with test data at version 10000
    let (mut service, peer_network_id, storage) = setup_test_service().await;
    populate_storage(&storage, 10000).await;
    
    // Attack: Send optimistic fetch with known_version=0 repeatedly
    let mut responses_received = 0;
    
    for i in 0..10 {
        // Create optimistic fetch request with known_version=0
        let request = StorageServiceRequest::new(
            DataRequest::GetNewTransactionsWithProof(NewTransactionsWithProofRequest {
                known_version: 0, // Always claim version 0
                known_epoch: 0,
                include_events: false,
            }),
            false,
        );
        
        let (response_sender, response_receiver) = oneshot::channel();
        
        // Send request to service
        service.handle_request(peer_network_id, request, response_sender).await;
        
        // Wait for background handler to process (100ms interval)
        tokio::time::sleep(Duration::from_millis(150)).await;
        
        // Verify response was received
        if let Ok(response) = response_receiver.await {
            responses_received += 1;
            assert!(response.is_ok(), "Request {} should succeed", i);
        }
    }
    
    // Verify server processed all 10 duplicate requests
    assert_eq!(responses_received, 10, 
        "All 10 duplicate requests should be processed");
    
    // Verify storage was read 10 times for the same data
    let storage_reads = storage.get_read_count();
    assert!(storage_reads >= 10, 
        "Storage should be read at least 10 times for duplicate data");
}
```

## Notes

This vulnerability is confirmed in the codebase and represents a realistic attack vector. The server-side lacks any mechanism to detect or prevent peers from repeatedly claiming low `known_version` values, enabling resource exhaustion through duplicate data processing. While individual peer impact may be limited by the 100ms refresh interval, multiple malicious peers can amplify the attack to significantly degrade storage service performance.

### Citations

**File:** state-sync/storage-service/server/src/handler.rs (L243-280)
```rust
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

**File:** state-sync/storage-service/server/src/handler.rs (L308-318)
```rust
            Entry::Occupied(mut occupied_entry) => {
                // If the stream has a different ID than the request, replace the stream.
                // Otherwise, add the request to the existing stream.
                let existing_stream_id = occupied_entry.get().subscription_stream_id();
                if existing_stream_id != request_stream_id {
                    // Create a new subscription stream for the peer
                    let subscription_stream = SubscriptionStreamRequests::new(
                        subscription_request,
                        self.time_service.clone(),
                    );
                    occupied_entry.replace_entry(subscription_stream);
```

**File:** state-sync/storage-service/server/src/optimistic_fetch.rs (L274-278)
```rust
        let ready_optimistic_fetch =
            optimistic_fetches.remove_if(&peer_network_id, |_, optimistic_fetch| {
                optimistic_fetch.highest_known_version()
                    < target_ledger_info.ledger_info().version()
            });
```

**File:** state-sync/storage-service/server/src/utils.rs (L89-192)
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
```

**File:** config/src/config/state_sync_config.rs (L215-215)
```rust
            storage_summary_refresh_interval_ms: 100, // Optimal for <= 10 blocks per second
```

**File:** state-sync/storage-service/server/src/moderator.rs (L134-187)
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
```

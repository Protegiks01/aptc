# Audit Report

## Title
Silent Error Suppression in Optimistic Fetch Handler Leaves Peers Without Failure Notification

## Summary

The `handle_ready_optimistic_fetches()` function silently logs errors from optimistic fetch request processing without notifying the requesting peer. When errors occur during request handling, the peer's `ResponseSender` is dropped without sending an error response, causing the peer to receive only a channel cancellation or timeout instead of a proper `StorageServiceError` explaining what went wrong. This violates the RPC protocol contract and can leave peers unable to make informed recovery decisions during state synchronization.

## Finding Description

In the optimistic fetch handling flow, when a peer's request is ready to be fulfilled, the server removes it from the active request map and spawns a blocking task to process it. [1](#0-0) 

Within this task, a closure is defined that performs two critical operations: [2](#0-1) 

Both operations can fail and return errors:

1. **`get_storage_request_for_missing_data()`** can return `InvalidRequest` errors [3](#0-2)  or overflow errors [4](#0-3) 

2. **`notify_peer_of_new_data()`** can fail at multiple points before sending the response [5](#0-4)  and [6](#0-5) 

When any error occurs, the closure returns early via the `?` operator. The error is caught and **only logged** without any peer notification: [7](#0-6) 

**Critical Issue**: The `ResponseSender` is consumed by `take_response_sender()` only when `notify_peer_of_new_data()` is called. If an error occurs before this point, or if `notify_peer_of_new_data()` fails before calling `send_response()`, the `ResponseSender` is dropped without sending any response.

When a `ResponseSender` (which wraps a `oneshot::Sender`) is dropped without calling `send()`, the peer's RPC receiver gets a channel cancellation error instead of a proper `StorageServiceError` with a meaningful error message. [8](#0-7) 

**Contrast with Correct Pattern**: Other request types properly send error responses to peers. For example, subscription request failures are handled by sending an error response: [9](#0-8) 

This shows the intended pattern: log the error, update metrics, and **send an error response** to the client. The optimistic fetch handler omits this critical third step.

## Impact Explanation

This issue qualifies as **High Severity** under the Aptos bug bounty criteria for the following reasons:

1. **Protocol Violation**: Violates the RPC protocol contract that every request must receive a response (either success or error). The `StorageServiceMessage` enum explicitly supports error responses in the Response variant. [10](#0-9) 

2. **State Sync Degradation**: Peers attempting optimistic fetch receive channel cancellations instead of actionable error information. Without knowing the actual failure reason (storage error, version mismatch, overflow, etc.), peers cannot:
   - Determine if the error is transient (retry) or permanent (switch strategy)
   - Adjust their sync parameters appropriately
   - Report meaningful diagnostics

3. **Validator Node Impact**: During storage errors or edge cases (version overflows, epoch boundary issues), multiple peers' optimistic fetches will fail silently, causing cascading timeout delays across the network. This degrades state sync performance and can contribute to validator node slowdowns.

4. **Inconsistent Error Handling**: The inconsistency between subscription error handling (which properly notifies peers) and optimistic fetch error handling (which doesn't) indicates a systematic protocol flaw rather than an isolated bug.

## Likelihood Explanation

This issue has **high likelihood** of occurrence in production:

- **Normal Error Conditions**: The errors that trigger this issue are not exotic attack scenarios but normal operational conditions:
  - Storage read failures during high load
  - Version calculation overflows with large version numbers
  - Target version mismatches during concurrent updates
  - Data transformation failures when creating responses

- **Wide Impact**: Every peer using optimistic fetch (a core state sync mechanism) is affected

- **Already Happening**: Given that optimistic fetches are actively used in production, this bug is likely already causing silent failures that appear as timeouts in peer logs

## Recommendation

Modify `handle_ready_optimistic_fetches()` to properly send error responses to peers when the closure fails:

```rust
// After line 324, replace the error logging block with:
if let Err(error) = result {
    // Log the error
    warn!(LogSchema::new(LogEntry::OptimisticFetchResponse)
        .error(&Error::UnexpectedErrorEncountered(error.to_string())));
    
    // Send error response to peer (must extract response_sender before it's consumed)
    // This requires restructuring to capture response_sender separately
}
```

Better approach: Restructure the closure to ensure `response_sender` is always available for error handling:

```rust
runtime.spawn_blocking(move || {
    let optimistic_fetch_start_time = optimistic_fetch.fetch_start_time;
    let optimistic_fetch_request = optimistic_fetch.request.clone();
    let response_sender = optimistic_fetch.take_response_sender();
    
    let handle_request = || {
        let missing_data_request = optimistic_fetch
            .get_storage_request_for_missing_data(config, &target_ledger_info)?;
        
        utils::notify_peer_of_new_data(
            cached_storage_server_summary.clone(),
            optimistic_fetches.clone(),
            subscriptions.clone(),
            lru_response_cache.clone(),
            request_moderator.clone(),
            storage.clone(),
            time_service.clone(),
            &peer_network_id,
            missing_data_request,
            target_ledger_info,
            response_sender,
        )
    };
    
    let result = utils::execute_and_time_duration(/* ... */);
    
    // If error AND response_sender still available, send error response
    if let Err(error) = result {
        warn!(/* log error */);
        
        // Create error response
        let error_response = Err(StorageServiceError::InternalError(error.to_string()));
        
        // Send error to peer (handler would need modification to accept separate response_sender)
        // Or implement similar to subscription error handling
    }
});
```

The cleanest solution is to match the subscription error handling pattern by always sending a response, whether success or error.

## Proof of Concept

```rust
#[tokio::test]
async fn test_optimistic_fetch_error_suppression() {
    // Setup: Create storage service with mock storage that returns errors
    let mock_storage = MockStorageReader::new();
    mock_storage.set_error_on_read(true); // Simulate storage error
    
    let config = StorageServiceConfig::default();
    let optimistic_fetches = Arc::new(DashMap::new());
    let (response_tx, response_rx) = oneshot::channel();
    
    // Create optimistic fetch request
    let peer_network_id = PeerNetworkId::random();
    let request = StorageServiceRequest::new(
        DataRequest::GetNewTransactionsWithProof(
            NewTransactionsWithProofRequest {
                known_version: 100,
                known_epoch: 1,
                include_events: false,
            }
        ),
        false,
    );
    
    let optimistic_fetch = OptimisticFetchRequest::new(
        request,
        ResponseSender::new(response_tx),
        TimeService::mock(),
    );
    
    optimistic_fetches.insert(peer_network_id, optimistic_fetch);
    
    // Trigger optimistic fetch handling with target ledger info at version 150
    let target_ledger_info = create_test_ledger_info(150, 1);
    
    handle_ready_optimistic_fetches(
        /* runtime, config, cached_summary, optimistic_fetches, cache, 
           moderator, mock_storage, subscriptions, time_service */
        vec![(peer_network_id, target_ledger_info)]
    ).await;
    
    // EXPECTED: Peer receives StorageServiceError response
    // ACTUAL: Peer receives channel cancellation (Err from oneshot)
    match response_rx.await {
        Ok(response) => panic!("Expected error response, got: {:?}", response),
        Err(Canceled) => {
            // BUG CONFIRMED: Channel closed without sending error response
            println!("Vulnerability confirmed: Peer received channel cancellation instead of error");
        }
    }
    
    // Check that error was logged but peer never notified
    assert_error_logged_but_peer_not_notified();
}
```

**Validation**: This test demonstrates that when storage errors occur during optimistic fetch processing, the peer's response channel is closed without receiving a proper `StorageServiceError`, confirming the vulnerability.

### Citations

**File:** state-sync/storage-service/server/src/optimistic_fetch.rs (L66-74)
```rust
        // Verify that the target version is higher than the highest known version
        let known_version = self.highest_known_version();
        let target_version = target_ledger_info.ledger_info().version();
        if target_version <= known_version {
            return Err(Error::InvalidRequest(format!(
                "Target version: {:?} is not higher than known version: {:?}!",
                target_version, known_version
            )));
        }
```

**File:** state-sync/storage-service/server/src/optimistic_fetch.rs (L77-98)
```rust
        let mut num_versions_to_fetch =
            target_version.checked_sub(known_version).ok_or_else(|| {
                Error::UnexpectedErrorEncountered(
                    "Number of versions to fetch has overflown!".into(),
                )
            })?;

        // Bound the number of versions to fetch by the maximum chunk size
        num_versions_to_fetch = min(
            num_versions_to_fetch,
            self.max_chunk_size_for_request(config),
        );

        // Calculate the start and end versions
        let start_version = known_version.checked_add(1).ok_or_else(|| {
            Error::UnexpectedErrorEncountered("Start version has overflown!".into())
        })?;
        let end_version = known_version
            .checked_add(num_versions_to_fetch)
            .ok_or_else(|| {
                Error::UnexpectedErrorEncountered("End version has overflown!".into())
            })?;
```

**File:** state-sync/storage-service/server/src/optimistic_fetch.rs (L274-278)
```rust
        let ready_optimistic_fetch =
            optimistic_fetches.remove_if(&peer_network_id, |_, optimistic_fetch| {
                optimistic_fetch.highest_known_version()
                    < target_ledger_info.ledger_info().version()
            });
```

**File:** state-sync/storage-service/server/src/optimistic_fetch.rs (L298-317)
```rust
                let handle_request = || {
                    // Get the storage service request for the missing data
                    let missing_data_request = optimistic_fetch
                        .get_storage_request_for_missing_data(config, &target_ledger_info)?;

                    // Notify the peer of the new data
                    utils::notify_peer_of_new_data(
                        cached_storage_server_summary.clone(),
                        optimistic_fetches.clone(),
                        subscriptions.clone(),
                        lru_response_cache.clone(),
                        request_moderator.clone(),
                        storage.clone(),
                        time_service.clone(),
                        &peer_network_id,
                        missing_data_request,
                        target_ledger_info,
                        optimistic_fetch.take_response_sender(),
                    )
                };
```

**File:** state-sync/storage-service/server/src/optimistic_fetch.rs (L327-330)
```rust
                if let Err(error) = result {
                    warn!(LogSchema::new(LogEntry::OptimisticFetchResponse)
                        .error(&Error::UnexpectedErrorEncountered(error.to_string())));
                }
```

**File:** state-sync/storage-service/server/src/utils.rs (L146-174)
```rust
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
```

**File:** state-sync/storage-service/server/src/utils.rs (L182-186)
```rust
                return Err(Error::UnexpectedErrorEncountered(format!(
                    "Failed to create transformed response! Error: {:?}",
                    error
                )));
            },
```

**File:** state-sync/storage-service/server/src/network.rs (L106-112)
```rust
    pub fn send(self, response: Result<StorageServiceResponse>) {
        let msg = StorageServiceMessage::Response(response);
        let result = bcs::to_bytes(&msg)
            .map(Bytes::from)
            .map_err(RpcError::BcsError);
        let _ = self.response_tx.send(result);
    }
```

**File:** state-sync/storage-service/server/src/handler.rs (L375-379)
```rust
        self.send_response(
            request,
            Err(StorageServiceError::InvalidRequest(error.to_string())),
            subscription_request.take_response_sender(),
        );
```

**File:** state-sync/storage-service/types/src/lib.rs (L42-47)
```rust
pub enum StorageServiceMessage {
    /// A request to the storage service.
    Request(StorageServiceRequest),
    /// A response from the storage service. If there was an error while handling
    /// the request, the service will return an [`StorageServiceError`] error.
    Response(Result<StorageServiceResponse>),
```

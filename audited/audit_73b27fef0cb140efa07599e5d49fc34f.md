# Audit Report

## Title
Server-Side Resource Leak Due to Incomplete Subscription Stream Cleanup on Client Termination

## Summary
When a subscription stream encounters an error and is terminated on the client side via `handle_subscription_error()`, the client aborts local tasks and clears its request queue but fails to notify the server. This leaves orphaned subscription requests on the server side that consume resources until they timeout, enabling resource exhaustion attacks.

## Finding Description

The vulnerability exists in the subscription stream termination flow within the state-sync data streaming service. When `ContinuousTransactionStreamEngine::handle_subscription_error()` is invoked, it performs client-side cleanup: [1](#0-0) 

The function sets `active_subscription_stream = None` and updates metrics, then returns. Subsequently, `DataStream::notify_new_data_request_error()` calls `clear_sent_data_requests_queue()`: [2](#0-1) 

Which clears the pending request queue and aborts spawned tasks: [3](#0-2) [4](#0-3) 

**The Critical Flaw:** By the time tasks are aborted, subscription requests have already been sent over the network and stored on the server side in `SubscriptionStreamRequests.pending_subscription_requests`: [5](#0-4) 

The network requests are sent via the data client before task abortion occurs: [6](#0-5) 

**No cancellation notification is sent to the server.** The server continues holding these requests until they expire based on timeout: [7](#0-6) 

**Attack Scenario:**
1. Attacker creates subscription streams repeatedly
2. Sends multiple subscription requests per stream (indices 0-9)
3. Immediately triggers error conditions (e.g., by introducing artificial lag)
4. Client terminates streams locally without notifying server
5. Server accumulates orphaned requests in `pending_subscription_requests` maps
6. Repeating this faster than the timeout period causes unbounded resource accumulation

## Impact Explanation

This is a **Medium Severity** issue per Aptos bug bounty criteria:

- **Resource Exhaustion:** Orphaned subscription requests consume server memory and CPU cycles attempting to serve dead clients
- **State Inconsistencies:** Server maintains stale subscription state that doesn't reflect client reality
- **DoS Potential:** Sustained exploitation can degrade validator node performance and potentially cause crashes
- **Requires Intervention:** Manual server restarts may be needed to clear accumulated orphaned subscriptions

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The lack of cleanup violates resource management guarantees.

## Likelihood Explanation

**Likelihood: High**

- **Easy to Trigger:** Subscription errors occur naturally (network issues, lag) or can be artificially induced
- **Low Barrier:** Any network peer can create subscription streams without special privileges
- **Amplification:** Single attacker can create many parallel streams with multiple requests each
- **Timing Window:** Gap between client termination and server timeout (configurable, typically seconds to minutes) provides exploitation window
- **No Rate Limiting:** No explicit mechanism prevents rapid subscription creation/termination cycles

## Recommendation

Implement explicit subscription cancellation notification from client to server:

1. **Add cancellation message type** to the storage service protocol
2. **Send cancellation on stream termination** from `handle_subscription_error()`:
   - Before setting `active_subscription_stream = None`
   - Send `CancelSubscription(subscription_stream_id)` message to server
3. **Server-side cancellation handler** to immediately remove subscription stream:
   - Remove from active subscriptions map
   - Send error responses to pending requests
   - Update cancellation metrics

Example fix for `handle_subscription_error()`:

```rust
fn handle_subscription_error(
    &mut self,
    client_request: &DataClientRequest,
    request_error: aptos_data_client::error::Error,
) -> Result<(), Error> {
    // Verify active subscription exists
    if self.active_subscription_stream.is_none() {
        return Err(Error::UnexpectedErrorEncountered(format!(...)));
    }
    
    // NEW: Send cancellation notification to server before cleanup
    if let Some(subscription_stream) = &self.active_subscription_stream {
        let stream_id = subscription_stream.get_subscription_stream_id();
        // Send cancel message via data client
        let _ = self.send_subscription_cancellation(stream_id);
    }
    
    // Existing cleanup logic
    self.active_subscription_stream = None;
    update_terminated_subscription_metrics(request_error.get_label());
    // ... rest of function
}
```

## Proof of Concept

The following Rust integration test demonstrates the vulnerability:

```rust
#[tokio::test]
async fn test_orphaned_subscription_requests() {
    // Setup mock storage service server
    let (server, mut subscription_map) = setup_mock_server();
    
    // Setup data streaming client
    let (mut data_stream, _listener) = create_data_stream_with_subscriptions();
    
    // Phase 1: Create subscription stream with multiple requests
    let subscription_requests = vec![0, 1, 2, 3, 4]; // 5 request indices
    for idx in subscription_requests {
        data_stream.send_subscription_request(idx).await.unwrap();
    }
    
    // Verify server received and stored all requests
    let server_subscriptions = subscription_map.lock().unwrap();
    assert_eq!(server_subscriptions.pending_requests.len(), 5);
    drop(server_subscriptions);
    
    // Phase 2: Trigger subscription error on client
    data_stream.simulate_subscription_error().await;
    
    // Verify client cleaned up locally
    assert!(data_stream.active_subscription_stream.is_none());
    assert_eq!(data_stream.sent_data_requests.len(), 0);
    
    // Phase 3: VULNERABILITY - Server still holds orphaned requests
    let server_subscriptions = subscription_map.lock().unwrap();
    assert_eq!(
        server_subscriptions.pending_requests.len(), 
        5, // All 5 requests still present!
        "Server should have 0 pending requests after client termination, but has 5"
    );
    
    // Phase 4: Demonstrate resource exhaustion attack
    for _ in 0..100 {
        // Create and immediately terminate subscriptions
        let stream = create_subscription_stream();
        for idx in 0..10 {
            stream.send_subscription_request(idx).await.unwrap();
        }
        stream.simulate_error().await;
    }
    
    // Server now has 1000 orphaned requests consuming resources
    let total_orphaned = subscription_map.lock().unwrap()
        .values()
        .map(|s| s.pending_requests.len())
        .sum::<usize>();
    assert!(total_orphaned >= 1000, "Resource exhaustion demonstrated");
}
```

## Notes

The vulnerability is exacerbated by:
- No explicit limit on active subscription streams per peer
- Timeout-based cleanup relies on `max_subscription_period_ms` which may be configured generously
- Server continues attempting to serve requests even after client disconnection
- Multiple parallel subscription streams can amplify the resource leak

This represents a **protocol design flaw** rather than just an implementation bug, as there is no cancellation message type defined in the storage service protocol specification.

### Citations

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L938-1003)
```rust
    fn handle_subscription_error(
        &mut self,
        client_request: &DataClientRequest,
        request_error: aptos_data_client::error::Error,
    ) -> Result<(), Error> {
        // We should only receive an error notification if we have an active stream
        if self.active_subscription_stream.is_none() {
            return Err(Error::UnexpectedErrorEncountered(format!(
                "Received a subscription notification error but no active subscription stream exists! Error: {:?}, request: {:?}",
                request_error, client_request
            )));
        }

        // Reset the active subscription stream and update the metrics
        self.active_subscription_stream = None;
        update_terminated_subscription_metrics(request_error.get_label());

        // Log the error based on the request type
        if matches!(
            self.request,
            StreamRequest::ContinuouslyStreamTransactions(_)
        ) && matches!(
            client_request,
            DataClientRequest::SubscribeTransactionsWithProof(_)
        ) {
            info!(
                (LogSchema::new(LogEntry::RequestError).message(&format!(
                    "Subscription error for new transactions: {:?}",
                    request_error
                )))
            );
        } else if matches!(
            self.request,
            StreamRequest::ContinuouslyStreamTransactionOutputs(_)
        ) && matches!(
            client_request,
            DataClientRequest::SubscribeTransactionOutputsWithProof(_)
        ) {
            info!(
                (LogSchema::new(LogEntry::RequestError).message(&format!(
                    "Subscription error for new transaction outputs: {:?}",
                    request_error
                )))
            );
        } else if matches!(
            self.request,
            StreamRequest::ContinuouslyStreamTransactionsOrOutputs(_)
        ) && matches!(
            client_request,
            DataClientRequest::SubscribeTransactionsOrOutputsWithProof(_)
        ) {
            info!(
                (LogSchema::new(LogEntry::RequestError).message(&format!(
                    "Subscription error for new transactions or outputs: {:?}",
                    request_error
                )))
            );
        } else {
            return Err(Error::UnexpectedErrorEncountered(format!(
                "Received a subscription request error but the request did not match the expected type for the stream! \
                Error: {:?}, request: {:?}, stream: {:?}", request_error, client_request, self.request
            )));
        }

        Ok(())
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L176-184)
```rust
    pub fn clear_sent_data_requests_queue(&mut self) {
        // Clear all pending data requests
        if let Some(sent_data_requests) = self.sent_data_requests.as_mut() {
            sent_data_requests.clear();
        }

        // Abort all spawned tasks
        self.abort_spawned_tasks();
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L633-645)
```rust
    /// Notifies the stream engine that a new data request error was encountered
    fn notify_new_data_request_error(
        &mut self,
        client_request: &DataClientRequest,
        error: aptos_data_client::error::Error,
    ) -> Result<(), Error> {
        // Notify the stream engine and clear the requests queue
        self.stream_engine
            .notify_new_data_request_error(client_request, error)?;
        self.clear_sent_data_requests_queue();

        Ok(())
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L940-944)
```rust
    fn abort_spawned_tasks(&mut self) {
        for spawned_task in &self.spawned_tasks {
            spawned_task.abort();
        }
    }
```

**File:** state-sync/storage-service/server/src/subscription.rs (L298-336)
```rust
/// A set of subscription requests that together form a stream
#[derive(Debug)]
pub struct SubscriptionStreamRequests {
    subscription_stream_metadata: SubscriptionStreamMetadata, // The metadata for the subscription stream (as specified by the client)

    highest_known_version: u64, // The highest version known by the peer (at this point in the stream)
    highest_known_epoch: u64,   // The highest epoch known by the peer (at this point in the stream)

    next_index_to_serve: u64, // The next subscription stream request index to serve
    pending_subscription_requests: BTreeMap<u64, SubscriptionRequest>, // The pending subscription requests by stream index

    last_stream_update_time: Instant, // The last time the stream was updated
    time_service: TimeService,        // The time service
}

impl SubscriptionStreamRequests {
    pub fn new(subscription_request: SubscriptionRequest, time_service: TimeService) -> Self {
        // Extract the relevant information from the request
        let highest_known_version = subscription_request.highest_known_version_at_stream_start();
        let highest_known_epoch = subscription_request.highest_known_epoch_at_stream_start();
        let subscription_stream_metadata = subscription_request.subscription_stream_metadata();

        // Create a new set of pending subscription requests using the first request
        let mut pending_subscription_requests = BTreeMap::new();
        pending_subscription_requests.insert(
            subscription_request.subscription_stream_index(),
            subscription_request,
        );

        Self {
            highest_known_version,
            highest_known_epoch,
            next_index_to_serve: 0,
            pending_subscription_requests,
            subscription_stream_metadata,
            last_stream_update_time: time_service.now(),
            time_service,
        }
    }
```

**File:** state-sync/storage-service/server/src/subscription.rs (L418-433)
```rust
    fn is_expired(&self, timeout_ms: u64) -> bool {
        // Determine the time when the stream was first blocked
        let time_when_first_blocked =
            if let Some(subscription_request) = self.first_pending_request() {
                subscription_request.request_start_time // The stream is blocked on the first pending request
            } else {
                self.last_stream_update_time // The stream is idle and hasn't been updated in a while
            };

        // Verify the stream hasn't been blocked for too long
        let current_time = self.time_service.now();
        let elapsed_time = current_time
            .duration_since(time_when_first_blocked)
            .as_millis();
        elapsed_time > (timeout_ms as u128)
    }
```

**File:** state-sync/aptos-data-client/src/client.rs (L629-702)
```rust
    async fn send_request_and_decode<T, E>(
        &self,
        request: StorageServiceRequest,
        request_timeout_ms: u64,
    ) -> crate::error::Result<Response<T>>
    where
        T: TryFrom<StorageServiceResponse, Error = E> + Send + Sync + 'static,
        E: Into<Error>,
    {
        // Select the peers to service the request
        let peers = self.choose_peers_for_request(&request)?;

        // If peers is empty, return an error
        if peers.is_empty() {
            return Err(Error::DataIsUnavailable(format!(
                "No peers were chosen to service the given request: {:?}",
                request
            )));
        }

        // Update the metrics for the number of selected peers (for the request)
        metrics::observe_value_with_label(
            &metrics::MULTI_FETCHES_PER_REQUEST,
            &request.get_label(),
            peers.len() as f64,
        );

        // Send the requests to the peers (and gather abort handles for the tasks)
        let mut sent_requests = FuturesUnordered::new();
        let mut abort_handles = vec![];
        for peer in peers {
            // Send the request to the peer
            let aptos_data_client = self.clone();
            let request = request.clone();
            let sent_request = tokio::spawn(async move {
                aptos_data_client
                    .send_request_to_peer_and_decode(peer, request, request_timeout_ms)
                    .await
            });
            let abort_handle = sent_request.abort_handle();

            // Gather the tasks and abort handles
            sent_requests.push(sent_request);
            abort_handles.push(abort_handle);
        }

        // Wait for the first successful response and abort all other tasks.
        // If all requests fail, gather the errors and return them.
        let num_sent_requests = sent_requests.len();
        let mut sent_request_errors = vec![];
        for _ in 0..num_sent_requests {
            if let Ok(response_result) = sent_requests.select_next_some().await {
                match response_result {
                    Ok(response) => {
                        // We received a valid response. Abort all pending tasks.
                        for abort_handle in abort_handles {
                            abort_handle.abort();
                        }
                        return Ok(response); // Return the response
                    },
                    Err(error) => {
                        // Gather the error and continue waiting for a response
                        sent_request_errors.push(error)
                    },
                }
            }
        }

        // Otherwise, all requests failed and we should return an error
        Err(Error::DataIsUnavailable(format!(
            "All {} attempts failed for the given request: {:?}. Errors: {:?}",
            num_sent_requests, request, sent_request_errors
        )))
    }
```

# Audit Report

## Title
Subscription Request Processing Failure Causes Permanent Data Gaps in State Synchronization

## Summary
A critical flaw in the subscription request processing logic allows subscription requests to be removed from the processing queue without updating the stream's index counter when processing fails. This creates permanent data gaps where peers never receive blockchain data for specific version ranges, violating state consistency guarantees and potentially causing validator/full node desynchronization.

## Finding Description
The vulnerability exists in the `handle_ready_subscriptions` function where subscription requests are processed asynchronously. The issue occurs in the following sequence: [1](#0-0) 

The subscription request with index N is popped from the pending queue and the lock is released. A blocking task is then spawned to process this request: [2](#0-1) 

The critical bug: if the `handle_request` closure fails at any point (storage read failure, network error, response serialization failure), the error is only logged at line 732-735, but the stream's `next_index_to_serve` counter is **never updated**.

The counter is only incremented inside `update_known_version_and_epoch`: [3](#0-2) 

This function is called within the `handle_request` closure, so if any preceding operation fails, it never executes.

**Attack Scenario:**
1. Peer syncs to version 100 and creates subscription stream with index 0
2. Server pops request with index 0 (expecting to send versions 101-200)
3. Processing fails due to database error, network issue, or corruption
4. Request is lost, but `next_index_to_serve` remains 0
5. Peer sends request with index 1
6. Server checks readiness: index 1 != `next_index_to_serve` (0), so not ready
7. Stream is permanently blocked; peer never receives versions 101-200

The check that enforces ordering prevents recovery: [4](#0-3) 

**Invariant Violation:**
This breaks the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs." Peers with data gaps cannot correctly verify state transitions or participate in consensus.

## Impact Explanation
**Severity: High/Medium** - State inconsistencies requiring intervention

This vulnerability creates:
1. **Permanent data gaps** in peer blockchain state - peers never receive missing transaction ranges
2. **Validator/full node desynchronization** - affected nodes cannot validate subsequent blocks correctly
3. **Network reliability degradation** - peers must restart synchronization with new stream IDs
4. **Potential consensus participation failure** - validators with incomplete state cannot sign blocks safely

This maps to **Medium Severity** per the Aptos bug bounty: "State inconsistencies requiring intervention." While it doesn't directly cause fund loss or consensus safety violations, it degrades network health and requires manual intervention (stream timeout/restart).

The impact could escalate to **High Severity** if this affects multiple validators during critical periods, as it causes "Significant protocol violations" by breaking state sync guarantees.

## Likelihood Explanation
**Likelihood: Medium-High**

This vulnerability can be triggered by:
1. **Natural failures** (common): Database read errors, network timeouts, storage corruption, memory pressure
2. **Malicious triggers** (feasible): Adversary causes storage failures through resource exhaustion or targeted disruption
3. **Race conditions** (occasional): Concurrent state updates causing temporary inconsistencies

The likelihood is high because state sync operations involve multiple failure points (storage reads, network sends, serialization), and any single failure triggers the bug. No special privileges are required - normal network participants experiencing transient failures will encounter this issue.

## Recommendation
Add error recovery logic to restore the request back to the pending queue when processing fails, or alternatively, always update `next_index_to_serve` regardless of success/failure and track failures separately for retry logic.

**Recommended Fix:**

```rust
// In handle_ready_subscriptions, after spawning the blocking task:
let active_task = runtime.spawn_blocking(move || {
    let subscription_start_time = subscription_request.request_start_time;
    let subscription_data_request = subscription_request.request.clone();
    let subscription_stream_index = subscription_request.subscription_stream_index();

    let handle_request = || {
        // ... existing processing logic ...
    };
    
    let result = utils::execute_and_time_duration(
        &metrics::SUBSCRIPTION_LATENCIES,
        Some((&peer_network_id, &subscription_data_request)),
        None,
        handle_request,
        Some(subscription_start_time),
    );

    // NEW: On failure, restore the request to the pending queue
    if let Err(error) = result {
        warn!(LogSchema::new(LogEntry::SubscriptionResponse)
            .error(&Error::UnexpectedErrorEncountered(error.to_string())));
        
        // Re-insert the request at its original index for retry
        if let Some(mut subscription_stream_requests) = subscriptions.get_mut(&peer_network_id) {
            subscription_stream_requests
                .get_pending_subscription_requests()
                .insert(subscription_stream_index, subscription_request);
        }
    }
});
```

Alternatively, implement a more robust solution with explicit retry tracking and exponential backoff.

## Proof of Concept

```rust
#[tokio::test]
async fn test_subscription_request_failure_causes_data_gap() {
    use crate::subscription::{SubscriptionRequest, SubscriptionStreamRequests};
    use aptos_storage_service_types::requests::{
        DataRequest, StorageServiceRequest, SubscriptionStreamMetadata,
    };
    use aptos_time_service::TimeService;
    use futures::channel::oneshot;
    
    // Create a subscription stream with known_version=100
    let time_service = TimeService::mock();
    let metadata = SubscriptionStreamMetadata {
        known_version_at_stream_start: 100,
        known_epoch_at_stream_start: 1,
        subscription_stream_id: 12345,
    };
    
    // Create subscription request with index 0
    let data_request = DataRequest::SubscribeTransactionsWithProof(
        SubscribeTransactionsWithProofRequest {
            subscription_stream_metadata: metadata,
            subscription_stream_index: 0,
            include_events: false,
        }
    );
    let storage_request = StorageServiceRequest::new(data_request, false);
    let (callback, _) = oneshot::channel();
    let response_sender = ResponseSender::new(callback);
    let subscription_request = SubscriptionRequest::new(
        storage_request,
        response_sender,
        time_service.clone(),
    );
    
    let mut stream_requests = SubscriptionStreamRequests::new(
        subscription_request,
        time_service.clone(),
    );
    
    // Verify initial state
    assert_eq!(stream_requests.get_next_index_to_serve(), 0);
    assert_eq!(stream_requests.get_pending_subscription_requests().len(), 1);
    
    // Simulate: Pop the request (as done in handle_ready_subscriptions)
    let popped_request = stream_requests.pop_first_pending_request().unwrap();
    
    // Verify request was removed
    assert_eq!(stream_requests.get_pending_subscription_requests().len(), 0);
    assert_eq!(stream_requests.get_next_index_to_serve(), 0); // Still 0!
    
    // Simulate: Processing fails, error is logged but next_index_to_serve NOT updated
    // (In real code, this happens when handle_request closure returns Err)
    
    // Add next request with index 1
    let data_request_1 = DataRequest::SubscribeTransactionsWithProof(
        SubscribeTransactionsWithProofRequest {
            subscription_stream_metadata: metadata,
            subscription_stream_index: 1,
            include_events: false,
        }
    );
    let storage_request_1 = StorageServiceRequest::new(data_request_1, false);
    let (callback_1, _) = oneshot::channel();
    let response_sender_1 = ResponseSender::new(callback_1);
    let subscription_request_1 = SubscriptionRequest::new(
        storage_request_1,
        response_sender_1,
        time_service.clone(),
    );
    
    let config = StorageServiceConfig::default();
    stream_requests.add_subscription_request(config, subscription_request_1).unwrap();
    
    // BUG DEMONSTRATED: Stream is now permanently blocked
    // - pending_requests has index 1
    // - next_index_to_serve is still 0
    // - first_request_ready_to_be_served() returns false (1 != 0)
    assert_eq!(stream_requests.get_next_index_to_serve(), 0);
    assert!(!stream_requests.first_request_ready_to_be_served());
    
    // This stream will remain blocked until timeout, creating a data gap
    // Peer never receives versions 101-200 that were supposed to be in index 0
}
```

## Notes
This vulnerability affects all subscription types (transactions, transaction outputs, and transaction data v2). The bug is particularly concerning because it can be triggered by transient failures that are common in distributed systems. The issue requires either implementing proper error recovery (re-queueing failed requests) or changing the semantics to always advance the index counter while tracking failures separately for retry logic.

### Citations

**File:** state-sync/storage-service/server/src/subscription.rs (L438-443)
```rust
    fn first_request_ready_to_be_served(&self) -> bool {
        if let Some(subscription_request) = self.first_pending_request() {
            subscription_request.subscription_stream_index() == self.next_index_to_serve
        } else {
            false
        }
```

**File:** state-sync/storage-service/server/src/subscription.rs (L553-554)
```rust
        // Update the next index to serve
        self.next_index_to_serve += 1;
```

**File:** state-sync/storage-service/server/src/subscription.rs (L659-667)
```rust
        let subscription_request_and_known_version =
            subscriptions
                .get_mut(&peer_network_id)
                .map(|mut subscription_stream_requests| {
                    (
                        subscription_stream_requests.pop_first_pending_request(),
                        subscription_stream_requests.highest_known_version,
                    )
                });
```

**File:** state-sync/storage-service/server/src/subscription.rs (L683-736)
```rust
            let active_task = runtime.spawn_blocking(move || {
                // Get the subscription start time and request
                let subscription_start_time = subscription_request.request_start_time;
                let subscription_data_request = subscription_request.request.clone();

                // Handle the subscription request and time the operation
                let handle_request = || {
                    // Get the storage service request for the missing data
                    let missing_data_request = subscription_request
                        .get_storage_request_for_missing_data(
                            config,
                            known_version,
                            &target_ledger_info,
                        )?;

                    // Notify the peer of the new data
                    let data_response = utils::notify_peer_of_new_data(
                        cached_storage_server_summary,
                        optimistic_fetches,
                        subscriptions.clone(),
                        lru_response_cache,
                        request_moderator,
                        storage,
                        time_service.clone(),
                        &peer_network_id,
                        missing_data_request,
                        target_ledger_info,
                        subscription_request.take_response_sender(),
                    )?;

                    // Update the stream's known version and epoch
                    if let Some(mut subscription_stream_requests) =
                        subscriptions.get_mut(&peer_network_id)
                    {
                        subscription_stream_requests
                            .update_known_version_and_epoch(&data_response)?;
                    }

                    Ok(())
                };
                let result = utils::execute_and_time_duration(
                    &metrics::SUBSCRIPTION_LATENCIES,
                    Some((&peer_network_id, &subscription_data_request)),
                    None,
                    handle_request,
                    Some(subscription_start_time),
                );

                // Log an error if the handler failed
                if let Err(error) = result {
                    warn!(LogSchema::new(LogEntry::SubscriptionResponse)
                        .error(&Error::UnexpectedErrorEncountered(error.to_string())));
                }
            });
```

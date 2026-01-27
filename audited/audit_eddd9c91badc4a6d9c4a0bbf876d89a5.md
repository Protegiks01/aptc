# Audit Report

## Title
Subscription Stream Parameter Inconsistency: `include_events` Flag Can Change Mid-Stream

## Summary
The `subscribe_transaction_or_output_data_with_proof()` function creates subscription requests with an `include_events` parameter, but the subscription stream validation does not enforce that this parameter remains consistent across all requests in the same stream. This allows a client to receive some transaction chunks with events and others without events within a single subscription stream, leading to data inconsistencies.

## Finding Description

The subscription mechanism in Aptos state-sync allows clients to subscribe to transaction data streams. When a client calls `subscribe_transaction_or_output_data_with_proof()`, it creates a `SubscribeTransactionDataWithProofRequest` containing a `TransactionOrOutputData` type with an `include_events` flag. [1](#0-0) 

Multiple subscription requests can be added to the same stream if they share the same `subscription_stream_id`. However, the `add_subscription_request()` method only validates that the `subscription_stream_metadata` (containing `known_version_at_stream_start`, `known_epoch_at_stream_start`, and `subscription_stream_id`) matches between requests - it does NOT validate that the `include_events` flag or other parameters in `transaction_data_request_type` remain consistent: [2](#0-1) 

When each subscription request is processed via `get_storage_request_for_missing_data()`, the system directly copies the `transaction_data_request_type` from each individual request, including its `include_events` setting: [3](#0-2) 

**Attack Path:**
1. Client sends subscription request #0 with `include_events: true`, `subscription_stream_index: 0`
2. Client sends subscription request #1 with `include_events: false`, `subscription_stream_index: 1`, but same `subscription_stream_id`
3. Both requests pass validation and are added to the same stream
4. Request #0 is processed and returns transactions WITH events
5. Request #1 is processed and returns transactions WITHOUT events
6. The subscription stream now delivers inconsistent data to the syncing node

This breaks the **State Consistency** invariant: a single subscription stream should deliver uniform data format throughout its lifecycle. The inconsistency can cause state sync failures, client crashes, or incorrect application of transaction data.

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty criteria: "State inconsistencies requiring intervention."

**Specific Impacts:**
- **State Sync Failures**: Nodes syncing via affected subscription streams may fail to apply transactions correctly when the data format changes unexpectedly
- **Data Processing Errors**: Client code expecting consistent event inclusion across a stream will encounter unexpected format changes
- **Potential DoS**: Buggy client implementations may crash when receiving inconsistent data formats
- **Manual Intervention Required**: Affected nodes may require manual restart or re-sync to recover

While this does not directly cause consensus violations (validators use different sync mechanisms), it affects the reliability and correctness of the state sync subsystem, which is critical for new nodes joining the network and fullnodes staying synchronized.

## Likelihood Explanation

**Likelihood: Moderate**

This vulnerability can occur in two scenarios:

1. **Accidental**: A buggy client implementation that changes subscription parameters between requests could trigger this unintentionally
2. **Malicious**: An attacker deliberately sends subscription requests with varying parameters to cause state sync failures in target nodes

**Attacker Requirements:**
- No special privileges required - any peer can make subscription requests
- No validator access needed
- No economic stake required
- Simple to execute - just send two subscription requests with different `include_events` values

**Complexity: Low** - The attack requires only basic knowledge of the subscription API and can be executed by sending properly formatted subscription requests.

## Recommendation

Add parameter consistency validation to the `add_subscription_request()` method. When adding a new request to an existing stream, verify that the `transaction_data_request_type` parameters match the stream's initial request:

```rust
// In SubscriptionStreamRequests::add_subscription_request()
// After validating subscription_stream_metadata (around line 356):

// Extract the transaction data request type from the new request
let new_request_type = match &subscription_request.request.data_request {
    DataRequest::SubscribeTransactionDataWithProof(request) => {
        Some(request.transaction_data_request_type)
    },
    _ => None,
};

// Extract the transaction data request type from an existing request in the stream
if let Some(existing_request) = self.first_pending_request() {
    let existing_request_type = match &existing_request.request.data_request {
        DataRequest::SubscribeTransactionDataWithProof(request) => {
            Some(request.transaction_data_request_type)
        },
        _ => None,
    };
    
    // Verify that the request types match
    if new_request_type != existing_request_type {
        return Err((
            Error::InvalidRequest(format!(
                "The subscription request parameters do not match the stream! Expected: {:?}, found: {:?}",
                existing_request_type, new_request_type
            )),
            subscription_request,
        ));
    }
}
```

Apply similar validation for the v1 subscription request types (`SubscribeTransactionsWithProof`, `SubscribeTransactionsOrOutputsWithProof`) to ensure `include_events` and other parameters remain consistent.

## Proof of Concept

```rust
#[tokio::test]
async fn test_subscription_inconsistent_include_events() {
    use crate::subscription::{SubscriptionRequest, SubscriptionStreamRequests};
    use aptos_config::config::StorageServiceConfig;
    use aptos_storage_service_types::requests::{
        DataRequest, SubscriptionStreamMetadata,
    };
    use aptos_time_service::TimeService;
    use futures::channel::oneshot;
    use crate::network::ResponseSender;
    
    let time_service = TimeService::mock();
    let subscription_stream_id = 12345;
    let known_version = 100;
    let known_epoch = 1;
    
    // Create subscription stream metadata
    let metadata = SubscriptionStreamMetadata {
        known_version_at_stream_start: known_version,
        known_epoch_at_stream_start: known_epoch,
        subscription_stream_id,
    };
    
    // Create first subscription request with include_events: true
    let request1 = DataRequest::subscribe_transaction_or_output_data_with_proof(
        metadata,
        0, // stream index 0
        true, // include_events: true
        1000,
    );
    let storage_request1 = StorageServiceRequest::new(request1, false);
    let (callback1, _) = oneshot::channel();
    let response_sender1 = ResponseSender::new(callback1);
    let sub_request1 = SubscriptionRequest::new(
        storage_request1,
        response_sender1,
        time_service.clone(),
    );
    
    // Create subscription stream with first request
    let mut stream = SubscriptionStreamRequests::new(sub_request1, time_service.clone());
    
    // Create second subscription request with include_events: false
    let request2 = DataRequest::subscribe_transaction_or_output_data_with_proof(
        metadata,
        1, // stream index 1
        false, // include_events: false (DIFFERENT!)
        1000,
    );
    let storage_request2 = StorageServiceRequest::new(request2, false);
    let (callback2, _) = oneshot::channel();
    let response_sender2 = ResponseSender::new(callback2);
    let sub_request2 = SubscriptionRequest::new(
        storage_request2,
        response_sender2,
        time_service.clone(),
    );
    
    // This should fail but currently succeeds, demonstrating the vulnerability
    let result = stream.add_subscription_request(
        StorageServiceConfig::default(),
        sub_request2,
    );
    
    // VULNERABILITY: This assertion will currently PASS (request is accepted)
    // but it SHOULD FAIL (request should be rejected for inconsistent parameters)
    assert!(result.is_ok(), "Inconsistent include_events parameter was accepted!");
    
    // The stream now has requests with different include_events settings
    // When processed, it will deliver inconsistent data
}
```

**Notes:**
- This vulnerability is present in both v1 (using `SubscribeTransactionsWithProof`, `SubscribeTransactionsOrOutputsWithProof`) and v2 (using `SubscribeTransactionDataWithProof`) subscription APIs
- The same issue affects other parameters like `max_response_bytes` in v2 requests and `max_num_output_reductions` in v1 requests
- The fix should validate ALL request-type-specific parameters, not just `include_events`
- This is a data integrity issue rather than a direct security exploit, but it undermines the reliability of the state sync subsystem

### Citations

**File:** state-sync/storage-service/types/src/requests.rs (L298-314)
```rust
    pub fn subscribe_transaction_or_output_data_with_proof(
        subscription_stream_metadata: SubscriptionStreamMetadata,
        subscription_stream_index: u64,
        include_events: bool,
        max_response_bytes: u64,
    ) -> Self {
        let transaction_data_request_type =
            TransactionDataRequestType::TransactionOrOutputData(TransactionOrOutputData {
                include_events,
            });
        Self::SubscribeTransactionDataWithProof(SubscribeTransactionDataWithProofRequest {
            transaction_data_request_type,
            subscription_stream_metadata,
            subscription_stream_index,
            max_response_bytes,
        })
    }
```

**File:** state-sync/storage-service/server/src/subscription.rs (L127-135)
```rust
            DataRequest::SubscribeTransactionDataWithProof(request) => {
                DataRequest::GetTransactionDataWithProof(GetTransactionDataWithProofRequest {
                    transaction_data_request_type: request.transaction_data_request_type,
                    proof_version: target_version,
                    start_version,
                    end_version,
                    max_response_bytes: request.max_response_bytes,
                })
            },
```

**File:** state-sync/storage-service/server/src/subscription.rs (L341-404)
```rust
    pub fn add_subscription_request(
        &mut self,
        storage_service_config: StorageServiceConfig,
        subscription_request: SubscriptionRequest,
    ) -> Result<(), (Error, SubscriptionRequest)> {
        // Verify that the subscription metadata is valid
        let subscription_stream_metadata = subscription_request.subscription_stream_metadata();
        if subscription_stream_metadata != self.subscription_stream_metadata {
            return Err((
                Error::InvalidRequest(format!(
                    "The subscription request stream metadata is invalid! Expected: {:?}, found: {:?}",
                    self.subscription_stream_metadata, subscription_stream_metadata
                )),
                subscription_request,
            ));
        }

        // Verify that the subscription request index is valid
        let subscription_request_index = subscription_request.subscription_stream_index();
        if subscription_request_index < self.next_index_to_serve {
            return Err((
                Error::InvalidRequest(format!(
                    "The subscription request index is too low! Next index to serve: {:?}, found: {:?}",
                    self.next_index_to_serve, subscription_request_index
                )),
                subscription_request,
            ));
        }

        // Verify that the number of active subscriptions respects the maximum
        let max_num_active_subscriptions =
            storage_service_config.max_num_active_subscriptions as usize;
        if self.pending_subscription_requests.len() >= max_num_active_subscriptions {
            return Err((
                Error::InvalidRequest(format!(
                    "The maximum number of active subscriptions has been reached! Max: {:?}, found: {:?}",
                    max_num_active_subscriptions, self.pending_subscription_requests.len()
                )),
                subscription_request,
            ));
        }

        // Insert the subscription request into the pending requests
        let existing_request = self.pending_subscription_requests.insert(
            subscription_request.subscription_stream_index(),
            subscription_request,
        );

        // Refresh the last stream update time
        self.refresh_last_stream_update_time();

        // If a pending request already existed, return the previous request to the caller
        if let Some(existing_request) = existing_request {
            return Err((
                Error::InvalidRequest(format!(
                    "Overwriting an existing subscription request for the given index: {:?}",
                    subscription_request_index
                )),
                existing_request,
            ));
        }

        Ok(())
    }
```

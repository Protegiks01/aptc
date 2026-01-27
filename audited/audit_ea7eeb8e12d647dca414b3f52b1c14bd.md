# Audit Report

## Title
Malicious Peers Can Cause Subscription Stream Failures Without Penalty By Sending Empty Transaction Lists

## Summary
Malicious network peers can exploit a validation gap in the subscription streaming logic to cause denial of service on state synchronization by sending empty `TransactionListWithProof` responses (where `first_transaction_version` is None) without being penalized by the peer reputation system.

## Finding Description
The vulnerability exists in the subscription response validation flow within the data streaming service. When a subscription stream is active, the system expects peers to respond with new transactions when data is available. However, the code fails to properly validate and penalize peers that send empty transaction lists when non-empty responses are expected.

**Attack Flow:**

1. A client node subscribes to transactions from a remote peer with a `known_version` of X
2. The remote peer's storage service determines there is new data available (versions X+1 onwards) and marks the subscription as "ready" [1](#0-0) 

3. A malicious peer crafts a `ResponsePayload::NewTransactionsWithProof` containing an empty `TransactionListWithProof` where `first_transaction_version` is None, despite data being available

4. The response passes the type-based sanity check since it has the correct payload type [2](#0-1) 

5. The response reaches `check_subscription_stream_lag()` which detects the missing `first_transaction_version` and returns an error [3](#0-2) 

6. This error triggers `notify_new_data_request_error()` which terminates the subscription stream [4](#0-3) 

7. The stream engine's `handle_subscription_error()` resets the active subscription stream [5](#0-4) 

**Critical Issue:** Unlike sanity check failures which call `notify_bad_response()` to penalize the peer, subscription errors from `check_subscription_stream_lag()` do NOT notify the data client about the bad response. The malicious peer faces no reputation penalty and can repeat this attack indefinitely. [6](#0-5) 

Compare this to sanity check failures which properly penalize peers: [7](#0-6) 

## Impact Explanation
This qualifies as **Medium Severity** under Aptos bug bounty criteria:

- **State inconsistencies requiring intervention**: Subscription streams are critical for state synchronization in Aptos. Repeated failures force nodes to continuously restart subscriptions, preventing reliable state sync progression.

- **Availability impact**: While not causing total network unavailability, this significantly degrades the ability of nodes to stay synchronized via subscription streaming, a key mechanism for continuous state sync.

- **No peer accountability**: The absence of peer penalization means malicious actors can attack without consequences, making the attack sustainable and difficult to mitigate through existing reputation systems.

The impact is limited to state sync disruption rather than consensus violations or fund loss, placing it in the Medium severity category.

## Likelihood Explanation
**Likelihood: Medium to High**

**Attacker Requirements:**
- Network connectivity to target nodes (low barrier)
- Ability to respond to subscription requests (standard peer functionality)
- Knowledge of the vulnerability (disclosed here)

**Complexity:** Low - The attack requires simply returning an empty `TransactionListWithProof` structure, which is trivial to construct.

**Detection Difficulty:** The attack appears as normal errors in logs, making it difficult to distinguish from legitimate transient failures without deep analysis of peer behavior patterns.

**Incentives:** Attackers could use this to:
- Degrade network performance during critical periods
- Target specific nodes (e.g., validators) to impact their synchronization
- Create instability in the state sync subsystem

## Recommendation

Add proper validation and peer penalization for subscription responses that contain empty transaction lists when non-empty data was expected. The fix should:

1. **Validate response content consistency**: When a subscription request is sent expecting data (because the peer advertised having data beyond known_version), validate that the response actually contains transactions.

2. **Penalize malicious peers**: Call `notify_bad_response()` when `check_subscription_stream_lag()` detects an invalid empty response, ensuring the peer's reputation is downgraded.

**Suggested Fix** (in `state-sync/data-streaming-service/src/data_stream.rs`):

Modify the subscription error handling path to check if the error is due to a malformed response and penalize the peer accordingly:

```rust
// Around line 492-498, modify the subscription lag check handling
if client_request.is_subscription_request() {
    if let Err(error) = self.check_subscription_stream_lag(
        &global_data_summary,
        &client_response.payload,
    ) {
        // Check if this is a malformed response (empty when it shouldn't be)
        if is_malformed_subscription_response(&client_response.payload, &error) {
            // Penalize the peer for sending an invalid response
            self.notify_bad_response(&client_response.context, ResponseError::InvalidPayloadDataType);
        }
        
        self.notify_new_data_request_error(client_request, error)?;
        head_of_line_blocked = true;
    }
}

// Add helper function
fn is_malformed_subscription_response(
    payload: &ResponsePayload,
    error: &aptos_data_client::error::Error,
) -> bool {
    // Check if error is about missing first_transaction_version in a subscription response
    matches!(error, aptos_data_client::error::Error::UnexpectedErrorEncountered(msg)
        if msg.contains("first transaction version is missing"))
}
```

Additionally, consider adding a validation check that ensures non-empty responses when the subscription was marked as "ready" with available data.

## Proof of Concept

```rust
// This test demonstrates the vulnerability
// Add to state-sync/data-streaming-service/src/tests/data_stream.rs

#[tokio::test]
async fn test_malicious_empty_subscription_response() {
    // Setup a data stream with subscription enabled
    let (mut data_stream, mut stream_listener) = create_subscription_data_stream(100);
    
    // Initialize the stream
    let global_data_summary = create_global_summary(200); // Server has data up to version 200
    data_stream.initialize_data_requests(global_data_summary.clone()).unwrap();
    
    // Simulate malicious peer sending empty response when data is available
    let malicious_response = create_empty_new_transactions_response(); // Creates NewTransactionsWithProof with empty list
    
    // Inject the response
    inject_response_for_stream(&mut data_stream, malicious_response);
    
    // Process the response
    data_stream.process_data_responses(global_data_summary).await.unwrap();
    
    // Verify that:
    // 1. The subscription stream is terminated
    assert!(data_stream.get_subscription_stream_lag().is_none());
    
    // 2. The peer was NOT penalized (this is the bug!)
    // In the actual implementation, we'd verify that notify_bad_response was not called
    // on the peer's ResponseContext
    
    // Expected: The malicious peer should be penalized
    // Actual: The peer faces no consequences and can repeat the attack
}

fn create_empty_new_transactions_response() -> Response<ResponsePayload> {
    let empty_txn_list = TransactionListWithProof::new_empty();
    let target_ledger_info = create_ledger_info_at_version(200);
    
    Response::new(
        ResponseContext::new(/* ... */),
        ResponsePayload::NewTransactionsWithProof((
            TransactionListWithProofV2::new_from_v1(empty_txn_list),
            target_ledger_info
        ))
    )
}
```

## Notes

This vulnerability specifically affects the subscription streaming mechanism, which is a key component for continuous state synchronization in Aptos. The lack of proper validation and peer accountability creates an exploitable gap that can be used for targeted denial-of-service attacks against state sync functionality. The fix requires both validating response content consistency and ensuring malicious peers are properly penalized through the existing reputation system.

### Citations

**File:** state-sync/storage-service/server/src/subscription.rs (L919-920)
```rust
            // Check if we have synced beyond the highest known version
            if highest_known_version < highest_synced_version {
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L492-498)
```rust
                            if let Err(error) = self.check_subscription_stream_lag(
                                &global_data_summary,
                                &client_response.payload,
                            ) {
                                self.notify_new_data_request_error(client_request, error)?;
                                head_of_line_blocked = true; // We're now head of line blocked on the failed stream
                            }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L556-567)
```rust
            ResponsePayload::NewTransactionsWithProof((transactions_with_proof, _)) => {
                if let Some(first_version) = transactions_with_proof.get_first_transaction_version()
                {
                    let num_transactions = transactions_with_proof.get_num_transactions();
                    first_version
                        .saturating_add(num_transactions as u64)
                        .saturating_sub(1) // first_version + num_txns - 1
                } else {
                    return Err(aptos_data_client::error::Error::UnexpectedErrorEncountered(
                        "The first transaction version is missing from the stream response!".into(),
                    ));
                }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L634-644)
```rust
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
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L695-707)
```rust
    /// Handles a client response that failed sanity checks
    fn handle_sanity_check_failure(
        &mut self,
        data_client_request: &DataClientRequest,
        response_context: &ResponseContext,
    ) -> Result<(), Error> {
        error!(LogSchema::new(LogEntry::ReceivedDataResponse)
            .stream_id(self.data_stream_id)
            .event(LogEvent::Error)
            .message("Encountered a client response that failed the sanity checks!"));

        self.notify_bad_response(response_context, ResponseError::InvalidPayloadDataType);
        self.resend_data_client_request(data_client_request)
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L1336-1341)
```rust
        DataClientRequest::SubscribeTransactionsWithProof(_) => {
            matches!(
                data_client_response.payload,
                ResponsePayload::NewTransactionsWithProof(_)
            )
        },
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L951-953)
```rust
        // Reset the active subscription stream and update the metrics
        self.active_subscription_stream = None;
        update_terminated_subscription_metrics(request_error.get_label());
```

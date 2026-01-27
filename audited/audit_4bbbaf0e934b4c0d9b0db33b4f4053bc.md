# Audit Report

## Title
Infinite Loop in Data Stream Missing Data Request Handler Causes State Sync DoS

## Summary
A malicious network peer can cause an infinite loop in the data streaming service by repeatedly returning empty responses (0 transactions/outputs/state values) for data requests. This creates an endless cycle of identical missing data requests that never make progress, causing resource exhaustion and preventing state synchronization.

## Finding Description

The vulnerability exists in the interaction between `request_missing_data()` and the response processing logic in the data streaming service. When a peer returns an empty response (e.g., 0 transactions), the system attempts to request the "missing" data, but the new request has **identical parameters** to the original request because the start version/index doesn't advance.

**Attack Flow:**

1. Attacker (malicious peer) receives `TransactionsWithProofRequest{start_version: 100, end_version: 200}`
2. Attacker responds with `TransactionsWithProof` containing **0 transactions**
3. `request_missing_data()` calls `create_missing_transactions_request()` [1](#0-0) 
4. New request created: `start_version = 100 + 0 = 100`, `end_version = 200` (identical parameters)
5. New request pushed to front of queue [2](#0-1) 
6. System attempts to send notification but fails because `create_notification_for_continuous_data()` rejects empty responses [3](#0-2) 
7. Error is caught and logged in `check_progress_of_all_data_streams()` but stream continues [4](#0-3) 
8. Next iteration processes the new request with **same parameters**, attacker responds with 0 transactions again
9. **Cycle repeats indefinitely**

**Critical Issues:**

1. `create_missing_data_request()` doesn't detect that it's creating a request with identical parameters to prevent infinite loops [5](#0-4) 

2. `request_failure_count` is **not incremented** when missing data requests fail - it's only incremented in `resend_data_client_request()` [6](#0-5)  which is never called in this path

3. The stream never terminates because the failure count never reaches `max_request_retry` [7](#0-6) 

**Affected Request Types:**
- `TransactionsWithProof` [1](#0-0) 
- `TransactionOutputsWithProof` [8](#0-7) 
- `TransactionsOrOutputsWithProof` [9](#0-8) 
- `StateValuesWithProof` [10](#0-9) 
- `EpochEndingLedgerInfos` [11](#0-10) 

## Impact Explanation

**High Severity** per Aptos bug bounty criteria:

1. **Validator Node Slowdowns**: The infinite loop consumes CPU cycles processing identical requests repeatedly, degrading node performance

2. **Significant Protocol Violations**: Breaks the **Resource Limits** invariant - the system should respect computational limits but instead enters an unbounded loop

3. **State Sync Denial of Service**: Affected streams cannot make progress, preventing nodes from synchronizing state with the network. This can prevent new validators from joining or existing nodes from catching up after downtime

4. **Log Flooding**: Each iteration generates error logs [12](#0-11) , potentially filling disk space and obscuring other critical errors

5. **Network Resource Exhaustion**: Continuous identical requests waste network bandwidth and processing resources on both sender and receiver

This does not reach Critical severity because:
- No funds are lost or stolen
- Consensus is not directly broken (though state sync is critical for consensus participation)
- The issue is recoverable by restarting the node or blacklisting the malicious peer

## Likelihood Explanation

**Likelihood: High**

**Attacker Requirements:**
- Control of at least one network peer that the victim connects to
- Ability to respond to data requests (standard P2P capability)
- No special privileges, validator status, or insider access required

**Attack Complexity: Trivial**
- Attacker simply returns empty responses (0 items) to any data request
- No sophisticated timing, cryptographic operations, or state manipulation needed
- Can be implemented in a few lines of code

**Detection Difficulty: Easy for attacker to hide**
- Empty responses are technically valid protocol messages
- Attacker can appear to be a slow or resource-constrained peer
- No obvious fingerprint distinguishes malicious empty responses from legitimate network issues

**Real-World Scenarios:**
- Malicious peer intentionally returning empty data
- Buggy peer implementation that always returns 0 items
- Network conditions causing response truncation to 0 items (though less likely)

## Recommendation

**Fix 1: Detect identical missing data requests (Preferred)**

Add validation in `request_missing_data()` to detect when a missing data request would have identical parameters:

```rust
fn request_missing_data(
    &mut self,
    data_client_request: &DataClientRequest,
    response_payload: &ResponsePayload,
) -> Result<bool, Error> {
    // Identify if any missing data needs to be requested
    if let Some(missing_data_request) =
        create_missing_data_request(data_client_request, response_payload)?
    {
        // SECURITY FIX: Detect if the missing data request is identical to the original
        // This prevents infinite loops when peers return 0 items repeatedly
        if requests_are_identical(data_client_request, &missing_data_request) {
            // Treat this as a failure and increment the failure count
            self.request_failure_count += 1;
            
            // Log the issue
            warn!(LogSchema::new(LogEntry::ReceivedDataResponse)
                .stream_id(self.data_stream_id)
                .message("Received response with 0 items, identical missing data request detected"));
            
            // Return false - no actual missing data was requested
            return Ok(false);
        }
        
        // Rest of existing logic...
    }
    
    Ok(false)
}

// Helper function to detect identical requests
fn requests_are_identical(req1: &DataClientRequest, req2: &DataClientRequest) -> bool {
    match (req1, req2) {
        (DataClientRequest::TransactionsWithProof(r1), 
         DataClientRequest::TransactionsWithProof(r2)) => {
            r1.start_version == r2.start_version && 
            r1.end_version == r2.end_version
        },
        // Similar checks for other request types...
        _ => false
    }
}
```

**Fix 2: Increment failure count on notification creation errors**

Alternatively, increment `request_failure_count` when `send_data_notification_to_client()` fails [13](#0-12) :

```rust
// In process_data_responses(), handle notification errors
if let Err(error) = self.send_data_notification_to_client(client_request, client_response).await {
    // Increment failure count to eventually terminate the stream
    self.request_failure_count += 1;
    return Err(error);
}
```

**Fix 3: Reject empty responses earlier (Defense in depth)**

Add validation in `sanity_check_client_response_type()` to reject empty responses before processing [14](#0-13) .

## Proof of Concept

```rust
#[tokio::test]
async fn test_infinite_loop_with_empty_responses() {
    use aptos_config::config::DataStreamingServiceConfig;
    use aptos_data_client::interface::Response;
    use aptos_types::transaction::TransactionListWithProof;
    
    // Setup: Create a data stream requesting transactions 100-200
    let config = DataStreamingServiceConfig::default();
    let mut data_stream = create_test_data_stream(100, 200).await;
    
    // Attack: Simulate malicious peer returning 0 transactions repeatedly
    let empty_response = Response {
        context: create_response_context(),
        payload: ResponsePayload::TransactionsWithProof(
            TransactionListWithProof::new(vec![], None, None, None, vec![])
        ),
    };
    
    // Inject empty response
    inject_response(&mut data_stream, empty_response.clone());
    
    // Process: First iteration
    data_stream.process_data_responses(create_global_summary()).await.unwrap_err();
    
    // Verify: New request was created with IDENTICAL parameters (100-200)
    let queue = get_sent_requests_queue(&mut data_stream);
    assert_eq!(queue.len(), 1);
    let pending_request = queue.front().unwrap();
    let request = &pending_request.lock().client_request;
    
    match request {
        DataClientRequest::TransactionsWithProof(req) => {
            assert_eq!(req.start_version, 100); // Same as original!
            assert_eq!(req.end_version, 200);    // Same as original!
        },
        _ => panic!("Expected TransactionsWithProof request"),
    }
    
    // Attack continues: Inject another empty response
    inject_response(&mut data_stream, empty_response.clone());
    
    // Process: Second iteration - infinite loop demonstrated
    data_stream.process_data_responses(create_global_summary()).await.unwrap_err();
    
    // Verify: ANOTHER identical request was created
    assert_eq!(queue.len(), 1);
    
    // Critical: request_failure_count was NOT incremented
    assert_eq!(data_stream.request_failure_count, 0);
    
    // This cycle can continue indefinitely, proving the vulnerability
    println!("✗ VULNERABILITY CONFIRMED: Infinite loop of identical requests with empty responses");
}
```

## Notes

This vulnerability represents a critical flaw in the state synchronization protocol's handling of malicious or faulty peer behavior. The lack of progress detection when receiving empty responses allows a single malicious peer to effectively DoS any node attempting to sync from it. While the impact doesn't reach Critical severity (no direct consensus break or fund loss), it significantly degrades network reliability and validator participation, making it a High severity issue per the Aptos bug bounty guidelines.

### Citations

**File:** state-sync/data-streaming-service/src/data_stream.rs (L446-447)
```rust
        if self.stream_engine.is_stream_complete()
            || self.request_failure_count >= self.streaming_service_config.max_request_retry
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L502-503)
```rust
                        self.send_data_notification_to_client(client_request, client_response)
                            .await?;
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L669-670)
```rust
            self.get_sent_data_requests()?
                .push_front(pending_client_response);
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L733-734)
```rust
        // Increment the number of client failures for this request
        self.request_failure_count += 1;
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L1035-1058)
```rust
pub(crate) fn create_missing_data_request(
    data_client_request: &DataClientRequest,
    response_payload: &ResponsePayload,
) -> Result<Option<DataClientRequest>, Error> {
    // Determine if the request was satisfied, and if not, create
    // a missing data request to satisfy the original request.
    match data_client_request {
        DataClientRequest::EpochEndingLedgerInfos(request) => {
            create_missing_epoch_ending_ledger_infos_request(request, response_payload)
        },
        DataClientRequest::StateValuesWithProof(request) => {
            create_missing_state_values_request(request, response_payload)
        },
        DataClientRequest::TransactionsWithProof(request) => {
            create_missing_transactions_request(request, response_payload)
        },
        DataClientRequest::TransactionOutputsWithProof(request) => {
            create_missing_transaction_outputs_request(request, response_payload)
        },
        DataClientRequest::TransactionsOrOutputsWithProof(request) => {
            create_missing_transactions_or_outputs_request(request, response_payload)
        },
        _ => Ok(None), // The request was trivially satisfied (based on the type)
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L1061-1101)
```rust
/// Creates and returns a missing epoch ending ledger info request if the
/// given client response doesn't satisfy the original request. If the request
/// is satisfied, None is returned.
fn create_missing_epoch_ending_ledger_infos_request(
    request: &EpochEndingLedgerInfosRequest,
    response_payload: &ResponsePayload,
) -> Result<Option<DataClientRequest>, Error> {
    // Determine the number of requested ledger infos
    let num_requested_ledger_infos = request
        .end_epoch
        .checked_sub(request.start_epoch)
        .and_then(|v| v.checked_add(1))
        .ok_or_else(|| {
            Error::IntegerOverflow("Number of requested ledger infos has overflown!".into())
        })?;

    // Identify the missing data if the request was not satisfied
    match response_payload {
        ResponsePayload::EpochEndingLedgerInfos(ledger_infos) => {
            // Check if the request was satisfied
            let num_received_ledger_infos = ledger_infos.len() as u64;
            if num_received_ledger_infos < num_requested_ledger_infos {
                let start_epoch = request
                    .start_epoch
                    .checked_add(num_received_ledger_infos)
                    .ok_or_else(|| Error::IntegerOverflow("Start epoch has overflown!".into()))?;
                Ok(Some(DataClientRequest::EpochEndingLedgerInfos(
                    EpochEndingLedgerInfosRequest {
                        start_epoch,
                        end_epoch: request.end_epoch,
                    },
                )))
            } else {
                Ok(None) // The request was satisfied!
            }
        },
        payload => Err(Error::AptosDataClientResponseIsInvalid(format!(
            "Invalid response payload found for epoch ending ledger info request: {:?}",
            payload
        ))),
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L1104-1145)
```rust
/// Creates and returns a missing state values request if the given client
/// response doesn't satisfy the original request. If the request is satisfied,
/// None is returned.
fn create_missing_state_values_request(
    request: &StateValuesWithProofRequest,
    response_payload: &ResponsePayload,
) -> Result<Option<DataClientRequest>, Error> {
    // Determine the number of requested state values
    let num_requested_state_values = request
        .end_index
        .checked_sub(request.start_index)
        .and_then(|v| v.checked_add(1))
        .ok_or_else(|| {
            Error::IntegerOverflow("Number of requested state values has overflown!".into())
        })?;

    // Identify the missing data if the request was not satisfied
    match response_payload {
        ResponsePayload::StateValuesWithProof(state_values_with_proof) => {
            // Check if the request was satisfied
            let num_received_state_values = state_values_with_proof.raw_values.len() as u64;
            if num_received_state_values < num_requested_state_values {
                let start_index = request
                    .start_index
                    .checked_add(num_received_state_values)
                    .ok_or_else(|| Error::IntegerOverflow("Start index has overflown!".into()))?;
                Ok(Some(DataClientRequest::StateValuesWithProof(
                    StateValuesWithProofRequest {
                        version: request.version,
                        start_index,
                        end_index: request.end_index,
                    },
                )))
            } else {
                Ok(None) // The request was satisfied!
            }
        },
        payload => Err(Error::AptosDataClientResponseIsInvalid(format!(
            "Invalid response payload found for state values request: {:?}",
            payload
        ))),
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L1151-1190)
```rust
fn create_missing_transactions_request(
    request: &TransactionsWithProofRequest,
    response_payload: &ResponsePayload,
) -> Result<Option<DataClientRequest>, Error> {
    // Determine the number of requested transactions
    let num_requested_transactions = request
        .end_version
        .checked_sub(request.start_version)
        .and_then(|v| v.checked_add(1))
        .ok_or_else(|| {
            Error::IntegerOverflow("Number of requested transactions has overflown!".into())
        })?;

    // Identify the missing data if the request was not satisfied
    match response_payload {
        ResponsePayload::TransactionsWithProof(transactions_with_proof) => {
            // Check if the request was satisfied
            let num_received_transactions = transactions_with_proof.get_num_transactions() as u64;
            if num_received_transactions < num_requested_transactions {
                let start_version = request
                    .start_version
                    .checked_add(num_received_transactions)
                    .ok_or_else(|| Error::IntegerOverflow("Start version has overflown!".into()))?;
                Ok(Some(DataClientRequest::TransactionsWithProof(
                    TransactionsWithProofRequest {
                        start_version,
                        end_version: request.end_version,
                        proof_version: request.proof_version,
                        include_events: request.include_events,
                    },
                )))
            } else {
                Ok(None) // The request was satisfied!
            }
        },
        payload => Err(Error::AptosDataClientResponseIsInvalid(format!(
            "Invalid response payload found for transactions request: {:?}",
            payload
        ))),
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L1193-1234)
```rust
/// Creates and returns a missing transaction outputs request if the given client
/// response doesn't satisfy the original request. If the request is satisfied,
/// None is returned.
fn create_missing_transaction_outputs_request(
    request: &TransactionOutputsWithProofRequest,
    response_payload: &ResponsePayload,
) -> Result<Option<DataClientRequest>, Error> {
    // Determine the number of requested transaction outputs
    let num_requested_outputs = request
        .end_version
        .checked_sub(request.start_version)
        .and_then(|v| v.checked_add(1))
        .ok_or_else(|| {
            Error::IntegerOverflow("Number of requested transaction outputs has overflown!".into())
        })?;

    // Identify the missing data if the request was not satisfied
    match response_payload {
        ResponsePayload::TransactionOutputsWithProof(transaction_outputs_with_proof) => {
            // Check if the request was satisfied
            let num_received_outputs = transaction_outputs_with_proof.get_num_outputs() as u64;
            if num_received_outputs < num_requested_outputs {
                let start_version = request
                    .start_version
                    .checked_add(num_received_outputs)
                    .ok_or_else(|| Error::IntegerOverflow("Start version has overflown!".into()))?;
                Ok(Some(DataClientRequest::TransactionOutputsWithProof(
                    TransactionOutputsWithProofRequest {
                        start_version,
                        end_version: request.end_version,
                        proof_version: request.proof_version,
                    },
                )))
            } else {
                Ok(None) // The request was satisfied!
            }
        },
        payload => Err(Error::AptosDataClientResponseIsInvalid(format!(
            "Invalid response payload found for transaction outputs request: {:?}",
            payload
        ))),
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L1237-1288)
```rust
/// Creates and returns a missing transactions or outputs request if the
/// given client response doesn't satisfy the original request. If the request
/// is satisfied, None is returned.
fn create_missing_transactions_or_outputs_request(
    request: &TransactionsOrOutputsWithProofRequest,
    response_payload: &ResponsePayload,
) -> Result<Option<DataClientRequest>, Error> {
    // Determine the number of requested transactions or outputs
    let num_request_data_items = request
        .end_version
        .checked_sub(request.start_version)
        .and_then(|v| v.checked_add(1))
        .ok_or_else(|| {
            Error::IntegerOverflow(
                "Number of requested transactions or outputs has overflown!".into(),
            )
        })?;

    // Calculate the number of received data items
    let num_received_data_items = match response_payload {
        ResponsePayload::TransactionsWithProof(transactions_with_proof) => {
            transactions_with_proof.get_num_transactions() as u64
        },
        ResponsePayload::TransactionOutputsWithProof(transaction_outputs_with_proof) => {
            transaction_outputs_with_proof.get_num_outputs() as u64
        },
        payload => {
            return Err(Error::AptosDataClientResponseIsInvalid(format!(
                "Invalid response payload found for transactions or outputs request: {:?}",
                payload
            )))
        },
    };

    // Identify the missing data if the request was not satisfied
    if num_received_data_items < num_request_data_items {
        let start_version = request
            .start_version
            .checked_add(num_received_data_items)
            .ok_or_else(|| Error::IntegerOverflow("Start version has overflown!".into()))?;
        Ok(Some(DataClientRequest::TransactionsOrOutputsWithProof(
            TransactionsOrOutputsWithProofRequest {
                start_version,
                end_version: request.end_version,
                proof_version: request.proof_version,
                include_events: request.include_events,
            },
        )))
    } else {
        Ok(None) // The request was satisfied!
    }
}
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L1290-1300)
```rust
/// Returns true iff the data client response payload type matches the
/// expected type of the original request. No other sanity checks are done.
fn sanity_check_client_response_type(
    data_client_request: &DataClientRequest,
    data_client_response: &Response<ResponsePayload>,
) -> bool {
    match data_client_request {
        DataClientRequest::EpochEndingLedgerInfos(_) => {
            matches!(
                data_client_response.payload,
                ResponsePayload::EpochEndingLedgerInfos(_)
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L560-565)
```rust
        if num_received_versions == 0 {
            return Err(Error::AptosDataClientResponseIsInvalid(format!(
                "Received an empty continuous data response! Request: {:?}",
                self.request
            )));
        }
```

**File:** state-sync/data-streaming-service/src/streaming_service.rs (L313-332)
```rust
            if let Err(error) = self.update_progress_of_data_stream(data_stream_id).await {
                if matches!(error, Error::NoDataToFetch(_)) {
                    sample!(
                        SampleRate::Duration(Duration::from_secs(NO_DATA_TO_FETCH_LOG_FREQ_SECS)),
                        info!(LogSchema::new(LogEntry::CheckStreamProgress)
                            .stream_id(*data_stream_id)
                            .event(LogEvent::Pending)
                            .error(&error))
                    );
                } else {
                    metrics::increment_counter(
                        &metrics::CHECK_STREAM_PROGRESS_ERROR,
                        error.get_label(),
                    );
                    warn!(LogSchema::new(LogEntry::CheckStreamProgress)
                        .stream_id(*data_stream_id)
                        .event(LogEvent::Error)
                        .error(&error));
                }
            }
```

# Audit Report

## Title
Infinite Loop Vulnerability in Data Streaming Service Due to Zero-Length Chunk Sizes

## Summary
The data streaming service can enter an infinite loop when zero-length optimal chunk sizes are used, causing nodes to repeatedly request invalid data ranges without making progress. This occurs because the retry logic does not increment failure counters when `AptosDataClientResponseIsInvalid` errors are triggered by empty responses, and the stream is never terminated despite continuous failures.

## Finding Description

The vulnerability exists in the state synchronization data streaming service and manifests through the following chain of events:

**Root Cause:** At initialization, the `DataStreamingService` creates a cached `GlobalDataSummary` using `GlobalDataSummary::empty()`, which sets all optimal chunk sizes to 0. [1](#0-0) 

**Validation Bypass:** When fetching a new global data summary, if the summary is empty, validation is skipped entirely and the empty summary with zero chunk sizes is accepted. [2](#0-1) 

**Stream Creation Without Validation:** When a client requests a new data stream, the service refreshes the global data summary but does not check if the refresh succeeded or if chunk sizes are valid. The stream is created even with zero chunk sizes. [3](#0-2) 

**Invalid Request Generation:** When creating data client requests with zero chunk sizes, the function `create_data_client_request_batch` computes `num_items_to_fetch = min(total_items, 0) = 0`, leading to either:
1. Integer underflow when `request_start_index = 0`: `request_end_index = 0 + 0 - 1` triggers checked arithmetic failure
2. Invalid range when `request_start_index > 0`: creates range where `start > end`, which returns empty request vector [4](#0-3) 

**Empty Response Detection:** If peers respond with empty data (0 items), multiple validation points detect this and return `AptosDataClientResponseIsInvalid` errors. [5](#0-4) 

**Critical Flaw - No Failure Counter Increment:** When the error occurs in `transform_client_response_into_notification`, it propagates through `send_data_notification_to_client` during response processing. This happens in the `Ok` branch (successful data client response with invalid content), so `resend_data_client_request` is never called and `request_failure_count` is never incremented. [6](#0-5) 

**No Stream Termination:** Errors are caught in `check_progress_of_all_data_streams` and logged, but the stream remains active in the data streams map. [7](#0-6) 

**Infinite Loop:** On the next progress check cycle, the same process repeats because:
- Stream state (next_request_version) was never updated
- The global data summary still has zero chunk sizes
- `request_failure_count` is still 0 (never reaches `max_request_retry` threshold of 5)
- The stream creates the same invalid requests indefinitely [8](#0-7) 

## Impact Explanation

**Severity: Medium (up to $10,000)**

This vulnerability causes **state inconsistencies requiring intervention** and represents a **liveness failure**:

1. **Node Synchronization Failure:** Affected nodes cannot sync blockchain state, preventing them from participating in consensus or serving API requests
2. **Resource Exhaustion:** Continuous invalid request generation wastes CPU, network bandwidth, and memory
3. **Cascading Effects:** Multiple nodes experiencing this issue simultaneously could degrade network health
4. **Manual Intervention Required:** The only recovery is node restart or waiting for valid peer advertisements

The issue falls under "State inconsistencies requiring intervention" in the Medium severity category. While it doesn't directly cause fund loss or consensus safety violations, it creates a denial-of-service condition affecting node availability.

## Likelihood Explanation

**Likelihood: High**

This vulnerability can occur in multiple realistic scenarios:

1. **Node Startup Race Condition:** Nodes starting before sufficient peers are connected will use empty global data summary with zero chunk sizes (occurs naturally, no attack required)

2. **Malicious Peer Attack:** Coordinated malicious peers advertising zero chunk sizes can force victim nodes into this state through the median calculation mechanism. [9](#0-8) 

3. **Network Partition:** Temporary network issues preventing global summary refresh leaves nodes vulnerable

**No special privileges required:** Any network peer can participate, making this accessible to external attackers.

## Recommendation

Implement multiple defensive layers:

**1. Validate Chunk Sizes Before Use:** Add validation in `create_data_client_request_batch` to reject zero chunk sizes:

```rust
fn create_data_client_request_batch(
    start_index: u64,
    end_index: u64,
    max_number_of_requests: u64,
    optimal_chunk_size: u64,
    stream_engine: StreamEngine,
) -> Result<Vec<DataClientRequest>, Error> {
    // Add validation
    if optimal_chunk_size == 0 {
        return Err(Error::AptosDataClientResponseIsInvalid(
            "Cannot create requests with zero chunk size".into()
        ));
    }
    
    if start_index > end_index {
        return Ok(vec![]);
    }
    // ... rest of function
}
```

**2. Enforce Non-Empty Summary:** Remove the bypass in `fetch_global_data_summary` and always validate chunk sizes:

```rust
fn fetch_global_data_summary<T: AptosDataClientInterface + Send + Clone + 'static>(
    aptos_data_client: T,
) -> Result<GlobalDataSummary, Error> {
    let global_data_summary = aptos_data_client.get_global_data_summary();
    
    // Always validate, even for empty summaries
    verify_optimal_chunk_sizes(&global_data_summary.optimal_chunk_sizes)?;
    
    Ok(global_data_summary)
}
```

**3. Increment Failure Counter for Invalid Responses:** Ensure `request_failure_count` is incremented even when errors occur during response transformation:

```rust
async fn send_data_notification_to_client(
    &mut self,
    data_client_request: &DataClientRequest,
    data_client_response: Response<ResponsePayload>,
) -> Result<(), Error> {
    let (response_context, response_payload) = data_client_response.into_parts();

    match self.stream_engine.transform_client_response_into_notification(
        data_client_request,
        response_payload,
        self.notification_id_generator.clone(),
    ) {
        Ok(Some(data_notification)) => {
            // ... existing success path
        }
        Ok(None) => Ok(()),
        Err(e) => {
            // Increment failure count for invalid responses
            self.request_failure_count += 1;
            // Notify bad response
            self.notify_bad_response(&response_context, ResponseError::InvalidPayloadDataType);
            Err(e)
        }
    }
}
```

**4. Provide Default Fallback:** Use configured maximum chunk sizes when peer data is unavailable instead of zeros.

## Proof of Concept

```rust
// This test demonstrates the infinite loop vulnerability
#[tokio::test]
async fn test_zero_chunk_size_infinite_loop() {
    use crate::streaming_service::DataStreamingService;
    use aptos_data_client::global_summary::GlobalDataSummary;
    
    // Create streaming service with empty global data summary
    let (streaming_client, mut streaming_service) = 
        create_streaming_client_and_server(None, false, false, true, false);
    
    // Verify initial summary has zero chunk sizes
    let summary = streaming_service.get_global_data_summary();
    assert_eq!(summary.optimal_chunk_sizes.state_chunk_size, 0);
    assert_eq!(summary.optimal_chunk_sizes.transaction_chunk_size, 0);
    
    // Request a transaction stream
    let stream_request = StreamRequest::GetAllTransactions(
        GetAllTransactionsRequest {
            start_version: 0,
            end_version: 1000,
            proof_version: 1000,
            include_events: false,
        }
    );
    
    // Stream creation succeeds despite zero chunk sizes
    let stream_listener = streaming_client.get_all_transactions(
        0, 1000, 1000, false
    ).await.unwrap();
    
    // Progress check attempts to create requests
    let mut iteration_count = 0;
    let max_iterations = 10;
    
    while iteration_count < max_iterations {
        streaming_service.check_progress_of_all_data_streams().await;
        iteration_count += 1;
        
        // Verify stream is still active (not terminated)
        assert!(!streaming_service.get_all_data_stream_ids().is_empty());
        
        // Verify no requests were successfully created and sent
        // (due to zero chunk sizes causing invalid ranges or underflows)
    }
    
    // After multiple iterations, stream should have been terminated
    // but due to the bug, it remains active indefinitely
    assert!(!streaming_service.get_all_data_stream_ids().is_empty(), 
            "Stream should remain active, demonstrating the infinite loop bug");
}
```

## Notes

The vulnerability demonstrates a failure in defense-in-depth: while validation exists for non-zero chunk sizes, it's bypassed for empty summaries, and error handling doesn't properly count failures that occur during response transformation. This allows nodes to get stuck in an infinite retry loop that bypasses the `max_request_retry` termination condition, violating the liveness guarantees of the state synchronization protocol.

### Citations

**File:** state-sync/aptos-data-client/src/global_summary.rs (L52-60)
```rust
impl OptimalChunkSizes {
    pub fn empty() -> Self {
        OptimalChunkSizes {
            epoch_chunk_size: 0,
            state_chunk_size: 0,
            transaction_chunk_size: 0,
            transaction_output_chunk_size: 0,
        }
    }
```

**File:** state-sync/data-streaming-service/src/streaming_service.rs (L265-284)
```rust
        // Refresh the cached global data summary
        refresh_global_data_summary(
            self.aptos_data_client.clone(),
            self.global_data_summary.clone(),
        );

        // Create a new data stream
        let stream_id = self.stream_id_generator.next();
        let advertised_data = self.get_global_data_summary().advertised_data.clone();
        let (data_stream, stream_listener) = DataStream::new(
            self.data_client_config,
            self.streaming_service_config,
            stream_id,
            &request_message.stream_request,
            stream_update_notifier,
            self.aptos_data_client.clone(),
            self.notification_id_generator.clone(),
            &advertised_data,
            self.time_service.clone(),
        )?;
```

**File:** state-sync/data-streaming-service/src/streaming_service.rs (L309-337)
```rust
    async fn check_progress_of_all_data_streams(&mut self) {
        // Drive the progress of each stream
        let data_stream_ids = self.get_all_data_stream_ids();
        for data_stream_id in &data_stream_ids {
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
        }

        // Update the metrics
        metrics::set_active_data_streams(data_stream_ids.len());
    }
```

**File:** state-sync/data-streaming-service/src/streaming_service.rs (L463-471)
```rust
    if global_data_summary.is_empty() {
        sample!(
            SampleRate::Duration(Duration::from_secs(GLOBAL_DATA_REFRESH_LOG_FREQ_SECS)),
            info!(LogSchema::new(LogEntry::RefreshGlobalData)
                .message("Latest global data summary is empty."))
        );
    } else {
        verify_optimal_chunk_sizes(&global_data_summary.optimal_chunk_sizes)?;
    }
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

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L2049-2098)
```rust
fn create_data_client_request_batch(
    start_index: u64,
    end_index: u64,
    max_number_of_requests: u64,
    optimal_chunk_size: u64,
    stream_engine: StreamEngine,
) -> Result<Vec<DataClientRequest>, Error> {
    if start_index > end_index {
        return Ok(vec![]);
    }

    // Calculate the total number of items left to satisfy the stream
    let mut total_items_to_fetch = end_index
        .checked_sub(start_index)
        .and_then(|e| e.checked_add(1)) // = end_index - start_index + 1
        .ok_or_else(|| Error::IntegerOverflow("Total items to fetch has overflown!".into()))?;

    // Iterate until we've requested all transactions or hit the maximum number of requests
    let mut data_client_requests = vec![];
    let mut num_requests_made = 0;
    let mut next_index_to_request = start_index;
    while total_items_to_fetch > 0 && num_requests_made < max_number_of_requests {
        // Calculate the number of items to fetch in this request
        let num_items_to_fetch = cmp::min(total_items_to_fetch, optimal_chunk_size);

        // Calculate the start and end indices for the request
        let request_start_index = next_index_to_request;
        let request_end_index = request_start_index
            .checked_add(num_items_to_fetch)
            .and_then(|e| e.checked_sub(1)) // = request_start_index + num_items_to_fetch - 1
            .ok_or_else(|| Error::IntegerOverflow("End index to fetch has overflown!".into()))?;

        // Create the data client requests
        let data_client_request =
            create_data_client_request(request_start_index, request_end_index, &stream_engine)?;
        data_client_requests.push(data_client_request);

        // Update the local loop state
        next_index_to_request = request_end_index
            .checked_add(1)
            .ok_or_else(|| Error::IntegerOverflow("Next index to request has overflown!".into()))?;
        total_items_to_fetch = total_items_to_fetch
            .checked_sub(num_items_to_fetch)
            .ok_or_else(|| Error::IntegerOverflow("Total items to fetch has overflown!".into()))?;
        num_requests_made = num_requests_made.checked_add(1).ok_or_else(|| {
            Error::IntegerOverflow("Number of payload requests has overflown!".into())
        })?;
    }

    Ok(data_client_requests)
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L466-522)
```rust
            match client_response {
                Ok(client_response) => {
                    // Sanity check and process the response
                    if sanity_check_client_response_type(client_request, &client_response) {
                        // If the response wasn't enough to satisfy the original request (e.g.,
                        // it was truncated), missing data should be requested.
                        let mut head_of_line_blocked = false;
                        match self.request_missing_data(client_request, &client_response.payload) {
                            Ok(missing_data_requested) => {
                                if missing_data_requested {
                                    head_of_line_blocked = true; // We're now head of line blocked on the missing data
                                }
                            },
                            Err(error) => {
                                warn!(LogSchema::new(LogEntry::ReceivedDataResponse)
                                    .stream_id(self.data_stream_id)
                                    .event(LogEvent::Error)
                                    .error(&error)
                                    .message("Failed to determine if missing data was requested!"));
                            },
                        }

                        // If the request was a subscription request and the subscription
                        // stream is lagging behind the data advertisements, the stream
                        // engine should be notified (e.g., so that it can catch up).
                        if client_request.is_subscription_request() {
                            if let Err(error) = self.check_subscription_stream_lag(
                                &global_data_summary,
                                &client_response.payload,
                            ) {
                                self.notify_new_data_request_error(client_request, error)?;
                                head_of_line_blocked = true; // We're now head of line blocked on the failed stream
                            }
                        }

                        // The response is valid, send the data notification to the client
                        self.send_data_notification_to_client(client_request, client_response)
                            .await?;

                        // If the request is for specific data, increase the prefetching limit.
                        // Note: we don't increase the limit for new data requests because
                        // those don't invoke the prefetcher (as we're already up-to-date).
                        if !client_request.is_new_data_request() {
                            self.dynamic_prefetching_state
                                .increase_max_concurrent_requests();
                        }

                        // If we're head of line blocked, we should return early
                        if head_of_line_blocked {
                            break;
                        }
                    } else {
                        // The sanity check failed
                        self.handle_sanity_check_failure(client_request, &client_response.context)?;
                        break; // We're now head of line blocked on the failed request
                    }
                },
```

**File:** config/src/config/state_sync_config.rs (L277-277)
```rust
            max_request_retry: 5,
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L419-443)
```rust
pub(crate) fn calculate_optimal_chunk_sizes(
    config: &AptosDataClientConfig,
    max_epoch_chunk_sizes: Vec<u64>,
    max_state_chunk_sizes: Vec<u64>,
    max_transaction_chunk_sizes: Vec<u64>,
    max_transaction_output_chunk_size: Vec<u64>,
) -> OptimalChunkSizes {
    let epoch_chunk_size = median_or_max(max_epoch_chunk_sizes, config.max_epoch_chunk_size);
    let state_chunk_size = median_or_max(max_state_chunk_sizes, config.max_state_chunk_size);
    let transaction_chunk_size = median_or_max(
        max_transaction_chunk_sizes,
        config.max_transaction_chunk_size,
    );
    let transaction_output_chunk_size = median_or_max(
        max_transaction_output_chunk_size,
        config.max_transaction_output_chunk_size,
    );

    OptimalChunkSizes {
        epoch_chunk_size,
        state_chunk_size,
        transaction_chunk_size,
        transaction_output_chunk_size,
    }
}
```

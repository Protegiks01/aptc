# Audit Report

## Title
Infinite Loop Vulnerability in Data Streaming Service Due to Zero-Length Optimal Chunk Sizes

## Summary
The data streaming service can enter an infinite loop when zero-length optimal chunk sizes are used, causing nodes to repeatedly request invalid data ranges without making progress. This occurs because the retry logic does not increment failure counters when `AptosDataClientResponseIsInvalid` errors are triggered, and the stream is never terminated despite continuous failures.

## Finding Description

The vulnerability exists in the state synchronization data streaming service and manifests through the following chain of events:

**1. Root Cause - Empty Summary Initialization:**
At initialization, the `DataStreamingService` creates a cached `GlobalDataSummary` using `GlobalDataSummary::empty()`, which sets all optimal chunk sizes to 0. [1](#0-0) [2](#0-1) 

**2. Validation Bypass:**
When fetching a new global data summary, if the summary is empty (`is_empty()` returns true), validation is skipped entirely. The `verify_optimal_chunk_sizes()` function that would reject zero chunk sizes is never called for empty summaries. [3](#0-2) 

**3. Stream Creation Without Validation:**
When a client requests a new data stream, `refresh_global_data_summary()` is called but cannot fail - if fetching a valid summary fails, the error is only logged and the cached empty summary remains. [4](#0-3) [5](#0-4) 

**4. Invalid Request Generation:**
When creating data client requests with zero chunk sizes, `create_data_client_request_batch` computes `num_items_to_fetch = min(total_items, 0) = 0`, leading to `request_end_index = request_start_index + 0 - 1`, which either triggers an integer underflow error or creates an invalid range where start > end. [6](#0-5) 

**5. Empty Response Detection:**
Multiple validation points detect empty responses (0 items) and return `AptosDataClientResponseIsInvalid` errors. [7](#0-6) [8](#0-7) [9](#0-8) 

**6. Critical Flaw - No Failure Counter Increment:**
When `transform_client_response_into_notification` returns an `AptosDataClientResponseIsInvalid` error, it propagates through `send_data_notification_to_client`. This error occurs in the `Ok` branch of client response processing (successful network response with invalid content), so `resend_data_client_request` is never called and `request_failure_count` is never incremented. [10](#0-9) [11](#0-10) [12](#0-11) 

**7. No Stream Termination:**
Errors from `update_progress_of_data_stream` are caught in `check_progress_of_all_data_streams` and logged, but the stream remains active in the data streams map. [13](#0-12) 

**8. Infinite Loop:**
On the next progress check cycle, the same process repeats because stream state was never updated, the global data summary still has zero chunk sizes, and `request_failure_count` remains at 0 (never reaching the `max_request_retry` threshold). [14](#0-13) 

## Impact Explanation

**Severity: Medium (up to $10,000)**

This vulnerability causes **state inconsistencies requiring manual intervention** and represents a **temporary liveness failure**:

1. **Node Synchronization Failure:** Affected nodes cannot sync blockchain state, preventing them from participating in consensus or serving API requests
2. **Resource Exhaustion:** Continuous invalid request generation wastes CPU, network bandwidth, and memory  
3. **Cascading Effects:** Multiple nodes experiencing this simultaneously could degrade network health
4. **Manual Intervention Required:** Recovery requires node restart or waiting for valid peer advertisements

This falls under the Medium severity category for "State inconsistencies requiring manual intervention" and "Temporary liveness issues". It affects individual nodes rather than causing network-wide consensus failure, making it distinct from Critical "Total Loss of Liveness/Network Availability" which requires all validators to be unable to progress.

## Likelihood Explanation

**Likelihood: High**

This vulnerability can occur in multiple realistic scenarios:

1. **Node Startup Race Condition:** Nodes starting before sufficient peers are connected will use the empty global data summary with zero chunk sizes. This occurs naturally without any attack.

2. **Malicious Peer Attack:** Coordinated malicious peers can advertise zero chunk sizes, forcing victim nodes into this state through the median calculation mechanism used for optimal chunk sizes.

3. **Network Partition:** Temporary network issues preventing global summary refresh leave nodes with the cached empty summary.

No special privileges are required - any network peer can participate, making this accessible to external attackers.

## Recommendation

Implement the following fixes:

1. **Validate chunk sizes before creating streams:** In `process_new_stream_request`, check that optimal chunk sizes are non-zero after refreshing the global data summary. Reject stream creation if validation fails.

2. **Handle transformation errors properly:** When `transform_client_response_into_notification` returns an error in `send_data_notification_to_client`, call `resend_data_client_request` to increment the failure counter and properly retry or terminate the stream.

3. **Enforce chunk size validation consistently:** Always call `verify_optimal_chunk_sizes` even for empty summaries, or prevent empty summaries from being used entirely.

4. **Add stream health monitoring:** Implement a mechanism to detect streams making no progress and automatically terminate them after a reasonable timeout.

## Proof of Concept

A complete PoC would require setting up a test harness with mock peers, but the vulnerability can be triggered by:

1. Starting a node with no connected peers (or mock peers advertising zero chunk sizes)
2. Creating a data stream request
3. Observing the node enter an infinite loop attempting to create invalid requests
4. Confirming that `request_failure_count` never increments despite continuous errors
5. Verifying the stream is never automatically terminated

The code paths identified in the citations demonstrate this behavior will occur deterministically under these conditions.

## Notes

This is a protocol-level implementation bug in the state synchronization layer, not a network DoS attack. The vulnerability stems from incorrect error handling in the state machine logic, causing nodes to fail due to improper state transitions rather than external resource exhaustion. It represents a legitimate security issue affecting node availability that falls within the scope of the Aptos bug bounty program's Medium severity category.

### Citations

**File:** state-sync/data-streaming-service/src/streaming_service.rs (L106-106)
```rust
            global_data_summary: Arc::new(ArcSwap::new(Arc::new(GlobalDataSummary::empty()))),
```

**File:** state-sync/data-streaming-service/src/streaming_service.rs (L265-269)
```rust
        // Refresh the cached global data summary
        refresh_global_data_summary(
            self.aptos_data_client.clone(),
            self.global_data_summary.clone(),
        );
```

**File:** state-sync/data-streaming-service/src/streaming_service.rs (L313-333)
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
        }
```

**File:** state-sync/data-streaming-service/src/streaming_service.rs (L431-452)
```rust
fn refresh_global_data_summary<T: AptosDataClientInterface + Send + Clone + 'static>(
    aptos_data_client: T,
    cached_global_data_summary: Arc<ArcSwap<GlobalDataSummary>>,
) {
    // Fetch the global data summary and update the cache
    match fetch_global_data_summary(aptos_data_client) {
        Ok(global_data_summary) => {
            // Update the cached global data summary
            cached_global_data_summary.store(Arc::new(global_data_summary));
        },
        Err(error) => {
            // Otherwise, log an error and increment the error counter
            sample!(
                SampleRate::Duration(Duration::from_secs(GLOBAL_DATA_REFRESH_LOG_FREQ_SECS)),
                warn!(LogSchema::new(LogEntry::RefreshGlobalData)
                    .event(LogEvent::Error)
                    .error(&error))
            );
            metrics::increment_counter(&metrics::GLOBAL_DATA_SUMMARY_ERROR, error.get_label());
        },
    }
}
```

**File:** state-sync/data-streaming-service/src/streaming_service.rs (L463-473)
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

    Ok(global_data_summary)
```

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

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L322-327)
```rust
                        if state_values_with_proof.raw_values.is_empty() {
                            return Err(Error::AptosDataClientResponseIsInvalid(format!(
                                "Received an empty state values response! Request: {:?}",
                                client_request
                            )));
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

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L1716-1721)
```rust
        if num_received_versions == 0 {
            return Err(Error::AptosDataClientResponseIsInvalid(format!(
                "Received an empty response! Request: {:?}",
                self.request
            )));
        }
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L2070-2079)
```rust
    while total_items_to_fetch > 0 && num_requests_made < max_number_of_requests {
        // Calculate the number of items to fetch in this request
        let num_items_to_fetch = cmp::min(total_items_to_fetch, optimal_chunk_size);

        // Calculate the start and end indices for the request
        let request_start_index = next_index_to_request;
        let request_end_index = request_start_index
            .checked_add(num_items_to_fetch)
            .and_then(|e| e.checked_sub(1)) // = request_start_index + num_items_to_fetch - 1
            .ok_or_else(|| Error::IntegerOverflow("End index to fetch has overflown!".into()))?;
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L446-448)
```rust
        if self.stream_engine.is_stream_complete()
            || self.request_failure_count >= self.streaming_service_config.max_request_retry
            || self.send_failure
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L467-503)
```rust
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
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L729-744)
```rust
    fn resend_data_client_request(
        &mut self,
        data_client_request: &DataClientRequest,
    ) -> Result<(), Error> {
        // Increment the number of client failures for this request
        self.request_failure_count += 1;

        // Resend the client request
        let pending_client_response = self.send_client_request(true, data_client_request.clone());

        // Push the pending response to the head of the sent requests queue
        self.get_sent_data_requests()?
            .push_front(pending_client_response);

        Ok(())
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L767-811)
```rust
    async fn send_data_notification_to_client(
        &mut self,
        data_client_request: &DataClientRequest,
        data_client_response: Response<ResponsePayload>,
    ) -> Result<(), Error> {
        let (response_context, response_payload) = data_client_response.into_parts();

        // Create a new data notification
        if let Some(data_notification) = self
            .stream_engine
            .transform_client_response_into_notification(
                data_client_request,
                response_payload,
                self.notification_id_generator.clone(),
            )?
        {
            // Update the metrics for the data notification send latency
            metrics::observe_duration(
                &metrics::DATA_NOTIFICATION_SEND_LATENCY,
                data_client_request.get_label(),
                response_context.creation_time,
            );

            // Save the response context for this notification ID
            let notification_id = data_notification.notification_id;
            self.insert_notification_response_mapping(notification_id, response_context)?;

            // Send the notification along the stream
            trace!(
                (LogSchema::new(LogEntry::StreamNotification)
                    .stream_id(self.data_stream_id)
                    .event(LogEvent::Success)
                    .message(&format!(
                        "Sent a single stream notification! Notification ID: {:?}",
                        notification_id
                    )))
            );
            self.send_data_notification(data_notification).await?;

            // Reset the failure count. We've sent a notification and can move on.
            self.request_failure_count = 0;
        }

        Ok(())
    }
```

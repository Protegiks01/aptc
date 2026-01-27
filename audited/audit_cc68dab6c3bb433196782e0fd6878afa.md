# Audit Report

## Title
Subscription Processing Resource Starvation in Data Streaming Service

## Summary
The data streaming service processes multiple concurrent data streams sequentially without fairness guarantees, allowing one subscription with many pending responses to monopolize processing time and starve other subscriptions.

## Finding Description

The `DataStreamingService` maintains multiple concurrent data streams in a `HashMap<DataStreamId, DataStream<T>>` structure. [1](#0-0) 

When checking progress of all streams, the service iterates through streams sequentially in an unfair manner: [2](#0-1) 

For each stream, the `process_data_responses` method contains a while loop that processes **all** ready responses before returning control: [3](#0-2) 

Each response processing involves an async `send_data_notification` call which can block if the consumer channel is full or slow. The developers acknowledged this issue explicitly: [4](#0-3) 

The vulnerability manifests when:
1. Multiple data streams exist concurrently (verified possible in tests: [5](#0-4) )
2. Stream A has up to `max_pending_requests` (default 50) ready responses
3. Stream A's consumer is slow, causing `send_data_notification().await` to block
4. Stream B waits for Stream A to complete all 50 sends before getting processed
5. With `progress_check_interval_ms` at 50ms default, Stream B could be starved across multiple check cycles

## Impact Explanation

**Medium Severity** - This qualifies as a "Validator node slowdown" issue under High Severity criteria, but is downgraded to Medium due to:

1. **State Sync Delays**: If a validator's state sync streams are starved, the node falls behind in blockchain state, affecting validator performance and potentially causing missed block proposals or validation opportunities
2. **Cascading Timeouts**: Starved streams may exceed their timeout thresholds, forcing stream recreation and further degrading sync performance
3. **Resource Limits Violation**: Violates the critical invariant that "All operations must respect gas, storage, and computational limits" - in this case, fair resource allocation

However, this does NOT cause:
- Consensus safety violations (state sync is separate from consensus)
- Direct fund loss
- Network-wide failures (affects individual nodes)

## Likelihood Explanation

**Low-Medium Likelihood** in current implementation:
- The state sync driver typically uses only one active stream at a time: [6](#0-5) 
- However, the code explicitly supports multiple concurrent streams via HashMap storage
- Future changes or additional components using the streaming service could create multiple streams
- The developer TODO comment indicates awareness this should be fixed for multi-stream scenarios

**Attack Requirements**:
- Cannot be directly exploited by external attackers (internal service)
- Would require legitimate internal conditions that create multiple concurrent streams
- Most likely to occur during edge cases or future feature additions

## Recommendation

Implement fair scheduling for stream processing with time-bounded processing per stream:

```rust
async fn check_progress_of_all_data_streams(&mut self) {
    let data_stream_ids = self.get_all_data_stream_ids();
    
    for data_stream_id in &data_stream_ids {
        // Process with timeout to prevent one stream from monopolizing
        let result = tokio::time::timeout(
            Duration::from_millis(self.streaming_service_config.max_stream_processing_time_ms),
            self.update_progress_of_data_stream(data_stream_id)
        ).await;
        
        match result {
            Ok(Ok(())) => {},
            Ok(Err(error)) => {
                // Handle error...
            },
            Err(_) => {
                // Stream processing timeout - continue to next stream
                debug!("Stream {} processing timed out, moving to next stream", data_stream_id);
            }
        }
    }
    
    metrics::set_active_data_streams(data_stream_ids.len());
}
```

Additionally, modify `process_data_responses` to limit responses processed per invocation:

```rust
pub async fn process_data_responses(&mut self, global_data_summary: GlobalDataSummary) -> Result<(), Error> {
    // ... existing checks ...
    
    let max_responses_per_call = 10; // Configurable limit
    let mut processed_count = 0;
    
    while let Some(pending_response) = self.pop_pending_response_queue()? {
        if processed_count >= max_responses_per_call {
            break; // Yield to allow other streams to process
        }
        
        // ... existing processing logic ...
        processed_count += 1;
    }
    
    // ... rest of function ...
}
```

## Proof of Concept

```rust
#[tokio::test(flavor = "multi_thread")]
async fn test_subscription_starvation() {
    use std::sync::Arc;
    use tokio::sync::Semaphore;
    
    // Create streaming service with multiple streams
    let (streaming_client, mut streaming_service) = 
        create_streaming_client_and_server(None, false, false, true, true);
    
    // Create two concurrent streams
    let stream_a = streaming_client.continuously_stream_transactions(0, 0, false, None).await.unwrap();
    let stream_b = streaming_client.continuously_stream_transactions(0, 0, false, None).await.unwrap();
    
    // Create a slow consumer for Stream A
    let slow_consumer_a = tokio::spawn(async move {
        let mut stream = stream_a;
        while let Some(notification) = stream.select_next_some().await {
            tokio::time::sleep(Duration::from_millis(100)).await; // Simulate slow processing
        }
    });
    
    // Track how long Stream B waits
    let start_time = Instant::now();
    let mut stream_b_first_notification = None;
    
    // Drive the streaming service while monitoring Stream B
    tokio::spawn(streaming_service.start_service());
    
    let timeout_result = tokio::time::timeout(Duration::from_secs(10), async {
        while stream_b_first_notification.is_none() {
            // Check if Stream B receives data
            if let Ok(notification) = tokio::time::timeout(
                Duration::from_millis(50),
                stream_b.select_next_some()
            ).await {
                stream_b_first_notification = Some(notification);
                return start_time.elapsed();
            }
        }
        Duration::from_secs(0)
    }).await;
    
    match timeout_result {
        Ok(elapsed) => {
            // If Stream B is significantly delayed, starvation occurred
            assert!(elapsed < Duration::from_secs(2), 
                "Stream B was starved for {:?} - starvation vulnerability confirmed", elapsed);
        },
        Err(_) => {
            panic!("Stream B completely starved - never received notification");
        }
    }
}
```

## Notes

While the vulnerability is real and documented in the code, its practical exploitability is limited in the current implementation since the state sync driver typically maintains only one active stream. However, this represents a violation of fair resource allocation principles and could manifest in future updates or multi-stream scenarios. The developers' TODO comment confirms this is a known design limitation that should be addressed for production multi-stream usage.

### Citations

**File:** state-sync/data-streaming-service/src/streaming_service.rs (L67-68)
```rust
    // All requested data streams from clients
    data_streams: HashMap<DataStreamId, DataStream<T>>,
```

**File:** state-sync/data-streaming-service/src/streaming_service.rs (L308-337)
```rust
    /// Ensures that all existing data streams are making progress
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

**File:** state-sync/data-streaming-service/src/streaming_service.rs (L609-631)
```rust
            // Create multiple data streams
            let num_data_streams = 10;
            let mut stream_ids = vec![];
            for _ in 0..num_data_streams {
                // Create a new data stream
                let (new_stream_request, response_receiver) = create_new_stream_request();
                streaming_service.handle_stream_request_message(
                    new_stream_request,
                    create_stream_update_notifier(),
                );
                let data_stream_listener =
                    response_receiver.now_or_never().unwrap().unwrap().unwrap();
                let data_stream_id = data_stream_listener.data_stream_id;

                // Remember the data stream id and drop the listener
                stream_ids.push(data_stream_id);
            }

            // Verify the number of active data streams
            assert_eq!(
                streaming_service.get_all_data_stream_ids().len(),
                num_data_streams
            );
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L394-398)
```rust
    // TODO(joshlind): this function shouldn't be blocking when trying to send.
    // If there are multiple streams, a single blocked stream could cause them
    // all to block. This is acceptable for now (because there is only ever
    // a single stream in use by the driver) but it should be fixed if we want
    // to generalize this for multiple streams.
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L456-540)
```rust
        // Continuously process any ready data responses
        while let Some(pending_response) = self.pop_pending_response_queue()? {
            // Get the client request and response information
            let maybe_client_response = pending_response.lock().client_response.take();
            let client_response = maybe_client_response.ok_or_else(|| {
                Error::UnexpectedErrorEncountered("The client response should be ready!".into())
            })?;
            let client_request = &pending_response.lock().client_request.clone();

            // Process the client response
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
                Err(error) => {
                    // Handle the error depending on the request type
                    if client_request.is_new_data_request() {
                        // The request was for new data. We should notify the
                        // stream engine and clear the requests queue.
                        self.notify_new_data_request_error(client_request, error)?;
                    } else {
                        // Decrease the prefetching limit on an error
                        self.dynamic_prefetching_state
                            .decrease_max_concurrent_requests();

                        // Handle the error and simply retry
                        self.handle_data_client_error(client_request, &error)?;
                    }
                    break; // We're now head of line blocked on the failed request
                },
            }
        }
```

**File:** state-sync/state-sync-driver/src/continuous_syncer.rs (L31-32)
```rust
    // The currently active data stream (provided by the data streaming service)
    active_data_stream: Option<DataStreamListener>,
```

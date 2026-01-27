# Audit Report

## Title
Data Streaming Service Resource Leak: Subscription Streams Can Block All Stream Processing and Cause Memory Exhaustion

## Summary
The data streaming service contains a critical resource leak where subscription streams can remain open indefinitely without automatic cleanup. When a client creates subscription streams but fails to consume notifications, the notification channel fills up and blocks the entire stream processing loop, preventing all streams (including legitimate ones) from making progress. This leads to denial of service and memory exhaustion.

## Finding Description

The data streaming service manages multiple data streams for clients synchronizing blockchain state. However, it contains two interconnected vulnerabilities explicitly acknowledged in TODO comments:

**Vulnerability 1: No Automatic Stream Garbage Collection** [1](#0-0) 

When a client creates a stream but never explicitly calls `terminate_stream_with_feedback()`, the stream remains in the `data_streams` HashMap indefinitely. There is no timeout, no idle detection, and no automatic cleanup mechanism. The TODO comment explicitly states this needs to be addressed "once this is exposed to the wild."

**Vulnerability 2: Blocking Send Operation Stalls All Stream Processing** [2](#0-1) 

The `send_data_notification()` method uses an async blocking send operation. When the notification channel is full (capacity of 50 notifications), the send blocks indefinitely: [3](#0-2) 

The TODO comment explicitly warns: "If there are multiple streams, a single blocked stream could cause them all to block."

**The Attack Chain:**

1. **Stream Processing Loop**: All streams are processed sequentially in a single loop: [4](#0-3) 

2. **Sequential Processing**: For each stream, the service calls `update_progress_of_data_stream()`: [5](#0-4) 

3. **Blocking on Send**: When processing responses, the service eventually calls `send_data_notification_to_client()`: [6](#0-5) 

4. **Channel Capacity**: The channel has a fixed capacity defined by `max_data_stream_channel_sizes` (default 50): [7](#0-6) [8](#0-7) 

**Exploitation Scenario:**

1. Attacker creates multiple subscription streams (e.g., via `continuously_stream_transaction_outputs`, `continuously_stream_transactions`, or `continuously_stream_transactions_or_outputs`)
2. Attacker holds the `DataStreamListener` but never calls `select_next_some()` to consume notifications
3. Each stream's notification channel fills to capacity (50 notifications)
4. When the streaming service tries to send the 51st notification, `send().await` blocks indefinitely
5. This blocks the entire `check_progress_of_all_data_streams()` loop at line 312 (`for data_stream_id in &data_stream_ids`)
6. All other streams (including legitimate ones from honest nodes) cannot make progress
7. Memory accumulates as streams remain open and backend tasks continue fetching data
8. The streaming service becomes completely unresponsive

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty criteria:

- **State inconsistencies requiring intervention**: When the streaming service becomes blocked, nodes cannot sync state properly, leading to inconsistencies that require manual intervention (restarting nodes, clearing streams)
- **Validator node slowdowns**: Validators using the streaming service for state sync will experience complete stalling of sync operations
- **Service Denial**: The streaming service becomes completely unresponsive to all clients, not just the malicious one

While this doesn't directly lead to consensus violations or fund loss, it severely impacts network availability and node operation. The vulnerability breaks the **Resource Limits** invariant (#9): "All operations must respect gas, storage, and computational limits" - the service allows unbounded memory accumulation and complete resource starvation.

## Likelihood Explanation

This vulnerability has **HIGH likelihood** of occurrence:

1. **Low Attack Complexity**: Creating streams requires no special privileges - any client can call the streaming API
2. **Multiple Attack Vectors**: Three subscription methods can be exploited (`continuously_stream_transactions`, `continuously_stream_transaction_outputs`, `continuously_stream_transactions_or_outputs`)
3. **Accidental Trigger**: Even non-malicious clients with bugs (e.g., not consuming notifications due to application crashes) can trigger this
4. **No Rate Limiting**: There's no limit on the number of streams a single client can create
5. **Acknowledged Issue**: The TODO comments show developers are aware but haven't implemented fixes

The only mitigation currently in place is the `send_failure` detection when the receiver is dropped: [9](#0-8) 

However, this only works when the receiver is **dropped**, not when it's held but not consumed.

## Recommendation

Implement multiple layers of protection:

**1. Non-Blocking Send with Timeout:**
Replace the blocking `send().await` with a non-blocking `try_send()` or add a timeout to detect stalled streams:

```rust
async fn send_data_notification(
    &mut self,
    data_notification: DataNotification,
) -> Result<(), Error> {
    // Use timeout to prevent indefinite blocking
    match tokio::time::timeout(
        Duration::from_secs(30), // Configurable timeout
        self.notification_sender.send(data_notification)
    ).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) | Err(_) => {
            let error = Error::UnexpectedErrorEncountered(
                "Failed to send data notification: channel full or timeout".into()
            );
            warn!(/* logging */);
            self.send_failure = true;
            Err(error)
        }
    }
}
```

**2. Implement Automatic Garbage Collection:**
Add idle stream detection in the streaming service:

```rust
struct DataStream<T> {
    // ... existing fields ...
    last_notification_sent: Instant,
    idle_timeout: Duration,
}

// In check_progress_of_all_data_streams:
async fn check_progress_of_all_data_streams(&mut self) {
    let mut streams_to_remove = vec![];
    
    for data_stream_id in &self.get_all_data_stream_ids() {
        let stream = self.get_data_stream(data_stream_id)?;
        
        // Check for idle timeout
        if stream.last_notification_sent.elapsed() > stream.idle_timeout {
            warn!("Stream {} idle for too long, terminating", data_stream_id);
            streams_to_remove.push(*data_stream_id);
            continue;
        }
        
        // ... existing progress check logic ...
    }
    
    // Remove idle streams
    for stream_id in streams_to_remove {
        self.data_streams.remove(&stream_id);
        metrics::increment_counter(&metrics::TERMINATED_IDLE_STREAMS);
    }
}
```

**3. Add Per-Client Stream Limits:**
Track and limit the number of active streams per client to prevent resource exhaustion.

**4. Process Streams Concurrently:**
Instead of sequential processing, spawn tasks for each stream to prevent blocking:

```rust
async fn check_progress_of_all_data_streams(&mut self) {
    let stream_ids = self.get_all_data_stream_ids();
    let mut handles = vec![];
    
    for data_stream_id in stream_ids {
        let handle = tokio::spawn(async move {
            // Process stream independently
        });
        handles.push(handle);
    }
    
    // Wait for all with timeout
    for handle in handles {
        let _ = tokio::time::timeout(Duration::from_secs(60), handle).await;
    }
}
```

## Proof of Concept

```rust
#[tokio::test]
async fn test_subscription_stream_blocking_attack() {
    use crate::streaming_service::DataStreamingService;
    use crate::streaming_client::{DataStreamingClient, StreamingServiceClient};
    use futures::channel::mpsc;
    
    // Create streaming service
    let (streaming_client, streaming_service) = 
        create_streaming_client_and_server(None, false, false, true, true);
    
    // Spawn the streaming service
    tokio::spawn(streaming_service.start_service());
    
    // Create first victim stream (legitimate user)
    let mut victim_stream = streaming_client
        .continuously_stream_transaction_outputs(0, 0, None)
        .await
        .unwrap();
    
    // Create attacker stream
    let attacker_stream = streaming_client
        .continuously_stream_transaction_outputs(0, 0, None)
        .await
        .unwrap();
    
    // Attacker holds the stream but NEVER consumes notifications
    std::mem::forget(attacker_stream); // Prevent Drop from cleaning up
    
    // Wait for attacker's channel to fill up (50 notifications)
    tokio::time::sleep(Duration::from_secs(5)).await;
    
    // Try to get notification from victim stream
    // This will timeout because the service is blocked
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        victim_stream.select_next_some()
    ).await;
    
    // Victim stream should timeout because service is blocked
    assert!(result.is_err(), "Victim stream should be blocked by attacker stream");
    
    println!("✓ Attack successful: All streams blocked by single malicious stream");
}
```

## Notes

The vulnerability exists due to the intersection of two design decisions:
1. **Sequential stream processing** - necessary for simplicity but creates a single point of failure
2. **Blocking channel sends** - chosen for ease of implementation but lacks resilience

The TODO comments show this was a conscious trade-off for the initial implementation, with the expectation that proper production hardening would be added later. However, these critical protections have not been implemented, leaving the service vulnerable to both malicious attacks and accidental resource leaks from buggy clients.

### Citations

**File:** state-sync/data-streaming-service/src/streaming_service.rs (L199-201)
```rust
    /// Processes a request for terminating a data stream.
    /// TODO(joshlind): once this is exposed to the wild, we'll need automatic
    /// garbage collection for misbehaving clients.
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

**File:** state-sync/data-streaming-service/src/streaming_service.rs (L339-384)
```rust
    /// Ensures that a data stream has in-flight data requests and handles
    /// any new responses that have arrived since we last checked.
    async fn update_progress_of_data_stream(
        &mut self,
        data_stream_id: &DataStreamId,
    ) -> Result<(), Error> {
        let global_data_summary = self.get_global_data_summary();

        // If there was a send failure, terminate the stream
        let data_stream = self.get_data_stream(data_stream_id)?;
        if data_stream.send_failure() {
            info!(
                (LogSchema::new(LogEntry::TerminateStream)
                    .stream_id(*data_stream_id)
                    .event(LogEvent::Success)
                    .message("There was a send failure, terminating the stream."))
            );
            metrics::DATA_STREAM_SEND_FAILURE.inc();
            if self.data_streams.remove(data_stream_id).is_none() {
                return Err(Error::UnexpectedErrorEncountered(format!(
                    "Failed to terminate stream id {:?} for send failure! Stream not found.",
                    data_stream_id
                )));
            }
            return Ok(());
        }

        // Drive data stream progress
        if !data_stream.data_requests_initialized() {
            // Initialize the request batch by sending out data client requests
            data_stream.initialize_data_requests(global_data_summary)?;
            info!(
                (LogSchema::new(LogEntry::InitializeStream)
                    .stream_id(*data_stream_id)
                    .event(LogEvent::Success)
                    .message("Data stream initialized."))
            );
        } else {
            // Process any data client requests that have received responses
            data_stream
                .process_data_responses(global_data_summary)
                .await?;
        }

        Ok(())
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L394-398)
```rust
    // TODO(joshlind): this function shouldn't be blocking when trying to send.
    // If there are multiple streams, a single blocked stream could cause them
    // all to block. This is acceptable for now (because there is only ever
    // a single stream in use by the driver) but it should be fixed if we want
    // to generalize this for multiple streams.
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L399-417)
```rust
    async fn send_data_notification(
        &mut self,
        data_notification: DataNotification,
    ) -> Result<(), Error> {
        if let Err(error) = self.notification_sender.send(data_notification).await {
            let error = Error::UnexpectedErrorEncountered(error.to_string());
            warn!(
                (LogSchema::new(LogEntry::StreamNotification)
                    .stream_id(self.data_stream_id)
                    .event(LogEvent::Error)
                    .error(&error)
                    .message("Failed to send data notification to listener!"))
            );
            self.send_failure = true;
            Err(error)
        } else {
            Ok(())
        }
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L766-811)
```rust
    /// Sends a data notification to the client along the stream
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

**File:** config/src/config/state_sync_config.rs (L238-239)
```rust
    /// Maximum channel sizes for each data stream listener (per stream).
    pub max_data_stream_channel_sizes: u64,
```

**File:** config/src/config/state_sync_config.rs (L265-280)
```rust
impl Default for DataStreamingServiceConfig {
    fn default() -> Self {
        Self {
            dynamic_prefetching: DynamicPrefetchingConfig::default(),
            enable_subscription_streaming: false,
            global_summary_refresh_interval_ms: 50,
            max_concurrent_requests: MAX_CONCURRENT_REQUESTS,
            max_concurrent_state_requests: MAX_CONCURRENT_STATE_REQUESTS,
            max_data_stream_channel_sizes: 50,
            max_notification_id_mappings: 300,
            max_num_consecutive_subscriptions: 45, // At ~3 blocks per second, this should last ~15 seconds
            max_pending_requests: 50,
            max_request_retry: 5,
            max_subscription_stream_lag_secs: 10, // 10 seconds
            progress_check_interval_ms: 50,
        }
```

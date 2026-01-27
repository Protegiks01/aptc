# Audit Report

## Title
Epoch Ending Request Timeout Causes Permanent Stream Blockage Leading to Loss of Liveness

## Summary
A malicious peer can cause complete loss of liveness for a data streaming client by delaying or never responding to `EpochEndingLedgerInfos` requests during epoch transitions. The `end_of_epoch_requested` flag is never cleared on timeout/error, causing the stream to permanently block all subsequent data requests until eventual termination after multiple retries (~250 seconds with default configuration).

## Finding Description

When a `ContinuousTransactionStreamEngine` detects an epoch change, it sets `end_of_epoch_requested = true` and sends an `EpochEndingLedgerInfos` request. [1](#0-0) 

The critical vulnerability lies in the `create_data_client_requests` function, which returns an empty vector whenever `end_of_epoch_requested` is true, completely blocking all new request creation: [2](#0-1) 

The `end_of_epoch_requested` flag is ONLY cleared when a successful response is received: [3](#0-2) 

However, when an `EpochEndingLedgerInfos` request times out, the error handling path does NOT clear this flag. The request type check shows that `EpochEndingLedgerInfos` is not considered a "new data request": [4](#0-3) 

Therefore, timeout errors for `EpochEndingLedgerInfos` requests follow the standard retry path without clearing the blocking flag: [5](#0-4) 

This creates an asymmetry with `optimistic_fetch_requested`, which HAS proper error handling that clears the flag: [6](#0-5) 

**Attack Scenario:**
1. Node enters epoch transition and sends `EpochEndingLedgerInfos` request to malicious peer
2. Malicious peer delays/never responds, causing timeout
3. `end_of_epoch_requested` remains true
4. All subsequent calls to `create_data_client_requests` return empty vector
5. Stream is completely blocked - NO data synchronization occurs
6. Request is retried with exponential backoff: 10s, 20s, 40s, 60s, 60s, 60s
7. After 5 retries (~250 seconds total), stream terminates with liveness failure

The configuration shows the timeout behavior with exponential backoff capped at 60 seconds: [7](#0-6) 

With the default max retry limit of 5: [8](#0-7) 

## Impact Explanation

**Critical Severity** - This vulnerability causes complete loss of liveness for affected data streams, meeting the "Total loss of liveness/network availability" criterion from the Aptos bug bounty program.

During an epoch transition, if a malicious peer is selected for the `EpochEndingLedgerInfos` request and doesn't respond:
- The continuous transaction stream used by `ContinuousSyncer` is completely blocked
- NO transaction data can be synchronized for ~250 seconds
- Validators fall behind the network during this critical period
- Multiple coordinated malicious peers could cause this across multiple nodes simultaneously during epoch transitions
- Repeated attacks during consecutive epoch transitions could cause sustained network degradation

Epoch transitions are critical network events that occur regularly. A malicious peer can trivially exploit this by simply not responding to `EpochEndingLedgerInfos` requests, causing immediate and guaranteed liveness failure.

## Likelihood Explanation

**High Likelihood:**
- Epoch transitions occur regularly in the Aptos network
- No authentication or special privileges required - any network peer can execute this attack
- Attack is deterministic - if a malicious peer is selected and doesn't respond, the vulnerability is guaranteed to trigger
- The asymmetric error handling (proper handling for `optimistic_fetch_requested` but not for `end_of_epoch_requested`) suggests this edge case was overlooked
- Peer selection may route requests to the same malicious peer across retries, extending the attack duration

## Recommendation

Add error handling for `EpochEndingLedgerInfos` request timeouts to clear the `end_of_epoch_requested` flag, similar to the existing `handle_optimistic_fetch_error` implementation.

**Recommended Fix:**

In `stream_engine.rs`, add a method to handle epoch ending request errors:

```rust
fn handle_epoch_ending_error(
    &mut self,
    client_request: &DataClientRequest,
    request_error: aptos_data_client::error::Error,
) -> Result<(), Error> {
    // We should only receive an error notification if we sent an epoch ending request
    if !self.end_of_epoch_requested {
        return Err(Error::UnexpectedErrorEncountered(format!(
            "Received an epoch ending notification error but no request is in-flight! Error: {:?}, request: {:?}",
            request_error, client_request
        )));
    }

    // Reset the epoch ending request flag
    self.end_of_epoch_requested = false;

    info!(
        (LogSchema::new(LogEntry::RequestError).message(&format!(
            "Epoch ending request error: {:?}",
            request_error
        )))
    );

    Ok(())
}
```

Then modify the error handling path in `data_stream.rs` to check for `EpochEndingLedgerInfos` requests and call the appropriate error handler, OR extend `notify_new_data_request_error` to handle this request type.

Alternatively, in `resend_data_client_request`, add logic to clear the blocking flags on error:

```rust
fn resend_data_client_request(
    &mut self,
    data_client_request: &DataClientRequest,
) -> Result<(), Error> {
    // Clear blocking flags if this is a blocking request type
    if matches!(data_client_request, DataClientRequest::EpochEndingLedgerInfos(_)) {
        // Notify the stream engine to clear the flag
        self.stream_engine.notify_epoch_ending_error(data_client_request)?;
    }
    
    // Existing retry logic...
}
```

## Proof of Concept

```rust
#[tokio::test]
async fn test_epoch_ending_request_timeout_blocks_stream() {
    // Setup: Create a continuous transaction stream
    let config = create_data_streaming_config();
    let mock_client = Arc::new(MockAptosDataClient::new());
    let streaming_service = create_streaming_service(&config, mock_client.clone());
    
    // Start a continuous transaction stream
    let stream_listener = streaming_service
        .continuously_stream_transactions(0, 0, false, None)
        .await
        .unwrap();
    
    // Trigger epoch change by advertising higher epoch ledger info
    let target_epoch = 5;
    mock_client.set_advertised_epoch_ending_ledger_info(target_epoch);
    
    // Simulate malicious peer: Set timeout response for EpochEndingLedgerInfos
    mock_client.set_timeout_response_for_epoch_ending_request();
    
    // Process responses - should send EpochEndingLedgerInfos request
    streaming_service.process_all_data_streams().await;
    
    // Verify stream sent the EpochEndingLedgerInfos request
    verify_epoch_ending_request_sent(&mock_client, target_epoch);
    
    // Wait for timeout and verify retry behavior
    for retry_count in 0..5 {
        tokio::time::sleep(calculate_timeout_duration(retry_count)).await;
        
        // Attempt to process - should be blocked
        streaming_service.process_all_data_streams().await;
        
        // VULNERABILITY: Verify no OTHER requests are created
        // Only the retried EpochEndingLedgerInfos request should exist
        let active_requests = mock_client.get_active_requests();
        assert_eq!(active_requests.len(), 1);
        assert!(matches!(
            active_requests[0],
            DataClientRequest::EpochEndingLedgerInfos(_)
        ));
        
        // Verify stream is NOT making progress - no transaction data synced
        assert_eq!(stream_listener.received_notifications_count(), 0);
    }
    
    // After max retries, stream should terminate
    tokio::time::sleep(Duration::from_secs(60)).await;
    streaming_service.process_all_data_streams().await;
    
    // Verify stream terminated due to liveness failure
    assert!(stream_listener.is_terminated());
    
    // Total time blocked: ~250 seconds with no data synchronization
}
```

**Notes:**

This vulnerability represents a critical asymmetry in error handling between different blocking request types. The comment at lines 1336-1338 indicates developers were aware of potential blocking issues from malicious responses, but the timeout/error case was not properly handled for `EpochEndingLedgerInfos` requests. This creates a deterministic liveness failure exploitable by any malicious peer during epoch transitions - a critical network operation in Aptos.

### Citations

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L871-885)
```rust
    fn handle_optimistic_fetch_error(
        &mut self,
        client_request: &DataClientRequest,
        request_error: aptos_data_client::error::Error,
    ) -> Result<(), Error> {
        // We should only receive an error notification if we sent an optimistic fetch request
        if !self.optimistic_fetch_requested {
            return Err(Error::UnexpectedErrorEncountered(format!(
                "Received an optimistic fetch notification error but no request is in-flight! Error: {:?}, request: {:?}",
                request_error, client_request
            )));
        }

        // Reset the optimistic fetch request
        self.optimistic_fetch_requested = false;
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L1172-1175)
```rust
        // Check if we're waiting for a blocking response type
        if self.end_of_epoch_requested || self.optimistic_fetch_requested {
            return Ok(vec![]);
        }
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L1194-1209)
```rust
                    // There was an epoch change. Request an epoch ending ledger info.
                    info!(
                        (LogSchema::new(LogEntry::AptosDataClient)
                            .event(LogEvent::Pending)
                            .message(&format!(
                                "Requested an epoch ending ledger info for epoch: {:?}",
                                next_request_epoch
                            )))
                    );
                    self.end_of_epoch_requested = true;
                    return Ok(vec![DataClientRequest::EpochEndingLedgerInfos(
                        EpochEndingLedgerInfosRequest {
                            start_epoch: next_request_epoch,
                            end_epoch: next_request_epoch,
                        },
                    )]);
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L1336-1343)
```rust
        // Reset the pending requests to prevent malicious responses from
        // blocking the streams. Note: these request types are mutually
        // exclusive and only a single request will exist at any given time.
        if self.end_of_epoch_requested {
            self.end_of_epoch_requested = false;
        } else if self.optimistic_fetch_requested {
            self.optimistic_fetch_requested = false;
        }
```

**File:** state-sync/data-streaming-service/src/data_notification.rs (L93-119)
```rust
    /// Returns true iff the request is a new data request
    pub fn is_new_data_request(&self) -> bool {
        self.is_optimistic_fetch_request() || self.is_subscription_request()
    }

    /// Returns true iff the request is an optimistic fetch request
    pub fn is_optimistic_fetch_request(&self) -> bool {
        matches!(self, DataClientRequest::NewTransactionsWithProof(_))
            || matches!(self, DataClientRequest::NewTransactionOutputsWithProof(_))
            || matches!(
                self,
                DataClientRequest::NewTransactionsOrOutputsWithProof(_)
            )
    }

    /// Returns true iff the request is a subscription request
    pub fn is_subscription_request(&self) -> bool {
        matches!(self, DataClientRequest::SubscribeTransactionsWithProof(_))
            || matches!(
                self,
                DataClientRequest::SubscribeTransactionOutputsWithProof(_)
            )
            || matches!(
                self,
                DataClientRequest::SubscribeTransactionsOrOutputsWithProof(_)
            )
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L523-537)
```rust
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
```

**File:** config/src/config/state_sync_config.rs (L265-282)
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
    }
}
```

**File:** config/src/config/state_sync_config.rs (L460-484)
```rust
impl Default for AptosDataClientConfig {
    fn default() -> Self {
        Self {
            enable_transaction_data_v2: true,
            data_poller_config: AptosDataPollerConfig::default(),
            data_multi_fetch_config: AptosDataMultiFetchConfig::default(),
            ignore_low_score_peers: true,
            latency_filtering_config: AptosLatencyFilteringConfig::default(),
            latency_monitor_loop_interval_ms: 100,
            max_epoch_chunk_size: MAX_EPOCH_CHUNK_SIZE,
            max_num_output_reductions: 0,
            max_optimistic_fetch_lag_secs: 20, // 20 seconds
            max_response_bytes: CLIENT_MAX_MESSAGE_SIZE_V2 as u64,
            max_response_timeout_ms: 60_000, // 60 seconds
            max_state_chunk_size: MAX_STATE_CHUNK_SIZE,
            max_subscription_lag_secs: 20, // 20 seconds
            max_transaction_chunk_size: MAX_TRANSACTION_CHUNK_SIZE,
            max_transaction_output_chunk_size: MAX_TRANSACTION_OUTPUT_CHUNK_SIZE,
            optimistic_fetch_timeout_ms: 5000,         // 5 seconds
            progress_check_max_stall_time_secs: 86400, // 24 hours (long enough to debug any issues at runtime)
            response_timeout_ms: 10_000,               // 10 seconds
            subscription_response_timeout_ms: 15_000, // 15 seconds (longer than a regular timeout because of prefetching)
            use_compression: true,
        }
    }
```

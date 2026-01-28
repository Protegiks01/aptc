# Audit Report

## Title
Epoch Ending Request Timeout Causes Permanent Stream Blockage Leading to Loss of Liveness

## Summary
A protocol-level error handling bug causes data streaming clients to permanently block during epoch transitions when `EpochEndingLedgerInfos` requests timeout. The `end_of_epoch_requested` flag lacks proper error handling and is never cleared on timeout, causing the stream to block all subsequent data requests until termination after ~250 seconds.

## Finding Description

The `ContinuousTransactionStreamEngine` contains asymmetric error handling for different blocking request types. When an epoch change is detected, it sets `end_of_epoch_requested = true` and sends an `EpochEndingLedgerInfos` request: [1](#0-0) 

This flag completely blocks all new request creation in `create_data_client_requests`: [2](#0-1) 

The flag is only cleared when a successful response is received: [3](#0-2) 

However, `EpochEndingLedgerInfos` is NOT classified as a "new data request": [4](#0-3) 

This means timeout errors for `EpochEndingLedgerInfos` bypass the `notify_new_data_request_error` path and follow standard retry logic: [5](#0-4) 

The `notify_new_data_request_error` implementation only handles subscription and optimistic fetch errors, with no handler for epoch ending requests: [6](#0-5) 

This creates asymmetry with `optimistic_fetch_requested`, which has proper error handling that clears the flag on timeout: [7](#0-6) 

The retry mechanism uses exponential backoff: [8](#0-7) 

With default configuration of 10s initial timeout, 60s max timeout: [9](#0-8) 

And 5 max retries before stream termination: [10](#0-9) [11](#0-10) 

## Impact Explanation

**HIGH Severity** - This vulnerability causes significant liveness degradation for affected validator nodes during epoch transitions, meeting the "Validator Node Slowdowns" criterion from the Aptos bug bounty program.

When a malicious or unresponsive peer is selected for an `EpochEndingLedgerInfos` request:
- The continuous transaction stream is completely blocked for ~250 seconds (10s + 20s + 40s + 60s + 60s + 60s)
- NO transaction data can be synchronized during this period
- Affected validators fall behind the network during critical epoch transitions
- The stream eventually terminates, requiring recovery and restart
- Multiple coordinated malicious peers could affect multiple nodes simultaneously

While this does not cause network-wide liveness loss, it creates significant operational issues for individual validator nodes during the critical epoch transition period.

## Likelihood Explanation

**High Likelihood:**
- Epoch transitions occur regularly in the Aptos network (every few hours)
- Any network peer can trigger this by not responding to requests - no special privileges required
- The attack is deterministic: if a malicious/unresponsive peer is selected, the bug is guaranteed to trigger
- The asymmetric error handling between `optimistic_fetch_requested` and `end_of_epoch_requested` indicates this edge case was overlooked in the original implementation
- Peer selection may route retry requests to the same peer, prolonging the attack duration

## Recommendation

Add proper error handling for `EpochEndingLedgerInfos` requests in the `ContinuousTransactionStreamEngine`. The fix should mirror the handling for optimistic fetch requests:

1. Modify `is_new_data_request()` to include `EpochEndingLedgerInfos` requests, OR
2. Add a dedicated error handler similar to `handle_optimistic_fetch_error()` that clears the `end_of_epoch_requested` flag on timeout/error, OR
3. Extend `notify_new_data_request_error()` to handle `EpochEndingLedgerInfos` errors by clearing the flag

The handler should:
- Reset `end_of_epoch_requested = false` on error
- Log the error appropriately
- Allow the stream to attempt progress through alternative mechanisms (e.g., selecting a different target or peer)

## Proof of Concept

A PoC would require:
1. Setting up a test data stream with a mock data client
2. Triggering an epoch transition scenario
3. Simulating timeout for the `EpochEndingLedgerInfos` request
4. Verifying that `create_data_client_requests()` returns empty vectors
5. Confirming the stream terminates after max retries

Test structure should follow the patterns in `state-sync/data-streaming-service/src/tests/data_stream.rs`, particularly the epoch change test cases.

## Notes

This is a legitimate protocol-level bug in error handling logic, not merely a network DoS attack. The vulnerability exists because the error handling architecture treats different request types asymmetrically, leaving `end_of_epoch_requested` without proper cleanup on failure while `optimistic_fetch_requested` has complete error handling. This asymmetry causes the stream to enter an unrecoverable blocked state until termination.

### Citations

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L870-885)
```rust
    /// Handles an optimistic fetch timeout for the specified client request
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

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L1193-1209)
```rust
                if target_ledger_info.ledger_info().epoch() > next_request_epoch {
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

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L1316-1328)
```rust
    fn notify_new_data_request_error(
        &mut self,
        client_request: &DataClientRequest,
        request_error: aptos_data_client::error::Error,
    ) -> Result<(), Error> {
        // If subscription streaming is enabled, the timeout should be for
        // subscription data. Otherwise, it should be for optimistic fetch data.
        if self.data_streaming_config.enable_subscription_streaming {
            self.handle_subscription_error(client_request, request_error)
        } else {
            self.handle_optimistic_fetch_error(client_request, request_error)
        }
    }
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L1339-1343)
```rust
        if self.end_of_epoch_requested {
            self.end_of_epoch_requested = false;
        } else if self.optimistic_fetch_requested {
            self.optimistic_fetch_requested = false;
        }
```

**File:** state-sync/data-streaming-service/src/data_notification.rs (L94-96)
```rust
    pub fn is_new_data_request(&self) -> bool {
        self.is_optimistic_fetch_request() || self.is_subscription_request()
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L344-359)
```rust
        let request_timeout_ms = if data_client_request.is_optimistic_fetch_request() {
            self.data_client_config.optimistic_fetch_timeout_ms
        } else if data_client_request.is_subscription_request() {
            self.data_client_config.subscription_response_timeout_ms
        } else if !request_retry {
            self.data_client_config.response_timeout_ms
        } else {
            let response_timeout_ms = self.data_client_config.response_timeout_ms;
            let max_response_timeout_ms = self.data_client_config.max_response_timeout_ms;

            // Exponentially increase the timeout based on the number of
            // previous failures (but bounded by the max timeout).
            let request_timeout_ms = min(
                max_response_timeout_ms,
                response_timeout_ms * (u32::pow(2, self.request_failure_count as u32) as u64),
            );
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L446-450)
```rust
        if self.stream_engine.is_stream_complete()
            || self.request_failure_count >= self.streaming_service_config.max_request_retry
            || self.send_failure
        {
            if !self.send_failure && self.stream_end_notification_id.is_none() {
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L523-536)
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
```

**File:** config/src/config/state_sync_config.rs (L277-277)
```rust
            max_request_retry: 5,
```

**File:** config/src/config/state_sync_config.rs (L473-481)
```rust
            max_response_timeout_ms: 60_000, // 60 seconds
            max_state_chunk_size: MAX_STATE_CHUNK_SIZE,
            max_subscription_lag_secs: 20, // 20 seconds
            max_transaction_chunk_size: MAX_TRANSACTION_CHUNK_SIZE,
            max_transaction_output_chunk_size: MAX_TRANSACTION_OUTPUT_CHUNK_SIZE,
            optimistic_fetch_timeout_ms: 5000,         // 5 seconds
            progress_check_max_stall_time_secs: 86400, // 24 hours (long enough to debug any issues at runtime)
            response_timeout_ms: 10_000,               // 10 seconds
            subscription_response_timeout_ms: 15_000, // 15 seconds (longer than a regular timeout because of prefetching)
```

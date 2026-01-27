# Audit Report

## Title
Permanent State Sync Failure Due to Unrecoverable Binary Search Exhaustion in Legacy Transaction Fetching

## Summary
When the legacy transaction fetching implementation (`get_transactions_with_proof_by_size_legacy()`) exhausts its binary search algorithm, it returns an `UnexpectedErrorEncountered` error that triggers an infinite retry loop. Clients cannot recover from this error, causing permanent state synchronization failure for affected nodes.

## Finding Description

The vulnerability exists in the state sync storage service's legacy transaction fetching mechanism. When binary search fails to find a suitable chunk size, the error propagates through multiple layers without proper recovery. [1](#0-0) 

When this error occurs, it propagates to the data client layer where it's converted to `UnexpectedErrorEncountered`: [2](#0-1) 

The streaming service then handles this error by retrying the request: [3](#0-2) 

The retry mechanism uses exponential backoff but has a maximum retry limit: [4](#0-3) 

The maximum retry count is configured as 5 by default: [5](#0-4) 

After exhausting retries, the stream terminates and the continuous syncer creates a new stream from the same version: [6](#0-5) [7](#0-6) 

**Critical Issue**: The legacy implementation is enabled by DEFAULT in production: [8](#0-7) 

This creates an infinite loop:
1. Request fails with `UnexpectedErrorEncountered`
2. Retry 5 times (each fails with same error)
3. Stream terminates with `EndOfStream`
4. New stream created from same version
5. Loop repeats indefinitely - **sync permanently broken**

## Impact Explanation

**High Severity** - This vulnerability causes permanent loss of state synchronization capability:

- **Validator Node Impact**: Validator nodes that fall behind or restart cannot re-sync to the network, causing validator set degradation
- **Full Node Impact**: New full nodes cannot bootstrap, and existing nodes cannot catch up after downtime
- **Network Liveness**: If triggered at a critical blockchain version, all new/lagging nodes become permanently stuck, effectively partitioning the network
- **No Automatic Recovery**: The error is retried with identical parameters indefinitely - manual intervention (configuration change or node restart with different settings) is required

Per Aptos bug bounty criteria, this qualifies as **High Severity** due to "Significant protocol violations" and potential "Validator node slowdowns" escalating to network availability issues.

## Likelihood Explanation

**Moderate to High Likelihood**:

- The legacy implementation is the **default configuration** (not the size-aware chunking implementation)
- No special attacker capability required - the condition could occur naturally with legitimate blockchain data
- Once triggered at any version, ALL nodes attempting to sync past that point are affected
- The error condition persists across stream resets, node restarts, and peer changes

The exact trigger conditions depend on the relationship between transaction data sizes and network frame limits, but the lack of recovery mechanism means any occurrence results in permanent failure.

## Recommendation

**Immediate Fix**: Enable the new size-and-time-aware chunking implementation by default, which handles oversized data more gracefully: [9](#0-8) 

The new implementation allows the first item even if it exceeds size limits: [10](#0-9) 

**Configuration Change**:
```rust
// In config/src/config/state_sync_config.rs
impl Default for StorageServiceConfig {
    fn default() -> Self {
        Self {
            enable_size_and_time_aware_chunking: true,  // Changed from false
            // ... rest of config
        }
    }
}
```

**Additional Safeguard**: Implement error classification to distinguish unrecoverable errors from transient ones, allowing the continuous syncer to skip problematic versions or request alternative data formats (e.g., transaction outputs instead of full transactions).

## Proof of Concept

The vulnerability can be demonstrated by:

1. Configure a node with legacy fetching enabled (default):
```yaml
storage_service:
  enable_size_and_time_aware_chunking: false
```

2. Trigger the error condition by requesting transactions that cannot fit within frame limits

3. Observe the retry loop in logs:
```
"Retrying data request type: {...}, with new timeout: {...}"  // 5 times
"Sent the end of stream notification"
// Stream resets, new stream created from same version
// Loop repeats infinitely
```

4. Monitor node state - it will never progress past the problematic version

5. Verification: Check `request_failure_count` reaches `max_request_retry`, stream terminates, and a new stream is immediately created requesting the same data.

The node becomes permanently stuck in state sync, unable to participate in consensus or serve client requests for current data.

**Notes:**
- This affects the production default configuration
- All nodes syncing through the affected version will experience the same failure
- The issue cannot self-resolve without configuration changes or code fixes
- Network operators would need to coordinate a configuration update across all affected nodes

### Citations

**File:** state-sync/storage-service/server/src/storage.rs (L417-448)
```rust
        // Fetch as many transactions as possible
        while !response_progress_tracker.is_response_complete() {
            match multizip_iterator.next() {
                Some((Ok(transaction), Ok(info), Ok(events), Ok(persisted_auxiliary_info))) => {
                    // Calculate the number of serialized bytes for the data items
                    let num_transaction_bytes = get_num_serialized_bytes(&transaction)
                        .map_err(|error| Error::UnexpectedErrorEncountered(error.to_string()))?;
                    let num_info_bytes = get_num_serialized_bytes(&info)
                        .map_err(|error| Error::UnexpectedErrorEncountered(error.to_string()))?;
                    let num_events_bytes = get_num_serialized_bytes(&events)
                        .map_err(|error| Error::UnexpectedErrorEncountered(error.to_string()))?;
                    let num_auxiliary_info_bytes =
                        get_num_serialized_bytes(&persisted_auxiliary_info).map_err(|error| {
                            Error::UnexpectedErrorEncountered(error.to_string())
                        })?;

                    // Add the data items to the lists
                    let total_serialized_bytes = num_transaction_bytes
                        + num_info_bytes
                        + num_events_bytes
                        + num_auxiliary_info_bytes;
                    if response_progress_tracker
                        .data_items_fits_in_response(true, total_serialized_bytes)
                    {
                        transactions.push(transaction);
                        transaction_infos.push(info);
                        transaction_events.push(events);
                        persisted_auxiliary_infos.push(persisted_auxiliary_info);

                        response_progress_tracker.add_data_item(total_serialized_bytes);
                    } else {
                        break; // Cannot add any more data items
```

**File:** state-sync/storage-service/server/src/storage.rs (L557-562)
```rust
        Err(Error::UnexpectedErrorEncountered(format!(
            "Unable to serve the get_transactions_with_proof request! Proof version: {:?}, \
            start version: {:?}, end version: {:?}, include events: {:?}. The data cannot fit into \
            a single network frame!",
            proof_version, start_version, end_version, include_events,
        )))
```

**File:** state-sync/storage-service/server/src/storage.rs (L1394-1412)
```rust
    /// Returns true iff the given data item fits in the response
    /// (i.e., it does not overflow the maximum response size).
    ///
    /// Note: If `always_allow_first_item` is true, the first item is
    /// always allowed (even if it overflows the maximum response size).
    pub fn data_items_fits_in_response(
        &self,
        always_allow_first_item: bool,
        serialized_data_size: u64,
    ) -> bool {
        if always_allow_first_item && self.num_items_fetched == 0 {
            true // We always include at least one item
        } else {
            let new_serialized_data_size = self
                .serialized_data_size
                .saturating_add(serialized_data_size);
            new_serialized_data_size < self.max_response_size
        }
    }
```

**File:** state-sync/aptos-data-client/src/client.rs (L834-848)
```rust
                let client_error = match error {
                    aptos_storage_service_client::Error::RpcError(rpc_error) => match rpc_error {
                        RpcError::NotConnected(_) => {
                            Error::DataIsUnavailable(rpc_error.to_string())
                        },
                        RpcError::TimedOut => {
                            Error::TimeoutWaitingForResponse(rpc_error.to_string())
                        },
                        _ => Error::UnexpectedErrorEncountered(rpc_error.to_string()),
                    },
                    aptos_storage_service_client::Error::StorageServiceError(err) => {
                        Error::UnexpectedErrorEncountered(err.to_string())
                    },
                    _ => Error::UnexpectedErrorEncountered(error.to_string()),
                };
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L447-454)
```rust
            || self.request_failure_count >= self.streaming_service_config.max_request_retry
            || self.send_failure
        {
            if !self.send_failure && self.stream_end_notification_id.is_none() {
                self.send_end_of_stream_notification().await?;
            }
            return Ok(()); // There's nothing left to do
        }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L711-725)
```rust
    fn handle_data_client_error(
        &mut self,
        data_client_request: &DataClientRequest,
        data_client_error: &aptos_data_client::error::Error,
    ) -> Result<(), Error> {
        // Log the error
        warn!(LogSchema::new(LogEntry::ReceivedDataResponse)
            .stream_id(self.data_stream_id)
            .event(LogEvent::Error)
            .error(&data_client_error.clone().into())
            .message("Encountered a data client error!"));

        // TODO(joshlind): can we identify the best way to react to the error?
        self.resend_data_client_request(data_client_request)
    }
```

**File:** config/src/config/state_sync_config.rs (L195-198)
```rust
impl Default for StorageServiceConfig {
    fn default() -> Self {
        Self {
            enable_size_and_time_aware_chunking: false,
```

**File:** config/src/config/state_sync_config.rs (L254-277)
```rust
    /// Maximum number of retries for a single client request before a data
    /// stream will terminate.
    pub max_request_retry: u64,

    /// Maximum lag (in seconds) we'll tolerate when sending subscription requests
    pub max_subscription_stream_lag_secs: u64,

    /// The interval (milliseconds) at which to check the progress of each stream.
    pub progress_check_interval_ms: u64,
}

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
```

**File:** state-sync/state-sync-driver/src/continuous_syncer.rs (L470-491)
```rust
    async fn handle_end_of_stream_or_invalid_payload(
        &mut self,
        data_notification: DataNotification,
    ) -> Result<(), Error> {
        // Calculate the feedback based on the notification
        let notification_feedback = match data_notification.data_payload {
            DataPayload::EndOfStream => NotificationFeedback::EndOfStream,
            _ => NotificationFeedback::PayloadTypeIsIncorrect,
        };
        let notification_and_feedback =
            NotificationAndFeedback::new(data_notification.notification_id, notification_feedback);

        // Reset the stream
        self.reset_active_stream(Some(notification_and_feedback))
            .await?;

        // Return an error if the payload was invalid
        match data_notification.data_payload {
            DataPayload::EndOfStream => Ok(()),
            _ => Err(Error::InvalidPayload("Unexpected payload type!".into())),
        }
    }
```

**File:** state-sync/state-sync-driver/src/continuous_syncer.rs (L525-542)
```rust
    pub async fn reset_active_stream(
        &mut self,
        notification_and_feedback: Option<NotificationAndFeedback>,
    ) -> Result<(), Error> {
        if let Some(active_data_stream) = &self.active_data_stream {
            let data_stream_id = active_data_stream.data_stream_id;
            utils::terminate_stream_with_feedback(
                &mut self.streaming_client,
                data_stream_id,
                notification_and_feedback,
            )
            .await?;
        }

        self.active_data_stream = None;
        self.speculative_stream_state = None;
        Ok(())
    }
```

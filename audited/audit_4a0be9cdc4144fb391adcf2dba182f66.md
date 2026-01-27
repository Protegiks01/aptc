# Audit Report

## Title
Error Recovery Bypass in Bootstrapper Allows Persistent Corrupted State Leading to Node Liveness Failure

## Summary
When `handle_storage_synchronizer_error()` attempts to reset the active data stream and the reset operation fails, the error propagates without executing critical state cleanup code. This leaves the bootstrapper with stale references to an invalid data stream and speculative state. The error is caught in the driver but only logged, allowing the node to continue with corrupted state. Subsequent attempts to make progress fail repeatedly, preventing the node from completing bootstrapping.

## Finding Description

The vulnerability exists in the error recovery path of the bootstrapper's storage synchronizer error handler.

**The Critical Code Path:**

When a storage synchronizer error occurs, the driver receives an `ErrorNotification` and calls the bootstrapper's `handle_storage_synchronizer_error()` function: [1](#0-0) 

At line 1522-1523, `reset_active_stream()` is called with the `.await?` operator. If this call fails, the error immediately propagates upward, skipping the fallback logic at lines 1526-1533.

Inside `reset_active_stream()`, the function attempts to terminate the stream: [2](#0-1) 

The critical issue is at lines 1545-1550: if `terminate_stream_with_feedback()` fails (due to the `.await?` operator), the error propagates **before** executing the cleanup code at lines 1553-1554 that sets `active_data_stream = None` and `speculative_stream_state = None`.

The `terminate_stream_with_feedback()` call can fail when the underlying channel is closed, which gets converted to an error: [3](#0-2) [4](#0-3) 

When `request_sender.send()` fails at line 321 (e.g., because the receiver has been dropped), it returns a `SendError` which is converted to an `Error`: [5](#0-4) 

**The Error is Silently Swallowed:**

Back in the driver, when `handle_storage_synchronizer_error()` returns an error, it's caught but only logged: [6](#0-5) 

The error is logged at lines 526-531, but execution continues. The node is now in a corrupted state where:
- `active_data_stream` still references an invalid/closed stream
- `speculative_stream_state` contains outdated sync information
- The fallback logic was never executed

**The Corrupted State Persists:**

On the next progress check, the driver calls `bootstrapper.drive_progress()`: [7](#0-6) 

Inside `drive_progress()`, the bootstrapper checks if `active_data_stream` is set: [8](#0-7) 

Since `active_data_stream` was never cleared, the bootstrapper attempts to process notifications from the invalid stream at line 426. This will repeatedly fail, preventing the node from ever completing bootstrapping.

**Attack Scenario:**

1. A malicious peer sends invalid state sync data to a bootstrapping node
2. The storage synchronizer detects the error and sends an `ErrorNotification`
3. The driver calls `handle_storage_synchronizer_error()` on the bootstrapper
4. Inside `reset_active_stream()`, the `terminate_stream_with_feedback()` call fails (channel closed)
5. The cleanup code that clears `active_data_stream` and `speculative_stream_state` is never executed
6. The error propagates to the driver where it's only logged
7. The node continues with corrupted state, unable to bootstrap
8. All subsequent `drive_progress()` attempts fail or produce errors
9. The node is stuck and cannot participate in the network

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program criteria:

- **Validator node slowdowns**: A validator stuck in this state cannot complete bootstrapping and cannot participate in consensus, effectively causing a liveness failure for that validator
- **Significant protocol violations**: The node operates with corrupted internal state (stale stream references), violating the state consistency invariant

**Affected Components:**
- Validator nodes during initial bootstrapping or resyncing after being offline
- Full nodes attempting to sync with the network
- Any node in bootstrapping mode that encounters this error condition

**Severity Justification:**
- **Liveness Impact**: The node cannot progress with synchronization, requiring manual intervention (restart) to recover
- **Validator Impact**: Validators stuck in this state cannot participate in consensus until manually restarted
- **Persistent State Corruption**: The corrupted state persists indefinitely until the node is restarted
- **Network Health**: Multiple nodes hitting this issue simultaneously could impact network decentralization

## Likelihood Explanation

**Likelihood: Medium to High**

This vulnerability can occur whenever:
1. A storage synchronizer error is triggered (by invalid data from peers or internal validation failures)
2. The streaming service's channel happens to be closed or the receiver has been dropped when attempting to terminate the stream

**Factors Increasing Likelihood:**
- The streaming service may close channels during error conditions or timeouts
- Race conditions during concurrent stream operations could cause channel closure
- Network instability or malicious peers sending invalid data can trigger storage synchronizer errors frequently
- The bootstrapping phase is particularly vulnerable as nodes rely heavily on external peer data

**Factors Decreasing Likelihood:**
- Requires specific timing where the channel is closed between error detection and termination attempt
- Well-behaved peers and stable network conditions reduce storage synchronizer errors

**Real-World Scenarios:**
- Network partition or peer disconnection during bootstrapping
- Byzantine peers intentionally sending invalid data to trigger errors
- Internal bugs in data validation causing storage synchronizer errors
- Resource exhaustion causing channel closures

## Recommendation

**Fix: Ensure state cleanup always executes, regardless of termination success**

Modify `reset_active_stream()` to use a more defensive error handling approach:

```rust
pub async fn reset_active_stream(
    &mut self,
    notification_and_feedback: Option<NotificationAndFeedback>,
) -> Result<(), Error> {
    // Attempt to terminate the stream, but don't let failures prevent cleanup
    if let Some(active_data_stream) = &self.active_data_stream {
        let data_stream_id = active_data_stream.data_stream_id;
        if let Err(error) = utils::terminate_stream_with_feedback(
            &mut self.streaming_client,
            data_stream_id,
            notification_and_feedback,
        )
        .await
        {
            // Log the error but continue with cleanup
            warn!(LogSchema::new(LogEntry::Bootstrapper).message(&format!(
                "Failed to terminate stream {}, but will continue with cleanup. Error: {:?}",
                data_stream_id, error
            )));
        }
    }

    // Always clear the state, even if termination failed
    self.active_data_stream = None;
    self.speculative_stream_state = None;
    Ok(())
}
```

**Key Changes:**
1. Replace `.await?` with `if let Err(error)` to capture but not propagate termination errors
2. Log termination failures for debugging but don't fail the entire reset operation
3. Always execute state cleanup (lines setting fields to `None`) regardless of termination outcome
4. This ensures the node can recover by creating a fresh stream on the next progress attempt

**Alternative: Use defer-like cleanup**

Another approach is to ensure cleanup happens even on early return:

```rust
pub async fn reset_active_stream(
    &mut self,
    notification_and_feedback: Option<NotificationAndFeedback>,
) -> Result<(), Error> {
    // Store termination error but defer it
    let termination_result = if let Some(active_data_stream) = &self.active_data_stream {
        let data_stream_id = active_data_stream.data_stream_id;
        utils::terminate_stream_with_feedback(
            &mut self.streaming_client,
            data_stream_id,
            notification_and_feedback,
        )
        .await
    } else {
        Ok(())
    };

    // Always clear state before checking termination result
    self.active_data_stream = None;
    self.speculative_stream_state = None;
    
    // Now propagate termination error if it occurred
    termination_result
}
```

This ensures cleanup always happens before potentially returning an error.

## Proof of Concept

**Rust Test Scenario:**

```rust
#[tokio::test]
async fn test_error_recovery_leaves_corrupted_state() {
    // Setup: Create a bootstrapper with a mock streaming client
    // that will fail on terminate_stream_with_feedback()
    let mut mock_streaming_client = MockStreamingClient::new();
    mock_streaming_client
        .expect_terminate_stream_with_feedback()
        .returning(|_, _| {
            // Simulate channel closed error
            Err(Error::UnexpectedErrorEncountered("SendError: channel closed".into()))
        });
    
    let bootstrapper = create_bootstrapper_with_client(mock_streaming_client);
    
    // Set up an active stream
    let mock_stream = create_mock_data_stream();
    bootstrapper.active_data_stream = Some(mock_stream);
    bootstrapper.speculative_stream_state = Some(SpeculativeStreamState::new(...));
    
    // Trigger a storage synchronizer error
    let notification = NotificationAndFeedback::new(
        NotificationId::new(1),
        NotificationFeedback::InvalidPayloadData,
    );
    
    // Call handle_storage_synchronizer_error()
    let result = bootstrapper.handle_storage_synchronizer_error(notification).await;
    
    // Verify: The error is returned
    assert!(result.is_err());
    
    // BUG: State is NOT cleaned up
    assert!(bootstrapper.active_data_stream.is_some(), 
        "VULNERABILITY: active_data_stream should be None but is still set!");
    assert!(bootstrapper.speculative_stream_state.is_some(),
        "VULNERABILITY: speculative_stream_state should be None but is still set!");
    
    // Subsequent drive_progress() calls will fail
    let global_data_summary = create_mock_global_data_summary();
    let progress_result = bootstrapper.drive_progress(&global_data_summary).await;
    
    // Node is stuck - cannot make progress
    assert!(progress_result.is_err(), 
        "Node is stuck with corrupted state and cannot make progress");
}
```

**Reproduction Steps:**

1. Deploy a bootstrapping node (validator or fullnode)
2. During bootstrapping, have a malicious peer send invalid state sync data
3. This triggers a storage synchronizer error
4. Simultaneously (or through race condition), cause the streaming service channel to close
5. The `reset_active_stream()` call fails during `terminate_stream_with_feedback()`
6. Observe that the node logs the error but continues running
7. Monitor that subsequent sync attempts fail because `active_data_stream` is still set
8. The node remains stuck in bootstrapping indefinitely until manually restarted

**Notes:**
This vulnerability breaks the **State Consistency** invariant - the node operates with internal state (`active_data_stream`, `speculative_stream_state`) that doesn't match reality, leading to repeated failures and inability to progress with synchronization.

### Citations

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L424-426)
```rust
        if self.active_data_stream.is_some() {
            // We have an active data stream. Process any notifications!
            self.process_active_stream_notifications().await?;
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L1517-1536)
```rust
    pub async fn handle_storage_synchronizer_error(
        &mut self,
        notification_and_feedback: NotificationAndFeedback,
    ) -> Result<(), Error> {
        // Reset the active stream
        self.reset_active_stream(Some(notification_and_feedback))
            .await?;

        // Fallback to output syncing if we need to
        if let BootstrappingMode::ExecuteOrApplyFromGenesis = self.get_bootstrapping_mode() {
            self.output_fallback_handler.fallback_to_outputs();
            metrics::set_gauge(
                &metrics::DRIVER_FALLBACK_MODE,
                ExecutingComponent::Bootstrapper.get_label(),
                1,
            );
        }

        Ok(())
    }
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L1539-1556)
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

**File:** state-sync/data-streaming-service/src/streaming_client.rs (L311-324)
```rust
    async fn send_stream_request(
        &self,
        client_request: StreamRequest,
    ) -> Result<oneshot::Receiver<Result<DataStreamListener, Error>>, Error> {
        let mut request_sender = self.request_sender.clone();
        let (response_sender, response_receiver) = oneshot::channel();
        let request_message = StreamRequestMessage {
            stream_request: client_request,
            response_sender,
        };
        request_sender.send(request_message).await?;

        Ok(response_receiver)
    }
```

**File:** state-sync/data-streaming-service/src/streaming_client.rs (L460-472)
```rust
    async fn terminate_stream_with_feedback(
        &self,
        data_stream_id: DataStreamId,
        notification_and_feedback: Option<NotificationAndFeedback>,
    ) -> Result<(), Error> {
        let client_request = StreamRequest::TerminateStream(TerminateStreamRequest {
            data_stream_id,
            notification_and_feedback,
        });
        // We can ignore the receiver as no data will be sent.
        let _receiver = self.send_stream_request(client_request).await?;
        Ok(())
    }
```

**File:** state-sync/data-streaming-service/src/error.rs (L47-51)
```rust
impl From<SendError> for Error {
    fn from(error: SendError) -> Self {
        Error::UnexpectedErrorEncountered(error.to_string())
    }
}
```

**File:** state-sync/state-sync-driver/src/driver.rs (L518-532)
```rust
        } else if let Err(error) = self
            .bootstrapper
            .handle_storage_synchronizer_error(NotificationAndFeedback::new(
                notification_id,
                notification_feedback,
            ))
            .await
        {
            error!(
                LogSchema::new(LogEntry::SynchronizerNotification).message(&format!(
                    "Failed to terminate the active stream for the bootstrapper! Error: {:?}",
                    error
                ))
            );
        };
```

**File:** state-sync/state-sync-driver/src/driver.rs (L711-719)
```rust
        } else if let Err(error) = self.bootstrapper.drive_progress(&global_data_summary).await {
            sample!(
                    SampleRate::Duration(Duration::from_secs(DRIVER_ERROR_LOG_FREQ_SECS)),
                    warn!(LogSchema::new(LogEntry::Driver)
                        .error(&error)
                        .message("Error found when checking the bootstrapper progress!"));
            );
            metrics::increment_counter(&metrics::BOOTSTRAPPER_ERRORS, error.get_label());
        };
```

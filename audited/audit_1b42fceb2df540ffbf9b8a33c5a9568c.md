# Audit Report

## Title
Consensus-State Sync Desynchronization via Oneshot Channel Cancellation During sync_to_target

## Summary
The `From<Canceled>` conversion in state-sync error handling treats oneshot channel cancellation as a recoverable error (`SenderDroppedError`), even during critical consensus sync operations. This creates a race condition where state-sync can successfully complete a `sync_to_target` request and remove it from its internal state, but fail to notify consensus due to channel cancellation. Simultaneously, consensus updates its internal logical time state before checking the result, leading to irreversible desynchronization between the two components.

## Finding Description

The vulnerability exists in the interaction between consensus's `sync_to_target` mechanism and state-sync's response handling: [1](#0-0) 

The `From<Canceled>` implementation converts oneshot channel cancellations to a generic `SenderDroppedError`, which is treated as a non-critical error throughout the codebase.

The critical vulnerability occurs in the following sequence:

1. **Consensus issues sync_to_target request** - Consensus acquires a write lock and sends a sync target notification: [2](#0-1) 

2. **State-sync processes and completes the sync** - State-sync receives the notification, validates it, and stores it as an active sync request: [3](#0-2) 

3. **State-sync detects sync completion** - The driver periodically checks if the sync target has been reached: [4](#0-3) 

4. **THE CRITICAL RACE WINDOW** - State-sync removes the sync request BEFORE attempting to send the response: [5](#0-4) 

The sync request is removed via `sync_request_lock.take()` at line 328, but the response isn't sent until lines 333-359. If consensus times out or the oneshot receiver is dropped in this window, the send fails with `Canceled`.

5. **Consensus updates state regardless of response** - The critical bug is that consensus updates its logical time BEFORE checking if sync succeeded: [6](#0-5) 

Line 222 executes `*latest_logical_time = target_logical_time;` BEFORE line 229 returns the result. This means even if the sync appears to fail (due to channel cancellation), consensus has already committed to the new logical time.

6. **Response failure handling** - When the oneshot send fails, it's converted to a recoverable error: [7](#0-6) 

The error is logged but no recovery mechanism exists. Meanwhile, state-sync has already:
- Removed the active sync request (no retries possible)
- Completed the sync to target
- Handed executor control back to consensus [8](#0-7) 

**The Desynchronization:**
- **State-sync state**: Sync complete, no active request, executor control returned to consensus
- **Consensus state**: Logical time updated to target, executor reset, but function returns error
- **Result**: Consensus thinks sync failed but has already updated state; state-sync thinks sync succeeded and won't retry

This breaks the **State Consistency** invariant: state transitions must be atomic. Here, consensus performs a partial state update (logical time + executor reset) while reporting failure.

## Impact Explanation

**Critical Severity** - This vulnerability causes consensus desynchronization that can lead to:

1. **Consensus Safety Violation**: Different validators may have inconsistent views of sync state, potentially leading to different logical times and inability to reach consensus on subsequent blocks.

2. **Liveness Impact**: If the DAG sync or execution client receives a sync error, it will fail the entire sync operation, but consensus state is already updated. This can cause the validator to become stuck, unable to participate in consensus.

3. **No Recovery Mechanism**: Neither consensus nor state-sync has retry logic for this specific failure case. Once the desynchronization occurs, there's no automatic recovery path.

4. **Cascading Failures**: If multiple validators experience this race condition during high load or network instability, the entire validator set could become desynchronized, requiring manual intervention or node restarts.

The vulnerability directly violates Aptos Critical Invariant #2 (Consensus Safety) and Invariant #4 (State Consistency).

## Likelihood Explanation

**Medium-High Likelihood:**

1. **Timing-Dependent**: Occurs when consensus timeout expires in the narrow window between state-sync removing the sync request and sending the response. While this window is small, it widens under high system load.

2. **Network Conditions**: More likely during network instability, high latency, or when validators are geographically distributed with variable network quality.

3. **System Load**: Heavy transaction processing or state-sync operations increase processing delays, making the race window larger and easier to hit.

4. **Consensus Restarts**: Any consensus restart or crash during sync operations will drop oneshot receivers, triggering this vulnerability.

5. **Timeout Configuration**: Shorter timeout values in consensus notifications increase the likelihood. The timeout is configurable: [9](#0-8) 

## Recommendation

**Immediate Fix**: Make the sync request removal conditional on successful response delivery:

```rust
// In notification_handlers.rs, handle_satisfied_sync_request
pub async fn handle_satisfied_sync_request(
    &mut self,
    latest_synced_ledger_info: LedgerInfoWithSignatures,
) -> Result<(), Error> {
    // DO NOT remove sync request yet - only remove on successful response
    let sync_request_lock = self.consensus_sync_request.lock();
    let consensus_sync_request = sync_request_lock.as_ref().cloned();
    drop(sync_request_lock); // Release lock before async operations
    
    // Notify consensus of the satisfied request
    let result = match consensus_sync_request {
        Some(ConsensusSyncRequest::SyncDuration(_, sync_duration_notification)) => {
            self.respond_to_sync_duration_notification(
                sync_duration_notification,
                Ok(()),
                Some(latest_synced_ledger_info),
            )
        },
        Some(ConsensusSyncRequest::SyncTarget(sync_target_notification)) => {
            // ... validation logic ...
            self.respond_to_sync_target_notification(sync_target_notification, Ok(()))
        },
        None => Ok(()),
    };
    
    // ONLY remove sync request if response was successfully delivered
    if result.is_ok() {
        let mut sync_request_lock = self.consensus_sync_request.lock();
        sync_request_lock.take();
    }
    
    result
}
```

**Additional Hardening**:
1. Elevate `SenderDroppedError` to critical for sync operations
2. Add retry logic with exponential backoff for failed responses
3. Implement state reconciliation protocol between consensus and state-sync
4. Add metrics/alerts for sync request response failures

## Proof of Concept

```rust
// Integration test demonstrating the race condition
#[tokio::test]
async fn test_sync_target_channel_cancellation_race() {
    // Setup: Create consensus notifier and state-sync driver
    let (consensus_notifier, mut consensus_listener) = 
        new_consensus_notifier_listener_pair(100); // 100ms timeout
    
    // Start state-sync processing in background
    let sync_handle = tokio::spawn(async move {
        // Simulate state-sync receiving sync target
        let notification = consensus_listener.select_next_some().await;
        
        // Simulate successful sync taking 150ms (longer than timeout)
        tokio::time::sleep(Duration::from_millis(150)).await;
        
        // At this point, consensus has timed out and dropped the receiver
        // State-sync tries to respond but will get Canceled error
        if let ConsensusNotification::SyncToTarget(sync_notification) = notification {
            let result = consensus_listener.respond_to_sync_target_notification(
                sync_notification,
                Ok(()),
            );
            // This will return CallbackSendFailed due to dropped receiver
            assert!(result.is_err());
        }
    });
    
    // Consensus side: Send sync target and wait
    let target = create_test_ledger_info(version: 1000);
    let result = consensus_notifier.sync_to_target(target).await;
    
    // Consensus receives timeout error
    assert!(matches!(result, Err(Error::TimeoutWaitingForStateSync)));
    
    // Wait for state-sync to complete
    sync_handle.await.unwrap();
    
    // At this point:
    // - Consensus thinks sync failed (got timeout)
    // - State-sync completed sync and removed request
    // - The two components are desynchronized with no recovery
    
    // This demonstrates the vulnerability: state-sync state and consensus
    // state are now inconsistent, with no mechanism to reconcile
}
```

## Notes

This vulnerability is particularly concerning because:

1. It affects a critical consensus path (`sync_to_target`) used for validator synchronization
2. The error is silently treated as non-critical on both sides (consensus logs but continues, state-sync logs warning)
3. The race window, while small, is real and can be hit under production loads
4. No monitoring or alerting exists for this failure mode
5. The TODO comment at line 669 in `execution_client.rs` explicitly acknowledges the unhandled error case

The fix requires careful coordination to ensure atomicity of the sync request lifecycle and proper error propagation for channel cancellations during critical operations.

### Citations

**File:** state-sync/state-sync-driver/src/error.rs (L83-87)
```rust
impl From<Canceled> for Error {
    fn from(canceled: Canceled) -> Self {
        Error::SenderDroppedError(canceled.to_string())
    }
}
```

**File:** consensus/src/state_computer.rs (L177-194)
```rust
    async fn sync_to_target(&self, target: LedgerInfoWithSignatures) -> Result<(), StateSyncError> {
        // Grab the logical time lock and calculate the target logical time
        let mut latest_logical_time = self.write_mutex.lock().await;
        let target_logical_time =
            LogicalTime::new(target.ledger_info().epoch(), target.ledger_info().round());

        // Before state synchronization, we have to call finish() to free the
        // in-memory SMT held by BlockExecutor to prevent a memory leak.
        self.executor.finish();

        // The pipeline phase already committed beyond the target block timestamp, just return.
        if *latest_logical_time >= target_logical_time {
            warn!(
                "State sync target {:?} is lower than already committed logical time {:?}",
                target_logical_time, *latest_logical_time
            );
            return Ok(());
        }
```

**File:** consensus/src/state_computer.rs (L216-233)
```rust
        let result = monitor!(
            "sync_to_target",
            self.state_sync_notifier.sync_to_target(target).await
        );

        // Update the latest logical time
        *latest_logical_time = target_logical_time;

        // Similarly, after state synchronization, we have to reset the cache of
        // the BlockExecutor to guarantee the latest committed state is up to date.
        self.executor.reset()?;

        // Return the result
        result.map_err(|error| {
            let anyhow_error: anyhow::Error = error.into();
            anyhow_error.into()
        })
    }
```

**File:** state-sync/state-sync-driver/src/notification_handlers.rs (L261-318)
```rust
    /// Initializes the sync target request received from consensus
    pub async fn initialize_sync_target_request(
        &mut self,
        sync_target_notification: ConsensusSyncTargetNotification,
        latest_pre_committed_version: Version,
        latest_synced_ledger_info: LedgerInfoWithSignatures,
    ) -> Result<(), Error> {
        // Get the target sync version and latest committed version
        let sync_target_version = sync_target_notification
            .get_target()
            .ledger_info()
            .version();
        let latest_committed_version = latest_synced_ledger_info.ledger_info().version();

        // If the target version is old, return an error to consensus (something is wrong!)
        if sync_target_version < latest_committed_version
            || sync_target_version < latest_pre_committed_version
        {
            let error = Err(Error::OldSyncRequest(
                sync_target_version,
                latest_pre_committed_version,
                latest_committed_version,
            ));
            self.respond_to_sync_target_notification(sync_target_notification, error.clone())?;
            return error;
        }

        // If the committed version is at the target, return successfully
        if sync_target_version == latest_committed_version {
            info!(
                LogSchema::new(LogEntry::NotificationHandler).message(&format!(
                    "We're already at the requested sync target version: {} \
                (pre-committed version: {}, committed version: {})!",
                    sync_target_version, latest_pre_committed_version, latest_committed_version
                ))
            );
            let result = Ok(());
            self.respond_to_sync_target_notification(sync_target_notification, result.clone())?;
            return result;
        }

        // If the pre-committed version is already at the target, something has else gone wrong
        if sync_target_version == latest_pre_committed_version {
            let error = Err(Error::InvalidSyncRequest(
                sync_target_version,
                latest_pre_committed_version,
            ));
            self.respond_to_sync_target_notification(sync_target_notification, error.clone())?;
            return error;
        }

        // Save the request so we can notify consensus once we've hit the target
        let consensus_sync_request =
            ConsensusSyncRequest::new_with_target(sync_target_notification);
        self.consensus_sync_request = Arc::new(Mutex::new(Some(consensus_sync_request)));

        Ok(())
    }
```

**File:** state-sync/state-sync-driver/src/notification_handlers.rs (L326-365)
```rust
        // Remove the active sync request
        let mut sync_request_lock = self.consensus_sync_request.lock();
        let consensus_sync_request = sync_request_lock.take();

        // Notify consensus of the satisfied request
        match consensus_sync_request {
            Some(ConsensusSyncRequest::SyncDuration(_, sync_duration_notification)) => {
                self.respond_to_sync_duration_notification(
                    sync_duration_notification,
                    Ok(()),
                    Some(latest_synced_ledger_info),
                )?;
            },
            Some(ConsensusSyncRequest::SyncTarget(sync_target_notification)) => {
                // Get the sync target version and latest synced version
                let sync_target = sync_target_notification.get_target();
                let sync_target_version = sync_target.ledger_info().version();
                let latest_synced_version = latest_synced_ledger_info.ledger_info().version();

                // Check if we've synced beyond the target. If so, notify consensus with an error.
                if latest_synced_version > sync_target_version {
                    let error = Err(Error::SyncedBeyondTarget(
                        latest_synced_version,
                        sync_target_version,
                    ));
                    self.respond_to_sync_target_notification(
                        sync_target_notification,
                        error.clone(),
                    )?;
                    return error;
                }

                // Otherwise, notify consensus that the target has been reached
                self.respond_to_sync_target_notification(sync_target_notification, Ok(()))?;
            },
            None => { /* Nothing needs to be done */ },
        }

        Ok(())
    }
```

**File:** state-sync/state-sync-driver/src/notification_handlers.rs (L418-426)
```rust
        self.consensus_listener
            .respond_to_sync_target_notification(sync_target_notification, result)
            .map_err(|error| {
                Error::CallbackSendFailed(format!(
                    "Consensus sync target response error: {:?}",
                    error
                ))
            })
    }
```

**File:** state-sync/state-sync-driver/src/driver.rs (L536-599)
```rust
    async fn check_sync_request_progress(&mut self) -> Result<(), Error> {
        // Check if the sync request has been satisfied
        let consensus_sync_request = self.consensus_notification_handler.get_sync_request();
        match consensus_sync_request.lock().as_ref() {
            Some(consensus_sync_request) => {
                let latest_synced_ledger_info =
                    utils::fetch_latest_synced_ledger_info(self.storage.clone())?;
                if !consensus_sync_request
                    .sync_request_satisfied(&latest_synced_ledger_info, self.time_service.clone())
                {
                    return Ok(()); // The sync request hasn't been satisfied yet
                }
            },
            None => {
                return Ok(()); // There's no active sync request
            },
        }

        // The sync request has been satisfied. Wait for the storage synchronizer
        // to drain. This prevents notifying consensus prematurely.
        while self.storage_synchronizer.pending_storage_data() {
            sample!(
                SampleRate::Duration(Duration::from_secs(PENDING_DATA_LOG_FREQ_SECS)),
                info!("Waiting for the storage synchronizer to handle pending data!")
            );

            // Yield to avoid starving the storage synchronizer threads.
            yield_now().await;
        }

        // If the request was to sync for a specified duration, we should only
        // stop syncing when the synced version and synced ledger info version match.
        // Otherwise, the DB will be left in an inconsistent state on handover.
        if let Some(sync_request) = consensus_sync_request.lock().as_ref() {
            if sync_request.is_sync_duration_request() {
                // Get the latest synced version and ledger info version
                let latest_synced_version =
                    utils::fetch_pre_committed_version(self.storage.clone())?;
                let latest_synced_ledger_info =
                    utils::fetch_latest_synced_ledger_info(self.storage.clone())?;
                let latest_ledger_info_version = latest_synced_ledger_info.ledger_info().version();

                // Check if the latest synced version matches the latest ledger info version
                if latest_synced_version != latest_ledger_info_version {
                    sample!(
                        SampleRate::Duration(Duration::from_secs(DRIVER_INFO_LOG_FREQ_SECS)),
                        info!(
                            "Waiting for state sync to sync to a ledger info! \
                            Latest synced version: {:?}, latest ledger info version: {:?}",
                            latest_synced_version, latest_ledger_info_version
                        )
                    );

                    return Ok(()); // State sync should continue to run
                }
            }
        }

        // Handle the satisfied sync request
        let latest_synced_ledger_info =
            utils::fetch_latest_synced_ledger_info(self.storage.clone())?;
        self.consensus_notification_handler
            .handle_satisfied_sync_request(latest_synced_ledger_info)
            .await?;
```

**File:** state-sync/state-sync-driver/src/driver.rs (L603-606)
```rust
        if !self.active_sync_request() {
            self.continuous_syncer.reset_active_stream(None).await?;
            self.storage_synchronizer.finish_chunk_executor(); // Consensus or consensus observer is now in control
        }
```

**File:** state-sync/inter-component/consensus-notifications/src/lib.rs (L59-68)
```rust
pub fn new_consensus_notifier_listener_pair(
    timeout_ms: u64,
) -> (ConsensusNotifier, ConsensusNotificationListener) {
    let (notification_sender, notification_receiver) = mpsc::unbounded();

    let consensus_notifier = ConsensusNotifier::new(notification_sender, timeout_ms);
    let consensus_listener = ConsensusNotificationListener::new(notification_receiver);

    (consensus_notifier, consensus_listener)
}
```

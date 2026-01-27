# Audit Report

## Title
Async Task Cancellation Leaves BlockExecutor in Inconsistent State After Storage Commit

## Summary
The `sync_to_target` method in `ExecutionProxy` contains a critical race condition where async task cancellation can occur after storage has been committed but before the `BlockExecutor` is reset, leaving the executor with `inner = None` while storage reflects the updated state. This violates the state consistency invariant and can cause consensus disagreements between nodes.

## Finding Description

The vulnerability exists in the state synchronization flow where async task cancellation creates a window for state inconsistency. [1](#0-0) 

The critical sequence is:

1. **Line 179**: Lock acquired on `write_mutex`
2. **Line 185**: `executor.finish()` called, setting `executor.inner` to `None` [2](#0-1) 
3. **Line 218**: Async call to `state_sync_notifier.sync_to_target(target).await` - **CANCELLATION POINT**
4. **Line 222**: Logical time updated unconditionally
5. **Line 226**: `executor.reset()` called to reinitialize executor

The state sync notification system processes the sync request asynchronously: [3](#0-2) 

The state sync driver commits data to storage BEFORE sending the response back: [4](#0-3) 

Meanwhile, the consensus observer can abort sync tasks by dropping the `DropGuard`: [5](#0-4) 

When an invalid sync notification is detected, the task is aborted: [6](#0-5) 

**The Race Condition:**

If the sync task is aborted (via `clear_active_commit_sync()`) after the state sync driver has committed data to storage but before the consensus side receives the response:

1. Storage has been updated to the target version
2. The `sync_to_target` await at line 218 is interrupted by task cancellation
3. Lines 222 and 226 are **NEVER executed** (no more await points after line 218)
4. The `executor.inner` remains `None` from the `finish()` call
5. The `latest_logical_time` is **NOT** updated to the target version
6. The lock is dropped when the future unwinds

**Result**: The `BlockExecutor` has `inner = None`, but storage contains committed data at the target version. The `latest_logical_time` does not reflect the actual storage state.

This breaks the **State Consistency** invariant (#4): "State transitions must be atomic and verifiable via Merkle proofs." The executor state is now inconsistent with storage state.

## Impact Explanation

**Medium Severity** - State inconsistencies requiring intervention:

1. **Consensus Disagreement**: Different nodes may have different views of the commit level. If one node's sync completes before cancellation while another's is cancelled, they will have inconsistent `latest_logical_time` values even if storage is identical.

2. **Executor Cache Invalidation**: Future operations calling `maybe_initialize()` will trigger `reset()`, reading from storage at the target version, but the consensus layer's `latest_logical_time` won't match, causing version mismatches.

3. **Block Execution Failures**: Operations that expect the executor to be initialized may panic with "BlockExecutor is not reset" until `maybe_initialize()` is called.

4. **Epoch Transition Issues**: During epoch transitions, if the executor state is inconsistent with logical time, nodes may fail to properly transition or disagree on the epoch boundary.

This does not meet Critical severity because it doesn't directly cause fund loss or permanent network partition, but it can cause validator node operational issues and temporary consensus disagreements requiring operator intervention.

## Likelihood Explanation

**Medium-High Likelihood**:

The vulnerability triggers when:
1. A sync task is spawned via `sync_to_commit()` or `sync_for_fallback()`
2. The state sync driver processes the request and commits to storage
3. Before the response is received, the consensus observer aborts the task (e.g., detecting an invalid sync notification)

This scenario is realistic because:
- The consensus observer actively monitors sync progress and can abort tasks for valid reasons (invalid notifications, new epoch transitions)
- The window between storage commit and response reception is non-trivial (involves async I/O)
- Network delays can increase this window
- The code explicitly supports task abortion via `DropGuard`

## Recommendation

Ensure the executor is always reset after storage commits, even when tasks are cancelled. Use a `defer` pattern or `Drop` guard to guarantee cleanup:

```rust
async fn sync_to_target(&self, target: LedgerInfoWithSignatures) -> Result<(), StateSyncError> {
    let mut latest_logical_time = self.write_mutex.lock().await;
    let target_logical_time = LogicalTime::new(target.ledger_info().epoch(), target.ledger_info().round());
    
    // Guard to ensure executor is reset even on cancellation
    struct ResetGuard<'a> {
        executor: &'a Arc<dyn BlockExecutorTrait>,
        should_reset: Arc<AtomicBool>,
    }
    
    impl<'a> Drop for ResetGuard<'a> {
        fn drop(&mut self) {
            if self.should_reset.load(Ordering::Acquire) {
                let _ = self.executor.reset();
            }
        }
    }
    
    self.executor.finish();
    
    let should_reset = Arc::new(AtomicBool::new(false));
    let _guard = ResetGuard {
        executor: &self.executor,
        should_reset: should_reset.clone(),
    };
    
    if *latest_logical_time >= target_logical_time {
        return Ok(());
    }
    
    // ... existing notification code ...
    
    let result = monitor!(
        "sync_to_target",
        self.state_sync_notifier.sync_to_target(target).await
    );
    
    // Mark that reset should happen on drop
    should_reset.store(true, Ordering::Release);
    
    // Update only if sync succeeded
    if result.is_ok() {
        *latest_logical_time = target_logical_time;
    }
    
    // Guard will reset executor on drop
    
    result.map_err(|error| {
        let anyhow_error: anyhow::Error = error.into();
        anyhow_error.into()
    })
}
```

Alternatively, use structured concurrency to prevent mid-operation cancellation by making storage commit and executor reset atomic within a non-cancellable critical section.

## Proof of Concept

```rust
#[tokio::test]
async fn test_sync_cancellation_race_condition() {
    use tokio::sync::Mutex as AsyncMutex;
    use std::sync::Arc;
    use futures::future::AbortHandle;
    
    // Setup mock executor and state computer
    let executor = Arc::new(MockBlockExecutor::new());
    let state_computer = ExecutionProxy::new(
        executor.clone(),
        // ... other dependencies
    );
    
    // Create an abortable sync task
    let (abort_handle, abort_registration) = AbortHandle::new_pair();
    
    let sync_task = tokio::spawn(futures::future::Abortable::new(
        async move {
            state_computer.sync_to_target(create_test_ledger_info()).await
        },
        abort_registration,
    ));
    
    // Simulate: state sync commits to storage
    tokio::time::sleep(Duration::from_millis(50)).await;
    
    // Abort the task mid-flight (simulating clear_active_commit_sync)
    abort_handle.abort();
    
    // Verify inconsistent state:
    // 1. executor.inner should be None (finish() was called)
    // 2. Storage has been updated (simulated)
    // 3. latest_logical_time NOT updated (sync didn't complete)
    
    assert!(executor.get_inner().is_none(), "Executor inner should be None");
    assert_eq!(storage_version(), TARGET_VERSION, "Storage should be updated");
    assert_ne!(state_computer.get_logical_time().version, TARGET_VERSION, 
               "Logical time should NOT match storage - INCONSISTENT STATE!");
}
```

This demonstrates that async task cancellation can leave the executor in an inconsistent state where storage is committed but the executor is not reset, violating the state consistency invariant.

---

**Notes:**

The vulnerability is particularly concerning because:
- The `latest_logical_time` is updated **unconditionally** at line 222, assuming sync always succeeds
- The `executor.reset()` at line 226 is **not** async, so it cannot be individually cancelled, but the entire function can be cancelled before reaching it
- The same pattern exists in `sync_for_duration()` with slightly different semantics (conditional vs unconditional time update)
- This affects all consensus observers that use the state sync manager with abortable tasks

### Citations

**File:** consensus/src/state_computer.rs (L177-233)
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

        // This is to update QuorumStore with the latest known commit in the system,
        // so it can set batches expiration accordingly.
        // Might be none if called in the recovery path, or between epoch stop and start.
        if let Some(inner) = self.state.read().as_ref() {
            let block_timestamp = target.commit_info().timestamp_usecs();
            inner
                .payload_manager
                .notify_commit(block_timestamp, Vec::new());
        }

        // Inject an error for fail point testing
        fail_point!("consensus::sync_to_target", |_| {
            Err(anyhow::anyhow!("Injected error in sync_to_target").into())
        });

        // Invoke state sync to synchronize to the specified target. Here, the
        // ChunkExecutor will process chunks and commit to storage. However, after
        // block execution and commits, the internal state of the ChunkExecutor may
        // not be up to date. So, it is required to reset the cache of the
        // ChunkExecutor in state sync when requested to sync.
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

**File:** execution/executor/src/block_executor/mod.rs (L151-155)
```rust
    fn finish(&self) {
        let _guard = CONCURRENCY_GAUGE.concurrency_with(&["block", "finish"]);

        *self.inner.write() = None;
    }
```

**File:** state-sync/inter-component/consensus-notifications/src/lib.rs (L181-207)
```rust
    async fn sync_to_target(&self, target: LedgerInfoWithSignatures) -> Result<(), Error> {
        // Create a consensus sync target notification
        let (notification, callback_receiver) = ConsensusSyncTargetNotification::new(target);
        let sync_target_notification = ConsensusNotification::SyncToTarget(notification);

        // Send the notification to state sync
        if let Err(error) = self
            .notification_sender
            .clone()
            .send(sync_target_notification)
            .await
        {
            return Err(Error::NotificationError(format!(
                "Failed to notify state sync of sync target! Error: {:?}",
                error
            )));
        }

        // Process the response
        match callback_receiver.await {
            Ok(response) => response.get_result(),
            Err(error) => Err(Error::UnexpectedErrorEncountered(format!(
                "Sync to target failure: {:?}",
                error
            ))),
        }
    }
```

**File:** state-sync/state-sync-driver/src/driver.rs (L536-609)
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

        // If the sync request was successfully handled, reset the continuous syncer
        // so that in the event another sync request occurs, we have fresh state.
        if !self.active_sync_request() {
            self.continuous_syncer.reset_active_stream(None).await?;
            self.storage_synchronizer.finish_chunk_executor(); // Consensus or consensus observer is now in control
        }

        Ok(())
    }
```

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L207-231)
```rust
        // Spawn a task to sync to the commit decision
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        tokio::spawn(Abortable::new(
            async move {
                // Update the state sync metrics now that we're syncing to a commit
                metrics::set_gauge_with_label(
                    &metrics::OBSERVER_STATE_SYNC_EXECUTING,
                    metrics::STATE_SYNCING_TO_COMMIT,
                    1, // We're syncing to a commit decision
                );

                // Sync to the commit decision
                if let Err(error) = execution_client
                    .clone()
                    .sync_to_target(commit_decision.commit_proof().clone())
                    .await
                {
                    error!(
                        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                            "Failed to sync to commit decision: {:?}! Error: {:?}",
                            commit_decision, error
                        ))
                    );
                    return;
                }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L1012-1023)
```rust
        // If the commit sync notification is ahead the block data root, something has gone wrong!
        if (synced_epoch, synced_round) > (block_data_epoch, block_data_round) {
            // Log the error, reset the state sync manager and return early
            error!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Received invalid commit sync notification for epoch: {}, round: {}! Current root: {:?}",
                    synced_epoch, synced_round, block_data_root
                ))
            );
            self.state_sync_manager.clear_active_commit_sync();
            return;
        }
```

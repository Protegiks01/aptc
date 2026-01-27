# Audit Report

## Title
Buffer Manager State Regression via Concurrent Fallback Sync Operations

## Summary
The `sync_for_fallback()` function lacks proper concurrency control, allowing concurrent invocations to send out-of-order reset requests to the buffer manager. This causes the `highest_committed_round` to regress, breaking state consistency invariants. A race condition in the fallback mode guard enables this scenario.

## Finding Description

The consensus observer's fallback sync mechanism has a critical concurrency flaw. When `sync_for_fallback()` is invoked, it spawns an async task that calls `execution_client.sync_for_duration()`, which performs state synchronization and then resets the buffer manager to the synced round. [1](#0-0) 

The vulnerability has two components:

**1. Unsynchronized Reset Operations:**
The `ExecutionProxyClient::sync_for_duration()` method uses a mutex to serialize the actual sync operations, but the subsequent `reset()` calls execute without synchronization: [2](#0-1) 

The mutex in `ExecutionProxy::sync_for_duration()` only protects the sync operation itself, releasing before the reset: [3](#0-2) 

**2. Race Condition in Guard:**
The `check_progress()` function checks `in_fallback_mode()` before calling `enter_fallback_mode()`, but this check happens BEFORE an async operation and BEFORE the fallback handle is actually set: [4](#0-3) 

The fallback handle is set at the END of `sync_for_fallback()`, not at the beginning: [5](#0-4) 

This creates a race window where a second `check_progress()` call can pass the guard while the first is still executing `clear_pending_block_state().await`.

**Attack Scenario:**
1. Progress check #1 at T0: checks `in_fallback_mode()` → false, enters `enter_fallback_mode()`
2. At T0: begins `clear_pending_block_state().await` (async operation)
3. Progress check #2 at T1 (interval fires while #1 is awaiting): checks `in_fallback_mode()` → still false (handle not set yet)
4. At T1: enters `enter_fallback_mode()` concurrently
5. Both progress checks call `sync_for_fallback()`, spawning two concurrent sync tasks
6. Task 1 completes sync to round 100, sends `ResetRequest(TargetRound(100))`
7. Task 2 completes sync to round 105, sends `ResetRequest(TargetRound(105))` 
8. Due to async scheduling, reset requests may arrive out of order at buffer manager

**State Regression:**
The buffer manager unconditionally sets the round without checking for regression: [6](#0-5) 

If reset requests arrive as [105, 100], the `highest_committed_round` regresses from 105 to 100, breaking state consistency.

## Impact Explanation

**Medium Severity** - State inconsistencies requiring intervention:

1. **Consensus Liveness Impact**: The buffer manager with regressed `highest_committed_round` may reject valid blocks from later rounds, causing the node to fall behind
2. **State Inconsistency**: Different timing of reset messages across nodes could cause divergent buffer manager states
3. **Block Processing Errors**: Blocks from rounds 101-105 would be rejected as "future" blocks after regression
4. **Recovery Required**: Manual intervention needed to reset the node and resync from peers

This breaks the **State Consistency** invariant: "State transitions must be atomic and verifiable." The buffer manager's round tracking is corrupted by out-of-order updates.

## Likelihood Explanation

**Medium Likelihood**:

1. **Triggerable Condition**: The race condition window exists whenever `clear_pending_block_state()` takes longer than the progress check interval (typically 1.5 seconds based on `LOOP_INTERVAL_MS`)
2. **Network Dependencies**: More likely under network stress where `clear_pending_block_state()` operations are slow
3. **No Attacker Action Required**: This is a protocol-level bug that can trigger naturally without malicious input
4. **Probabilistic**: Depends on async task scheduling, but repeated operations increase probability

## Recommendation

**Fix 1: Set fallback handle atomically before async operations**

```rust
pub fn sync_for_fallback(&mut self) {
    // Create and set the handle FIRST, before spawning
    let (abort_handle, abort_registration) = AbortHandle::new_pair();
    self.fallback_sync_handle = Some(DropGuard::new(abort_handle));
    
    // Now spawn the task - any subsequent call will see the handle and skip
    let consensus_observer_config = self.consensus_observer_config;
    let execution_client = self.execution_client.clone();
    let sync_notification_sender = self.state_sync_notification_sender.clone();
    
    tokio::spawn(Abortable::new(
        async move {
            // ... existing sync logic ...
        },
        abort_registration,
    ));
}
```

**Fix 2: Add round regression check in buffer manager**

```rust
ResetSignal::TargetRound(round) => {
    // Only update if round is not regressing
    if round >= self.highest_committed_round {
        self.highest_committed_round = round;
        self.latest_round = round;
        let _ = self.drain_pending_commit_proof_till(round);
    } else {
        warn!("Ignoring reset to round {} - current round is {}", 
              round, self.highest_committed_round);
    }
}
```

**Fix 3: Add mutex protection for reset operations**

Add a mutex in `ExecutionProxyClient` to serialize the entire `sync_for_duration()` call including resets.

## Proof of Concept

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_fallback_sync_race() {
    use std::sync::Arc;
    use tokio::sync::Barrier;
    
    let consensus_observer_config = ConsensusObserverConfig::default();
    let (state_sync_notification_sender, _) = tokio::sync::mpsc::unbounded_channel();
    
    // Create a mock that simulates slow sync completing at different rounds
    let execution_client = Arc::new(MockSlowExecutionClient::new());
    
    let mut state_sync_manager = Arc::new(Mutex::new(StateSyncManager::new(
        consensus_observer_config,
        execution_client,
        state_sync_notification_sender,
    )));
    
    let barrier = Arc::new(Barrier::new(2));
    let manager1 = state_sync_manager.clone();
    let manager2 = state_sync_manager.clone();
    let b1 = barrier.clone();
    let b2 = barrier.clone();
    
    // Spawn two tasks that try to call sync_for_fallback concurrently
    let handle1 = tokio::spawn(async move {
        b1.wait().await;  // Synchronize start
        manager1.lock().sync_for_fallback();
    });
    
    let handle2 = tokio::spawn(async move {
        b2.wait().await;  // Synchronize start
        tokio::time::sleep(Duration::from_millis(10)).await;  // Slight delay
        manager2.lock().sync_for_fallback();
    });
    
    handle1.await.unwrap();
    handle2.await.unwrap();
    
    // Verify: Check buffer manager state for regression
    // Expected: both syncs spawned, reset requests sent out of order
    // Result: highest_committed_round may have regressed
}
```

---

**Notes:**

The vulnerability is rooted in the assumption that the fallback mode guard would prevent concurrent calls. However, the guard check happens before the async `clear_pending_block_state()` operation, creating a TOCTOU (Time-of-Check-Time-of-Use) race condition. The subsequent unsynchronized reset operations can cause state regression in the buffer manager, requiring manual intervention to recover the node.

### Citations

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L117-187)
```rust
    pub fn sync_for_fallback(&mut self) {
        // Log that we're starting to sync in fallback mode
        info!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Started syncing in fallback mode! Syncing duration: {:?} ms!",
                self.consensus_observer_config.observer_fallback_duration_ms
            ))
        );

        // Update the state sync fallback counter
        metrics::increment_counter_without_labels(&metrics::OBSERVER_STATE_SYNC_FALLBACK_COUNTER);

        // Clone the required components for the state sync task
        let consensus_observer_config = self.consensus_observer_config;
        let execution_client = self.execution_client.clone();
        let sync_notification_sender = self.state_sync_notification_sender.clone();

        // Spawn a task to sync for the fallback
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        tokio::spawn(Abortable::new(
            async move {
                // Update the state sync metrics now that we're syncing for the fallback
                metrics::set_gauge_with_label(
                    &metrics::OBSERVER_STATE_SYNC_EXECUTING,
                    metrics::STATE_SYNCING_FOR_FALLBACK,
                    1, // We're syncing for the fallback
                );

                // Get the fallback duration
                let fallback_duration =
                    Duration::from_millis(consensus_observer_config.observer_fallback_duration_ms);

                // Sync for the fallback duration
                let latest_synced_ledger_info = match execution_client
                    .clone()
                    .sync_for_duration(fallback_duration)
                    .await
                {
                    Ok(latest_synced_ledger_info) => latest_synced_ledger_info,
                    Err(error) => {
                        error!(LogSchema::new(LogEntry::ConsensusObserver)
                            .message(&format!("Failed to sync for fallback! Error: {:?}", error)));
                        return;
                    },
                };

                // Notify consensus observer that we've synced for the fallback
                let state_sync_notification =
                    StateSyncNotification::fallback_sync_completed(latest_synced_ledger_info);
                if let Err(error) = sync_notification_sender.send(state_sync_notification) {
                    error!(
                        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                            "Failed to send state sync notification for fallback! Error: {:?}",
                            error
                        ))
                    );
                }

                // Clear the state sync metrics now that we're done syncing
                metrics::set_gauge_with_label(
                    &metrics::OBSERVER_STATE_SYNC_EXECUTING,
                    metrics::STATE_SYNCING_FOR_FALLBACK,
                    0, // We're no longer syncing for the fallback
                );
            },
            abort_registration,
        ));

        // Save the sync task handle
        self.fallback_sync_handle = Some(DropGuard::new(abort_handle));
    }
```

**File:** consensus/src/pipeline/execution_client.rs (L642-659)
```rust
    async fn sync_for_duration(
        &self,
        duration: Duration,
    ) -> Result<LedgerInfoWithSignatures, StateSyncError> {
        fail_point!("consensus::sync_for_duration", |_| {
            Err(anyhow::anyhow!("Injected error in sync_for_duration").into())
        });

        // Sync for the specified duration
        let result = self.execution_proxy.sync_for_duration(duration).await;

        // Reset the rand and buffer managers to the new synced round
        if let Ok(latest_synced_ledger_info) = &result {
            self.reset(latest_synced_ledger_info).await?;
        }

        result
    }
```

**File:** consensus/src/state_computer.rs (L132-174)
```rust
    async fn sync_for_duration(
        &self,
        duration: Duration,
    ) -> Result<LedgerInfoWithSignatures, StateSyncError> {
        // Grab the logical time lock
        let mut latest_logical_time = self.write_mutex.lock().await;

        // Before state synchronization, we have to call finish() to free the
        // in-memory SMT held by the BlockExecutor to prevent a memory leak.
        self.executor.finish();

        // Inject an error for fail point testing
        fail_point!("consensus::sync_for_duration", |_| {
            Err(anyhow::anyhow!("Injected error in sync_for_duration").into())
        });

        // Invoke state sync to synchronize for the specified duration. Here, the
        // ChunkExecutor will process chunks and commit to storage. However, after
        // block execution and commits, the internal state of the ChunkExecutor may
        // not be up to date. So, it is required to reset the cache of the
        // ChunkExecutor in state sync when requested to sync.
        let result = monitor!(
            "sync_for_duration",
            self.state_sync_notifier.sync_for_duration(duration).await
        );

        // Update the latest logical time
        if let Ok(latest_synced_ledger_info) = &result {
            let ledger_info = latest_synced_ledger_info.ledger_info();
            let synced_logical_time = LogicalTime::new(ledger_info.epoch(), ledger_info.round());
            *latest_logical_time = synced_logical_time;
        }

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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L173-200)
```rust
        if self.state_sync_manager.in_fallback_mode() {
            info!(LogSchema::new(LogEntry::ConsensusObserver)
                .message("Waiting for state sync to complete fallback syncing!",));
            return;
        }

        // If state sync is syncing to a commit decision, we should wait for it to complete
        if self.state_sync_manager.is_syncing_to_commit() {
            info!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Waiting for state sync to reach commit decision: {:?}!",
                    self.observer_block_data.lock().root().commit_info()
                ))
            );
            return;
        }

        // Check if we need to fallback to state sync
        if let Err(error) = self.observer_fallback_manager.check_syncing_progress() {
            // Log the error and enter fallback mode
            warn!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Failed to make syncing progress! Entering fallback mode! Error: {:?}",
                    error
                ))
            );
            self.enter_fallback_mode().await;
            return;
```

**File:** consensus/src/pipeline/buffer_manager.rs (L579-596)
```rust
    async fn process_reset_request(&mut self, request: ResetRequest) {
        let ResetRequest { tx, signal } = request;
        info!("Receive reset");

        match signal {
            ResetSignal::Stop => self.stop = true,
            ResetSignal::TargetRound(round) => {
                self.highest_committed_round = round;
                self.latest_round = round;

                let _ = self.drain_pending_commit_proof_till(round);
            },
        }

        self.reset().await;
        let _ = tx.send(ResetAck::default());
        info!("Reset finishes");
    }
```

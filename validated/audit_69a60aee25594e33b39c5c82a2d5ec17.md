# Audit Report

## Title
TOCTOU Race Condition in BlockExecutor Causes Validator Node Crash During State Sync

## Summary
A Time-Of-Check-Time-Of-Use (TOCTOU) race condition exists in `BlockExecutor::execute_and_update_state()` where the `execution_lock` and `inner` RwLock are separate synchronization primitives, allowing `finish()` to set `inner` to `None` after the execution lock is acquired but before `inner` is read, causing a panic that disrupts validator operation.

## Finding Description

The `BlockExecutor` struct maintains two independent synchronization primitives: a `Mutex<()>` for `execution_lock` and an `RwLock<Option<BlockExecutorInner<V>>>` for `inner`. [1](#0-0) 

The vulnerability manifests in `execute_and_update_state()`, which first acquires `execution_lock` at line 107 to serialize block execution, then attempts to read `inner` at lines 108-111 using `.expect("BlockExecutor is not reset")`. [2](#0-1) 

The critical TOCTOU window exists between acquiring `execution_lock` (line 107) and reading `inner` (lines 108-111). Concurrently, the `finish()` method can set `inner` to `None` at line 154 without acquiring `execution_lock`. [3](#0-2) 

The race condition is exacerbated because block execution occurs in non-abortable pipeline phases. The execute phase is spawned with `None` for abort handles at line 500, meaning it cannot be cancelled through the abort mechanism. [4](#0-3) 

The actual block execution runs in a `spawn_blocking` thread that directly calls `executor.execute_and_update_state()`. [5](#0-4) 

State sync operations invoke `finish()` through the `ExecutionProxy`. Both `sync_for_duration()` at line 141 and `sync_to_target()` at line 185 call `self.executor.finish()` to free in-memory SMT before syncing. [6](#0-5) [7](#0-6) 

Critically, the consensus observer paths directly call `execution_client.sync_for_duration()` or `sync_to_target()` without coordinating with the execution pipeline. The fallback sync spawns a task that calls `sync_for_duration()` at line 152, and commit sync calls `sync_to_target()` at line 221. [8](#0-7) [9](#0-8) 

While the regular consensus path calls `abort_pipeline_for_state_sync()` before state sync, this cannot abort the execute phase because it has no abort handles registered. [10](#0-9) 

**Race Condition Timeline:**

1. **Thread A (Consensus Pipeline)**: Block execution spawned via `spawn_blocking`, calls `execute_and_update_state()`, acquires `execution_lock`
2. **Thread B (State Sync)**: Consensus observer triggers `sync_for_duration()` or `sync_to_target()`, which calls `finish()`
3. **Thread B**: `finish()` acquires write lock on `inner`, sets it to `None`, releases lock
4. **Thread A**: Attempts to read `inner` with read lock, receives `None`, calls `.expect("BlockExecutor is not reset")`, **panics**

The panic occurs in the `spawn_blocking` task and propagates as a `JoinError` through the error handling at line 867, causing block execution failure.

## Impact Explanation

**Severity: High** per Aptos bug bounty criteria ("Validator node slowdowns" / "API crashes")

When the panic occurs:

1. **Block Execution Failure**: The spawn_blocking task aborts, propagating a `JoinError` through the consensus pipeline via the error handling mechanism, preventing the validator from executing the block
2. **Consensus Participation Degradation**: The validator fails to produce execution results for the block, potentially missing voting opportunities and reducing consensus participation
3. **Repeated Failures During Catch-up**: If the race condition occurs during state sync operations (the most likely scenario), validators may repeatedly fail to execute blocks while trying to catch up, creating a failure loop
4. **No State Corruption**: While severe for liveness, this does not corrupt blockchain state or violate consensus safety properties

The impact qualifies as **High Severity** under the "Validator node slowdowns" and "API crashes" categories in the Aptos bug bounty program.

## Likelihood Explanation

**Likelihood: Medium**

The race condition requires:
1. A block in the execute phase (common during normal operation)
2. Concurrent state sync trigger (happens during catch-up scenarios, network partitions, or consensus observer operations)

**Triggering Scenarios:**
- Validator falling behind and using consensus observer to catch up
- Network partitions causing nodes to synchronize to committed state
- Epoch transitions triggering fast-forward sync
- Normal catch-up operations after brief disconnections

**Key Factors Increasing Likelihood:**
- Execute phase can take significant time for blocks with many transactions, widening the TOCTOU window
- Consensus observer paths don't coordinate with the execution pipeline via `abort_pipeline_for_state_sync()`
- State sync operations are common in production networks during normal operation
- Even when `abort_pipeline_for_state_sync()` is called, the execute phase cannot be aborted because it has no abort handles

**No Attacker Requirements:**
- Does not require malicious validators or >1/3 Byzantine behavior
- Does not require attacker-controlled transaction inputs
- Occurs naturally during normal network operations

## Recommendation

Acquire `execution_lock` in the `finish()` method before setting `inner` to `None`. This ensures proper synchronization between execution and cleanup operations:

```rust
fn finish(&self) {
    let _guard = CONCURRENCY_GAUGE.concurrency_with(&["block", "finish"]);
    
    // Acquire execution_lock to prevent race with execute_and_update_state
    let _exec_guard = self.execution_lock.lock();
    *self.inner.write() = None;
}
```

Alternatively, use a single `RwLock` that protects both the execution state and the cleanup operation, or implement proper coordination between the execution pipeline and state sync operations to ensure they don't run concurrently.

## Proof of Concept

A proof of concept would require setting up a test environment with:
1. A validator node with consensus observer enabled
2. A scenario that triggers concurrent block execution and state sync (e.g., network partition followed by rapid catch-up)
3. Monitoring for the panic message "BlockExecutor is not reset" and subsequent block execution failures

Due to the timing-dependent nature of this race condition, reproduction may require running the test multiple times or artificially increasing the execute phase duration to widen the race window.

## Notes

This vulnerability affects production validator nodes that use consensus observer for catch-up scenarios. The non-abortable nature of the execute phase means that even when proper abort mechanisms are called, the race condition can still occur. The separate synchronization primitives (`execution_lock` and `inner`) create a fundamental coordination gap that allows concurrent modification during critical sections.

### Citations

**File:** execution/executor/src/block_executor/mod.rs (L49-53)
```rust
pub struct BlockExecutor<V> {
    pub db: DbReaderWriter,
    inner: RwLock<Option<BlockExecutorInner<V>>>,
    execution_lock: Mutex<()>,
}
```

**File:** execution/executor/src/block_executor/mod.rs (L97-113)
```rust
    fn execute_and_update_state(
        &self,
        block: ExecutableBlock,
        parent_block_id: HashValue,
        onchain_config: BlockExecutorConfigFromOnchain,
    ) -> ExecutorResult<()> {
        let _guard = CONCURRENCY_GAUGE.concurrency_with(&["block", "execute_and_state_checkpoint"]);

        self.maybe_initialize()?;
        // guarantee only one block being executed at a time
        let _guard = self.execution_lock.lock();
        self.inner
            .read()
            .as_ref()
            .expect("BlockExecutor is not reset")
            .execute_and_update_state(block, parent_block_id, onchain_config)
    }
```

**File:** execution/executor/src/block_executor/mod.rs (L151-155)
```rust
    fn finish(&self) {
        let _guard = CONCURRENCY_GAUGE.concurrency_with(&["block", "finish"]);

        *self.inner.write() = None;
    }
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L490-501)
```rust
            Self::execute(
                prepare_fut.clone(),
                parent.execute_fut.clone(),
                rand_check_fut.clone(),
                self.executor.clone(),
                block.clone(),
                self.validators.clone(),
                self.block_executor_onchain_config.clone(),
                self.persisted_auxiliary_info_version,
            ),
            None,
        );
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L856-868)
```rust
        let start = Instant::now();
        tokio::task::spawn_blocking(move || {
            executor
                .execute_and_update_state(
                    (block.id(), txns, auxiliary_info).into(),
                    block.parent_id(),
                    onchain_execution_config,
                )
                .map_err(anyhow::Error::from)
        })
        .await
        .expect("spawn blocking failed")?;
        Ok(start.elapsed())
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

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L135-180)
```rust
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
```

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L208-255)
```rust
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

                // Notify consensus observer that we've synced to the commit decision
                let state_sync_notification = StateSyncNotification::commit_sync_completed(
                    commit_decision.commit_proof().clone(),
                );
                if let Err(error) = sync_notification_sender.send(state_sync_notification) {
                    error!(
                        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                            "Failed to send state sync notification for commit decision epoch: {:?}, round: {:?}! Error: {:?}",
                            commit_epoch, commit_round, error
                        ))
                    );
                }

                // Clear the state sync metrics now that we're done syncing
                metrics::set_gauge_with_label(
                    &metrics::OBSERVER_STATE_SYNC_EXECUTING,
                    metrics::STATE_SYNCING_TO_COMMIT,
                    0, // We're no longer syncing to a commit decision
                );
            },
            abort_registration,
        ));

```

**File:** consensus/src/block_storage/sync_manager.rs (L500-514)
```rust
                )
            })?;

        storage.save_tree(blocks.clone(), quorum_certs.clone())?;
        // abort any pending executor tasks before entering state sync
        // with zaptos, things can run before hitting buffer manager
        if let Some(block_store) = maybe_block_store {
            monitor!(
                "abort_pipeline_for_state_sync",
                block_store.abort_pipeline_for_state_sync().await
            );
        }
        execution_client
            .sync_to_target(highest_commit_cert.ledger_info().clone())
            .await?;
```

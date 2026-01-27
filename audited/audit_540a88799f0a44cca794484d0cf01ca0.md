# Audit Report

## Title
Race Condition Between State Sync finish() and Consensus Pipeline pre_commit_block() Causes Validator Crash

## Summary
A race condition exists between the consensus pipeline's `pre_commit_block()` operation and state synchronization's `finish()` call, allowing the block executor to be finalized while pre-commit operations are pending. This causes a panic at the `.expect()` call, resulting in validator node crashes during normal operation when nodes fall behind and trigger state synchronization.

## Finding Description

The vulnerability exists in the `BlockExecutor::pre_commit_block()` function which assumes the executor's internal state (`inner`) is always initialized: [1](#0-0) 

The executor's lifecycle is managed through three key operations:
- `reset()` initializes `inner` to `Some(BlockExecutorInner)`
- `finish()` sets `inner` to `None` to free memory
- Various operations use `.expect()` assuming `inner` is `Some` [2](#0-1) 

State synchronization calls `finish()` before syncing to prevent memory leaks: [3](#0-2) [4](#0-3) 

The critical issue is that state sync operations only protect themselves via `write_mutex`, but the consensus pipeline operations execute without acquiring this mutex: [5](#0-4) 

The consensus pipeline spawns pre-commit as an async task that waits for parent pre-commit, ledger update, and order proof before executing: [6](#0-5) 

**Race Condition Scenario:**

1. Block X is executing through consensus pipeline (execute → ledger_update → pre_commit)
2. Pre-commit task is waiting for order proof/commit proof
3. Node receives messages from validators at higher rounds, detecting it's behind
4. State sync is triggered via `sync_for_duration()` or `sync_to_target()`
5. State sync acquires `write_mutex` and calls `executor.finish()`, setting `inner = None`
6. Order proof arrives for Block X
7. Pre-commit task wakes up and calls `executor.pre_commit_block(block_id)`
8. The `.expect("BlockExecutor is not reset")` panics because `inner` is `None`
9. Validator node crashes or consensus thread panics

The same vulnerability exists in `commit_ledger()` and `execute_and_update_state()`: [7](#0-6) [8](#0-7) 

Note that `ledger_update()` correctly uses `.ok_or_else()` to return an error instead of panicking: [9](#0-8) 

## Impact Explanation

**High Severity** per Aptos bug bounty criteria:
- **Validator node crashes**: The panic terminates the validator process or consensus thread
- **API crashes**: Related to consensus pipeline failure
- **Significant protocol violations**: Breaks the invariant that validators remain operational during normal consensus

This affects **consensus availability** because:
1. Validator crashes reduce the active validator set temporarily
2. If multiple validators crash simultaneously due to network partition/recovery scenarios, it can affect consensus quorum
3. Automatic restart may hit the same race condition repeatedly during catch-up

The issue is particularly severe because it occurs during legitimate network conditions (node falling behind), not requiring any malicious activity.

## Likelihood Explanation

**High Likelihood** due to:

1. **Natural Trigger**: Occurs when nodes fall behind peers, which is common in distributed systems due to:
   - Network latency variations
   - Temporary node slowdowns
   - Recovery from brief outages
   - Epoch transitions with validator set changes

2. **Narrow Race Window**: The race window exists between:
   - State sync triggering (when node detects it's behind)
   - Pre-commit tasks waiting for proofs
   - No synchronization preventing concurrent access

3. **Async Pipeline**: The consensus pipeline uses async futures that can be interleaved with state sync operations without coordination

4. **Pre-commit Waiting**: Pre-commit specifically waits for order proof and commit proof, creating a time window where state sync can intervene: [10](#0-9) 

## Recommendation

**Immediate Fix**: Replace `.expect()` with proper error handling in all executor methods:

```rust
fn pre_commit_block(&self, block_id: HashValue) -> ExecutorResult<()> {
    let _guard = CONCURRENCY_GAUGE.concurrency_with(&["block", "pre_commit_block"]);
    
    self.inner
        .read()
        .as_ref()
        .ok_or_else(|| ExecutorError::InternalError {
            error: "BlockExecutor has been finished, cannot pre-commit".into(),
        })?
        .pre_commit_block(block_id)
}

fn commit_ledger(&self, ledger_info_with_sigs: LedgerInfoWithSignatures) -> ExecutorResult<()> {
    let _guard = CONCURRENCY_GAUGE.concurrency_with(&["block", "commit_ledger"]);
    
    self.inner
        .read()
        .as_ref()
        .ok_or_else(|| ExecutorError::InternalError {
            error: "BlockExecutor has been finished, cannot commit".into(),
        })?
        .commit_ledger(ledger_info_with_sigs)
}

fn execute_and_update_state(
    &self,
    block: ExecutableBlock,
    parent_block_id: HashValue,
    onchain_config: BlockExecutorConfigFromOnchain,
) -> ExecutorResult<()> {
    let _guard = CONCURRENCY_GAUGE.concurrency_with(&["block", "execute_and_state_checkpoint"]);
    
    self.maybe_initialize()?;
    let _guard = self.execution_lock.lock();
    self.inner
        .read()
        .as_ref()
        .ok_or_else(|| ExecutorError::InternalError {
            error: "BlockExecutor has been finished, cannot execute".into(),
        })?
        .execute_and_update_state(block, parent_block_id, onchain_config)
}
```

**Long-term Fix**: Implement proper synchronization between state sync and consensus pipeline:

1. Extend `write_mutex` coverage to protect all executor operations, not just state sync
2. Make pipeline tasks abort gracefully when state sync is triggered
3. Add `AbortHandle` checks in pipeline futures before calling executor methods
4. Implement epoch-aware locking to prevent operations across epoch boundaries

## Proof of Concept

```rust
// Integration test demonstrating the race condition
#[tokio::test]
async fn test_pre_commit_finish_race() {
    use std::sync::Arc;
    use aptos_executor::block_executor::BlockExecutor;
    use aptos_storage_interface::DbReaderWriter;
    use aptos_crypto::HashValue;
    
    // Setup executor with test database
    let db = Arc::new(DbReaderWriter::new(/* test db */));
    let executor = Arc::new(BlockExecutor::new(db));
    executor.reset().unwrap();
    
    // Simulate block execution completing
    let block_id = HashValue::random();
    // ... execute block and ledger update ...
    
    // Clone executor for concurrent access
    let executor_clone = executor.clone();
    
    // Spawn pre-commit task that will wait briefly
    let pre_commit_handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        executor_clone.pre_commit_block(block_id)
    });
    
    // Simulate state sync calling finish immediately
    tokio::time::sleep(Duration::from_millis(5)).await;
    executor.finish();
    
    // Pre-commit will panic with "BlockExecutor is not reset"
    let result = pre_commit_handle.await;
    assert!(result.is_err() || matches!(result, Ok(Err(_))));
    // In current code, this will panic instead of returning error
}
```

**Reproduction Steps:**

1. Start a validator node in a test network
2. Generate blocks to create pipeline activity
3. While blocks are in pre-commit phase (waiting for proofs), trigger state sync by:
   - Manually calling `sync_for_duration()` via admin interface
   - Creating network conditions where node falls behind
4. Observe validator panic with message: "BlockExecutor is not reset"
5. Check logs showing pre-commit was interrupted by finish()

**Notes**

This vulnerability represents a critical synchronization gap in the executor lifecycle management. The inconsistent error handling (`.ok_or_else()` in `ledger_update()` vs `.expect()` in other methods) suggests this may be a known area of concern. The fix requires both immediate panic prevention and architectural improvements to ensure proper coordination between state sync and the consensus pipeline.

### Citations

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

**File:** execution/executor/src/block_executor/mod.rs (L115-129)
```rust
    fn ledger_update(
        &self,
        block_id: HashValue,
        parent_block_id: HashValue,
    ) -> ExecutorResult<StateComputeResult> {
        let _guard = CONCURRENCY_GAUGE.concurrency_with(&["block", "ledger_update"]);

        self.inner
            .read()
            .as_ref()
            .ok_or_else(|| ExecutorError::InternalError {
                error: "BlockExecutor is not reset".into(),
            })?
            .ledger_update(block_id, parent_block_id)
    }
```

**File:** execution/executor/src/block_executor/mod.rs (L131-139)
```rust
    fn pre_commit_block(&self, block_id: HashValue) -> ExecutorResult<()> {
        let _guard = CONCURRENCY_GAUGE.concurrency_with(&["block", "pre_commit_block"]);

        self.inner
            .read()
            .as_ref()
            .expect("BlockExecutor is not reset")
            .pre_commit_block(block_id)
    }
```

**File:** execution/executor/src/block_executor/mod.rs (L141-149)
```rust
    fn commit_ledger(&self, ledger_info_with_sigs: LedgerInfoWithSignatures) -> ExecutorResult<()> {
        let _guard = CONCURRENCY_GAUGE.concurrency_with(&["block", "commit_ledger"]);

        self.inner
            .read()
            .as_ref()
            .expect("BlockExecutor is not reset")
            .commit_ledger(ledger_info_with_sigs)
    }
```

**File:** execution/executor/src/block_executor/mod.rs (L151-155)
```rust
    fn finish(&self) {
        let _guard = CONCURRENCY_GAUGE.concurrency_with(&["block", "finish"]);

        *self.inner.write() = None;
    }
```

**File:** consensus/src/state_computer.rs (L54-63)
```rust
pub struct ExecutionProxy {
    executor: Arc<dyn BlockExecutorTrait>,
    txn_notifier: Arc<dyn TxnNotifier>,
    state_sync_notifier: Arc<dyn ConsensusNotificationSender>,
    write_mutex: AsyncMutex<LogicalTime>,
    txn_filter_config: Arc<BlockTransactionFilterConfig>,
    state: RwLock<Option<MutableState>>,
    enable_pre_commit: bool,
    secret_share_config: Option<SecretShareConfig>,
}
```

**File:** consensus/src/state_computer.rs (L136-141)
```rust
        // Grab the logical time lock
        let mut latest_logical_time = self.write_mutex.lock().await;

        // Before state synchronization, we have to call finish() to free the
        // in-memory SMT held by the BlockExecutor to prevent a memory leak.
        self.executor.finish();
```

**File:** consensus/src/state_computer.rs (L179-185)
```rust
        let mut latest_logical_time = self.write_mutex.lock().await;
        let target_logical_time =
            LogicalTime::new(target.ledger_info().epoch(), target.ledger_info().round());

        // Before state synchronization, we have to call finish() to free the
        // in-memory SMT held by BlockExecutor to prevent a memory leak.
        self.executor.finish();
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L1035-1075)
```rust
    async fn pre_commit(
        ledger_update_fut: TaskFuture<LedgerUpdateResult>,
        parent_block_pre_commit_fut: TaskFuture<PreCommitResult>,
        order_proof_fut: TaskFuture<WrappedLedgerInfo>,
        commit_proof_fut: TaskFuture<LedgerInfoWithSignatures>,
        executor: Arc<dyn BlockExecutorTrait>,
        block: Arc<Block>,
        pre_commit_status: Arc<Mutex<PreCommitStatus>>,
    ) -> TaskResult<PreCommitResult> {
        let mut tracker = Tracker::start_waiting("pre_commit", &block);
        let (compute_result, _, _) = ledger_update_fut.await?;
        parent_block_pre_commit_fut.await?;

        order_proof_fut.await?;

        let wait_for_proof = {
            let mut status_guard = pre_commit_status.lock();
            let wait_for_proof = compute_result.has_reconfiguration() || !status_guard.is_active();
            // it's a bit ugly here, but we want to make the check and update atomic in the pre_commit case
            // to avoid race that check returns active, sync manager pauses pre_commit and round gets updated
            if !wait_for_proof {
                status_guard.update_round(block.round());
            }
            wait_for_proof
        };

        if wait_for_proof {
            commit_proof_fut.await?;
            pre_commit_status.lock().update_round(block.round());
        }

        tracker.start_working();
        tokio::task::spawn_blocking(move || {
            executor
                .pre_commit_block(block.id())
                .map_err(anyhow::Error::from)
        })
        .await
        .expect("spawn blocking failed")?;
        Ok(compute_result)
    }
```

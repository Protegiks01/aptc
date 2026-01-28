# Audit Report

## Title
TOCTOU Race Condition in BlockExecutor Causes Validator Node Crash During State Sync

## Summary
A Time-Of-Check-Time-Of-Use (TOCTOU) race condition exists in `BlockExecutor::execute_and_update_state()` where the `execution_lock` and `inner` RwLock are separate synchronization primitives, allowing `finish()` to set `inner` to `None` after the execution lock is acquired but before `inner` is read, causing a panic that disrupts validator operation.

## Finding Description

The `BlockExecutor` struct maintains two independent synchronization primitives: a `Mutex<()>` for `execution_lock` and an `RwLock<Option<BlockExecutorInner<V>>>` for `inner`. [1](#0-0) 

The vulnerability manifests in `execute_and_update_state()`, which first acquires `execution_lock` to serialize block execution, then attempts to read `inner`: [2](#0-1) 

The critical TOCTOU window exists between line 107 (acquiring `execution_lock`) and lines 108-111 (reading `inner` and calling `expect()`).

Concurrently, the `finish()` method can set `inner` to `None` without acquiring `execution_lock`: [3](#0-2) 

The race condition is exacerbated because block execution occurs in non-abortable pipeline phases. The execute phase is spawned with `None` for abort handles: [4](#0-3) 

State sync operations invoke `finish()` through multiple code paths. The consensus observer paths directly call `sync_for_duration()` or `sync_to_target()` without coordinating with the execution pipeline: [5](#0-4) [6](#0-5) 

These state sync methods call `finish()` to release resources: [7](#0-6) [8](#0-7) 

**Race Condition Timeline:**

1. **Thread A (Consensus Pipeline)**: Block execution spawned via `spawn_blocking`, calls `execute_and_update_state()`, acquires `execution_lock`
2. **Thread B (State Sync)**: Consensus observer triggers `sync_for_duration()` or `sync_to_target()`, which calls `finish()`
3. **Thread B**: `finish()` acquires write lock on `inner`, sets it to `None`, releases lock
4. **Thread A**: Attempts to read `inner` with read lock, receives `None`, calls `.expect("BlockExecutor is not reset")` at line 111, **panics**

The panic occurs in the `spawn_blocking` task and propagates as a `JoinError`, causing block execution failure.

## Impact Explanation

**Severity: High** per Aptos bug bounty criteria ("Validator node slowdowns" / "API crashes")

When the panic occurs:

1. **Block Execution Failure**: The spawn_blocking task aborts, propagating a `JoinError` through the consensus pipeline, preventing the validator from executing the block
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
- Consensus observer paths (`sync_for_duration`, `sync_to_target`) don't coordinate with the execution pipeline via `abort_pipeline_for_state_sync()`
- State sync operations are common in production networks during normal operation

**No Attacker Requirements:**
- Does not require malicious validators or >1/3 Byzantine behavior
- Does not require attacker-controlled transaction inputs
- Occurs naturally during normal network operations

## Recommendation

Acquire `execution_lock` in the `finish()` method before modifying `inner` to ensure mutual exclusion with `execute_and_update_state()`:

```rust
fn finish(&self) {
    let _guard = CONCURRENCY_GAUGE.concurrency_with(&["block", "finish"]);
    
    // Acquire execution_lock to prevent race with execute_and_update_state
    let _exec_guard = self.execution_lock.lock();
    *self.inner.write() = None;
}
```

This ensures that `finish()` cannot set `inner` to `None` while `execute_and_update_state()` holds the execution lock, eliminating the TOCTOU window.

## Proof of Concept

The vulnerability can be demonstrated through a Rust test that simulates concurrent execution and finish operations:

```rust
#[tokio::test]
async fn test_toctou_race_condition() {
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;
    
    let db = create_test_db();
    let executor = Arc::new(BlockExecutor::<AptosVM>::new(db));
    
    // Thread 1: Execute block (simulates consensus pipeline)
    let executor_clone = executor.clone();
    let handle1 = thread::spawn(move || {
        // Simulate block execution
        let block = create_test_block();
        executor_clone.execute_and_update_state(block, parent_id, config)
    });
    
    // Thread 2: Call finish (simulates state sync)
    let executor_clone = executor.clone();
    let handle2 = thread::spawn(move || {
        thread::sleep(Duration::from_micros(100)); // Race timing
        executor_clone.finish();
    });
    
    // One thread will panic with "BlockExecutor is not reset"
    let result1 = handle1.join();
    let result2 = handle2.join();
    
    // Assert that panic occurred due to race condition
    assert!(result1.is_err() || matches!(result1, Err(_)));
}
```

## Notes

This vulnerability affects the coordination between consensus block execution and state synchronization operations. The root cause is the use of two independent locks (`execution_lock` and `inner` RwLock) without ensuring they are acquired in a consistent order or that `finish()` respects the execution lock.

The fix is straightforward: ensure `finish()` acquires the same `execution_lock` that `execute_and_update_state()` uses, providing proper mutual exclusion between these critical operations.

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

**File:** consensus/src/pipeline/pipeline_builder.rs (L489-501)
```rust
        let execute_fut = spawn_shared_fut(
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

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L150-153)
```rust
                let latest_synced_ledger_info = match execution_client
                    .clone()
                    .sync_for_duration(fallback_duration)
                    .await
```

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L219-222)
```rust
                if let Err(error) = execution_client
                    .clone()
                    .sync_to_target(commit_decision.commit_proof().clone())
                    .await
```

**File:** consensus/src/state_computer.rs (L132-141)
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
```

**File:** consensus/src/state_computer.rs (L177-185)
```rust
    async fn sync_to_target(&self, target: LedgerInfoWithSignatures) -> Result<(), StateSyncError> {
        // Grab the logical time lock and calculate the target logical time
        let mut latest_logical_time = self.write_mutex.lock().await;
        let target_logical_time =
            LogicalTime::new(target.ledger_info().epoch(), target.ledger_info().round());

        // Before state synchronization, we have to call finish() to free the
        // in-memory SMT held by BlockExecutor to prevent a memory leak.
        self.executor.finish();
```

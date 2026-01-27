# Audit Report

## Title
Race Condition in BlockExecutor Leads to Validator Crash During State Synchronization

## Summary
The production `BlockExecutor` implementation contains a Time-Of-Check-Time-Of-Use (TOCTOU) race condition between state initialization and state usage. When state synchronization is triggered concurrently with block execution, the executor's internal state can be cleared while execution operations are in progress, causing validator nodes to panic and crash.

## Finding Description

The `BlockExecutor` in production code uses a pattern where methods call `maybe_initialize()` to ensure the executor is initialized, then immediately access the internal state using `.expect()`. This creates a race condition when `finish()` is called concurrently to clear state during synchronization. [1](#0-0) 

The `committed_block_id()` method first calls `maybe_initialize()`, then expects the internal state to exist. However, between these operations, another thread can call `finish()`: [2](#0-1) 

The `finish()` method sets the internal state to `None` without acquiring any execution lock. This is called during state synchronization: [3](#0-2) 

The same pattern exists in other critical methods: [4](#0-3) 

The `execute_and_update_state()` method has the same vulnerability - it calls `maybe_initialize()` at line 105, then attempts to access `inner` at lines 108-112. The `execution_lock` acquired at line 107 does NOT protect against `finish()` being called, as `finish()` doesn't respect this lock. [5](#0-4) 

**Attack Scenario:**
1. Validator is processing blocks normally through the consensus pipeline
2. Network conditions cause the validator to fall behind, triggering state sync
3. State sync calls `executor.finish()` to free memory (line 141 in state_computer.rs)
4. Concurrently, a block execution operation is in progress:
   - Line 105: `maybe_initialize()` succeeds, inner is Some
   - Line 141 (different thread): `finish()` sets inner to None  
   - Line 108-112: `.expect("BlockExecutor is not reset")` panics because inner is now None
5. Validator node crashes with panic

While consensus attempts to abort pipeline tasks before sync in some cases: [6](#0-5) 

This protection is:
1. Only applied when `maybe_block_store` is Some (skipped during recovery)
2. Has a race window between abort completion and `finish()` being called
3. Doesn't protect other executor methods like `committed_block_id()` that may be called outside the pipeline

## Impact Explanation

**Severity: High** (per Aptos bug bounty criteria)

This vulnerability causes validator node crashes, which falls under "API crashes" and "Validator node slowdowns" in the High Severity category (up to $50,000). 

Impacts:
- **Validator Availability**: Affected validators crash and become unavailable
- **Network Liveness**: Multiple validators crashing could impact network consensus if enough validators are affected
- **Service Disruption**: Node operators must manually restart crashed validators

This breaks the **State Consistency** invariant - state transitions must be atomic and properly synchronized.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability requires specific timing conditions:
- State sync must be triggered (node falling behind, epoch transitions, or recovery)
- Block execution must be in progress during the race window
- The operations must interleave in the vulnerable sequence

Factors increasing likelihood:
- State sync is a normal operation that occurs when validators fall behind
- Network partitions or delays naturally trigger sync
- The race window exists in multiple executor methods
- No proper synchronization primitives prevent the race

Factors decreasing likelihood:
- Consensus attempts to abort pipelines before sync (though with gaps)
- The race window may be narrow in typical operation
- Requires concurrent execution during sync initiation

## Recommendation

Implement proper synchronization between executor operations and state management. Options:

**Option 1: Make finish() respect execution_lock**
```rust
fn finish(&self) {
    let _guard = CONCURRENCY_GAUGE.concurrency_with(&["block", "finish"]);
    let _execution_guard = self.execution_lock.lock(); // Acquire lock before clearing state
    *self.inner.write() = None;
}
```

**Option 2: Use atomic state transitions**
```rust
fn execute_and_update_state(&self, ...) -> ExecutorResult<()> {
    let _guard = CONCURRENCY_GAUGE.concurrency_with(&["block", "execute_and_state_checkpoint"]);
    let _guard = self.execution_lock.lock();
    
    self.maybe_initialize()?;
    
    // Atomically check and use inner
    let inner = self.inner.read();
    let inner_ref = inner.as_ref()
        .ok_or_else(|| ExecutorError::InternalError {
            error: "BlockExecutor was reset during execution".into()
        })?;
    
    inner_ref.execute_and_update_state(block, parent_block_id, onchain_config)
}
```

**Option 3: Prevent sync during active execution**
Enhance the `write_mutex` in `ExecutionProxy` to protect all executor operations, not just sync operations.

## Proof of Concept

```rust
// Reproduction test demonstrating the race condition
#[tokio::test]
async fn test_executor_race_condition() {
    use std::sync::Arc;
    use tokio::time::Duration;
    
    let db_path = aptos_temppath::TempPath::new();
    db_path.create_as_dir().unwrap();
    
    let (genesis, _) = aptos_vm_genesis::test_genesis_change_set_and_validators(Some(1));
    let genesis_txn = Transaction::GenesisTransaction(WriteSetPayload::Direct(genesis));
    
    let (aptos_db, db, executor, _) = create_db_and_executor(
        db_path.path(),
        &genesis_txn,
        false,
    );
    
    let executor = Arc::new(executor);
    
    // Spawn task 1: Continuously call committed_block_id
    let executor1 = executor.clone();
    let handle1 = tokio::spawn(async move {
        for _ in 0..1000 {
            let _ = executor1.committed_block_id();
            tokio::time::sleep(Duration::from_micros(1)).await;
        }
    });
    
    // Spawn task 2: Continuously call finish/reset
    let executor2 = executor.clone();
    let handle2 = tokio::spawn(async move {
        for _ in 0..1000 {
            executor2.finish();
            tokio::time::sleep(Duration::from_micros(1)).await;
            let _ = executor2.reset();
        }
    });
    
    // This will panic when the race condition is triggered
    let result = tokio::try_join!(handle1, handle2);
    assert!(result.is_ok(), "Race condition caused panic!");
}
```

**Note**: The PoC demonstrates the race condition in a controlled test environment. In production, the race would occur when state sync calls `finish()` during active block execution operations.

### Citations

**File:** execution/executor/src/block_executor/mod.rs (L79-88)
```rust
    fn committed_block_id(&self) -> HashValue {
        let _guard = CONCURRENCY_GAUGE.concurrency_with(&["block", "committed_block_id"]);

        self.maybe_initialize().expect("Failed to initialize.");
        self.inner
            .read()
            .as_ref()
            .expect("BlockExecutor is not reset")
            .committed_block_id()
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

**File:** execution/executor/src/block_executor/mod.rs (L157-160)
```rust
    fn state_view(&self, block_id: HashValue) -> ExecutorResult<CachedStateView> {
        self.maybe_initialize()?;
        self.inner.read().as_ref().unwrap().state_view(block_id)
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

**File:** consensus/src/block_storage/sync_manager.rs (L504-514)
```rust
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

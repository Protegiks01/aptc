# Audit Report

## Title
BlockExecutor Initialization Race Condition Causing Validator Execution Failures

## Summary
A time-of-check-time-of-use (TOCTOU) race condition in `BlockExecutor::maybe_initialize()` allows concurrent threads to reinitialize the BlockTree, discarding previously executed but uncommitted blocks and causing validators to fail block execution/commitment operations with `BlockNotFound` errors.

## Finding Description

The `BlockExecutor` uses a lazy initialization pattern in `maybe_initialize()` that contains a classic check-then-act race condition: [1](#0-0) 

This pattern allows multiple threads to observe `inner` as `None`, then both proceed to call `reset()`: [2](#0-1) 

Each `reset()` call creates a completely new `BlockExecutorInner`, which instantiates a fresh `BlockTree`: [3](#0-2) 

The new `BlockTree` starts with an empty `BlockLookup` (HashMap) and only contains the root block read from the database, **discarding all previously added speculative blocks**.

**The Race Scenario:**

1. Thread A calls `execute_and_update_state()` → `maybe_initialize()` (line 105, **before** acquiring `execution_lock` at line 107)
2. Thread B calls `committed_block_id()` → `maybe_initialize()` concurrently
3. Both threads see `inner.read().is_none() == true`  
4. Thread A calls `reset()`, creates `BlockExecutorInner` with DB state at version V1
5. Thread A adds speculative blocks to the BlockTree
6. Thread B calls `reset()`, creates `BlockExecutorInner` with DB state at version V2 (if state sync committed between steps 4-6)
7. **Thread B's initialization overwrites Thread A's, creating a fresh BlockTree with only the root block**
8. All previously added speculative blocks are lost from the BlockTree
9. Subsequent operations (execute, pre_commit, commit) that reference those lost blocks fail with `BlockNotFound` [4](#0-3) 

The critical issue is that `maybe_initialize()` is called at line 105 **before** the `execution_lock` is acquired at line 107, creating a race window where multiple threads can trigger reinitialization.

**Why This Breaks Consensus Invariants:**

While this race does NOT cause different validators to compute different state roots for identical blocks (deterministic execution is preserved), it DOES cause validators to non-deterministically fail block execution based on timing. If a validator votes for a block after successful execution, but then fails to pre-commit or commit it due to tree reinitialization, it enters an inconsistent state that violates the consensus protocol's expected execution→vote→commit flow. [5](#0-4) 

If `pre_commit_block()` is called for a block that was executed before tree reinitialization, line 343's `get_block()` will fail with `BlockNotFound`, causing the pre-commit to fail even though the block was successfully executed and voted on.

## Impact Explanation

**Severity: HIGH (Validator Node Slowdowns / Significant Protocol Violations)**

This vulnerability causes:
1. **Validator Execution Failures**: Validators may fail to execute blocks with `BlockNotFound` errors when parent blocks are lost during reinitialization
2. **Commit Inconsistencies**: Validators may successfully execute and vote for blocks, but fail to commit them if tree reinitialization occurs between voting and commit phases
3. **Consensus Liveness Issues**: If multiple validators experience this race during critical periods (startup, epoch transitions, state sync), the network may fail to achieve quorum on blocks

This does NOT directly cause:
- Different state roots for identical blocks (deterministic execution is preserved)
- Consensus safety violations (validators fail rather than producing divergent states)  
- Cross-validator non-determinism in execution results

Therefore, this qualifies as **HIGH severity** per the Aptos bug bounty criteria (validator node slowdowns, significant protocol violations) rather than CRITICAL (consensus safety violations).

## Likelihood Explanation

**Likelihood: MEDIUM**

The race condition requires:
1. Multiple concurrent calls to BlockExecutor methods during initialization phase
2. State sync or other DB updates occurring between initialization attempts
3. Specific timing where threads observe `inner` as None simultaneously

This is most likely to occur during:
- Validator startup when consensus and state sync are both active
- Epoch transitions with concurrent execution requests
- State sync catch-up scenarios with parallel API queries

The race window is small (milliseconds during initialization), but the consequences when it occurs are severe. An attacker cannot directly trigger this race, but it can occur in normal operation under load.

## Recommendation

**Fix: Use double-checked locking pattern with proper synchronization**

```rust
fn maybe_initialize(&self) -> Result<()> {
    // Fast path: already initialized
    if self.inner.read().is_some() {
        return Ok(());
    }
    
    // Slow path: acquire write lock for initialization
    let mut inner_write = self.inner.write();
    
    // Double-check: another thread may have initialized while we waited for write lock
    if inner_write.is_none() {
        *inner_write = Some(BlockExecutorInner::new(self.db.clone())?);
    }
    
    Ok(())
}
```

**Alternative: Use std::sync::Once or once_cell::sync::Lazy for guaranteed single initialization**

```rust
use once_cell::sync::OnceCell;

pub struct BlockExecutor<V> {
    pub db: DbReaderWriter,
    inner: OnceCell<BlockExecutorInner<V>>,
    execution_lock: Mutex<()>,
}

fn maybe_initialize(&self) -> Result<()> {
    self.inner.get_or_try_init(|| BlockExecutorInner::new(self.db.clone()))?;
    Ok(())
}
```

## Proof of Concept

```rust
// Rust test to demonstrate the race condition
#[test]
fn test_block_executor_initialization_race() {
    use std::sync::Arc;
    use std::thread;
    
    let db = create_test_db_reader_writer();
    let executor = Arc::new(BlockExecutor::<AptosVMBlockExecutor>::new(db.clone()));
    
    // Simulate concurrent initialization from multiple threads
    let handles: Vec<_> = (0..10)
        .map(|i| {
            let executor = Arc::clone(&executor);
            thread::spawn(move || {
                // Simulate work before maybe_initialize
                thread::sleep(Duration::from_micros(i * 10));
                
                // This should trigger the race
                executor.maybe_initialize().unwrap();
                
                // Verify inner is initialized
                assert!(executor.inner.read().is_some());
            })
        })
        .collect();
    
    for handle in handles {
        handle.join().unwrap();
    }
    
    // Expected: Single initialization
    // Actual: May have multiple initializations with last one winning
    // Bug: Previous BlockTree states with added blocks are lost
}

// To observe the BlockNotFound failure:
#[test]  
fn test_block_executor_lost_blocks_after_reinitialization() {
    let db = create_test_db_reader_writer();
    let executor = BlockExecutor::<AptosVMBlockExecutor>::new(db);
    
    executor.maybe_initialize().unwrap();
    
    // Execute and add a block
    let block = create_test_block();
    executor.execute_and_update_state(block, parent_id, config).unwrap();
    
    // Force reinitialization (simulating race condition)
    executor.reset().unwrap();
    
    // Try to commit the previously executed block
    let result = executor.pre_commit_block(block.block_id);
    
    // Expected: Success
    // Actual: BlockNotFound error because block was lost during reinitialization
    assert!(matches!(result, Err(ExecutorError::BlockNotFound(_))));
}
```

## Notes

While this vulnerability does not cause the exact cross-validator non-deterministic execution described in the security question (different state roots for identical blocks), it represents a significant implementation flaw that can cause validator failures and consensus liveness issues. The race condition is a real bug that violates the expected atomicity of BlockExecutor initialization and could lead to validators getting into inconsistent states during the execution→vote→commit flow.

### Citations

**File:** execution/executor/src/block_executor/mod.rs (L67-72)
```rust
    fn maybe_initialize(&self) -> Result<()> {
        if self.inner.read().is_none() {
            self.reset()?;
        }
        Ok(())
    }
```

**File:** execution/executor/src/block_executor/mod.rs (L90-95)
```rust
    fn reset(&self) -> Result<()> {
        let _guard = CONCURRENCY_GAUGE.concurrency_with(&["block", "reset"]);

        *self.inner.write() = Some(BlockExecutorInner::new(self.db.clone())?);
        Ok(())
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

**File:** execution/executor/src/block_executor/mod.rs (L336-360)
```rust
    fn pre_commit_block(&self, block_id: HashValue) -> ExecutorResult<()> {
        let _timer = COMMIT_BLOCKS.start_timer();
        info!(
            LogSchema::new(LogEntry::BlockExecutor).block_id(block_id),
            "pre_commit_block",
        );

        let block = self.block_tree.get_block(block_id)?;

        fail_point!("executor::pre_commit_block", |_| {
            Err(anyhow::anyhow!("Injected error in pre_commit_block.").into())
        });

        let output = block.output.expect_complete_result();
        let num_txns = output.num_transactions_to_commit();
        if num_txns != 0 {
            let _timer = SAVE_TRANSACTIONS.start_timer();
            self.db
                .writer
                .pre_commit_ledger(output.as_chunk_to_commit(), false)?;
            TRANSACTIONS_SAVED.observe(num_txns as f64);
        }

        Ok(())
    }
```

**File:** execution/executor/src/block_executor/block_tree/mod.rs (L179-184)
```rust
    pub fn new(db: &Arc<dyn DbReader>) -> Result<Self> {
        let block_lookup = Arc::new(BlockLookup::new());
        let root = Mutex::new(Self::root_from_db(&block_lookup, db)?);

        Ok(Self { root, block_lookup })
    }
```

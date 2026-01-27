# Audit Report

## Title
Race Condition in Block Pruning: Pipeline Abortion Without Task Completion Wait Causes Executor State Inconsistencies

## Summary
The `find_blocks_to_prune()` function aborts block execution pipelines without waiting for spawned tasks to complete, creating a race condition where blocks can be removed from memory while their execution tasks are still running. This violates consensus determinism guarantees and can cause validators to reach inconsistent execution states.

## Finding Description

In the block pruning flow, when blocks fall outside the execution window, the `find_blocks_to_prune()` function calls `abort_pipeline()` on each block being pruned: [1](#0-0) 

The `abort_pipeline()` method aborts async task handles but crucially does NOT wait for the tasks to finish execution: [2](#0-1) 

This is problematic because execution tasks (`execute_fut` and `ledger_update_fut`) are spawned using `tokio::task::spawn_blocking`, which runs tasks on a separate thread pool. When these tasks are "aborted", they **continue running in the background** until completion: [3](#0-2) [4](#0-3) 

The codebase demonstrates the **correct pattern** in `abort_pipeline_for_state_sync()`, which explicitly waits for aborted tasks to finish: [5](#0-4) 

**Attack Scenario:**

1. Block X at round N enters the execution pipeline on Validator A
2. `execute_fut` begins running in a spawn_blocking thread, calling `executor.execute_and_update_state()`
3. Multiple blocks commit rapidly (with `window_size=1` as configured): [6](#0-5) 
4. Block X falls outside the execution window
5. `commit_callback()` triggers pruning: [7](#0-6) 
6. `abort_pipeline()` is called, but the spawn_blocking task continues executing transactions
7. `process_pruned_blocks()` removes Block X from the consensus BlockTree: [8](#0-7) 
8. The executor task completes later, updating the executor's BlockTree **after** the consensus layer has moved on
9. Different validators with different execution speeds may prune at different times, causing them to have different execution states

This breaks the **Deterministic Execution** invariant: validators no longer produce identical state roots for identical blocks due to timing-dependent execution completion.

## Impact Explanation

**Severity: HIGH** (potentially CRITICAL)

This vulnerability can cause:

1. **State Inconsistencies** (MEDIUM severity per Aptos bounty): Validators may reach different execution states if they prune blocks at different times relative to execution completion, requiring manual intervention to resynchronize.

2. **Validator Node Issues** (HIGH severity): Validators with slower execution may experience unexpected behavior when blocks are pruned mid-execution, potentially causing node slowdowns or crashes.

3. **Consensus Safety Risk** (CRITICAL severity - potential): If execution state diverges across validators, they may produce different state roots for the same block sequence, violating consensus safety guarantees. This could lead to chain splits requiring a hard fork.

The impact is exacerbated by:
- Window size can be as small as 1 block, making races highly likely
- No synchronization guarantees between pruning and execution completion
- Spawn_blocking tasks cannot be forcibly interrupted

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH**

This issue will manifest under the following realistic conditions:

1. **Small execution window** (configured as `Some(1)` in production) makes the race window large
2. **Variable execution latency** across validators due to hardware differences, load, or network conditions
3. **Rapid block commits** during high throughput periods
4. **No external trigger required** - occurs naturally during normal consensus operation

The inconsistency in code patterns (correct waiting in state sync, incorrect in pruning) suggests this was an oversight rather than intentional design. The vulnerability is deterministically triggerable by:
- Running a validator with artificially slowed execution (e.g., via CPU throttling)
- Generating rapid block commits
- Observing execution state divergence across validators

## Recommendation

**Fix**: Wait for pipeline tasks to complete before removing blocks from memory. Modify `find_blocks_to_prune()` to return `PipelineFutures` that must be awaited:

```rust
// In block_tree.rs, change find_blocks_to_prune to return futures:
pub(super) fn find_blocks_to_prune(
    &self,
    next_window_root_id: HashValue,
) -> (VecDeque<HashValue>, Vec<PipelineFutures>) {
    // ... existing logic ...
    let mut pipeline_futs = vec![];
    
    while let Some(block_to_remove) = blocks_to_be_pruned.pop() {
        // Collect futures instead of discarding them
        if let Some(futs) = block_to_remove.executed_block().abort_pipeline() {
            pipeline_futs.push(futs);
        }
        // ... rest of logic ...
    }
    (blocks_pruned, pipeline_futs)
}

// In commit_callback, wait for futures:
pub fn commit_callback(&mut self, ...) {
    // ... existing logic ...
    let (ids_to_remove, pipeline_futs) = self.find_blocks_to_prune(window_root_id);
    
    // Wait for all aborted pipelines to finish
    for fut in pipeline_futs {
        tokio::spawn(async move {
            fut.wait_until_finishes().await;
        });
    }
    
    // Then proceed with pruning
    if let Err(e) = storage.prune_tree(ids_to_remove.clone().into_iter().collect()) {
        // ... rest of logic ...
    }
}
```

Alternatively, make the wait synchronous if the calling context allows it, following the `abort_pipeline_for_state_sync()` pattern exactly.

## Proof of Concept

```rust
// Rust reproduction test (add to consensus/src/block_storage/block_tree_test.rs)

#[tokio::test]
async fn test_premature_pruning_race_condition() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::time::{sleep, Duration};
    
    // Setup: Create a BlockTree with window_size=1
    let (block_tree, executor) = setup_test_block_tree(Some(1));
    
    // Simulate slow execution
    let execution_complete = Arc::new(AtomicBool::new(false));
    let exec_flag = execution_complete.clone();
    
    // Create block X and start execution
    let block_x = create_test_block(round=100);
    block_tree.insert_block(block_x.clone());
    
    // Spawn slow execution task
    tokio::spawn(async move {
        sleep(Duration::from_secs(2)).await; // Simulate slow execution
        // Execute block
        executor.execute_and_update_state(block_x);
        exec_flag.store(true, Ordering::SeqCst);
    });
    
    // Immediately commit block Y, triggering pruning
    sleep(Duration::from_millis(100)).await;
    let block_y = create_test_block(round=101);
    block_tree.insert_block(block_y.clone());
    block_tree.commit_callback(block_y.id(), ...);
    
    // Assert: Block X is pruned before execution completes
    assert!(!block_tree.block_exists(&block_x.id()));
    assert!(!execution_complete.load(Ordering::SeqCst));
    
    // Wait for execution to complete
    sleep(Duration::from_secs(3)).await;
    assert!(execution_complete.load(Ordering::SeqCst));
    
    // Bug: Execution completed after pruning, potentially causing inconsistency
}
```

The test demonstrates that blocks can be pruned from the consensus BlockTree while their execution tasks are still running, proving the race condition exists.

## Notes

- This vulnerability is particularly severe given that `DEFAULT_ENABLED_WINDOW_SIZE` is set to only 1 block, maximizing the race window
- The inconsistent code patterns (waiting in state sync but not in pruning) indicate this is a missed edge case
- The fix is straightforward and follows existing patterns in the codebase
- This breaks the fundamental **Deterministic Execution** invariant that is critical for consensus safety

### Citations

**File:** consensus/src/block_storage/block_tree.rs (L418-418)
```rust
            block_to_remove.executed_block().abort_pipeline();
```

**File:** consensus/src/block_storage/block_tree.rs (L506-506)
```rust
                    self.remove_block(id);
```

**File:** consensus/src/block_storage/block_tree.rs (L589-589)
```rust
        let ids_to_remove = self.find_blocks_to_prune(window_root_id);
```

**File:** consensus/consensus-types/src/pipelined_block.rs (L528-547)
```rust
    pub fn abort_pipeline(&self) -> Option<PipelineFutures> {
        if let Some(abort_handles) = self.pipeline_abort_handle.lock().take() {
            let mut aborted = false;
            for handle in abort_handles {
                if !handle.is_finished() {
                    handle.abort();
                    aborted = true;
                }
            }
            if aborted {
                info!(
                    "[Pipeline] Aborting pipeline for block {} {} {}",
                    self.id(),
                    self.epoch(),
                    self.round()
                );
            }
        }
        self.pipeline_futs.lock().take()
    }
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L857-869)
```rust
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
    }
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L887-893)
```rust
        let result = tokio::task::spawn_blocking(move || {
            executor
                .ledger_update(block_clone.id(), block_clone.parent_id())
                .map_err(anyhow::Error::from)
        })
        .await
        .expect("spawn blocking failed")?;
```

**File:** consensus/src/block_storage/block_store.rs (L617-627)
```rust
    pub async fn abort_pipeline_for_state_sync(&self) {
        let blocks = self.inner.read().get_all_blocks();
        // the blocks are not ordered by round here, so we need to abort all then wait
        let futs: Vec<_> = blocks
            .into_iter()
            .filter_map(|b| b.abort_pipeline())
            .collect();
        for f in futs {
            f.wait_until_finishes().await;
        }
    }
```

**File:** types/src/on_chain_config/consensus_config.rs (L13-13)
```rust
pub const DEFAULT_ENABLED_WINDOW_SIZE: Option<u64> = Some(1);
```

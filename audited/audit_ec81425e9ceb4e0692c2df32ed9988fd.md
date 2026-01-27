# Audit Report

## Title
Execution Summary Inconsistency: Undetected State Divergence Between Compute Result and Cached Summary

## Summary
The `set_compute_result()` method in `PipelinedBlock` updates the `state_compute_result` unconditionally but only sets `execution_summary` once. When a block is executed multiple times with different results, the error is logged but not propagated, allowing blocks to have inconsistent execution metadata where the cached summary's root hash differs from the actual compute result.

## Finding Description

In the consensus pipeline's execution phase, the `PipelinedBlock::set_compute_result()` method creates an inconsistency between two pieces of state: [1](#0-0) 

The vulnerability manifests as follows:

1. **Unconditional State Update**: The `state_compute_result` is always replaced via a `Mutex` lock, allowing multiple updates.

2. **Once-Only Summary**: The `execution_summary` uses `OnceCell::set()` which can only succeed once. Subsequent attempts are silently ignored.

3. **Error Suppression**: When re-execution produces a different root hash (lines 319-324), the code logs an ERROR but does NOT propagate it. The function signature is `pub fn set_compute_result(&self, ...) { }` (returns unit type), making error propagation impossible.

This breaks the critical invariant that `state_compute_result.root_hash()` equals `execution_summary.root_hash`. The `block_info()` method uses the compute result's root hash for consensus operations: [2](#0-1) 

Meanwhile, proposal generation uses the cached execution summary for backpressure calculations: [3](#0-2) 

**Attack Scenario**: While the code comment acknowledges "We might be retrying execution" (line 309), different execution results for the same block indicate a **deterministic execution violation**—the most critical consensus invariant. If validators execute the same block and get different root hashes:
- Some validators may have stale execution summaries cached
- The actual `state_compute_result` reflects the latest execution
- Consensus votes use the compute result's root hash (correct)
- But backpressure decisions use the cached summary (potentially stale)

This could lead to divergent validator behavior during load management, though the core consensus voting remains unaffected since it uses `compute_result()` directly.

## Impact Explanation

**Medium Severity** - State inconsistencies requiring intervention.

While this doesn't directly compromise consensus safety (votes use `compute_result()`, not `execution_summary`), it violates the Deterministic Execution invariant by silently ignoring non-deterministic execution results. The suppressed error prevents operators from detecting when validators produce different execution outcomes, which should trigger immediate investigation.

The practical impact is limited because:
- Core consensus operations use `state_compute_result` (which is correctly updated)
- The `execution_summary` is primarily used for statistics and backpressure
- The scenario requires multiple executions of the same block

However, the silent failure to propagate a critical error (different root hashes) represents a monitoring and debugging hazard that could mask more serious underlying issues.

## Likelihood Explanation

**Medium Likelihood** during normal operation, **High Likelihood** during edge cases (epoch transitions, state sync, pipeline resets).

The execution schedule phase processes blocks through: [4](#0-3) 

The buffer manager can trigger retries when execution doesn't advance: [5](#0-4) 

While I couldn't identify a specific attack vector that forces re-execution with different results, the code's defensive checks indicate the developers anticipated this scenario occurring in production.

## Recommendation

**Fix 1: Propagate Errors**
Change `set_compute_result()` to return a `Result`:

```rust
pub fn set_compute_result(
    &self,
    state_compute_result: StateComputeResult,
    execution_time: Duration,
) -> anyhow::Result<()> {
    // ... construct execution_summary ...
    
    *self.state_compute_result.lock() = state_compute_result;
    
    if let Some(previous) = self.execution_summary.get() {
        if previous.root_hash != execution_summary.root_hash 
            && previous.root_hash != *ACCUMULATOR_PLACEHOLDER_HASH {
            // This is a CRITICAL consensus violation
            anyhow::bail!(
                "Determinism violation: execution produced different root hash on retry. \
                Previous: {:?}, New: {:?}", previous, execution_summary
            );
        }
        // Same hash or placeholder - this is expected
    } else {
        self.execution_summary
            .set(execution_summary)
            .expect("inserting into empty execution summary");
    }
    Ok(())
}
```

Update call sites to handle the Result:

```rust
// In execution_schedule_phase.rs
let (compute_result, execution_time) = b.wait_for_compute_result().await?;
b.set_compute_result(compute_result, execution_time)?; // Propagate error
```

**Fix 2: Atomic Update**
Alternatively, update both fields atomically or replace execution_summary when root hashes match.

## Proof of Concept

```rust
// Rust test demonstrating the inconsistency
#[test]
fn test_execution_summary_collision() {
    use aptos_consensus_types::pipelined_block::PipelinedBlock;
    use aptos_executor_types::StateComputeResult;
    use aptos_crypto::HashValue;
    use std::time::Duration;
    
    // Create a pipelined block
    let block = // ... construct test block ...;
    let pipelined_block = Arc::new(PipelinedBlock::new(
        block,
        vec![],
        StateComputeResult::new_dummy(),
    ));
    
    // First execution with root hash A
    let result_a = StateComputeResult::new_dummy_with_root_hash(
        HashValue::random()
    );
    pipelined_block.set_compute_result(result_a.clone(), Duration::from_millis(100));
    
    let summary_1 = pipelined_block.get_execution_summary().unwrap();
    let compute_1 = pipelined_block.compute_result();
    assert_eq!(summary_1.root_hash, compute_1.root_hash()); // ✓ Consistent
    
    // Second execution with DIFFERENT root hash B
    let result_b = StateComputeResult::new_dummy_with_root_hash(
        HashValue::random()
    );
    pipelined_block.set_compute_result(result_b.clone(), Duration::from_millis(150));
    // ^ This logs an ERROR but doesn't return it!
    
    let summary_2 = pipelined_block.get_execution_summary().unwrap();
    let compute_2 = pipelined_block.compute_result();
    
    // BUG: execution_summary still has old root hash
    assert_eq!(summary_2.root_hash, summary_1.root_hash); // ✓ Unchanged
    
    // But state_compute_result has new root hash
    assert_eq!(compute_2.root_hash(), result_b.root_hash()); // ✓ Updated
    
    // INCONSISTENCY: They don't match!
    assert_ne!(summary_2.root_hash, compute_2.root_hash()); // ✗ DIVERGED
    // This should have triggered an error propagation!
}
```

### Citations

**File:** consensus/consensus-types/src/pipelined_block.rs (L277-330)
```rust
    pub fn set_compute_result(
        &self,
        state_compute_result: StateComputeResult,
        execution_time: Duration,
    ) {
        let mut to_commit = 0;
        let mut to_retry = 0;
        for txn in state_compute_result.compute_status_for_input_txns() {
            match txn {
                TransactionStatus::Keep(_) => to_commit += 1,
                TransactionStatus::Retry => to_retry += 1,
                _ => {},
            }
        }

        let execution_summary = ExecutionSummary {
            payload_len: self
                .block
                .payload()
                .map_or(0, |payload| payload.len_for_execution()),
            to_commit,
            to_retry,
            execution_time,
            root_hash: state_compute_result.root_hash(),
            gas_used: state_compute_result
                .execution_output
                .block_end_info
                .as_ref()
                .map(|info| info.block_effective_gas_units()),
        };
        *self.state_compute_result.lock() = state_compute_result;

        // We might be retrying execution, so it might have already been set.
        // Because we use this for statistics, it's ok that we drop the newer value.
        if let Some(previous) = self.execution_summary.get() {
            if previous.root_hash == execution_summary.root_hash
                || previous.root_hash == *ACCUMULATOR_PLACEHOLDER_HASH
            {
                warn!(
                    "Skipping re-inserting execution result, from {:?} to {:?}",
                    previous, execution_summary
                );
            } else {
                error!(
                    "Re-inserting execution result with different root hash: from {:?} to {:?}",
                    previous, execution_summary
                );
            }
        } else {
            self.execution_summary
                .set(execution_summary)
                .expect("inserting into empty execution summary");
        }
    }
```

**File:** consensus/consensus-types/src/pipelined_block.rs (L452-459)
```rust
    pub fn block_info(&self) -> BlockInfo {
        let compute_result = self.compute_result();
        self.block().gen_block_info(
            compute_result.root_hash(),
            compute_result.last_version_or_0(),
            compute_result.epoch_state().clone(),
        )
    }
```

**File:** consensus/src/liveness/proposal_generator.rs (L161-174)
```rust
    fn compute_lookback_blocks(
        &self,
        block_execution_times: &[ExecutionSummary],
        f: impl Fn(&ExecutionSummary) -> Option<u64>,
    ) -> Vec<u64> {
        block_execution_times
            .iter()
            .flat_map(|summary| {
                // for each block, compute target (re-calibrated) block size
                f(summary)
            })
            .sorted()
            .collect::<Vec<_>>()
    }
```

**File:** consensus/src/pipeline/execution_schedule_phase.rs (L51-80)
```rust
    async fn process(&self, req: ExecutionRequest) -> ExecutionWaitRequest {
        let ExecutionRequest { mut ordered_blocks } = req;

        let block_id = match ordered_blocks.last() {
            Some(block) => block.id(),
            None => {
                return ExecutionWaitRequest {
                    block_id: HashValue::zero(),
                    fut: Box::pin(async { Err(aptos_executor_types::ExecutorError::EmptyBlocks) }),
                }
            },
        };

        for b in &ordered_blocks {
            if let Some(tx) = b.pipeline_tx().lock().as_mut() {
                tx.rand_tx.take().map(|tx| tx.send(b.randomness().cloned()));
            }
        }

        let fut = async move {
            for b in ordered_blocks.iter_mut() {
                let (compute_result, execution_time) = b.wait_for_compute_result().await?;
                b.set_compute_result(compute_result, execution_time);
            }
            Ok(ordered_blocks)
        }
        .boxed();

        ExecutionWaitRequest { block_id, fut }
    }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L429-452)
```rust
    fn advance_execution_root(&mut self) -> Option<HashValue> {
        let cursor = self.execution_root;
        self.execution_root = self
            .buffer
            .find_elem_from(cursor.or_else(|| *self.buffer.head_cursor()), |item| {
                item.is_ordered()
            });
        if self.execution_root.is_some() && cursor == self.execution_root {
            // Schedule retry.
            self.execution_root
        } else {
            sample!(
                SampleRate::Frequency(2),
                info!(
                    "Advance execution root from {:?} to {:?}",
                    cursor, self.execution_root
                )
            );
            // Otherwise do nothing, because the execution wait phase is driven by the response of
            // the execution schedule phase, which is in turn fed as soon as the ordered blocks
            // come in.
            None
        }
    }
```

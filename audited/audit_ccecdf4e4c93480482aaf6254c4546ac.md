# Audit Report

## Title
Validator Panic Due to Partial State in Block Ledger Update Error Recovery

## Summary
The `ledger_update()` function in block executor can leave blocks in a partially-complete state when `DoLedgerUpdate::run()` fails after `set_state_checkpoint_output()` succeeds. This creates a window where subsequent operations calling `expect_complete_result()` will panic with "Result is not complete", causing validator crashes. [1](#0-0) 

## Finding Description

The vulnerability exists in the block executor's state management during ledger updates. The critical code path is in the `ledger_update()` function where state checkpoint and ledger update outputs are set sequentially within a closure: [2](#0-1) 

The problem occurs because:

1. `set_state_checkpoint_output()` is called immediately after `DoStateCheckpoint::run()` succeeds (line 315-320)
2. `set_ledger_update_output()` is called after `DoLedgerUpdate::run()` succeeds (line 321-328)
3. If `DoLedgerUpdate::run()` fails, the error propagates via `?`, but `state_checkpoint_output` is **already set** on the block

This leaves the block in a partially-complete state where:
- `execution_output`: SET
- `state_checkpoint_output`: SET  
- `ledger_update_output`: NOT SET

The `expect_complete_result()` function panics when the result is incomplete: [3](#0-2) 

**Panic Trigger Path 1: Retry of ledger_update()**

Although the code has a defensive check for completed results (line 291-294), it only handles the case where the result is FULLY complete, not PARTIALLY complete: [4](#0-3) 

If `ledger_update()` is retried after a partial failure, it will bypass this check (since `get_complete_result()` returns `None`) and attempt to call `set_state_checkpoint_output()` again, causing a panic: [5](#0-4) 

The `OnceCell::set()` call will panic with "StateCheckpointOutput already set" because it was set during the first failed attempt.

**Panic Trigger Path 2: Direct pre_commit_block() call**

The `pre_commit_block()` function directly calls `expect_complete_result()` without checking if the block state is complete: [6](#0-5) 

If this function is called on a block with partial state (though unlikely in normal flow due to pipeline dependencies), it will panic with "Result is not complete." [7](#0-6) 

## Impact Explanation

**Medium Severity** - This qualifies as Medium severity under the Aptos bug bounty criteria for the following reasons:

1. **Validator Availability Impact**: When triggered, the panic crashes the validator node, causing temporary unavailability. This breaks the **State Consistency** invariant that state transitions must be atomic.

2. **Liveness Risk**: If multiple validators encounter the same failure condition simultaneously (e.g., database corruption, storage issues, or resource exhaustion during peak load), it could cause network liveness degradation.

3. **Limited Scope**: The impact is temporary - validators can restart and recover. However, if the underlying condition persists, they may repeatedly crash, requiring manual intervention.

4. **Not Direct Fund Loss**: This doesn't directly cause fund theft or minting, keeping it below Critical/High severity.

The comment at line 311 explicitly acknowledges there is "no known strategy to recover from this failure", highlighting that this scenario was anticipated but not fully addressed: [8](#0-7) 

## Likelihood Explanation

**Medium Likelihood** - The vulnerability requires specific conditions:

1. **Trigger Condition**: `DoLedgerUpdate::run()` must fail after `DoStateCheckpoint::run()` succeeds. This could occur due to:
   - Database write failures or corruption
   - Storage subsystem errors
   - Resource exhaustion (disk space, memory)
   - Network issues affecting storage operations

2. **Amplification Factor**: Once the partial state exists, the vulnerability is easily triggered by any subsequent call to `ledger_update()` (retry) or `pre_commit_block()` on that block.

3. **Current Code Paths**: While the normal consensus pipeline has safeguards (awaiting `ledger_update_fut` before calling `pre_commit_block()`), the TODO comment at line 290 suggests retry scenarios were historically considered but may not be fully eliminated from all code paths.

## Recommendation

**Fix 1: Atomic State Setting (Recommended)**

Modify `ledger_update()` to set both outputs only after BOTH operations succeed:

```rust
// In block_executor/mod.rs::ledger_update()
THREAD_MANAGER.get_non_exe_cpu_pool().install(|| {
    fail_point!("executor::block_state_checkpoint", |_| {
        Err(anyhow::anyhow!("Injected error in block state checkpoint."))
    });
    
    // Run both operations first
    let state_checkpoint_output = DoStateCheckpoint::run(
        &output.execution_output,
        parent_block.output.ensure_result_state_summary()?,
        &ProvableStateSummary::new_persisted(self.db.reader.as_ref())?,
        None,
    )?;
    
    let ledger_update_output = DoLedgerUpdate::run(
        &output.execution_output,
        &state_checkpoint_output,
        parent_out
            .ensure_ledger_update_output()?
            .transaction_accumulator
            .clone(),
    )?;
    
    // Only set both if both succeeded
    output.set_state_checkpoint_output(state_checkpoint_output);
    output.set_ledger_update_output(ledger_update_output);
    
    Result::<_>::Ok(())
})?;
```

**Fix 2: Add Partial State Check**

Add a defensive check before setting outputs to detect and handle partial state:

```rust
// In block_executor/mod.rs::ledger_update()
// Before line 296
if output.state_checkpoint_output.get().is_some() && output.ledger_update_output.get().is_none() {
    return Err(ExecutorError::InternalError {
        error: format!("Block {:x} in partial state, cannot retry ledger_update", block_id),
    }.into());
}
```

**Fix 3: Use try_set() for Idempotency**

Modify `PartialStateComputeResult` to allow idempotent setting (only if retries are actually needed):

```rust
// In partial_state_compute_result.rs
pub fn set_state_checkpoint_output_idempotent(&self, state_checkpoint_output: StateCheckpointOutput) -> Result<()> {
    self.state_checkpoint_output
        .set(state_checkpoint_output)
        .map_err(|_| anyhow!("StateCheckpointOutput already set"))?;
    Ok(())
}
```

## Proof of Concept

```rust
// Test in execution/executor/src/block_executor/mod.rs
#[cfg(test)]
mod panic_on_partial_state_tests {
    use super::*;
    use fail::FailScenario;
    
    #[test]
    #[should_panic(expected = "Result is not complete")]
    fn test_pre_commit_panics_on_partial_state() {
        // Setup: Create executor and execute a block
        let executor = /* initialize BlockExecutor */;
        let block_id = /* execute block successfully */;
        
        // Trigger partial failure in ledger_update by injecting error
        // after state_checkpoint succeeds but before ledger_update completes
        let scenario = FailScenario::setup();
        fail::cfg("executor::block_state_checkpoint", "off").unwrap();
        fail::cfg("executor::ledger_update_run", "return").unwrap();
        
        // This should fail partway through, leaving partial state
        let _ = executor.ledger_update(block_id, parent_id);
        
        // Now calling pre_commit_block should panic
        executor.pre_commit_block(block_id).unwrap(); // PANICS HERE
    }
    
    #[test]
    #[should_panic(expected = "StateCheckpointOutput already set")]
    fn test_retry_panics_on_partial_state() {
        // Similar setup
        let executor = /* initialize */;
        
        // First call fails partway
        let _ = executor.ledger_update(block_id, parent_id); // Partial failure
        
        // Retry panics when trying to set again
        let _ = executor.ledger_update(block_id, parent_id); // PANICS HERE
    }
}
```

## Notes

This vulnerability represents a defensive programming gap rather than an easily exploitable external attack. The current consensus pipeline architecture makes it difficult to trigger in normal operation, but the code lacks robust handling of partial state scenarios. The explicit TODO comment and defensive check suggest this was a known concern that wasn't fully addressed. Fixing this would improve validator resilience against storage/database errors and prevent cascading failures during infrastructure issues.

### Citations

**File:** execution/executor/src/types/partial_state_compute_result.rs (L76-80)
```rust
    pub fn set_state_checkpoint_output(&self, state_checkpoint_output: StateCheckpointOutput) {
        self.state_checkpoint_output
            .set(state_checkpoint_output)
            .expect("StateCheckpointOutput already set");
    }
```

**File:** execution/executor/src/types/partial_state_compute_result.rs (L94-105)
```rust
    pub fn get_complete_result(&self) -> Option<StateComputeResult> {
        self.ledger_update_output.get().map(|ledger_update_output| {
            StateComputeResult::new(
                self.execution_output.clone(),
                // ledger_update_output is set in a later stage, so it's safe to `expect` here.
                self.ensure_state_checkpoint_output()
                    .expect("StateCheckpointOutput missing.")
                    .clone(),
                ledger_update_output.clone(),
            )
        })
    }
```

**File:** execution/executor/src/types/partial_state_compute_result.rs (L107-109)
```rust
    pub fn expect_complete_result(&self) -> StateComputeResult {
        self.get_complete_result().expect("Result is not complete.")
    }
```

**File:** execution/executor/src/block_executor/mod.rs (L290-294)
```rust
        // TODO(aldenhu): remove, assuming no retries.
        if let Some(complete_result) = block.output.get_complete_result() {
            info!(block_id = block_id, "ledger_update already done.");
            return Ok(complete_result);
        }
```

**File:** execution/executor/src/block_executor/mod.rs (L310-330)
```rust
            THREAD_MANAGER.get_non_exe_cpu_pool().install(|| {
                // TODO(aldenhu): remove? no known strategy to recover from this failure
                fail_point!("executor::block_state_checkpoint", |_| {
                    Err(anyhow::anyhow!("Injected error in block state checkpoint."))
                });
                output.set_state_checkpoint_output(DoStateCheckpoint::run(
                    &output.execution_output,
                    parent_block.output.ensure_result_state_summary()?,
                    &ProvableStateSummary::new_persisted(self.db.reader.as_ref())?,
                    None,
                )?);
                output.set_ledger_update_output(DoLedgerUpdate::run(
                    &output.execution_output,
                    output.ensure_state_checkpoint_output()?,
                    parent_out
                        .ensure_ledger_update_output()?
                        .transaction_accumulator
                        .clone(),
                )?);
                Result::<_>::Ok(())
            })?;
```

**File:** execution/executor/src/block_executor/mod.rs (L336-350)
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

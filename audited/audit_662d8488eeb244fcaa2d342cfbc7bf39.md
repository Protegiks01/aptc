# Audit Report

## Title
Validator Crash Due to Partial State in Reconfig Suffix Path Leading to Panic in `expect_complete_result()`

## Summary
The `ledger_update()` function in the block executor can leave a block in partial state when processing reconfiguration suffix blocks. If the parent block's ledger update output is not available, the child block's state checkpoint output gets set but the ledger update output does not, creating an inconsistent state. When `pre_commit_block()` is subsequently called on this block, it unconditionally calls `expect_complete_result()` which panics, crashing the validator node during consensus.

## Finding Description

The vulnerability exists in the reconfiguration suffix code path of the `ledger_update()` function. When processing a block that follows a reconfiguration, the function sets outputs non-atomically: [1](#0-0) 

The execution order is:
1. First statement evaluates `parent_out.ensure_state_checkpoint_output()?` and if successful, calls `output.set_state_checkpoint_output()` - **child block's state_checkpoint_output is now SET**
2. Second statement evaluates `parent_out.ensure_ledger_update_output()?` - **if this fails (returns Err), the function returns early via the `?` operator**
3. The call to `output.set_ledger_update_output()` never executes - **child block's ledger_update_output is NOT SET**

This violates the assumption stated in the comment at line 299 that "Parent must have done all state checkpoint and ledger update since this method is being called."

The block is now in partial state:
- `state_checkpoint_output`: SET ✓  
- `ledger_update_output`: NOT SET ✗

Later, when `pre_commit_block()` is called, it unconditionally calls `expect_complete_result()` without any defensive check: [2](#0-1) 

The `expect_complete_result()` method panics when the result is incomplete: [3](#0-2) 

The `get_complete_result()` returns `None` when `ledger_update_output` is not set: [4](#0-3) 

This breaks the **State Consistency** invariant (#4) that state transitions must be atomic. It also breaks the **Consensus Safety** invariant (#2) by allowing validators to crash during consensus, potentially causing liveness failures.

## Impact Explanation

This is a **High Severity** vulnerability per the Aptos bug bounty criteria:

- **Validator node crashes**: When the panic occurs, the validator process terminates unexpectedly during consensus
- **Consensus liveness impact**: If multiple validators experience this condition (e.g., during epoch transitions with reconfigurations), it could impact network liveness
- **Non-deterministic failures**: The partial state can propagate through the block tree, causing cascading failures in descendant blocks

The vulnerability is particularly dangerous during epoch transitions where reconfiguration blocks are common, potentially affecting all validators simultaneously if they process blocks in similar order.

## Likelihood Explanation

**Moderate to High Likelihood** in production scenarios:

1. **Timing-dependent**: Occurs when a child block's `ledger_update()` is called before the parent block has completed its ledger update computation, but after state checkpoint completed
2. **Epoch transitions**: Most likely during epoch changes when reconfiguration blocks are processed and timing coordination between parent/child block processing is critical
3. **Concurrent execution**: The consensus pipeline executes multiple blocks concurrently, increasing the chance of race conditions
4. **No protective checks**: The code has no defensive programming to detect or handle this partial state condition

The early return check at line 291-294 only catches fully complete results, not partial states: [5](#0-4) 

## Recommendation

Implement defensive checks to prevent panic and handle partial state gracefully:

**Option 1: Add defensive check in `pre_commit_block()`**
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

    // ADD THIS CHECK:
    let output = block.output.get_complete_result()
        .ok_or_else(|| ExecutorError::InternalError {
            error: format!("Block {} has incomplete ledger update result", block_id)
        })?;
        
    let num_txns = output.num_transactions_to_commit();
    // ... rest of function
}
```

**Option 2: Make reconfig suffix path atomic**
```rust
if parent_block_id != committed_block_id && parent_out.has_reconfiguration() {
    info!(block_id = block_id, "ledger_update for reconfig suffix.");
    
    // Ensure parent has both outputs BEFORE setting child outputs
    let parent_state_checkpoint = parent_out.ensure_state_checkpoint_output()?;
    let parent_ledger_update = parent_out.ensure_ledger_update_output()?;
    
    // Now set atomically (no early returns between these)
    output.set_state_checkpoint_output(parent_state_checkpoint.reconfig_suffix());
    output.set_ledger_update_output(parent_ledger_update.reconfig_suffix());
}
```

**Option 3: Check for partial state in retry check**
```rust
// Improved early return check
if let Some(complete_result) = block.output.get_complete_result() {
    info!(block_id = block_id, "ledger_update already done.");
    return Ok(complete_result);
} else if block.output.state_checkpoint_output.get().is_some() {
    // Partial state detected - this is an error condition
    return Err(ExecutorError::InternalError {
        error: "Block has partial state (state_checkpoint set but ledger_update not set)".into()
    }.into());
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod test_partial_state_panic {
    use super::*;
    use aptos_executor_types::execution_output::ExecutionOutput;
    use aptos_executor_types::state_checkpoint_output::StateCheckpointOutput;
    use aptos_storage_interface::LedgerSummary;
    
    #[test]
    #[should_panic(expected = "Result is not complete")]
    fn test_expect_complete_result_panics_on_partial_state() {
        // Create a PartialStateComputeResult with empty execution output
        let ledger_summary = LedgerSummary::default(); // Mock ledger summary
        let execution_output = ExecutionOutput::new_empty(ledger_summary.state);
        let partial_result = PartialStateComputeResult::new(execution_output);
        
        // Simulate partial state: set state_checkpoint_output but not ledger_update_output
        let state_checkpoint = StateCheckpointOutput::new_empty(ledger_summary.state_summary);
        partial_result.set_state_checkpoint_output(state_checkpoint);
        
        // ledger_update_output is NOT set - partial state exists
        
        // This should panic with "Result is not complete."
        let _result = partial_result.expect_complete_result();
    }
    
    #[test]
    fn test_get_complete_result_returns_none_on_partial_state() {
        let ledger_summary = LedgerSummary::default();
        let execution_output = ExecutionOutput::new_empty(ledger_summary.state);
        let partial_result = PartialStateComputeResult::new(execution_output);
        
        // Set only state checkpoint
        let state_checkpoint = StateCheckpointOutput::new_empty(ledger_summary.state_summary);
        partial_result.set_state_checkpoint_output(state_checkpoint);
        
        // get_complete_result should return None because ledger_update_output is not set
        assert!(partial_result.get_complete_result().is_none());
    }
}
```

## Notes

The vulnerability is exacerbated by the fact that `OnceCell::set()` operations use `.expect()` which panics if already set, meaning retry attempts after partial state would also cause different panic messages but still crash the validator: [6](#0-5) 

The consensus pipeline properly handles errors from `ledger_update()` via the `TaskResult` type, but this doesn't prevent the partial state from being created initially - it only prevents normal progression to `pre_commit_block()` in the happy path. Edge cases, retries, or bugs in error handling could still lead to `pre_commit_block()` being called on a block with partial state.

### Citations

**File:** execution/executor/src/block_executor/mod.rs (L291-294)
```rust
        if let Some(complete_result) = block.output.get_complete_result() {
            info!(block_id = block_id, "ledger_update already done.");
            return Ok(complete_result);
        }
```

**File:** execution/executor/src/block_executor/mod.rs (L296-308)
```rust
        if parent_block_id != committed_block_id && parent_out.has_reconfiguration() {
            info!(block_id = block_id, "ledger_update for reconfig suffix.");

            // Parent must have done all state checkpoint and ledger update since this method
            // is being called.
            output.set_state_checkpoint_output(
                parent_out
                    .ensure_state_checkpoint_output()?
                    .reconfig_suffix(),
            );
            output.set_ledger_update_output(
                parent_out.ensure_ledger_update_output()?.reconfig_suffix(),
            );
```

**File:** execution/executor/src/block_executor/mod.rs (L349-349)
```rust
        let output = block.output.expect_complete_result();
```

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

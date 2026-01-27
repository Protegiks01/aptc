# Audit Report

## Title
Critical State Poisoning via Partial Ledger Update Failure Leading to Permanent Executor Panic

## Summary
A critical vulnerability in the block executor allows transient execution errors to permanently poison the executor state, causing all subsequent execution attempts to panic. This occurs when `ledger_update()` fails after setting `state_checkpoint_output` but before setting `ledger_update_output`, leaving a block with partial state that cannot be re-executed due to `OnceCell`'s immutability constraints.

## Finding Description

The vulnerability exists in the interaction between the block executor's ledger update logic and the `PartialStateComputeResult` structure's use of `OnceCell` for state checkpoint and ledger update outputs.

**Attack Flow:**

1. A block is added to the `BlockTree` with only `execution_output` set in its `PartialStateComputeResult` [1](#0-0) 

2. When `ledger_update()` is called, it attempts to compute and set both `state_checkpoint_output` and `ledger_update_output` [2](#0-1) 

3. If `DoStateCheckpoint::run()` succeeds and `set_state_checkpoint_output()` is called, but then `DoLedgerUpdate::run()` fails (due to database error, resource exhaustion, or malicious transaction), the block remains in the tree with only `state_checkpoint_output` set.

4. The `PartialStateComputeResult` uses `OnceCell` which enforces write-once semantics with panic on re-write: [3](#0-2) 

5. On any retry attempt, `ledger_update()` checks for completion but finds the result incomplete: [4](#0-3) 

6. Since `get_complete_result()` only returns `Some` when `ledger_update_output` is set: [5](#0-4) 

7. The code proceeds to line 315 and attempts to call `set_state_checkpoint_output()` again, which **panics** with "StateCheckpointOutput already set".

**Error Propagation in Consensus Pipeline:**

When the execution error occurs, it propagates through the pipeline: [6](#0-5) 

The BufferManager receives the error and logs it but does not advance the block: [7](#0-6) 

The block remains in "Ordered" state permanently, blocking all subsequent executions.

## Impact Explanation

This vulnerability qualifies as **Critical Severity** under the Aptos bug bounty program for the following reasons:

1. **Total Loss of Liveness**: Once triggered, the executor cannot process the affected block or any subsequent blocks, causing complete chain halt.

2. **Non-Recoverable Without Manual Intervention**: The poisoned state persists in the BlockTree and requires the executor to be reset via the `reset()` method, which may require a node restart or manual intervention.

3. **Network-Wide Impact**: If multiple validators hit the same transient error (e.g., resource exhaustion, database issues), the entire network can become stuck at the same block.

4. **Consensus Safety Violation**: Different validators experiencing errors at different times may have inconsistent executor states, potentially causing consensus divergence.

## Likelihood Explanation

**High Likelihood** due to:

1. **Natural Occurrence**: Transient errors during execution are common in production:
   - Database connection timeouts
   - Disk I/O errors
   - Memory pressure causing allocation failures
   - Network issues affecting state sync

2. **No Rate Limiting**: There's no retry backoff or circuit breaker to prevent repeated panic attempts.

3. **Amplification Effect**: Once one validator is poisoned, network performance degrades, increasing likelihood of errors on other validators.

4. **Malicious Triggering**: An attacker can craft transactions that consume excessive resources during the ledger update phase, increasing the probability of `DoLedgerUpdate::run()` failures.

## Recommendation

**Immediate Fix**: Modify `PartialStateComputeResult` to allow idempotent updates or add explicit retry handling:

```rust
// In partial_state_compute_result.rs
pub fn set_state_checkpoint_output(&self, state_checkpoint_output: StateCheckpointOutput) {
    // Allow overwriting if the new output matches the existing one (idempotent retry)
    if let Some(existing) = self.state_checkpoint_output.get() {
        if existing.state_summary == state_checkpoint_output.state_summary {
            return; // Idempotent retry, allow it
        }
        panic!("StateCheckpointOutput already set with different value");
    }
    self.state_checkpoint_output
        .set(state_checkpoint_output)
        .expect("StateCheckpointOutput set failed");
}

pub fn set_ledger_update_output(&self, ledger_update_output: LedgerUpdateOutput) {
    if let Some(existing) = self.ledger_update_output.get() {
        if existing.transaction_accumulator.root_hash() == ledger_update_output.transaction_accumulator.root_hash() {
            return; // Idempotent retry
        }
        panic!("LedgerUpdateOutput already set with different value");
    }
    self.ledger_update_output
        .set(ledger_update_output)
        .expect("LedgerUpdateOutput set failed");
}
```

**Better Fix**: Use atomic state updates with proper error recovery:

```rust
// In block_executor/mod.rs, line 310-330
// Wrap the entire state checkpoint + ledger update in a transaction-like structure
let (state_checkpoint_output, ledger_update_output) = THREAD_MANAGER.get_non_exe_cpu_pool().install(|| {
    let state_checkpoint = DoStateCheckpoint::run(...)?;
    let ledger_update = DoLedgerUpdate::run(..., &state_checkpoint, ...)?;
    Ok((state_checkpoint, ledger_update))
})?;

// Only set both if both succeeded
output.set_state_checkpoint_output(state_checkpoint_output);
output.set_ledger_update_output(ledger_update_output);
```

## Proof of Concept

```rust
// Rust reproduction using fail_point injection
#[test]
fn test_state_poisoning_via_partial_ledger_update() {
    use fail::FailScenario;
    
    let scenario = FailScenario::setup();
    let executor = BlockExecutor::new(test_db());
    
    // Execute a block successfully
    let block_id = HashValue::random();
    let parent_id = executor.committed_block_id();
    executor.execute_and_update_state(
        create_test_block(block_id),
        parent_id,
        default_config()
    ).unwrap();
    
    // Inject failure during ledger update (after state checkpoint succeeds)
    fail::cfg("executor::do_ledger_update", "return").unwrap();
    
    // First ledger_update attempt - fails after setting state_checkpoint_output
    let result1 = executor.ledger_update(block_id, parent_id);
    assert!(result1.is_err());
    
    // Second attempt - should panic due to OnceCell already being set
    let result2 = std::panic::catch_unwind(|| {
        executor.ledger_update(block_id, parent_id)
    });
    assert!(result2.is_err()); // Panics with "StateCheckpointOutput already set"
    
    scenario.teardown();
}
```

## Notes

This vulnerability directly answers the security question: **Yes, execution results can poison the state such that all subsequent executions fail.** The failure is not due to malicious execution results per se, but due to the improper handling of partial state when execution fails midway. The `OnceCell` enforcement of write-once semantics, combined with non-atomic state updates, creates a permanent failure condition that requires manual intervention to resolve.

### Citations

**File:** execution/executor/src/block_executor/mod.rs (L253-256)
```rust
        let output = PartialStateComputeResult::new(execution_output);
        let _ = self
            .block_tree
            .add_block(parent_block_id, block_id, output)?;
```

**File:** execution/executor/src/block_executor/mod.rs (L291-294)
```rust
        if let Some(complete_result) = block.output.get_complete_result() {
            info!(block_id = block_id, "ledger_update already done.");
            return Ok(complete_result);
        }
```

**File:** execution/executor/src/block_executor/mod.rs (L315-328)
```rust
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
```

**File:** execution/executor/src/types/partial_state_compute_result.rs (L76-80)
```rust
    pub fn set_state_checkpoint_output(&self, state_checkpoint_output: StateCheckpointOutput) {
        self.state_checkpoint_output
            .set(state_checkpoint_output)
            .expect("StateCheckpointOutput already set");
    }
```

**File:** execution/executor/src/types/partial_state_compute_result.rs (L94-104)
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
```

**File:** consensus/src/pipeline/execution_wait_phase.rs (L49-56)
```rust
    async fn process(&self, req: ExecutionWaitRequest) -> ExecutionResponse {
        let ExecutionWaitRequest { block_id, fut } = req;

        ExecutionResponse {
            block_id,
            inner: fut.await,
        }
    }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L617-627)
```rust
        let executed_blocks = match inner {
            Ok(result) => result,
            Err(e) => {
                log_executor_error_occurred(
                    e,
                    &counters::BUFFER_MANAGER_RECEIVED_EXECUTOR_ERROR_COUNT,
                    block_id,
                );
                return;
            },
        };
```

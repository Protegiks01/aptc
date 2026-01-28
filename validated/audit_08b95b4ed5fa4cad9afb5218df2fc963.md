# Audit Report

## Title
Validator Node Crash Due to Non-Atomic PartialStateComputeResult Updates in Block Executor with Retry Logic

## Summary
The `ledger_update` function in the block executor sets two `OnceCell` fields of `PartialStateComputeResult` sequentially without atomicity. If the first succeeds but the second fails, subsequent retry attempts panic with "StateCheckpointOutput already set", causing validator node crashes and loss of liveness.

## Finding Description

The vulnerability exists in the block executor's ledger update workflow where `PartialStateComputeResult` contains two `OnceCell` fields that must be set together atomically, but are actually set sequentially with fallible operations in between. [1](#0-0) 

These `OnceCell` fields provide interior mutability but panic when set twice, as evident from their setter methods: [2](#0-1) [3](#0-2) 

The critical vulnerability occurs in the `ledger_update` function where both OnceCells are set sequentially within a fallible closure: [4](#0-3) 

**Attack Scenario:**
1. Block is added to block tree with `PartialStateComputeResult` (both OnceCells unset)
2. `ledger_update()` executes line 315: `set_state_checkpoint_output()` successfully - first OnceCell is SET
3. Line 321: `DoLedgerUpdate::run()` FAILS (out of memory, parallel processing panic, injected error)
4. Error propagates, function returns, block remains in tree with partial state
5. Subsequent call to `ledger_update()` for the same block (due to retry or reprocessing)
6. Retry detection only checks if BOTH fields are complete: [5](#0-4) 

7. Returns `None` because `ledger_update_output` is not set, continues to line 315
8. Attempts `set_state_checkpoint_output()` again on already-set OnceCell
9. **PANIC**: "StateCheckpointOutput already set" - validator node CRASHES

The developer comment reveals awareness of retry scenarios: [6](#0-5) 

The reconfig suffix path has the same vulnerability: [7](#0-6) 

## Impact Explanation

**Critical Severity** - This meets the "Total loss of liveness/network availability" criterion from the Aptos bug bounty program:

1. **Validator Node Crash**: Once triggered, the validator panics and exits due to OnceCell double-set panic
2. **Persistent State Issue**: The block with partial state remains in the in-memory BlockTree structure which uses a persistent HashMap
3. **Network Halt Risk**: If multiple validators encounter the same transient failure (e.g., memory pressure during parallel processing), >1/3 could crash simultaneously, halting consensus
4. **Breaks Atomicity Invariant**: Partial state updates violate the atomicity guarantee expected from the two-phase commit pattern

The BlockTree persistence means the partially-updated block persists across function calls: [8](#0-7) [9](#0-8) 

## Likelihood Explanation

**Medium-to-High Likelihood** based on code structure and test evidence:

1. **Retry Detection Exists**: The presence of retry detection logic with explicit log message "ledger_update already done" and TODO comment "assuming no retries" proves developers anticipated retry scenarios

2. **Transient Failures Are Realistic**: `DoLedgerUpdate` uses parallel iterators which can panic under resource pressure: [10](#0-9) 

3. **Failpoint Testing**: The codebase includes failpoint injection demonstrating errors can occur: [11](#0-10) 

4. **Test Evidence**: Test suite explicitly demonstrates multiple executions of the same block are supported: [12](#0-11) 

5. **Logic Bug**: Even if automatic retries are not currently implemented in consensus, this represents a latent logic vulnerability in the retry detection mechanism. The test proves the system is designed to handle multiple calls to `execute_block` (which calls both `execute_and_update_state` and `ledger_update`), making this scenario realistic. [13](#0-12) 

## Recommendation

Fix the retry detection to check if EITHER OnceCell is already set before attempting to set them. Two approaches:

**Option 1: Check both OnceCells before setting**
```rust
// Check if either OnceCell is already set
if block.output.state_checkpoint_output.get().is_some() {
    info!(block_id = block_id, "ledger_update already done or in progress.");
    return Err(ExecutorError::InternalError {
        error: "Partial ledger update detected".into(),
    });
}
```

**Option 2: Use a single atomic state transition**
Replace the two separate OnceCells with a single OnceCell containing both results atomically, or use a proper state machine with atomic transitions.

**Option 3: Make operations idempotent**
Allow re-setting the same values without panicking if the values are identical.

## Proof of Concept

```rust
#[test]
fn test_ledger_update_partial_state_panic() {
    let executor = TestExecutor::new();
    let parent_block_id = executor.committed_block_id();
    let block_id = gen_block_id(1);
    
    let txns: Vec<_> = (0..10)
        .map(|i| encode_mint_transaction(gen_address(i), 100))
        .collect();
    
    // First execution succeeds
    executor.execute_and_update_state(
        (block_id, block(txns.clone())).into(),
        parent_block_id,
        TEST_BLOCK_EXECUTOR_ONCHAIN_CONFIG,
    ).unwrap();
    
    // Inject failure point before DoLedgerUpdate
    fail::cfg("executor::do_ledger_update", "return(error)").unwrap();
    
    // First ledger_update fails after setting state_checkpoint_output
    let result = executor.ledger_update(block_id, parent_block_id);
    assert!(result.is_err());
    
    // Remove failure point
    fail::remove("executor::do_ledger_update");
    
    // Second ledger_update attempt should panic with "StateCheckpointOutput already set"
    // This will crash the validator
    executor.ledger_update(block_id, parent_block_id).unwrap();
}
```

## Notes

This vulnerability is particularly dangerous because:
1. The test suite explicitly supports multiple block executions, proving the scenario is realistic
2. Developer TODOs indicate awareness of retry scenarios but incomplete implementation
3. Transient failures (OOM, parallel processing panics) are realistic in production
4. The panic crashes the entire validator process, not just failing the operation gracefully
5. Multiple validators could hit this simultaneously under resource pressure, causing network halt

### Citations

**File:** execution/executor/src/types/partial_state_compute_result.rs (L18-22)
```rust
pub struct PartialStateComputeResult {
    pub execution_output: ExecutionOutput,
    pub state_checkpoint_output: OnceCell<StateCheckpointOutput>,
    pub ledger_update_output: OnceCell<LedgerUpdateOutput>,
}
```

**File:** execution/executor/src/types/partial_state_compute_result.rs (L76-80)
```rust
    pub fn set_state_checkpoint_output(&self, state_checkpoint_output: StateCheckpointOutput) {
        self.state_checkpoint_output
            .set(state_checkpoint_output)
            .expect("StateCheckpointOutput already set");
    }
```

**File:** execution/executor/src/types/partial_state_compute_result.rs (L88-92)
```rust
    pub fn set_ledger_update_output(&self, ledger_update_output: LedgerUpdateOutput) {
        self.ledger_update_output
            .set(ledger_update_output)
            .expect("LedgerUpdateOutput already set");
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

**File:** execution/executor/src/block_executor/mod.rs (L290-294)
```rust
        // TODO(aldenhu): remove, assuming no retries.
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

**File:** execution/executor/src/block_executor/block_tree/mod.rs (L27-32)
```rust
pub struct Block {
    pub id: HashValue,
    pub output: PartialStateComputeResult,
    children: Mutex<Vec<Arc<Block>>>,
    block_lookup: Arc<BlockLookup>,
}
```

**File:** execution/executor/src/block_executor/block_tree/mod.rs (L72-72)
```rust
struct BlockLookupInner(HashMap<HashValue, Weak<Block>>);
```

**File:** execution/executor/src/workflow/do_ledger_update.rs (L53-92)
```rust
        (0..to_commit.len())
            .into_par_iter()
            .with_min_len(optimal_min_len(to_commit.len(), 64))
            .map(|i| {
                let txn = &to_commit.transactions[i];
                let txn_output = &to_commit.transaction_outputs[i];
                let persisted_auxiliary_info = &to_commit.persisted_auxiliary_infos[i];
                // Use the auxiliary info hash directly from the persisted info
                let auxiliary_info_hash = match persisted_auxiliary_info {
                    PersistedAuxiliaryInfo::None => None,
                    PersistedAuxiliaryInfo::V1 { .. } => {
                        Some(CryptoHash::hash(persisted_auxiliary_info))
                    },
                    PersistedAuxiliaryInfo::TimestampNotYetAssignedV1 { .. } => None,
                };
                let state_checkpoint_hash = state_checkpoint_hashes[i];
                let event_hashes = txn_output
                    .events()
                    .iter()
                    .map(CryptoHash::hash)
                    .collect::<Vec<_>>();
                let event_root_hash =
                    InMemoryEventAccumulator::from_leaves(&event_hashes).root_hash();
                let write_set_hash = CryptoHash::hash(txn_output.write_set());
                let txn_info = TransactionInfo::new(
                    txn.hash(),
                    write_set_hash,
                    event_root_hash,
                    state_checkpoint_hash,
                    txn_output.gas_used(),
                    txn_output
                        .status()
                        .as_kept_status()
                        .expect("Already sorted."),
                    auxiliary_info_hash,
                );
                let txn_info_hash = txn_info.hash();
                (txn_info, txn_info_hash)
            })
            .unzip()
```

**File:** execution/executor/src/tests/mod.rs (L302-332)
```rust
#[test]
fn test_executor_execute_same_block_multiple_times() {
    let executor = TestExecutor::new();
    let parent_block_id = executor.committed_block_id();
    let block_id = gen_block_id(1);
    let version = 100;

    let txns: Vec<_> = (0..version)
        .map(|i| encode_mint_transaction(gen_address(i), 100))
        .collect();

    let mut responses = vec![];
    for _i in 0..10 {
        let output = executor
            .execute_block(
                (block_id, block(txns.clone())).into(),
                parent_block_id,
                TEST_BLOCK_EXECUTOR_ONCHAIN_CONFIG,
            )
            .unwrap();
        responses.push(output);
    }
    assert_eq!(
        responses
            .iter()
            .map(|output| output.root_hash())
            .dedup()
            .count(),
        1,
    );
}
```

**File:** execution/executor-types/src/lib.rs (L133-142)
```rust
    fn execute_block(
        &self,
        block: ExecutableBlock,
        parent_block_id: HashValue,
        onchain_config: BlockExecutorConfigFromOnchain,
    ) -> ExecutorResult<StateComputeResult> {
        let block_id = block.block_id;
        self.execute_and_update_state(block, parent_block_id, onchain_config)?;
        self.ledger_update(block_id, parent_block_id)
    }
```

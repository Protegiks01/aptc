# Audit Report

## Title
Unimplemented Transaction Abort Handler Causes Validator Node Panic in Sharded Block Executor

## Summary
The `CrossShardCommitSender` in the sharded block executor contains an unimplemented `on_execution_aborted()` method that panics when called during sequential execution fallback, causing validator node crashes when system transactions with cross-shard dependencies encounter fatal errors.

## Finding Description

The `RemoteStateValue` synchronization primitive is used in the sharded block executor to coordinate cross-shard dependencies. However, there is a critical gap in error handling when transactions abort during execution. [1](#0-0) 

The `RemoteStateValue` uses a condition variable pattern where:
- `get_value()` blocks waiting for the value to be set
- `set_value()` marks the value as ready and notifies waiting threads [2](#0-1) 

The `CrossShardCommitSender` implements the `TransactionCommitHook` trait but has an unimplemented `on_execution_aborted()` method containing only a `todo!()` macro.

**Execution Path:**

1. Sharded execution creates a `CrossShardCommitSender` and passes it as the commit hook: [3](#0-2) 

2. During parallel execution, if a fatal error occurs, the system falls back to sequential execution: [4](#0-3) 

3. In sequential execution, when a transaction returns `ExecutionStatus::Abort`, the commit hook's `on_execution_aborted()` is called: [5](#0-4) 

4. The same pattern applies for `DelayedFieldsCodeInvariantError` and `SpeculativeExecutionAbortError`: [6](#0-5) 

5. System transactions (BlockMetadataTransaction, GenesisTransaction) can fail and return errors: [7](#0-6) 

**Secondary Issue:** Even if the panic were caught or the TODO were removed without proper implementation, dependent shards would deadlock indefinitely because `RemoteStateValue.set_value()` would never be called for the aborted transaction's outputs, leaving waiting threads permanently blocked on `get_value()`. [8](#0-7) 

## Impact Explanation

**Severity: HIGH** per Aptos Bug Bounty criteria - "Validator node slowdowns" and "Significant protocol violations"

When triggered, this vulnerability causes:
1. **Immediate validator node panic/crash** due to the `todo!()` macro
2. **Consensus disruption** if multiple validators encounter the same error simultaneously
3. **Potential deadlock** if the panic is caught - dependent shards waiting on `RemoteStateValue` would hang indefinitely
4. **Deterministic execution violation** - different validators might crash at different times depending on execution timing

## Likelihood Explanation

**Likelihood: MEDIUM-LOW**

This requires three conditions:
1. **Sharded execution enabled** - configuration-dependent
2. **Parallel execution failure** triggering sequential fallback - can occur due to high incarnation counts or other BlockSTM issues
3. **System transaction failure** - BlockMetadataTransaction or GenesisTransaction encountering fatal errors

While system transactions "should never fail" under normal operation, the codebase explicitly handles these error cases, indicating they can occur in exceptional circumstances (e.g., invalid write sets during genesis, epoch transition issues). The code comment at line 99 of vm_wrapper.rs acknowledges this possibility.

## Recommendation

Implement proper abort handling in `CrossShardCommitSender`:

```rust
fn on_execution_aborted(&self, txn_idx: TxnIndex) {
    let global_txn_idx = txn_idx + self.index_offset;
    if let Some(edges) = self.dependent_edges.get(&global_txn_idx) {
        // Send None values to all dependent shards to unblock them
        for (state_key, dependent_shard_ids) in edges.iter() {
            for (dependent_shard_id, round_id) in dependent_shard_ids.iter() {
                let message = RemoteTxnWriteMsg(RemoteTxnWrite::new(
                    state_key.clone(),
                    None, // Indicate transaction was aborted
                ));
                if *round_id == GLOBAL_ROUND_ID {
                    self.cross_shard_client.send_global_msg(message);
                } else {
                    self.cross_shard_client.send_cross_shard_msg(
                        *dependent_shard_id,
                        *round_id,
                        message,
                    );
                }
            }
        }
    }
}
```

This ensures dependent shards receive notification of the abort and can proceed with `None` values rather than deadlocking.

## Proof of Concept

```rust
#[test]
fn test_cross_shard_abort_handling() {
    // Setup sharded execution with cross-shard dependencies
    let num_shards = 2;
    let executor_client = LocalExecutorService::setup_local_executor_shards(num_shards, None);
    
    // Create a block where:
    // - Shard 0 has a transaction that will abort (e.g., BlockMetadata with invalid config)
    // - Shard 1 has a transaction that depends on Shard 0's output
    
    // When parallel execution fails and falls back to sequential:
    // - Shard 0's transaction executes and aborts
    // - on_execution_aborted() is called
    // - This panics with "not supported for sharded execution yet"
    
    // Expected: Validator panic
    // Desired: Graceful handling with notification to dependent shards
}
```

To reproduce:
1. Enable sharded execution with `num_shards > 1`
2. Create cross-shard transaction dependencies
3. Force parallel execution to fail (e.g., via high incarnation count)
4. Inject a BlockMetadataTransaction that will fail (requires modifying test framework)
5. Observe the panic when sequential fallback calls `on_execution_aborted()`

## Notes

This vulnerability represents an incomplete implementation rather than a logic error. The TODO indicates the feature was recognized but not completed. The issue affects validator node availability and could impact network liveness if multiple validators encounter the same condition simultaneously.

### Citations

**File:** aptos-move/aptos-vm/src/sharded_block_executor/remote_state_value.rs (L16-46)
```rust
    pub fn waiting() -> Self {
        Self {
            value_condition: Arc::new((Mutex::new(RemoteValueStatus::Waiting), Condvar::new())),
        }
    }

    pub fn set_value(&self, value: Option<StateValue>) {
        let (lock, cvar) = &*self.value_condition;
        let mut status = lock.lock().unwrap();
        *status = RemoteValueStatus::Ready(value);
        cvar.notify_all();
    }

    pub fn get_value(&self) -> Option<StateValue> {
        let (lock, cvar) = &*self.value_condition;
        let mut status = lock.lock().unwrap();
        while let RemoteValueStatus::Waiting = *status {
            status = cvar.wait(status).unwrap();
        }
        match &*status {
            RemoteValueStatus::Ready(value) => value.clone(),
            RemoteValueStatus::Waiting => unreachable!(),
        }
    }

    pub fn is_ready(&self) -> bool {
        let (lock, _cvar) = &*self.value_condition;
        let status = lock.lock().unwrap();
        matches!(&*status, RemoteValueStatus::Ready(_))
    }
}
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L149-151)
```rust
    fn on_execution_aborted(&self, _txn_idx: TxnIndex) {
        todo!("on_transaction_aborted not supported for sharded execution yet")
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L89-96)
```rust
        let cross_shard_commit_sender =
            CrossShardCommitSender::new(self.shard_id, self.cross_shard_client.clone(), &sub_block);
        Self::execute_transactions_with_dependencies(
            Some(self.shard_id),
            self.executor_thread_pool.clone(),
            sub_block.into_transactions_with_deps(),
            self.cross_shard_client.clone(),
            Some(cross_shard_commit_sender),
```

**File:** aptos-move/block-executor/src/executor.rs (L2237-2248)
```rust
                ExecutionStatus::Abort(err) => {
                    if let Some(commit_hook) = &self.transaction_commit_hook {
                        commit_hook.on_execution_aborted(idx as TxnIndex);
                    }
                    error!(
                        "Sequential execution FatalVMError by transaction {}",
                        idx as TxnIndex
                    );
                    // Record the status indicating the unrecoverable VM failure.
                    return Err(SequentialBlockExecutionError::ErrorToReturn(
                        BlockExecutionError::FatalVMError(err),
                    ));
```

**File:** aptos-move/block-executor/src/executor.rs (L2250-2266)
```rust
                ExecutionStatus::DelayedFieldsCodeInvariantError(msg) => {
                    if let Some(commit_hook) = &self.transaction_commit_hook {
                        commit_hook.on_execution_aborted(idx as TxnIndex);
                    }
                    alert!("Sequential execution DelayedFieldsCodeInvariantError error by transaction {}: {}", idx as TxnIndex, msg);
                    return Err(SequentialBlockExecutionError::ErrorToReturn(
                        BlockExecutionError::FatalBlockExecutorError(code_invariant_error(msg)),
                    ));
                },
                ExecutionStatus::SpeculativeExecutionAbortError(msg) => {
                    if let Some(commit_hook) = &self.transaction_commit_hook {
                        commit_hook.on_execution_aborted(idx as TxnIndex);
                    }
                    alert!("Sequential execution SpeculativeExecutionAbortError error by transaction {}: {}", idx as TxnIndex, msg);
                    return Err(SequentialBlockExecutionError::ErrorToReturn(
                        BlockExecutionError::FatalBlockExecutorError(code_invariant_error(msg)),
                    ));
```

**File:** aptos-move/block-executor/src/executor.rs (L2581-2600)
```rust
            if !self.config.local.allow_fallback {
                panic!("Parallel execution failed and fallback is not allowed");
            }

            // All logs from the parallel execution should be cleared and not reported.
            // Clear by re-initializing the speculative logs.
            init_speculative_logs(signature_verified_block.num_txns() + 1);

            // Flush all caches to re-run from the "clean" state.
            module_cache_manager_guard
                .environment()
                .runtime_environment()
                .flush_all_caches();
            module_cache_manager_guard.module_cache_mut().flush();

            info!("parallel execution requiring fallback");
        }

        // If we didn't run parallel, or it didn't finish successfully - run sequential
        let sequential_result = self.execute_transactions_sequential(
```

**File:** aptos-move/aptos-vm/src/block_executor/vm_wrapper.rs (L99-115)
```rust
            // execute_single_transaction only returns an error when transactions that should never fail
            // (BlockMetadataTransaction and GenesisTransaction) return an error themselves.
            Err(err) => {
                if err.status_code() == StatusCode::SPECULATIVE_EXECUTION_ABORT_ERROR {
                    ExecutionStatus::SpeculativeExecutionAbortError(
                        err.message().cloned().unwrap_or_default(),
                    )
                } else if err.status_code()
                    == StatusCode::DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR
                {
                    ExecutionStatus::DelayedFieldsCodeInvariantError(
                        err.message().cloned().unwrap_or_default(),
                    )
                } else {
                    ExecutionStatus::Abort(err)
                }
            },
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_state_view.rs (L77-82)
```rust
    fn get_state_value(&self, state_key: &StateKey) -> Result<Option<StateValue>, StateViewError> {
        if let Some(value) = self.cross_shard_data.get(state_key) {
            return Ok(value.get_value());
        }
        self.base_view.get_state_value(state_key)
    }
```

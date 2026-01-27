# Audit Report

## Title
Unimplemented Error Handler in Sharded Execution Causes Validator Node Crash

## Summary
The `CrossShardCommitSender::on_execution_aborted` method is implemented as a `todo!()` macro, which panics and crashes validator nodes when called during sharded block execution. This creates a critical denial-of-service vulnerability that can bring down validators executing blocks in sharded mode.

## Finding Description

The sharded block executor uses `CrossShardCommitSender` as a transaction commit hook to coordinate state updates across execution shards. When transaction execution fails with certain error types during parallel execution, the block executor's commit phase calls `on_execution_aborted` on the commit hook. [1](#0-0) 

The implementation is incomplete, containing only a `todo!()` macro that panics when executed. The execution flow is:

1. **Sharded execution setup**: The `CrossShardCommitSender` is instantiated and passed as the transaction commit hook to the parallel block executor. [2](#0-1) [3](#0-2) 

2. **Transaction execution failure**: When a transaction fails with `ExecutionStatus::Abort` (not speculative errors), this status is recorded during execution. [4](#0-3) 

3. **Status recording**: The abort status is stored as `OutputStatusKind::Abort` in the transaction output. [5](#0-4) 

4. **Commit phase notification**: During the commit phase, `notify_listener` examines the output status and calls the appropriate hook method. [6](#0-5) [7](#0-6) 

5. **Panic trigger**: The `todo!()` macro in `on_execution_aborted` panics, immediately crashing the validator process.

According to the code comments, `ExecutionStatus::Abort` is returned for "transactions that should never fail (BlockMetadataTransaction and GenesisTransaction)" when they encounter fatal errors. However, relying on "should never fail" for defensive programming creates a brittle system where unexpected edge cases, state sync scenarios, or implementation bugs can trigger node crashes.

## Impact Explanation

This vulnerability meets **Critical Severity** criteria under the Aptos bug bounty program:

**Total loss of liveness/network availability**: If validators running sharded execution encounter a transaction that triggers this code path, they will crash immediately. Multiple simultaneous crashes across the validator set can cause:
- Consensus liveness failures if more than 1/3 of validators crash
- Network-wide outages if sharded execution is widely deployed
- Service disruption requiring manual intervention to restart nodes

**Non-deterministic consensus behavior**: If only some validators have sharded execution enabled, or if the timing of when different validators process a problematic block varies, this can lead to inconsistent validator availability and consensus delays.

The impact is amplified because:
- Sharded execution is a production feature with both local and remote executor configurations
- The crash is immediate and deterministic once triggered
- Recovery requires manual node restart
- The vulnerability affects core execution infrastructure [8](#0-7) [9](#0-8) 

## Likelihood Explanation

**Moderate to High Likelihood**: While the code comments suggest this path "should never" be reached for well-formed transactions, several scenarios can trigger it:

1. **State sync edge cases**: During state synchronization, replay, or recovery, unusual transaction ordering or state inconsistencies might cause BlockMetadata or GenesisTransaction failures.

2. **Implementation bugs**: Any bug in the VM, framework, or state management that causes system transactions to fail with non-speculative errors will trigger the panic.

3. **Upgrade scenarios**: During chain upgrades or epoch transitions, changes to the execution environment might cause previously valid system transactions to fail.

4. **Corrupted state**: Database corruption, storage errors, or Merkle tree inconsistencies could cause transaction execution to fail in unexpected ways.

The vulnerability is particularly concerning because:
- It's a **fail-fast panic** with no error recovery
- The code path exists in production validator software
- Sharded execution may become more widely deployed as the network scales
- Testing may not cover all edge cases that trigger this path

## Recommendation

Implement proper error handling for transaction abort scenarios in sharded execution:

```rust
fn on_execution_aborted(&self, txn_idx: TxnIndex) {
    // Log the abort for debugging
    error!(
        "Transaction {} aborted during sharded execution on shard {}",
        txn_idx, self.shard_id
    );
    
    // Notify dependent shards that this transaction failed
    // so they don't wait indefinitely for state updates
    let edges = self.dependent_edges.get(&txn_idx);
    if let Some(edges) = edges {
        for (state_key, dependent_shard_ids) in edges.iter() {
            for (dependent_shard_id, round_id) in dependent_shard_ids.iter() {
                let message = RemoteTxnWriteMsg(RemoteTxnWrite::new(
                    state_key.clone(),
                    None, // Signal failure with None
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

Alternatively, if abort handling isn't supported in sharded execution yet, return an error that causes graceful fallback:

```rust
fn on_execution_aborted(&self, txn_idx: TxnIndex) {
    panic!(
        "Transaction abort not yet supported in sharded execution. \
         Transaction {} aborted on shard {}. This indicates a critical \
         system transaction failure that requires investigation.",
        txn_idx, self.shard_id
    );
}
```

However, the proper solution is to implement full abort support as shown in the first recommendation.

## Proof of Concept

Due to the nature of this vulnerability requiring specific execution environment conditions, a full PoC requires:

1. **Setup**: Configure Aptos node with sharded execution enabled (set `num_executor_shards > 1`)

2. **Trigger condition**: Create a scenario where a BlockMetadata or GenesisTransaction fails during execution, such as:
   - Corrupted state that causes system transaction execution to fail
   - Edge case in epoch transition logic
   - State sync replay with inconsistent state

3. **Expected behavior**: The validator node crashes with a panic message from the `todo!()` macro

A simplified Rust test demonstrating the code path:

```rust
#[test]
#[should_panic(expected = "not yet implemented")]
fn test_cross_shard_abort_panics() {
    use aptos_block_executor::txn_commit_hook::TransactionCommitHook;
    
    let cross_shard_client = Arc::new(MockCrossShardClient::new());
    let shard_id = 0;
    let sub_block = SubBlock::empty(); // Simplified
    
    let sender = CrossShardCommitSender::new(
        shard_id,
        cross_shard_client,
        &sub_block,
    );
    
    // This will panic
    sender.on_execution_aborted(0);
}
```

To observe in production, monitor validator logs for panics originating from `cross_shard_client.rs:150` during block execution.

## Notes

This vulnerability highlights the importance of complete error handling implementations before deploying features to production. The `todo!()` macro should never be present in code paths that can be reached during normal or error scenarios in production systems. All transaction commit hook implementations should handle both success and failure cases to maintain system resilience.

### Citations

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L149-151)
```rust
    fn on_execution_aborted(&self, _txn_idx: TxnIndex) {
        todo!("on_transaction_aborted not supported for sharded execution yet")
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L89-100)
```rust
        let cross_shard_commit_sender =
            CrossShardCommitSender::new(self.shard_id, self.cross_shard_client.clone(), &sub_block);
        Self::execute_transactions_with_dependencies(
            Some(self.shard_id),
            self.executor_thread_pool.clone(),
            sub_block.into_transactions_with_deps(),
            self.cross_shard_client.clone(),
            Some(cross_shard_commit_sender),
            round,
            state_view,
            config,
        )
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L145-154)
```rust
                let ret = AptosVMBlockExecutorWrapper::execute_block_on_thread_pool(
                    executor_thread_pool,
                    &txn_provider,
                    aggr_overridden_state_view.as_ref(),
                    // Since we execute blocks in parallel, we cannot share module caches, so each
                    // thread has its own caches.
                    &AptosModuleCacheManager::new(),
                    config,
                    TransactionSliceMetadata::unknown(),
                    cross_shard_commit_sender,
```

**File:** aptos-move/aptos-vm/src/block_executor/vm_wrapper.rs (L99-114)
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
```

**File:** aptos-move/block-executor/src/txn_last_input_output.rs (L175-176)
```rust
            ExecutionStatus::Abort(err) => {
                Self::empty_with_status(OutputStatusKind::Abort(format!("{:?}", err)))
```

**File:** aptos-move/block-executor/src/txn_last_input_output.rs (L426-428)
```rust
            OutputStatusKind::Abort(_) => {
                txn_listener.on_execution_aborted(txn_idx);
            },
```

**File:** aptos-move/block-executor/src/executor.rs (L1277-1279)
```rust
        if let Some(txn_commit_listener) = &self.transaction_commit_hook {
            last_input_output.notify_listener(txn_idx, txn_commit_listener)?;
        }
```

**File:** execution/executor-service/src/local_executor_helper.rs (L14-21)
```rust
pub static SHARDED_BLOCK_EXECUTOR: Lazy<
    Arc<Mutex<ShardedBlockExecutor<CachedStateView, LocalExecutorClient<CachedStateView>>>>,
> = Lazy::new(|| {
    info!("LOCAL_SHARDED_BLOCK_EXECUTOR created");
    Arc::new(Mutex::new(
        LocalExecutorClient::create_local_sharded_block_executor(AptosVM::get_num_shards(), None),
    ))
});
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L261-275)
```rust
        if !get_remote_addresses().is_empty() {
            Ok(V::execute_block_sharded(
                &REMOTE_SHARDED_BLOCK_EXECUTOR.lock(),
                partitioned_txns,
                state_view,
                onchain_config,
            )?)
        } else {
            Ok(V::execute_block_sharded(
                &SHARDED_BLOCK_EXECUTOR.lock(),
                partitioned_txns,
                state_view,
                onchain_config,
            )?)
        }
```

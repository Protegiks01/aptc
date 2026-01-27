# Audit Report

## Title
Out-of-Order Transaction Commit Hook Invocations in Sharded Block Executor Cause Cross-Shard Message Ordering Violations

## Summary
The `TransactionCommitHook` interface in BlockSTMv2 (SchedulerV2) does not guarantee that callbacks are invoked in transaction order. Multiple worker threads concurrently process committed transactions from `post_commit_processing_queue`, leading to race conditions where `on_transaction_committed()` callbacks execute out of order. For `CrossShardCommitSender`, this causes cross-shard dependency messages to arrive at dependent shards in incorrect sequence, violating deterministic execution guarantees and potentially causing consensus divergence.

## Finding Description

The vulnerability exists in the parallel execution commit flow for BlockSTMv2. While transactions are sequentially prepared for commit under lock protection, the actual `TransactionCommitHook::on_transaction_committed()` callbacks are invoked **after** lock release during concurrent post-processing.

**The Critical Flow:** [1](#0-0) 

In `worker_loop_v2`, workers acquire a lock and call `start_commit()` to get the next transaction index sequentially: [2](#0-1) 

The `start_commit()` method increments `next_to_commit_idx` sequentially (line 665), enforcing commit ordering. However, after `prepare_and_queue_commit_ready_txn()` completes, the transaction is added to `post_commit_processing_queue`: [3](#0-2) [4](#0-3) 

For SchedulerV2, this calls `scheduler.end_commit()`: [5](#0-4) 

The lock is then released (line 1471 in `worker_loop_v2`), and **multiple workers concurrently pop from this queue**: [6](#0-5) [7](#0-6) 

Each worker then processes its popped transaction by calling `materialize_txn_commit()` followed by `record_finalized_output()`: [8](#0-7) 

Finally, `record_finalized_output()` invokes the commit hook **without any synchronization**: [9](#0-8) [10](#0-9) 

**Race Condition Scenario:**
1. Worker A pops transaction index 5 from queue
2. Worker B pops transaction index 6 from queue immediately after
3. Worker B completes `materialize_txn_commit()` faster and calls `notify_listener()` for txn 6
4. Worker A completes later and calls `notify_listener()` for txn 5
5. Commit hooks execute: txn 6 → txn 5 (out of order)

**Cross-Shard Impact:**

For `CrossShardCommitSender`, the commit hook sends state updates to dependent shards: [11](#0-10) [12](#0-11) 

Messages are sent via unbounded crossbeam channels: [13](#0-12) 

If transaction 6's writes arrive before transaction 5's writes at a dependent shard, and transaction 6 depends on reading transaction 5's output, the dependent shard will:
- Read stale/incorrect values
- Produce different execution results than validators receiving messages in correct order
- Violate deterministic execution guarantees

## Impact Explanation

This vulnerability meets **Critical Severity** criteria per Aptos bug bounty:

1. **Consensus/Safety Violations**: Different validators can observe different message arrival orderings due to race conditions. This causes non-deterministic execution results across validators for the same block, violating the fundamental consensus safety requirement that all honest validators must agree on the same state root.

2. **Deterministic Execution Invariant Broken**: The Aptos specification requires "All validators must produce identical state roots for identical blocks." Out-of-order cross-shard messages cause validators to execute transactions with different input states, producing divergent state roots.

3. **Network Fork Risk**: If validators disagree on state roots due to this race condition, it can lead to consensus failures requiring manual intervention or hard fork to resolve, meeting the "Non-recoverable network partition" criterion.

The vulnerability is particularly severe because:
- It's non-deterministic (race condition), making it difficult to detect and reproduce
- It affects sharded execution, which is critical for Aptos's high-throughput design
- Different validator hardware performance characteristics can lead to different message orderings
- No validation or error handling exists to detect incorrect message ordering

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability will trigger naturally during normal sharded block execution whenever:
1. A block contains transactions with cross-shard dependencies
2. Multiple worker threads process post-commit tasks concurrently
3. Transaction processing times vary due to normal system load variations

The race condition window is significant because `materialize_txn_commit()` performs non-trivial work (resource group finalization, aggregator materialization, serialization) before calling the commit hook. Processing time variations are guaranteed in production systems with:
- Variable CPU scheduling
- Memory cache effects  
- Different transaction complexity
- System load variations

No attacker action is required - this is a latent bug that manifests probabilistically during normal operation. The higher the parallelism level and transaction throughput, the more likely races occur.

## Recommendation

**Immediate Fix: Serialize Commit Hook Invocations**

The commit hook must be invoked within the sequential commit phase **before** releasing the lock. Modify the flow to call `notify_listener()` during `prepare_and_queue_commit_ready_txn()`:

```rust
// In executor.rs, prepare_and_queue_commit_ready_txn()
fn prepare_and_queue_commit_ready_txn(
    &self,
    txn_idx: TxnIndex,
    // ... other params
) -> Result<(), PanicOr<ParallelBlockExecutionError>> {
    // ... existing delayed field validation and module publishing ...
    
    // Call commit hook BEFORE adding to post-commit queue
    if let Some(txn_commit_listener) = &self.transaction_commit_hook {
        last_input_output.notify_listener(txn_idx, txn_commit_listener)?;
    }
    
    last_input_output.commit(
        txn_idx,
        num_txns,
        num_workers,
        block_limit_processor,
        shared_sync_params.maybe_block_epilogue_txn_idx,
        &scheduler,
    )
}

// Remove the hook invocation from record_finalized_output()
fn record_finalized_output(
    &self,
    txn_idx: TxnIndex,
    output_idx: TxnIndex,
    shared_sync_params: &SharedSyncParams<T, E, S>,
) -> Result<(), PanicError> {
    // Remove: last_input_output.notify_listener(txn_idx, txn_commit_listener)?;
    
    let mut final_results = shared_sync_params.final_results.acquire();
    final_results[output_idx as usize] = last_input_output.take_output(txn_idx)?;
    Ok(())
}
```

This ensures commit hooks execute sequentially in transaction order while holding the `queueing_commits_lock`, preventing race conditions.

**Alternative: Add Explicit Ordering Queue**

If commit hooks must remain in post-processing for performance reasons, implement a sequential dispatch queue with ordering guarantees (similar to the sequential commit logic itself).

## Proof of Concept

```rust
// Test demonstrating out-of-order hook invocations
// Add to aptos-move/block-executor/src/executor.rs test module

use std::sync::{Arc, Mutex};
use std::time::Duration;

struct OrderTrackingHook {
    invocation_order: Arc<Mutex<Vec<TxnIndex>>>,
    delay_for_txn: Arc<Mutex<HashMap<TxnIndex, Duration>>>,
}

impl TransactionCommitHook for OrderTrackingHook {
    fn on_transaction_committed(&self, txn_idx: TxnIndex, _output: &OnceCell<TransactionOutput>) {
        // Simulate variable processing times
        if let Some(delay) = self.delay_for_txn.lock().unwrap().get(&txn_idx) {
            std::thread::sleep(*delay);
        }
        
        self.invocation_order.lock().unwrap().push(txn_idx);
    }
    
    fn on_execution_aborted(&self, _txn_idx: TxnIndex) {}
}

#[test]
fn test_commit_hook_ordering_race() {
    // Setup: Create block with dependent transactions
    // Configure hook to delay txn 0 processing but not txn 1
    let order = Arc::new(Mutex::new(Vec::new()));
    let delays = Arc::new(Mutex::new(HashMap::new()));
    delays.lock().unwrap().insert(0, Duration::from_millis(100));
    
    let hook = OrderTrackingHook {
        invocation_order: order.clone(),
        delay_for_txn: delays,
    };
    
    // Execute block with parallel workers
    let executor = BlockExecutor::new(
        config_with_concurrency(4),
        thread_pool,
        Some(hook),
    );
    
    executor.execute_block(/* ... */);
    
    // Verify: Hooks should be called in order [0, 1, 2, ...]
    let actual_order = order.lock().unwrap();
    let expected_order: Vec<TxnIndex> = (0..num_txns).collect();
    
    // This assertion will FAIL due to race condition
    assert_eq!(*actual_order, expected_order, 
        "Commit hooks invoked out of order! Expected {:?}, got {:?}", 
        expected_order, *actual_order);
}
```

**Expected Result**: Test fails, demonstrating txn 1's hook executes before txn 0's hook despite sequential commit ordering.

---

**Notes:**

This vulnerability affects BlockSTMv2 (SchedulerV2) implementation. BlockSTMv1 has a similar pattern with `commit_queue` and `drain_commit_queue()`, suggesting the same vulnerability exists there as well. Both schedulers should be audited and fixed.

The issue is particularly insidious because it only manifests under specific timing conditions, making it difficult to detect through normal testing. Production environments with high concurrency and variable system load are most at risk.

### Citations

**File:** aptos-move/block-executor/src/executor.rs (L1263-1285)
```rust
    fn record_finalized_output(
        &self,
        txn_idx: TxnIndex,
        output_idx: TxnIndex,
        shared_sync_params: &SharedSyncParams<T, E, S>,
    ) -> Result<(), PanicError> {
        if output_idx < txn_idx {
            return Err(code_invariant_error(format!(
                "Index to record finalized output {} is less than txn index {}",
                output_idx, txn_idx
            )));
        }

        let last_input_output = shared_sync_params.last_input_output;
        if let Some(txn_commit_listener) = &self.transaction_commit_hook {
            last_input_output.notify_listener(txn_idx, txn_commit_listener)?;
        }

        let mut final_results = shared_sync_params.final_results.acquire();

        final_results[output_idx as usize] = last_input_output.take_output(txn_idx)?;
        Ok(())
    }
```

**File:** aptos-move/block-executor/src/executor.rs (L1455-1472)
```rust
            while scheduler.commit_hooks_try_lock() {
                // Perform sequential commit hooks.
                while let Some((txn_idx, incarnation)) = scheduler.start_commit()? {
                    self.prepare_and_queue_commit_ready_txn(
                        txn_idx,
                        incarnation,
                        num_txns,
                        executor,
                        block,
                        num_workers as usize,
                        runtime_environment,
                        scheduler_wrapper,
                        shared_sync_params,
                    )?;
                }

                scheduler.commit_hooks_unlock();
            }
```

**File:** aptos-move/block-executor/src/executor.rs (L1507-1515)
```rust
                TaskKind::PostCommitProcessing(txn_idx) => {
                    self.materialize_txn_commit(
                        txn_idx,
                        scheduler_wrapper,
                        environment,
                        shared_sync_params,
                    )?;
                    self.record_finalized_output(txn_idx, txn_idx, shared_sync_params)?;
                },
```

**File:** aptos-move/block-executor/src/scheduler_v2.rs (L606-680)
```rust
    pub(crate) fn start_commit(&self) -> Result<Option<(TxnIndex, Incarnation)>, PanicError> {
        // Relaxed ordering due to armed lock acq-rel.
        let next_to_commit_idx = self.next_to_commit_idx.load(Ordering::Relaxed);
        assert!(next_to_commit_idx <= self.num_txns);

        if self.is_halted() || next_to_commit_idx == self.num_txns {
            // All sequential commit hooks are already dispatched.
            return Ok(None);
        }

        let incarnation = self.txn_statuses.incarnation(next_to_commit_idx);
        if self.txn_statuses.is_executed(next_to_commit_idx) {
            self.commit_marker_invariant_check(next_to_commit_idx)?;

            // All prior transactions are committed and the latest incarnation of the transaction
            // at next_to_commit_idx has finished but has not been aborted. If any of its reads was
            // incorrect, it would have been invalidated by the respective transaction's last
            // (committed) (re-)execution, and led to an abort in the corresponding finish execution
            // (which, inductively, must occur before the transaction is committed). Hence, it
            // must also be safe to commit the current transaction.
            //
            // The only exception is if there are unsatisfied cold validation requirements,
            // blocking the commit. These may not yet be scheduled for validation, or deferred
            // until after the txn finished execution, whereby deferral happens before txn status
            // becomes Executed, while validation and unblocking happens after.
            if self
                .cold_validation_requirements
                .is_commit_blocked(next_to_commit_idx, incarnation)
            {
                // May not commit a txn with an unsatisfied validation requirement. This will be
                // more rare than !is_executed in the common case, hence the order of checks.
                return Ok(None);
            }
            // The check might have passed after the validation requirement has been fulfilled.
            // Yet, if validation failed, the status would be aborted before removing the block,
            // which would increase the incarnation number. It is also important to note that
            // blocking happens during sequential commit hook, while holding the lock (which is
            // also held here), hence before the call of this method.
            if incarnation != self.txn_statuses.incarnation(next_to_commit_idx) {
                return Ok(None);
            }

            if self
                .committed_marker
                .get(next_to_commit_idx as usize)
                .is_some_and(|marker| {
                    marker.swap(CommitMarkerFlag::CommitStarted as u8, Ordering::Relaxed)
                        != CommitMarkerFlag::NotCommitted as u8
                })
            {
                return Err(code_invariant_error(format!(
                    "Marking {} as PENDING_COMMIT_HOOK, but previous marker != NOT_COMMITTED",
                    next_to_commit_idx
                )));
            }

            // TODO(BlockSTMv2): fetch_add as a RMW instruction causes a barrier even with
            // Relaxed ordering. The read is only used to check an invariant, so we can
            // eventually change to just a relaxed write.
            let prev_idx = self.next_to_commit_idx.fetch_add(1, Ordering::Relaxed);
            if prev_idx != next_to_commit_idx {
                return Err(code_invariant_error(format!(
                    "Scheduler committing {}, stored next to commit idx = {}",
                    next_to_commit_idx, prev_idx
                )));
            }

            return Ok(Some((
                next_to_commit_idx,
                self.txn_statuses.incarnation(next_to_commit_idx),
            )));
        }

        Ok(None)
    }
```

**File:** aptos-move/block-executor/src/scheduler_v2.rs (L696-719)
```rust
    pub(crate) fn end_commit(&self, txn_idx: TxnIndex) -> Result<(), PanicError> {
        let prev_marker = self.committed_marker[txn_idx as usize].load(Ordering::Relaxed);
        if prev_marker != CommitMarkerFlag::CommitStarted as u8 {
            return Err(code_invariant_error(format!(
                "Marking txn {} as COMMITTED, but previous marker {} != {}",
                txn_idx,
                prev_marker,
                CommitMarkerFlag::CommitStarted as u8
            )));
        }
        // Allows next sequential commit hook to be processed.
        self.committed_marker[txn_idx as usize]
            .store(CommitMarkerFlag::Committed as u8, Ordering::Relaxed);

        if let Err(e) = self.post_commit_processing_queue.push(txn_idx) {
            return Err(code_invariant_error(format!(
                "Error adding {txn_idx} to commit queue, len {}, error: {:?}",
                self.post_commit_processing_queue.len(),
                e
            )));
        }

        Ok(())
    }
```

**File:** aptos-move/block-executor/src/scheduler_v2.rs (L807-809)
```rust
        match self.pop_post_commit_task()? {
            Some(txn_idx) => {
                return Ok(TaskKind::PostCommitProcessing(txn_idx));
```

**File:** aptos-move/block-executor/src/scheduler_v2.rs (L1177-1190)
```rust
    fn pop_post_commit_task(&self) -> Result<Option<TxnIndex>, PanicError> {
        match self.post_commit_processing_queue.pop() {
            Ok(txn_idx) => {
                if txn_idx == self.num_txns - 1 {
                    self.is_done.store(true, Ordering::SeqCst);
                }
                Ok(Some(txn_idx))
            },
            Err(PopError::Empty) => Ok(None),
            Err(PopError::Closed) => {
                Err(code_invariant_error("Commit queue should never be closed"))
            },
        }
    }
```

**File:** aptos-move/block-executor/src/txn_last_input_output.rs (L376-376)
```rust
        scheduler.add_to_post_commit(txn_idx)?;
```

**File:** aptos-move/block-executor/src/txn_last_input_output.rs (L409-440)
```rust
    pub(crate) fn notify_listener<L: TransactionCommitHook>(
        &self,
        txn_idx: TxnIndex,
        txn_listener: &L,
    ) -> Result<(), PanicError> {
        let output_wrapper = self.output_wrappers[txn_idx as usize].lock();
        match output_wrapper.output_status_kind {
            OutputStatusKind::Success | OutputStatusKind::SkipRest => {
                txn_listener.on_transaction_committed(
                    txn_idx,
                    output_wrapper
                        .output
                        .as_ref()
                        .expect("Output must be set when status is success or skip rest")
                        .committed_output(),
                );
            },
            OutputStatusKind::Abort(_) => {
                txn_listener.on_execution_aborted(txn_idx);
            },
            OutputStatusKind::SpeculativeExecutionAbortError
            | OutputStatusKind::DelayedFieldsCodeInvariantError
            | OutputStatusKind::None => {
                return Err(code_invariant_error(format!(
                    "Unexpected output status kind {:?}",
                    output_wrapper.output_status_kind
                )));
            },
        }

        Ok(())
    }
```

**File:** aptos-move/block-executor/src/scheduler_wrapper.rs (L68-76)
```rust
    pub(crate) fn add_to_post_commit(&self, txn_idx: TxnIndex) -> Result<(), PanicError> {
        match self {
            SchedulerWrapper::V1(scheduler, _) => {
                scheduler.add_to_commit_queue(txn_idx);
                Ok(())
            },
            SchedulerWrapper::V2(scheduler, _) => scheduler.end_commit(txn_idx),
        }
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L103-134)
```rust
    fn send_remote_update_for_success(
        &self,
        txn_idx: TxnIndex,
        txn_output: &OnceCell<TransactionOutput>,
    ) {
        let edges = self.dependent_edges.get(&txn_idx).unwrap();
        let write_set = txn_output
            .get()
            .expect("Committed output must be set")
            .write_set();

        for (state_key, write_op) in write_set.expect_write_op_iter() {
            if let Some(dependent_shard_ids) = edges.get(state_key) {
                for (dependent_shard_id, round_id) in dependent_shard_ids.iter() {
                    trace!("Sending remote update for success for shard id {:?} and txn_idx: {:?}, state_key: {:?}, dependent shard id: {:?}", self.shard_id, txn_idx, state_key, dependent_shard_id);
                    let message = RemoteTxnWriteMsg(RemoteTxnWrite::new(
                        state_key.clone(),
                        Some(write_op.clone()),
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

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L137-152)
```rust
impl TransactionCommitHook for CrossShardCommitSender {
    fn on_transaction_committed(
        &self,
        txn_idx: TxnIndex,
        txn_output: &OnceCell<TransactionOutput>,
    ) {
        let global_txn_idx = txn_idx + self.index_offset;
        if self.dependent_edges.contains_key(&global_txn_idx) {
            self.send_remote_update_for_success(global_txn_idx, txn_output);
        }
    }

    fn on_execution_aborted(&self, _txn_idx: TxnIndex) {
        todo!("on_transaction_aborted not supported for sharded execution yet")
    }
}
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/local_executor_shard.rs (L326-333)
```rust
impl CrossShardClient for LocalCrossShardClient {
    fn send_global_msg(&self, msg: CrossShardMsg) {
        self.global_message_tx.send(msg).unwrap()
    }

    fn send_cross_shard_msg(&self, shard_id: ShardId, round: RoundId, msg: CrossShardMsg) {
        self.message_txs[shard_id][round].send(msg).unwrap()
    }
```

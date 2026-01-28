# Audit Report

## Title
Transaction Commit Hooks Invoked Out-of-Order During Parallel PostCommitProcessing in BlockSTM V2

## Summary
In BlockSTM V2 parallel execution, transaction commit hooks (`on_transaction_committed`) are invoked during the parallel PostCommitProcessing phase without ordering guarantees. This allows hooks for transaction i+1 to fire before hooks for transaction i, causing cross-shard state inconsistencies in sharded execution scenarios and potentially leading to non-deterministic state roots across validators.

## Finding Description

BlockSTM V2 implements a two-phase commit process where commit hooks are invoked AFTER sequential commit, during parallel PostCommitProcessing:

**Phase 1 - Sequential Commit (with lock held):**

Workers acquire `queueing_commits_lock` and call `prepare_and_queue_commit_ready_txn` which validates delayed fields, publishes modules, and adds transactions to the post-commit queue in sequential order. [1](#0-0) 

The sequential commit calls `last_input_output.commit()` which adds the transaction to the post-commit processing queue: [2](#0-1) 

This invokes `scheduler.end_commit()` which pushes to the concurrent queue: [3](#0-2) 

**Phase 2 - Parallel PostCommitProcessing (NO ordering guarantees):**

Multiple workers concurrently pop transactions from `post_commit_processing_queue`: [4](#0-3) 

Workers execute PostCommitProcessing tasks by calling `materialize_txn_commit` followed by `record_finalized_output`: [5](#0-4) 

The `materialize_txn_commit` function performs heavy work including group finalization, materialization, serialization, and optional type checking: [6](#0-5) 

After materialization completes, `record_finalized_output` invokes the transaction commit hook: [7](#0-6) 

**The Race Condition:**

Since materialization work has variable timing (simple vs. complex transactions), transaction i+1 can complete PostCommitProcessing before transaction i, causing its commit hook to fire first despite i committing earlier in the sequential phase.

**Impact on CrossShardCommitSender:**

The `CrossShardCommitSender` hook implementation sends cross-shard state updates when transactions with dependent edges commit: [8](#0-7) 

When dependent shards receive these messages, they call `set_value` on the `RemoteStateValue`: [9](#0-8) 

The `RemoteStateValue.set_value` method unconditionally overwrites the stored value with no transaction index tracking or ordering checks: [10](#0-9) 

**Consensus Impact:**

If transactions i and i+1 both write to StateKey K with cross-shard dependencies:
1. Sequential commit: i commits first (K=old_value), then i+1 commits (K=new_value)
2. Parallel PostCommitProcessing: Thread scheduling causes i+1's hook to fire first
3. Remote shard receives: K=new_value, then K=old_value
4. Remote shard stores: K=old_value (incorrect!)
5. Dependent transactions read the wrong value

Since thread scheduling is non-deterministic, different validators could observe different orderings, leading to different state roots for the same block - a critical consensus violation.

## Impact Explanation

This violates **Invariant 1: Deterministic Execution** as defined in the Aptos Bug Bounty program under "Consensus/Safety Violations (Critical)". All validators must produce identical state roots for identical blocks. The non-deterministic hook invocation ordering in parallel PostCommitProcessing means different validators could observe different cross-shard state values based on their thread scheduling, leading to:

1. **State Divergence**: Different validators compute different state roots for the same block
2. **Consensus Failure**: Validators cannot reach agreement on block commits
3. **Network Partition Risk**: Persistent state inconsistencies requiring manual intervention

While this doesn't directly enable fund theft, it represents a fundamental consensus protocol violation that could halt the network or require emergency intervention.

**Severity: HIGH** (potentially CRITICAL if sharded execution is actively deployed on mainnet) - This meets the "Consensus/Safety Violations" category, as it can cause different validators to commit different blocks due to non-deterministic execution.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH** (conditional on sharded execution being enabled)

The race condition occurs naturally during normal BlockSTM V2 operation when sharded execution is active:

- **No attacker action required**: Happens automatically due to thread scheduling
- **Depends only on timing**: Relative speed of `materialize_txn_commit` operations
- **Higher with heterogeneous transactions**: Simple transactions complete faster than complex ones
- **Guaranteed eventual occurrence**: In high-throughput scenarios with sufficient transaction diversity

**Prerequisites for exploitation:**
1. Sharded block execution must be enabled (infrastructure exists in production code)
2. Block partitioner creates sub-blocks with cross-shard dependencies
3. Multiple transactions in same shard write to same StateKey with dependent edges
4. Thread scheduling causes out-of-order PostCommitProcessing completion

The sharded execution infrastructure is production-ready and integrated into the main execution path: [11](#0-10) [12](#0-11) 

## Recommendation

**Solution: Invoke commit hooks during the sequential commit phase, before adding to PostCommitProcessing queue.**

Modify `prepare_and_queue_commit_ready_txn` to invoke the commit hook BEFORE calling `last_input_output.commit()`:

```rust
// After publishing modules (line 1053)
if side_effect_at_commit {
    scheduler.wake_dependencies_and_decrease_validation_idx(txn_idx)?;
}

// ADD: Invoke commit hook during sequential phase
if let Some(txn_commit_listener) = &self.transaction_commit_hook {
    last_input_output.notify_listener(txn_idx, txn_commit_listener)?;
}

// Then add to post-commit queue
last_input_output.commit(
    txn_idx,
    num_txns,
    num_workers,
    block_limit_processor,
    shared_sync_params.maybe_block_epilogue_txn_idx,
    &scheduler,
)
```

Remove the hook invocation from `record_finalized_output` to avoid duplicate calls.

**Alternative Solution: Add transaction index tracking to RemoteStateValue**

Modify `RemoteStateValue` to track transaction indices and reject out-of-order updates:

```rust
pub struct RemoteStateValue {
    value_condition: Arc<(Mutex<RemoteValueStatus>, Condvar)>,
    txn_idx: AtomicU64, // Track which transaction's value is stored
}

pub fn set_value(&self, txn_idx: TxnIndex, value: Option<StateValue>) {
    let (lock, cvar) = &*self.value_condition;
    let mut status = lock.lock().unwrap();
    
    // Only update if this is from a later transaction
    let current_idx = self.txn_idx.load(Ordering::Acquire);
    if txn_idx >= current_idx {
        *status = RemoteValueStatus::Ready(value);
        self.txn_idx.store(txn_idx, Ordering::Release);
        cvar.notify_all();
    }
}
```

## Proof of Concept

The following demonstrates the race condition conceptually (actual PoC would require sharded execution setup):

```rust
// Scenario: Two transactions in Shard A write to same key K
// Transaction 5: writes K = 100, has dependent in Shard B
// Transaction 6: writes K = 200, has dependent in Shard B

// Sequential commit phase (in order, with lock):
// - commit(5): adds txn 5 to post_commit_processing_queue
// - commit(6): adds txn 6 to post_commit_processing_queue

// Parallel PostCommitProcessing phase (no ordering):
// - Worker B: pop() → gets txn 6
// - Worker A: pop() → gets txn 5
// - Worker B: materialize_txn_commit(6) → fast (simple transaction)
// - Worker B: record_finalized_output(6) → on_transaction_committed(6)
// - Worker B: CrossShardCommitSender sends K=200 to Shard B
// - Shard B: RemoteStateValue.set_value(K, 200)
// - Worker A: materialize_txn_commit(5) → slow (complex transaction)
// - Worker A: record_finalized_output(5) → on_transaction_committed(5)
// - Worker A: CrossShardCommitSender sends K=100 to Shard B
// - Shard B: RemoteStateValue.set_value(K, 100) ← OVERWRITES CORRECT VALUE

// Result: Shard B has K=100 (incorrect) instead of K=200 (correct)
// Different validators may observe different orderings → consensus failure
```

**Notes:**
- This vulnerability affects the sharded block execution infrastructure within Aptos Core
- The race condition is inherent to the design of parallel PostCommitProcessing with hooks invoked after materialization
- The severity depends on whether sharded execution is currently active on mainnet validators
- The fix requires either sequential hook invocation or versioned cross-shard state updates
- No external attacker action is required; the vulnerability manifests naturally during normal operation with sufficient transaction throughput and complexity variance

### Citations

**File:** aptos-move/block-executor/src/executor.rs (L1178-1232)
```rust
        let finalized_groups = groups_to_finalize!(last_input_output, txn_idx)
            .map(|((group_key, metadata_op), is_read_needing_exchange)| {
                let (finalized_group, group_size) = shared_sync_params
                    .versioned_cache
                    .group_data()
                    .finalize_group(&group_key, txn_idx)?;

                map_finalized_group::<T>(
                    group_key,
                    finalized_group,
                    group_size,
                    metadata_op,
                    is_read_needing_exchange,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let materialized_finalized_groups =
            map_id_to_values_in_group_writes(finalized_groups, &latest_view)?;

        let serialized_groups =
            serialize_groups::<T>(materialized_finalized_groups).map_err(|e| {
                code_invariant_error(format!("Panic error in serializing groups {e:?}"))
            })?;

        let resource_write_set = last_input_output.resource_write_set(txn_idx)?;
        let resource_writes_to_materialize = resource_writes_to_materialize!(
            resource_write_set,
            last_input_output,
            last_input_output,
            txn_idx
        )?;
        let materialized_resource_write_set =
            map_id_to_values_in_write_set(resource_writes_to_materialize, &latest_view)?;

        let events = last_input_output.events(txn_idx);
        let materialized_events = map_id_to_values_events(events, &latest_view)?;
        let aggregator_v1_delta_writes = Self::materialize_aggregator_v1_delta_writes(
            txn_idx,
            last_input_output,
            shared_sync_params.versioned_cache,
            shared_sync_params.base_view,
        );

        // This call finalizes the output and may not be concurrent with any other
        // accesses to the output (e.g. querying the write-set, events, etc), as
        // these read accesses are not synchronized and assumed to have terminated.
        let trace = last_input_output.record_materialized_txn_output(
            txn_idx,
            aggregator_v1_delta_writes,
            materialized_resource_write_set
                .into_iter()
                .chain(serialized_groups)
                .collect(),
            materialized_events,
        )?;
```

**File:** aptos-move/block-executor/src/executor.rs (L1277-1278)
```rust
        if let Some(txn_commit_listener) = &self.transaction_commit_hook {
            last_input_output.notify_listener(txn_idx, txn_commit_listener)?;
```

**File:** aptos-move/block-executor/src/executor.rs (L1455-1471)
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
```

**File:** aptos-move/block-executor/src/executor.rs (L1507-1514)
```rust
                TaskKind::PostCommitProcessing(txn_idx) => {
                    self.materialize_txn_commit(
                        txn_idx,
                        scheduler_wrapper,
                        environment,
                        shared_sync_params,
                    )?;
                    self.record_finalized_output(txn_idx, txn_idx, shared_sync_params)?;
```

**File:** aptos-move/block-executor/src/txn_last_input_output.rs (L376-376)
```rust
        scheduler.add_to_post_commit(txn_idx)?;
```

**File:** aptos-move/block-executor/src/scheduler_v2.rs (L710-716)
```rust
        if let Err(e) = self.post_commit_processing_queue.push(txn_idx) {
            return Err(code_invariant_error(format!(
                "Error adding {txn_idx} to commit queue, len {}, error: {:?}",
                self.post_commit_processing_queue.len(),
                e
            )));
        }
```

**File:** aptos-move/block-executor/src/scheduler_v2.rs (L1177-1189)
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
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L137-147)
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
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_state_view.rs (L49-56)
```rust
    pub fn set_value(&self, state_key: &StateKey, state_value: Option<StateValue>) {
        self.cross_shard_data
            .get(state_key)
            .unwrap()
            .set_value(state_value);
        // uncomment the following line to debug waiting count
        // trace!("waiting count for shard id {} is {}", self.shard_id, self.waiting_count());
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/remote_state_value.rs (L22-26)
```rust
    pub fn set_value(&self, value: Option<StateValue>) {
        let (lock, cvar) = &*self.value_condition;
        let mut status = lock.lock().unwrap();
        *status = RemoteValueStatus::Ready(value);
        cvar.notify_all();
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L68-89)
```rust
        let out = match transactions {
            ExecutableTransactions::Unsharded(txns) => {
                Self::by_transaction_execution_unsharded::<V>(
                    executor,
                    txns,
                    auxiliary_infos,
                    parent_state,
                    state_view,
                    onchain_config,
                    transaction_slice_metadata,
                )?
            },
            // TODO: Execution with auxiliary info is yet to be supported properly here for sharded transactions
            ExecutableTransactions::Sharded(txns) => Self::by_transaction_execution_sharded::<V>(
                txns,
                auxiliary_infos,
                parent_state,
                state_view,
                onchain_config,
                transaction_slice_metadata.append_state_checkpoint_to_block(),
            )?,
        };
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L256-275)
```rust
    fn execute_block_sharded<V: VMBlockExecutor>(
        partitioned_txns: PartitionedTransactions,
        state_view: Arc<CachedStateView>,
        onchain_config: BlockExecutorConfigFromOnchain,
    ) -> Result<Vec<TransactionOutput>> {
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

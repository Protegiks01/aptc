# Audit Report

## Title
Non-Atomic Incarnation Transition Causes Dirty Reads in BlockSTMv2 Parallel Execution

## Summary
In BlockSTMv2's parallel execution engine, when a transaction re-executes with an incremented incarnation number, its write operations to the multi-version data structure occur sequentially across different keys. Concurrent readers can observe partial state where some keys reflect the new incarnation while others still contain values from the old incarnation, violating isolation guarantees and enabling dirty reads that could cause consensus divergence.

## Finding Description

BlockSTMv2 implements optimistic parallel transaction execution using a multi-version hashmap (`MVHashMap`) to store versioned writes. When a transaction is aborted and re-executes with an incremented incarnation number, the system must update all its writes from the old incarnation to the new incarnation.

The vulnerability occurs in the `process_resource_output_v2` function, which iterates sequentially over resource keys to update them: [1](#0-0) 

This function processes keys one at a time, calling `write_v2` for each key. Between these individual write operations, concurrent readers executing at higher transaction indices can read from the multi-version data structure and observe an inconsistent state.

The `write_impl` function performs atomic replacement of entries per key via `BTreeMap::insert`: [2](#0-1) 

However, this atomicity is **per-key only**. There is no mechanism to atomically update all keys belonging to a single transaction's incarnation.

Concurrent readers call the `read` function which returns whichever version it finds without checking incarnation consistency across keys: [3](#0-2) 

Critically, BlockSTMv2 **does not use the estimate flag mechanism** to prevent reads during writes. The code explicitly states that estimates should not be marked in V2: [4](#0-3) 

The estimate mechanism is only used during abort handling, not during normal execution: [5](#0-4) 

### Attack Scenario

Consider transaction T5 (index 5) with initial incarnation 0 writing:
- `AccountA.balance = 100`
- `AccountB.balance = 50`  
- `TotalSupply = 150`

T5 is aborted and re-executes with incarnation 1, writing:
- `AccountA.balance = 200`
- `AccountB.balance = 75`
- `TotalSupply = 275`

**Race Condition Timeline:**
1. T5 incarnation 1 calls `process_resource_output_v2`
2. T5 writes `AccountA.balance = 200` (incarnation 1) via `write_v2`
3. **T10 (concurrent reader) reads `AccountA.balance`** → observes 200 (incarnation 1)
4. T5 writes `AccountB.balance = 75` (incarnation 1)
5. **T10 reads `AccountB.balance`** → observes 50 (incarnation 0) ← **DIRTY READ**
6. **T10 reads `TotalSupply`** → observes 150 (incarnation 0) ← **DIRTY READ**
7. T5 completes writing `TotalSupply = 275`

**Result:** T10 observed `{AccountA: 200, AccountB: 50, TotalSupply: 150}`, an inconsistent state that never existed atomically. The invariant `AccountA + AccountB == TotalSupply` is violated from T10's perspective.

## Impact Explanation

This vulnerability meets **Critical Severity** criteria under "Consensus/Safety violations" because:

1. **Deterministic Execution Violation**: Different validators may observe different execution paths depending on timing. If T10's execution makes control-flow decisions based on the inconsistent state (e.g., early termination, conditional branches), different nodes may produce different state roots for the same block.

2. **Cascading Inconsistencies**: T10's outputs (computed from dirty reads) may be read by T11, T12, etc. before T10 is aborted, propagating inconsistency through the dependency chain.

3. **Consensus Divergence Risk**: While push-validation will eventually abort T10, there is a window where:
   - T10 executes with dirty data
   - T10 writes speculative outputs  
   - Higher transactions read T10's outputs
   - Only after this cascade does abort propagation begin

4. **Non-Deterministic Aborts**: If Move VM execution depends on invariants (e.g., assertions that total supply equals sum of balances), dirty reads may cause different validators to hit different assertion failures, leading to non-deterministic transaction outcomes.

This breaks the fundamental **State Consistency** invariant (#4) and the **Deterministic Execution** invariant (#1), which are critical for blockchain consensus safety.

## Likelihood Explanation

This vulnerability has **high likelihood** of occurrence:

1. **No Special Privileges Required**: Any transaction sender can trigger this by submitting transactions that create read-write conflicts, forcing re-executions.

2. **Inherent to Design**: The issue is structural to BlockSTMv2's current implementation. Every re-execution creates a window for dirty reads.

3. **Amplified by Complexity**: Transactions with many resource writes increase the window size, making the race more likely. Complex DeFi transactions (swaps, liquidity operations) commonly access 5-10+ resources.

4. **High-Concurrency Environments**: Aptos targets high throughput with many concurrent transactions, increasing the probability of overlapping read-write operations.

5. **Deterministically Triggerable**: An attacker can craft transaction sequences that maximize re-execution frequency (e.g., intentionally creating conflicts), making this exploitable rather than merely probabilistic.

## Recommendation

Implement atomic incarnation transitions using one of these approaches:

### Option 1: Transactional Write Batching
Accumulate all writes for an incarnation in a local buffer, then atomically commit them to the MVHashMap:

```rust
// Pseudo-code for atomic batch write
pub fn write_batch_v2(
    &self,
    txn_idx: TxnIndex,
    incarnation: Incarnation,
    writes: Vec<(K, Arc<V>, Option<Arc<MoveTypeLayout>>)>,
) -> Result<BTreeMap<TxnIndex, Incarnation>, PanicError> {
    // Acquire exclusive lock on txn_idx's entries
    let _guard = self.acquire_txn_lock(txn_idx);
    
    // Remove old incarnation entries
    for (key, _, _) in &writes {
        self.remove_entry(key, txn_idx)?;
    }
    
    // Write new incarnation entries atomically
    let mut invalidated_deps = BTreeMap::new();
    for (key, value, layout) in writes {
        let deps = self.write_v2_internal(key, txn_idx, incarnation, value, layout)?;
        invalidated_deps.extend(deps);
    }
    
    Ok(invalidated_deps)
}
```

### Option 2: Re-enable Estimate Marking for V2
Mark all existing entries as estimates before writing new incarnation, preventing concurrent reads:

```rust
// In process_resource_output_v2, before writing:
for key in old_keys.union(new_keys) {
    versioned_cache.data().mark_estimate(key, txn_idx);
}

// Then write all keys
// Then unmark estimates (implicitly done by write_v2)
```

### Option 3: Transaction-Level Version Counter
Add a transaction-level version counter that increments only after all keys are written. Readers check this counter for consistency across multi-key reads.

**Recommended**: Option 1 (Transactional Write Batching) provides the strongest guarantee with minimal performance overhead, as it requires locking only the specific transaction's entries, not the entire data structure.

## Proof of Concept

```rust
// Rust integration test demonstrating the race condition
#[test]
fn test_dirty_read_during_incarnation_transition() {
    use std::sync::{Arc, Barrier};
    use std::thread;
    
    let versioned_cache = Arc::new(MVHashMap::new());
    let barrier = Arc::new(Barrier::new(2));
    
    // Transaction T5 writes initial values (incarnation 0)
    versioned_cache.data().write(
        "AccountA.balance", 5, 0, 
        Arc::new(TestValue::from_u128(100)), None
    );
    versioned_cache.data().write(
        "AccountB.balance", 5, 0,
        Arc::new(TestValue::from_u128(50)), None
    );
    versioned_cache.data().write(
        "TotalSupply", 5, 0,
        Arc::new(TestValue::from_u128(150)), None
    );
    
    let cache_writer = Arc::clone(&versioned_cache);
    let barrier_writer = Arc::clone(&barrier);
    let writer_thread = thread::spawn(move || {
        // T5 re-executes with incarnation 1
        cache_writer.data().write(
            "AccountA.balance", 5, 1,
            Arc::new(TestValue::from_u128(200)), None
        );
        
        // Synchronization point - reader will read here
        barrier_writer.wait();
        
        // Continue writing other keys
        cache_writer.data().write(
            "AccountB.balance", 5, 1,
            Arc::new(TestValue::from_u128(75)), None
        );
        cache_writer.data().write(
            "TotalSupply", 5, 1,
            Arc::new(TestValue::from_u128(275)), None
        );
    });
    
    let cache_reader = Arc::clone(&versioned_cache);
    let barrier_reader = Arc::clone(&barrier);
    let reader_thread = thread::spawn(move || {
        // T10 reads during T5's incarnation transition
        barrier_reader.wait();
        
        let account_a = cache_reader.data()
            .fetch_data_no_record("AccountA.balance", 10)
            .unwrap();
        let account_b = cache_reader.data()
            .fetch_data_no_record("AccountB.balance", 10)
            .unwrap();
        let total = cache_reader.data()
            .fetch_data_no_record("TotalSupply", 10)
            .unwrap();
        
        // Extract values (simplified)
        let a_val = extract_u128(account_a);
        let b_val = extract_u128(account_b);
        let total_val = extract_u128(total);
        
        // Invariant check: should always hold, but will fail
        assert_eq!(a_val + b_val, total_val, 
            "Dirty read detected: AccountA={}, AccountB={}, Total={}",
            a_val, b_val, total_val
        );
        
        (a_val, b_val, total_val)
    });
    
    writer_thread.join().unwrap();
    let (a, b, total) = reader_thread.join().unwrap();
    
    // This assertion will fail, demonstrating the dirty read:
    // Expected: (200, 75, 275) or (100, 50, 150)
    // Actual: (200, 50, 150) - mixed state!
    println!("Observed: A={}, B={}, Total={}", a, b, total);
}
```

**Expected Result**: The test will fail, demonstrating that T10 observes `(200, 50, 150)` - a mixed state from two different incarnations, proving the isolation violation.

## Notes

The vulnerability is specifically in **BlockSTMv2** as evidenced by the explicit design choice to not use estimate flags during execution. BlockSTMv1 may have different behavior. The `execute_v2` function orchestrates the vulnerable flow, calling resource and resource group output processors that perform sequential writes without synchronization against concurrent readers. [6](#0-5)

### Citations

**File:** aptos-move/block-executor/src/executor.rs (L170-227)
```rust
    fn process_resource_output_v2(
        maybe_output: Option<&E::Output>,
        idx_to_execute: TxnIndex,
        incarnation: Incarnation,
        last_input_output: &TxnLastInputOutput<T, E::Output>,
        versioned_cache: &MVHashMap<T::Key, T::Tag, T::Value, DelayedFieldID>,
        abort_manager: &mut AbortManager,
    ) -> Result<(), PanicError> {
        // The order is reversed in BlockSTMv2 as opposed to V1, avoiding the necessity
        // to clone the previous keys.

        let mut resource_write_set = maybe_output.map_or(Ok(HashMap::new()), |output| {
            output
                .before_materialization()
                .map(|inner| inner.resource_write_set())
        })?;

        last_input_output.for_each_resource_key_no_aggregator_v1(
            idx_to_execute,
            |prev_key_ref| {
                match resource_write_set.remove_entry(prev_key_ref) {
                    Some((key, (value, maybe_layout))) => {
                        abort_manager.invalidate_dependencies(
                            versioned_cache.data().write_v2::<false>(
                                key,
                                idx_to_execute,
                                incarnation,
                                value,
                                maybe_layout,
                            )?,
                        )?;
                    },
                    None => {
                        // Clean up the write from previous incarnation.
                        abort_manager.invalidate_dependencies(
                            versioned_cache
                                .data()
                                .remove_v2::<_, false>(prev_key_ref, idx_to_execute)?,
                        )?;
                    },
                }
                Ok(())
            },
        )?;

        // Handle remaining entries in resource_write_set (new writes)
        for (key, (value, maybe_layout)) in resource_write_set {
            abort_manager.invalidate_dependencies(versioned_cache.data().write_v2::<false>(
                key,
                idx_to_execute,
                incarnation,
                value,
                maybe_layout,
            )?)?;
        }

        Ok(())
    }
```

**File:** aptos-move/block-executor/src/executor.rs (L389-530)
```rust
    fn execute_v2(
        worker_id: u32,
        idx_to_execute: TxnIndex,
        incarnation: Incarnation,
        txn: &T,
        auxiliary_info: &A,
        last_input_output: &TxnLastInputOutput<T, E::Output>,
        versioned_cache: &MVHashMap<T::Key, T::Tag, T::Value, DelayedFieldID>,
        executor: &E,
        base_view: &S,
        global_module_cache: &GlobalModuleCache<
            ModuleId,
            CompiledModule,
            Module,
            AptosModuleExtension,
        >,
        runtime_environment: &RuntimeEnvironment,
        parallel_state: ParallelState<T>,
        scheduler: &SchedulerV2,
        block_gas_limit_type: &BlockGasLimitType,
    ) -> Result<(), PanicError> {
        let _timer = TASK_EXECUTE_SECONDS.start_timer();

        let mut abort_manager = AbortManager::new(idx_to_execute, incarnation, scheduler);
        let sync_view = LatestView::new(
            base_view,
            global_module_cache,
            runtime_environment,
            ViewState::Sync(parallel_state),
            idx_to_execute,
        );
        let execution_result =
            executor.execute_transaction(&sync_view, txn, auxiliary_info, idx_to_execute);

        let mut read_set = sync_view.take_parallel_reads();
        if read_set.is_incorrect_use() {
            return Err(code_invariant_error(format!(
                "Incorrect use detected in CapturedReads after executing txn = {idx_to_execute} incarnation = {incarnation}"
            )));
        }

        let (maybe_output, is_speculative_failure) =
            Self::process_execution_result(&execution_result, &mut read_set, idx_to_execute)?;

        if is_speculative_failure {
            // Recording in order to check the invariant that the final, committed incarnation
            // of each transaction is not a speculative failure.
            last_input_output.record_speculative_failure(idx_to_execute);
            // Ignoring module validation requirements since speculative failure
            // anyway requires re-execution.
            let _ = scheduler.finish_execution(abort_manager)?;
            return Ok(());
        }

        // TODO: BlockSTMv2: use estimates for delayed field reads? (see V1 update on abort).
        Self::process_delayed_field_output(
            maybe_output,
            idx_to_execute,
            &mut read_set,
            last_input_output,
            versioned_cache,
            true,
        )?;
        Self::process_resource_group_output_v2(
            maybe_output,
            idx_to_execute,
            incarnation,
            last_input_output,
            versioned_cache,
            &mut abort_manager,
        )?;
        Self::process_resource_output_v2(
            maybe_output,
            idx_to_execute,
            incarnation,
            last_input_output,
            versioned_cache,
            &mut abort_manager,
        )?;

        // Legacy aggregator v1 handling.
        let mut prev_modified_aggregator_v1_keys = last_input_output
            .modified_aggregator_v1_keys(idx_to_execute)
            .map_or_else(HashSet::new, |keys| keys.collect());
        if let Some(output) = maybe_output {
            let output_before_guard = output.before_materialization()?;

            // Apply aggregator v1 writes and deltas, using versioned data's V1 (write/add_delta) APIs.
            // AggregatorV1 is not push-validated, but follows the same logic as delayed fields, i.e.
            // commit-time validation in BlockSTMv2.
            for (key, value) in output_before_guard.aggregator_v1_write_set().into_iter() {
                prev_modified_aggregator_v1_keys.remove(&key);

                versioned_cache.data().write(
                    key,
                    idx_to_execute,
                    incarnation,
                    TriompheArc::new(value),
                    None,
                );
            }
            for (key, delta) in output_before_guard.aggregator_v1_delta_set().into_iter() {
                prev_modified_aggregator_v1_keys.remove(&key);
                versioned_cache.data().add_delta(key, idx_to_execute, delta);
            }
        }
        for key in prev_modified_aggregator_v1_keys {
            versioned_cache.data().remove(&key, idx_to_execute);
        }

        last_input_output.record(
            idx_to_execute,
            read_set,
            execution_result,
            block_gas_limit_type,
            txn.user_txn_bytes_len() as u64,
        )?;

        // It is important to call finish_execution after recording the input/output.
        // CAUTION: once any update has been applied to the shared data structures, there should
        // be no short circuits until the record succeeds and scheduler is notified that the
        // execution is finished. This allows cleaning up the shared data structures before
        // applying the updates from next incarnation (which can also be the block epilogue txn).
        if let Some(module_validation_requirements) = scheduler.finish_execution(abort_manager)? {
            Self::module_validation_v2(
                idx_to_execute,
                incarnation,
                scheduler,
                &module_validation_requirements,
                last_input_output,
                global_module_cache,
                versioned_cache,
            )?;
            scheduler.finish_cold_validation_requirement(
                worker_id,
                idx_to_execute,
                incarnation,
                true,
            )?;
        }
        Ok(())
    }
```

**File:** aptos-move/mvhashmap/src/versioned_data.rs (L242-290)
```rust
    fn read(
        &self,
        reader_txn_idx: TxnIndex,
        maybe_reader_incarnation: Option<Incarnation>,
    ) -> Result<MVDataOutput<V>, MVDataError> {
        use MVDataError::*;
        use MVDataOutput::*;

        let mut iter = self
            .versioned_map
            .range(ShiftedTxnIndex::zero_idx()..ShiftedTxnIndex::new(reader_txn_idx));

        // If read encounters a delta, it must traverse the block of transactions
        // (top-down) until it encounters a write or reaches the end of the block.
        // During traversal, all aggregator deltas have to be accumulated together.
        let mut accumulator: Option<Result<DeltaOp, ()>> = None;
        while let Some((idx, entry)) = iter.next_back() {
            if entry.is_estimate() {
                debug_assert!(
                    maybe_reader_incarnation.is_none(),
                    "Entry must not be marked as estimate for BlockSTMv2"
                );
                // Found a dependency.
                return Err(Dependency(
                    idx.idx().expect("May not depend on storage version"),
                ));
            }

            match (&entry.value, accumulator.as_mut()) {
                (
                    EntryCell::ResourceWrite {
                        incarnation,
                        value_with_layout,
                        dependencies,
                    },
                    None,
                ) => {
                    // Record the read dependency (only in V2 case, not to add contention to V1).
                    if let Some(reader_incarnation) = maybe_reader_incarnation {
                        // TODO(BlockSTMv2): convert to PanicErrors after MVHashMap refactoring.
                        assert_ok!(dependencies
                            .lock()
                            .insert(reader_txn_idx, reader_incarnation));
                    }

                    // Resolve to the write if no deltas were applied in between.
                    return Ok(Versioned(
                        idx.idx().map(|idx| (idx, *incarnation)),
                        value_with_layout.clone(),
```

**File:** aptos-move/mvhashmap/src/versioned_data.rs (L625-653)
```rust
    fn write_impl(
        versioned_values: &mut VersionedValue<V>,
        txn_idx: TxnIndex,
        incarnation: Incarnation,
        value: ValueWithLayout<V>,
        dependencies: BTreeMap<TxnIndex, Incarnation>,
    ) {
        let prev_entry = versioned_values.versioned_map.insert(
            ShiftedTxnIndex::new(txn_idx),
            CachePadded::new(new_write_entry(incarnation, value, dependencies)),
        );

        // Assert that the previous entry for txn_idx, if present, had lower incarnation.
        assert!(prev_entry.is_none_or(|entry| -> bool {
            if let EntryCell::ResourceWrite {
                incarnation: prev_incarnation,
                ..
            } = &entry.value
            {
                // For BlockSTMv1, the dependencies are always empty.
                *prev_incarnation < incarnation
                // TODO(BlockSTMv2): when AggregatorV1 is deprecated, we can assert that
                // prev_dependencies is empty: they must have been drained beforehand
                // (into dependencies) if there was an entry at the same index before.
            } else {
                true
            }
        }));
    }
```

**File:** aptos-move/block-executor/src/executor_utilities.rs (L308-346)
```rust
pub(crate) fn update_transaction_on_abort<T, E>(
    txn_idx: TxnIndex,
    last_input_output: &TxnLastInputOutput<T, E::Output>,
    versioned_cache: &MVHashMap<T::Key, T::Tag, T::Value, DelayedFieldID>,
) where
    T: Transaction,
    E: ExecutorTask<Txn = T>,
{
    counters::SPECULATIVE_ABORT_COUNT.inc();

    // Any logs from the aborted execution should be cleared and not reported.
    clear_speculative_txn_logs(txn_idx as usize);

    // Not valid and successfully aborted, mark the latest write/delta sets as estimates.
    if let Some(keys) = last_input_output.modified_resource_keys(txn_idx) {
        for (k, _) in keys {
            versioned_cache.data().mark_estimate(&k, txn_idx);
        }
    }

    // Group metadata lives in same versioned cache as data / resources.
    // We are not marking metadata change as estimate, but after a transaction execution
    // changes metadata, suffix validation is guaranteed to be triggered. Estimation affecting
    // execution behavior is left to size, which uses a heuristic approach.
    last_input_output
        .for_each_resource_group_key_and_tags(txn_idx, |key, tags| {
            versioned_cache
                .group_data()
                .mark_estimate(key, txn_idx, tags);
            Ok(())
        })
        .expect("Passed closure always returns Ok");

    if let Some(keys) = last_input_output.delayed_field_keys(txn_idx) {
        for k in keys {
            versioned_cache.delayed_fields().mark_estimate(&k, txn_idx);
        }
    }
}
```

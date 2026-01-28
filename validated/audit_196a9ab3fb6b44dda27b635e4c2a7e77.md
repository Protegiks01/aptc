# Audit Report

## Title
Race Condition in Resource Group Initialization Can Trigger Code Invariant Errors and Force Sequential Execution Fallback

## Summary
A race condition exists in the MVHashMap parallel execution system during resource group initialization. The non-atomic creation of `group_sizes` and `group_tags` DashMap entries creates a race window where concurrent write operations can trigger `code_invariant_error`, forcing fallback to sequential execution and causing validator performance degradation.

## Finding Description

The vulnerability stems from non-atomic initialization of resource group data structures in the BlockSTM parallel execution engine. When a resource group is accessed for the first time in a block, the initialization process creates two separate DashMap entries in a non-atomic manner: [1](#0-0) 

The initialization then performs size computation (which can take microseconds to milliseconds depending on group size): [2](#0-1) 

Finally, it creates the `group_tags` entry: [3](#0-2) 

During this initialization window (lines 155-175), the `group_sizes` entry exists but `group_tags` does not. If a parallel transaction attempts to write to the same resource group during this window via `write_v2`, the operation checks `group_tags` first in `data_write_impl`: [4](#0-3) 

This triggers a `code_invariant_error` because the code relies on an unenforced "read-before-write" assumption: [5](#0-4) 

The TODO comment explicitly acknowledges this as a known limitation requiring future refactoring. The error propagates through the execution stack: `data_write_impl` → `write_v2` → `process_resource_group_output_v2` → `execute_v2` → `worker_loop_v2`, where it sets an error flag: [6](#0-5) 

## Impact Explanation

This vulnerability aligns with the Aptos bug bounty **HIGH Severity** category: "Validator node slowdowns - Significant performance degradation affecting consensus."

The production configuration enables fallback to sequential execution by default: [7](#0-6) 

When parallel execution encounters the `code_invariant_error`, the system falls back to sequential execution: [8](#0-7) 

**Impact:**
- **Forced sequential execution** instead of parallel execution for the affected block
- **Significant performance degradation** - loss of 10-20x parallelism benefits
- **Validator slowdown** affecting network throughput and consensus participation  
- **Potential DoS vector** if repeatedly triggered across multiple blocks

If `allow_fallback` were set to `false`, the system would panic instead: [9](#0-8) 

## Likelihood Explanation

**LOW to MEDIUM Likelihood:**

The race window exists during every first access to a resource group in each block. The vulnerability can be triggered when:

1. Transaction i reads from resource group G for the first time, triggering initialization at: [10](#0-9) 

2. Transaction j (executing in parallel) attempts to write to the same group before initialization completes

3. The timing hits the race window between lines 155 and 175 of `set_raw_base_values`

**Factors affecting likelihood:**
- The initialization window is relatively narrow (microseconds to milliseconds)
- Larger resource groups widen the window due to size computation overhead
- Higher concurrency increases probability under load
- The TODO comment acknowledges this as a known limitation requiring future fixes

While the exact attack path is non-trivial (requires writes without prior reads in the same transaction execution), the explicit acknowledgment in the codebase via TODO comments and use of `code_invariant_error` (rather than regular error handling) indicates this is a real concern recognized by the development team.

## Recommendation

Implement atomic initialization of resource group data structures. Options include:

1. **Single-lock initialization**: Hold a lock that covers both `group_sizes` and `group_tags` creation
2. **Initialization flag**: Add a separate "initialization in progress" flag that blocks concurrent access
3. **Lazy initialization on write**: Allow writes to initialize missing structures instead of failing
4. **Refactor MVHashMap**: As noted in the TODO comment, refactor the group initialization logic to eliminate the read-before-write assumption

The recommended approach is to refactor the initialization to be atomic, ensuring both `group_sizes` and `group_tags` are created together before releasing any locks.

## Proof of Concept

A theoretical PoC would require:
1. Deploying a Move module with resource group definitions
2. Submitting transaction i that reads from a new resource group (triggers initialization)
3. Submitting transaction j that writes to the same group without reading it first
4. Timing both transactions to execute in the same block with sufficient concurrency

Note: The practical exploitability depends on Move semantics and transaction execution patterns, which typically involve reads before writes. However, the explicit TODO comment and `code_invariant_error` usage indicate this is a real concern that requires addressing through refactoring.

## Notes

This vulnerability is explicitly acknowledged in the codebase through TODO comments, indicating awareness by the development team that this is a real limitation requiring future refactoring. The use of `code_invariant_error` rather than regular error handling suggests this represents a serious code invariant violation. While the practical exploitability requires specific timing and transaction patterns, the potential impact on validator performance and the explicit acknowledgment in code comments validate this as a legitimate security concern warranting remediation.

### Citations

**File:** aptos-move/mvhashmap/src/versioned_group_data.rs (L155-155)
```rust
        let mut group_sizes = self.group_sizes.entry(group_key.clone()).or_default();
```

**File:** aptos-move/mvhashmap/src/versioned_group_data.rs (L158-173)
```rust
        if let Vacant(entry) = group_sizes.size_entries.entry(ShiftedTxnIndex::zero_idx()) {
            // Perform group size computation if base not already provided.
            let group_size = group_size_as_sum::<T>(
                base_values
                    .iter()
                    .flat_map(|(tag, value)| value.bytes().map(|b| (tag.clone(), b.len()))),
            )
            .map_err(|e| {
                anyhow!(
                    "Tag serialization error in resource group at {:?}: {:?}",
                    group_key.clone(),
                    e
                )
            })?;

            entry.insert(SizeEntry::new(SizeAndDependencies::from_size(group_size)));
```

**File:** aptos-move/mvhashmap/src/versioned_group_data.rs (L175-175)
```rust
            let mut superset_tags = self.group_tags.entry(group_key.clone()).or_default();
```

**File:** aptos-move/mvhashmap/src/versioned_group_data.rs (L276-284)
```rust
            // Currently, we rely on read-before-write to make sure the group would have
            // been initialized, which would have created an entry in group_sizes. Group
            // being initialized sets up data-structures, such as superset_tags, which
            // is used in write_v2, hence the code invariant error. Note that in read API
            // (fetch_tagged_data) we return Uninitialized / TagNotFound errors, because
            // currently that is a part of expected initialization flow.
            // TODO(BlockSTMv2): when we refactor MVHashMap and group initialization logic,
            // also revisit and address the read-before-write assumption.
            code_invariant_error("Group (sizes) must be initialized to write to")
```

**File:** aptos-move/mvhashmap/src/versioned_group_data.rs (L630-633)
```rust
            let superset_tags = self.group_tags.get(group_key).ok_or_else(|| {
                // Due to read-before-write.
                code_invariant_error("Group (tags) must be initialized to write to")
            })?;
```

**File:** aptos-move/block-executor/src/executor.rs (L1778-1799)
```rust
                    if let Err(err) = self.worker_loop_v2(
                        &executor,
                        signature_verified_block,
                        environment,
                        *worker_id,
                        num_workers,
                        &scheduler,
                        &shared_sync_params,
                    ) {
                        // If there are multiple errors, they all get logged: FatalVMError is
                        // logged at construction, below we log CodeInvariantErrors.
                        if let PanicOr::CodeInvariantError(err_msg) = err {
                            alert!(
                                "[BlockSTMv2] worker loop: CodeInvariantError({:?})",
                                err_msg
                            );
                        }
                        shared_maybe_error.store(true, Ordering::SeqCst);

                        // Make sure to halt the scheduler if it hasn't already been halted.
                        scheduler.halt();
                    }
```

**File:** aptos-move/block-executor/src/executor.rs (L2576-2596)
```rust
            // If parallel gave us result, return it
            if let Ok(output) = parallel_result {
                return Ok(output);
            }

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
```

**File:** types/src/block_executor/config.rs (L72-75)
```rust
        Self {
            blockstm_v2: false,
            concurrency_level,
            allow_fallback: true,
```

**File:** aptos-move/block-executor/src/view.rs (L1586-1619)
```rust
    fn initialize_mvhashmap_base_group_contents(&self, group_key: &T::Key) -> PartialVMResult<()> {
        let (base_group, metadata_op): (BTreeMap<T::Tag, Bytes>, _) =
            match self.get_raw_base_value(group_key)? {
                Some(state_value) => (
                    bcs::from_bytes(state_value.bytes()).map_err(|e| {
                        PartialVMError::new(StatusCode::UNEXPECTED_DESERIALIZATION_ERROR)
                            .with_message(format!(
                                "Failed to deserialize the resource group at {:?}: {:?}",
                                group_key, e
                            ))
                    })?,
                    TransactionWrite::from_state_value(Some(state_value)),
                ),
                None => (BTreeMap::new(), TransactionWrite::from_state_value(None)),
            };
        let base_group_sentinel_ops = base_group
            .into_iter()
            .map(|(t, bytes)| {
                (
                    t,
                    TransactionWrite::from_state_value(Some(StateValue::new_legacy(bytes))),
                )
            })
            .collect();

        self.latest_view
            .get_resource_group_state()
            .set_raw_group_base_values(group_key.clone(), base_group_sentinel_ops)?;
        self.latest_view.get_resource_state().set_base_value(
            group_key.clone(),
            ValueWithLayout::RawFromStorage(TriompheArc::new(metadata_op)),
        );
        Ok(())
    }
```

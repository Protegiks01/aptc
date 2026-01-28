# Audit Report

## Title
Race Condition in Resource Group Initialization Causes Non-Deterministic Parallel Execution Failures

## Summary
A race condition exists between `group_sizes` and `group_tags` initialization in `VersionedGroupData::set_raw_base_values()`, allowing concurrent write operations to trigger code invariant errors during parallel execution. This forces fallback to sequential execution, creating a performance DoS vector affecting all validators.

## Finding Description

The vulnerability occurs in the parallel execution path (BlockSTM) when resource groups are lazily initialized. The initialization process creates two separate DashMap data structures non-atomically in `set_raw_base_values()`:

First, the `group_sizes` entry is created: [1](#0-0) 

Then, after computing the group size (lines 158-173), the `group_tags` entry is created: [2](#0-1) 

These are separate DashMaps defined in the struct: [3](#0-2) 

**Critical Race Window:** Between lines 155 and 175, `group_sizes` exists but `group_tags` does not. During this window, the read path only checks `group_sizes` to determine initialization: [4](#0-3) 

However, the write path requires `group_tags` to exist: [5](#0-4) 

**Exploitation Path:**

1. Transaction T1 reads from a new resource group G, triggering initialization via `initialize_mvhashmap_base_group_contents`: [6](#0-5) 

2. Thread 1 (T1) enters `set_raw_base_values(G)`, creates `group_sizes[G]` entry at line 155
3. Thread 2 (T2) reads from group G, calls `fetch_tagged_data_and_record_dependency()`, sees `group_sizes[G]` exists at line 452, considers group initialized
4. Thread 2 (T2) later writes to group G via `write_v2()` which calls `data_write_impl()` at line 630
5. `data_write_impl()` checks `group_tags[G]` → **None!** → returns code invariant error

This error propagates through the call stack causing parallel execution failure. The error flows from `write_v2()` through `process_resource_group_output_v2()`: [7](#0-6) 

Up to `execute_v2()`: [8](#0-7) 

Causing `worker_loop_v2()` to return an error, which triggers fallback to sequential execution: [9](#0-8) 

## Impact Explanation

**HIGH Severity** per Aptos bug bounty criteria: "Validator node slowdowns"

The vulnerability forces validators to fall back from parallel to sequential execution, causing significant performance degradation:

- **Parallel execution**: ~N transactions concurrently (N = concurrency_level, typically 8-32)
- **Sequential execution**: 1 transaction at a time
- **Performance degradation**: ~N× slower block execution

The default configuration enables fallback: [10](#0-9) 

This prevents consensus failures but allows performance attacks affecting all validators processing the same block.

**Security Impacts:**
1. **Performance DoS**: Attackers force sequential execution across all validators
2. **Non-deterministic behavior**: Same block executes differently (parallel vs sequential) based on race timing
3. **Resource waste**: Computational resources wasted on failed parallel execution attempts
4. **Code invariant violation**: The system explicitly treats this as a bug that shouldn't occur

## Likelihood Explanation

**HIGH Likelihood:**

1. **Low attacker complexity**: Simply submit transactions accessing new resource groups
2. **No special privileges required**: Any transaction sender can trigger this
3. **Reproducible with attempts**: Race window exists during size computation (lines 158-173); attackers can submit multiple blocks to increase hit probability
4. **Natural occurrence**: Can happen without malicious intent when legitimate transactions access new groups concurrently
5. **Parallel execution is common**: Most validators run with concurrency_level > 1

The race window exists between DashMap operations on separate data structures with no cross-map synchronization.

## Recommendation

Synchronize the creation of both `group_sizes` and `group_tags` entries atomically. One approach:

```rust
pub fn set_raw_base_values(
    &self,
    group_key: K,
    base_values: Vec<(T, V)>,
) -> anyhow::Result<()> {
    // Acquire locks on both maps before any modifications
    let mut group_sizes = self.group_sizes.entry(group_key.clone()).or_default();
    let mut superset_tags = self.group_tags.entry(group_key.clone()).or_default();
    
    if let Vacant(entry) = group_sizes.size_entries.entry(ShiftedTxnIndex::zero_idx()) {
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

        for (tag, value) in base_values.into_iter() {
            superset_tags.insert(tag.clone());
            self.values.set_base_value(
                (group_key.clone(), tag),
                ValueWithLayout::RawFromStorage(Arc::new(value)),
            );
        }
    }
    
    Ok(())
}
```

This ensures both entries exist before any concurrent thread can observe `group_sizes` without `group_tags`.

## Proof of Concept

A Rust test demonstrating the race condition would involve:

1. Create a `VersionedGroupData` instance
2. Spawn two threads:
   - Thread 1: Call `set_raw_base_values()` for a group
   - Thread 2: Immediately call `fetch_tagged_data_and_record_dependency()` followed by `write_v2()` on the same group
3. Use synchronization primitives to maximize race window probability
4. Assert that `write_v2()` returns a code invariant error

The test would require careful timing to hit the narrow race window between lines 155 and 175, but the window is demonstrably non-zero during group size computation.

## Notes

This vulnerability is particularly concerning because:
1. It explicitly violates code invariants that developers expected to hold
2. The TODO comment at line 451 indicates the developers are aware initialization logic needs refactoring
3. The performance impact affects all validators simultaneously, not just the attacker's node
4. The fallback mechanism masks the root cause, making debugging difficult

### Citations

**File:** aptos-move/mvhashmap/src/versioned_group_data.rs (L81-92)
```rust
    group_sizes: DashMap<K, VersionedGroupSize>,

    // Stores a set of tags for this group, basically a superset of all tags encountered in
    // group related APIs. The accesses are synchronized with group size entry (for now),
    // but it is stored separately for conflict free read-path for txn materialization
    // (as the contents of group_tags are used in preparing finalized group contents).
    // Note: The contents of group_tags are non-deterministic, but finalize_group filters
    // out tags for which the latest value does not exist. The implementation invariant
    // that the contents observed in the multi-versioned map after index is committed
    // must correspond to the outputs recorded by the committed transaction incarnations.
    // (and the correctness of the outputs is the responsibility of BlockSTM validation).
    group_tags: DashMap<K, HashSet<T>>,
```

**File:** aptos-move/mvhashmap/src/versioned_group_data.rs (L155-155)
```rust
        let mut group_sizes = self.group_sizes.entry(group_key.clone()).or_default();
```

**File:** aptos-move/mvhashmap/src/versioned_group_data.rs (L175-175)
```rust
            let mut superset_tags = self.group_tags.entry(group_key.clone()).or_default();
```

**File:** aptos-move/mvhashmap/src/versioned_group_data.rs (L452-452)
```rust
        let initialized = self.group_sizes.contains_key(group_key);
```

**File:** aptos-move/mvhashmap/src/versioned_group_data.rs (L630-633)
```rust
            let superset_tags = self.group_tags.get(group_key).ok_or_else(|| {
                // Due to read-before-write.
                code_invariant_error("Group (tags) must be initialized to write to")
            })?;
```

**File:** aptos-move/block-executor/src/view.rs (L1505-1506)
```rust
        if matches!(group_read, GroupReadResult::Uninitialized) {
            self.initialize_mvhashmap_base_group_contents(group_key)?;
```

**File:** aptos-move/block-executor/src/executor.rs (L268-275)
```rust
                            versioned_cache.group_data().write_v2(
                                group_key,
                                idx_to_execute,
                                incarnation,
                                group_ops.into_iter(),
                                group_size,
                                prev_tags,
                            )?,
```

**File:** aptos-move/block-executor/src/executor.rs (L452-459)
```rust
        Self::process_resource_group_output_v2(
            maybe_output,
            idx_to_execute,
            incarnation,
            last_input_output,
            versioned_cache,
            &mut abort_manager,
        )?;
```

**File:** aptos-move/block-executor/src/executor.rs (L2577-2596)
```rust
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

**File:** types/src/block_executor/config.rs (L75-75)
```rust
            allow_fallback: true,
```

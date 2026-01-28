# Audit Report

## Title
Race Condition Between Layout Cache and Module Cache Invalidation Causes Consensus Divergence

## Summary
A critical race condition exists between `mark_overridden()` and `flush_layout_cache()` during module publishing in parallel block execution (Block-STM). This allows concurrent transactions to use stale struct layouts from old module versions while loading new module versions, creating layout-module version mismatches that pass validation but produce non-deterministic execution results across validators, leading to consensus divergence.

## Finding Description

The vulnerability exists in the module publishing flow within Block-STM parallel execution. The issue arises from non-atomic cache invalidation operations:

**The Race Window:**

During module publishing, the system processes module writes in a loop, marking each module as overridden, then flushes the layout cache after all modules are processed: [1](#0-0) 

Within this loop, `add_module_write_to_module_cache` marks the module as overridden: [2](#0-1) 

However, the layout cache flush only occurs after the loop completes (line 574). This creates a race window where concurrent transactions can access inconsistent cache states.

**The Attack Scenario:**

1. Transaction T1 (txn_idx=5) publishes module M, enters the race window between marking overridden and flushing layouts
2. Transaction T2 (txn_idx=10) executes concurrently and calls `load_layout_from_cache()`: [3](#0-2) 

3. T2 retrieves the OLD layout from the global cache (line 209) since `flush_layout_cache()` hasn't been called yet
4. T2 then charges for modules (lines 211-218), which triggers module loading via `get_module_or_build_with()`
5. Since module M is marked as overridden, the global cache returns `None`: [4](#0-3) 

6. T2 falls through to per-block cache and loads the NEW module M (lines 166-174)
7. T2 records a per-block cache read with the correct version
8. Validation checks only module version consistency, not layout coherency: [5](#0-4) 

9. T2 passes validation (version matches) but executes with OLD layout + NEW module

**Result:** If the struct layout changed between module versions (e.g., field reordering), T2 deserializes struct fields from wrong offsets, computing incorrect values and producing different execution results.

**Consensus Divergence Mechanism:**

Different validators experience different race timings due to CPU scheduling, load conditions, and hardware variations:
- **Validator A**: T2 executes before T1's race window → uses old module + old layout → CORRECT
- **Validator B**: T2 executes during T1's race window → uses new module + old layout → INCORRECT  
- **Validator C**: T2 executes after T1's race window → uses new module + new layout → CORRECT

All three validators have T2 pass validation (module version matches), but produce different state roots, causing consensus divergence.

## Impact Explanation

This vulnerability achieves **Critical Severity** under the Aptos bug bounty's "Consensus/Safety Violations" category because it directly violates the deterministic execution invariant: "All validators must produce identical state roots for identical blocks."

The race condition timing is inherently non-deterministic across validators, enabling:
1. **Consensus divergence**: Different validators commit different state roots for the same block
2. **Network partition**: Validators split into incompatible forks
3. **Non-recoverable state**: Requires hard fork to resolve the consensus split
4. **Memory corruption**: Incompatible layouts cause deserialization to wrong field offsets
5. **Data corruption**: Values interpreted incorrectly based on wrong struct layouts

This matches the Critical impact criteria: "Different validators commit different blocks" and "Chain splits without hardfork requirement."

## Likelihood Explanation

**High likelihood** of occurrence:

1. **Frequent trigger condition**: Module publishing occurs regularly during protocol upgrades, framework updates, and DApp deployments

2. **Default configuration vulnerable**: Parallel execution (Block-STM) is enabled by default when `concurrency_level > 1`: [6](#0-5) 

3. **Significant race window**: The window spans from inside the module processing loop (line 317) to after the loop (line 574), encompassing multiple function calls and iterations

4. **No synchronization barriers**: The layout cache uses `DashMap` for concurrent access without additional locking between module override and layout flush operations: [7](#0-6) 

5. **No special privileges required**: Any user can trigger the vulnerable code path by submitting a module publishing transaction

## Recommendation

Implement atomic cache invalidation by flushing the layout cache immediately after marking each module as overridden, within the same critical section:

```rust
for write in output_before_guard.module_write_set().values() {
    published = true;
    if scheduler.is_v2() {
        module_ids_for_v2.insert(write.module_id().clone());
    }
    add_module_write_to_module_cache::<T>(
        write,
        txn_idx,
        runtime_environment,
        global_module_cache,
        versioned_cache.module_cache(),
    )?;
    // FIX: Flush layout cache immediately after marking module as overridden
    global_module_cache.flush_layout_cache();
}
if published {
    scheduler.record_validation_requirements(txn_idx, module_ids_for_v2)?;
}
```

Alternatively, extend validation to verify layout coherency by checking that cached layouts match the module versions read during execution.

## Proof of Concept

A complete PoC would require:
1. Deploying a module M with struct S containing fields in order [field_a, field_b]
2. Publishing an upgraded module M' with struct S' containing fields in reverse order [field_b, field_a]
3. Scheduling concurrent transactions that read struct S during M's publishing
4. Observing different validators produce different state roots due to layout-module mismatches

The vulnerability can be triggered through standard module publishing transactions without requiring special validator access or coordination.

## Notes

The vulnerable code path exists in both BlockSTM v1 and v2 schedulers. The sequential execution path has the same pattern but is not vulnerable since transactions execute serially without concurrency. The comment in `flush_layout_cache()` indicates this is a temporary solution ("Flushing is only needed because of enums"), suggesting the developers are aware of layout cache complexity but not the race condition implications.

### Citations

**File:** aptos-move/block-executor/src/txn_last_input_output.rs (L559-577)
```rust
        for write in output_before_guard.module_write_set().values() {
            published = true;
            if scheduler.is_v2() {
                module_ids_for_v2.insert(write.module_id().clone());
            }
            add_module_write_to_module_cache::<T>(
                write,
                txn_idx,
                runtime_environment,
                global_module_cache,
                versioned_cache.module_cache(),
            )?;
        }
        if published {
            // Record validation requirements after the modules are published.
            global_module_cache.flush_layout_cache();
            scheduler.record_validation_requirements(txn_idx, module_ids_for_v2)?;
        }
        Ok(published)
```

**File:** aptos-move/block-executor/src/code_cache_global.rs (L96-96)
```rust
    struct_layouts: DashMap<StructKey, LayoutCacheEntry>,
```

**File:** aptos-move/block-executor/src/code_cache_global.rs (L317-317)
```rust
    global_module_cache.mark_overridden(write.module_id());
```

**File:** third_party/move/move-vm/runtime/src/storage/loader/lazy.rs (L203-221)
```rust
    fn load_layout_from_cache(
        &self,
        gas_meter: &mut impl DependencyGasMeter,
        traversal_context: &mut TraversalContext,
        key: &StructKey,
    ) -> Option<PartialVMResult<LayoutWithDelayedFields>> {
        let entry = self.module_storage.get_struct_layout(key)?;
        let (layout, modules) = entry.unpack();
        for module_id in modules.iter() {
            // Re-read all modules for this layout, so that transaction gets invalidated
            // on module publish. Also, we re-read them in exactly the same way as they
            // were traversed during layout construction, so gas charging should be exactly
            // the same as on the cache miss.
            if let Err(err) = self.charge_module(gas_meter, traversal_context, module_id) {
                return Some(Err(err));
            }
        }
        Some(Ok(layout))
    }
```

**File:** aptos-move/block-executor/src/code_cache.rs (L156-161)
```rust
                if let Some(module) = self.global_module_cache.get(key) {
                    state
                        .captured_reads
                        .borrow_mut()
                        .capture_global_cache_read(key.clone(), module.clone());
                    return Ok(Some((module, Self::Version::default())));
```

**File:** aptos-move/block-executor/src/captured_reads.rs (L1060-1066)
```rust
        let validate = |key: &K, read: &ModuleRead<DC, VC, S>| match read {
            ModuleRead::GlobalCache(_) => global_module_cache.contains_not_overridden(key),
            ModuleRead::PerBlockCache(previous) => {
                let current_version = per_block_module_cache.get_module_version(key);
                let previous_version = previous.as_ref().map(|(_, version)| *version);
                current_version == previous_version
            },
```

**File:** types/src/block_executor/config.rs (L71-79)
```rust
    pub fn default_with_concurrency_level(concurrency_level: usize) -> Self {
        Self {
            blockstm_v2: false,
            concurrency_level,
            allow_fallback: true,
            discard_failed_blocks: false,
            module_cache_config: BlockExecutorModuleCacheLocalConfig::default(),
        }
    }
```

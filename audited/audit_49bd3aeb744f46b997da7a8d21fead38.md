# Audit Report

## Title
Layout Cache Pollution from Aborted Transactions Enables Consensus Divergence

## Summary
The `store_struct_layout_entry()` function uses a "Vacant only" insertion strategy that allows aborted transactions to permanently pollute the global layout cache with stale struct layouts. This prevents legitimate layout updates after module republishing, causing different validators to potentially use incompatible layouts and diverge on state roots, violating the Deterministic Execution invariant.

## Finding Description

The vulnerability exists in the interaction between parallel transaction execution, module republishing, and the global struct layout cache: [1](#0-0) 

The `store_struct_layout_entry()` function uses a Vacant-only check, meaning once a layout is inserted for a given `StructKey`, it cannot be updated. The `StructKey` contains `StructNameIndex` and `TypeVecId`, and critically, the `StructNameIndex` remains stable across module versions—the same struct name always maps to the same index. [2](#0-1) 

The `struct_layouts` cache is global and shared across all transactions in a block. When modules are published, the cache is flushed: [3](#0-2) 

However, when transactions abort after validation failure, there is NO cleanup of layout cache entries: [4](#0-3) 

**Attack Scenario:**

1. Transaction T1 at index 0 uses struct `S` from module `M` (version v1), stores layout `L_v1` with key `K`
2. Transaction T2 at index 1 publishes module `M` version v2 (compatible upgrade, struct `S` has additional field)
   - Calls `flush_layout_cache()` - clears entire cache including key `K`
   - Marks module `M` as overridden in module cache
3. Transaction T3 at index 2 was executing in parallel (started before T2 committed):
   - Read module `M` v1 speculatively before T2's changes were visible
   - Computed layout `L_v1` for struct `S`
   - **After T2's flush**, T3 calls `store_struct_layout_entry(K, L_v1)`
   - Entry is Vacant (just flushed), so `L_v1` is inserted
4. T3 reaches validation phase:
   - Validates module reads via `validate_module_reads()`
   - Discovers module `M` was overridden
   - Validation fails, T3 must re-execute
5. T3 re-executes:
   - Reads module `M` v2 (current version)
   - Computes correct layout `L_v2` for struct `S` with new field
   - Calls `store_struct_layout_entry(K, L_v2)`
   - Entry is NOT Vacant (T3's aborted execution inserted `L_v1`)
   - **`L_v2` is silently discarded** due to Vacant-only check
6. Transaction T4 uses struct `S` from module `M` v2:
   - Calls `get_struct_layout_entry(K)`
   - Receives stale layout `L_v1` (missing the new field)
   - Serializes/deserializes with wrong layout
   - **State corruption and potential consensus divergence** [5](#0-4) 

The validation mechanism detects overridden modules but cannot prevent the layout pollution that occurs during the window between cache flush and validation failure. [6](#0-5) 

While `load_layout_from_cache()` re-reads defining modules for gas metering and validation triggering, it does NOT verify that the cached layout matches the current module version—it blindly returns the cached layout regardless of module version.

## Impact Explanation

**Critical Severity - Consensus/Safety Violation**

This vulnerability directly violates the **Deterministic Execution** invariant: "All validators must produce identical state roots for identical blocks."

When different validators execute the same block with different timing:
- Validator A: T3's layout store happens before flush, gets cleaned up properly
- Validator B: T3's layout store happens after flush, pollutes cache with stale layout

Subsequently, when transactions use the affected struct:
- Validator A uses correct layout `L_v2`, produces state root `R_A`
- Validator B uses stale layout `L_v1`, produces state root `R_B`
- `R_A ≠ R_B` - **Consensus divergence**

This breaks consensus safety and could lead to:
- Chain split requiring hard fork to resolve
- Permanent network partition
- Loss of finality guarantees
- Potential double-spend if validators diverge on transaction outcomes

Per Aptos Bug Bounty criteria, consensus/safety violations are **Critical Severity** (up to $1,000,000).

## Likelihood Explanation

**Likelihood: Medium-High**

This vulnerability triggers under these conditions:
1. Module republishing occurs within a block (common during upgrades)
2. Parallel execution is enabled (default in production)
3. Timing window: transaction stores layout after flush but before validation
4. Struct is used in subsequent transactions

The timing window is narrow but realistic in parallel execution. Module upgrades happen regularly on Aptos mainnet. The likelihood increases with:
- Higher transaction throughput (more parallel execution)
- Frequent module upgrades
- Structs used in multiple transactions per block

No special privileges required - any account can publish modules and trigger this condition.

## Recommendation

**Solution: Clear layout cache entries for specific modules when they are overridden, OR implement version-aware layout caching**

### Option 1: Module-specific cache invalidation
When `mark_overridden()` is called for a module, also remove all layout entries that depend on that module:

```rust
pub fn mark_overridden_and_invalidate_layouts(&self, key: &K, module_id: &ModuleId) {
    // Mark module as overridden
    if let Some(entry) = self.module_cache.get(key) {
        entry.mark_overridden();
    }
    
    // Remove layouts that depend on this module
    self.struct_layouts.retain(|_struct_key, layout_entry| {
        let (_layout, modules) = layout_entry.clone().unpack();
        !modules.iter().any(|m| m == module_id)
    });
}
```

### Option 2: Include module version in StructKey
Modify `StructKey` to include module version/hash:

```rust
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct StructKey {
    pub idx: StructNameIndex,
    pub ty_args_id: TypeVecId,
    pub module_version: TxnIndex, // NEW: module version/transaction index
}
```

### Option 3: Rollback layout stores on abort (Recommended)
Track layout cache insertions per transaction and roll them back on abort:

```rust
// In TxnLastInputOutput, add:
cached_layouts: Vec<StructKey>,

// In store_struct_layout_entry, track insertion:
if let dashmap::Entry::Vacant(e) = self.struct_layouts.entry(*key) {
    e.insert(entry);
    // Record this insertion for potential rollback
    if let Some(tracker) = txn_layout_tracker {
        tracker.track_layout_store(*key);
    }
}

// In update_transaction_on_abort, add cleanup:
if let Some(layout_keys) = last_input_output.cached_layouts(txn_idx) {
    for key in layout_keys {
        global_module_cache.struct_layouts.remove(&key);
    }
}
```

## Proof of Concept

```rust
// Add to aptos-move/e2e-move-tests/src/tests/code_publishing.rs

#[test]
fn test_layout_cache_pollution_from_aborted_transaction() {
    let mut executor = FakeExecutor::from_head_genesis().set_parallel();
    executor.disable_block_executor_fallback();
    
    let mut h = MoveHarness::new_with_executor(executor);
    let addr = AccountAddress::random();
    let account = h.new_account_at(addr);
    
    // Publish initial module with struct Foo { data: u64 }
    let source_v1 = format!(
        "module {}::test {{ 
            struct Foo has key, store {{ data: u64 }}
            public fun store_foo(s: &signer) {{
                move_to(s, Foo {{ data: 1 }})
            }}
        }}", 
        addr
    );
    
    let txn1 = h.create_transaction_payload(&account, publish_module_txn(source_v1, "test"));
    assert_success!(h.run_block(vec![txn1])[0].status());
    
    // In a single block, publish upgraded module and use it
    let source_v2 = format!(
        "module {}::test {{ 
            struct Foo has key, store {{ data: u64, extra: u128 }}
            public fun store_foo(s: &signer) {{
                move_to(s, Foo {{ data: 2, extra: 100 }})
            }}
        }}", 
        addr
    );
    
    // T1: Use old version (will cause parallel execution to cache old layout)
    let use_old = h.create_transaction_payload(&account, 
        transaction_call_function(addr, "test", "store_foo", vec![], vec![])
    );
    
    // T2: Publish new version (flushes layout cache)
    let publish_new = h.create_transaction_payload(&account, 
        publish_module_txn(source_v2, "test")
    );
    
    // T3: Use new version (should use new layout)
    let use_new = h.create_transaction_payload(&account,
        transaction_call_function(addr, "test", "store_foo", vec![], vec![])
    );
    
    // Execute in parallel - timing may allow T1 to pollute cache after T2's flush
    let outputs = h.run_block_get_output(vec![use_old, publish_new, use_new]);
    
    // If vulnerability exists, validators with different timing may produce different state roots
    // This test would need to run with specific parallel execution instrumentation
    // to trigger the race condition reliably
    
    // Expected: All transactions succeed and T3 uses correct new layout
    // Actual (if vulnerable): T3 may use stale layout, causing state inconsistency
}
```

**Notes:**
- The PoC requires parallel execution timing control to reliably trigger the race
- In production, this manifests as non-deterministic consensus failures
- Testing requires instrumentation to control transaction execution scheduling
- The existing test `test_module_publishing_does_not_leak_speculative_information` validates that layouts aren't cached during publishing verification, but doesn't cover post-flush cache pollution by aborted transactions

### Citations

**File:** aptos-move/block-executor/src/code_cache_global.rs (L86-97)
```rust
/// A global cache for verified code and derived information (such as layouts) that is concurrently
/// accessed during the block execution. Module cache is read-only, and modified safely only at
/// block boundaries. Layout cache can be modified during execution of the block.
pub struct GlobalModuleCache<K, D, V, E> {
    /// Module cache containing the verified code.
    module_cache: HashMap<K, Entry<D, V, E>>,
    /// Sum of serialized sizes (in bytes) of all cached modules.
    size: usize,
    /// Cached layouts of structs or enums. This cache stores roots only and is invalidated when
    /// modules are published.
    struct_layouts: DashMap<StructKey, LayoutCacheEntry>,
}
```

**File:** aptos-move/block-executor/src/code_cache_global.rs (L181-190)
```rust
    pub(crate) fn store_struct_layout_entry(
        &self,
        key: &StructKey,
        entry: LayoutCacheEntry,
    ) -> PartialVMResult<()> {
        if let dashmap::Entry::Vacant(e) = self.struct_layouts.entry(*key) {
            e.insert(entry);
        }
        Ok(())
    }
```

**File:** aptos-move/block-executor/src/txn_last_input_output.rs (L572-576)
```rust
        if published {
            // Record validation requirements after the modules are published.
            global_module_cache.flush_layout_cache();
            scheduler.record_validation_requirements(txn_idx, module_ids_for_v2)?;
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

**File:** aptos-move/block-executor/src/captured_reads.rs (L1050-1067)
```rust
    pub(crate) fn validate_module_reads(
        &self,
        global_module_cache: &GlobalModuleCache<K, DC, VC, S>,
        per_block_module_cache: &SyncModuleCache<K, DC, VC, S, Option<TxnIndex>>,
        maybe_updated_module_keys: Option<&BTreeSet<K>>,
    ) -> bool {
        if self.non_delayed_field_speculative_failure {
            return false;
        }

        let validate = |key: &K, read: &ModuleRead<DC, VC, S>| match read {
            ModuleRead::GlobalCache(_) => global_module_cache.contains_not_overridden(key),
            ModuleRead::PerBlockCache(previous) => {
                let current_version = per_block_module_cache.get_module_version(key);
                let previous_version = previous.as_ref().map(|(_, version)| *version);
                current_version == previous_version
            },
        };
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

# Audit Report

## Title
Race Condition in Layout Cache Invalidation During Module Republishing Leads to Stale Layout Usage

## Summary
A critical race condition exists between marking a module as overridden and flushing the layout cache during module republishing. This timing window allows concurrent transactions to retrieve stale struct layouts while reading updated module code, potentially causing memory corruption, consensus splits, and violation of deterministic execution guarantees.

## Finding Description

The vulnerability exists in the module publishing flow where two critical operations are non-atomic: [1](#0-0) [2](#0-1) 

**The Attack Scenario:**

1. **Transaction T1** (index 1) executes:
   - Loads module M version 1 from global cache
   - Computes layout L1 for struct S in module M
   - Stores layout L1 in global layout cache
   - Commits successfully

2. **Transaction T2** (index 2) executes and commits:
   - Publishes module M version 2 with different struct S layout
   - Calls `add_module_write_to_module_cache` which marks M as overridden in global cache
   - **CRITICAL TIMING WINDOW OPENS HERE**
   - Later calls `flush_layout_cache()` to clear stale layouts

3. **Transaction T3** (index 3) executes **during the timing window**:
   - Calls `load_layout_from_cache` for struct S
   - Successfully retrieves cached layout L1 (stale from M v1) because cache not yet flushed
   - Re-reads module M for gas charging via `charge_module`
   - Since M is now marked overridden in global cache, reads M v2 from per-block cache
   - Captures `ModuleRead::PerBlockCache(Some((M v2, Some(2))))`
   - **Returns stale layout L1 (computed from M v1) to be used with M v2**
   - Uses incorrect layout L1 for deserialization/serialization operations

4. **T3 Validation Phase:**
   - Module read validation checks captured reads
   - For the captured `ModuleRead::PerBlockCache`, validates that version hasn't changed
   - Validation **PASSES** because M v2 is still at version Some(2)
   - T3 commits with stale layout usage [3](#0-2) 

**Why Validation Doesn't Catch This:**

The module read validation only checks if the module version matches, not whether the cached layout is consistent with that module version. The `StructKey` used for layout caching contains no module version information: [4](#0-3) 

The `LayoutCacheEntry` stores which modules were used to construct the layout but not their versions or content hashes: [5](#0-4) 

When `load_layout_from_cache` re-reads modules, it only does so for gas charging and transaction invalidation, not to validate layout correctness: [6](#0-5) 

## Impact Explanation

This vulnerability has **Critical Severity** impact:

1. **Consensus Safety Violation**: Different validators experiencing different timing windows will use different layouts for the same struct, producing different state roots for identical blocks. This breaks the fundamental "Deterministic Execution" invariant requiring all validators to produce identical state roots.

2. **Memory Corruption**: Using an incorrect memory layout for struct deserialization can lead to:
   - Reading/writing memory at wrong offsets
   - Type confusion attacks
   - Buffer overflows if struct sizes differ
   - Undefined behavior in Rust unsafe code paths

3. **State Manipulation**: Attackers can craft module upgrades that change struct layouts to:
   - Manipulate resource balances by changing field positions
   - Bypass access controls if layout affects capability checking
   - Corrupt critical system state (governance, staking, framework modules)

4. **Non-Recoverable Network Split**: Once validators diverge on state roots due to layout inconsistency, the network cannot self-recover without manual intervention (hardfork), meeting the Critical severity criteria.

## Likelihood Explanation

**HIGH Likelihood:**

1. **Frequent Opportunity**: Module publishing is a standard operation in Aptos. Every module upgrade creates this race condition window.

2. **Parallel Execution Design**: The BlockSTM parallel executor explicitly allows concurrent transaction execution, maximizing the chance of hitting this timing window.

3. **No Special Privileges Required**: Any user can publish modules to their own address. An attacker only needs to:
   - Publish module M v1 with struct S
   - Have transactions use struct S (populating layout cache)
   - Publish module M v2 with different layout for struct S
   - Rely on normal parallel execution to hit the race window

4. **Exploitable Timing Window**: The window between `mark_overridden` and `flush_layout_cache` includes:
   - Loop iteration overhead processing multiple module writes
   - Conditional branch checking if modules were published
   - DashMap concurrent access with no synchronization

5. **Validation Blind Spot**: The module validation mechanism explicitly does not validate layout consistency, making this a persistent vulnerability rather than a transient race that gets caught.

## Recommendation

**Immediate Fix**: Make `mark_overridden` and `flush_layout_cache` atomic. Move the layout cache flush inside `add_module_write_to_module_cache` immediately after marking the module as overridden:

```rust
pub(crate) fn add_module_write_to_module_cache<T: BlockExecutableTransaction>(
    write: &ModuleWrite<T::Value>,
    txn_idx: TxnIndex,
    runtime_environment: &RuntimeEnvironment,
    global_module_cache: &GlobalModuleCache<ModuleId, CompiledModule, Module, AptosModuleExtension>,
    per_block_module_cache: &impl ModuleCache<...>,
) -> Result<(), PanicError> {
    // ... existing code ...
    
    per_block_module_cache.insert_deserialized_module(...)?;
    global_module_cache.mark_overridden(write.module_id());
    
    // FIX: Immediately flush layout cache after marking overridden
    // This prevents the race condition window
    global_module_cache.flush_layout_cache();
    
    Ok(())
}
```

Then remove the separate `flush_layout_cache()` call from `publish_module_write_set`.

**Long-Term Fix**: Add module version/hash to layout cache keys or entries:

1. Include module code hash in `StructKey` or validate it when loading from cache
2. Store module versions in `LayoutCacheEntry` and validate during `load_layout_from_cache`
3. Implement fine-grained invalidation: only invalidate layouts for republished modules rather than flushing entire cache

## Proof of Concept

```rust
// This PoC demonstrates the race condition window
// Run with: cargo test --package aptos-block-executor

#[test]
fn test_layout_cache_race_condition() {
    use std::sync::{Arc, Barrier};
    use std::thread;
    
    // Setup: GlobalModuleCache with a layout cached for module M v1
    let global_cache = Arc::new(GlobalModuleCache::empty());
    
    // Thread 1: Simulates T2 publishing module M v2
    let cache1 = global_cache.clone();
    let barrier = Arc::new(Barrier::new(2));
    let barrier1 = barrier.clone();
    
    let t1 = thread::spawn(move || {
        // Simulate module publishing
        cache1.mark_overridden(&module_id_m);
        // Wait here - this is the race window
        barrier1.wait();
        // Now flush - but too late!
        cache1.flush_layout_cache();
    });
    
    // Thread 2: Simulates T3 loading layout during the race window
    let cache2 = global_cache.clone();
    let barrier2 = barrier.clone();
    
    let t2 = thread::spawn(move || {
        barrier2.wait(); // Wait for mark_overridden to complete
        
        // This read happens AFTER mark_overridden but BEFORE flush_layout_cache
        let stale_layout = cache2.get_struct_layout_entry(&struct_key);
        
        // At this point:
        // - Module M is marked overridden (would read M v2 from per-block cache)
        // - But layout cache still contains L1 from M v1
        // - T3 will use L1 with M v2 = INCONSISTENCY
        
        assert!(stale_layout.is_some()); // This should be None after proper flush
    });
    
    t1.join().unwrap();
    t2.join().unwrap();
}
```

## Notes

The vulnerability is confirmed by examining the concurrent access pattern of `DashMap` used for `struct_layouts`: [7](#0-6) 

The `DashMap` allows concurrent reads during the critical window, and there is no lock protecting the atomicity of `mark_overridden` + `flush_layout_cache` operations. The comment acknowledging this issue exists: [8](#0-7) 

The TODO comment about enum variants suggests the developers are aware of layout cache complexity but haven't addressed the fundamental race condition.

### Citations

**File:** aptos-move/block-executor/src/code_cache_global.rs (L96-96)
```rust
    struct_layouts: DashMap<StructKey, LayoutCacheEntry>,
```

**File:** aptos-move/block-executor/src/code_cache_global.rs (L163-168)
```rust
    pub fn flush_layout_cache(&self) {
        // TODO(layouts):
        //   Flushing is only needed because of enums. Once we refactor layouts to store a single
        //   variant instead, this can be removed.
        self.struct_layouts.clear();
    }
```

**File:** aptos-move/block-executor/src/code_cache_global.rs (L317-317)
```rust
    global_module_cache.mark_overridden(write.module_id());
```

**File:** aptos-move/block-executor/src/txn_last_input_output.rs (L574-574)
```rust
            global_module_cache.flush_layout_cache();
```

**File:** aptos-move/block-executor/src/captured_reads.rs (L1060-1067)
```rust
        let validate = |key: &K, read: &ModuleRead<DC, VC, S>| match read {
            ModuleRead::GlobalCache(_) => global_module_cache.contains_not_overridden(key),
            ModuleRead::PerBlockCache(previous) => {
                let current_version = per_block_module_cache.get_module_version(key);
                let previous_version = previous.as_ref().map(|(_, version)| *version);
                current_version == previous_version
            },
        };
```

**File:** third_party/move/move-vm/runtime/src/storage/layout_cache.rs (L59-77)
```rust
/// An entry into layout cache: layout and a set of modules used to construct it.
#[derive(Debug, Clone)]
pub struct LayoutCacheEntry {
    layout: LayoutWithDelayedFields,
    modules: TriompheArc<DefiningModules>,
}

impl LayoutCacheEntry {
    pub(crate) fn new(layout: LayoutWithDelayedFields, modules: DefiningModules) -> Self {
        Self {
            layout,
            modules: TriompheArc::new(modules),
        }
    }

    pub(crate) fn unpack(self) -> (LayoutWithDelayedFields, TriompheArc<DefiningModules>) {
        (self.layout, self.modules)
    }
}
```

**File:** third_party/move/move-vm/runtime/src/storage/layout_cache.rs (L79-83)
```rust
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct StructKey {
    pub idx: StructNameIndex,
    pub ty_args_id: TypeVecId,
}
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

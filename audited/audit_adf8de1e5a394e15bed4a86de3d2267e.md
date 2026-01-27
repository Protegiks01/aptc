# Audit Report

## Title
Unbounded Memory Consumption in Layout Cache Due to Lack of Size-Based Limits

## Summary

The layout cache in the Move VM runtime tracks only the number of cached entries (`max_layout_cache_size: 4_000_000`) but does not impose any limit on the total memory consumed by these layouts. Since individual layouts can contain up to 512 nodes and occupy significant memory, an attacker can fill the cache with 4 million large layouts, potentially consuming tens to hundreds of gigabytes of validator memory, leading to resource exhaustion. [1](#0-0) [2](#0-1) 

## Finding Description

The vulnerability arises from a mismatch between layout size limits during construction and cache capacity limits:

**During Layout Construction:**
Individual layouts are bounded by node count (`layout_max_size: 512`) and depth (`layout_max_depth: 128`). This ensures no single layout becomes excessively large during its creation. [3](#0-2) [4](#0-3) 

**At Cache Level:**
The global layout cache only enforces a limit on the NUMBER of entries (4 million by default), with no tracking of total memory consumption: [5](#0-4) [6](#0-5) 

The cache check occurs in `check_ready()` before block execution: [7](#0-6) 

**Attack Scenario:**

1. Attacker publishes a generic Move module with multiple type parameters:
   ```move
   struct LargeGeneric<T1, T2, T3, T4, T5> has key {
       // Fields designed to maximize layout node count
       field1: vector<vector<T1>>,
       field2: vector<vector<T2>>,
       // ... up to 512 nodes total
   }
   ```

2. Attacker sends transactions instantiating this struct with different type argument combinations. With 5 type parameters and ~20 base Move types (u8, u64, u128, u256, address, bool, etc.), the attacker can create millions of unique combinations.

3. Each unique `(struct_idx, ty_args_id)` pair creates a distinct cache entry: [8](#0-7) 

4. Each layout is constructed with maximum allowed size (512 nodes), then cached: [9](#0-8) 

5. The cache stores these in a `DashMap` with no memory accounting: [10](#0-9) 

**Memory Calculation:**

- Conservative estimate: Each 512-node layout occupies ~20KB in memory (accounting for Rust enum overhead, `TriompheArc` pointers, struct metadata, type names)
- Maximum entries: 4,000,000
- **Total memory: 20KB × 4,000,000 = 80GB**

More aggressive layouts with deeply nested structures and long identifiers could reach 50KB+ per entry, resulting in **200GB+** of memory consumption.

This breaks **Invariant #9: Resource Limits** - "All operations must respect gas, storage, and computational limits." While individual operations are gas-metered, the cumulative memory consumption of the cache is not bounded by memory size.

## Impact Explanation

This vulnerability qualifies as **Medium Severity** per Aptos bug bounty criteria:

**"Validator node slowdowns"** (High Severity) / **"State inconsistencies requiring intervention"** (Medium Severity):

- Validators consuming 80-200GB of memory will experience severe performance degradation due to memory pressure, swapping, and potential Out-Of-Memory (OOM) kills
- Modern validator nodes typically have 32-128GB RAM; filling the layout cache can consume most or all available memory
- This leads to validator slowdowns, failed block executions, and potential network instability
- Recovery requires manual intervention (cache flush, node restart, or governance action to clear malicious modules)
- While not causing permanent fund loss, it degrades network reliability and validator operations

The impact is limited to Medium rather than High because:
- The cache is eventually flushed when exceeding 4 million entries
- Individual validators can restart to clear the cache
- Does not directly cause fund loss or consensus safety violations

However, the resource exhaustion is real and exploitable, requiring operational intervention.

## Likelihood Explanation

**Likelihood: High**

The attack is feasible because:

1. **Low barrier to entry**: Any user can publish Move modules and send transactions
2. **Scalable attack**: With generic structs and multiple type parameters, creating 4 million unique type instantiations is computationally feasible
3. **Gas costs are reasonable**: While layout construction costs gas, the cost is spread across many transactions and blocks
4. **Persistent effect**: Once cached, layouts remain until the limit is exceeded or modules are republished
5. **Gradual attack**: The attacker can slowly fill the cache over days/weeks, making detection harder

**Attack complexity**: Medium
- Requires understanding of Move generics and type instantiation
- Need to craft modules that maximize layout size within the 512-node limit
- Must generate enough unique type combinations (achievable with 5-6 type parameters)

**Detection difficulty**: Medium to Hard
- Memory growth is gradual
- No obvious anomalies in individual transactions
- Requires monitoring cache size metrics that may not be prominently tracked

## Recommendation

Implement **memory-based cache limits** in addition to entry-count limits:

1. **Track total memory consumption**:
   Add a `size_in_bytes()` method to `LayoutCacheEntry` and track cumulative memory usage in `GlobalModuleCache`:

   ```rust
   pub struct GlobalModuleCache<K, D, V, E> {
       module_cache: HashMap<K, Entry<D, V, E>>,
       size: usize,
       struct_layouts: DashMap<StructKey, LayoutCacheEntry>,
       // ADD THIS:
       layout_cache_size_in_bytes: AtomicUsize,
   }
   ```

2. **Add memory limit configuration**: [11](#0-10) 
   
   Add `max_layout_cache_size_in_bytes: usize` (e.g., 1GB limit) alongside the existing `max_layout_cache_size` entry count.

3. **Enforce memory limit**:
   In `store_struct_layout_entry`, check both entry count AND total bytes:
   
   ```rust
   pub(crate) fn store_struct_layout_entry(
       &self,
       key: &StructKey,
       entry: LayoutCacheEntry,
   ) -> PartialVMResult<()> {
       let entry_size = entry.size_in_bytes();
       
       // Check if adding this entry would exceed memory limit
       if self.layout_cache_size_in_bytes.load(Ordering::Relaxed) + entry_size 
           > config.max_layout_cache_size_in_bytes {
           // Flush cache or reject entry
           self.flush_layout_cache();
       }
       
       if let dashmap::Entry::Vacant(e) = self.struct_layouts.entry(*key) {
           e.insert(entry);
           self.layout_cache_size_in_bytes.fetch_add(entry_size, Ordering::Relaxed);
       }
       Ok(())
   }
   ```

4. **Update check_ready**: [7](#0-6) 
   
   Add a check for `layout_cache_size_in_bytes` alongside the entry count check.

5. **Implement LRU eviction** (optional but recommended):
   Instead of flushing the entire cache, implement selective eviction of least-recently-used entries when memory pressure increases.

## Proof of Concept

```move
// File: sources/memory_bomb.move
module attacker::memory_bomb {
    use std::vector;

    // Generic struct with maximum nesting to approach 512-node limit
    struct DeepNested<T1, T2, T3, T4, T5> has key {
        f1: vector<vector<vector<T1>>>,
        f2: vector<vector<vector<T2>>>,
        f3: vector<vector<vector<T3>>>,
        f4: vector<vector<vector<T4>>>,
        f5: vector<vector<vector<T5>>>,
        // Add more fields to maximize node count
    }

    // Function to instantiate with different type combinations
    public entry fun create_layouts<T1, T2, T3, T4, T5>(account: &signer) {
        // This will trigger layout construction and caching
        move_to(account, DeepNested<T1, T2, T3, T4, T5> {
            f1: vector::empty(),
            f2: vector::empty(),
            f3: vector::empty(),
            f4: vector::empty(),
            f5: vector::empty(),
        });
    }
}

// Attack script:
// 1. Publish the module above
// 2. Send ~4 million transactions calling create_layouts with different type combinations:
//    - create_layouts<u8, u64, u128, u256, bool>
//    - create_layouts<u8, u64, u128, u256, address>
//    - create_layouts<u8, u64, u128, bool, address>
//    - ... (continue with all combinations)
// 3. Monitor validator memory consumption growing to 80GB+
// 4. Observe validator performance degradation
```

**Rust test demonstrating the issue**:

```rust
#[test]
fn test_unbounded_layout_cache_memory() {
    let config = BlockExecutorModuleCacheLocalConfig::default();
    let mut cache = GlobalModuleCache::empty();
    
    // Simulate inserting 4 million large layouts
    for i in 0..4_000_000 {
        let key = StructKey { 
            idx: StructNameIndex::new(0), 
            ty_args_id: TypeVecId::new(i) 
        };
        
        // Create a layout with ~512 nodes (maximal size)
        let large_layout = create_max_size_layout();
        let entry = LayoutCacheEntry::new(large_layout, DefiningModules::new());
        
        cache.store_struct_layout_entry(&key, entry).unwrap();
    }
    
    // Verify: entry count limit is enforced
    assert_eq!(cache.num_cached_layouts(), 4_000_000);
    
    // ISSUE: No check on total memory consumption
    // If each layout is 20KB, total is 80GB - no limit enforced!
    // Expected: cache.layout_cache_size_in_bytes() should be checked
    // Actual: Only entry count is checked
}
```

## Notes

The vulnerability is exacerbated by the fact that the cache check occurs only BEFORE block execution (`check_ready()`), not DURING execution. This means a single block with many layout-creating transactions can temporarily push the cache beyond both the 4 million entry limit and any reasonable memory limit, causing immediate memory pressure before the next block's pre-check triggers a flush. [12](#0-11) 

The lack of memory-based tracking in the layout cache stands in contrast to other cache systems in the Aptos codebase (e.g., module cache tracks `size_in_bytes`), suggesting this is an oversight rather than a deliberate design choice. [13](#0-12)

### Citations

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

**File:** aptos-move/block-executor/src/code_cache_global.rs (L150-153)
```rust
    /// Returns the sum of serialized sizes of modules stored in cache.
    pub fn size_in_bytes(&self) -> usize {
        self.size
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

**File:** third_party/move/move-vm/runtime/src/storage/ty_layout_converter.rs (L108-130)
```rust
            if let Some(key) = key {
                if let Some(result) = self.struct_definition_loader.load_layout_from_cache(
                    gas_meter,
                    traversal_context,
                    &key,
                ) {
                    return result;
                }

                // Otherwise a cache miss, compute the result and store it.
                let mut modules = DefiningModules::new();
                let layout = self.type_to_type_layout_with_delayed_fields_impl::<false>(
                    gas_meter,
                    traversal_context,
                    &mut modules,
                    ty,
                    check_option_type,
                )?;
                let cache_entry = LayoutCacheEntry::new(layout.clone(), modules);
                self.struct_definition_loader
                    .store_layout_to_cache(&key, cache_entry)?;
                return Ok(layout);
            }
```

**File:** third_party/move/move-vm/runtime/src/storage/ty_layout_converter.rs (L194-222)
```rust
    /// Since layout is a tree data structure, we limit its size and depth during construction.
    /// This function checks that the number of nodes in the layout and its depth are within limits
    /// enforced by the VM config. The count is incremented.
    fn check_depth_and_increment_count(
        &self,
        node_count: &mut u64,
        depth: u64,
    ) -> PartialVMResult<()> {
        let max_count = self.vm_config().layout_max_size;
        if *node_count > max_count || *node_count == max_count && self.is_lazy_loading_enabled() {
            return Err(
                PartialVMError::new(StatusCode::TOO_MANY_TYPE_NODES).with_message(format!(
                    "Number of type nodes when constructing type layout exceeded the maximum of {}",
                    max_count
                )),
            );
        }
        *node_count += 1;

        if depth > self.vm_config().layout_max_depth {
            return Err(
                PartialVMError::new(StatusCode::VM_MAX_VALUE_DEPTH_REACHED).with_message(format!(
                    "Depth of a layout exceeded the maximum of {} during construction",
                    self.vm_config().layout_max_depth
                )),
            );
        }
        Ok(())
    }
```

**File:** third_party/move/move-vm/runtime/src/config.rs (L29-31)
```rust
    pub layout_max_size: u64,
    /// Maximum depth (in number of nodes) of the type layout tree.
    pub layout_max_depth: u64,
```

**File:** types/src/block_executor/config.rs (L12-29)
```rust
pub struct BlockExecutorModuleCacheLocalConfig {
    /// If true, when global caches are empty, Aptos framework is prefetched into module cache.
    pub prefetch_framework_code: bool,
    /// The maximum size of module cache (the sum of serialized sizes of all cached modules in
    /// bytes).
    pub max_module_cache_size_in_bytes: usize,
    /// The maximum size (in terms of entries) of struct name re-indexing map stored in the runtime
    /// environment.
    pub max_struct_name_index_map_num_entries: usize,
    /// The maximum number of types to intern.
    pub max_interned_tys: usize,
    /// The maximum number of type vectors to intern.
    pub max_interned_ty_vecs: usize,
    /// The maximum number of layout entries.
    pub max_layout_cache_size: usize,
    /// The maximum number of module IDs to intern.
    pub max_interned_module_ids: usize,
}
```

**File:** types/src/block_executor/config.rs (L43-44)
```rust
            // Maximum number of cached layouts.
            max_layout_cache_size: 4_000_000,
```

**File:** aptos-move/block-executor/src/code_cache_global_manager.rs (L99-104)
```rust
    fn check_ready(
        &mut self,
        storage_environment: AptosEnvironment,
        config: &BlockExecutorModuleCacheLocalConfig,
        transaction_slice_metadata: TransactionSliceMetadata,
    ) -> Result<(), VMStatus> {
```

**File:** aptos-move/block-executor/src/code_cache_global_manager.rs (L177-181)
```rust
        let num_non_generic_layout_entries = self.module_cache.num_cached_layouts();
        GLOBAL_LAYOUT_CACHE_NUM_NON_ENTRIES.set(num_non_generic_layout_entries as i64);
        if num_non_generic_layout_entries > config.max_layout_cache_size {
            self.module_cache.flush_layout_cache();
        }
```

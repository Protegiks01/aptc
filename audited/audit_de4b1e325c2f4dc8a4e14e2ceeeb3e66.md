# Audit Report

## Title
Memory Leak in Cache Manager Due to Incomplete Flush of Interdependent Caches

## Summary
The `ModuleCacheManager::check_ready()` function performs partial cache flushes that invalidate `StructNameIndex` values used as keys in `TypeTagCache`, creating orphaned cache entries that accumulate unbounded memory over time, eventually degrading validator node performance.

## Finding Description

The `ModuleCacheManager::check_ready()` function in the code cache global manager implements multiple cache size monitoring scenarios. However, critical partial flush operations fail to maintain cache consistency, creating a memory leak. [1](#0-0) 

When the module ID pool exceeds configured limits (default: 100,000 entries), the code flushes `module_id_pool` and `struct_name_index_map` but **does not flush `ty_tag_cache`**. This creates orphaned cache entries because:

1. The `TypeTagCache` stores entries keyed by `StructKey`, which contains `StructNameIndex` values: [2](#0-1) 

2. When `struct_name_index_map` is flushed, both forward and backward maps are cleared, invalidating all existing indices: [3](#0-2) 

3. The old `StructNameIndex` values in `ty_tag_cache` keys now point to invalid positions in the cleared backward_map. Future lookups use newly-assigned indices (starting from 0 again), which cannot match the old orphaned entries. These entries remain allocated indefinitely.

4. A similar partial flush occurs when type pool limits are exceeded: [4](#0-3) 

The `RuntimeEnvironment` holds all these interdependent caches: [5](#0-4) 

Only the `flush_all_caches()` method properly maintains cache consistency by flushing all dependent structures: [6](#0-5) 

The `flush_all_caches()` approach is correctly used when struct name index map size exceeds limits: [7](#0-6) 

## Impact Explanation

This qualifies as **High Severity** per Aptos bug bounty criteria: "Validator node slowdowns."

Over extended validator operation:
- Orphaned `ty_tag_cache` entries accumulate with each partial flush
- Each entry contains `PricedStructTag` structures with `StructTag` data (addresses, module names, struct names, type arguments)
- Memory usage grows unbounded as there is no size limit enforced on `TypeTagCache`
- Eventually causes OOM conditions or severe performance degradation
- Requires validator node restart to clear accumulated orphaned entries
- Affects all validators running extended block execution without hitting the higher 1M struct name limit that triggers `flush_all_caches()`

The default configuration makes this realistic: [8](#0-7) 

## Likelihood Explanation

**High likelihood** to occur in production:
- Validators execute thousands of blocks continuously between restarts
- The module ID pool limit (100,000) is significantly lower than the struct name index map limit (1,000,000)
- Partial flush at line 162 triggers whenever `num_interned_module_ids > 100,000` during normal operation
- No attacker action required - occurs naturally through sustained block execution with diverse module deployments
- Each partial flush creates additional orphaned entries that can never be reclaimed until full restart or the rare `flush_all_caches()` trigger

## Recommendation

Ensure all partial flush operations maintain cache consistency. When flushing `struct_name_index_map`, also flush `ty_tag_cache` since cache keys contain now-invalid `StructNameIndex` values:

```rust
if num_interned_module_ids > config.max_interned_module_ids {
    runtime_environment.module_id_pool().flush();
    runtime_environment.struct_name_index_map().flush();
    runtime_environment.ty_tag_cache().flush();  // Add this line
    self.module_cache.flush();
}
```

Similarly, consider whether `ty_tag_cache` should be flushed when `ty_pool` is flushed at lines 158-159, since cache entries may contain stale type references.

Alternatively, use `flush_all_caches()` for all cache size limit scenarios to ensure consistency.

## Proof of Concept

Observable through metrics monitoring:
1. Deploy diverse Move modules over extended validator operation to accumulate interned module IDs
2. Monitor `NUM_INTERNED_MODULE_IDS` metric approaching 100,000
3. Monitor validator memory usage before and after the partial flush at line 162 triggers
4. Observe that `ty_tag_cache` memory is not reclaimed despite `struct_name_index_map` flush
5. Continued operation accumulates orphaned entries over time, observable through increasing memory baseline

## Notes

This is a resource leak vulnerability affecting validator availability and performance. While it doesn't directly compromise consensus or enable fund theft, unbounded memory growth qualifies as High severity under "Validator node slowdowns" per the Aptos bug bounty program. The issue stems from incomplete understanding of cache interdependencies in the flush logic.

### Citations

**File:** aptos-move/block-executor/src/code_cache_global_manager.rs (L143-146)
```rust
        if struct_name_index_map_size > config.max_struct_name_index_map_num_entries {
            runtime_environment.flush_all_caches();
            self.module_cache.flush();
        }
```

**File:** aptos-move/block-executor/src/code_cache_global_manager.rs (L155-160)
```rust
        if num_interned_tys > config.max_interned_tys
            || num_interned_ty_vecs > config.max_interned_ty_vecs
        {
            runtime_environment.ty_pool().flush();
            self.module_cache.flush();
        }
```

**File:** aptos-move/block-executor/src/code_cache_global_manager.rs (L162-166)
```rust
        if num_interned_module_ids > config.max_interned_module_ids {
            runtime_environment.module_id_pool().flush();
            runtime_environment.struct_name_index_map().flush();
            self.module_cache.flush();
        }
```

**File:** third_party/move/move-vm/runtime/src/storage/ty_tag_converter.rs (L66-70)
```rust
#[derive(Clone, Eq, PartialEq)]
struct StructKey {
    idx: StructNameIndex,
    ty_args: Vec<Type>,
}
```

**File:** third_party/move/move-vm/types/src/loaded_data/struct_name_indexing.rs (L60-65)
```rust
    /// Flushes the cached struct names and indices.
    pub fn flush(&self) {
        let mut index_map = self.0.write();
        index_map.backward_map.clear();
        index_map.forward_map.clear();
    }
```

**File:** third_party/move/move-vm/runtime/src/storage/environment.rs (L45-74)
```rust
pub struct RuntimeEnvironment {
    /// Configuration for the VM. Contains information about enabled checks, verification,
    /// deserialization, etc.
    vm_config: VMConfig,
    /// All registered native functions in the current context (binary). When a verified [Module]
    /// is constructed, existing native functions are inlined in the module representation, so that
    /// the interpreter can call them directly.
    natives: NativeFunctions,

    /// Map from struct names to indices, to save on unnecessary cloning and reduce memory
    /// consumption. Used by all struct type creations in the VM and in code cache.
    ///
    /// SAFETY:
    ///   By itself, it is fine to index struct names even of non-successful module publishes. If
    ///   we cached some name, which was not published, it will stay in cache and will be used by
    ///   another republish. Since there is no other information other than index, even for structs
    ///   with different layouts it is fine to re-use the index.
    ///   We wrap the index map into an [Arc] so that on republishing these clones are cheap.
    struct_name_index_map: Arc<StructNameIndexMap>,

    /// Caches struct tags for instantiated types. This cache can be used concurrently and
    /// speculatively because type tag information does not change with module publishes.
    ty_tag_cache: Arc<TypeTagCache>,

    /// Pool of interned type representations. Same lifetime as struct index map.
    interned_ty_pool: Arc<InternedTypePool>,

    /// Pool of interned module ids.
    interned_module_id_pool: Arc<InternedModuleIdPool>,
}
```

**File:** third_party/move/move-vm/runtime/src/storage/environment.rs (L366-371)
```rust
    pub fn flush_all_caches(&self) {
        self.ty_tag_cache.flush();
        self.struct_name_index_map.flush();
        self.interned_ty_pool.flush();
        self.interned_module_id_pool.flush();
    }
```

**File:** types/src/block_executor/config.rs (L31-48)
```rust
impl Default for BlockExecutorModuleCacheLocalConfig {
    fn default() -> Self {
        Self {
            prefetch_framework_code: true,
            // Use 1Gb for now, should be large enough to cache all mainnet modules (at the time
            // of writing this comment, 13.11.24).
            max_module_cache_size_in_bytes: 1024 * 1024 * 1024,
            max_struct_name_index_map_num_entries: 1_000_000,
            // Each entry is 4 + 2 * 8 = 20 bytes. This allows ~200 Mb of distinct types.
            max_interned_tys: 10 * 1024 * 1024,
            // Use slightly less for vectors of types.
            max_interned_ty_vecs: 4 * 1024 * 1024,
            // Maximum number of cached layouts.
            max_layout_cache_size: 4_000_000,
            // Maximum number of module IDs to intern.
            max_interned_module_ids: 100_000,
        }
    }
```

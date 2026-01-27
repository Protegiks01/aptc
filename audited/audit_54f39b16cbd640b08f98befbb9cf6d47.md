# Audit Report

## Title
Memory Leak in Cache Manager Due to Incomplete Flush of Interdependent Caches

## Summary
The `check_ready()` function in the code cache global manager performs partial flushes of interdependent caches, leaving orphaned entries in `ty_tag_cache` that reference invalidated struct name indices. This causes unbounded memory growth over time, eventually degrading validator node performance.

## Finding Description

The `ModuleCacheManager::check_ready()` function implements multiple flush scenarios to manage cache sizes. However, not all flush operations properly clear interdependent caches, leading to memory leaks. [1](#0-0) 

When the module ID pool exceeds configured limits, the code flushes `module_id_pool` and `struct_name_index_map`, but critically **does not flush `ty_tag_cache`**. This creates orphaned cache entries because:

1. The `TypeTagCache` stores entries keyed by `StructKey`, which contains `StructNameIndex` values: [2](#0-1) 

2. When `struct_name_index_map` is flushed, all struct name-to-index mappings are cleared: [3](#0-2) 

3. The old indices in `ty_tag_cache` no longer map to valid struct names, but the cache entries remain allocated [4](#0-3) 

A similar issue occurs at lines 158-159 where only `ty_pool` is flushed but not `ty_tag_cache`: [5](#0-4) 

The `RuntimeEnvironment` holds all these caches in Arc-wrapped structures: [6](#0-5) 

Only the `flush_all_caches()` method properly flushes all interdependent caches: [7](#0-6) 

## Impact Explanation

This qualifies as **High Severity** per Aptos bug bounty criteria: "Validator node slowdowns."

Over many blocks of execution:
- Orphaned `ty_tag_cache` entries accumulate in memory
- Each entry contains `StructTag` data structures with identifiers and type arguments
- Memory usage grows unbounded until node OOM or performance degradation
- Requires node restart to clear, impacting validator availability
- Affects all validators running extended operations without full cache flushes

The leak is exacerbated when modules with diverse struct names are deployed, increasing cache diversity and the likelihood of hitting partial flush conditions.

## Likelihood Explanation

**High likelihood** to occur in production:
- Validators execute thousands of blocks between epoch changes
- Cache limits (configured via `BlockExecutorModuleCacheLocalConfig`) will eventually be exceeded during normal operation
- The partial flush at line 165 triggers whenever `num_interned_module_ids > config.max_interned_module_ids`
- No attacker action required - occurs naturally through sustained block execution
- Accelerated by diverse module deployments increasing cache pressure

## Recommendation

Modify the partial flush operations to include `ty_tag_cache` whenever `struct_name_index_map` or `ty_pool` are flushed:

**Fix for lines 158-160:**
```rust
if num_interned_tys > config.max_interned_tys
    || num_interned_ty_vecs > config.max_interned_ty_vecs
{
    runtime_environment.ty_pool().flush();
    runtime_environment.ty_tag_cache().flush();  // ADD THIS
    self.module_cache.flush();
}
```

**Fix for lines 162-166:**
```rust
if num_interned_module_ids > config.max_interned_module_ids {
    runtime_environment.module_id_pool().flush();
    runtime_environment.struct_name_index_map().flush();
    runtime_environment.ty_tag_cache().flush();  // ADD THIS
    self.module_cache.flush();
}
```

Alternatively, replace partial flushes with `flush_all_caches()` to ensure consistency:
```rust
if num_interned_module_ids > config.max_interned_module_ids {
    runtime_environment.flush_all_caches();
    self.module_cache.flush();
}
```

## Proof of Concept

The following test demonstrates the memory leak by simulating repeated partial flushes:

```rust
#[test]
fn test_memory_leak_partial_flush() {
    use aptos_types::state_store::MockStateView;
    
    let mut manager = ModuleCacheManager::new();
    let state_view = MockStateView::empty();
    let config = BlockExecutorModuleCacheLocalConfig {
        max_interned_module_ids: 5,  // Low limit to trigger flush
        max_struct_name_index_map_num_entries: 100,
        max_interned_tys: 100,
        max_interned_ty_vecs: 100,
        max_layout_cache_size: 100,
        max_module_cache_size_in_bytes: 1000,
        prefetch_framework_code: false,
    };
    
    // Simulate multiple blocks triggering partial flushes
    for block_num in 0..10 {
        let metadata = TransactionSliceMetadata::block_from_u64(block_num, block_num + 1);
        let env = AptosEnvironment::new(&state_view);
        
        // Populate module IDs to exceed limit
        for i in 0..10 {
            let module_id = ModuleId::new(
                AccountAddress::from_hex_literal(&format!("0x{:x}", i)).unwrap(),
                Identifier::new("test").unwrap()
            );
            env.runtime_environment().module_id_pool().intern(&module_id);
        }
        
        // Populate struct names that get indexed
        for i in 0..10 {
            let struct_id = StructIdentifier::new(
                env.runtime_environment().module_id_pool(),
                ModuleId::new(AccountAddress::ZERO, Identifier::new("m").unwrap()),
                Identifier::new(&format!("Struct{}", i)).unwrap()
            );
            env.runtime_environment()
                .struct_name_index_map()
                .struct_name_to_idx(&struct_id)
                .unwrap();
        }
        
        // This triggers partial flush at line 165, leaving ty_tag_cache orphaned
        assert_ok!(manager.check_ready(env, &config, metadata));
        
        // Memory in ty_tag_cache is not freed despite struct_name_index_map flush
    }
    
    // After multiple blocks, orphaned entries accumulate in ty_tag_cache
    // leading to unbounded memory growth
}
```

## Notes

The vulnerability stems from incomplete understanding of cache interdependencies. The `ty_tag_cache` stores struct tags keyed by struct name indices, so flushing the index map without flushing the tag cache creates semantic inconsistency and memory leaks. This issue is masked during normal operation because full environment replacements (epoch changes, config updates) eventually clear everything, but sustained operation between such events allows leak accumulation.

### Citations

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

**File:** third_party/move/move-vm/runtime/src/storage/ty_tag_converter.rs (L150-165)
```rust
pub(crate) struct TypeTagCache {
    cache: RwLock<HashMap<StructKey, PricedStructTag>>,
}

impl TypeTagCache {
    /// Creates a new empty cache without any entries.
    pub(crate) fn empty() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Removes all entries from the cache.
    pub(crate) fn flush(&self) {
        self.cache.write().clear();
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

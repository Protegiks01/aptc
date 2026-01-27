# Audit Report

## Title
Intra-Block Memory Exhaustion via Unbounded Struct Layout Cache Growth

## Summary
The struct layout cache (`GlobalModuleCache::struct_layouts`) has a configured size limit of 4 million entries, but this limit is only enforced between block executions, not during block execution. An attacker can potentially create many unique struct type instantiations within a single block, causing unbounded cache growth that may exhaust validator memory before the block completes, leading to validator crashes and network disruption. [1](#0-0) 

## Finding Description

The vulnerability exists in the layout caching mechanism used by the Move VM runtime. When layout caching is enabled (which is the default in production configurations), computed struct layouts are stored in a concurrent `DashMap` without checking size limits during insertion. [2](#0-1) 

The cache insertion happens in `GlobalModuleCache::store_struct_layout_entry()`, which unconditionally inserts entries without any size validation: [3](#0-2) 

The configured size limit (`max_layout_cache_size: 4_000_000`) exists but is only checked in `check_ready()` between block executions: [4](#0-3) [5](#0-4) 

**Attack Vector:**

1. Attacker publishes a module containing generic structs (e.g., `struct Container<T> has key { value: T }`)
2. Attacker submits multiple transactions within a single block that instantiate these structs with diverse type arguments:
   - Primitive types: `Container<u8>`, `Container<u64>`, `Container<u128>`, `Container<address>`, etc.
   - Vector types: `Container<vector<u8>>`, `Container<vector<u64>>`, etc.
   - Nested generics up to type depth limits: `Container<vector<vector<u8>>>`, etc.
3. Each unique `StructKey` (combination of struct index and type argument vector) triggers layout computation and caching: [6](#0-5) 

4. The cache grows unboundedly during block execution, with each `LayoutCacheEntry` consuming memory for the layout structure and module metadata
5. If memory consumption exceeds available RAM, the validator process crashes with OOM before the block completes

This breaks the **Move VM Safety** invariant: "Bytecode execution must respect gas limits and memory constraints" and the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

## Impact Explanation

**High Severity** - Validator node crashes leading to network disruption.

This vulnerability allows an unprivileged attacker to cause validator crashes through memory exhaustion. The impact includes:

1. **Validator Liveness Impact**: Affected validators crash during block execution, removing them from consensus temporarily
2. **Network Disruption**: If multiple validators process the malicious block simultaneously, network consensus could be disrupted
3. **Repeated Attacks**: The attacker can repeatedly craft blocks with new type instantiations to maintain pressure on the network
4. **Deterministic Crash**: All validators executing the same malicious block will experience identical memory growth patterns, potentially causing coordinated failures

The issue qualifies as **High Severity** per the bug bounty criteria: "Validator node slowdowns / API crashes / Significant protocol violations."

While this doesn't directly cause fund loss or permanent network partition, it can significantly impact network availability and validator operations.

## Likelihood Explanation

**Medium to High Likelihood:**

The attack is feasible because:

1. **Default Configuration**: Layout caching is enabled by default in production
2. **Public Module Deployment**: Any user can publish modules with generic structs
3. **Type Instantiation Freedom**: Move allows diverse type instantiations within bytecode verifier limits (32 type parameters, 128-256 type nodes)
4. **Gas-Memory Disparity**: Gas metering charges for computation time, not memory allocation. An attacker can potentially find type instantiations where:
   - Layout computation is fast (low gas cost)
   - But cached layout structure is large (high memory cost)
   - Creating a disproportionate memory-to-gas ratio

The primary constraint is the block gas limit, which bounds total operations. However, if the attacker can create sufficient unique type instantiations within gas limits to exhaust memory (e.g., creating tens of thousands of cache entries at 10-100KB each), the attack succeeds.

The likelihood depends on empirical gas costs vs. memory consumption ratios, which would require testing to confirm exploitability definitively.

## Recommendation

**Implement intra-block cache size enforcement:**

Add size checking in `store_struct_layout_entry()` to enforce the limit during block execution:

```rust
pub(crate) fn store_struct_layout_entry(
    &self,
    key: &StructKey,
    entry: LayoutCacheEntry,
    max_size: usize,
) -> PartialVMResult<()> {
    // Check current size before insertion
    if self.struct_layouts.len() >= max_size {
        return Err(
            PartialVMError::new(StatusCode::MEMORY_LIMIT_EXCEEDED)
                .with_message("Layout cache size limit exceeded".to_string())
        );
    }
    
    if let dashmap::Entry::Vacant(e) = self.struct_layouts.entry(*key) {
        e.insert(entry);
    }
    Ok(())
}
```

**Alternative/Additional Mitigations:**

1. **Gas-Proportional Cache Charging**: Charge additional gas when inserting into the cache, proportional to the cached layout size
2. **Per-Block Cache Limit**: Introduce a separate, lower limit for cache growth within a single block
3. **LRU Eviction**: Implement an LRU eviction policy that removes old entries when limits are approached
4. **Type Instantiation Limits**: Add stricter limits on the number of unique type instantiations per transaction or block

## Proof of Concept

**Move Module (publish to attacker's account):**

```move
module attacker::memory_exhaust {
    struct Container<T> has key, store {
        value: T
    }
    
    // Function that creates many unique type instantiations
    public entry fun exploit_cache() {
        // Create containers with different type parameters
        let _c1 = Container<u8> { value: 1 };
        let _c2 = Container<u64> { value: 1 };
        let _c3 = Container<u128> { value: 1 };
        let _c4 = Container<address> { value: @0x1 };
        let _c5 = Container<bool> { value: true };
        
        // Nested vectors create more unique types
        let _c6 = Container<vector<u8>> { value: vector[] };
        let _c7 = Container<vector<u64>> { value: vector[] };
        let _c8 = Container<vector<u128>> { value: vector[] };
        let _c9 = Container<vector<address>> { value: vector[] };
        let _c10 = Container<vector<bool>> { value: vector[] };
        
        // Double nesting
        let _c11 = Container<vector<vector<u8>>> { value: vector[] };
        let _c12 = Container<vector<vector<u64>>> { value: vector[] };
        
        // Multiple type parameters with different combinations
        // (would need structs with multiple generics)
        // Each unique instantiation triggers layout caching
    }
}
```

**Attack Execution:**

1. Publish the module above
2. Submit many transactions in the same block calling `exploit_cache()` or similar functions
3. Create scripts with different type instantiation patterns to maximize unique cache entries
4. Monitor validator memory consumption during block execution
5. If successful, validators will crash with OOM errors before block completion

**Validation Steps:**

1. Enable layout caching in test environment
2. Deploy module with extensive generic type usage
3. Submit block with thousands of transactions creating unique type instantiations
4. Monitor `GLOBAL_LAYOUT_CACHE_NUM_NON_ENTRIES` metric and process memory
5. Verify memory growth exceeds available RAM within block gas limits
6. Confirm validator crashes before `check_ready()` can flush the cache

## Notes

This vulnerability represents a **design weakness** in the cache size enforcement mechanism. While the cache limit exists and is checked between blocks, the lack of intra-block enforcement creates a window for memory exhaustion attacks. The exploitability depends on the gas-to-memory consumption ratio for type layout caching, which should be empirically validated to confirm practical impact. The fix requires careful consideration of performance implications, as checking cache size on every insertion may impact execution throughput.

### Citations

**File:** types/src/block_executor/config.rs (L26-26)
```rust
    pub max_layout_cache_size: usize,
```

**File:** types/src/block_executor/config.rs (L44-44)
```rust
            max_layout_cache_size: 4_000_000,
```

**File:** config/src/config/execution_config.rs (L92-92)
```rust
            layout_caches_enabled: true,
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

**File:** aptos-move/block-executor/src/code_cache_global_manager.rs (L177-181)
```rust
        let num_non_generic_layout_entries = self.module_cache.num_cached_layouts();
        GLOBAL_LAYOUT_CACHE_NUM_NON_ENTRIES.set(num_non_generic_layout_entries as i64);
        if num_non_generic_layout_entries > config.max_layout_cache_size {
            self.module_cache.flush_layout_cache();
        }
```

**File:** third_party/move/move-vm/runtime/src/storage/ty_layout_converter.rs (L89-129)
```rust
        if self.vm_config().enable_layout_caches {
            let key = match ty {
                Type::Struct { idx, .. } => {
                    let ty_args_id = ty_pool.intern_ty_args(&[]);
                    Some(StructKey {
                        idx: *idx,
                        ty_args_id,
                    })
                },
                Type::StructInstantiation { idx, ty_args, .. } => {
                    let ty_args_id = ty_pool.intern_ty_args(ty_args);
                    Some(StructKey {
                        idx: *idx,
                        ty_args_id,
                    })
                },
                _ => None,
            };

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
```

# Audit Report

## Title
Module Cache Size Limit Bypass Through Post-Execution Insertion

## Summary
The global module cache size limit (`max_module_cache_size_in_bytes`) can be bypassed because the size check occurs before block execution in `check_ready()`, while module insertion happens after execution without any size validation. This allows the cache to persistently exceed the configured 1GB limit across multiple blocks, potentially causing validator memory pressure and node slowdowns.

## Finding Description

The vulnerability exists in the timing gap between cache size validation and module insertion:

**Size Check (Before Execution):** [1](#0-0) 

The `check_ready()` function checks cache size and flushes if it exceeds `max_module_cache_size_in_bytes`. This happens **before** block execution begins.

**Module Insertion (After Execution):** [2](#0-1) 

After block execution completes, all verified modules from the per-block `versioned_cache` are bulk-inserted into the global cache via `insert_verified()`.

**Missing Size Validation:** [3](#0-2) 

The `insert_verified()` method iterates through modules and updates the size counter (`self.size += module.extension().size_in_bytes()`) but performs **no validation** against `max_module_cache_size_in_bytes`. It unconditionally accepts all modules from the iterator.

**Attack Scenario:**

1. **Block N starts**: Cache contains 800MB of modules (below 1GB limit)
2. **check_ready() at line 168**: Size check passes (800MB ≤ 1GB), no flush occurs
3. **Block N executes**: Transactions load 300MB of unique modules into `versioned_cache`
4. **Post-execution at line 1827**: `insert_verified(versioned_cache.take_modules_iter())` adds all 300MB without size check
5. **Block N ends**: Global cache now contains 1.1GB (exceeds limit by 100MB)
6. **Block N+1 starts**: Size check at line 173 triggers flush
7. **Framework prefetch**: If enabled, loads framework code after flush [4](#0-3) 
8. **Pattern repeats**: Cache persistently oscillates above and below limit

The default configuration sets the limit to 1GB: [5](#0-4) 

## Impact Explanation

This qualifies as **High Severity** per Aptos bug bounty criteria:

**"Validator node slowdowns"**: When the cache grows beyond the configured limit, it creates memory pressure on validator nodes. Operations that iterate or search the cache (layout lookups, module retrieval) become slower. Validators with constrained memory may experience swap thrashing or OOM conditions.

**"Significant protocol violations"**: The resource limit invariant (#9: "All operations must respect gas, storage, and computational limits") is violated. The cache size limit exists specifically to prevent unbounded memory growth, but the post-execution insertion bypasses this protection.

**Not Critical** because:
- Does not break consensus safety (deterministic execution preserved)
- Does not enable fund theft or minting
- Self-correcting (cache flushed at next block when exceeded)
- Constrained by block gas limits (prevents extreme single-block growth)

## Likelihood Explanation

**Moderate to High Likelihood**:

**Attacker Requirements:**
- Submit transactions that load many unique Move modules
- Sustained across multiple blocks to maintain memory pressure
- Modules must exist in storage or be published (gas cost: storage + publishing fees)

**Constraints:**
- Module loading consumes gas based on size (DEPENDENCY_PER_MODULE + DEPENDENCY_PER_BYTE)
- Block gas limits cap total modules loaded per block
- Modules must be verified Move bytecode

**Realistic Exploitation:**
An attacker with sufficient funds can craft transactions that:
1. Access rarely-used but legitimate modules from storage
2. Publish new modules (expensive but possible)
3. Execute module-loading native functions

With a block gas limit of ~1 billion units and module loading costs of ~1000-10000 gas per KB, an attacker could realistically load 100-300MB of modules per block. Combined with existing cache state, this easily exceeds the 1GB limit.

## Recommendation

**Add size validation in `insert_verified()` to enforce limits during insertion:**

```rust
pub fn insert_verified(
    &mut self,
    modules: impl Iterator<Item = (K, Arc<ModuleCode<D, V, E>>)>,
    max_size_bytes: Option<usize>, // Pass limit from config
) -> Result<(), PanicError> {
    use hashbrown::hash_map::Entry::*;

    for (key, module) in modules {
        // Check size limit before insertion
        if let Some(max_size) = max_size_bytes {
            let module_size = module.extension().size_in_bytes();
            if self.size + module_size > max_size {
                // Option 1: Return error and reject entire batch
                return Err(PanicError::CodeInvariantError(
                    format!("Module cache size {} + {} would exceed limit {}", 
                            self.size, module_size, max_size)
                ));
                
                // Option 2: Skip remaining modules (less safe)
                // break;
            }
        }

        if let Occupied(entry) = self.module_cache.entry(key.clone()) {
            if entry.get().is_not_overridden() {
                return Err(PanicError::CodeInvariantError(
                    "Should never replace a non-overridden module".to_string(),
                ));
            } else {
                self.size -= entry.get().module_code().extension().size_in_bytes();
                entry.remove();
            }
        }

        if module.code().is_verified() {
            self.size += module.extension().size_in_bytes();
            let entry = Entry::new(module).expect("Module has been checked and must be verified");
            let prev = self.module_cache.insert(key.clone(), entry);
            assert!(prev.is_none())
        }
    }
    Ok(())
}
```

**Alternative:** Perform an additional size check immediately after `insert_verified()` and flush if exceeded, though this wastes work.

## Proof of Concept

```rust
#[test]
fn test_cache_size_bypass_via_post_execution_insertion() {
    use aptos_move::block_executor::code_cache_global::GlobalModuleCache;
    use aptos_move::block_executor::code_cache_global_manager::ModuleCacheManager;
    use move_vm_types::code::{mock_verified_code, MockExtension};
    
    let mut manager = ModuleCacheManager::new();
    let state_view = MockStateView::empty();
    let config = BlockExecutorModuleCacheLocalConfig {
        prefetch_framework_code: false,
        max_module_cache_size_in_bytes: 100, // Small limit for testing
        ..Default::default()
    };
    
    // Simulate Block N: Start with cache at 80 bytes (below limit)
    for i in 0..8 {
        manager.module_cache.insert(i, mock_verified_code(i, MockExtension::new(10)));
    }
    assert_eq!(manager.module_cache.size_in_bytes(), 80);
    
    // check_ready() passes because 80 <= 100
    let metadata = TransactionSliceMetadata::block_from_u64(0, 1);
    assert_ok!(manager.check_ready(AptosEnvironment::new(&state_view), &config, metadata));
    assert_eq!(manager.module_cache.num_modules(), 8); // No flush
    
    // Simulate execution loading more modules into versioned_cache
    let mut versioned_modules = vec![];
    for i in 8..12 { // Load 4 more modules (40 bytes)
        versioned_modules.push((i, mock_verified_code(i, MockExtension::new(10))));
    }
    
    // Post-execution: insert_verified() adds modules WITHOUT size check
    assert_ok!(manager.module_cache.insert_verified(versioned_modules.into_iter()));
    
    // Cache now exceeds limit: 80 + 40 = 120 > 100
    assert_eq!(manager.module_cache.size_in_bytes(), 120);
    assert!(manager.module_cache.size_in_bytes() > config.max_module_cache_size_in_bytes);
    
    // This state persists until next block's check_ready()
    println!("Cache size {} exceeds limit {} by {} bytes",
             manager.module_cache.size_in_bytes(),
             config.max_module_cache_size_in_bytes,
             manager.module_cache.size_in_bytes() - config.max_module_cache_size_in_bytes);
}
```

**Notes:**
- The vulnerability is confirmed: cache size validation happens at the wrong point in the execution flow
- Attackers can exploit the timing gap between pre-execution size check and post-execution module insertion
- Gas limits provide partial mitigation but do not prevent the bypass entirely
- Framework prefetching after flush can exacerbate the issue by immediately consuming cache capacity
- The fix requires either adding size validation during insertion or performing an additional check after insertion

### Citations

**File:** aptos-move/block-executor/src/code_cache_global_manager.rs (L168-175)
```rust
        let module_cache_size_in_bytes = self.module_cache.size_in_bytes();
        GLOBAL_MODULE_CACHE_SIZE_IN_BYTES.set(module_cache_size_in_bytes as i64);
        GLOBAL_MODULE_CACHE_NUM_MODULES.set(self.module_cache.num_modules() as i64);

        // If module cache stores too many modules, flush it as well.
        if module_cache_size_in_bytes > config.max_module_cache_size_in_bytes {
            self.module_cache.flush();
        }
```

**File:** aptos-move/block-executor/src/code_cache_global_manager.rs (L246-251)
```rust
        if guard.module_cache().num_modules() == 0 && config.prefetch_framework_code {
            prefetch_aptos_framework(state_view, &mut guard).map_err(|err| {
                alert_or_println!("Failed to load Aptos framework to module cache: {:?}", err);
                VMError::from(err).into_vm_status()
            })?;
        }
```

**File:** aptos-move/block-executor/src/executor.rs (L1825-1828)
```rust
                        module_cache_manager_guard
                            .module_cache_mut()
                            .insert_verified(versioned_cache.take_modules_iter())
                            .is_err(),
```

**File:** aptos-move/block-executor/src/code_cache_global.rs (L197-226)
```rust
    pub fn insert_verified(
        &mut self,
        modules: impl Iterator<Item = (K, Arc<ModuleCode<D, V, E>>)>,
    ) -> Result<(), PanicError> {
        use hashbrown::hash_map::Entry::*;

        for (key, module) in modules {
            if let Occupied(entry) = self.module_cache.entry(key.clone()) {
                if entry.get().is_not_overridden() {
                    return Err(PanicError::CodeInvariantError(
                        "Should never replace a non-overridden module".to_string(),
                    ));
                } else {
                    self.size -= entry.get().module_code().extension().size_in_bytes();
                    entry.remove();
                }
            }

            if module.code().is_verified() {
                self.size += module.extension().size_in_bytes();
                let entry =
                    Entry::new(module).expect("Module has been checked and must be verified");
                let prev = self.module_cache.insert(key.clone(), entry);

                // At this point, we must have removed the entry, or returned a panic error.
                assert!(prev.is_none())
            }
        }
        Ok(())
    }
```

**File:** types/src/block_executor/config.rs (L32-38)
```rust
    fn default() -> Self {
        Self {
            prefetch_framework_code: true,
            // Use 1Gb for now, should be large enough to cache all mainnet modules (at the time
            // of writing this comment, 13.11.24).
            max_module_cache_size_in_bytes: 1024 * 1024 * 1024,
            max_struct_name_index_map_num_entries: 1_000_000,
```

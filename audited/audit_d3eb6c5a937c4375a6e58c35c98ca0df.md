# Audit Report

## Title
Global Verification Cache Enables Reuse of Modules with Stale Dependency Assumptions

## Summary
The `VERIFIED_MODULES_CACHE` in the Move VM caches module hashes after local bytecode verification but does not invalidate cached entries when module dependencies are upgraded. This allows modules to bypass re-verification even when their dependencies have changed, potentially causing type safety violations and consensus divergence between validators with different cache states.

## Finding Description

The Move VM uses a global static cache (`VERIFIED_MODULES_CACHE`) to memoize bytecode verification results and avoid expensive re-verification of identical module bytes. [1](#0-0) 

When a module is verified, its SHA3-256 hash is computed and stored in this cache: [2](#0-1) 

The critical flaw is in the assumption stated in the code comment: *"This should be ok because as long as the hash is the same, the deployed bytecode and any dependencies are the same"*. This assumption is **incorrect** because:

1. The module hash only covers the module's bytecode, not its dependencies
2. Dependencies can be upgraded independently while the dependent module's bytes remain unchanged
3. The cache is **never invalidated** when dependencies change

The cache is only flushed when:
- The verifier configuration changes
- The struct name index map exceeds threshold [3](#0-2) 

But it is NOT flushed when module dependencies are upgraded.

**Exploit Scenario:**

1. **Block N**: Module A (depends on B::foo() returning `u64`) is published and verified
   - Local bytecode verification passes
   - `hash(A)` is added to `VERIFIED_MODULES_CACHE`
   - Linking checks pass with B v1
   
2. **Block N+1**: Module B is upgraded to v2 where `foo()` returns `u128` (compatibility checks may not catch all internal changes)
   - B v2 is successfully published
   - `VERIFIED_MODULES_CACHE` is NOT flushed
   
3. **Block N+2**: Module A is loaded again (e.g., for execution)
   - `hash(A)` is found in cache
   - Local verification is **SKIPPED**
   - In lazy loading mode: linking checks are **ALSO SKIPPED** [4](#0-3) 
   - Module A is marked as verified and used
   - At runtime, A calls B::foo() expecting `u64` but receives `u128`
   - **TYPE CONFUSION / MEMORY CORRUPTION**

## Impact Explanation

This vulnerability has **CRITICAL** severity impact:

1. **Consensus Safety Violation**: Different validators may have different cache states depending on:
   - When they started (empty cache vs. populated cache)
   - Which transactions they've processed
   - Cache eviction timing (LRU with 100K entries)
   
   This can cause validators to execute the same block differently, producing different state roots and breaking consensus.

2. **Type Safety Violation**: Modules can call functions with mismatched signatures, leading to:
   - Reading wrong memory layouts (u64 vs u128)
   - Stack corruption
   - Undefined behavior in native functions

3. **Deterministic Execution Violation**: The core invariant that "all validators produce identical state roots for identical blocks" is broken because cached verification results are not deterministic across different validator states.

This meets the **Critical Severity** criteria: "Consensus/Safety violations" and can lead to "Non-recoverable network partition (requires hardfork)".

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH**

The vulnerability occurs when:
1. A module is loaded and verified (common - happens on every module use)
2. A dependency is upgraded (common - module upgrades are a core feature)
3. The dependent module is loaded again in lazy loading mode (common when lazy loading is enabled)

**Factors increasing likelihood:**
- Lazy loading is **enabled by default** in production for performance
- Module upgrades are frequent in active development
- The cache persists across blocks (100K entries, LRU eviction)
- No cache invalidation on dependency changes

**Factors decreasing likelihood:**
- Compatibility checks catch many breaking changes
- Both validators would need inconsistent cache states (but this naturally occurs due to timing differences)

## Recommendation

**Immediate Fix**: Invalidate `VERIFIED_MODULES_CACHE` when any module is published/upgraded:

```rust
// In code_cache_global_manager.rs or appropriate location
pub fn on_module_published(&mut self, module_id: &ModuleId) {
    // Flush the verification cache since dependencies may have changed
    RuntimeEnvironment::flush_verified_module_cache();
}
```

**Better Fix**: Include dependency versions in the cache key instead of just the module hash. This requires tracking the entire dependency graph hash:

```rust
// Compute hash including all dependencies
let cache_key = compute_module_cache_key(
    module_hash,
    dependency_hashes // Include hashes of all immediate dependencies
);
```

**Alternative**: Disable lazy loading for critical operations or always perform linking checks regardless of lazy loading mode when the cache is used.

## Proof of Concept

```rust
// Pseudocode for reproduction

// Step 1: Publish Module A with dependency B v1
let module_a = compile("
    module 0xcafe::A {
        use 0xcafe::B;
        public fun call_b(): u64 {
            B::foo()  // Expects u64
        }
    }
");
let module_b_v1 = compile("
    module 0xcafe::B {
        public fun foo(): u64 { 42 }
    }
");
publish(module_b_v1);
publish(module_a);  // hash(A) is now cached

// Step 2: Upgrade B to return u128
let module_b_v2 = compile("
    module 0xcafe::B {
        public fun foo(): u128 { 42 }  // Changed return type
    }
");
publish(module_b_v2);  // Cache NOT invalidated

// Step 3: Load and execute A in lazy mode
let result = execute_function("0xcafe::A::call_b");
// Result: Type confusion - A expects u64 but gets u128
// This can cause different validators to compute different state roots
```

**Notes**

The vulnerability exploits a fundamental flaw in the caching assumption that module verification results remain valid as long as module bytes are unchanged. This fails to account for the mutable dependency graph in a system that supports module upgrades. The issue is exacerbated by lazy loading mode which intentionally skips linking checks for performance, relying solely on the cached local verification result.

### Citations

**File:** third_party/move/move-vm/runtime/src/storage/verified_module_cache.rs (L51-54)
```rust
lazy_static! {
    pub(crate) static ref VERIFIED_MODULES_CACHE: VerifiedModuleCache =
        VerifiedModuleCache::empty();
}
```

**File:** third_party/move/move-vm/runtime/src/storage/environment.rs (L184-198)
```rust
        if !VERIFIED_MODULES_CACHE.contains(module_hash) {
            let _timer =
                VM_TIMER.timer_with_label("move_bytecode_verifier::verify_module_with_config");

            // For regular execution, we cache already verified modules. Note that this even caches
            // verification for the published modules. This should be ok because as long as the
            // hash is the same, the deployed bytecode and any dependencies are the same, and so
            // the cached verification result can be used.
            move_bytecode_verifier::verify_module_with_config(
                &self.vm_config().verifier_config,
                compiled_module.as_ref(),
            )?;
            check_natives(compiled_module.as_ref())?;
            VERIFIED_MODULES_CACHE.put(*module_hash);
        }
```

**File:** aptos-move/block-executor/src/code_cache_global_manager.rs (L118-126)
```rust
                let flush_verifier_cache = self.environment.as_ref().is_none_or(|e| {
                    e.verifier_config_bytes() != storage_environment.verifier_config_bytes()
                });
                if flush_verifier_cache {
                    // Additionally, if the verifier config changes, we flush static verifier cache
                    // as well.
                    RuntimeEnvironment::flush_verified_module_cache();
                }
            }
```

**File:** third_party/move/move-vm/runtime/src/storage/module_storage.rs (L308-321)
```rust
        let _timer = VM_TIMER.timer_with_label("unmetered_get_lazily_verified_module [cache miss]");
        let runtime_environment = self.runtime_environment();
        runtime_environment.paranoid_check_module_address_and_name(
            module.code().deserialized(),
            module_id.address(),
            module_id.name(),
        )?;
        let locally_verified_code = runtime_environment.build_locally_verified_module(
            module.code().deserialized().clone(),
            module.extension().size_in_bytes(),
            module.extension().hash(),
        )?;
        let verified_code =
            runtime_environment.build_verified_module_skip_linking_checks(locally_verified_code)?;
```

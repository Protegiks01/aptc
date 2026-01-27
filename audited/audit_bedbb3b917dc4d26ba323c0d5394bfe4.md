# Audit Report

## Title
Stale Verified Module Cache in None Path Leading to Consensus Divergence After Verifier Config Change

## Summary
When the `AptosModuleCacheManager::try_lock` method fails to acquire the global lock, it returns a `None` variant with a freshly created environment but **does not** flush the global `VERIFIED_MODULES_CACHE`. This cache stores module hashes of already-verified modules to skip re-verification. If the verifier configuration changes via on-chain governance (e.g., reducing `max_loop_depth`), validators taking the `None` path will use stale verification results from the old configuration, while validators taking the `Guard` path will correctly re-verify modules with the new configuration. This breaks deterministic execution and can cause consensus divergence.

## Finding Description

The vulnerability exists in the interaction between three components:

1. **Global Verified Module Cache**: [1](#0-0) 

   This is a **global static cache** that stores module hashes of verified modules. When loading a module, if its hash exists in this cache, verification is skipped entirely.

2. **Module Verification Using Cached Results**: [2](#0-1) 

   When building a locally verified module, the system checks if the module hash is in the cache. If present, it skips calling `verify_module_with_config` entirely. Critically, the cache key is **only the module hash**, not a tuple of `(module_hash, verifier_config)`.

3. **Asymmetric Cache Flushing in Lock Acquisition Paths**:

   **Guard Path (Lock Acquired)**: [3](#0-2) 

   The `check_ready` function is called, which detects verifier config changes and flushes the cache: [4](#0-3) 

   **None Path (Lock Failed)**: [5](#0-4) 

   The `check_ready` function is **NOT called**, and the verified module cache is **never flushed**, even though a new environment with the updated verifier config is created from the current state view.

4. **Environment Access in None Variant**: [6](#0-5) 

   The environment returned in the `None` variant was created at lock acquisition time and contains the new verifier config, but the global verification cache still contains stale entries.

**Attack Scenario:**

1. **T0**: Verifier config V1 is active (e.g., `max_loop_depth = 5`)
2. **T1**: Module M with 4 nested loops is published and verified under V1, hash H added to `VERIFIED_MODULES_CACHE`
3. **T2**: Governance proposal passes changing verifier config to V2 (`max_loop_depth = 3`)
4. **T3**: Validator A executes next block:
   - Acquires lock successfully
   - `check_ready()` detects config change (V1 → V2)
   - Flushes `VERIFIED_MODULES_CACHE` via `RuntimeEnvironment::flush_verified_module_cache()`
   - Loads module M, re-verifies with V2, **fails** (4 loops > 3 limit)
5. **T4**: Validator B executes same block (or retries):
   - `try_lock()` fails (contention)
   - Takes `None` path with environment containing V2 config
   - **`VERIFIED_MODULES_CACHE` NOT flushed**
   - Loads module M, checks cache: hash H found
   - **Skips verification**, uses cached result from V1
   - Module M executes **successfully** (4 loops passed under V1)
6. **Result**: Validator A and B produce different state roots → **Consensus divergence**

The verifier config is read from on-chain state during environment creation: [7](#0-6) 

The config affects critical security limits like `max_loop_depth`, `max_function_parameters`, `max_generic_instantiation_length`, and feature flags for signature verification, enums, resource access control, etc.

## Impact Explanation

**Critical Severity** - This vulnerability meets the Critical criteria:

1. **Consensus/Safety Violation**: Different validators executing the same block with different verification results will produce different state roots, breaking the fundamental consensus invariant: [8](#0-7) 

2. **Deterministic Execution Violation**: The first critical invariant "All validators must produce identical state roots for identical blocks" is violated when some validators use stale verification results while others use fresh verification.

3. **Security Bypass**: Modules that violate new security constraints (e.g., excessive loop depth, unsupported features) can execute on validators taking the `None` path, while being rejected by validators taking the `Guard` path. This defeats the purpose of governance-driven security upgrades.

4. **Non-recoverable Network Partition**: If a sufficient number of validators disagree on state roots due to this issue, the network could halt or fork, potentially requiring a hard fork to recover.

The block executor uses this manager for all block execution: [9](#0-8) 

## Likelihood Explanation

**Medium-High Likelihood:**

1. **Triggering the None Path**: While the code logs an alert indicating this is unexpected, [10](#0-9)  lock contention can occur during:
   - Block execution retries after failures
   - Concurrent API calls (view functions) during block execution
   - Epoch transitions with timing races
   - High transaction throughput causing execution delays

2. **Verifier Config Changes**: Governance proposals that modify verifier configuration are legitimate operations that can happen via: [11](#0-10) 

3. **Timing Window**: The vulnerability window exists from when the config changes until all validators have flushed their caches. During this window, any validator experiencing lock contention will use stale verification results.

4. **No Special Privileges Required**: This can occur naturally during normal operations without any malicious actors - it's a race condition triggered by legitimate concurrent execution and governance changes.

## Recommendation

**Immediate Fix**: Flush the global verified module cache in the `None` path before returning the environment.

Modify the `try_lock_inner` function:

```rust
fn try_lock_inner(
    &self,
    state_view: &impl StateView,
    config: &BlockExecutorModuleCacheLocalConfig,
    transaction_slice_metadata: TransactionSliceMetadata,
) -> Result<AptosModuleCacheManagerGuard<'_>, VMStatus> {
    let storage_environment =
        AptosEnvironment::new_with_delayed_field_optimization_enabled(&state_view);

    Ok(match self.inner.try_lock() {
        Some(mut guard) => {
            guard.check_ready(storage_environment, config, transaction_slice_metadata)?;
            AptosModuleCacheManagerGuard::Guard { guard }
        },
        None => {
            alert_or_println!("Locking module cache manager failed, fallback to empty caches");
            
            // CRITICAL FIX: Check if verifier config changed and flush cache if needed
            // This matches the logic in check_ready() to ensure consistency
            if storage_environment.gas_feature_version() >= RELEASE_V1_34 {
                // We don't have access to old environment in None path, so we must
                // conservatively flush the cache to ensure correctness.
                // This is safe but may cause performance degradation when lock fails.
                RuntimeEnvironment::flush_verified_module_cache();
            }

            AptosModuleCacheManagerGuard::None {
                environment: storage_environment,
                module_cache: GlobalModuleCache::empty(),
            }
        },
    })
}
```

**Alternative Fix** (more performant but complex): Store the verifier config hash in a static atomic variable and compare before checking the cache during module loading. This would require changes to the verified module cache structure to be config-aware.

**Long-term Fix**: Redesign the `VERIFIED_MODULES_CACHE` to include the verifier config hash as part of the cache key: `(module_hash, verifier_config_hash) -> verification_result`. This would make the cache naturally handle config changes without requiring explicit flushes.

## Proof of Concept

```rust
// This is a conceptual PoC showing the race condition
// Actual reproduction would require a full Aptos test environment

#[test]
fn test_stale_verification_cache_consensus_divergence() {
    use aptos_types::on_chain_config::{Features, FeatureFlag};
    use std::sync::{Arc, Barrier};
    use std::thread;
    
    // Setup: Deploy a module M with 4 nested loops under config V1 (max_loop_depth=5)
    let state_view_v1 = create_state_with_verifier_config(/* max_loop_depth: 5 */);
    let module_with_4_loops = compile_module_with_nested_loops(4);
    
    // Module M is verified and cached under V1
    let manager = Arc::new(AptosModuleCacheManager::new());
    let guard = manager.try_lock(&state_view_v1, &default_config(), metadata_1).unwrap();
    // ... execute block, module M gets verified with V1, hash cached ...
    drop(guard);
    
    // Governance changes config to V2 (max_loop_depth=3)
    let state_view_v2 = create_state_with_verifier_config(/* max_loop_depth: 3 */);
    
    // Simulate concurrent execution by two validators
    let barrier = Arc::new(Barrier::new(2));
    let manager_clone = manager.clone();
    
    // Thread A: Acquires lock (Guard path)
    let handle_a = thread::spawn(move || {
        barrier.wait(); // Synchronize start
        let guard = manager.try_lock(&state_view_v2, &default_config(), metadata_2).unwrap();
        // check_ready() called -> cache flushed -> module M re-verified with V2 -> FAILS
        let result_a = execute_with_module_m(&guard, &state_view_v2);
        assert!(result_a.is_err(), "Should fail verification with V2");
        result_a
    });
    
    // Thread B: Fails to acquire lock (None path)  
    let handle_b = thread::spawn(move || {
        barrier.wait(); // Synchronize start
        thread::sleep(Duration::from_millis(1)); // Ensure A locks first
        let guard = manager_clone.try_lock(&state_view_v2, &default_config(), metadata_2).unwrap();
        // None path taken -> cache NOT flushed -> module M uses cached verification -> PASSES
        let result_b = execute_with_module_m(&guard, &state_view_v2);
        assert!(result_b.is_ok(), "Should pass with cached V1 verification");
        result_b
    });
    
    let result_a = handle_a.join().unwrap();
    let result_b = handle_b.join().unwrap();
    
    // CONSENSUS DIVERGENCE: Different validators get different results!
    assert_ne!(
        result_a.is_ok(), 
        result_b.is_ok(),
        "Consensus divergence: Validator A rejects, Validator B accepts"
    );
}
```

**Notes**

This vulnerability is particularly insidious because:

1. The `None` path is designed as a fallback for lock contention, not as a common path
2. The environment IS correctly created with the new config from state_view
3. However, the **global verification cache** is shared across all threads and is not config-aware
4. The cache flush logic exists in `check_ready()` but is only called in the `Guard` path
5. Most of the time, validators will take the `Guard` path and work correctly - the bug only manifests during rare lock contention scenarios
6. The impact is catastrophic when it does occur: consensus divergence between validators

The fix is straightforward but must be applied carefully to ensure the cache flush happens unconditionally in the `None` path, or the cache must be redesigned to be config-aware.

### Citations

**File:** third_party/move/move-vm/runtime/src/storage/verified_module_cache.rs (L51-54)
```rust
lazy_static! {
    pub(crate) static ref VERIFIED_MODULES_CACHE: VerifiedModuleCache =
        VerifiedModuleCache::empty();
}
```

**File:** third_party/move/move-vm/runtime/src/storage/environment.rs (L178-201)
```rust
    pub fn build_locally_verified_module(
        &self,
        compiled_module: Arc<CompiledModule>,
        module_size: usize,
        module_hash: &[u8; 32],
    ) -> VMResult<LocallyVerifiedModule> {
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

        Ok(LocallyVerifiedModule(compiled_module, module_size))
    }
```

**File:** aptos-move/block-executor/src/code_cache_global_manager.rs (L92-98)
```rust
    /// Checks if the manager is ready for execution. That is:
    ///   1. If previously recorded transaction metadata is not immediately before, flushes module
    ///      and environment.
    ///   2. Sets the metadata to the new one.
    ///   3. Checks if environment is set and is the same. If not, resets it. Module caches are
    ///      flushed in case of resets.
    ///   4. Checks sizes of type and module caches. If they are too large, caches are flushed.
```

**File:** aptos-move/block-executor/src/code_cache_global_manager.rs (L117-126)
```rust
            if storage_environment.gas_feature_version() >= RELEASE_V1_34 {
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

**File:** aptos-move/block-executor/src/code_cache_global_manager.rs (L215-219)
```rust
        Ok(match self.inner.try_lock() {
            Some(mut guard) => {
                guard.check_ready(storage_environment, config, transaction_slice_metadata)?;
                AptosModuleCacheManagerGuard::Guard { guard }
            },
```

**File:** aptos-move/block-executor/src/code_cache_global_manager.rs (L220-229)
```rust
            None => {
                alert_or_println!("Locking module cache manager failed, fallback to empty caches");

                // If this is true, we failed to acquire a lock, and so default storage environment
                // and empty (thread-local) module caches will be used.
                AptosModuleCacheManagerGuard::None {
                    environment: storage_environment,
                    module_cache: GlobalModuleCache::empty(),
                }
            },
```

**File:** aptos-move/block-executor/src/code_cache_global_manager.rs (L276-285)
```rust
    pub fn environment(&self) -> &AptosEnvironment {
        use AptosModuleCacheManagerGuard::*;
        match self {
            Guard { guard } => guard
                .environment
                .as_ref()
                .expect("Guard always has environment set"),
            None { environment, .. } => environment,
        }
    }
```

**File:** aptos-move/aptos-vm-environment/src/environment.rs (L219-220)
```rust
        let features =
            fetch_config_and_update_hash::<Features>(&mut sha3_256, state_view).unwrap_or_default();
```

**File:** aptos-move/aptos-vm-environment/src/environment.rs (L276-285)
```rust
        let vm_config = aptos_prod_vm_config(
            chain_id,
            gas_feature_version,
            &features,
            &timed_features,
            ty_builder,
        );
        let verifier_bytes =
            bcs::to_bytes(&vm_config.verifier_config).expect("Verifier config is serializable");
        let runtime_environment = RuntimeEnvironment::new_with_config(natives, vm_config);
```

**File:** aptos-move/aptos-vm/src/block_executor/mod.rs (L539-543)
```rust
        let mut module_cache_manager_guard = module_cache_manager.try_lock(
            &state_view,
            &config.local.module_cache_config,
            transaction_slice_metadata,
        )?;
```

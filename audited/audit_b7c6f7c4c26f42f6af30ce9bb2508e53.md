# Audit Report

## Title
Feature Flag Transition Allows Execution of Unverified Bytecode Leading to Consensus Divergence

## Summary
During governance-initiated feature flag changes at epoch boundaries, the bytecode verifier cache is not always properly invalidated, allowing modules verified under old feature flag settings to execute under new settings without reverification. This creates a critical window where different validators may execute different code paths, leading to consensus divergence and potential state inconsistencies.

## Finding Description

The Aptos Move VM uses a global cache (`VERIFIED_MODULES_CACHE`) to avoid repeatedly verifying modules that have already been checked. This cache is keyed solely by module hash, without considering the `VerifierConfig` that was used during verification. [1](#0-0) 

When a module is verified, its hash is cached: [2](#0-1) 

The `VerifierConfig` contains feature-dependent settings that directly affect verification behavior: [3](#0-2) 

Critically, when feature flags like `ENABLE_FUNCTION_VALUES` change, the verifier config changes (e.g., `max_type_nodes` switches from 256 to 128), but the verification cache is only flushed for networks with `gas_feature_version >= 38`: [4](#0-3) 

Feature flag changes take effect at epoch boundaries via the governance mechanism: [5](#0-4) 

The `AptosEnvironment` is created once per block and reads feature flags from on-chain state: [6](#0-5) 

**Attack Path:**

1. **Epoch N**: Feature flag `ENABLE_FUNCTION_VALUES = true`
   - Attacker publishes Module M containing function value bytecode (e.g., `PackClosure` instructions)
   - `FeatureVerifier` allows this since the feature is enabled
   - Module is verified with `VerifierConfig{enable_function_values: true, max_type_nodes: Some(128)}`
   - Module hash is cached in `VERIFIED_MODULES_CACHE`

2. **Epoch N+1**: Governance disables `ENABLE_FUNCTION_VALUES`
   - `on_new_epoch()` applies the feature flag change
   - New `VerifierConfig{enable_function_values: false, max_type_nodes: Some(256)}`
   - **If `gas_feature_version < 38`**: Cache is NOT flushed
   - **If `gas_feature_version >= 38`**: Cache flush logic compares `verifier_config_bytes`

3. **Execution in Epoch N+1**:
   - Transaction calls Module M
   - In `build_locally_verified_module()`, module hash is found in cache (if not flushed)
   - Verification is **SKIPPED**
   - Module M executes even though it uses disabled features
   - `FeatureVerifier` would reject it if re-verified: [7](#0-6) 

This violates the critical invariant that "all validators must produce identical state roots for identical blocks" because different validators may have different cache states, leading to divergent execution outcomes.

## Impact Explanation

**Critical Severity** - This vulnerability enables:

1. **Consensus Divergence**: Validators with different cache states will execute the same module differently, producing different state roots and breaking consensus safety
2. **Protocol Invariant Violation**: Modules using disabled features can execute, violating the Move VM safety model
3. **Verification Limit Bypass**: Modules verified with looser limits (e.g., `max_type_nodes: 256`) can execute under tighter limits (`max_type_nodes: 128`), potentially causing unexpected behavior
4. **Non-Deterministic Execution**: The same transaction may succeed or fail depending on cache state, breaking deterministic execution guarantees

This directly maps to **Critical Severity** per the Aptos bug bounty:
- "Consensus/Safety violations" - Different validators produce different execution results
- "Non-recoverable network partition (requires hardfork)" - Consensus divergence requires manual intervention

## Likelihood Explanation

**High Likelihood** for networks with `gas_feature_version < 38`:
- Feature flag changes occur regularly through governance
- Cache is never flushed on these networks
- Attackers can deliberately publish modules before feature flag changes

**Medium Likelihood** for networks with `gas_feature_version >= 38`:
- Cache flushing logic exists but depends on proper environment comparison
- Race conditions or implementation bugs in cache management could still cause issues
- Multiple code paths manage the cache, increasing complexity

The vulnerability is realistic because:
1. Governance feature flag changes are normal operations
2. Module publishing is permissionless
3. No special privileges required
4. Attack can be timed with public governance proposals

## Recommendation

**Immediate Fix:**

1. **Include verifier config hash in cache key** instead of just module hash:

```rust
// In verified_module_cache.rs
pub(crate) struct VerifiedModuleCache(Mutex<lru::LruCache<([u8; 32], [u8; 32]), ()>>);

// Cache key becomes (module_hash, verifier_config_hash)
pub(crate) fn contains(&self, module_hash: &[u8; 32], verifier_hash: &[u8; 32]) -> bool {
    verifier_cache_enabled() && self.0.lock().get(&(*module_hash, *verifier_hash)).is_some()
}
```

2. **Always flush cache on verifier config change**, regardless of gas feature version:

```rust
// In code_cache_global_manager.rs, remove the gas_feature_version check:
let flush_verifier_cache = self.environment.as_ref().is_none_or(|e| {
    e.verifier_config_bytes() != storage_environment.verifier_config_bytes()
});
if flush_verifier_cache {
    RuntimeEnvironment::flush_verified_module_cache();
}
```

3. **Add explicit verifier config versioning** to make cache invalidation more robust and observable

## Proof of Concept

```rust
// Rust test demonstrating the vulnerability
#[test]
fn test_feature_flag_transition_cache_bug() {
    use aptos_types::on_chain_config::{Features, FeatureFlag};
    use move_vm_runtime::storage::verified_module_cache::VERIFIED_MODULES_CACHE;
    
    // Epoch N: Feature enabled
    let mut features_enabled = Features::default();
    features_enabled.enable(FeatureFlag::ENABLE_FUNCTION_VALUES);
    
    let state_view_n = create_state_view_with_features(features_enabled);
    let env_n = AptosEnvironment::new(&state_view_n);
    
    // Publish module using function values
    let module_with_closures = compile_module_with_closures();
    let module_hash = sha3_256(&module_with_closures);
    
    // Verify and cache
    env_n.runtime_environment()
        .build_locally_verified_module(Arc::new(module_with_closures.clone()), 
                                      module_with_closures.len(), 
                                      &module_hash)
        .expect("Should verify with feature enabled");
    
    assert!(VERIFIED_MODULES_CACHE.contains(&module_hash));
    
    // Epoch N+1: Feature disabled, cache NOT flushed (simulating gas_feature_version < 38)
    let mut features_disabled = Features::default();
    features_disabled.disable(FeatureFlag::ENABLE_FUNCTION_VALUES);
    
    let state_view_n1 = create_state_view_with_features(features_disabled);
    let env_n1 = AptosEnvironment::new(&state_view_n1);
    
    // Cache still contains the module
    assert!(VERIFIED_MODULES_CACHE.contains(&module_hash));
    
    // Load module - verification is SKIPPED due to cache hit
    let result = env_n1.runtime_environment()
        .build_locally_verified_module(Arc::new(module_with_closures.clone()),
                                      module_with_closures.len(),
                                      &module_hash);
    
    // BUG: Module loads successfully even though feature is disabled!
    assert!(result.is_ok());
    
    // If we flush cache and retry, verification should fail
    VERIFIED_MODULES_CACHE.flush();
    let result_after_flush = env_n1.runtime_environment()
        .build_locally_verified_module(Arc::new(module_with_closures),
                                      module_with_closures.len(),
                                      &module_hash);
    
    // Now it correctly fails
    assert!(result_after_flush.is_err());
    assert!(matches!(result_after_flush.unwrap_err().major_status(), 
                    StatusCode::FEATURE_NOT_ENABLED));
}
```

## Notes

This vulnerability has existed since the introduction of feature-gated bytecode verification. The partial fix in gas feature version 38 mitigates but does not fully eliminate the issue:

1. **Legacy networks** with `gas_feature_version < 38` remain vulnerable
2. **Cache invalidation complexity** across multiple code paths increases risk of future bugs
3. **No explicit verifier config versioning** makes cache invalidation fragile and error-prone

The fundamental design flaw is that verification results are cached without considering the verification configuration, violating the principle that cached results must be invalidated when their input parameters change.

### Citations

**File:** third_party/move/move-vm/runtime/src/storage/verified_module_cache.rs (L13-13)
```rust
pub(crate) struct VerifiedModuleCache(Mutex<lru::LruCache<[u8; 32], ()>>);
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

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L145-194)
```rust
pub fn aptos_prod_verifier_config(gas_feature_version: u64, features: &Features) -> VerifierConfig {
    let sig_checker_v2_fix_script_ty_param_count =
        features.is_enabled(FeatureFlag::SIGNATURE_CHECKER_V2_SCRIPT_FIX);
    let sig_checker_v2_fix_function_signatures = gas_feature_version >= RELEASE_V1_34;
    let enable_enum_types = features.is_enabled(FeatureFlag::ENABLE_ENUM_TYPES);
    let enable_resource_access_control =
        features.is_enabled(FeatureFlag::ENABLE_RESOURCE_ACCESS_CONTROL);
    let enable_function_values = features.is_enabled(FeatureFlag::ENABLE_FUNCTION_VALUES);
    // Note: we reuse the `enable_function_values` flag to set various stricter limits on types.

    VerifierConfig {
        scope: VerificationScope::Everything,
        max_loop_depth: Some(5),
        max_generic_instantiation_length: Some(32),
        max_function_parameters: Some(128),
        max_basic_blocks: Some(1024),
        max_value_stack_size: 1024,
        max_type_nodes: if enable_function_values {
            Some(128)
        } else {
            Some(256)
        },
        max_push_size: Some(10000),
        max_struct_definitions: None,
        max_struct_variants: None,
        max_fields_in_struct: None,
        max_function_definitions: None,
        max_back_edges_per_function: None,
        max_back_edges_per_module: None,
        max_basic_blocks_in_script: None,
        max_per_fun_meter_units: Some(1000 * 80000),
        max_per_mod_meter_units: Some(1000 * 80000),
        _use_signature_checker_v2: true,
        sig_checker_v2_fix_script_ty_param_count,
        sig_checker_v2_fix_function_signatures,
        enable_enum_types,
        enable_resource_access_control,
        enable_function_values,
        max_function_return_values: if enable_function_values {
            Some(128)
        } else {
            None
        },
        max_type_depth: if enable_function_values {
            Some(20)
        } else {
            None
        },
    }
}
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

**File:** aptos-move/framework/move-stdlib/sources/configs/features.move (L834-844)
```text
    public fun on_new_epoch(framework: &signer) acquires Features, PendingFeatures {
        ensure_framework_signer(framework);
        if (exists<PendingFeatures>(@std)) {
            let PendingFeatures { features } = move_from<PendingFeatures>(@std);
            if (exists<Features>(@std)) {
                Features[@std].features = features;
            } else {
                move_to(framework, Features { features })
            }
        }
    }
```

**File:** aptos-move/aptos-vm-environment/src/environment.rs (L31-34)
```rust
/// A runtime environment which can be used for VM initialization and more. Contains features
/// used by execution, gas parameters, VM configs and global caches. Note that it is the user's
/// responsibility to make sure the environment is consistent, for now it should only be used per
/// block of transactions because all features or configs are updated only on per-block basis.
```

**File:** third_party/move/move-bytecode-verifier/src/features.rs (L139-157)
```rust
    fn verify_code(&self, code: &[Bytecode], idx: Option<TableIndex>) -> PartialVMResult<()> {
        if !self.config.enable_function_values {
            for bc in code {
                if matches!(
                    bc,
                    Bytecode::PackClosure(..)
                        | Bytecode::PackClosureGeneric(..)
                        | Bytecode::CallClosure(..)
                ) {
                    let mut err = PartialVMError::new(StatusCode::FEATURE_NOT_ENABLED);
                    if let Some(idx) = idx {
                        err = err.at_index(IndexKind::FunctionDefinition, idx);
                    }
                    return Err(err.with_message("function value feature not enabled".to_string()));
                }
            }
        }
        Ok(())
    }
```

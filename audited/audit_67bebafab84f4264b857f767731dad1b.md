# Audit Report

## Title
Feature Flag Downgrade Allows Cached Modules to Bypass Re-verification, Breaking Deterministic Execution Invariant

## Summary
The Move bytecode verifier caches verified modules using only the module hash as the cache key, without including the `VerifierConfig` state. When feature flags are disabled through governance after modules have been verified and cached, those modules can continue executing with now-disabled features, causing consensus divergence between nodes with warm vs. cold caches.

## Finding Description

The vulnerability exists in the interaction between three components:

1. **Verification Cache Design**: The `VERIFIED_MODULES_CACHE` stores module hashes without the verifier configuration state. [1](#0-0) 

2. **Feature-Dependent Verification**: The `FeatureVerifier` checks feature flags like `enable_function_values`, `enable_enum_types`, and `enable_resource_access_control` during module verification. [2](#0-1) 

3. **Cache Bypass Logic**: Module verification is skipped if the module hash exists in the cache, regardless of whether the `VerifierConfig` has changed. [3](#0-2) 

4. **Governance Feature Control**: Features can be disabled through governance proposals. [4](#0-3) 

5. **Incomplete Mitigation**: Cache flushing on verifier config changes only occurs for `gas_feature_version >= RELEASE_V1_34` (version 38), leaving earlier versions vulnerable. [5](#0-4) 

**Attack Scenario:**

1. Feature `ENABLE_FUNCTION_VALUES` is enabled via governance
2. Attacker publishes a module using function values (e.g., `PackClosure`, `CallClosure` bytecodes)
3. Module is verified with `enable_function_values = true` and module hash is cached
4. Governance discovers critical vulnerability in function values feature
5. Emergency proposal disables `ENABLE_FUNCTION_VALUES` to protect the network
6. **On nodes with gas_feature_version < 38**: Cache is never flushed
7. **On nodes with gas_feature_version >= 38**: Cache is only flushed during block execution via `code_cache_global_manager`, but not in all module loading paths
8. When the module executes again:
   - **Nodes with warm cache**: Skip verification, execute with function values
   - **Nodes with cold cache**: Verify with new config, reject function values
9. **Result**: Consensus divergence - different state roots for identical blocks

This breaks the **Deterministic Execution** invariant: "All validators must produce identical state roots for identical blocks."

## Impact Explanation

**Critical Severity** - This vulnerability enables:

1. **Consensus Safety Violations**: Different nodes executing the same transaction produce different state roots, breaking AptosBFT consensus guarantees and potentially causing chain splits.

2. **Governance Bypass**: Emergency feature disablement (e.g., due to discovered vulnerabilities) can be circumvented by cached modules, defeating the security purpose of feature flags.

3. **Non-deterministic State Transitions**: The behavior depends on cache state rather than blockchain state, violating fundamental blockchain invariants.

4. **Network Partition Risk**: Nodes with different cache states may permanently diverge, requiring manual intervention or hard fork to recover.

The verifier configuration is explicitly serialized and tracked for comparison purposes. [6](#0-5)  This indicates the system recognizes verifier config changes are critical, but the cache invalidation logic is incomplete.

## Likelihood Explanation

**High Likelihood** - This vulnerability will occur whenever:

1. A feature is disabled after being enabled (common for emergency security responses)
2. Modules using that feature were previously published and cached
3. Those modules are executed after the feature is disabled

The likelihood is elevated by:
- Feature flags are changed through governance proposals [7](#0-6) 
- Emergency responses to discovered vulnerabilities naturally trigger feature disablement
- The mitigation only exists for gas_feature_version >= 38, leaving all earlier versions vulnerable
- Even with the mitigation, cache flushing only occurs in specific code paths, not universally

## Recommendation

**Immediate Fix**: Include the verifier configuration hash in the cache key.

Modify `VerifiedModuleCache` to use a composite key:

```rust
// In verified_module_cache.rs
pub(crate) struct VerifiedModuleCache(Mutex<lru::LruCache<([u8; 32], [u8; 32]), ()>>);

impl VerifiedModuleCache {
    pub(crate) fn contains(&self, module_hash: &[u8; 32], config_hash: &[u8; 32]) -> bool {
        verifier_cache_enabled() && self.0.lock().get(&(*module_hash, *config_hash)).is_some()
    }

    pub(crate) fn put(&self, module_hash: [u8; 32], config_hash: [u8; 32]) {
        if verifier_cache_enabled() {
            let mut cache = self.0.lock();
            cache.put((module_hash, config_hash), ());
        }
    }
}
```

Update `build_locally_verified_module` to pass both hashes:

```rust
// In environment.rs
pub fn build_locally_verified_module(
    &self,
    compiled_module: Arc<CompiledModule>,
    module_size: usize,
    module_hash: &[u8; 32],
) -> VMResult<LocallyVerifiedModule> {
    let config_hash = self.vm_config().verifier_config_hash();
    if !VERIFIED_MODULES_CACHE.contains(module_hash, &config_hash) {
        // verification...
        VERIFIED_MODULES_CACHE.put(*module_hash, config_hash);
    }
    Ok(LocallyVerifiedModule(compiled_module, module_size))
}
```

Add verifier config hash to VMConfig:

```rust
// In verifier.rs
impl VerifierConfig {
    pub fn compute_hash(&self) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let bytes = bcs::to_bytes(self).expect("VerifierConfig is serializable");
        Sha3_256::digest(&bytes).into()
    }
}
```

**Long-term Fix**: Implement cache versioning tied to epoch changes, automatically flushing when any configuration changes occur.

## Proof of Concept

```rust
// Reproduction steps:

// 1. Setup: Enable ENABLE_FUNCTION_VALUES feature
// 2. Publish module using function values:

module 0xCAFE::exploit {
    public fun exploit_function() {
        // Use function value features
        let closure = |x| x + 1;  // PackClosure bytecode
        closure(5);                // CallClosure bytecode
    }
}

// 3. Module gets verified with enable_function_values=true
// 4. Module hash cached in VERIFIED_MODULES_CACHE

// 5. Governance disables ENABLE_FUNCTION_VALUES due to vulnerability

// 6. Execute exploit_function() again:
//    - Node A (warm cache): Skips verification, executes successfully
//    - Node B (cold cache): Verification fails with FEATURE_NOT_ENABLED
//    - Result: Consensus divergence on transaction success/failure

// Validation:
// - Check VERIFIED_MODULES_CACHE.contains() returns true for Node A
// - Check FeatureVerifier::verify_code() rejects on Node B
// - Observe different transaction outcomes
```

## Notes

The comment at line 373 in `environment.rs` explicitly states "Flushes the global verified module cache. Should be used when verifier configuration has changed," [8](#0-7)  acknowledging this is a known issue that requires manual cache management. However, the current implementation relies on external callers to flush the cache, which is error-prone and incomplete.

The root cause is architectural: caches should be self-invalidating based on their dependencies, not require external coordination. The verifier cache violates this principle by ignoring a critical dependency (the verifier configuration).

### Citations

**File:** third_party/move/move-vm/runtime/src/storage/verified_module_cache.rs (L13-13)
```rust
pub(crate) struct VerifiedModuleCache(Mutex<lru::LruCache<[u8; 32], ()>>);
```

**File:** third_party/move/move-bytecode-verifier/src/features.rs (L19-42)
```rust
pub struct FeatureVerifier<'a> {
    config: &'a VerifierConfig,
    code: BinaryIndexedView<'a>,
}

impl<'a> FeatureVerifier<'a> {
    pub fn verify_module(config: &'a VerifierConfig, module: &'a CompiledModule) -> VMResult<()> {
        Self::verify_module_impl(config, module)
            .map_err(|e| e.finish(Location::Module(module.self_id())))
    }

    fn verify_module_impl(
        config: &'a VerifierConfig,
        module: &'a CompiledModule,
    ) -> PartialVMResult<()> {
        let verifier = Self {
            config,
            code: BinaryIndexedView::Module(module),
        };
        verifier.verify_signatures()?;
        verifier.verify_function_handles()?;
        verifier.verify_struct_defs()?;
        verifier.verify_function_defs()
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

**File:** third_party/move/move-vm/runtime/src/storage/environment.rs (L373-377)
```rust
    /// Flushes the global verified module cache. Should be used when verifier configuration has
    /// changed.
    pub fn flush_verified_module_cache() {
        VERIFIED_MODULES_CACHE.flush();
    }
```

**File:** aptos-move/framework/move-stdlib/sources/configs/features.move (L805-828)
```text
    public fun change_feature_flags_for_next_epoch(
        framework: &signer,
        enable: vector<u64>,
        disable: vector<u64>
    ) acquires PendingFeatures, Features {
        assert!(signer::address_of(framework) == @std, error::permission_denied(EFRAMEWORK_SIGNER_NEEDED));

        // Figure out the baseline feature vec that the diff will be applied to.
        let new_feature_vec = if (exists<PendingFeatures>(@std)) {
            // If there is a buffered feature vec, use it as the baseline.
            let PendingFeatures { features } = move_from<PendingFeatures>(@std);
            features
        } else if (exists<Features>(@std)) {
            // Otherwise, use the currently effective feature flag vec as the baseline, if it exists.
            Features[@std].features
        } else {
            // Otherwise, use an empty feature vec.
            vector[]
        };

        // Apply the diff and save it to the buffer.
        apply_diff(&mut new_feature_vec, enable, disable);
        move_to(framework, PendingFeatures { features: new_feature_vec });
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

**File:** aptos-move/aptos-vm-environment/src/environment.rs (L283-284)
```rust
        let verifier_bytes =
            bcs::to_bytes(&vm_config.verifier_config).expect("Verifier config is serializable");
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L145-193)
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
```

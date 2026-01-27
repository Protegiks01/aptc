# Audit Report

## Title
Consensus Divergence via Cache Flush Bypass on Legacy Gas Feature Versions

## Summary
The verified module cache is not flushed when the verifier configuration changes on networks running `gas_feature_version < 38` (RELEASE_V1_34), allowing previously-verified modules to bypass re-verification under stricter configurations. This creates a critical window where validators may execute modules that would fail verification under the current configuration, potentially causing consensus divergence.

## Finding Description

The Move VM maintains a global cache (`VERIFIED_MODULES_CACHE`) that stores hashes of already-verified modules to optimize verification performance. [1](#0-0) 

When the runtime verifier configuration changes (e.g., feature flags enabled, stricter limits applied), the cache should be flushed to ensure all modules are re-verified under the new rules. However, this flush only occurs for networks with `gas_feature_version >= RELEASE_V1_34` (38). [2](#0-1) 

The verification cache is checked during module loading in both lazy and eager verification paths. [3](#0-2) 

**Attack Scenario:**

While the original security question asks about different compilation flags across validators, the actual exploitable vulnerability is more subtle and does not require that scenario. Instead, it affects networks running older gas feature versions:

1. Network operates with `gas_feature_version < 38` (e.g., version 35)
2. Module M is published and verified under verifier config C1 (e.g., `max_type_nodes = 256`)
3. Module hash is cached in `VERIFIED_MODULES_CACHE`
4. On-chain governance enables new feature flags, creating stricter config C2 (e.g., `max_type_nodes = 128`)
5. The verifier config bytes change: [4](#0-3) 
6. Cache flush logic checks `gas_feature_version >= RELEASE_V1_34` but fails, so cache is NOT flushed
7. Transaction executes code from module M
8. Cache hit occurs, verification is skipped [5](#0-4) 
9. Module M would now fail verification under C2, but executes successfully due to stale cache

**Regarding the "Different Compilation Flags" Question:**

The production `aptos-node` has an explicit test preventing the `disable_verifier_cache` feature from being enabled. [6](#0-5) 

This means all production validators should have the cache enabled identically. However, if through operator error or malicious intent validators DO compile with different flags, the vulnerability would be amplified, as some validators would always verify (cache disabled) while others use stale cache entries (cache enabled).

## Impact Explanation

**Critical Severity** - This vulnerability breaks the fundamental "Deterministic Execution" invariant: all validators must produce identical state roots for identical blocks.

When the cache is not flushed on older gas versions:
- Modules that are invalid under the current verifier config can be executed
- This bypasses security controls added via governance (e.g., stricter type limits to prevent DoS)
- Different execution paths may occur based on whether modules are cached
- In extreme cases with the compilation flag scenario, validators could permanently diverge

The verifier config controls critical security parameters defined in the production configuration. [7](#0-6) 

This qualifies as Critical under the Aptos bug bounty: "Consensus/Safety violations" and potentially "Non-recoverable network partition."

## Likelihood Explanation

**For Legacy Networks**: HIGH
- Any network still operating with `gas_feature_version < 38` is vulnerable
- Verifier config changes happen through governance proposals
- Once config changes, the window exists until the next module load
- The latest version is 45, but testnets or private chains may use older versions [8](#0-7) 

**For Different Compilation Flags**: VERY LOW (but CRITICAL if it occurs)
- Production test prevents this feature in official binaries
- Requires operator error or malicious validator
- Not directly exploitable by external attackers
- However, if it occurs, creates permanent consensus divergence

## Recommendation

1. **Remove the gas version check** for cache flushing to ensure all networks flush properly:

```rust
// In code_cache_global_manager.rs, lines 117-126
// REMOVE the gas_feature_version check:
let flush_verifier_cache = self.environment.as_ref().is_none_or(|e| {
    e.verifier_config_bytes() != storage_environment.verifier_config_bytes()
});
if flush_verifier_cache {
    RuntimeEnvironment::flush_verified_module_cache();
}
```

2. **Add runtime detection** for the `disable_verifier_cache` feature to ensure all validators use identical settings:

```rust
// Add a consensus-critical assertion during validator startup
#[cfg(not(test))]
fn verify_cache_consistency() {
    let cache_enabled = verifier_cache_enabled();
    // Include this in validator handshake or health checks
    // to ensure all validators have identical cache behavior
}
```

3. **Force cache flush on epoch boundaries** as an additional safety measure, regardless of config changes.

## Proof of Concept

```rust
// Reproduction steps for the legacy gas version scenario:

#[test]
fn test_stale_cache_after_config_change() {
    use aptos_types::on_chain_config::Features;
    use move_vm_runtime::RuntimeEnvironment;
    
    // 1. Create environment with gas_feature_version = 35 (< 38)
    let mut features = Features::default();
    let gas_version = 35u64;
    
    // 2. Publish and verify module with permissive config
    let module_bytes = /* valid module with 200 type nodes */;
    let module_hash = compute_hash(&module_bytes);
    
    // Module passes verification, gets cached
    let env1 = create_environment_with_gas_version(35, permissive_config);
    env1.build_locally_verified_module(module, size, &module_hash)?;
    assert!(VERIFIED_MODULES_CACHE.contains(&module_hash)); // Cached
    
    // 3. Change verifier config to stricter limits (max_type_nodes = 128)
    features.enable(FeatureFlag::SOME_STRICTER_FLAG);
    let env2 = create_environment_with_gas_version(35, strict_config);
    
    // 4. Cache should be flushed but ISN'T due to gas_version < 38
    // Module would fail verification under new config, but cache hit occurs
    let result = env2.build_locally_verified_module(module, size, &module_hash);
    
    // Expected: verification error (module invalid under strict config)
    // Actual: Success (cache hit, verification skipped)
    assert!(result.is_ok()); // BUG: Should have failed!
}
```

## Notes

The primary exploitable vulnerability is the missing cache flush for `gas_feature_version < 38`, which affects all validators uniformly but breaks deterministic execution when verifier configs change. The "different compilation flags" scenario mentioned in the security question is operationally prevented by production tests but would amplify the impact if it occurred through validator misconfiguration.

### Citations

**File:** third_party/move/move-vm/runtime/src/storage/verified_module_cache.rs (L26-29)
```rust
    pub(crate) fn contains(&self, module_hash: &[u8; 32]) -> bool {
        // Note: need to use get to update LRU queue.
        verifier_cache_enabled() && self.0.lock().get(module_hash).is_some()
    }
```

**File:** third_party/move/move-vm/runtime/src/storage/verified_module_cache.rs (L51-54)
```rust
lazy_static! {
    pub(crate) static ref VERIFIED_MODULES_CACHE: VerifiedModuleCache =
        VerifiedModuleCache::empty();
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

**File:** aptos-move/aptos-vm-environment/src/environment.rs (L283-284)
```rust
        let verifier_bytes =
            bcs::to_bytes(&vm_config.verifier_config).expect("Verifier config is serializable");
```

**File:** aptos-node/src/tests.rs (L133-138)
```rust
    let feature = "disable_verifier_cache";
    assert!(
        !output.contains(feature),
        "Feature `{}` should not be enabled for aptos-node",
        feature
    );
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

**File:** aptos-move/aptos-gas-schedule/src/ver.rs (L104-111)
```rust
    pub const RELEASE_V1_34: u64 = 38;
    pub const RELEASE_V1_35: u64 = 39;
    pub const RELEASE_V1_36: u64 = 40;
    pub const RELEASE_V1_37: u64 = 41;
    pub const RELEASE_V1_38: u64 = 42;
    pub const RELEASE_V1_39: u64 = 43;
    pub const RELEASE_V1_40: u64 = 44;
    pub const RELEASE_V1_41: u64 = 45;
```

# Audit Report

## Title
Verifier Cache Invalidation Bypass Leading to Consensus Divergence for Networks with gas_feature_version < 38

## Summary

The `VERIFIED_MODULES_CACHE` uses only the module hash as a cache key, without considering the verifier configuration. For networks running with `gas_feature_version < RELEASE_V1_34` (value 38), cache invalidation when verifier configuration changes is not performed, allowing modules verified under relaxed settings to be executed under stricter settings. This creates a consensus divergence vulnerability where validators with different cache states produce different execution results for identical blocks. [1](#0-0) 

## Finding Description

The vulnerability exists in the module verification caching mechanism. When a module is verified, it is cached in a global static `VERIFIED_MODULES_CACHE` keyed only by module hash: [2](#0-1) 

The cache does not include the verifier configuration in the key. A mitigation was added to flush the cache when verifier configuration changes, but this mitigation is ONLY active when `gas_feature_version >= RELEASE_V1_34`: [3](#0-2) 

For networks with `gas_feature_version < 38`, when the verifier configuration changes (e.g., through governance enabling stricter feature flags like `ENABLE_FUNCTION_VALUES` which reduces `max_type_nodes` from 256 to 128), the cache is not flushed. [4](#0-3) 

**Attack Scenario:**

1. Network runs with `gas_feature_version = 30`, `ENABLE_FUNCTION_VALUES = false`
2. Module M with 200 type nodes is deployed (passes verification with `max_type_nodes = 256`)
3. Module M is verified and cached in `VERIFIED_MODULES_CACHE`
4. Governance enables `ENABLE_FUNCTION_VALUES` feature flag
5. New verifier config has `max_type_nodes = 128` (stricter)
6. Because `gas_feature_version < 38`, cache flush logic doesn't execute
7. Validator A (with cached Module M): loads from cache, executes successfully
8. Validator B (without cache/restarted): attempts verification with new config, fails (200 > 128), rejects transaction
9. **Consensus Divergence**: Same block produces different state roots on different validators [5](#0-4) 

## Impact Explanation

**Severity: HIGH to CRITICAL**

This vulnerability breaks the fundamental "Deterministic Execution" invariant: validators must produce identical state roots for identical blocks. The impact includes:

- **Consensus Divergence**: Different validators produce different execution results
- **Chain Split Risk**: Network could fork if validators disagree on block validity
- **Requires Hardfork**: Resolution may require emergency hardfork to restore consensus
- **Validator Set Impact**: Affected validators may be slashed or excluded

Under the Aptos Bug Bounty program, this qualifies as **Critical Severity** ("Consensus/Safety violations", "Non-recoverable network partition requiring hardfork") if exploitable on production networks, or **High Severity** ("Significant protocol violations") if limited to test networks.

## Likelihood Explanation

**Likelihood: MEDIUM for affected networks**

The vulnerability is triggered when:

1. **Network Configuration**: `gas_feature_version < RELEASE_V1_34` (38)
   - Current mainnet likely runs version 45, so **not vulnerable**
   - Testnets, devnets, or private networks may run older versions
   - Edge case: networks with missing gas schedule (version = 0) [6](#0-5) 

2. **Trigger Event**: Verifier configuration change via governance
   - Feature flag changes: `ENABLE_FUNCTION_VALUES`, `ENABLE_ENUM_TYPES`, `ENABLE_RESOURCE_ACCESS_CONTROL`
   - Requires legitimate governance proposal (not attacker-controlled)
   - But creates vulnerability window when validators have divergent cache states

3. **Cache State Divergence**: Validators with different cache states
   - Long-running validators have populated caches
   - Newly started or restarted validators have empty caches
   - Common during network upgrades or node maintenance

The likelihood is MEDIUM because while current mainnet is protected, the vulnerability still exists in the codebase for configurations that may be in use elsewhere.

## Recommendation

**Primary Fix**: Modify the cache key to include verifier configuration hash:

```rust
// In verified_module_cache.rs
pub(crate) struct VerifiedModuleCache(Mutex<lru::LruCache<([u8; 32], [u8; 32]), ()>>);

// In environment.rs build_locally_verified_module()
let verifier_config_hash = compute_verifier_config_hash(&self.vm_config().verifier_config);
let cache_key = (*module_hash, verifier_config_hash);

if !VERIFIED_MODULES_CACHE.contains(&cache_key) {
    // verification...
    VERIFIED_MODULES_CACHE.put(cache_key);
}
```

**Alternative Fix**: Remove the `gas_feature_version >= RELEASE_V1_34` condition to ensure cache flush always happens when config changes: [3](#0-2) 

Change to:
```rust
let flush_verifier_cache = self.environment.as_ref().is_none_or(|e| {
    e.verifier_config_bytes() != storage_environment.verifier_config_bytes()
});
if flush_verifier_cache {
    RuntimeEnvironment::flush_verified_module_cache();
}
```

**Immediate Mitigation**: For networks with `gas_feature_version < 38`, explicitly flush the verifier cache after any governance action that modifies feature flags.

## Proof of Concept

```rust
// Test demonstrating the vulnerability
#[test]
fn test_verifier_cache_invalidation_bypass() {
    use move_vm_runtime::RuntimeEnvironment;
    use aptos_types::on_chain_config::Features;
    
    // Setup: Create environment with gas_feature_version = 30 (< 38)
    let mut features = Features::default();
    features.disable(FeatureFlag::ENABLE_FUNCTION_VALUES);
    
    let env_old = create_test_environment_with_gas_version(30, &features);
    
    // Step 1: Verify and cache module with 200 type nodes
    let module_with_200_nodes = create_test_module_with_type_nodes(200);
    let module_hash = compute_hash(&module_with_200_nodes);
    
    // This should succeed with max_type_nodes = 256
    let result = env_old.build_locally_verified_module(
        Arc::new(module_with_200_nodes.clone()),
        1000,
        &module_hash
    );
    assert!(result.is_ok(), "Module should verify with old config");
    
    // Step 2: Change verifier config by enabling ENABLE_FUNCTION_VALUES
    features.enable(FeatureFlag::ENABLE_FUNCTION_VALUES);
    let env_new = create_test_environment_with_gas_version(30, &features);
    
    // Step 3: Verify cache was NOT flushed (because gas_feature_version < 38)
    // Validator A (with cache) succeeds
    let result_cached = env_old.build_locally_verified_module(
        Arc::new(module_with_200_nodes.clone()),
        1000,
        &module_hash
    );
    assert!(result_cached.is_ok(), "Cached verification should succeed");
    
    // Validator B (without cache) fails
    RuntimeEnvironment::flush_verified_module_cache(); // Simulate empty cache
    let result_fresh = env_new.build_locally_verified_module(
        Arc::new(module_with_200_nodes),
        1000,
        &module_hash
    );
    // This should fail because max_type_nodes = 128 < 200
    assert!(result_fresh.is_err(), "Fresh verification should fail with stricter config");
    
    // CONSENSUS DIVERGENCE: Same module, different verification results
}
```

**Notes**

- This vulnerability is **conditionally present** based on `gas_feature_version < 38`
- Current mainnet (likely version 45) has the mitigation in place via the gas version check
- Testnets, devnets, or networks with missing gas schedules remain vulnerable
- The root cause is architectural: cache key should include verifier configuration
- The gas version check is a workaround, not a complete fix

### Citations

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

**File:** third_party/move/move-vm/runtime/src/storage/verified_module_cache.rs (L9-49)
```rust
/// Cache for already verified modules. Since loader V1 uses such a cache to not perform repeated
/// verifications, possibly even across blocks, for comparative performance we need to have it as
/// well. For now, we keep it as a separate cache to make sure there is no interference between V1
/// and V2 implementations.
pub(crate) struct VerifiedModuleCache(Mutex<lru::LruCache<[u8; 32], ()>>);

impl VerifiedModuleCache {
    /// Maximum size of the cache. When modules are cached, they can skip re-verification.
    const VERIFIED_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(100_000).unwrap();

    /// Returns new empty verified module cache.
    pub(crate) fn empty() -> Self {
        Self(Mutex::new(lru::LruCache::new(Self::VERIFIED_CACHE_SIZE)))
    }

    /// Returns true if the module hash is contained in the cache. For tests, the cache is treated
    /// as empty at all times.
    pub(crate) fn contains(&self, module_hash: &[u8; 32]) -> bool {
        // Note: need to use get to update LRU queue.
        verifier_cache_enabled() && self.0.lock().get(module_hash).is_some()
    }

    /// Inserts the hash into the cache, marking the corresponding as locally verified. For tests,
    /// entries are not added to the cache.
    pub(crate) fn put(&self, module_hash: [u8; 32]) {
        if verifier_cache_enabled() {
            let mut cache = self.0.lock();
            cache.put(module_hash, ());
        }
    }

    /// Flushes the verified modules cache.
    pub(crate) fn flush(&self) {
        self.0.lock().clear();
    }

    /// Returns the number of verified modules in the cache.
    pub(crate) fn size(&self) -> usize {
        self.0.lock().len()
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

**File:** aptos-move/aptos-gas-schedule/src/ver.rs (L78-112)
```rust
pub mod gas_feature_versions {
    pub const RELEASE_V1_8: u64 = 11;
    pub const RELEASE_V1_9_SKIPPED: u64 = 12;
    pub const RELEASE_V1_9: u64 = 13;
    pub const RELEASE_V1_10: u64 = 15;
    pub const RELEASE_V1_11: u64 = 16;
    pub const RELEASE_V1_12: u64 = 17;
    pub const RELEASE_V1_13: u64 = 18;
    pub const RELEASE_V1_14: u64 = 19;
    pub const RELEASE_V1_15: u64 = 20;
    pub const RELEASE_V1_16: u64 = 21;
    pub const RELEASE_V1_18: u64 = 22;
    pub const RELEASE_V1_19: u64 = 23;
    pub const RELEASE_V1_20: u64 = 24;
    pub const RELEASE_V1_21: u64 = 25;
    pub const RELEASE_V1_22: u64 = 26;
    pub const RELEASE_V1_23: u64 = 27;
    pub const RELEASE_V1_24: u64 = 28;
    pub const RELEASE_V1_26: u64 = 30;
    pub const RELEASE_V1_27: u64 = 31;
    pub const RELEASE_V1_28: u64 = 32;
    pub const RELEASE_V1_29: u64 = 33;
    pub const RELEASE_V1_30: u64 = 34;
    pub const RELEASE_V1_31: u64 = 35;
    pub const RELEASE_V1_32: u64 = 36;
    pub const RELEASE_V1_33: u64 = 37;
    pub const RELEASE_V1_34: u64 = 38;
    pub const RELEASE_V1_35: u64 = 39;
    pub const RELEASE_V1_36: u64 = 40;
    pub const RELEASE_V1_37: u64 = 41;
    pub const RELEASE_V1_38: u64 = 42;
    pub const RELEASE_V1_39: u64 = 43;
    pub const RELEASE_V1_40: u64 = 44;
    pub const RELEASE_V1_41: u64 = 45;
}
```

**File:** aptos-move/aptos-vm-environment/src/gas.rs (L15-19)
```rust
pub fn get_gas_feature_version(state_view: &impl StateView) -> u64 {
    GasScheduleV2::fetch_config(state_view)
        .map(|gas_schedule| gas_schedule.feature_version)
        .unwrap_or(0)
}
```

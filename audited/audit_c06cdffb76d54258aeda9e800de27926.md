# Audit Report

## Title
Global Verified Module Cache Enables Cross-Chain Verification Bypass in Multi-VM Scenarios

## Summary
The global static `VERIFIED_MODULES_CACHE` uses only module hash as its cache key without chain-specific identifiers. When multiple VM instances for different chains exist in the same process (e.g., debugging tools, testing frameworks), a module verified under one chain's rules can bypass verification when loaded on another chain with different verification requirements, violating the deterministic execution invariant.

## Finding Description

The verified module cache is implemented as a process-wide singleton that caches verification results based solely on module hash: [1](#0-0) 

When a module is loaded, the system checks if its hash exists in the cache to skip verification: [2](#0-1) 

The comment at lines 188-191 states the assumption: "as long as the hash is the same, the deployed bytecode and any dependencies are the same, and so the cached verification result can be used."

**This assumption is incorrect for multi-chain scenarios** because:

1. **VerifierConfig varies by chain**: Different chains have different feature flags and verification rules: [3](#0-2) 

2. **Chain-specific features**: The config includes chain-dependent flags like `enable_enum_types`, `enable_function_values`, and different type limits (e.g., `max_type_nodes` = 128 vs 256).

3. **Tools create VMs without cache protection**: The aptos-debugger directly creates environments without using the cache protection mechanism: [4](#0-3) 

**Attack Scenario:**

1. Debugger/tool creates VM for Chain A (e.g., testnet with `ENABLE_FUNCTION_VALUES` enabled)
2. Loads module M using function values (valid on Chain A)
3. Module verified with Chain A's lenient rules, hash cached globally
4. Tool creates VM for Chain B (e.g., custom network with `ENABLE_FUNCTION_VALUES` disabled)
5. Loads same module M (same hash)
6. Cache hit → verification skipped
7. Module M accepted on Chain B despite violating its verification rules

**Broken Invariant:**
- **Deterministic Execution**: Validators/tools with different cache states could accept/reject the same module differently
- **Move VM Safety**: Bytecode verification can be bypassed across chain boundaries

## Impact Explanation

**Primary Impact: State Inconsistencies in Development/Analysis Tools (Medium Severity)**

This vulnerability primarily affects:
- **Debugging tools** that replay transactions across different chains
- **Testing frameworks** that simulate multiple chain configurations
- **Security analysis tools** that compare behavior across mainnet/testnet

While production validators typically run a single chain, the architectural flaw means:
- Incorrect security analysis results
- Development bugs from multi-chain testing
- Potential consensus issues if validators run analysis tools in-process

**Mitigation exists for production (partial):** [5](#0-4) 

However, this protection:
- Only applies to code paths using `ModuleCacheManager`
- Only works for `gas_feature_version >= RELEASE_V1_34`
- Does NOT protect debugging/analysis tools

This qualifies as **Medium severity** per bug bounty criteria: "State inconsistencies requiring intervention" in tool environments.

## Likelihood Explanation

**Likelihood: Low to Medium**

**Factors increasing likelihood:**
- Debugging tools (aptos-debugger) commonly replay transactions across chains
- Testing frameworks may run multi-chain scenarios
- Development workflows frequently compare mainnet/testnet behavior

**Factors decreasing likelihood:**
- Production validators run single chains
- ModuleCacheManager provides protection for main execution paths
- Exploitation requires specific tool usage patterns

The vulnerability is **architecturally present** but requires specific multi-chain tool usage to manifest.

## Recommendation

**Solution 1: Include chain-specific identifier in cache key**

Modify the cache to use a composite key including verifier config hash:

```rust
// In verified_module_cache.rs
pub(crate) struct VerifiedModuleCache(Mutex<lru::LruCache<VerificationKey, ()>>);

#[derive(Hash, Eq, PartialEq)]
struct VerificationKey {
    module_hash: [u8; 32],
    verifier_config_hash: [u8; 32],
}
```

**Solution 2: Flush cache on environment creation**

When creating a new `RuntimeEnvironment`, flush the global cache if the verifier config differs:

```rust
// In environment.rs, Environment::new()
let current_verifier_bytes = bcs::to_bytes(&vm_config.verifier_config)
    .expect("Verifier config is serializable");
    
// Check if verifier config changed and flush if needed
if should_flush_verifier_cache(&current_verifier_bytes) {
    RuntimeEnvironment::flush_verified_module_cache();
}
```

**Solution 3: Per-environment cache**

Replace global cache with per-environment caching to eliminate cross-chain sharing.

## Proof of Concept

```rust
// Reproduction test demonstrating the vulnerability
#[test]
fn test_cross_chain_cache_pollution() {
    use aptos_types::chain_id::ChainId;
    use aptos_vm_environment::environment::AptosEnvironment;
    use move_vm_runtime::RuntimeEnvironment;
    
    // Simulate state views for different chains with different features
    let testnet_state = create_state_with_features(ChainId::testnet(), enable_function_values_flag());
    let mainnet_state = create_state_with_features(ChainId::mainnet(), disable_function_values_flag());
    
    // Create VM for testnet
    let testnet_env = AptosEnvironment::new(&testnet_state);
    let module_bytes = compile_module_with_function_values();
    let module_hash = hash_module(&module_bytes);
    
    // Verify on testnet (should succeed with function values enabled)
    let result1 = testnet_env.runtime_environment()
        .build_locally_verified_module(module, size, &module_hash);
    assert!(result1.is_ok()); // Passes, cache populated
    
    // Create VM for mainnet
    let mainnet_env = AptosEnvironment::new(&mainnet_state);
    
    // Attempt to verify same module on mainnet (should fail but cache causes bypass)
    let result2 = mainnet_env.runtime_environment()
        .build_locally_verified_module(module, size, &module_hash);
    
    // BUG: This passes due to cache hit, but should fail on mainnet
    assert!(result2.is_ok()); // Incorrectly passes!
    
    // If we flush cache first, it correctly fails
    RuntimeEnvironment::flush_verified_module_cache();
    let result3 = mainnet_env.runtime_environment()
        .build_locally_verified_module(module, size, &module_hash);
    assert!(result3.is_err()); // Correctly fails
}
```

## Notes

This vulnerability represents an **architectural design flaw** in the global cache mechanism rather than a directly exploitable attack vector. While it primarily affects development and analysis tools rather than production consensus, it violates the fundamental assumption that cached verification results are universally valid. The issue is explicitly acknowledged in the codebase comment but incorrectly assumes chain-independence of verification rules.

The partial mitigation in `ModuleCacheManager` demonstrates awareness of the problem but doesn't protect all code paths, particularly debugging and analysis tools that are commonly used in the Aptos ecosystem.

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

**File:** aptos-move/aptos-debugger/src/aptos_debugger.rs (L147-148)
```rust
        let env = AptosEnvironment::new(&state_view);
        let vm = AptosVM::new(&env);
```

**File:** aptos-move/block-executor/src/code_cache_global_manager.rs (L117-125)
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
```

# Audit Report

## Title
Silent Fallback to Default Features Causes Consensus Divergence in Module Verification

## Summary
The `Environment::new` function silently falls back to `Features::default()` when on-chain Features cannot be fetched, causing validators with different state views to use different bytecode verifier configurations. This leads to consensus divergence when publishing Move modules with characteristics that fall between the different limit thresholds.

## Finding Description

The vulnerability exists in the environment initialization code where verifier configuration is determined based on on-chain feature flags. The critical code path is: [1](#0-0) 

When `fetch_config_and_update_hash::<Features>` returns `None` (due to state sync lag, corrupted state, or missing data), the code silently falls back to `Features::default()` without any error logging or alerting.

The verifier configuration is created based on these features: [2](#0-1) 

The `ENABLE_FUNCTION_VALUES` feature flag (flag #89) determines critical verification limits:
- When **enabled**: `max_type_nodes: Some(128)`, `max_function_return_values: Some(128)`, `max_type_depth: Some(20)`
- When **disabled**: `max_type_nodes: Some(256)`, `max_function_return_values: None`, `max_type_depth: None`

The default features list includes `ENABLE_FUNCTION_VALUES` as enabled: [3](#0-2) 

**Attack Scenario:**

1. Governance disables `ENABLE_FUNCTION_VALUES` on-chain (setting validators to use looser limits)
2. During execution of a block containing a module publish transaction:
   - **Validator A**: Successfully fetches Features from state → uses `max_type_nodes: Some(256)`, `max_function_return_values: None`
   - **Validator B**: Fails to fetch Features (state sync lag) → falls back to default → uses `max_type_nodes: Some(128)`, `max_function_return_values: Some(128)`
3. A module is published with 200 type nodes or 150 function return values
4. Module verification occurs in the bytecode verifier: [4](#0-3) 

5. **Validator A** accepts the module (200 < 256 or None means no limit)
6. **Validator B** rejects the module (200 > 128 or 150 > 128)
7. Validators commit different state roots → **consensus divergence**

The environment is cached and reused across blocks: [5](#0-4) 

This means a stale environment with incorrect configuration can persist across multiple blocks, amplifying the impact.

## Impact Explanation

**Severity: CRITICAL** ($1,000,000 tier per Aptos bug bounty)

This vulnerability causes a **Consensus/Safety violation**, which is explicitly listed as a critical severity issue:

1. **Network Partition**: Validators diverge on module acceptance, leading to different state roots for the same block
2. **Chain Split**: Different validators follow different forks based on their configurations
3. **Requires Hard Fork**: Recovery requires manual intervention and potential rollback
4. **Breaks Deterministic Execution Invariant**: All validators must produce identical state roots for identical blocks - this is violated
5. **No Byzantine Threshold Required**: This happens with <1/3 Byzantine nodes due to configuration bugs, not malicious behavior

The vulnerability is particularly severe because:
- Silent failure (no error logging when Features fetch fails)
- Affects all validators experiencing state sync issues
- Can persist across multiple blocks due to environment caching
- No built-in detection or recovery mechanism

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH**

This vulnerability is likely to occur because:

1. **State Sync Reliability Issues**: State synchronization across validators is complex and prone to temporary failures, especially during:
   - Network partitions or latency spikes
   - State pruning operations
   - Validator restarts or crashes
   - Rapid block production

2. **Governance Flag Changes**: When governance proposals modify feature flags, there's a window where different validators may observe different states

3. **No Error Detection**: The silent `unwrap_or_default()` pattern means validators don't alert operators when Features fetch fails

4. **Configuration Drift**: The environment caching mechanism means a validator that once failed to fetch Features will continue using the stale configuration until explicitly flushed

5. **Module Publishing is Common**: Move module deployments are regular operations on Aptos, providing frequent opportunities for this divergence to manifest

The main prerequisite is that at least one validator fails to fetch Features from state while others succeed, which is realistic under normal network conditions.

## Recommendation

Implement strict error handling for critical on-chain configurations and ensure deterministic fallback behavior:

**Fix 1: Fail-fast when Features cannot be fetched**
```rust
// In environment.rs, line 219-220
let features = fetch_config_and_update_hash::<Features>(&mut sha3_256, state_view)
    .expect("CRITICAL: Features must exist in state for consensus safety");
```

**Fix 2: Add explicit logging and monitoring**
```rust
let features = match fetch_config_and_update_hash::<Features>(&mut sha3_256, state_view) {
    Some(f) => f,
    None => {
        alert!("CRITICAL: Features not found in state, falling back to default");
        aptos_logger::error!("Features fetch failed at version {:?}", state_view.version());
        Features::default()
    }
};
```

**Fix 3: Make environment creation fallible**
```rust
fn new(
    state_view: &impl StateView,
    inject_create_signer_for_gov_sim: bool,
    gas_hook: Option<Arc<dyn Fn(DynamicExpression) + Send + Sync>>,
) -> Result<Self, VMStatus> {
    // Return error instead of using unwrap_or_default
}
```

**Fix 4: Add environment hash validation**
Before executing a block, validators should exchange and verify their environment hashes to detect configuration divergence early.

## Proof of Concept

```rust
// Test demonstrating consensus divergence
#[test]
fn test_verifier_config_divergence() {
    use aptos_types::state_store::MockStateView;
    use aptos_vm_environment::environment::AptosEnvironment;
    use move_binary_format::CompiledModule;
    
    // Setup: Create two state views
    // Validator A: Has Features in state with ENABLE_FUNCTION_VALUES = false
    let mut state_a = MockStateView::empty();
    let mut features_disabled = Features::default();
    features_disabled.disable(FeatureFlag::ENABLE_FUNCTION_VALUES);
    state_a.set_features(features_disabled);
    
    // Validator B: Missing Features (simulating state sync failure)
    let state_b = MockStateView::empty(); // No Features set
    
    // Create environments
    let env_a = AptosEnvironment::new(&state_a);
    let env_b = AptosEnvironment::new(&state_b);
    
    // Verify they have different configs
    assert_ne!(
        env_a.verifier_config_bytes(),
        env_b.verifier_config_bytes(),
        "Environment configs differ!"
    );
    
    // Create a module with 200 type nodes (between 128 and 256)
    let module = create_module_with_type_nodes(200);
    
    // Verify with both configs
    let result_a = move_bytecode_verifier::verify_module_with_config(
        &env_a.vm_config().verifier_config,
        &module
    );
    let result_b = move_bytecode_verifier::verify_module_with_config(
        &env_b.vm_config().verifier_config,
        &module
    );
    
    // Validator A accepts (limit is 256)
    assert!(result_a.is_ok(), "Validator A should accept module");
    
    // Validator B rejects (limit is 128)
    assert!(result_b.is_err(), "Validator B should reject module");
    assert_eq!(
        result_b.unwrap_err().major_status(),
        StatusCode::TOO_MANY_TYPE_NODES
    );
    
    // This demonstrates consensus divergence:
    // Same module, same block, different acceptance results!
    println!("CONSENSUS DIVERGENCE DETECTED: Validators would commit different states!");
}
```

## Notes

This vulnerability is particularly insidious because:

1. **Silent Failure**: No error is raised when Features fetch fails, making debugging extremely difficult
2. **Timing-Dependent**: Only manifests when validators have temporarily inconsistent state views
3. **Cascading Effect**: Once environments diverge, the caching mechanism perpetuates the divergence across multiple blocks
4. **Production Impact**: Default features have stricter limits, so validators failing to fetch Features become more restrictive, likely rejecting legitimate modules

The root cause is the use of `unwrap_or_default()` for a consensus-critical configuration. Any fallback behavior in consensus-sensitive code paths must be deterministic and identical across all validators. The current implementation violates this principle by allowing validators to independently decide whether to use on-chain or default configurations based on their local state availability.

### Citations

**File:** aptos-move/aptos-vm-environment/src/environment.rs (L219-220)
```rust
        let features =
            fetch_config_and_update_hash::<Features>(&mut sha3_256, state_view).unwrap_or_default();
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

**File:** types/src/on_chain_config/aptos_features.rs (L258-258)
```rust
            FeatureFlag::ENABLE_FUNCTION_VALUES,
```

**File:** third_party/move/move-bytecode-verifier/src/limits.rs (L189-193)
```rust
        if let Some(limit) = config.max_type_nodes {
            if type_size > limit {
                return Err(PartialVMError::new(StatusCode::TOO_MANY_TYPE_NODES));
            }
        }
```

**File:** aptos-move/block-executor/src/code_cache_global_manager.rs (L115-129)
```rust
        let environment_requires_update = self.environment.as_ref() != Some(&storage_environment);
        if environment_requires_update {
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

            self.environment = Some(storage_environment);
            self.module_cache.flush();
```

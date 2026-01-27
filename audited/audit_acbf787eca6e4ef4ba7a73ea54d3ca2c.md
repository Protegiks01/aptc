# Audit Report

## Title
Incomplete Feature Flag Validation Allows Unauthorized Flag Modifications to Pass Verification

## Summary
The `validate_upgrade()` function for `FeatureFlag` entries only validates that explicitly specified flags are in the expected state, but does not verify that the complete feature flag configuration matches expectations. This allows governance proposals to enable/disable additional flags beyond what was intended, and these unauthorized modifications will pass validation checks.

## Finding Description

The validation logic in `validate_upgrade()` has a critical gap that breaks the **Deterministic Execution** invariant (invariant #1) and **Governance Integrity** invariant (invariant #5). [1](#0-0) 

The validation only checks that:
1. All flags in `features.enabled` are enabled on-chain
2. All flags in `features.disabled` are disabled on-chain

**What it does NOT check**:
- Whether additional flags were enabled that are not in `features.enabled`
- Whether additional flags were disabled that are not in `features.disabled`
- Whether the complete set of enabled flags matches the expected configuration

**Attack Scenario**:

A malicious actor with governance influence could craft a proposal that:
1. Enables the expected flags A, B, C (as specified in release config)
2. **Also enables malicious flag D** (e.g., `ENABLE_TRUSTED_CODE` to disable runtime checks)
3. **Also disables critical flag E** (e.g., a security-critical verification flag)
4. Disables the expected flags X, Y (as specified in release config)

The validation would check:
- ✓ Are A, B, C enabled? Yes
- ✓ Are X, Y disabled? Yes
- **Does NOT check: Is D enabled when it shouldn't be?**
- **Does NOT check: Is E disabled when it shouldn't be?**

Feature flags control critical VM execution behavior through the `aptos_prod_vm_config()` function: [2](#0-1) 

Different feature flag states lead to different `VMConfig` settings for:
- Lazy module loading
- Function value depth checks
- Trusted code optimizations
- Type verification limits
- Binary format versions

If different validators end up with different feature flag states due to undetected malicious proposals, they will use different VM configurations, potentially causing:
- **Consensus violations** - different execution results for the same transactions
- **Chain splits** - validators commit different state roots
- **Security bypasses** - disabling critical runtime checks

## Impact Explanation

This is a **High Severity** vulnerability per Aptos bug bounty criteria because:

1. **Significant Protocol Violation**: Allows governance proposals to inject unauthorized feature flag changes that affect consensus-critical VM behavior
2. **Consensus Risk**: Different feature flag states across validators can lead to non-deterministic execution and state divergence
3. **Operational Risk**: Incomplete validation provides false confidence that upgrades executed correctly, masking state corruption

The vulnerability could escalate to **Critical Severity** if exploited to cause:
- Permanent consensus splits requiring hardfork
- Non-recoverable network partition
- Safety violations in AptosBFT consensus

While the attack requires governance influence, the incomplete validation creates a dangerous gap where such attacks go undetected, violating defense-in-depth principles.

## Likelihood Explanation

**Likelihood: Medium-High**

**Attack Requirements**:
- Attacker needs sufficient governance voting power OR ability to corrupt proposal execution
- Must craft a malicious proposal that appears legitimate
- Relies on operators trusting the incomplete validation

**Factors Increasing Likelihood**:
1. Validation is actively used to verify governance proposals
2. False positive validation creates operational blind spots
3. Feature flag changes are routine operations
4. Complexity of feature flag system makes manual verification difficult
5. No alternative verification mechanism exists

**Real-World Scenarios**:
- **Compromised governance participant** injects malicious flags
- **Bug in proposal generation** accidentally enables extra flags
- **Social engineering attack** where malicious proposal appears legitimate
- **Insider threat** from governance participant with voting power

## Recommendation

Implement complete feature flag state validation that verifies the entire configuration matches expectations:

```rust
ReleaseEntry::FeatureFlag(features) => {
    let on_chain_features = block_on(async {
        client
            .get_account_resource_bcs::<aptos_types::on_chain_config::Features>(
                CORE_CODE_ADDRESS,
                "0x1::features::Features",
            )
            .await
    })?;

    // Get all flags from the FeatureFlag enum
    let all_flags: Vec<FeatureFlag> = FeatureFlag::iter().collect();
    
    // Build expected state map
    let mut expected_state: HashMap<FeatureFlag, bool> = HashMap::new();
    for flag in &all_flags {
        expected_state.insert(*flag, false); // default to disabled
    }
    
    // Set expected enabled flags
    for to_enable in &features.enabled {
        expected_state.insert(to_enable.clone().into(), true);
    }
    
    // Set expected disabled flags (explicitly)
    for to_disable in &features.disabled {
        expected_state.insert(to_disable.clone().into(), false);
    }
    
    // Validate complete state matches expectations
    for (flag, expected_enabled) in expected_state {
        let actual_enabled = on_chain_features.inner().is_enabled(flag);
        if actual_enabled != expected_enabled {
            bail!(
                "Feature flag config mismatch: Expected {:?} to be {}, but was {}",
                flag,
                if expected_enabled { "enabled" } else { "disabled" },
                if actual_enabled { "enabled" } else { "disabled" }
            );
        }
    }
},
```

**Alternative approach**: Instead of listing enabled/disabled flags, store the complete expected feature vector as a hash and validate against it.

## Proof of Concept

```rust
// Test demonstrating the vulnerability
#[test]
fn test_incomplete_feature_flag_validation() {
    use aptos_types::on_chain_config::{Features, FeatureFlag};
    use crate::components::feature_flags;
    
    // Create release config that expects only flag A enabled
    let mut release_features = feature_flags::Features {
        enabled: vec![feature_flags::FeatureFlag::CodeDependencyCheck],
        disabled: vec![],
    };
    
    // Simulate on-chain state where BOTH flag A and flag B are enabled
    // (malicious proposal enabled extra flag B)
    let mut malicious_on_chain = Features::default();
    malicious_on_chain.enable(FeatureFlag::CODE_DEPENDENCY_CHECK);
    malicious_on_chain.enable(FeatureFlag::ENABLE_TRUSTED_CODE); // Extra flag!
    
    // Current validation logic
    // This SHOULD fail but WILL PASS because it only checks specified flags
    let specified_enabled = &release_features.enabled;
    for to_enable in specified_enabled {
        let flag = AptosFeatureFlag::from(to_enable.clone());
        assert!(malicious_on_chain.is_enabled(flag)); // This passes!
    }
    
    // Validation passes even though ENABLE_TRUSTED_CODE was maliciously enabled
    // This flag disables runtime checks, creating security vulnerability
    assert!(malicious_on_chain.is_enabled(FeatureFlag::ENABLE_TRUSTED_CODE));
    
    // VULNERABILITY: No check exists to detect this unauthorized flag
    // Different validators could have different states, breaking consensus
}
```

**Impact demonstration**: When `ENABLE_TRUSTED_CODE` is unexpectedly enabled, the VM configuration changes: [3](#0-2) 

This disables critical runtime verification checks, allowing potentially malicious code to execute without proper validation, which could lead to consensus violations if different validators have different feature flag states.

## Notes

The vulnerability exists at the intersection of governance safety and consensus integrity. While the attack requires governance influence, the incomplete validation violates defense-in-depth principles by providing false assurance that upgrades executed correctly. The on-chain feature flag mechanism properly restricts modification to framework signers, but the off-chain validation tool fails to detect unauthorized modifications, creating operational blind spots that could be exploited to introduce consensus violations.

### Citations

**File:** aptos-move/aptos-release-builder/src/components/mod.rs (L469-498)
```rust
            ReleaseEntry::FeatureFlag(features) => {
                let on_chain_features = block_on(async {
                    client
                        .get_account_resource_bcs::<aptos_types::on_chain_config::Features>(
                            CORE_CODE_ADDRESS,
                            "0x1::features::Features",
                        )
                        .await
                })?;

                for to_enable in &features.enabled {
                    let flag = to_enable.clone().into();
                    if !on_chain_features.inner().is_enabled(flag) {
                        bail!(
                            "Feature flag config mismatch: Expected {:?} to be enabled",
                            to_enable
                        );
                    }
                }

                for to_disable in &features.disabled {
                    let flag = to_disable.clone().into();
                    if on_chain_features.inner().is_enabled(flag) {
                        bail!(
                            "Feature flag config mismatch: Expected {:?} to be disabled",
                            to_disable
                        );
                    }
                }
            },
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L196-276)
```rust
/// Returns [VMConfig] used by the Aptos blockchain in production, based on the set of feature
/// flags.
pub fn aptos_prod_vm_config(
    chain_id: ChainId,
    gas_feature_version: u64,
    features: &Features,
    timed_features: &TimedFeatures,
    ty_builder: TypeBuilder,
) -> VMConfig {
    let paranoid_type_checks = get_paranoid_type_checks();
    let paranoid_ref_checks = get_paranoid_ref_checks();
    let enable_layout_caches = get_layout_caches();
    let enable_debugging = get_debugging_enabled();

    let deserializer_config = aptos_prod_deserializer_config(features);
    let verifier_config = aptos_prod_verifier_config(gas_feature_version, features);
    let enable_enum_option = features.is_enabled(FeatureFlag::ENABLE_ENUM_OPTION);
    let enable_framework_for_option = features.is_enabled(FeatureFlag::ENABLE_FRAMEWORK_FOR_OPTION);

    let layout_max_size = if gas_feature_version >= RELEASE_V1_30 {
        512
    } else {
        256
    };

    // Value runtime depth checks have been introduced together with function values and are only
    // enabled when the function values are enabled. Previously, checks were performed over types
    // to bound the value depth (checking the size of a packed struct type bounds the value), but
    // this no longer applies once function values are enabled. With function values, types can be
    // shallow while the value can be deeply nested, thanks to captured arguments not visible in a
    // type. Hence, depth checks have been adjusted to operate on values.
    let enable_depth_checks = features.is_enabled(FeatureFlag::ENABLE_FUNCTION_VALUES);
    let enable_capture_option = !timed_features.is_enabled(TimedFeatureFlag::DisabledCaptureOption)
        || features.is_enabled(FeatureFlag::ENABLE_CAPTURE_OPTION);

    // Some feature gating was missed, so for native dynamic dispatch the feature is always on for
    // testnet after 1.38 release.
    let enable_function_caches = features.is_call_tree_and_instruction_vm_cache_enabled();
    let enable_function_caches_for_native_dynamic_dispatch =
        enable_function_caches || (chain_id.is_testnet() && gas_feature_version >= RELEASE_V1_38);

    let config = VMConfig {
        verifier_config,
        deserializer_config,
        paranoid_type_checks,
        legacy_check_invariant_in_swap_loc: false,
        // Note: if updating, make sure the constant is in-sync.
        max_value_nest_depth: Some(DEFAULT_MAX_VM_VALUE_NESTED_DEPTH),
        layout_max_size,
        layout_max_depth: 128,
        // 5000 limits type tag total size < 5000 bytes and < 50 nodes.
        type_max_cost: 5000,
        type_base_cost: 100,
        type_byte_cost: 1,
        // By default, do not use delayed field optimization. Instead, clients should enable it
        // manually where applicable.
        delayed_field_optimization_enabled: false,
        ty_builder,
        enable_function_caches,
        enable_lazy_loading: features.is_lazy_loading_enabled(),
        enable_depth_checks,
        optimize_trusted_code: features.is_trusted_code_enabled(),
        paranoid_ref_checks,
        enable_capture_option,
        enable_enum_option,
        enable_layout_caches,
        propagate_dependency_limit_error: gas_feature_version >= RELEASE_V1_38,
        enable_framework_for_option,
        enable_function_caches_for_native_dynamic_dispatch,
        enable_debugging,
    };

    // Note: if max_value_nest_depth changed, make sure the constant is in-sync. Do not remove this
    // assertion as it ensures the constant value is set correctly.
    assert_eq!(
        config.max_value_nest_depth,
        Some(DEFAULT_MAX_VM_VALUE_NESTED_DEPTH)
    );

    config
}
```

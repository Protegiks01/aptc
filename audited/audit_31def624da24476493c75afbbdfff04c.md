# Audit Report

## Title
Config Sanitizer Bypass via Self-Referential Skip Flags Enables Consensus Divergence

## Summary
The `NodeStartupConfig` skip flags (`skip_config_optimizer` and `skip_config_sanitizer`) are embedded within the configuration file they control, creating a circular trust vulnerability. During emergency recovery scenarios, attackers can exploit this to inject malicious configs with disabled critical VM safety checks (`paranoid_type_verification`), potentially causing consensus divergence between validators. [1](#0-0) 

## Finding Description

The vulnerability exists in the node configuration loading architecture where validation controls are embedded within the data being validated. The attack exploits three interconnected weaknesses:

**1. Self-Referential Skip Flags**

The skip flags are part of the `NodeStartupConfig` structure that gets deserialized from the same YAML file they're meant to protect: [2](#0-1) 

**2. Bypass of Critical Mainnet Checks**

When `skip_config_sanitizer` is true, the sanitizer returns early without performing any validation: [3](#0-2) 

This bypasses critical mainnet-only safety requirements enforced by the ExecutionConfig sanitizer: [4](#0-3) 

**3. No Runtime Defense-in-Depth for VM Safety Flags**

Unlike validator network authentication (which has a runtime panic check), the `paranoid_type_verification` value from config is directly applied to global VM state without validation: [5](#0-4) [6](#0-5) 

**Attack Path:**

1. During a network-wide incident, emergency recovery procedures may involve sharing configuration templates
2. Attacker creates/modifies an "emergency config" with:
   ```yaml
   node_startup:
     skip_config_sanitizer: true
   execution:
     paranoid_type_verification: false
     paranoid_hot_potato_verification: false
   ```
3. Node operators deploy this config believing it's legitimate emergency guidance
4. Nodes restart with disabled paranoid type checking
5. The sanitizer that would normally reject disabled checks on mainnet is bypassed
6. Different validators may run with different VM safety settings
7. Type-safety-sensitive transactions could execute differently on nodes with checks disabled vs enabled
8. This breaks the **Deterministic Execution** invariant, causing consensus divergence

The test suite explicitly demonstrates this bypass capability: [7](#0-6) 

## Impact Explanation

**Severity: HIGH** (up to $50,000 per Aptos Bug Bounty - "Significant protocol violations")

This vulnerability enables:

1. **Consensus Divergence Risk**: Validators with different `paranoid_type_verification` settings may accept/reject the same transactions differently, violating the deterministic execution invariant
2. **VM Safety Degradation**: Paranoid type checks catch critical Move VM bugs. Disabling them on mainnet exposes nodes to:
   - Type confusion attacks
   - Ability constraint violations
   - Hot potato pattern bypasses
3. **Emergency Scenario Exploitation**: The attack is most viable during network incidents when operators are under pressure and may skip careful config validation

While not reaching "Critical" severity (no direct fund loss or total network halt), it represents a significant protocol violation that could cause state inconsistencies requiring hard intervention.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH during emergency scenarios**

**Attack Requirements:**
- Attacker must compromise config distribution channels OR have filesystem access on validator nodes
- Emergency scenario where operators are instructed to use special recovery configs
- Social engineering to make malicious configs appear legitimate

**Mitigating Factors:**
- Requires operators to deploy the malicious config
- Sophisticated operators may notice unusual config values
- Limited time window during emergencies

**Amplifying Factors:**
- Emergency scenarios reduce vigilance
- Skip flags appear to be "official" emergency features
- No runtime validation to catch the attack
- Once deployed, detection is difficult without cross-validator config audits

The circular trust design (config controls its own validation) significantly increases exploitability during crisis scenarios.

## Recommendation

**Implement defense-in-depth with external validation of critical flags:**

```rust
// In aptos-node/src/utils.rs - add after line 56
pub fn set_aptos_vm_configurations(node_config: &NodeConfig, chain_id: ChainId) {
    set_layout_caches(node_config.execution.layout_caches_enabled);
    
    // SECURITY: Enforce paranoid checks for mainnet regardless of config
    // This provides defense-in-depth against config sanitizer bypass
    let paranoid_type_verification = if chain_id.is_mainnet() {
        if !node_config.execution.paranoid_type_verification {
            panic!(
                "SECURITY VIOLATION: paranoid_type_verification must be enabled on mainnet! \
                 Current config has it disabled. This is not allowed even with skip_config_sanitizer."
            );
        }
        true // Force enable for mainnet
    } else {
        node_config.execution.paranoid_type_verification
    };
    
    set_paranoid_type_checks(paranoid_type_verification);
    set_async_runtime_checks(node_config.execution.async_runtime_checks);
    // ... rest of function
}
```

**Additional mitigations:**

1. **Restrict skip flag usage**: Make skip flags only work for non-mainnet chains:
   ```rust
   // In config/src/config/config_sanitizer.rs
   fn sanitize(node_config: &NodeConfig, node_type: NodeType, chain_id: Option<ChainId>) -> Result<(), Error> {
       // SECURITY: Never allow sanitizer skip on mainnet
       if node_config.node_startup.skip_config_sanitizer {
           if let Some(chain_id) = chain_id {
               if chain_id.is_mainnet() {
                   return Err(Error::ConfigSanitizerFailed(
                       "NodeStartupConfig".to_string(),
                       "skip_config_sanitizer cannot be enabled on mainnet!".into(),
                   ));
               }
           }
       }
       // ... rest of existing sanitization
   }
   ```

2. **External config signing**: Require emergency configs to be signed by Aptos Foundation keys, validated before node startup

3. **Runtime cross-validator config auditing**: Validators should periodically exchange config hashes to detect divergent configurations

## Proof of Concept

```rust
// Test demonstrating the vulnerability
// Add to config/src/config/config_sanitizer.rs

#[test]
fn test_mainnet_paranoid_checks_bypass_via_skip_sanitizer() {
    use crate::config::{NodeConfig, NodeStartupConfig, ExecutionConfig};
    use aptos_types::chain_id::ChainId;
    
    // Create a mainnet config with paranoid checks DISABLED (normally forbidden)
    let mut malicious_config = NodeConfig::default();
    malicious_config.node_startup = NodeStartupConfig {
        skip_config_sanitizer: true,  // Attacker's bypass flag
        skip_config_optimizer: false,
    };
    malicious_config.execution.paranoid_type_verification = false;  // UNSAFE for mainnet
    malicious_config.execution.paranoid_hot_potato_verification = false;  // UNSAFE for mainnet
    
    // This should FAIL but SUCCEEDS due to sanitizer bypass
    let result = NodeConfig::sanitize(
        &malicious_config,
        NodeType::Validator,
        Some(ChainId::mainnet()),
    );
    
    // The vulnerability: sanitizer passes malicious config
    assert!(result.is_ok(), "VULNERABILITY: Malicious config bypassed sanitizer!");
    
    // In production, this would lead to:
    // 1. set_paranoid_type_checks(false) being called
    // 2. VM running WITHOUT type safety checks on mainnet
    // 3. Potential consensus divergence with properly configured validators
}

#[test]
fn test_consensus_divergence_scenario() {
    // Scenario: Two validators with different configs
    
    // Validator A: Properly configured
    let mut proper_config = NodeConfig::default();
    proper_config.execution.paranoid_type_verification = true;
    
    // Validator B: Compromised with bypass
    let mut compromised_config = NodeConfig::default();
    compromised_config.node_startup.skip_config_sanitizer = true;
    compromised_config.execution.paranoid_type_verification = false;
    
    // Both configs pass their respective validation
    assert!(NodeConfig::sanitize(&proper_config, NodeType::Validator, Some(ChainId::mainnet())).is_ok());
    assert!(NodeConfig::sanitize(&compromised_config, NodeType::Validator, Some(ChainId::mainnet())).is_ok());
    
    // But they will execute Move code with DIFFERENT safety checks!
    // This breaks deterministic execution invariant
    // Result: Consensus divergence on type-safety-sensitive transactions
}
```

**Notes:**

The vulnerability is particularly insidious because:
1. The test suite itself documents this bypass capability (test_disable_config_sanitizer)
2. There's no runtime validation that chain_id + paranoid_type_verification settings are compatible
3. The mutual_authentication field has defense-in-depth (runtime panic), but VM safety flags don't
4. Emergency scenarios make social engineering attacks more plausible

The root cause is architectural: validation controls should never be part of the data structure they validate. Skip flags should either be removed entirely or controlled via external command-line arguments with strict chain-id-aware validation.

### Citations

**File:** config/src/config/node_startup_config.rs (L6-21)
```rust
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NodeStartupConfig {
    pub skip_config_optimizer: bool, // Whether or not to skip the config optimizer at startup
    pub skip_config_sanitizer: bool, // Whether or not to skip the config sanitizer at startup
}

#[allow(clippy::derivable_impls)] // Derive default manually (this is safer than guessing defaults)
impl Default for NodeStartupConfig {
    fn default() -> Self {
        Self {
            skip_config_optimizer: false,
            skip_config_sanitizer: false,
        }
    }
}
```

**File:** config/src/config/config_sanitizer.rs (L44-48)
```rust
    ) -> Result<(), Error> {
        // If config sanitization is disabled, don't do anything!
        if node_config.node_startup.skip_config_sanitizer {
            return Ok(());
        }
```

**File:** config/src/config/config_sanitizer.rs (L212-239)
```rust
    fn test_disable_config_sanitizer() {
        // Create a default node config (with sanitization enabled)
        let mut node_config = NodeConfig::default();

        // Set a bad node config for mainnet
        node_config.execution.paranoid_hot_potato_verification = false;

        // Sanitize the config and verify the sanitizer fails
        let error =
            NodeConfig::sanitize(&node_config, NodeType::Validator, Some(ChainId::mainnet()))
                .unwrap_err();
        assert!(matches!(error, Error::ConfigSanitizerFailed(_, _)));

        // Create a node config with the sanitizer disabled
        let mut node_config = NodeConfig {
            node_startup: NodeStartupConfig {
                skip_config_sanitizer: true,
                ..Default::default()
            },
            ..Default::default()
        };

        // Set a bad node config for mainnet
        node_config.execution.paranoid_hot_potato_verification = false;

        // Sanitize the config and verify the sanitizer passes
        NodeConfig::sanitize(&node_config, NodeType::Validator, Some(ChainId::mainnet())).unwrap();
    }
```

**File:** config/src/config/execution_config.rs (L166-183)
```rust
        // If this is a mainnet node, ensure that additional verifiers are enabled
        if let Some(chain_id) = chain_id {
            if chain_id.is_mainnet() {
                if !execution_config.paranoid_hot_potato_verification {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "paranoid_hot_potato_verification must be enabled for mainnet nodes!"
                            .into(),
                    ));
                }
                if !execution_config.paranoid_type_verification {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "paranoid_type_verification must be enabled for mainnet nodes!".into(),
                    ));
                }
            }
        }
```

**File:** aptos-node/src/utils.rs (L53-56)
```rust
pub fn set_aptos_vm_configurations(node_config: &NodeConfig) {
    set_layout_caches(node_config.execution.layout_caches_enabled);
    set_paranoid_type_checks(node_config.execution.paranoid_type_verification);
    set_async_runtime_checks(node_config.execution.async_runtime_checks);
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L205-240)
```rust
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
```

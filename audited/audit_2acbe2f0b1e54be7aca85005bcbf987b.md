# Audit Report

## Title
Config Sanitizer Bypass Allows Mainnet Validators to Run with Insecure Testing Configurations

## Summary
The `skip_config_sanitizer` flag in `NodeStartupConfig` can be set to `true` in a configuration file and replayed from testnet to mainnet, completely bypassing all mainnet-specific security validations. This allows attackers to deploy mainnet validators with dangerous testing configurations that violate critical security invariants.

## Finding Description

The vulnerability exists in the configuration sanitization logic. The `NodeStartupConfig` struct contains a `skip_config_sanitizer` field that is deserialized directly from YAML configuration files without any validation. [1](#0-0) 

When a node starts, the configuration sanitizer is called to enforce mainnet-specific security requirements. However, the very first check in the sanitizer looks at the `skip_config_sanitizer` flag and returns early if it's set to true, bypassing ALL subsequent security validations: [2](#0-1) 

This bypass occurs before any chain-specific checks are performed, meaning that even though the chain ID is correctly extracted from the genesis transaction, the sanitizer never uses it to enforce mainnet requirements. The sanitizer would normally enforce multiple critical security checks:

**Execution Config Mainnet Requirements:** [3](#0-2) 

**Safety Rules Mainnet Requirements:** [4](#0-3) 

**Failpoints Mainnet Restrictions:** [5](#0-4) 

### Attack Path

1. Attacker creates a testnet validator configuration with `skip_config_sanitizer: true` (legitimate for testing)
2. Attacker also sets insecure configurations such as:
   - `paranoid_hot_potato_verification: false`
   - `paranoid_type_verification: false`
   - Safety rules with in-memory backend
   - Safety rules test configurations enabled
   - Failpoints enabled
3. Attacker captures this testnet config file
4. Attacker deploys a mainnet validator using this config, pointing to mainnet genesis
5. During startup, `NodeConfig::load_from_path()` loads the config: [6](#0-5) 

6. The config loader calls `optimize_and_sanitize_node_config()`: [7](#0-6) 

7. Even though the chain ID is correctly extracted as mainnet from the genesis transaction, the sanitizer returns early due to `skip_config_sanitizer: true`, bypassing all mainnet security validations [8](#0-7) 

## Impact Explanation

This vulnerability qualifies as **HIGH severity** according to Aptos bug bounty criteria for "Significant protocol violations." The bypassed security checks are critical for mainnet validator security:

1. **Consensus Safety Risk**: Disabling `paranoid_hot_potato_verification` and `paranoid_type_verification` removes critical VM runtime checks designed to prevent consensus splits between validators. This could lead to different validators computing different state roots for the same block, violating the Deterministic Execution invariant.

2. **Validator Compromise Risk**: Using in-memory storage for the safety rules backend means validator signing keys are not properly protected by secure enclaves or key management systems, violating security best practices for mainnet validators.

3. **Failpoint Exploitation**: Enabling failpoints on mainnet allows arbitrary fault injection into critical code paths, which could be exploited to cause validator crashes, consensus delays, or state corruption.

4. **Test Configuration Risk**: Enabling safety rules test configurations on mainnet bypasses production consensus safety mechanisms.

The test case explicitly demonstrates this bypass is intentional but dangerous: [9](#0-8) 

## Likelihood Explanation

**Likelihood: Medium-High**

This vulnerability is likely to occur because:

1. **Simple Exploitation**: The attack requires no special privileges - any entity deploying a validator can create a custom config file
2. **Legitimate Testing Use**: The `skip_config_sanitizer` flag exists for legitimate testing purposes, making it easy for operators to accidentally or intentionally use testnet configs on mainnet
3. **No Warnings**: There are no runtime warnings or errors when this flag is used on mainnet
4. **Config Portability**: Configuration files are easily portable between testnet and mainnet deployments

The main limiting factor is that the attacker must be running their own validator node, but this is not a significant barrier for motivated attackers or even accidental misconfigurations by legitimate operators.

## Recommendation

Add explicit validation to prevent `skip_config_sanitizer` from being enabled on mainnet. This should be checked independently from the sanitizer itself to prevent the bypass:

```rust
// In config/src/config/node_config_loader.rs, in optimize_and_sanitize_node_config():

fn optimize_and_sanitize_node_config(
    node_config: &mut NodeConfig,
    local_config_yaml: Value,
) -> Result<(), Error> {
    // Extract the node type and chain ID from the node config
    let (node_type, chain_id) = extract_node_type_and_chain_id(node_config);

    // SECURITY FIX: Prevent skip_config_sanitizer on mainnet
    if let Some(chain_id) = chain_id {
        if chain_id.is_mainnet() && node_config.node_startup.skip_config_sanitizer {
            return Err(Error::ConfigSanitizerFailed(
                "StartupConfigSanitizer".to_string(),
                "skip_config_sanitizer cannot be enabled on mainnet! This flag is only for testing.".to_string(),
            ));
        }
    }

    // Print the extracted node type and chain ID
    println!(
        "Identified node type ({:?}) and chain ID ({:?}) from node config!",
        node_type, chain_id
    );

    // Optimize the node config
    NodeConfig::optimize(node_config, &local_config_yaml, node_type, chain_id)?;

    // Sanitize the node config
    NodeConfig::sanitize(node_config, node_type, chain_id)
}
```

Additionally, consider adding similar protection for `skip_config_optimizer` on mainnet, as it may also have security implications.

## Proof of Concept

```rust
#[cfg(test)]
mod test_mainnet_config_bypass {
    use super::*;
    use crate::config::{
        node_startup_config::NodeStartupConfig,
        ExecutionConfig, NodeConfig,
    };
    use aptos_types::chain_id::ChainId;

    #[test]
    fn test_skip_sanitizer_bypasses_mainnet_checks() {
        // Create a mainnet config with insecure settings that should fail validation
        let mut node_config = NodeConfig {
            node_startup: NodeStartupConfig {
                skip_config_sanitizer: false, // Sanitizer enabled
                ..Default::default()
            },
            execution: ExecutionConfig {
                paranoid_hot_potato_verification: false, // INSECURE for mainnet!
                ..Default::default()
            },
            ..Default::default()
        };

        // This should FAIL because paranoid_hot_potato_verification must be true on mainnet
        let result = NodeConfig::sanitize(&node_config, NodeType::Validator, Some(ChainId::mainnet()));
        assert!(result.is_err(), "Expected sanitizer to reject insecure mainnet config");

        // NOW: Enable skip_config_sanitizer (as if replayed from testnet)
        node_config.node_startup.skip_config_sanitizer = true;

        // This should still FAIL but it PASSES - THIS IS THE VULNERABILITY!
        let result = NodeConfig::sanitize(&node_config, NodeType::Validator, Some(ChainId::mainnet()));
        assert!(result.is_ok(), "VULNERABILITY: Sanitizer bypassed for mainnet with skip_config_sanitizer=true!");
        
        println!("VULNERABILITY CONFIRMED: Mainnet security checks bypassed!");
        println!("An insecure config (paranoid_hot_potato_verification=false) was accepted on mainnet");
        println!("This could lead to consensus safety violations");
    }
}
```

## Notes

This vulnerability is particularly concerning because:

1. The `skip_config_sanitizer` flag is serialized/deserialized as part of the config, making config replay trivial
2. There is no distinction between "testing flags" and "production flags" at the type level
3. The early return pattern means that even future mainnet-specific checks added to the sanitizer would also be bypassed
4. The test case at line 212-239 in `config_sanitizer.rs` explicitly demonstrates this bypass working, suggesting this behavior may be documented but not recognized as a security risk

The fix must validate the startup config independently from the sanitizer itself, as relying on the sanitizer to validate the flag that controls whether the sanitizer runs creates a chicken-and-egg problem.

### Citations

**File:** config/src/config/node_startup_config.rs (L6-11)
```rust
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NodeStartupConfig {
    pub skip_config_optimizer: bool, // Whether or not to skip the config optimizer at startup
    pub skip_config_sanitizer: bool, // Whether or not to skip the config sanitizer at startup
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

**File:** config/src/config/config_sanitizer.rs (L82-91)
```rust
    // Verify that failpoints are not enabled in mainnet
    let failpoints_enabled = are_failpoints_enabled();
    if let Some(chain_id) = chain_id {
        if chain_id.is_mainnet() && failpoints_enabled {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "Failpoints are not supported on mainnet nodes!".into(),
            ));
        }
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

**File:** config/src/config/safety_rules_config.rs (L85-112)
```rust
        if let Some(chain_id) = chain_id {
            // Verify that the secure backend is appropriate for mainnet validators
            if chain_id.is_mainnet()
                && node_type.is_validator()
                && safety_rules_config.backend.is_in_memory()
            {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "The secure backend should not be set to in memory storage in mainnet!"
                        .to_string(),
                ));
            }

            // Verify that the safety rules service is set to local for optimal performance
            if chain_id.is_mainnet() && !safety_rules_config.service.is_local() {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    format!("The safety rules service should be set to local in mainnet for optimal performance! Given config: {:?}", &safety_rules_config.service)
                ));
            }

            // Verify that the safety rules test config is not enabled in mainnet
            if chain_id.is_mainnet() && safety_rules_config.test.is_some() {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "The safety rules test config should not be used in mainnet!".to_string(),
                ));
            }
```

**File:** aptos-node/src/lib.rs (L177-183)
```rust
            let config = NodeConfig::load_from_path(config_path.clone()).unwrap_or_else(|error| {
                panic!(
                    "Failed to load the node config file! Given file path: {:?}. Error: {:?}",
                    config_path.display(),
                    error
                )
            });
```

**File:** config/src/config/node_config_loader.rs (L109-124)
```rust
/// Extracts the node type and chain ID from the given node config
/// and genesis transaction. If the chain ID cannot be extracted,
/// None is returned.
fn extract_node_type_and_chain_id(node_config: &NodeConfig) -> (NodeType, Option<ChainId>) {
    // Get the node type from the node config
    let node_type = NodeType::extract_from_config(node_config);

    // Get the chain ID from the genesis transaction
    match get_chain_id(node_config) {
        Ok(chain_id) => (node_type, Some(chain_id)),
        Err(error) => {
            println!("Failed to extract the chain ID from the genesis transaction: {:?}! Continuing with None.", error);
            (node_type, None)
        },
    }
}
```

**File:** config/src/config/node_config_loader.rs (L126-145)
```rust
/// Optimize and sanitize the node config for the current environment
fn optimize_and_sanitize_node_config(
    node_config: &mut NodeConfig,
    local_config_yaml: Value,
) -> Result<(), Error> {
    // Extract the node type and chain ID from the node config
    let (node_type, chain_id) = extract_node_type_and_chain_id(node_config);

    // Print the extracted node type and chain ID
    println!(
        "Identified node type ({:?}) and chain ID ({:?}) from node config!",
        node_type, chain_id
    );

    // Optimize the node config
    NodeConfig::optimize(node_config, &local_config_yaml, node_type, chain_id)?;

    // Sanitize the node config
    NodeConfig::sanitize(node_config, node_type, chain_id)
}
```

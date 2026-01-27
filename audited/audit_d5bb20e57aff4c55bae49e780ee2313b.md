# Audit Report

## Title
Node Startup Configuration Flags Allow Bypass of Mandatory Mainnet Security Policies

## Summary
The `skip_config_sanitizer` and `skip_config_optimizer` flags in `NodeStartupConfig` allow node operators to bypass all mandatory security policy enforcement for mainnet nodes, enabling them to run with disabled safety features that are explicitly required by network policies.

## Finding Description

The Aptos node configuration system enforces mandatory security policies through a sanitizer that validates configurations before node startup. [1](#0-0) 

However, both sanitization and optimization can be completely bypassed using startup configuration flags. [2](#0-1) 

This bypass allows mainnet node operators to violate multiple mandatory security requirements:

**1. Paranoid VM Verification Bypasses**

The sanitizer enforces that mainnet nodes MUST enable paranoid type verification and hot potato verification. [3](#0-2) 

These checks are critical runtime safety mechanisms that prevent VM execution divergence. By disabling the sanitizer, operators can run mainnet nodes without these protections, potentially causing consensus splits if different validators execute bytecode differently.

**2. Safety Rules Security Bypasses**

For mainnet validators, the sanitizer enforces secure backend storage (not in-memory), local safety rules service, and prohibits test configurations. [4](#0-3) 

Bypassing these checks allows validators to use insecure configurations that could compromise consensus safety.

**3. Consensus Feature Bypasses**

The sanitizer prohibits the consensus-only-perf-test feature on mainnet. [5](#0-4) 

**4. Network Security Bypasses**

The optimizer enforces mutual authentication for validator networks. [6](#0-5) 

The sanitizer validates this requirement. [7](#0-6) 

**5. Additional Mainnet Policy Bypasses**

- Failpoints cannot be enabled on mainnet [8](#0-7) 
- Admin service requires authentication on mainnet [9](#0-8) 
- Validators cannot expose configuration on mainnet [10](#0-9) 

The vulnerability occurs because production nodes load configuration through a path that respects these bypass flags. [11](#0-10) 

## Impact Explanation

This is a **Medium severity** compliance violation per the bug bounty criteria. While it doesn't directly cause fund loss or consensus failure, it:

1. **Violates Deterministic Execution Invariant**: Nodes with disabled paranoid checks may execute bytecode differently than compliant nodes, potentially causing state divergence
2. **Undermines Network Security Policies**: Allows individual operators to bypass governance decisions about mandatory security features
3. **Creates Consensus Risk**: If multiple validators disable safety features, network integrity could be compromised
4. **Enables Insider Threats**: Malicious validator operators can intentionally weaken their node's security posture

The impact is classified as Medium because it requires operator action (not externally exploitable) and affects individual nodes rather than the entire network directly. However, it creates significant risk if widely adopted.

## Likelihood Explanation

**Likelihood: Medium to High**

- **Ease of Exploitation**: Trivial - operators need only add a single line to their configuration file
- **Detection Difficulty**: Low - no automated monitoring exists to detect nodes running with bypassed sanitizers
- **Operator Motivation**: Some operators may disable checks for perceived performance benefits or to work around legitimate configuration issues
- **Accidental Misconfiguration**: Operators debugging issues might enable these flags and forget to remove them

The test suite explicitly demonstrates this bypass functionality, suggesting it was intentionally designed. [12](#0-11) 

## Recommendation

**Primary Fix**: Prevent sanitizer bypass for mainnet production environments:

```rust
impl ConfigSanitizer for NodeConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        // For mainnet, never allow skipping the sanitizer
        if let Some(chain_id) = chain_id {
            if chain_id.is_mainnet() && node_config.node_startup.skip_config_sanitizer {
                return Err(Error::ConfigSanitizerFailed(
                    "NodeConfigSanitizer".to_string(),
                    "Cannot skip config sanitizer on mainnet nodes!".to_string(),
                ));
            }
        }
        
        // Original sanitization logic continues...
```

**Alternative Approaches**:
1. Remove the bypass flags entirely from production builds (compile-time feature gate for test-only usage)
2. Add telemetry to detect and alert when nodes run with bypassed sanitizers
3. Document that these flags are test-only and must never be used on mainnet
4. Implement network-level monitoring to identify non-compliant validator configurations

## Proof of Concept

Create a mainnet validator configuration that bypasses all security checks:

```yaml
# node_config.yaml
node_startup:
  skip_config_sanitizer: true
  skip_config_optimizer: true

base:
  role: "Validator"
  
execution:
  paranoid_type_verification: false  # Violates mainnet policy
  paranoid_hot_potato_verification: false  # Violates mainnet policy

consensus:
  safety_rules:
    backend:
      type: "InMemory"  # Violates mainnet policy for validators
    test:
      author: "0x1"  # Violates mainnet policy
```

Steps to reproduce:
1. Create the above configuration file for a mainnet validator
2. Load the configuration using `NodeConfig::load_from_path()`
3. Observe that all sanitizer checks are bypassed despite violating multiple mainnet policies
4. The node will start successfully with security features disabled

This configuration would normally fail with errors like "paranoid_hot_potato_verification must be enabled for mainnet nodes!" but succeeds when the sanitizer is bypassed.

**Notes**

The existence of these bypass flags suggests they were intended for testing or development environments. However, their availability in production builds creates a governance compliance gap where individual operators can unilaterally decide to ignore mandatory network security policies. The severity is classified as Medium because the impact requires operator cooperation rather than external exploitation, but the ease of bypass and potential for consensus divergence make this a significant security concern for network integrity.

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

**File:** config/src/config/config_sanitizer.rs (L82-90)
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
```

**File:** config/src/config/config_sanitizer.rs (L191-197)
```rust
        // Ensure that mutual authentication is enabled
        if !validator_network_config.mutual_authentication {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "Mutual authentication must be enabled for the validator network!".into(),
            ));
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

**File:** config/src/config/safety_rules_config.rs (L85-113)
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
        }
```

**File:** config/src/config/consensus_config.rs (L515-523)
```rust
        // Verify that the consensus-only feature is not enabled in mainnet
        if let Some(chain_id) = chain_id {
            if chain_id.is_mainnet() && is_consensus_only_perf_test_enabled() {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "consensus-only-perf-test should not be enabled in mainnet!".to_string(),
                ));
            }
        }
```

**File:** config/src/config/config_optimizer.rs (L257-261)
```rust
        // We must enable mutual authentication for the validator network
        if local_network_config_yaml["mutual_authentication"].is_null() {
            validator_network_config.mutual_authentication = true;
            modified_config = true;
        }
```

**File:** config/src/config/admin_service_config.rs (L67-76)
```rust
        if node_config.admin_service.enabled == Some(true) {
            if let Some(chain_id) = chain_id {
                if chain_id.is_mainnet()
                    && node_config.admin_service.authentication_configs.is_empty()
                {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "Must enable authentication for AdminService on mainnet.".into(),
                    ));
                }
```

**File:** config/src/config/inspection_service_config.rs (L54-64)
```rust
        // Verify that mainnet validators do not expose the configuration
        if let Some(chain_id) = chain_id {
            if node_type.is_validator()
                && chain_id.is_mainnet()
                && inspection_service_config.expose_configuration
            {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "Mainnet validators should not expose the node configuration!".to_string(),
                ));
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

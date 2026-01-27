# Audit Report

## Title
Critical Sanitization Bypass via `skip_config_sanitizer` Flag Allows Dangerous Mainnet Configurations

## Summary
The node configuration sanitizer contains a bypass mechanism (`skip_config_sanitizer` flag) that allows ALL security validation checks to be skipped when set to `true`. This flag has no validation preventing its use on mainnet, allowing dangerous configurations—including disabled Move VM safety checks, insecure consensus settings, and vulnerable network configurations—to remain active on production validator nodes.

## Finding Description

The `optimize_and_sanitize_node_config()` function calls `NodeConfig::sanitize()` at line 144, which is intended to validate that node configurations meet security requirements for the current environment (node type and chain ID). [1](#0-0) 

However, the sanitizer implementation contains a bypass mechanism that returns success without performing any validation: [2](#0-1) 

The `skip_config_sanitizer` flag is a user-configurable boolean field defined in the node configuration: [3](#0-2) 

When this flag is set to `true` in a node's YAML configuration file, the sanitizer returns `Ok(())` without executing ANY of the sub-sanitizers, bypassing all critical mainnet security checks including:

1. **Move VM Safety Checks** - ExecutionConfig sanitizer enforces `paranoid_hot_potato_verification` and `paranoid_type_verification` must be enabled on mainnet: [4](#0-3) 

2. **Consensus SafetyRules Security** - SafetyRulesConfig sanitizer enforces secure backend storage and local service mode on mainnet validators: [5](#0-4) 

3. **Validator Network Authentication** - Network sanitizer enforces mutual authentication for validator networks: [6](#0-5) 

**Attack Vectors:**

1. **Misconfiguration**: Operator accidentally deploys a test/development config with `skip_config_sanitizer: true` to production
2. **Config File Compromise**: Attacker gains write access to node config files and sets the flag along with malicious values
3. **Social Engineering**: Attacker convinces operator to add the flag for "debugging" or "performance" reasons
4. **Supply Chain**: Malicious deployment scripts or config templates include the bypass flag

**Exploitation Path:**

An attacker creates a malicious node configuration:
```yaml
node_startup:
  skip_config_sanitizer: true

execution:
  paranoid_hot_potato_verification: false
  paranoid_type_verification: false

consensus:
  safety_rules:
    backend: "InMemoryStorage"
    service: "Thread"

validator_network:
  mutual_authentication: false
```

When this config is loaded via `NodeConfig::load_from_path()`, the sanitization is completely bypassed, and the dangerous configuration remains active. [7](#0-6) 

## Impact Explanation

**Severity: CRITICAL** (Consensus/Safety Violations, potential Loss of Funds)

This vulnerability enables multiple critical security failures on mainnet:

1. **Consensus Safety Violation**: A validator using `InMemoryStorage` for SafetyRules loses consensus safety guarantees on restart. SafetyRules maintains the last vote cast to prevent equivocation (double-signing). With in-memory storage, this state is lost on restart, allowing the validator to potentially vote for conflicting blocks in the same round, violating AptosBFT safety guarantees and enabling double-spend attacks.

2. **Move VM Execution Correctness**: Disabling `paranoid_hot_potato_verification` and `paranoid_type_verification` removes critical runtime safety checks in the Move VM. These checks prevent type confusion bugs and hot potato (non-droppable resource) violations. If a Move VM implementation bug exists, disabled checks could allow state divergence between validators, breaking the **Deterministic Execution** invariant.

3. **Network Security Compromise**: Disabling `mutual_authentication` on validator networks allows unauthorized peers to connect, potentially enabling consensus message injection or manipulation attacks.

4. **Consensus Parameter Violations**: Bypassing consensus config sanitization allows invalid block size limits, which could cause validators to reject blocks from others, leading to network fragmentation.

This meets **Critical Severity** criteria: Consensus/Safety violations that could lead to chain splits, state divergence, or loss of funds through double-spending.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

The vulnerability requires an attacker to influence the node configuration file, which can occur through:

1. **Accidental Misconfiguration** (MEDIUM likelihood): Operators commonly use different configs for testing/development vs production. If a test config with `skip_config_sanitizer: true` is accidentally deployed to mainnet, all sanitization is bypassed.

2. **Config File Compromise** (LOW-MEDIUM likelihood): If an attacker gains file system access (via another vulnerability, compromised deployment pipeline, or insider threat), they can modify the config to enable the bypass flag.

3. **Social Engineering** (LOW-MEDIUM likelihood): Attackers could impersonate support staff or provide "performance optimization" guides that include the bypass flag.

The vulnerability is particularly dangerous because:
- There's NO warning or error when the flag is set on mainnet
- The sanitizer silently returns success, providing false confidence
- Test configs might legitimately use this flag, creating operational confusion
- The impact is immediate upon node restart with the malicious config

## Recommendation

**Immediate Fix**: The sanitizer should NEVER be skippable on mainnet. Add validation to reject the bypass flag for mainnet nodes:

```rust
impl ConfigSanitizer for NodeConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        // CRITICAL: Never allow sanitization to be skipped on mainnet
        if let Some(chain_id) = chain_id {
            if chain_id.is_mainnet() && node_config.node_startup.skip_config_sanitizer {
                return Err(Error::ConfigSanitizerFailed(
                    "MainnetBypassProtection".to_string(),
                    "The skip_config_sanitizer flag cannot be set to true on mainnet! \
                     This flag bypasses critical security checks and is only for testing.".to_string(),
                ));
            }
        }

        // If config sanitization is disabled for non-mainnet, return early
        if node_config.node_startup.skip_config_sanitizer {
            println!("WARNING: Config sanitization is disabled! This should only be used in testing.");
            return Ok(());
        }

        // Sanitize all of the sub-configs...
        // (rest of implementation unchanged)
    }
}
```

**Additional Recommendations**:
1. Add logging/metrics when `skip_config_sanitizer` is true to detect accidental production use
2. Consider removing the flag entirely and using environment variables for testing
3. Add integration tests that verify mainnet configs cannot bypass sanitization
4. Document the security implications of this flag prominently in configuration guides

## Proof of Concept

Create a malicious config file `mainnet_bypass_poc.yaml`:

```yaml
# Malicious mainnet config with sanitization bypass
base:
  role: "validator"
  data_dir: "/opt/aptos/data"
  waypoint:
    from_config: "0:6072b68a942aace147e0655c5704beaa255c84a7829baa4e72a500f1516584c4"

node_startup:
  skip_config_sanitizer: true  # BYPASS ALL SECURITY CHECKS

execution:
  paranoid_hot_potato_verification: false  # DISABLE MOVE VM SAFETY
  paranoid_type_verification: false        # DISABLE TYPE CHECKS
  genesis_file_location: "genesis.blob"

consensus:
  safety_rules:
    backend: "InMemoryStorage"  # INSECURE: Loses safety on restart
    service: "Thread"            # SUBOPTIMAL: Should be Local on mainnet

validator_network:
  network_id: "Validator"
  discovery_method: "Onchain"
  mutual_authentication: false  # INSECURE: Allows unauthorized peers
  listen_address: "/ip4/0.0.0.0/tcp/6180"
```

Rust reproduction test (add to `config/src/config/config_sanitizer.rs`):

```rust
#[test]
fn test_mainnet_sanitizer_bypass_vulnerability() {
    // Create a mainnet validator config with dangerous settings
    let node_config = NodeConfig {
        node_startup: NodeStartupConfig {
            skip_config_sanitizer: true,  // Bypass enabled
            ..Default::default()
        },
        execution: ExecutionConfig {
            paranoid_hot_potato_verification: false,  // DANGEROUS on mainnet
            paranoid_type_verification: false,         // DANGEROUS on mainnet
            ..Default::default()
        },
        consensus: ConsensusConfig {
            safety_rules: SafetyRulesConfig {
                backend: SecureBackend::InMemoryStorage,  // DANGEROUS on mainnet
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    // VULNERABILITY: This should FAIL on mainnet but currently PASSES
    let result = NodeConfig::sanitize(
        &node_config,
        NodeType::Validator,
        Some(ChainId::mainnet()),  // MAINNET
    );

    // Current behavior: Returns Ok(()) despite dangerous config
    assert!(result.is_ok(), "VULNERABILITY: Dangerous mainnet config was not rejected!");
    
    // Expected behavior: Should return Err() to prevent dangerous config
    // After fix, this test should fail, confirming the vulnerability is patched
}
```

This PoC demonstrates that a mainnet validator configuration with disabled security checks passes sanitization when `skip_config_sanitizer: true`, violating multiple critical security invariants.

## Notes

The vulnerability is particularly insidious because:
- The bypass flag has a legitimate use case (testing) but lacks safeguards for production use
- The sanitizer silently succeeds, providing false confidence that configs are safe
- Multiple critical security checks across consensus, execution, and networking are bypassed simultaneously
- The default value is `false`, so the vulnerability requires explicit configuration, but operational errors or malicious actors could easily set it to `true`

This represents a fundamental design flaw in the configuration validation architecture that should be addressed immediately for mainnet deployments.

### Citations

**File:** config/src/config/node_config_loader.rs (L127-145)
```rust
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

**File:** config/src/config/config_sanitizer.rs (L44-48)
```rust
    ) -> Result<(), Error> {
        // If config sanitization is disabled, don't do anything!
        if node_config.node_startup.skip_config_sanitizer {
            return Ok(());
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

**File:** config/src/config/node_startup_config.rs (L8-11)
```rust
pub struct NodeStartupConfig {
    pub skip_config_optimizer: bool, // Whether or not to skip the config optimizer at startup
    pub skip_config_sanitizer: bool, // Whether or not to skip the config sanitizer at startup
}
```

**File:** config/src/config/execution_config.rs (L167-183)
```rust
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

**File:** config/src/config/node_config.rs (L140-143)
```rust
    pub fn load_from_path<P: AsRef<Path>>(input_path: P) -> Result<Self, Error> {
        let node_config_loader = NodeConfigLoader::new(input_path);
        node_config_loader.load_and_sanitize_config()
    }
```

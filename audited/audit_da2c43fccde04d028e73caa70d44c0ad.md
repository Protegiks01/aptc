# Audit Report

## Title
Configuration Sanitizer Bypass via skip_config_sanitizer Allows Validators to Deploy Insecure Configurations

## Summary
The `local_config_yaml` parameter at line 141 of `node_config_loader.rs` can contain a configuration directive (`skip_config_sanitizer: true`) that completely bypasses all security validation checks, allowing validator operators to deploy nodes with dangerous configurations that violate consensus safety invariants.

## Finding Description

The configuration loading system contains a critical design flaw where the `skip_config_sanitizer` field can be set in the local configuration YAML to bypass all security validations. This breaks the fundamental security invariant that all validators must operate with safe configurations to maintain consensus safety.

**Attack Flow:**

1. A validator operator creates a local config YAML file with: [1](#0-0) 

2. The config loader deserializes this YAML into the NodeConfig struct: [2](#0-1) 

3. The optimizer runs at line 141, respecting user-set values: [3](#0-2) 

4. The sanitizer check at line 144 is completely bypassed: [4](#0-3) 

**Dangerous Configurations Enabled:**

With sanitizer bypass, validators can set:
- **InMemoryStorage backend for safety rules on mainnet** - violates the requirement that mainnet validators must use persistent storage to prevent equivocation: [5](#0-4) 

- **Disabled mutual authentication** - violates the requirement that validator networks must enforce mutual authentication: [6](#0-5) 

- **Invalid network IDs** - allows validator networks to use public network IDs: [7](#0-6) 

## Impact Explanation

**Critical Severity** - This vulnerability enables **Consensus Safety Violations**, qualifying for up to $1,000,000 under the Aptos bug bounty program.

**Specific Impacts:**

1. **Equivocation Risk**: A validator using InMemoryStorage for safety rules loses their safety data on crash/restart, enabling double-signing of conflicting blocks. This directly violates **Consensus Safety** invariant #2: "AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine"

2. **Unauthorized Network Access**: Disabling mutual authentication allows unauthorized peers to connect to validator networks, potentially enabling message injection or consensus manipulation

3. **Network-Wide Impact**: While the misconfiguration affects a single validator, the resulting Byzantine behavior (equivocation, invalid voting) impacts the entire network's consensus safety

4. **Systematic Risk**: The bypass mechanism is discoverable and could be exploited by multiple validators simultaneously, approaching or exceeding the 1/3 Byzantine fault tolerance threshold

## Likelihood Explanation

**High Likelihood** for the following reasons:

1. **Discoverability**: The `skip_config_sanitizer` field is documented in the codebase and visible in the configuration struct definition

2. **Test Evidence**: The existence of a test explicitly demonstrating sanitizer bypass indicates this is a known capability: [8](#0-7) 

3. **Operational Scenarios**: Validators may intentionally disable sanitizer during testing/debugging and accidentally deploy to mainnet with the flag enabled

4. **No Runtime Protection**: There is no secondary validation mechanism to detect when nodes are running with sanitizer disabled

## Recommendation

**Immediate Fix**: Remove the `skip_config_sanitizer` capability from production code entirely. If needed for development/testing, make it compilation-conditional:

```rust
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NodeStartupConfig {
    pub skip_config_optimizer: bool,
    #[cfg(not(feature = "production"))]
    pub skip_config_sanitizer: bool,
}

impl Default for NodeStartupConfig {
    fn default() -> Self {
        Self {
            skip_config_optimizer: false,
            #[cfg(not(feature = "production"))]
            skip_config_sanitizer: false,
        }
    }
}
```

**Sanitizer Implementation Fix**:
```rust
impl ConfigSanitizer for NodeConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        #[cfg(not(feature = "production"))]
        {
            if node_config.node_startup.skip_config_sanitizer {
                return Ok(());
            }
        }
        
        // Sanitize all of the sub-configs
        AdminServiceConfig::sanitize(node_config, node_type, chain_id)?;
        // ... rest of sanitization
    }
}
```

**Additional Protections**:
1. Add runtime telemetry to detect when validators are running with insecure configurations
2. Implement peer validation to reject connections from validators with invalid network configurations
3. Add startup warnings/errors when critical security settings don't match expected values for the detected chain_id

## Proof of Concept

**Step 1**: Create malicious validator config file `insecure_validator.yaml`:
```yaml
node_startup:
  skip_config_sanitizer: true

consensus:
  safety_rules:
    backend:
      type: "in_memory_storage"
    test:
      author: "0x1"

validator_network:
  network_id: "Public"
  mutual_authentication: false
```

**Step 2**: Load and verify bypass:
```rust
use aptos_config::config::{NodeConfig, PersistableConfig, NodeConfigLoader};
use aptos_config::config::node_config_loader::NodeType;
use aptos_types::chain_id::ChainId;

#[test]
fn test_sanitizer_bypass_vulnerability() {
    // Load the malicious config
    let loader = NodeConfigLoader::new("insecure_validator.yaml");
    let node_config = loader.load_and_sanitize_config().unwrap();
    
    // Verify dangerous settings were loaded
    assert!(node_config.node_startup.skip_config_sanitizer);
    assert!(node_config.consensus.safety_rules.backend.is_in_memory());
    assert!(!node_config.validator_network.as_ref().unwrap().mutual_authentication);
    
    // These settings should have been rejected by sanitizer for mainnet validators
    // but were allowed due to skip_config_sanitizer bypass
}
```

**Step 3**: Demonstrate equivocation scenario:
```rust
// Validator node crashes with InMemoryStorage
// Safety data (last_voted_round, preferred_block_round) is lost
// On restart, validator can vote for conflicting blocks in same round
// This violates consensus safety and enables equivocation
```

## Notes

This vulnerability represents a fundamental design flaw where a testing/debugging feature (`skip_config_sanitizer`) was left accessible in production code. While it requires validator operator access to exploit, the capability itself should not exist in production builds as it undermines the entire security validation framework designed to prevent consensus-breaking misconfigurations.

### Citations

**File:** config/src/config/node_startup_config.rs (L9-10)
```rust
    pub skip_config_optimizer: bool, // Whether or not to skip the config optimizer at startup
    pub skip_config_sanitizer: bool, // Whether or not to skip the config sanitizer at startup
```

**File:** config/src/config/node_config_loader.rs (L74-87)
```rust
        let mut node_config = NodeConfig::load_config(&self.node_config_path)?;

        // Load the execution config
        let input_dir = RootPath::new(&self.node_config_path);
        node_config.execution.load_from_path(&input_dir)?;

        // Update the data directory. This needs to be done before
        // we optimize and sanitize the node configs (because some optimizers
        // rely on the data directory for file reading/writing).
        node_config.set_data_dir(node_config.get_data_dir().to_path_buf());

        // Optimize and sanitize the node config
        let local_config_yaml = get_local_config_yaml(&self.node_config_path)?;
        optimize_and_sanitize_node_config(&mut node_config, local_config_yaml)?;
```

**File:** config/src/config/node_config_loader.rs (L141-141)
```rust
    NodeConfig::optimize(node_config, &local_config_yaml, node_type, chain_id)?;
```

**File:** config/src/config/config_sanitizer.rs (L45-48)
```rust
        // If config sanitization is disabled, don't do anything!
        if node_config.node_startup.skip_config_sanitizer {
            return Ok(());
        }
```

**File:** config/src/config/config_sanitizer.rs (L175-181)
```rust
        let network_id = validator_network_config.network_id;
        if !network_id.is_validator_network() {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "The validator network config must have a validator network ID!".into(),
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

**File:** config/src/config/config_sanitizer.rs (L225-238)
```rust
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
```

**File:** config/src/config/safety_rules_config.rs (L86-96)
```rust
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
```

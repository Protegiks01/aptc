# Audit Report

## Title
Configuration Schema Evolution Causes Node Startup Failures During Binary Upgrades

## Summary
The Aptos node configuration system uses `#[serde(deny_unknown_fields)]` extensively across all config structs without version tracking or migration logic. When node software is upgraded and configuration schemas evolve (fields removed or renamed), existing config files cause deserialization failures, leading to node startup crashes and potential network liveness degradation.

## Finding Description

The vulnerability exists in the configuration deserialization layer where schema evolution is not handled gracefully: [1](#0-0) 

The `GasEstimationConfig` struct uses `#[serde(default, deny_unknown_fields)]` which causes serde to reject any fields in the YAML that don't exist in the struct definition. This pattern is used across ~26 critical config structs: [2](#0-1) 

When configs are loaded during node startup, deserialization failures cause immediate panic: [3](#0-2) 

The deserialization uses direct serde_yaml parsing without any migration or version compatibility layer: [4](#0-3) 

**Attack Scenario:**
1. Aptos releases version N+1 that removes a config field (e.g., removes `incorporate_reordering_effects` from `GasEstimationConfig`)
2. Validators upgrade their node binaries to version N+1
3. Existing config YAML files on disk still contain the removed field
4. On startup, `NodeConfig::load_from_path()` calls `serde_yaml::from_str()`
5. Serde encounters the unknown field and returns an error due to `deny_unknown_fields`
6. Node panics with error message and refuses to start
7. Validator is offline until config is manually corrected

This affects all config structs using this pattern, including critical consensus and execution configs: [5](#0-4) [6](#0-5) 

## Impact Explanation

**Medium Severity** - This meets the "State inconsistencies requiring intervention" criterion:

1. **Network Liveness Risk**: If many validators upgrade simultaneously without updating configs, consensus participation drops, potentially halting the network
2. **Validator Downtime**: Individual validators cannot participate until manual intervention
3. **No Automatic Recovery**: Requires human operator to edit config files
4. **Widespread Scope**: Affects ~26 config structs including consensus-critical components

However, this is NOT Critical/High because:
- No funds are at risk
- No consensus safety violation (safety vs liveness)
- Recoverable through manual config updates
- Not exploitable by external attackers

## Likelihood Explanation

**High Likelihood** that this will occur eventually because:

1. **Config schemas naturally evolve** as features are added/removed
2. **No protection mechanism exists** - no version field, no migration logic, no deprecation support
3. **Already happened in other systems** - this is a common failure mode in production systems
4. **Testing gaps** - integration tests use generated configs, not real-world upgrade scenarios

The likelihood of impact is **Medium** because:
- Coordinated upgrades typically happen gradually
- Operators have config update procedures
- Release notes should document config changes

## Recommendation

Implement one or more of these solutions:

**Option 1: Remove `deny_unknown_fields`**
Allow forward compatibility by ignoring unknown fields:
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default)] // Remove deny_unknown_fields
pub struct GasEstimationConfig {
    // fields...
}
```

**Option 2: Use `#[serde(alias)]` for renamed fields**
Support both old and new field names during transition:
```rust
#[serde(alias = "old_field_name")]
pub new_field_name: Type,
```

**Option 3: Add config versioning and migration**
```rust
#[derive(Deserialize)]
#[serde(untagged)]
enum ConfigVersion {
    V1(ConfigV1),
    V2(ConfigV2),
}

impl ConfigVersion {
    fn migrate_to_latest(self) -> ConfigV2 {
        match self {
            ConfigVersion::V1(v1) => v1.into(),
            ConfigVersion::V2(v2) => v2,
        }
    }
}
```

**Option 4: Graceful degradation**
Catch deserialization errors and provide helpful error messages with auto-fix suggestions.

## Proof of Concept

```rust
// Create a test demonstrating the failure
#[test]
fn test_config_schema_evolution_breaks_deserialization() {
    use serde::{Deserialize, Serialize};
    
    // Old schema with deprecated field
    let old_config_yaml = r#"
enabled: true
full_block_txns: 250
low_block_history: 10
market_block_history: 30
aggressive_block_history: 120
cache_expiration_ms: 500
incorporate_reordering_effects: true
deprecated_field: 100
"#;
    
    // New schema (without deprecated_field)
    #[derive(Debug, Deserialize, Serialize)]
    #[serde(default, deny_unknown_fields)]
    struct NewGasEstimationConfig {
        pub enabled: bool,
        pub full_block_txns: usize,
        pub low_block_history: usize,
        pub market_block_history: usize,
        pub aggressive_block_history: usize,
        pub cache_expiration_ms: u64,
        pub incorporate_reordering_effects: bool,
    }
    
    impl Default for NewGasEstimationConfig {
        fn default() -> Self {
            Self {
                enabled: true,
                full_block_txns: 250,
                low_block_history: 10,
                market_block_history: 30,
                aggressive_block_history: 120,
                cache_expiration_ms: 500,
                incorporate_reordering_effects: true,
            }
        }
    }
    
    // This will fail with "unknown field `deprecated_field`"
    let result: Result<NewGasEstimationConfig, _> = serde_yaml::from_str(old_config_yaml);
    
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("unknown field"));
    
    // This simulates what happens during node startup:
    // The node would panic here, preventing startup
}

// Reproduction steps:
// 1. Start a node with current version and config
// 2. Save the config file to disk
// 3. Upgrade node binary to version with field removed from struct
// 4. Restart node -> PANIC: "unknown field" error
// 5. Node remains offline until operator manually edits config
```

**Notes**

While this issue affects availability and operational robustness, it's important to clarify that:

1. **Not exploitable by external attackers** - requires node operator to upgrade software
2. **Primarily an operational concern** - relates to upgrade management, not active exploitation
3. **Recoverable** - operators can fix configs and restart
4. **Preventable** - proper release management and testing can mitigate this

The severity is rated Medium because it can cause validator downtime and requires manual intervention, but it doesn't compromise consensus safety, enable fund theft, or create permanent damage. This is a legitimate configuration management vulnerability that should be addressed to improve system resilience during upgrades.

### Citations

**File:** config/src/config/gas_estimation_config.rs (L17-36)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct GasEstimationConfig {
    /// A gate for computing GasEstimation. If false, just returns the default.
    pub enabled: bool,
    /// Static values to override. If set, use these values instead of computing a GasEstimation.
    pub static_override: Option<GasEstimationStaticOverride>,
    /// Number of transactions for blocks to be classified as full for gas estimation
    pub full_block_txns: usize,
    /// Maximum number of blocks read for low gas estimation
    pub low_block_history: usize,
    /// Maximum number of blocks read for market gas estimation
    pub market_block_history: usize,
    /// Maximum number of blocks read for aggressive gas estimation
    pub aggressive_block_history: usize,
    /// Time after write when previous value is returned without recomputing
    pub cache_expiration_ms: u64,
    /// Whether to account which TransactionShufflerType is used onchain, and how it affects gas estimation
    pub incorporate_reordering_effects: bool,
}
```

**File:** config/src/config/node_config.rs (L35-36)
```rust
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
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

**File:** config/src/config/persistable_config.rs (L52-55)
```rust
    /// Parse the config from the serialized string
    fn parse_serialized_config(serialized_config: &str) -> Result<Self, Error> {
        serde_yaml::from_str(serialized_config).map_err(|e| Error::Yaml("config".to_string(), e))
    }
```

**File:** config/src/config/consensus_config.rs (L31-31)
```rust
#[serde(default, deny_unknown_fields)]
```

**File:** config/src/config/execution_config.rs (L31-31)
```rust
#[serde(default, deny_unknown_fields)]
```

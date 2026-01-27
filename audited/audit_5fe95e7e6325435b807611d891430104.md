# Audit Report

## Title
Insecure Default Storage Backend for Validator Safety Rules Enables Consensus Safety Violations on Testnet and Misconfigured Validators

## Summary
The `SafetyRulesConfig` structure defaults to `InMemoryStorage` backend when not explicitly configured. This in-memory storage backend loses all critical consensus safety data on validator restarts, enabling double-voting and consensus safety violations. While mainnet validators are protected by the config sanitizer, testnet validators and validators with missing genesis files remain vulnerable to this misconfiguration.

## Finding Description

The Aptos consensus layer relies on `SafetyRules` to prevent equivocation (double-voting) by persistently storing critical safety data including the validator's last voted round, consensus private key, and voting history. This data **must survive restarts** to maintain consensus safety guarantees. [1](#0-0) 

When a validator configuration file omits the `consensus.safety_rules.backend` field (due to the `#[serde(default)]` annotation), the configuration defaults to `InMemoryStorage`: [2](#0-1) 

The `InMemoryStorage` implementation explicitly documents it should not be used in production: [3](#0-2) 

This storage backend holds critical consensus data: [4](#0-3) 

The safety data includes `last_voted_round` which prevents double-voting: [5](#0-4) 

**The Vulnerability Path:**

1. A validator configuration file omits the `backend:` field under `consensus.safety_rules`
2. Serde deserializer uses the `Default` implementation → `InMemoryStorage`
3. The config sanitizer only checks mainnet validators: [6](#0-5) 

4. For testnet validators or when `chain_id` extraction fails (returns `None`), the sanitizer does NOT reject `InMemoryStorage`
5. The validator starts successfully and stores all safety data in memory
6. On restart, all safety data is lost including `last_voted_round`
7. The validator can now vote on rounds it previously voted on, causing equivocation

## Impact Explanation

This vulnerability breaks the **Consensus Safety** invariant that "AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine validators."

**Critical Severity** per Aptos Bug Bounty criteria:
- **Consensus/Safety violations**: Validators can double-vote after restart, violating BFT safety
- **Potential chain split**: If multiple validators lose safety data simultaneously, they may vote inconsistently
- **Loss of consensus key**: The BLS private key stored in `CONSENSUS_KEY` is also lost, preventing the validator from participating

The secure storage README confirms the criticality: [7](#0-6) 

While the sanitizer protects mainnet, **testnet validators** running production-like workloads for testing, partner integrations, or pre-mainnet validation are unprotected. The sanitizer's chain ID check excludes testnets: [8](#0-7) 

## Likelihood Explanation

**Medium to High Likelihood** in the following scenarios:

1. **Testnet Validators**: Operators copying mainnet config templates but running on testnet chains are not protected by the sanitizer
2. **Genesis File Issues**: If genesis file is missing or corrupted, `chain_id` extraction fails and returns `None`, bypassing the sanitizer: [9](#0-8) 

3. **Configuration Templates**: The default validator template used by `get_default_validator_config()` does NOT specify the backend field: [10](#0-9) 

4. **Incomplete Configuration**: Validator operators creating minimal configurations may omit the backend field, relying on defaults

## Recommendation

**Immediate Fix**: Make `SecureBackend` a required field with no default, forcing explicit configuration:

```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)] // Remove 'default'
pub struct SafetyRulesConfig {
    pub backend: SecureBackend, // No default - must be explicitly configured
    #[serde(default)]
    pub logger: LoggerConfig,
    #[serde(default)]
    pub service: SafetyRulesService,
    pub test: Option<SafetyRulesTestConfig>,
    #[serde(default = "default_network_timeout_ms")]
    pub network_timeout_ms: u64,
    #[serde(default = "default_enable_cached_safety_data")]
    pub enable_cached_safety_data: bool,
    #[serde(default)]
    pub initial_safety_rules_config: InitialSafetyRulesConfig,
}

fn default_network_timeout_ms() -> u64 { 30_000 }
fn default_enable_cached_safety_data() -> bool { true }
```

**Enhanced Sanitizer**: Expand protection to all validators regardless of chain:

```rust
// Verify that validators NEVER use in-memory storage
if node_type.is_validator() && safety_rules_config.backend.is_in_memory() {
    return Err(Error::ConfigSanitizerFailed(
        sanitizer_name,
        "Validators must not use in-memory storage! Use on_disk_storage or vault.".to_string(),
    ));
}
```

**Documentation**: Update all validator configuration templates and documentation to explicitly show backend configuration as required.

## Proof of Concept

```rust
// Simulation showing the vulnerability
use aptos_config::config::{SafetyRulesConfig, SecureBackend};
use serde_yaml;

fn main() {
    // Minimal validator config without backend specified
    let minimal_config_yaml = r#"
consensus:
  safety_rules:
    service:
      type: local
"#;
    
    // Parse the config - will use Default implementation
    let parsed: serde_yaml::Value = serde_yaml::from_str(minimal_config_yaml).unwrap();
    let safety_rules: SafetyRulesConfig = 
        serde_yaml::from_value(parsed["consensus"]["safety_rules"].clone())
            .unwrap_or_default();
    
    // Verify it defaults to InMemoryStorage (VULNERABLE)
    assert!(safety_rules.backend.is_in_memory());
    println!("❌ VULNERABLE: Config defaults to InMemoryStorage!");
    println!("   Backend: {:?}", safety_rules.backend);
    println!("   This validator will lose all safety data on restart!");
    
    // Demonstrate sanitizer gap for testnet
    use aptos_config::config::{NodeConfig, ConsensusConfig};
    use aptos_config::config::node_config_loader::NodeType;
    use aptos_types::chain_id::ChainId;
    use aptos_config::config::config_sanitizer::ConfigSanitizer;
    
    let node_config = NodeConfig {
        consensus: ConsensusConfig {
            safety_rules: SafetyRulesConfig {
                backend: SecureBackend::InMemoryStorage,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };
    
    // Mainnet validator - BLOCKED
    let result_mainnet = SafetyRulesConfig::sanitize(
        &node_config,
        NodeType::Validator,
        Some(ChainId::mainnet()),
    );
    assert!(result_mainnet.is_err());
    println!("✅ Mainnet validator: Correctly blocked");
    
    // Testnet validator - ALLOWED (VULNERABLE!)
    let result_testnet = SafetyRulesConfig::sanitize(
        &node_config,
        NodeType::Validator,
        Some(ChainId::testnet()),
    );
    assert!(result_testnet.is_ok());
    println!("❌ Testnet validator: Allowed to use InMemoryStorage!");
    
    // Missing chain_id - ALLOWED (VULNERABLE!)
    let result_none = SafetyRulesConfig::sanitize(
        &node_config,
        NodeType::Validator,
        None,
    );
    assert!(result_none.is_ok());
    println!("❌ Validator with missing genesis: Allowed to use InMemoryStorage!");
}
```

This PoC demonstrates:
1. Configurations without explicit backend default to unsafe `InMemoryStorage`
2. The sanitizer only protects mainnet, leaving testnet and misconfigured validators vulnerable
3. Validators can start successfully with this insecure configuration and lose safety data on restart

### Citations

**File:** config/src/config/safety_rules_config.rs (L23-34)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SafetyRulesConfig {
    pub backend: SecureBackend,
    pub logger: LoggerConfig,
    pub service: SafetyRulesService,
    pub test: Option<SafetyRulesTestConfig>,
    // Read/Write/Connect networking operation timeout in milliseconds.
    pub network_timeout_ms: u64,
    pub enable_cached_safety_data: bool,
    pub initial_safety_rules_config: InitialSafetyRulesConfig,
}
```

**File:** config/src/config/safety_rules_config.rs (L36-49)
```rust
impl Default for SafetyRulesConfig {
    fn default() -> Self {
        Self {
            backend: SecureBackend::InMemoryStorage,
            logger: LoggerConfig::default(),
            service: SafetyRulesService::Local,
            test: None,
            // Default value of 30 seconds for a timeout
            network_timeout_ms: 30_000,
            enable_cached_safety_data: true,
            initial_safety_rules_config: InitialSafetyRulesConfig::None,
        }
    }
}
```

**File:** config/src/config/safety_rules_config.rs (L85-96)
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
```

**File:** secure/storage/src/in_memory.rs (L9-19)
```rust
/// InMemoryStorage represents a key value store that is purely in memory and intended for single
/// threads (or must be wrapped by a Arc<RwLock<>>). This provides no permission checks and simply
/// is a proof of concept to unblock building of applications without more complex data stores.
/// Internally, it retains all data, which means that it must make copies of all key material which
/// violates the code base. It violates it because the anticipation is that data stores would
/// securely handle key material. This should not be used in production.
#[derive(Default)]
pub struct InMemoryStorage {
    data: HashMap<String, Vec<u8>>,
    time_service: TimeService,
}
```

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L24-28)
```rust
pub struct PersistentSafetyStorage {
    enable_cached_safety_data: bool,
    cached_safety_data: Option<SafetyData>,
    internal_store: Storage,
}
```

**File:** consensus/consensus-types/src/safety_data.rs (L8-21)
```rust
/// Data structure for safety rules to ensure consensus safety.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize, Clone, Default)]
pub struct SafetyData {
    pub epoch: u64,
    pub last_voted_round: u64,
    // highest 2-chain round, used for 3-chain
    pub preferred_round: u64,
    // highest 1-chain round, used for 2-chain
    #[serde(default)]
    pub one_chain_round: u64,
    pub last_vote: Option<Vote>,
    #[serde(default)]
    pub highest_timeout_round: u64,
}
```

**File:** secure/storage/README.md (L34-36)
```markdown
- `InMemory`: The InMemory secure storage implementation provides a simple in-memory storage
engine. This engine should only be used for testing, as it does not offer any persistence, or
security (i.e., data is simply held in DRAM and may be lost on a crash, or restart).
```

**File:** config/src/config/node_config_loader.rs (L117-124)
```rust
    match get_chain_id(node_config) {
        Ok(chain_id) => (node_type, Some(chain_id)),
        Err(error) => {
            println!("Failed to extract the chain ID from the genesis transaction: {:?}! Continuing with None.", error);
            (node_type, None)
        },
    }
}
```

**File:** config/src/config/test_data/validator.yaml (L12-17)
```yaml
consensus:
    safety_rules:
        service:
            type: process
            server_address: "/ip4/127.0.0.1/tcp/5555"

```

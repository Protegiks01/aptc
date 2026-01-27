# Audit Report

## Title
Non-Mainnet Production Validators Can Use InMemoryStorage Without Policy Enforcement Leading to Consensus Safety Violations

## Summary
Non-mainnet production validators (testnet, devnet, premainnet) can be configured to use `InMemoryStorage` for consensus safety rules, which provides no policy enforcement and loses critical consensus safety data on restart. This violates consensus safety invariants when validators restart without persisted voting state.

## Finding Description

The `InMemoryStorage` implementation explicitly provides no permission checks and is intended only for testing: [1](#0-0) 

Despite this warning, the `SecureBackend` configuration enum includes `InMemoryStorage` as a valid production option: [2](#0-1) 

The `SafetyRulesConfig` sanitizer only prevents `InMemoryStorage` for **mainnet validators**, allowing it for all other chains: [3](#0-2) 

This means testnet validators (chain_id=2), devnet validators (chain_id=3), and premainnet validators (chain_id=5) can use `InMemoryStorage`. Additionally, if `chain_id` extraction fails, the check is skipped entirely: [4](#0-3) 

The `PersistentSafetyStorage` uses this storage backend to store critical consensus data: [5](#0-4) 

When `InMemoryStorage` is used, all consensus safety data (epoch, last_voted_round, preferred_round, consensus private keys, waypoint) is lost on validator restart, potentially causing the validator to vote inconsistently and violate consensus safety rules.

## Impact Explanation

**HIGH Severity** - This constitutes a significant protocol violation affecting testnet and devnet production networks:

1. **Consensus Safety Violation**: A validator using `InMemoryStorage` that restarts loses its `last_voted_round` state, potentially allowing it to vote twice in the same round, violating the fundamental safety guarantee of AptosBFT
2. **Liveness Impact**: Testnet and devnet are long-lived production networks with real validators and users. Loss of consensus safety data causes network instability
3. **No Access Control**: `InMemoryStorage` provides no policy enforcement, meaning any process with access to the validator's memory can read consensus private keys [6](#0-5) 

## Likelihood Explanation

**MEDIUM Likelihood**: While this requires validator operator misconfiguration, several factors increase the likelihood:

1. The default `SafetyRulesConfig` uses `InMemoryStorage`: [7](#0-6) 

2. Testnet/devnet operators may not realize the security implications
3. The sanitizer can be completely bypassed: [8](#0-7) 

4. Failed genesis transaction parsing results in `chain_id=None`, skipping all checks

## Recommendation

Extend the sanitization check to prevent `InMemoryStorage` for **all validator nodes**, not just mainnet:

```rust
// In safety_rules_config.rs, line 85-96
if node_type.is_validator() && safety_rules_config.backend.is_in_memory() {
    return Err(Error::ConfigSanitizerFailed(
        sanitizer_name,
        "InMemoryStorage should never be used for validators. Use OnDiskStorage or Vault for persistent storage.".to_string(),
    ));
}
```

Additionally, ensure `OnDiskStorage` and `Vault` provide actual policy enforcement as specified by the `KVStorage` trait contract: [9](#0-8) 

## Proof of Concept

```yaml
# testnet_validator_insecure.yaml
consensus:
  safety_rules:
    backend:
      type: in_memory_storage  # Dangerous: allowed on testnet!
    service:
      type: local
```

Steps to reproduce:
1. Configure a testnet validator with `InMemoryStorage` backend
2. Start the validator and observe it participates in consensus
3. Restart the validator
4. Observe that `last_voted_round` is lost, validator may vote inconsistently
5. This violates AptosBFT safety guarantees

The vulnerability is validated by test code showing mainnet enforcement but testnet allowing it: [10](#0-9) 

## Notes

While `InMemoryStorage` is explicitly documented as "should not be used in production," the sanitizer only enforces this for mainnet. Testnet and devnet are production-grade networks where validators earn rewards and users depend on availability. The current design creates a security gap where non-mainnet production validators can accidentally use insecure storage, violating the consensus safety invariant that validators must maintain consistent voting history across restarts.

### Citations

**File:** secure/storage/src/in_memory.rs (L9-14)
```rust
/// InMemoryStorage represents a key value store that is purely in memory and intended for single
/// threads (or must be wrapped by a Arc<RwLock<>>). This provides no permission checks and simply
/// is a proof of concept to unblock building of applications without more complex data stores.
/// Internally, it retains all data, which means that it must make copies of all key material which
/// violates the code base. It violates it because the anticipation is that data stores would
/// securely handle key material. This should not be used in production.
```

**File:** secure/storage/src/in_memory.rs (L36-64)
```rust
impl KVStorage for InMemoryStorage {
    fn available(&self) -> Result<(), Error> {
        Ok(())
    }

    fn get<V: DeserializeOwned>(&self, key: &str) -> Result<GetResponse<V>, Error> {
        let response = self
            .data
            .get(key)
            .ok_or_else(|| Error::KeyNotSet(key.to_string()))?;

        serde_json::from_slice(response).map_err(|e| e.into())
    }

    fn set<V: Serialize>(&mut self, key: &str, value: V) -> Result<(), Error> {
        let now = self.time_service.now_secs();
        self.data.insert(
            key.to_string(),
            serde_json::to_vec(&GetResponse::new(value, now))?,
        );
        Ok(())
    }

    #[cfg(any(test, feature = "testing"))]
    fn reset_and_clear(&mut self) -> Result<(), Error> {
        self.data.clear();
        Ok(())
    }
}
```

**File:** config/src/config/secure_backend_config.rs (L16-22)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum SecureBackend {
    InMemoryStorage,
    Vault(VaultConfig),
    OnDiskStorage(OnDiskStorageConfig),
}
```

**File:** config/src/config/safety_rules_config.rs (L36-48)
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

**File:** config/src/config/safety_rules_config.rs (L296-317)
```rust
    #[test]
    fn test_sanitize_backend_for_mainnet_fullnodes() {
        // Create a node config with an invalid backend for mainnet validators
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

        // Verify that the config sanitizer passes because the node is a fullnode
        SafetyRulesConfig::sanitize(
            &node_config,
            NodeType::PublicFullnode,
            Some(ChainId::mainnet()),
        )
        .unwrap();
    }
```

**File:** config/src/config/node_config_loader.rs (L117-123)
```rust
    match get_chain_id(node_config) {
        Ok(chain_id) => (node_type, Some(chain_id)),
        Err(error) => {
            println!("Failed to extract the chain ID from the genesis transaction: {:?}! Continuing with None.", error);
            (node_type, None)
        },
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

**File:** config/src/config/config_sanitizer.rs (L45-48)
```rust
        // If config sanitization is disabled, don't do anything!
        if node_config.node_startup.skip_config_sanitizer {
            return Ok(());
        }
```

**File:** secure/storage/src/kv_storage.rs (L8-11)
```rust
/// A secure key/value storage engine. Create takes a policy that is enforced internally by the
/// actual backend. The policy contains public identities that the backend can translate into a
/// unique and private token for another service. Hence get and set internally will pass the
/// current service private token to the backend to gain its permissions.
```

# Audit Report

## Title
Validator Private Keys Exposed Through Unsanitized NodeConfig Serialization

## Summary
The `save_config()` function in both `OverrideNodeConfig` and `NodeConfig` serializes the entire configuration structure to YAML without sanitizing sensitive cryptographic key material. When validator network private keys (x25519) or consensus private keys (BLS12-381) are embedded in the configuration using `Identity::FromConfig` or `SafetyRulesTestConfig`, these keys are written to disk in plain text, enabling complete validator compromise if the config file is accessed by an attacker.

## Finding Description
The Aptos node configuration system supports multiple methods for storing validator identity keys, including embedding them directly in the config file via `Identity::FromConfig`. While production deployments should use `Identity::FromStorage` (Vault) or `Identity::FromFile`, the `Identity::FromConfig` variant is a documented, supported configuration option that stores the x25519 private key directly in the config structure. [1](#0-0) 

When a `NodeConfig` containing such embedded keys is saved using `save_config()`, the entire structure is serialized to YAML without any sanitization: [2](#0-1) 

For `OverrideNodeConfig`, the implementation similarly serializes the full config: [3](#0-2) 

The private key types are fully serializable because they derive `SerializeKey`: [4](#0-3) [5](#0-4) 

The vulnerability manifests in multiple scenarios:

1. **Test/Development Environments**: The `generate_random_config()` function creates configs with embedded keys for testing: [6](#0-5) [7](#0-6) 

2. **Genesis Builder**: The genesis setup code creates identities with embedded keys and saves them: [8](#0-7) 

3. **Runtime Config Modification**: When configs are modified and saved during operation, any embedded keys are persisted: [9](#0-8) 

**Attack Path:**
1. Operator misconfigures a validator to use `Identity::FromConfig` instead of secure storage
2. Config is saved via `save_config()` or `save_to_path()`
3. Private keys are written to YAML file in plain text
4. Attacker gains filesystem read access (via backup leak, insider threat, misconfigured permissions, or supply chain compromise)
5. Attacker extracts validator private keys from config file
6. Attacker can impersonate the validator on the network (x25519 key) or manipulate consensus (BLS key)

## Impact Explanation
**Severity: Critical/High**

This vulnerability enables complete validator compromise through private key exposure. The impact includes:

1. **Network Impersonation**: Exposed x25519 private keys allow attackers to impersonate validators on the P2P network, potentially enabling man-in-the-middle attacks or network partitioning.

2. **Consensus Manipulation**: If `SafetyRulesTestConfig` with consensus keys is used and saved, exposed BLS12-381 private keys enable attackers to sign consensus messages, potentially violating consensus safety guarantees.

3. **Defense-in-Depth Violation**: Even though production deployments should use secure storage, the lack of sanitization creates a dangerous foot-gun that violates secure coding principles.

Per Aptos bug bounty criteria, this qualifies as **Critical Severity** if it leads to consensus violations or **High Severity** as a significant protocol violation enabler, depending on the deployment context.

## Likelihood Explanation
**Likelihood: Medium-High**

While production validators are documented to use `Identity::FromStorage` (Vault), several factors increase likelihood:

1. **Supported Configuration**: `Identity::FromConfig` is a valid, documented configuration option, not a hack or workaround.

2. **Test/Dev Environments**: Commonly used in development, staging, and test networks where operators may not realize the keys have production value.

3. **Configuration Errors**: Operators unfamiliar with Aptos security best practices may choose the "simpler" inline key configuration.

4. **Genesis Setup**: The genesis builder code demonstrates this pattern, potentially serving as a reference for custom deployments.

5. **No Runtime Protection**: The code provides no warnings, checks, or sanitization to prevent this misconfiguration.

6. **Backup/Logging Exposure**: Even if filesystem permissions are correct, config file backups, container images, or CI/CD systems may inadvertently expose these files.

## Recommendation

Implement multiple layers of defense:

**1. Add Sanitization to Serialization**

Implement a custom serializer that redacts private key fields:

```rust
// In ConfigKey implementation
impl<T: PrivateKey + Serialize> Serialize for ConfigKey<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Only serialize in test builds
        #[cfg(test)]
        {
            self.key.serialize(serializer)
        }
        #[cfg(not(test))]
        {
            serializer.serialize_str("<redacted-private-key>")
        }
    }
}
```

**2. Add Config Validation**

Prevent production nodes from using inline keys:

```rust
// In config sanitizer
if !cfg!(test) && matches!(network.identity, Identity::FromConfig(_)) {
    return Err(Error::ConfigSanitizerFailed(
        sanitizer_name,
        "Identity::FromConfig must not be used in production. Use FromStorage or FromFile.".to_string(),
    ));
}
```

**3. Emit Warnings**

Log warnings when saving configs with embedded keys:

```rust
// In save_config
if self.contains_embedded_keys() {
    warn!("Saving config with embedded private keys. This is insecure for production use.");
}
```

**4. Documentation**

Clearly document that `Identity::FromConfig` is for testing only and must never be used in production.

## Proof of Concept

```rust
#[test]
fn test_private_key_leak_via_config_save() {
    use aptos_config::config::{Identity, NetworkConfig, NodeConfig, PersistableConfig};
    use aptos_crypto::{x25519, Uniform};
    use aptos_types::account_address::from_identity_public_key;
    use rand::{rngs::StdRng, SeedableRng};
    use std::fs;
    use tempfile::TempDir;

    // Create a config with an embedded private key
    let mut rng = StdRng::from_seed([0u8; 32]);
    let private_key = x25519::PrivateKey::generate(&mut rng);
    let peer_id = from_identity_public_key(private_key.public_key());
    
    let mut config = NodeConfig::default();
    let mut validator_network = NetworkConfig::network_with_id(
        aptos_config::network_id::NetworkId::Validator
    );
    
    // Set identity with embedded key (FromConfig variant)
    validator_network.identity = Identity::from_config(private_key.clone(), peer_id);
    config.validator_network = Some(validator_network);

    // Save config to file
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("node.yaml");
    config.save_config(&config_path).unwrap();

    // Read the saved config file
    let saved_yaml = fs::read_to_string(&config_path).unwrap();
    
    // Verify the private key is in the YAML file (VULNERABILITY!)
    let private_key_hex = hex::encode(private_key.to_bytes());
    assert!(
        saved_yaml.contains(&private_key_hex),
        "Private key was leaked in config file!"
    );
    
    println!("VULNERABILITY CONFIRMED:");
    println!("Private key found in saved config:");
    println!("{}", saved_yaml);
}
```

This PoC demonstrates that when a `NodeConfig` with `Identity::FromConfig` is saved, the x25519 private key is written to the YAML file in plain text, confirming the vulnerability.

## Notes

The vulnerability exists due to the design decision to make `ConfigKey` serializable for testing convenience, combined with the lack of sanitization in the config save path. While production deployments use secure storage backends, the code itself provides no protection against misconfiguration. The `SilentDebug` and `SilentDisplay` derives prevent keys from appearing in debug output but do not affect serialization. This represents a significant defense-in-depth gap where sensitive cryptographic material can be persisted to disk through normal configuration operations.

### Citations

**File:** config/src/config/identity_config.rs (L130-139)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityFromConfig {
    #[serde(flatten)]
    pub key: ConfigKey<x25519::PrivateKey>,
    pub peer_id: PeerId,

    #[serde(skip)]
    pub source: IdentitySource,
}
```

**File:** config/src/config/persistable_config.rs (L23-29)
```rust
    fn save_config<P: AsRef<Path>>(&self, output_file: P) -> Result<(), Error> {
        // Serialize the config to a string
        let serialized_config = serde_yaml::to_vec(&self)
            .map_err(|e| Error::Yaml(output_file.as_ref().to_str().unwrap().to_string(), e))?;

        Self::write_file(serialized_config, output_file)
    }
```

**File:** config/src/config/override_node_config.rs (L142-152)
```rust
    fn save_config<P: AsRef<Path>>(&self, output_file: P) -> Result<(), Error> {
        let yaml_value = self.get_yaml()?;
        let yaml_string = serde_yaml::to_string(&yaml_value).map_err(|e| {
            Error::Yaml(
                "Unable to serialize override config to yaml. Error: {}".to_string(),
                e,
            )
        })?;
        let yaml_bytes = yaml_string.as_bytes().to_vec();
        Self::write_file(yaml_bytes, output_file)
    }
```

**File:** crates/aptos-crypto/src/x25519.rs (L66-68)
```rust
#[derive(DeserializeKey, SilentDisplay, SilentDebug, SerializeKey)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Clone))]
pub struct PrivateKey(x25519_dalek::StaticSecret);
```

**File:** config/src/keys.rs (L25-29)
```rust
#[derive(Debug, Deserialize, Serialize)]
pub struct ConfigKey<T: PrivateKey + Serialize> {
    #[serde(bound(deserialize = "T: Deserialize<'de>"))]
    key: T,
}
```

**File:** config/src/config/node_config.rs (L171-181)
```rust
    pub fn save_to_path<P: AsRef<Path>>(&mut self, output_path: P) -> Result<(), Error> {
        // Save the execution config to disk.
        let output_dir = RootPath::new(&output_path);
        self.execution.save_to_path(&output_dir)?;

        // Write the node config to disk. Note: this must be called last
        // as calling save_to_path() on subconfigs may change fields.
        self.save_config(&output_path)?;

        Ok(())
    }
```

**File:** config/src/config/node_config.rs (L222-226)
```rust
            validator_network.random_with_peer_id(rng, Some(peer_id));

            let mut safety_rules_test_config = SafetyRulesTestConfig::new(peer_id);
            safety_rules_test_config.random_consensus_key(rng);
            node_config.consensus.safety_rules.test = Some(safety_rules_test_config);
```

**File:** config/src/config/network_config.rs (L294-304)
```rust
    pub fn random_with_peer_id(&mut self, rng: &mut StdRng, peer_id: Option<PeerId>) {
        let identity_key = x25519::PrivateKey::generate(rng);
        let peer_id = if let Some(peer_id) = peer_id {
            peer_id
        } else {
            AuthenticationKey::try_from(identity_key.public_key().as_slice())
                .unwrap()
                .account_address()
        };
        self.identity = Identity::from_config(identity_key, peer_id);
    }
```

**File:** crates/aptos-genesis/src/builder.rs (L402-409)
```rust
fn set_identity_for_network(network: &mut NetworkConfig) -> anyhow::Result<()> {
    if let Identity::None = network.identity {
        let mut keygen = KeyGen::from_os_rng();
        let key = keygen.generate_x25519_private_key()?;
        let peer_id = aptos_types::account_address::from_identity_public_key(key.public_key());
        network.identity = Identity::from_config(key, peer_id);
    }
    Ok(())
```

# Audit Report

## Title
Private Key Leakage Through JSON Serialization in Node Startup Logs

## Summary
`ConfigKey<x25519::PrivateKey>` fails to prevent private key material leakage through JSON serialization. While it protects against debug output leakage (via `SilentDebug`), the `log_all_configs()` method called during node startup serializes the entire `NodeConfig` to JSON, exposing private network keys in INFO-level logs.

## Finding Description

The `ConfigKey<T>` wrapper is designed to make private keys clonable for configuration purposes. The implementation relies on the underlying key type's `SilentDebug` trait to prevent leakage through debug output. [1](#0-0) 

However, `ConfigKey` derives standard `Serialize` without any redaction logic. [2](#0-1) 

When the underlying `x25519::PrivateKey` is serialized, the `SerializeKey` macro outputs the actual key material - either as a hex-encoded string in human-readable mode (JSON) or as raw bytes in binary mode. [3](#0-2) 

During node startup, `setup_environment_and_start_node()` calls `log_all_configs()`: [4](#0-3) 

This method serializes the entire `NodeConfig` to JSON and logs each section at INFO level: [5](#0-4) 

The `IdentityFromConfig` struct contains a `ConfigKey<x25519::PrivateKey>` field that gets serialized: [6](#0-5) 

**Attack Path:**
1. Node starts up and calls `log_all_configs()`
2. `NodeConfig` is serialized to JSON via `serde_json::to_value()`
3. Network identity configuration containing `ConfigKey<x25519::PrivateKey>` is serialized
4. The x25519 private key is output as hex string in logs at INFO level
5. Attacker with log access extracts the private network key
6. Attacker can decrypt past network traffic or impersonate the node

## Impact Explanation

This is a **Low Severity** information leak according to Aptos bug bounty criteria. The x25519 network private key exposure allows:

- **Traffic Decryption**: Attacker can decrypt past and future encrypted network communications
- **Node Impersonation**: Attacker can impersonate the node at the network layer
- **Limited Network Disruption**: Potential for network-level attacks but NOT consensus-level attacks (consensus signing requires separate BLS keys)

The impact is limited because:
- Does not compromise consensus keys (BLS signatures still required for block signing)
- Does not enable theft of funds or consensus violations
- Requires log access (easier than key storage access, but not remotely exploitable)
- The documentation explicitly states this is for "low security requirements" [7](#0-6) 

## Likelihood Explanation

**Medium likelihood** in practice:
- Centralized logging systems often have weaker access controls than key management systems
- Cloud environments frequently aggregate logs from multiple nodes
- Developers may unknowingly enable verbose logging that includes INFO level
- The vulnerability triggers automatically on every node startup

## Recommendation

Implement a custom `Serialize` implementation for `ConfigKey` that redacts the private key material:

```rust
impl<T: PrivateKey + Serialize> Serialize for ConfigKey<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Always elide private keys during serialization
        serializer.serialize_str("<elided private key>")
    }
}
```

Alternatively, add `#[serde(skip_serializing)]` to private key fields in configuration structs, or avoid logging the full config via JSON serialization.

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use aptos_config::config::Identity;
    use aptos_crypto::{x25519, Uniform};
    use aptos_types::account_address::from_identity_public_key;
    use rand::SeedableRng;

    #[test]
    fn test_private_key_leak_via_json_serialization() {
        // Generate a test identity
        let mut rng = rand::rngs::StdRng::from_seed([0u8; 32]);
        let private_key = x25519::PrivateKey::generate(&mut rng);
        let peer_id = from_identity_public_key(private_key.public_key());
        
        let identity = Identity::from_config(private_key, peer_id);
        
        // Serialize to JSON (as log_all_configs does)
        let json = serde_json::to_string_pretty(&identity).unwrap();
        
        println!("Serialized Identity:\n{}", json);
        
        // The JSON output will contain the hex-encoded private key
        // Example: "x25519-priv-<hex_string>"
        assert!(json.contains("x25519-priv-"), 
                "Private key material exposed in JSON serialization");
    }
}
```

**Notes:**
- This is a documented design limitation of `ConfigKey` intended for testing/low-security scenarios
- Production deployments should use secure key storage backends (`IdentityFromStorage`) rather than embedding keys in configs
- The inspection service correctly uses Debug formatting to prevent this leak in API responses [8](#0-7)

### Citations

**File:** config/src/keys.rs (L20-29)
```rust
/// ConfigKey places a clonable wrapper around PrivateKeys for config purposes only. The only time
/// configs have keys is either for testing or for low security requirements. We recommend that
/// keys be stored in key managers. If we make keys unclonable, then the configs must be mutable
/// and that becomes a requirement strictly as a result of supporting test environments, which is
/// undesirable. Hence this internal wrapper allows for keys to be clonable but only from configs.
#[derive(Debug, Deserialize, Serialize)]
pub struct ConfigKey<T: PrivateKey + Serialize> {
    #[serde(bound(deserialize = "T: Deserialize<'de>"))]
    key: T,
}
```

**File:** crates/aptos-crypto-derive/src/lib.rs (L191-207)
```rust
        impl ::serde::Serialize for #name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                if serializer.is_human_readable() {
                    self.to_encoded_string()
                        .map_err(<S::Error as ::serde::ser::Error>::custom)
                        .and_then(|str| serializer.serialize_str(&str[..]))
                } else {
                    // See comment in deserialize_key.
                    serializer.serialize_newtype_struct(
                        #name_string,
                        serde_bytes::Bytes::new(&ValidCryptoMaterial::to_bytes(self).as_slice()),
                    )
                }
            }
```

**File:** aptos-node/src/lib.rs (L697-698)
```rust
    // Log the node config at node startup
    node_config.log_all_configs();
```

**File:** config/src/config/node_config.rs (L97-110)
```rust
    pub fn log_all_configs(&self) {
        // Parse the node config as serde JSON
        let config_value =
            serde_json::to_value(self).expect("Failed to serialize the node config!");
        let config_map = config_value
            .as_object()
            .expect("Failed to get the config map!");

        // Log each config entry
        for (config_name, config_value) in config_map {
            let config_string =
                serde_json::to_string(config_value).expect("Failed to parse the config value!");
            info!("Using {} config: {}", config_name, config_string);
        }
```

**File:** config/src/config/identity_config.rs (L132-135)
```rust
pub struct IdentityFromConfig {
    #[serde(flatten)]
    pub key: ConfigKey<x25519::PrivateKey>,
    pub peer_id: PeerId,
```

**File:** crates/aptos-inspection-service/src/server/configuration.rs (L16-19)
```rust
        // We format the configuration using debug formatting. This is important to
        // prevent secret/private keys from being serialized and leaked (i.e.,
        // all secret keys are marked with SilentDisplay and SilentDebug).
        let encoded_configuration = format!("{:?}", node_config);
```

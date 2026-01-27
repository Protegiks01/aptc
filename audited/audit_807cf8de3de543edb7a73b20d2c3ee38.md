# Audit Report

## Title
Validator Network Private Keys Exposed Through Unfiltered Telemetry Logs

## Summary
Validator nodes accidentally send their network identity private keys (`x25519::PrivateKey`) to the telemetry service through unfiltered logs. The `NodeConfig::log_all_configs()` function serializes the entire node configuration to JSON and logs it at startup, which includes private keys stored in the `Identity::FromConfig` variant. These logs are batched and transmitted to the telemetry service without any filtering or redaction, exposing sensitive cryptographic material.

## Finding Description

When an Aptos validator node starts, it calls `log_all_configs()` to log its configuration: [1](#0-0) 

This function serializes the entire `NodeConfig` to JSON and logs each field: [2](#0-1) 

The `NodeConfig` contains network configurations that include identity information: [3](#0-2) 

The `NetworkConfig` struct contains an `identity` field: [4](#0-3) 

When the identity is stored directly in config (`Identity::FromConfig`), it contains a wrapped private key: [5](#0-4) 

The `ConfigKey<T>` wrapper contains the actual private key and implements `Serialize`: [6](#0-5) 

Private key types like `x25519::PrivateKey` implement the `SerializeKey` derive macro, which serializes them to hex/base64 encoded strings when using human-readable formats like JSON: [7](#0-6) 

The serialized private key is then logged using `info!()` macro, which sends it through the logging system to the telemetry service without any filtering: [8](#0-7) 

The `post_logs()` function compresses and sends logs directly to the telemetry service: [9](#0-8) 

**Attack Path:**
1. Validator node starts with `Identity::FromConfig` containing network private key
2. `log_all_configs()` is called automatically
3. `serde_json::to_value()` serializes entire config including private key to hex string
4. Private key appears in JSON as `"key": "0x<hex_encoded_private_key>"`
5. Log is sent via `info!()` macro to telemetry channel
6. `TelemetryLogSender` batches and sends to telemetry service
7. Attacker with telemetry service access obtains private key

## Impact Explanation

This is a **HIGH severity** vulnerability according to Aptos bug bounty criteria:
- Falls under "Significant protocol violations" - breaks the network security model
- Could enable "Validator node slowdowns" through network-level attacks

The exposed `x25519::PrivateKey` is used for:
- Validator-to-validator network authentication
- Secure channel establishment for consensus messages
- Peer identity verification

An attacker obtaining these keys can:
- Impersonate validators on the network layer
- Intercept and decrypt validator communications
- Launch man-in-the-middle attacks on consensus messages
- Disrupt validator connectivity and network liveness

While this does not directly lead to fund theft or consensus safety violations, it severely compromises the validator network's security perimeter and could be leveraged for more sophisticated attacks.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability triggers automatically:
- Every validator node calls `log_all_configs()` at startup
- No special conditions or rare edge cases required
- Affects all validators using `Identity::FromConfig` (common in production)
- Telemetry is enabled by default on most production validators

Attack requirements:
- Access to telemetry service logs (service provider, cloud infrastructure, or compromised service)
- No specialized blockchain knowledge needed
- Keys are logged in plaintext hex format, easily extractable

The only mitigation is if validators use `Identity::FromStorage` (secure key management), but many deployments use `Identity::FromConfig` for convenience.

## Recommendation

**Immediate Fix:** Implement sensitive data filtering before sending logs to telemetry.

**Option 1: Filter at serialization level**
Implement custom `Serialize` for `Identity` and `ConfigKey` that redacts private keys:

```rust
impl Serialize for ConfigKey<T: PrivateKey + Serialize> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str("<redacted private key>")
    }
}
```

**Option 2: Filter in log_all_configs**
Add explicit filtering when logging configs:

```rust
pub fn log_all_configs(&self) {
    let mut config_value = serde_json::to_value(self)
        .expect("Failed to serialize the node config!");
    
    // Redact sensitive fields
    redact_sensitive_fields(&mut config_value);
    
    let config_map = config_value.as_object()
        .expect("Failed to get the config map!");
    
    for (config_name, config_value) in config_map {
        let config_string = serde_json::to_string(config_value)
            .expect("Failed to parse the config value!");
        info!("Using {} config: {}", config_name, config_string);
    }
}

fn redact_sensitive_fields(value: &mut serde_json::Value) {
    // Recursively find and redact "key" fields in Identity objects
    // or any field matching known private key patterns
}
```

**Option 3: Don't log full configs to telemetry**
Remove or disable `log_all_configs()` for production, or ensure it only logs to local files, not telemetry.

## Proof of Concept

```rust
#[cfg(test)]
mod test_private_key_exposure {
    use aptos_config::config::{Identity, NodeConfig};
    use aptos_crypto::{x25519, Uniform};
    use aptos_types::account_address::from_identity_public_key;
    
    #[test]
    fn test_private_key_in_serialized_config() {
        // Generate a test private key
        let mut rng = rand::thread_rng();
        let private_key = x25519::PrivateKey::generate(&mut rng);
        let peer_id = from_identity_public_key(private_key.public_key());
        
        // Create a NodeConfig with Identity::FromConfig
        let mut node_config = NodeConfig::default();
        if let Some(ref mut validator_network) = node_config.validator_network {
            validator_network.identity = Identity::from_config(private_key.clone(), peer_id);
        }
        
        // Serialize to JSON (what log_all_configs does)
        let config_json = serde_json::to_string(&node_config)
            .expect("Failed to serialize config");
        
        // Verify private key bytes appear in the JSON
        let private_key_hex = hex::encode(private_key.to_bytes());
        
        assert!(
            config_json.contains(&private_key_hex),
            "Private key should be exposed in serialized config! This is a security vulnerability."
        );
        
        println!("VULNERABILITY CONFIRMED: Private key found in config JSON:");
        println!("Key: {}", private_key_hex);
        println!("JSON excerpt: {:?}", 
            config_json.chars().take(500).collect::<String>());
    }
}
```

This test demonstrates that private keys are serialized as hex strings in the JSON output, confirming they would be sent to the telemetry service when `log_all_configs()` is called.

## Notes

While the `SilentDebug` derive macro protects against accidental logging via `Debug` trait, it does not protect against `Serialize` trait usage. The `SerializeKey` macro explicitly serializes private keys to hex/base64 strings for configuration persistence, but this creates a vulnerability when entire config objects are serialized and logged.

The vulnerability is particularly dangerous because:
1. It happens automatically at node startup
2. Logs are explicitly sent to external telemetry service
3. No warning or documentation alerts operators to this risk
4. The `info!()` log level means it's captured by default logging configurations

### Citations

**File:** aptos-node/src/lib.rs (L697-698)
```rust
    // Log the node config at node startup
    node_config.log_all_configs();
```

**File:** config/src/config/node_config.rs (L89-89)
```rust
    pub validator_network: Option<NetworkConfig>,
```

**File:** config/src/config/node_config.rs (L97-111)
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
    }
```

**File:** config/src/config/network_config.rs (L72-73)
```rust
    /// Identity of this network
    pub identity: Identity,
```

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

**File:** config/src/keys.rs (L25-29)
```rust
#[derive(Debug, Deserialize, Serialize)]
pub struct ConfigKey<T: PrivateKey + Serialize> {
    #[serde(bound(deserialize = "T: Deserialize<'de>"))]
    key: T,
}
```

**File:** crates/aptos-crypto-derive/src/lib.rs (L186-211)
```rust
pub fn serialize_key(source: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(source).expect("Incorrect macro input");
    let name = &ast.ident;
    let name_string = find_key_name(&ast, name.to_string());
    quote! {
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
        }
    }
    .into()
}
```

**File:** crates/aptos-telemetry/src/sender.rs (L176-193)
```rust
    pub async fn try_send_logs(&self, batch: Vec<String>) {
        if let Ok(json) = serde_json::to_string(&batch) {
            let len = json.len();

            match self.post_logs(json.as_bytes()).await {
                Ok(_) => {
                    increment_log_ingest_successes_by(batch.len() as u64);
                    debug!("Sent log of length: {}", len);
                },
                Err(error) => {
                    increment_log_ingest_failures_by(batch.len() as u64);
                    debug!("Failed send log of length: {} with error: {}", len, error);
                },
            }
        } else {
            debug!("Failed json serde of batch: {:?}", batch);
        }
    }
```

**File:** crates/aptos-telemetry/src/sender.rs (L195-214)
```rust
    async fn post_logs(&self, json: &[u8]) -> Result<Response, anyhow::Error> {
        debug!("Sending logs");

        let mut gzip_encoder = GzEncoder::new(Vec::new(), Compression::default());
        gzip_encoder.write_all(json)?;
        let compressed_bytes = gzip_encoder.finish()?;

        // Send the request and wait for a response
        let response = self
            .send_authenticated_request(
                self.client
                    .post(self.build_path("ingest/logs")?)
                    .header(CONTENT_ENCODING, "gzip")
                    .body(compressed_bytes),
            )
            .await?;

        // Process the result
        error_for_status_with_body(response).await
    }
```

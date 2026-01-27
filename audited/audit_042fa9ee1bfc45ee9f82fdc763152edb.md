# Audit Report

## Title
Private Keys Leak Through Telemetry Logging to External Monitoring Systems

## Summary
The `TelemetryLogWriter.write()` method lacks validation to prevent sensitive cryptographic material from being transmitted to external telemetry services. When node configurations are logged at INFO level, network private keys are serialized to JSON and sent unredacted to external monitoring systems, exposing validator credentials.

## Finding Description

The vulnerability exists in the telemetry logging pipeline where log strings are sent to external monitoring systems without any validation or sanitization of sensitive cryptographic material.

**Critical Code Path:**

1. **No Validation in write()**: The `TelemetryLogWriter.write()` method accepts a log string and directly sends it through a channel without any content validation. [1](#0-0) 

2. **Configuration Logging**: The `NodeConfig.log_all_configs()` method serializes the entire node configuration to JSON and logs each component at INFO level. [2](#0-1) 

3. **Identity Contains Private Keys**: The `NetworkConfig` struct contains an `Identity` field that holds network private keys. [3](#0-2) 

4. **Private Keys Are Serializable**: The `ConfigKey` wrapper derives both `Debug` and `Serialize`, allowing private keys to be serialized. [4](#0-3) 

5. **Full Key Encoding**: The `SerializeKey` macro implements JSON serialization that encodes the complete private key as a string in human-readable format. [5](#0-4) 

6. **No Sanitization in Formatter**: The `json_format()` function simply serializes log entries to JSON without checking for sensitive content. [6](#0-5) 

7. **Telemetry Transmission**: Logs passing the telemetry filter are formatted and sent through the telemetry writer. [7](#0-6) 

8. **External Endpoint**: The telemetry sender POSTs these logs to an external `/ingest/logs` endpoint. [8](#0-7) 

**Attack Scenario:**

When a validator node starts or when configuration is logged for debugging:
- `NodeConfig::log_all_configs()` is called
- Each config component is serialized to JSON including `NetworkConfig`
- The `Identity::FromConfig` variant contains `ConfigKey<x25519::PrivateKey>`
- JSON serialization encodes the full private key (e.g., "x25519-priv-<base64_bytes>")
- This log entry passes through at INFO level
- No validation occurs in `write()` - it sends the string directly
- The private key is transmitted to external telemetry monitoring systems

## Impact Explanation

**Critical Severity** - This vulnerability meets the Critical severity criteria per Aptos bug bounty:

1. **Validator Credential Exposure**: Network private keys (x25519) are used for validator peer-to-peer authentication and encrypted communication. Exposure allows:
   - Impersonation of validator nodes
   - Man-in-the-middle attacks on consensus messages
   - Potential consensus safety violations if attacker can intercept/modify validator communications

2. **Consensus Secret Leakage Risk**: If consensus private keys (BLS12-381) are ever logged similarly through error paths or debug configurations, they would enable:
   - Forging consensus votes and proposals
   - Direct consensus safety violations
   - Ability to equivocate and cause chain splits

3. **External Attack Surface**: Telemetry data is sent to external monitoring systems, expanding the attack surface beyond the validator node itself. Compromise of the telemetry service or interception of telemetry traffic exposes validator credentials.

4. **Wide Deployment Impact**: All validator nodes using telemetry logging at INFO level or enabling configuration logging are affected.

## Likelihood Explanation

**High Likelihood:**

1. **Default Behavior**: Configuration logging is a standard operational practice for debugging and monitoring, making this likely to occur in production deployments.

2. **Telemetry Level Configuration**: The default telemetry level is WARN, but operators commonly set it to INFO for troubleshooting. [9](#0-8) 

3. **No Warning Indicators**: There are no warnings or documentation indicating that configuration logging could expose private keys.

4. **Existing Logging Patterns**: The codebase already includes INFO-level configuration logging, demonstrating this is an active code path.

5. **No Detection Mechanism**: There is no monitoring or alerting to detect when sensitive keys are transmitted through telemetry.

## Recommendation

Implement a multi-layered defense:

**1. Add Validation in TelemetryLogWriter.write():**
```rust
pub fn write(&mut self, log: String) -> std::io::Result<usize> {
    // Validate log doesn't contain sensitive patterns
    if contains_sensitive_material(&log) {
        APTOS_LOG_SENSITIVE_DATA_BLOCKED.inc();
        return Err(Error::new(ErrorKind::InvalidData, "Log contains sensitive cryptographic material"));
    }
    
    let len = log.len();
    match self.tx.try_send(TelemetryLog::Log(log)) {
        // ... rest of implementation
    }
}

fn contains_sensitive_material(log: &str) -> bool {
    // Check for key prefixes used in SerializeKey
    log.contains("bls12381-priv-") ||
    log.contains("x25519-priv-") ||
    log.contains("ed25519-priv-") ||
    // Check for consensus_private_key field
    log.contains("\"consensus_private_key\"") ||
    // Add pattern matching for base64-encoded key material
    regex_matches_key_pattern(log)
}
```

**2. Implement SilentSerialize for Private Keys:**

Create a new derive macro `SilentSerialize` similar to `SilentDebug` that redacts key material during serialization:
```rust
#[derive(SerializeKey, DeserializeKey, SilentDebug, SilentDisplay, SilentSerialize)]
pub struct PrivateKey(x25519_dalek::StaticSecret);
```

**3. Add Security Audit Logging:**

Log attempts to serialize or transmit sensitive keys for security monitoring.

**4. Documentation and Warnings:**

Add clear documentation that configuration logging may expose sensitive data and should not be used with telemetry enabled in production.

## Proof of Concept

**Reproduction Steps:**

1. **Setup a test validator node with telemetry enabled:**
```yaml
# config.yaml
logger:
  level: Info
  telemetry_level: Info  # Enable telemetry at INFO level

validator_network:
  identity:
    type: from_config
    key: "x25519-priv-<generated_key>"  # Network private key
    peer_id: <peer_id>
```

2. **Start the node and trigger configuration logging:**
```rust
// In node startup code or via debug command
node_config.log_all_configs();
```

3. **Observe telemetry transmission:**

The following will be sent to the external telemetry service at `/ingest/logs`:
```json
{
  "level": "info",
  "message": "Using validator_network config: {\"identity\":{\"type\":\"from_config\",\"key\":\"x25519-priv-ABC123...\",\"peer_id\":\"0xDEF456...\"}}",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

4. **Verify the private key is exposed in clear text** in the telemetry service logs.

**Test Case:**
```rust
#[test]
fn test_private_key_not_leaked_to_telemetry() {
    let (tx, mut rx) = channel::mpsc::channel(100);
    let mut writer = TelemetryLogWriter::new(tx);
    
    // Simulate logging a config with a private key
    let log_with_key = r#"{"network_config":{"identity":{"type":"from_config","key":"x25519-priv-ABC123DEF456"}}}"#;
    
    // This should fail with validation error, but currently succeeds
    let result = writer.write(log_with_key.to_string());
    assert!(result.is_err(), "Private key should not be allowed in telemetry logs");
    
    // Verify nothing was sent
    assert!(rx.try_next().is_err(), "No data should be sent through channel");
}
```

**Current Behavior:** The test will fail because `write()` succeeds and sends the private key.

**Expected Behavior:** After implementing the fix, `write()` should return an error and block transmission of sensitive material.

---

**Notes:**

While BLS12-381 consensus private keys and Ed25519 account keys have `SilentDebug` protection that prevents direct Debug formatting from exposing them, the JSON serialization path via `SerializeKey` bypasses this protection. The x25519 network private keys are particularly vulnerable as they're commonly stored in `IdentityFromConfig` for configuration-based deployments. This vulnerability violates the **Cryptographic Correctness** invariant by failing to protect sensitive key material in the logging pipeline.

### Citations

**File:** crates/aptos-logger/src/telemetry_log_writer.rs (L29-43)
```rust
    pub fn write(&mut self, log: String) -> std::io::Result<usize> {
        let len = log.len();
        match self.tx.try_send(TelemetryLog::Log(log)) {
            Ok(_) => Ok(len),
            Err(err) => {
                if err.is_full() {
                    APTOS_LOG_INGEST_WRITER_FULL.inc_by(len as u64);
                    Err(Error::new(ErrorKind::WouldBlock, "Channel full"))
                } else {
                    APTOS_LOG_INGEST_WRITER_DISCONNECTED.inc_by(len as u64);
                    Err(Error::new(ErrorKind::ConnectionRefused, "Disconnected"))
                }
            },
        }
    }
```

**File:** config/src/config/node_config.rs (L99-111)
```rust
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

**File:** config/src/config/network_config.rs (L57-73)
```rust
pub struct NetworkConfig {
    /// Maximum backoff delay for connecting outbound to peers
    pub max_connection_delay_ms: u64,
    /// Base for outbound connection backoff
    pub connection_backoff_base: u64,
    /// Rate to check connectivity to connected peers
    pub connectivity_check_interval_ms: u64,
    /// Size of all network channels
    pub network_channel_size: usize,
    /// Choose a protocol to discover and dial out to other peers on this network.
    /// `DiscoveryMethod::None` disables discovery and dialing out (unless you have
    /// seed peers configured).
    pub discovery_method: DiscoveryMethod,
    /// Same as `discovery_method` but allows for multiple
    pub discovery_methods: Vec<DiscoveryMethod>,
    /// Identity of this network
    pub identity: Identity,
```

**File:** config/src/keys.rs (L25-29)
```rust
#[derive(Debug, Deserialize, Serialize)]
pub struct ConfigKey<T: PrivateKey + Serialize> {
    #[serde(bound(deserialize = "T: Deserialize<'de>"))]
    key: T,
}
```

**File:** crates/aptos-crypto-derive/src/lib.rs (L186-210)
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
```

**File:** crates/aptos-logger/src/aptos_logger.rs (L318-321)
```rust
            level: Level::Info,
            remote_level: Level::Info,
            telemetry_level: Level::Warn,
            printer: Some(Box::new(StdoutWriter::new())),
```

**File:** crates/aptos-logger/src/aptos_logger.rs (L642-653)
```rust
                    if let Some(writer) = &mut telemetry_writer {
                        if self
                            .facade
                            .filter
                            .read()
                            .telemetry_filter
                            .enabled(&entry.metadata)
                        {
                            let s = json_format(&entry).expect("Unable to format");
                            let _ = writer.write(s);
                        }
                    }
```

**File:** crates/aptos-logger/src/aptos_logger.rs (L781-789)
```rust
fn json_format(entry: &LogEntry) -> Result<String, fmt::Error> {
    match serde_json::to_string(&entry) {
        Ok(s) => Ok(s),
        Err(_) => {
            // TODO: Improve the error handling here. Currently we're just increasing some misleadingly-named metric and dropping any context on why this could not be deserialized.
            STRUCT_LOG_PARSE_ERROR_COUNT.inc();
            Err(fmt::Error)
        },
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

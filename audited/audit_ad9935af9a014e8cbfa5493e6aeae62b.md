# Audit Report

## Title
Vault Token Exposure Through Configuration Logging Enables Complete Validator Key Compromise

## Summary
The `Token::FromConfig` variant in `secure_backend_config.rs` allows Vault authentication tokens to be stored directly in configuration files. When validators use this option, these tokens are exposed in multiple locations during node startup: INFO-level logs, JSON-serialized configuration dumps, and remote telemetry systems. An attacker gaining access to any of these exposure points can steal the Vault token and subsequently extract all validator cryptographic keys (consensus keys, network identity keys), enabling consensus safety violations, equivocation attacks, and validator reward theft.

## Finding Description

The vulnerability chain consists of three critical flaws:

**1. Token Storage Without Protection**

The `Token` enum supports storing Vault tokens directly in configuration: [1](#0-0) 

The `VaultConfig` struct includes this token field with full serialization support and no sensitive data protection: [2](#0-1) 

**2. Unconditional Configuration Logging at Startup**

During node initialization, the entire configuration is logged via two mechanisms:

First, `log_all_configs()` serializes the complete `NodeConfig` to JSON and logs each section at INFO level: [3](#0-2) 

This function is called unconditionally at node startup: [4](#0-3) 

Second, the logger initialization also logs the entire config using Debug format: [5](#0-4) 

**3. Selective Masking Shows Awareness But Incomplete Protection**

The codebase demonstrates awareness of secret exposure by masking PostgreSQL passwords: [6](#0-5) 

However, Vault tokens receive no such protection. This selective masking proves the developers understand the risk but have not applied it consistently to all secrets.

**4. Multi-Destination Log Exposure**

Logs containing these tokens are written to multiple destinations: [7](#0-6) 

**Attack Scenario:**

1. A validator operator configures their node with `Token::FromConfig` (either due to misconfiguration or convenience)
2. Node starts and calls `log_all_configs()` at line 698 of `lib.rs`
3. Token is serialized and logged to: local log files, remote telemetry endpoints, stdout
4. Attacker compromises any of: backup system, log aggregation infrastructure, or gains file system access
5. Attacker extracts the Vault token from logs
6. Attacker authenticates to Vault using the stolen token
7. Attacker retrieves all validator keys from Vault (consensus private key, network identity keys)
8. Attacker can now: sign conflicting blocks (equivocation), forge consensus votes, steal validator rewards, cause Byzantine behavior

## Impact Explanation

This vulnerability qualifies as **Critical Severity** under the Aptos Bug Bounty program for multiple reasons:

**1. Loss of Funds:** With access to validator consensus keys, an attacker can manipulate block proposals and validator signatures to redirect staking rewards. The attacker could also perform slashing-inducing behavior while framing the legitimate validator.

**2. Consensus/Safety Violations:** Possessing validator private keys allows the attacker to:
- Sign conflicting votes (equivocation)
- Create forked chain histories
- Violate AptosBFT safety guarantees
- Potentially trigger consensus halts requiring manual intervention

**3. Complete Validator Compromise:** Unlike partial information leaks, this vulnerability exposes the root secret (Vault token) that provides access to ALL validator cryptographic material. This represents total compromise of a validator node's security boundary.

The impact is not limited to a single validator - if multiple validators use this insecure configuration pattern, an attacker could compromise multiple nodes, approaching the 1/3 Byzantine threshold required to break consensus safety.

## Likelihood Explanation

**High Likelihood** due to multiple factors:

1. **Easy Exploitation:** Attackers only need read access to logs or backups - no complex exploit development required

2. **Multiple Exposure Points:** 
   - Local log files (persisted on disk)
   - Remote telemetry systems (network transmission)
   - Configuration backups (often stored insecurely)
   - Process dumps (on crashes)
   - Log monitoring tools
   - Standard output (visible to system administrators)

3. **Common Attack Vectors:**
   - Compromised backup systems
   - Lateral movement after initial server breach
   - Insider threats with log access
   - Misconfigured log aggregation platforms
   - Cloud storage bucket misconfigurations

4. **Operational Reality:** While the example configuration uses `from_disk`, the `from_config` option exists without deprecation warnings. Operators may choose it for perceived convenience or during initial setup/testing and forget to change it in production.

5. **Long Exposure Window:** Once logged, tokens remain in:
   - Archived log files
   - Backup systems
   - Log aggregation indexes
   - Potentially indefinitely until manual cleanup

## Recommendation

**Immediate Fixes:**

1. **Mark Token Field as Sensitive:**
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Token {
    #[serde(serialize_with = "serialize_redacted")]
    FromConfig(String),
    FromDisk(PathBuf),
}

fn serialize_redacted<S>(_: &String, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str("***REDACTED***")
}
```

2. **Implement Custom Debug for VaultConfig:**
```rust
impl std::fmt::Debug for VaultConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultConfig")
            .field("server", &self.server)
            .field("namespace", &self.namespace)
            .field("token", &"***REDACTED***")
            .field("ca_certificate", &self.ca_certificate)
            // ... other non-sensitive fields
            .finish()
    }
}
```

3. **Add Configuration Validation:**
```rust
impl ConfigSanitizer for SafetyRulesConfig {
    fn sanitize(...) -> Result<(), Error> {
        // Existing checks...
        
        // Prevent Token::FromConfig in production
        if let SecureBackend::Vault(vault_config) = &safety_rules_config.backend {
            if matches!(vault_config.token, Token::FromConfig(_)) {
                if chain_id.map_or(false, |id| id.is_mainnet()) {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "Token::FromConfig must not be used in production. Use Token::FromDisk instead.".into()
                    ));
                }
            }
        }
        Ok(())
    }
}
```

4. **Deprecate Token::FromConfig with clear warnings in documentation**

**Additional Security Hardening:**

- Audit all serialization paths for sensitive data exposure
- Implement a centralized sensitive field redaction mechanism
- Add runtime detection of secrets in logs
- Rotate Vault tokens immediately on any validator that may have been affected

## Proof of Concept

```rust
#[cfg(test)]
mod token_exposure_poc {
    use super::*;
    use aptos_config::config::{NodeConfig, ConsensusConfig, SafetyRulesConfig, SecureBackend, VaultConfig, Token};
    use std::path::PathBuf;

    #[test]
    fn test_vault_token_logged_from_config() {
        // Create a NodeConfig with Token::FromConfig
        let secret_token = "hvs.SECRETVAULTTOKEN12345";
        let mut node_config = NodeConfig::default();
        
        node_config.consensus = ConsensusConfig {
            safety_rules: SafetyRulesConfig {
                backend: SecureBackend::Vault(VaultConfig {
                    server: "https://vault.example.com".to_string(),
                    token: Token::FromConfig(secret_token.to_string()),
                    namespace: Some("validator".to_string()),
                    ca_certificate: None,
                    renew_ttl_secs: None,
                    disable_cas: None,
                    connection_timeout_ms: None,
                    response_timeout_ms: None,
                }),
                ..Default::default()
            },
            ..Default::default()
        };

        // Simulate what log_all_configs() does
        let config_value = serde_json::to_value(&node_config).unwrap();
        let config_map = config_value.as_object().unwrap();
        
        for (config_name, config_value) in config_map {
            let config_string = serde_json::to_string(config_value).unwrap();
            
            // VULNERABILITY: The secret token appears in the serialized config
            if config_name == "consensus" {
                assert!(
                    config_string.contains(secret_token),
                    "Token was successfully redacted - vulnerability is fixed!"
                );
                println!("EXPOSED: Token found in logs: {}", config_string);
            }
        }

        // Also test Debug format (used in logger.rs:101)
        let debug_output = format!("{:?}", node_config);
        assert!(
            debug_output.contains(secret_token),
            "Token was successfully redacted in Debug output - vulnerability is fixed!"
        );
        println!("EXPOSED: Token found in Debug output");
    }

    #[test]
    fn test_token_from_disk_not_exposed() {
        // Demonstrate that Token::FromDisk does NOT expose the token content
        let mut node_config = NodeConfig::default();
        
        node_config.consensus = ConsensusConfig {
            safety_rules: SafetyRulesConfig {
                backend: SecureBackend::Vault(VaultConfig {
                    server: "https://vault.example.com".to_string(),
                    token: Token::FromDisk(PathBuf::from("/secure/path/to/token")),
                    namespace: Some("validator".to_string()),
                    ca_certificate: None,
                    renew_ttl_secs: None,
                    disable_cas: None,
                    connection_timeout_ms: None,
                    response_timeout_ms: None,
                }),
                ..Default::default()
            },
            ..Default::default()
        };

        let config_value = serde_json::to_value(&node_config).unwrap();
        let config_string = serde_json::to_string(&config_value).unwrap();
        
        // Only the path is logged, not the token content
        assert!(config_string.contains("/secure/path/to/token"));
        println!("Token::FromDisk only exposes path, not token content (expected behavior)");
    }
}
```

**Notes:**

The codebase already demonstrates awareness of this vulnerability class through the postgres password masking in `logger.rs`. The selective application suggests this may be an oversight rather than a deliberate design choice. The Prometheus client implementation also shows the correct pattern using `set_sensitive(true)` for authorization headers. [8](#0-7)

### Citations

**File:** config/src/config/secure_backend_config.rs (L51-74)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VaultConfig {
    /// Optional SSL Certificate for the vault host, this is expected to be a full path.
    pub ca_certificate: Option<PathBuf>,
    /// A namespace is an optional portion of the path to a key stored within Vault. For example,
    /// a secret, S, without a namespace would be available in secret/data/S, with a namespace, N, it
    /// would be in secret/data/N/S.
    pub namespace: Option<String>,
    /// Vault leverages leases on many tokens, specify this to automatically have your lease
    /// renewed up to that many seconds more. If this is not specified, the lease will not
    /// automatically be renewed.
    pub renew_ttl_secs: Option<u32>,
    /// Vault's URL, note: only HTTP is currently supported.
    pub server: String,
    /// The authorization token for accessing secrets
    pub token: Token,
    /// Disable check-and-set when writing secrets to Vault
    pub disable_cas: Option<bool>,
    /// Timeout for new vault socket connections, in milliseconds.
    pub connection_timeout_ms: Option<u64>,
    /// Timeout for generic vault operations (e.g., reads and writes), in milliseconds.
    pub response_timeout_ms: Option<u64>,
}
```

**File:** config/src/config/secure_backend_config.rs (L100-106)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Token {
    FromConfig(String),
    /// This is an absolute path and not relative to data_dir
    FromDisk(PathBuf),
}
```

**File:** config/src/config/node_config.rs (L95-111)
```rust
    /// Logs the node config using INFO level logging. This is useful for
    /// working around the length restrictions in the logger.
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

**File:** aptos-node/src/lib.rs (L697-698)
```rust
    // Log the node config at node startup
    node_config.log_all_configs();
```

**File:** aptos-node/src/logger.rs (L47-54)
```rust
    if let Some(log_file) = log_file {
        logger_builder.printer(Box::new(FileWriter::new(log_file)));
    }
    if node_config.logger.enable_telemetry_remote_log {
        let (tx, rx) = mpsc::channel(TELEMETRY_LOG_INGEST_BUFFER_SIZE);
        logger_builder.remote_log_tx(tx);
        remote_log_receiver = Some(rx);
    }
```

**File:** aptos-node/src/logger.rs (L88-101)
```rust
    // Log the node config
    let mut config = node_config;
    let mut masked_config;
    if let Some(u) = &node_config.indexer.postgres_uri {
        let mut parsed_url = url::Url::parse(u).expect("Invalid postgres uri");
        if parsed_url.password().is_some() {
            masked_config = node_config.clone();
            parsed_url.set_password(Some("*")).unwrap();
            masked_config.indexer.postgres_uri = Some(parsed_url.to_string());
            config = &masked_config;
        }
    }

    info!("Loaded node config: {:?}", config);
```

**File:** testsuite/forge/src/backend/k8s/prometheus.rs (L86-93)
```rust
        if let Ok(mut auth_value) =
            header::HeaderValue::from_str(format!("Bearer {}", token.as_str()).as_str())
        {
            auth_value.set_sensitive(true);
            headers.insert(header::AUTHORIZATION, auth_value);
        } else {
            bail!("Invalid prometheus token");
        }
```

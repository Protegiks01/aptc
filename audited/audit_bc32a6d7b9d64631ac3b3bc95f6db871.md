# Audit Report

## Title
Vault Authentication Credentials Exposed in Node Startup Logs via Debug Formatting

## Summary
VaultConfig credentials (authentication tokens and potentially server URLs with embedded credentials) are logged in plaintext during node startup due to Debug trait derivation on sensitive configuration structures, without credential masking.

## Finding Description

The `VaultConfig` struct stores Vault authentication credentials and derives the `Debug` trait, allowing its contents to be printed with `{:?}` formatting. [1](#0-0) 

The `Token` enum, which can contain the actual Vault authentication token as a plaintext `String` via the `FromConfig` variant, also derives `Debug` without any redaction mechanism. [2](#0-1) 

VaultConfig is embedded in critical configuration structures:
- `SafetyRulesConfig` (consensus safety rules backend) [3](#0-2) 
- `IdentityFromStorage` (network identity keys backend) [4](#0-3) 

These are contained within `NodeConfig`, which is logged at node startup using Debug formatting. [5](#0-4) 

While the logger masks PostgreSQL passwords from the indexer configuration, **no such masking is applied to Vault credentials**. If an operator configures `Token::FromConfig(String)` instead of `Token::FromDisk(PathBuf)`, the plaintext authentication token is logged. Additionally, if the `server` field contains HTTP Basic Auth credentials in the format `https://user:pass@host:port`, these would also be exposed.

**Attack Path:**
1. Validator node starts with VaultConfig containing `Token::FromConfig` or server URL with embedded credentials
2. Logger calls `info!("Loaded node config: {:?}", config)` at startup
3. Debug implementation prints full VaultConfig including plaintext credentials
4. Logs are collected by monitoring systems, stored in log aggregators, or accessed by operators
5. Attacker with log access extracts Vault credentials
6. Attacker authenticates to Vault and retrieves consensus keys, network identity keys, and other cryptographic material
7. Attacker can impersonate validator, sign malicious blocks, or compromise consensus

## Impact Explanation

This vulnerability qualifies as **High Severity** per Aptos Bug Bounty criteria:

**Direct Impact:**
- Unauthorized access to Vault storage containing validator consensus keys, network identity keys, and other cryptographic material
- Potential validator impersonation and consensus manipulation
- Breach of the secure backend protecting critical validator secrets

**Affected Components:**
- Consensus safety rules (SafetyRulesConfig uses SecureBackend::Vault)
- Network layer (validator and fullnode identity keys stored in Vault)
- Genesis waypoint verification (WaypointConfig::FromStorage)

**Severity Justification:**
While not directly causing consensus violations or fund theft, compromised Vault access enables:
- Theft of validator private keys leading to impersonation
- Consensus manipulation through unauthorized key access
- Potential validator node compromise

This meets "Significant protocol violations" and could escalate to Critical if keys are exfiltrated.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

**Factors Increasing Likelihood:**
1. **Common logging practices**: Production validators typically send logs to centralized monitoring systems (CloudWatch, Splunk, Datadog, etc.)
2. **Multiple access points**: Logs are accessible to SREs, DevOps teams, security analysts, and incident responders
3. **Log retention**: Credentials remain in historical logs even after rotation
4. **Cloud environments**: Managed logging services may have broader access controls
5. **Debug logging**: Node startup logs are typically at INFO level, enabled by default

**Factors Decreasing Likelihood:**
1. **Best practice discourages it**: Documentation recommends `Token::FromDisk` over `Token::FromConfig`
2. **Example configs use disk storage**: Validator templates show `from_disk` token configuration [6](#0-5) 

**Realistic Scenario:**
An operator during testing or quick setup uses `Token::FromConfig` for convenience, intending to change it later but forgetting. Logs are shipped to a monitoring system, and an attacker compromises the logging infrastructure or gains unauthorized access through misconfigured IAM policies.

## Recommendation

**Immediate Fix: Implement Custom Debug Trait for Sensitive Structures**

1. **Remove Debug derivation and implement custom Debug for VaultConfig:**

```rust
impl std::fmt::Debug for VaultConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultConfig")
            .field("ca_certificate", &self.ca_certificate)
            .field("namespace", &self.namespace)
            .field("renew_ttl_secs", &self.renew_ttl_secs)
            .field("server", &"<REDACTED>")  // Mask server URL
            .field("token", &"<REDACTED>")   // Mask token
            .field("disable_cas", &self.disable_cas)
            .field("connection_timeout_ms", &self.connection_timeout_ms)
            .field("response_timeout_ms", &self.response_timeout_ms)
            .finish()
    }
}
```

2. **Implement custom Debug for Token enum:**

```rust
impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Token::FromConfig(_) => write!(f, "Token::FromConfig(<REDACTED>)"),
            Token::FromDisk(path) => write!(f, "Token::FromDisk({:?})", path),
        }
    }
}
```

3. **Apply same pattern to SecureBackend enum to ensure consistent masking.**

**Additional Recommendations:**
- Audit all configuration structures containing sensitive data for similar issues
- Add lint rules or CI checks to prevent `Debug` derivation on sensitive types
- Document security best practices for credential storage in configs
- Consider deprecating `Token::FromConfig` entirely in production builds

## Proof of Concept

**Setup Configuration (vault_credentials_leak.yaml):**
```yaml
consensus:
  safety_rules:
    backend:
      type: vault
      server: "https://admin:supersecret@vault.example.com:8200"
      token:
        from_config: "s.VerySecretVaultToken123456789"
      namespace: "validator"
```

**Rust Test to Demonstrate Vulnerability:**
```rust
#[test]
fn test_vault_credentials_logged() {
    use aptos_config::config::*;
    
    // Create a VaultConfig with sensitive credentials
    let vault_config = VaultConfig {
        ca_certificate: None,
        namespace: Some("test".to_string()),
        renew_ttl_secs: None,
        server: "https://admin:password@vault.example.com:8200".to_string(),
        token: Token::FromConfig("s.SecretToken123".to_string()),
        disable_cas: None,
        connection_timeout_ms: None,
        response_timeout_ms: None,
    };
    
    // This is what happens in aptos-node/src/logger.rs:101
    let debug_output = format!("{:?}", vault_config);
    
    // Verify credentials are exposed
    assert!(debug_output.contains("admin:password"));
    assert!(debug_output.contains("s.SecretToken123"));
    
    println!("LEAKED CREDENTIALS IN LOGS:");
    println!("{}", debug_output);
    // Output would show:
    // VaultConfig { 
    //   server: "https://admin:password@vault.example.com:8200",
    //   token: FromConfig("s.SecretToken123"),
    //   ...
    // }
}
```

**Exploitation Steps:**
1. Attacker gains read access to validator node logs (via compromised monitoring system, misconfigured S3 bucket, or insider threat)
2. Search logs for "VaultConfig" or "Token::FromConfig" patterns at node startup
3. Extract plaintext Vault server URL and authentication token
4. Authenticate to Vault using extracted credentials
5. Export consensus private keys, network identity keys, or other secrets
6. Use stolen keys to impersonate validator or manipulate consensus

**Impact Verification:**
Access to Vault credentials grants full access to all secrets stored in that Vault namespace, including validator consensus keys that are critical for AptosBFT safety guarantees.

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

**File:** config/src/config/identity_config.rs (L151-157)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityFromStorage {
    pub backend: SecureBackend,
    pub key_name: String,
    pub peer_id_name: String,
}
```

**File:** aptos-node/src/logger.rs (L88-102)
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
}
```

**File:** config/src/config/test_data/validator.yaml (L9-10)
```yaml
            token:
                from_disk: "/full/path/to/token"
```

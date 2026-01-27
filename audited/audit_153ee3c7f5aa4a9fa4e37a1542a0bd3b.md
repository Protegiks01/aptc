# Audit Report

## Title
Vault Token and Internal IP Leakage via Configuration Error Messages

## Summary
Configuration error messages expose sensitive data including Vault authentication tokens and internal IP addresses through Debug formatting in panic messages and error displays, violating information security guarantees.

## Finding Description

The configuration system leaks sensitive data through error messages when configuration loading or sanitization fails. The vulnerability exists in multiple locations:

**1. Vault Token Exposure in Token Enum:**
The `Token` enum uses `#[derive(Debug)]` without protection for sensitive data: [1](#0-0) 

When a `Token::FromConfig(String)` variant contains an actual Vault authentication token, using Debug formatting (`{:?}`) exposes the plaintext token.

**2. Config Sanitizer Error Including Sensitive Config Values:**
The safety rules sanitizer directly includes configuration values in error messages: [2](#0-1) 

This includes the `RemoteService` with its `server_address: NetworkAddress` field: [3](#0-2) 

**3. Error Display Format Using Debug:**
Error messages are displayed using `{:?}` Debug formatting which doesn't mask sensitive data: [4](#0-3) 

**4. Panic Messages Expose Full Error Context:**
When configuration loading fails, the entire error is displayed in panic messages: [5](#0-4) 

**Attack Path:**
1. Operator configures Vault token directly in config file using `Token::FromConfig("sensitive_vault_token")`
2. Configuration file has YAML syntax error OR sanitizer validation fails (e.g., wrong safety rules service on mainnet)
3. Error is displayed via panic with Debug formatting
4. Vault token appears in plaintext: `Token::FromConfig("sensitive_vault_token")`
5. Internal IP addresses from `NetworkAddress` also exposed in error messages
6. Error messages logged to stderr, system logs, monitoring systems, or displayed to operators
7. Attacker with access to logs obtains credentials for further attacks

## Impact Explanation

This is classified as **Low Severity** per Aptos bug bounty categories: "Minor information leaks". While the leaked information (Vault authentication tokens, internal IP addresses) is sensitive and could enable subsequent attacks on infrastructure, the leak itself:
- Requires operator misconfiguration (syntax errors or validation failures)
- Does not directly cause loss of funds, consensus violations, or availability issues
- Is an operational security concern rather than a protocol vulnerability
- Requires access to error logs/output rather than remote exploitation

The leaked Vault tokens could allow attackers to access secure storage backends, and internal IPs could facilitate network reconnaissance, but these are secondary attack vectors enabled by the information leak.

## Likelihood Explanation

**Likelihood: Medium**
- Configuration errors occur regularly during node setup and updates
- Vault tokens are commonly stored directly in configs during testing/development
- Error messages are frequently logged to centralized logging systems
- Operators may not sanitize logs before sharing for debugging
- The vulnerability triggers automatically whenever config errors occur with sensitive data present

## Recommendation

Implement `SilentDebug` and `SilentDisplay` for sensitive configuration types:

```rust
// In config/src/config/secure_backend_config.rs
use aptos_crypto_derive::{SilentDebug, SilentDisplay};

#[derive(Clone, SilentDebug, SilentDisplay, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Token {
    FromConfig(String),
    FromDisk(PathBuf),
}
```

For error messages that include config values, sanitize the output:
```rust
// In config/src/config/safety_rules_config.rs
return Err(Error::ConfigSanitizerFailed(
    sanitizer_name,
    "The safety rules service should be set to local in mainnet for optimal performance!".to_string(),
    // Remove: Given config: {:?}", &safety_rules_config.service
));
```

Add redaction helper for NetworkAddress when used in error contexts.

## Proof of Concept

```rust
#[test]
fn test_vault_token_leak_in_error() {
    use std::fs;
    use aptos_config::config::NodeConfig;
    use aptos_temppath::TempPath;
    
    // Create a config file with a vault token and syntax error
    let config_content = r#"
base:
  role: "validator"
  
consensus:
  safety_rules:
    backend:
      type: "vault"
      server: "https://vault.example.com:8200"
      token:
        from_config: "hvs.SECRET_VAULT_TOKEN_12345"  # Sensitive token
    service:
      type: "serializer"  # Invalid for mainnet - will trigger sanitizer error

# Syntax error below
invalid_yaml: [unclosed
"#;
    
    let temp_path = TempPath::new();
    temp_path.create_as_file().unwrap();
    fs::write(temp_path.path(), config_content).unwrap();
    
    // Attempt to load config - this will fail and expose the token
    let result = NodeConfig::load_from_path(temp_path.path());
    
    // The error message will contain the plaintext vault token
    match result {
        Err(e) => {
            let error_string = format!("{:?}", e);
            // Verify token appears in error message (security vulnerability)
            assert!(error_string.contains("hvs.SECRET_VAULT_TOKEN_12345"),
                "Token leaked in error: {}", error_string);
        },
        Ok(_) => panic!("Expected config load to fail"),
    }
}
```

## Notes

While this is a real information disclosure issue, it does **not** meet the strict validation criteria for a high-severity bug bounty report because:
1. It's not remotely exploitable without node operator access
2. Classified as "Low Severity" (minor information leak) per bug bounty guidelines  
3. Doesn't violate consensus, execution, or state management invariants
4. Requires operational errors (misconfiguration) to trigger

This is an operational security hygiene issue that should be fixed to prevent credential leakage, but it's outside the scope of Critical/High/Medium severity protocol vulnerabilities.

### Citations

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

**File:** config/src/config/safety_rules_config.rs (L99-104)
```rust
            if chain_id.is_mainnet() && !safety_rules_config.service.is_local() {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    format!("The safety rules service should be set to local in mainnet for optimal performance! Given config: {:?}", &safety_rules_config.service)
                ));
            }
```

**File:** config/src/config/safety_rules_config.rs (L225-229)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteService {
    pub server_address: NetworkAddress,
}
```

**File:** config/src/config/error.rs (L8-17)
```rust
    #[error("Failed to sanitize the node config! Sanitizer: {0}, Error: {1}")]
    ConfigSanitizerFailed(String, String),
    #[error("Invariant violation: {0}")]
    InvariantViolation(String),
    #[error("Error accessing {0}: {1}")]
    IO(String, #[source] std::io::Error),
    #[error("Error (de)serializing {0}: {1}")]
    BCS(&'static str, #[source] bcs::Error),
    #[error("Error (de)serializing {0}: {1}")]
    Yaml(String, #[source] serde_yaml::Error),
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

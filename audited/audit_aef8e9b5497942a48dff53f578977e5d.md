# Audit Report

## Title
Vault Authentication Token Exposure via Debug Formatter Bypassing Secret Redaction

## Summary
The `Token` enum in the secure backend configuration derives standard `Debug` trait instead of `SilentDebug`, allowing Vault authentication tokens to be exposed in plain text when the inspection service configuration endpoint is queried. This bypasses the intended secret redaction mechanism and can lead to complete validator compromise.

## Finding Description
The inspection service's `handle_configuration_request()` function uses Debug formatting to serialize the entire `NodeConfig` structure. [1](#0-0) 

The code comment explicitly states that Debug formatting is used to prevent secret/private keys from being leaked because "all secret keys are marked with SilentDisplay and SilentDebug". However, this assumption is violated by the `Token` enum used for Vault authentication.

The vulnerability path traverses:
1. `NodeConfig` contains `consensus: ConsensusConfig` [2](#0-1) 
2. `ConsensusConfig` contains `safety_rules: SafetyRulesConfig` [3](#0-2) 
3. `SafetyRulesConfig` contains `backend: SecureBackend` [4](#0-3) 
4. `SecureBackend` has a `Vault(VaultConfig)` variant [5](#0-4) 
5. `VaultConfig` contains `token: Token` [6](#0-5) 
6. `Token` enum derives standard `Debug` and contains `FromConfig(String)` variant that stores the token as plain text [7](#0-6) 

When a validator uses Vault backend with `Token::FromConfig`, the actual authentication token is exposed. With this token, an attacker can access Vault and retrieve all stored secrets including consensus private keys, leading to complete validator compromise and potential consensus safety violations.

## Impact Explanation
This vulnerability qualifies as **CRITICAL severity** under the Aptos bug bounty program for multiple reasons:

1. **Consensus/Safety Violations**: Access to consensus private keys enables an attacker to sign malicious blocks and proposals, potentially causing equivocation, double-signing, and consensus safety violations.

2. **Loss of Funds**: Compromised validator keys can be used to manipulate staking rewards, steal delegated funds, or participate in governance attacks.

3. **Validator Node Compromise**: The Vault token provides access to all validator secrets, enabling complete control over the validator node's cryptographic operations.

The vulnerability breaks critical invariants:
- **Cryptographic Correctness**: Secret material (authentication tokens) must be protected
- **Access Control**: Authentication credentials must never be exposed to unauthorized parties
- **Consensus Safety**: Consensus private keys must remain confidential to prevent equivocation

## Likelihood Explanation
The likelihood is **MEDIUM** because exploitation requires specific conditions:

**Requirements for exploitation:**
1. The inspection service must have `expose_configuration: true` [8](#0-7) 
2. The validator must use Vault backend for secure storage
3. The Vault token must be configured as `Token::FromConfig` rather than `Token::FromDisk`

**Factors increasing likelihood:**
- Developers may enable the configuration endpoint during debugging or troubleshooting
- Some deployment scripts might use `Token::FromConfig` for convenience
- The endpoint may be unintentionally exposed if network configuration is misconfigured
- No authentication/authorization check is performed on the endpoint itself

**Factors decreasing likelihood:**
- Production validators typically use `Token::FromDisk` for better security
- The configuration endpoint should be disabled by default in production
- Many validators may use on-disk storage instead of Vault

However, even a medium likelihood combined with critical impact makes this a severe vulnerability requiring immediate remediation.

## Recommendation
The `Token` enum should derive `SilentDebug` and `SilentDisplay` instead of standard `Debug`:

```rust
#[derive(Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Token {
    FromConfig(SilentString),
    FromDisk(PathBuf),
}

// Wrapper type that implements SilentDebug
#[derive(Clone, Deserialize, PartialEq, Eq, Serialize, SilentDebug, SilentDisplay)]
pub struct SilentString(String);
```

Alternatively, implement custom `Debug` for `Token`:

```rust
impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Token::FromConfig(_) => write!(f, "Token::FromConfig(<redacted>)"),
            Token::FromDisk(path) => write!(f, "Token::FromDisk({:?})", path),
        }
    }
}
```

Additionally:
1. Perform a comprehensive audit of all config types to ensure sensitive fields use `SilentDebug`
2. Add compile-time enforcement via trait bounds where possible
3. Consider adding authentication/authorization to the inspection service endpoint
4. Add warning logs when the configuration endpoint is enabled

## Proof of Concept

```rust
#[cfg(test)]
mod test_token_exposure {
    use config::config::{NodeConfig, SecureBackend, VaultConfig, Token};
    
    #[test]
    fn test_vault_token_exposed_in_debug() {
        // Create a validator config with Vault backend
        let mut node_config = NodeConfig::get_default_validator_config();
        
        // Configure Vault with a secret token
        let vault_config = VaultConfig {
            ca_certificate: None,
            namespace: None,
            renew_ttl_secs: None,
            server: "https://vault.example.com".to_string(),
            token: Token::FromConfig("super_secret_vault_token_12345".to_string()),
            disable_cas: None,
            connection_timeout_ms: None,
            response_timeout_ms: None,
        };
        
        node_config.consensus.safety_rules.backend = 
            SecureBackend::Vault(vault_config);
        
        // Simulate what handle_configuration_request does
        let debug_output = format!("{:?}", node_config);
        
        // VULNERABILITY: The secret token appears in plain text
        assert!(debug_output.contains("super_secret_vault_token_12345"));
        println!("EXPOSED TOKEN IN DEBUG OUTPUT: {}", debug_output);
    }
}
```

This test demonstrates that the Vault token is exposed in the Debug output, which would be returned to any client querying the inspection service configuration endpoint.

## Notes
This vulnerability demonstrates that relying on coding conventions (using `SilentDebug` for all secrets) without compile-time enforcement is insufficient. While private key types like `x25519::PrivateKey`, `bls12381::PrivateKey`, and `Ed25519PrivateKey` correctly use `SilentDebug` [9](#0-8) [10](#0-9) [11](#0-10) , authentication tokens were overlooked.

The `ConfigKey` wrapper also derives standard `Debug` rather than `SilentDebug` [12](#0-11) , though this works correctly because the derived implementation recursively calls the inner type's `Debug`. However, this creates a fragile design that should be made more explicit.

### Citations

**File:** crates/aptos-inspection-service/src/server/configuration.rs (L15-15)
```rust
    let (status_code, body) = if node_config.inspection_service.expose_configuration {
```

**File:** crates/aptos-inspection-service/src/server/configuration.rs (L16-19)
```rust
        // We format the configuration using debug formatting. This is important to
        // prevent secret/private keys from being serialized and leaked (i.e.,
        // all secret keys are marked with SilentDisplay and SilentDebug).
        let encoded_configuration = format!("{:?}", node_config);
```

**File:** config/src/config/node_config.rs (L45-45)
```rust
    pub consensus: ConsensusConfig,
```

**File:** config/src/config/consensus_config.rs (L51-51)
```rust
    pub safety_rules: SafetyRulesConfig,
```

**File:** config/src/config/safety_rules_config.rs (L26-26)
```rust
    pub backend: SecureBackend,
```

**File:** config/src/config/secure_backend_config.rs (L20-20)
```rust
    Vault(VaultConfig),
```

**File:** config/src/config/secure_backend_config.rs (L67-67)
```rust
    pub token: Token,
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

**File:** crates/aptos-crypto/src/x25519.rs (L66-66)
```rust
#[derive(DeserializeKey, SilentDisplay, SilentDebug, SerializeKey)]
```

**File:** crates/aptos-crypto/src/bls12381/bls12381_keys.rs (L41-41)
```rust
#[derive(SerializeKey, DeserializeKey, SilentDebug, SilentDisplay)]
```

**File:** crates/aptos-crypto/src/ed25519/ed25519_keys.rs (L23-23)
```rust
#[derive(DeserializeKey, SerializeKey, SilentDebug, SilentDisplay)]
```

**File:** config/src/keys.rs (L25-25)
```rust
#[derive(Debug, Deserialize, Serialize)]
```

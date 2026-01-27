# Audit Report

## Title
Vault Authentication Token Leakage via Inspection Service Debug Formatting

## Summary
The `Token` enum in `SecureBackend` configuration derives `Debug` without protection, causing Vault authentication tokens to be exposed in plaintext when the inspection service's configuration endpoint is enabled. This leaks critical credentials that provide access to the Vault where consensus private keys are stored.

## Finding Description

The inspection service's `handle_configuration_request()` function uses Debug formatting to serialize the entire NodeConfig: [1](#0-0) 

The code comment explicitly states that "all secret keys are marked with SilentDisplay and SilentDebug" to prevent leakage. However, this protection is incomplete.

While cryptographic private keys (`x25519::PrivateKey`, `bls12381::PrivateKey`, `Ed25519PrivateKey`) properly use `SilentDebug`: [2](#0-1) [3](#0-2) 

The `Token` enum used for Vault authentication **derives Debug without any protection**: [4](#0-3) 

This enum is used in `VaultConfig` which is also Debug-derived: [5](#0-4) 

The attack chain is:
1. NodeConfig (Debug) → ConsensusConfig (Debug) → SafetyRulesConfig (Debug)
2. SafetyRulesConfig contains `backend: SecureBackend` 
3. SecureBackend::Vault(VaultConfig) contains `token: Token`
4. Token::FromConfig(String) **exposes the plaintext Vault token**

The codebase demonstrates awareness of this issue. `IndexerConfig` implements a **custom Debug** to redact database passwords: [6](#0-5) 

However, this same protection was not applied to the `Token` enum, creating an inconsistent security posture.

**Exploitation Scenario:**
1. On testnet/devnet, `expose_configuration` is enabled by default: [7](#0-6) 

2. An attacker makes an HTTP request to `http://<node>:9101/configuration`
3. The response contains the Debug-formatted NodeConfig with plaintext Vault tokens
4. The attacker uses the token to authenticate to the Vault server
5. The attacker retrieves the consensus private key from Vault
6. The attacker can now sign malicious blocks as the validator

**Note:** Mainnet validators are protected by a sanitizer that blocks this: [8](#0-7) 

However, the vulnerability still affects:
- All testnet/devnet validators (enabled by default)
- Mainnet fullnodes (if manually configured)
- Development/testing environments
- Any misconfigured nodes

## Impact Explanation

**Severity: HIGH to CRITICAL** depending on deployment:

1. **Credential Exposure**: Vault tokens are authentication credentials equivalent to passwords. Exposing them violates the **Cryptographic Correctness** invariant.

2. **Consensus Key Compromise**: With a Vault token, an attacker can retrieve the validator's consensus private key, enabling:
   - Signing malicious blocks
   - Double-signing attacks
   - Equivocation
   - Consensus safety violations

3. **Testnet Impact**: While testnet has lower security requirements, validators on testnet often test real consensus mechanisms and credential management practices that will be used in production.

4. **Defense-in-Depth Violation**: The sanitizer protection on mainnet validators represents a single point of failure. The Token type itself should be secure-by-default like all other private keys.

Per Aptos bug bounty criteria:
- **High Severity** ($50,000): "Significant protocol violations" - credential leakage enabling consensus compromise
- Potential **Critical** if demonstrated on a misconfigured mainnet node

## Likelihood Explanation

**High Likelihood** for affected deployments:

1. **Default Configuration**: On testnet/devnet, `expose_configuration` is automatically enabled, making this vulnerability immediately exploitable without any misconfig uration.

2. **Network Accessibility**: The inspection service listens on `0.0.0.0:9101` by default, making it accessible to any network peer.

3. **No Authentication**: The configuration endpoint has no authentication requirements when enabled.

4. **Common Vault Usage**: Many production-grade validator setups use Vault for key management, making this vulnerability widely applicable.

5. **Human Error**: Even with mainnet protections, operators might manually enable the endpoint for debugging without realizing the security implications.

## Recommendation

Apply the same protection pattern used for private keys and database passwords. Implement a custom `Debug` trait for the `Token` enum:

```rust
use std::fmt;

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Token::FromConfig(_) => write!(f, "Token::FromConfig(<redacted>)"),
            Token::FromDisk(path) => f.debug_tuple("Token::FromDisk").field(path).finish(),
        }
    }
}
```

Alternatively, wrap the token string in a type with `SilentDebug`:

```rust
use aptos_crypto_derive::SilentDebug;

#[derive(Clone, SilentDebug, Deserialize, Serialize)]
struct SensitiveString(String);

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum Token {
    FromConfig(SensitiveString),
    FromDisk(PathBuf),
}
```

**Additional Recommendations:**
1. Audit all config types for similar sensitive data leaks
2. Consider adding authentication to the inspection service endpoints
3. Add integration tests that verify sensitive data is redacted in Debug output

## Proof of Concept

Create a test demonstrating the token leak:

```rust
#[cfg(test)]
mod test {
    use super::*;
    use crate::config::{NodeConfig, ConsensusConfig, SafetyRulesConfig, SecureBackend, VaultConfig};
    
    #[test]
    fn test_vault_token_leaks_in_debug() {
        let vault_config = VaultConfig {
            server: "https://vault.example.com".to_string(),
            token: Token::FromConfig("secret-vault-token-12345".to_string()),
            ca_certificate: None,
            namespace: None,
            renew_ttl_secs: None,
            disable_cas: None,
            connection_timeout_ms: None,
            response_timeout_ms: None,
        };
        
        let backend = SecureBackend::Vault(vault_config);
        let debug_output = format!("{:?}", backend);
        
        // This assertion PASSES, demonstrating the vulnerability
        assert!(debug_output.contains("secret-vault-token-12345"),
            "Vault token is exposed in Debug output: {}", debug_output);
        
        // Expected behavior: token should be redacted
        // assert!(!debug_output.contains("secret-vault-token-12345"));
    }
}
```

To demonstrate the full attack:

```rust
// Simulate inspection service endpoint response
let mut node_config = NodeConfig::get_default_validator_config();
node_config.consensus.safety_rules.backend = SecureBackend::Vault(VaultConfig {
    server: "https://vault.example.com".to_string(),
    token: Token::FromConfig("attacker-can-steal-this".to_string()),
    // ... other fields
});
node_config.inspection_service.expose_configuration = true;

// What an attacker receives:
let response = format!("{:?}", node_config);
assert!(response.contains("attacker-can-steal-this"));
```

**Notes**

This vulnerability represents a defense-in-depth failure. While mainnet validators are protected by the configuration sanitizer, the underlying data structure is insecure-by-default. This violates the principle of least privilege and creates unnecessary attack surface. The inconsistency with how `IndexerConfig` handles sensitive data (custom Debug to redact passwords) and how private keys are protected (SilentDebug) indicates this is an oversight rather than intentional design.

### Citations

**File:** crates/aptos-inspection-service/src/server/configuration.rs (L13-20)
```rust
pub fn handle_configuration_request(node_config: &NodeConfig) -> (StatusCode, Body, String) {
    // Only return configuration if the endpoint is enabled
    let (status_code, body) = if node_config.inspection_service.expose_configuration {
        // We format the configuration using debug formatting. This is important to
        // prevent secret/private keys from being serialized and leaked (i.e.,
        // all secret keys are marked with SilentDisplay and SilentDebug).
        let encoded_configuration = format!("{:?}", node_config);
        (StatusCode::OK, Body::from(encoded_configuration))
```

**File:** crates/aptos-crypto/src/x25519.rs (L66-68)
```rust
#[derive(DeserializeKey, SilentDisplay, SilentDebug, SerializeKey)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Clone))]
pub struct PrivateKey(x25519_dalek::StaticSecret);
```

**File:** crates/aptos-crypto/src/bls12381/bls12381_keys.rs (L41-45)
```rust
#[derive(SerializeKey, DeserializeKey, SilentDebug, SilentDisplay)]
/// A BLS12381 private key
pub struct PrivateKey {
    pub(crate) privkey: blst::min_pk::SecretKey,
}
```

**File:** config/src/config/secure_backend_config.rs (L51-67)
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

**File:** config/src/config/indexer_config.rs (L92-100)
```rust
impl Debug for IndexerConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let postgres_uri = self.postgres_uri.as_ref().map(|u| {
            let mut parsed_url = url::Url::parse(u).expect("Invalid postgres uri");
            if parsed_url.password().is_some() {
                parsed_url.set_password(Some("*")).unwrap();
            }
            parsed_url.to_string()
        });
```

**File:** config/src/config/inspection_service_config.rs (L54-64)
```rust
        // Verify that mainnet validators do not expose the configuration
        if let Some(chain_id) = chain_id {
            if node_type.is_validator()
                && chain_id.is_mainnet()
                && inspection_service_config.expose_configuration
            {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "Mainnet validators should not expose the node configuration!".to_string(),
                ));
            }
```

**File:** config/src/config/inspection_service_config.rs (L84-88)
```rust
            if !chain_id.is_mainnet() {
                if local_inspection_config_yaml["expose_configuration"].is_null() {
                    inspection_service_config.expose_configuration = true;
                    modified_config = true;
                }
```

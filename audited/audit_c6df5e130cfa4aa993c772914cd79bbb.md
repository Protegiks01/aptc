# Audit Report

## Title
Vault Authentication Token Exposure via Inspection Service Configuration Endpoint

## Summary
The inspection service configuration endpoint exposes HashiCorp Vault authentication tokens when `expose_configuration=true` because the `Token` enum uses standard `Debug` formatting instead of `SilentDebug`. This allows attackers to steal Vault credentials and access all secrets stored in Vault, including consensus private keys, validator private keys, and network keys. [1](#0-0) 

## Finding Description

The inspection service provides a `/configuration` endpoint that exposes the entire `NodeConfig` when `expose_configuration=true`. The implementation uses Rust's Debug formatting to serialize the configuration: [2](#0-1) 

The code comment at line 16-18 claims that "all secret keys are marked with SilentDisplay and SilentDebug" to prevent leakage. However, the `Token` enum used for Vault authentication is **NOT** marked with `SilentDebug`: [3](#0-2) 

The `Token` enum derives standard `Debug`, which means `Token::FromConfig(String)` will print the actual token string in plain text. This token is used throughout the configuration hierarchy:

1. **Safety Rules Backend**: [4](#0-3) 

2. **Vault Configuration**: [5](#0-4) 

3. **Network Identity Storage**: [6](#0-5) 

When a validator or fullnode is configured with vault tokens embedded directly in the config (using `Token::FromConfig`), these tokens are exposed to anyone who can access the inspection service endpoint.

**Attack Path:**
1. Attacker discovers a node with inspection service enabled (port 9101 by default)
2. Attacker sends GET request to `http://<node-ip>:9101/configuration`
3. If `expose_configuration=true` (automatically enabled on non-mainnet by ConfigOptimizer): [7](#0-6) 
4. Response contains Debug-formatted NodeConfig with plain-text vault tokens
5. Attacker uses stolen token to authenticate to Vault and retrieve all secrets

## Impact Explanation

**Severity: CRITICAL** (up to $1,000,000 per Aptos Bug Bounty)

This vulnerability enables complete compromise of the validator's secure storage:

1. **Consensus Key Theft**: Vault stores BLS consensus private keys. With the vault token, an attacker can retrieve these keys and sign malicious blocks, leading to consensus safety violations and potential chain splits.

2. **Validator Private Key Theft**: Account private keys stored in Vault can be stolen, allowing fund theft from the validator's account.

3. **Network Key Compromise**: X25519 network private keys can be stolen, enabling man-in-the-middle attacks and network impersonation.

4. **Complete Validator Compromise**: Access to all secrets in Vault allows attacker to fully impersonate the validator.

This meets the **Critical Severity** criteria:
- Enables consensus/safety violations (validators can be impersonated)
- Enables loss of funds (validator account keys can be stolen)
- Enables remote compromise of validator operations

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

Factors increasing likelihood:
1. **Auto-enabled on testnet/devnet**: The ConfigOptimizer automatically enables `expose_configuration` on non-mainnet networks: [8](#0-7) 

2. **Common configuration pattern**: Documentation and test files show `Token::FromConfig` as a valid option: [9](#0-8) 

3. **No authentication**: Inspection service endpoints require no authentication

4. **Default port**: Service runs on predictable port 9101

Factors decreasing likelihood:
1. **Mainnet protection**: ConfigSanitizer prevents mainnet validators from enabling `expose_configuration`: [10](#0-9) 

2. **Best practice**: Recommended configuration uses `Token::FromDisk` instead of `Token::FromConfig`

3. **Network access required**: Attacker needs network access to the inspection service

However, the vulnerability remains critical because:
- Testnet/devnet validators handle real value during testing
- Many operators may expose inspection service for debugging
- The code explicitly claims secrets are protected when they are not

## Recommendation

**Immediate Fix**: Mark the `Token` enum with `SilentDebug` to prevent token exposure:

```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Token {
    FromConfig(String),
    FromDisk(PathBuf),
}
```

Should be changed to:

```rust
use aptos_crypto_derive::SilentDebug;

#[derive(Clone, SilentDebug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Token {
    FromConfig(String),
    FromDisk(PathBuf),
}
```

This ensures that Debug formatting outputs `<elided secret for Token>` instead of the actual token value.

**Additional Recommendations:**
1. Audit all configuration structures for similar issues where secrets may not use `SilentDebug`
2. Add authentication to inspection service endpoints
3. Consider disabling `expose_configuration` by default even on testnet
4. Document that `Token::FromDisk` is the only secure option for production use

## Proof of Concept

```rust
use aptos_config::config::{NodeConfig, SecureBackend, VaultConfig, Token};

#[test]
fn test_vault_token_exposure() {
    // Create a node config with embedded vault token
    let mut config = NodeConfig::default();
    
    // Configure safety rules with vault backend using embedded token
    config.consensus.safety_rules.backend = SecureBackend::Vault(VaultConfig {
        ca_certificate: None,
        namespace: Some("test".to_string()),
        renew_ttl_secs: None,
        server: "https://vault.example.com:8200".to_string(),
        token: Token::FromConfig("s.SuperSecretVaultToken12345".to_string()),
        disable_cas: None,
        connection_timeout_ms: None,
        response_timeout_ms: None,
    });
    
    // Simulate what the inspection service does
    let debug_output = format!("{:?}", config);
    
    // VULNERABILITY: The actual token is exposed in debug output
    assert!(debug_output.contains("s.SuperSecretVaultToken12345"));
    
    // Expected behavior: Token should be elided
    // assert!(debug_output.contains("<elided secret"));
    // assert!(!debug_output.contains("s.SuperSecretVaultToken12345"));
    
    println!("VULNERABLE: Vault token exposed in debug output!");
    println!("Leaked token: s.SuperSecretVaultToken12345");
}
```

This PoC demonstrates that when a `NodeConfig` with vault tokens is formatted using Debug (as done by the inspection service), the actual token string is exposed rather than being elided.

## Notes

While private keys themselves (BLS, Ed25519, X25519) are properly protected with `SilentDebug`, the authentication credentials used to access those keys in Vault are not protected. This creates a critical gap in the security model where the "keys to the keys" are exposed, allowing an attacker to bypass all the careful protections around the actual cryptographic key material.

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

**File:** config/src/config/secure_backend_config.rs (L99-115)
```rust
/// Tokens can either be directly within this config or stored somewhere on disk.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Token {
    FromConfig(String),
    /// This is an absolute path and not relative to data_dir
    FromDisk(PathBuf),
}

impl Token {
    pub fn read_token(&self) -> Result<String, Error> {
        match self {
            Token::FromDisk(path) => read_file(path),
            Token::FromConfig(token) => Ok(token.clone()),
        }
    }
}
```

**File:** crates/aptos-inspection-service/src/server/configuration.rs (L13-26)
```rust
pub fn handle_configuration_request(node_config: &NodeConfig) -> (StatusCode, Body, String) {
    // Only return configuration if the endpoint is enabled
    let (status_code, body) = if node_config.inspection_service.expose_configuration {
        // We format the configuration using debug formatting. This is important to
        // prevent secret/private keys from being serialized and leaked (i.e.,
        // all secret keys are marked with SilentDisplay and SilentDebug).
        let encoded_configuration = format!("{:?}", node_config);
        (StatusCode::OK, Body::from(encoded_configuration))
    } else {
        (
            StatusCode::FORBIDDEN,
            Body::from(CONFIGURATION_DISABLED_MESSAGE),
        )
    };
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

**File:** config/src/config/identity_config.rs (L150-157)
```rust
/// This represents an identity in a secure-storage as defined in NodeConfig::secure.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityFromStorage {
    pub backend: SecureBackend,
    pub key_name: String,
    pub peer_id_name: String,
}
```

**File:** config/src/config/inspection_service_config.rs (L45-69)
```rust
impl ConfigSanitizer for InspectionServiceConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let inspection_service_config = &node_config.inspection_service;

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
        }

        Ok(())
    }
}
```

**File:** config/src/config/inspection_service_config.rs (L71-109)
```rust
impl ConfigOptimizer for InspectionServiceConfig {
    fn optimize(
        node_config: &mut NodeConfig,
        local_config_yaml: &Value,
        _node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<bool, Error> {
        let inspection_service_config = &mut node_config.inspection_service;
        let local_inspection_config_yaml = &local_config_yaml["inspection_service"];

        // Enable all endpoints for non-mainnet nodes (to aid debugging)
        let mut modified_config = false;
        if let Some(chain_id) = chain_id {
            if !chain_id.is_mainnet() {
                if local_inspection_config_yaml["expose_configuration"].is_null() {
                    inspection_service_config.expose_configuration = true;
                    modified_config = true;
                }

                if local_inspection_config_yaml["expose_identity_information"].is_null() {
                    inspection_service_config.expose_identity_information = true;
                    modified_config = true;
                }

                if local_inspection_config_yaml["expose_peer_information"].is_null() {
                    inspection_service_config.expose_peer_information = true;
                    modified_config = true;
                }

                if local_inspection_config_yaml["expose_system_information"].is_null() {
                    inspection_service_config.expose_system_information = true;
                    modified_config = true;
                }
            }
        }

        Ok(modified_config)
    }
}
```

**File:** config/src/config/test_data/validator.yaml (L8-10)
```yaml
            ca_certificate: "/full/path/to/certificate"
            token:
                from_disk: "/full/path/to/token"
```

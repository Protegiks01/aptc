# Audit Report

## Title
Silent Dropping of Governance-Approved OIDC Providers During Migration Breaks Keyless Authentication

## Summary
The migration code that converts deprecated `SupportedOIDCProviders` to `OnChainJWKConsensusConfig` silently drops OIDC providers that fail UTF-8 validation, potentially breaking keyless authentication for governance-approved providers without any error indication.

## Finding Description

The vulnerability exists in the migration path from the deprecated OIDC provider configuration format to the new format. [1](#0-0) 

The old format stores provider names and URLs as raw byte vectors without UTF-8 validation: [2](#0-1) [3](#0-2) 

The new format requires valid UTF-8 strings: [4](#0-3) 

During epoch initialization, when `OnChainJWKConsensusConfig` is not yet initialized, the system falls back to constructing it from deprecated resources: [5](#0-4) [6](#0-5) 

The UTF-8 conversion can fail: [7](#0-6) 

When a provider fails conversion, the `.ok()` silently discards the error and `filter_map` removes it from the list. This means:

1. A governance proposal could approve a provider with non-UTF-8 bytes (accidentally or maliciously)
2. During epoch initialization, the provider would be silently dropped
3. Validators wouldn't fetch JWKs for that provider
4. Keyless authentication for users of that provider would fail
5. No error, warning, or log would indicate the provider was dropped

The impact propagates to keyless transaction validation: [8](#0-7) 

If the provider's JWKs aren't present, authentication fails with "JWK for {issuer} with KID {kid} was not found".

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty criteria:
- **State inconsistencies requiring intervention**: Governance-approved providers are silently excluded from the active configuration
- **Significant protocol violation**: Breaks keyless authentication, a critical security feature

While not reaching Critical severity (no direct fund loss or consensus break), this violates the governance integrity invariant by silently ignoring governance decisions.

## Likelihood Explanation

**Low to Medium likelihood**:

**Decreasing factors:**
- Requires use of deprecated API (`jwks::upsert_oidc_provider_for_next_epoch`)
- Only affects systems during migration period before new config is initialized
- Modern usage should use the new `jwk_consensus_config` API with proper UTF-8 validation

**Increasing factors:**
- No UTF-8 validation in the old API allows non-UTF-8 data
- Silent failure makes detection extremely difficult
- Could happen accidentally through encoding bugs in governance proposal tools
- Affects critical security feature (keyless authentication)

The code includes a TODO indicating migration code should be removed: [9](#0-8) 

## Recommendation

**Immediate Fix**: Replace silent dropping with explicit error handling:

```rust
impl From<(Option<Features>, Option<SupportedOIDCProviders>)> for OnChainJWKConsensusConfig {
    fn from(
        (features, supported_oidc_providers): (Option<Features>, Option<SupportedOIDCProviders>),
    ) -> Self {
        if let Some(features) = features {
            if features.is_enabled(FeatureFlag::JWK_CONSENSUS) {
                let mut oidc_providers = Vec::new();
                for deprecated in supported_oidc_providers.unwrap_or_default().providers {
                    match OIDCProvider::try_from(deprecated) {
                        Ok(provider) => oidc_providers.push(provider),
                        Err(e) => {
                            error!(
                                "Failed to convert OIDC provider to UTF-8, dropping: {:?}. \
                                This provider was governance-approved but cannot be used due to \
                                invalid UTF-8 encoding: {}",
                                deprecated, e
                            );
                            // Consider: return error or use default config instead of silently dropping
                        }
                    }
                }
                OnChainJWKConsensusConfig::V1(ConfigV1 { oidc_providers })
            } else {
                OnChainJWKConsensusConfig::Off
            }
        } else {
            OnChainJWKConsensusConfig::Off
        }
    }
}
```

**Long-term Fix**: 
1. Remove deprecated migration code path entirely as planned
2. Add UTF-8 validation to the old API if it must remain

## Proof of Concept

```rust
#[test]
fn test_silent_provider_dropping() {
    use aptos_types::jwks::{OIDCProvider as DeprecatedProvider, SupportedOIDCProviders};
    use aptos_types::on_chain_config::{Features, OnChainJWKConsensusConfig, FeatureFlag};
    
    // Create a provider with invalid UTF-8
    let invalid_utf8_provider = DeprecatedProvider {
        name: vec![0xFF, 0xFE], // Invalid UTF-8 bytes
        config_url: b"https://example.com".to_vec(),
    };
    
    let valid_provider = DeprecatedProvider {
        name: b"https://accounts.google.com".to_vec(),
        config_url: b"https://accounts.google.com/.well-known/openid-configuration".to_vec(),
    };
    
    let mut features = Features::default();
    features.enable(FeatureFlag::JWK_CONSENSUS);
    
    let supported_providers = SupportedOIDCProviders {
        providers: vec![valid_provider, invalid_utf8_provider],
    };
    
    // Conversion should drop the invalid provider silently
    let config = OnChainJWKConsensusConfig::from((Some(features), Some(supported_providers)));
    
    match config {
        OnChainJWKConsensusConfig::V1(v1) => {
            // Only 1 provider instead of 2 - invalid one was silently dropped
            assert_eq!(v1.oidc_providers.len(), 1);
            assert_eq!(v1.oidc_providers[0].name, "https://accounts.google.com");
            // The provider with invalid UTF-8 is gone without any error indication
        },
        _ => panic!("Expected V1 config"),
    }
}
```

**Notes**

This vulnerability represents a violation of the fail-fast principle in security-critical code. While the deprecated migration path has low likelihood of exploitation, the silent failure mode is problematic because:

1. It can hide genuine governance decisions without any indication
2. Debugging keyless authentication failures would be extremely difficult
3. The root cause (UTF-8 validation failure during migration) would not be apparent

The issue is contained to the migration code path and will be resolved when the deprecated API is fully removed. However, until then, explicit error handling or validation should be added to prevent silent data loss of governance-approved configurations.

### Citations

**File:** types/src/on_chain_config/jwk_consensus_config.rs (L112-132)
```rust
impl From<(Option<Features>, Option<SupportedOIDCProviders>)> for OnChainJWKConsensusConfig {
    fn from(
        (features, supported_oidc_providers): (Option<Features>, Option<SupportedOIDCProviders>),
    ) -> Self {
        if let Some(features) = features {
            if features.is_enabled(FeatureFlag::JWK_CONSENSUS) {
                let oidc_providers = supported_oidc_providers
                    .unwrap_or_default()
                    .providers
                    .into_iter()
                    .filter_map(|deprecated| OIDCProvider::try_from(deprecated).ok())
                    .collect();
                OnChainJWKConsensusConfig::V1(ConfigV1 { oidc_providers })
            } else {
                OnChainJWKConsensusConfig::Off
            }
        } else {
            OnChainJWKConsensusConfig::Off
        }
    }
}
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L54-61)
```text
    struct OIDCProvider has copy, drop, store {
        /// The utf-8 encoded issuer string. E.g., b"https://www.facebook.com".
        name: vector<u8>,

        /// The ut8-8 encoded OpenID configuration URL of the provider.
        /// E.g., b"https://www.facebook.com/.well-known/openid-configuration/".
        config_url: vector<u8>,
    }
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L317-330)
```text
    public fun upsert_oidc_provider_for_next_epoch(fx: &signer, name: vector<u8>, config_url: vector<u8>): Option<vector<u8>> acquires SupportedOIDCProviders {
        system_addresses::assert_aptos_framework(fx);

        let provider_set = if (config_buffer::does_exist<SupportedOIDCProviders>()) {
            config_buffer::extract_v2<SupportedOIDCProviders>()
        } else {
            *borrow_global<SupportedOIDCProviders>(@aptos_framework)
        };

        let old_config_url = remove_oidc_provider_internal(&mut provider_set, name);
        vector::push_back(&mut provider_set.providers, OIDCProvider { name, config_url });
        config_buffer::upsert(provider_set);
        old_config_url
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/jwk_consensus_config.move (L34-37)
```text
    struct OIDCProvider has copy, drop, store {
        name: String,
        config_url: String,
    }
```

**File:** consensus/src/epoch_manager.rs (L1223-1226)
```rust
        let jwk_consensus_config = onchain_jwk_consensus_config.unwrap_or_else(|_| {
            // `jwk_consensus_config` not yet initialized, falling back to the old configs.
            Self::equivalent_jwk_consensus_config_from_deprecated_resources(&payload)
        });
```

**File:** consensus/src/epoch_manager.rs (L1962-1969)
```rust
    /// Before `JWKConsensusConfig` is initialized, convert from `Features` and `SupportedOIDCProviders` instead.
    fn equivalent_jwk_consensus_config_from_deprecated_resources(
        payload: &OnChainConfigPayload<P>,
    ) -> OnChainJWKConsensusConfig {
        let features = payload.get::<Features>().ok();
        let oidc_providers = payload.get::<SupportedOIDCProviders>().ok();
        OnChainJWKConsensusConfig::from((features, oidc_providers))
    }
```

**File:** types/src/jwks/mod.rs (L83-92)
```rust
impl TryFrom<OIDCProvider> for crate::on_chain_config::OIDCProvider {
    type Error = anyhow::Error;

    fn try_from(value: OIDCProvider) -> Result<Self, Self::Error> {
        let OIDCProvider { name, config_url } = value;
        let name = String::from_utf8(name)?;
        let config_url = String::from_utf8(config_url)?;
        Ok(crate::on_chain_config::OIDCProvider { name, config_url })
    }
}
```

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L112-126)
```rust
fn get_jwk_for_authenticator(
    jwks: &AllProvidersJWKs,
    pk: &KeylessPublicKey,
    sig: &KeylessSignature,
) -> Result<JWK, VMStatus> {
    let jwt_header = sig
        .parse_jwt_header()
        .map_err(|_| invalid_signature!("Failed to parse JWT header"))?;

    let jwk_move_struct = jwks.get_jwk(&pk.iss_val, &jwt_header.kid).map_err(|_| {
        invalid_signature!(format!(
            "JWK for {} with KID {} was not found",
            pk.iss_val, jwt_header.kid
        ))
    })?;
```

**File:** crates/aptos-jwk-consensus/src/epoch_manager.rs (L188-194)
```rust
            Err(_) => {
                //TODO: remove this case once the framework change of this commit is published.
                let should_run = features.is_enabled(FeatureFlag::JWK_CONSENSUS)
                    && onchain_consensus_config.is_vtxn_enabled();
                let providers = payload.get::<SupportedOIDCProviders>().ok();
                (should_run, providers)
            },
```

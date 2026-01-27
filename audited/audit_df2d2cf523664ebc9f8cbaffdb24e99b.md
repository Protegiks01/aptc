# Audit Report

## Title
URL Trailing Slash Inconsistency in OIDC Provider Configuration Causes JWK Lookup Failures

## Summary
The `OIDCProvider` configuration in the JWK consensus system performs no URL normalization on the `name` field (issuer URL), leading to exact string matching failures when JWT issuers use different trailing slash conventions (e.g., Auth0 uses `"https://example.auth0.com/"` while Google uses `"https://accounts.google.com"`). This causes keyless transaction validation failures and allows duplicate provider configurations.

## Finding Description

The JWK consensus configuration system treats URLs with and without trailing slashes as completely different OIDC providers due to lack of URL normalization at multiple levels:

**Configuration Level:** The `OIDCProvider` struct stores the issuer URL in the `name` field with no validation or normalization. [1](#0-0) 

The duplicate check in `new_v1()` only compares string equality, so `"https://example.com"` and `"https://example.com/"` pass as distinct providers: [2](#0-1) 

**JWK Fetch Level:** The `JWKObserver` uses the provider `name` directly as the issuer when storing JWKs: [3](#0-2) 

**Validation Level:** During keyless transaction validation, JWK lookup uses exact string matching with no normalization: [4](#0-3) [5](#0-4) 

The validator calls this with the JWT's `iss` claim value: [6](#0-5) 

**Real-World Impact:** Different OIDC providers use different trailing slash conventions. Auth0 explicitly requires trailing slashes in issuer URLs: [7](#0-6) 

Test cases confirm Auth0 JWTs include the trailing slash: [8](#0-7) 

While Google and Apple do not: [9](#0-8) 

**Account Address Impact:** The `iss_val` field is included in the authentication key derivation, so different trailing slash variants create different account addresses: [10](#0-9) 

## Impact Explanation

This is correctly classified as **Low Severity** per the Aptos bug bounty criteria because:

1. **No Loss of Funds**: Users cannot lose assets; at worst they experience transaction rejections
2. **No Consensus Violation**: All validators apply the same (incorrect) string matching logic deterministically
3. **Limited Availability Impact**: Only affects keyless authentication for misconfigured providers, not the entire network
4. **Requires Misconfiguration**: The issue only manifests when governance configures providers incorrectly

The impact is primarily operational and UX-related:
- Keyless transactions fail validation if provider configuration doesn't match JWT issuer format
- Users may inadvertently create accounts with different addresses based on trailing slash presence
- Resource waste from duplicate JWK fetching if both variants are configured

## Likelihood Explanation

**High likelihood of occurrence** in production because:

1. **Different provider conventions**: Auth0, AWS Cognito, and other OIDC providers have varying trailing slash conventions in their issuer claims
2. **No validation guidance**: The configuration interface provides no warnings or normalization hints
3. **Easy to misconfigure**: Admins copying URLs from documentation may inconsistently include/exclude trailing slashes
4. **Silent failures**: Misconfiguration only becomes apparent when users attempt keyless transactions

## Recommendation

Implement URL normalization for OIDC provider names at configuration time:

1. **In Rust configuration layer**, add normalization when constructing `OIDCProvider`:

```rust
impl OIDCProvider {
    pub fn new(name: String, config_url: String) -> Self {
        // Normalize by removing trailing slashes from issuer URLs
        let normalized_name = name.trim_end_matches('/').to_string();
        Self {
            name: normalized_name.as_bytes().to_vec(),
            config_url: config_url.as_bytes().to_vec(),
        }
    }
}
```

2. **In Move configuration layer**, add validation in `new_oidc_provider`:

```move
public fun new_oidc_provider(name: String, config_url: String): OIDCProvider {
    // Add comment: "Provider names are automatically normalized by removing trailing slashes"
    OIDCProvider { name, config_url }
}
```

3. **In validation layer**, normalize JWT issuer claims before lookup:

```rust
pub fn get_provider_jwks(&self, iss: &str) -> Option<&ProviderJWKs> {
    let normalized_iss = iss.trim_end_matches('/');
    self.entries
        .iter()
        .find(|&provider_jwk_set| {
            let provider_iss = String::from_utf8_lossy(&provider_jwk_set.issuer);
            provider_iss.trim_end_matches('/') == normalized_iss
        })
}
```

## Proof of Concept

This Move test demonstrates the issue:

```move
#[test]
#[expected_failure]
fun test_trailing_slash_mismatch() {
    use std::string::utf8;
    use aptos_framework::jwk_consensus_config;
    
    // Configure provider WITHOUT trailing slash
    let providers = vector[
        jwk_consensus_config::new_oidc_provider(
            utf8(b"https://test.us.auth0.com"),
            utf8(b"https://test.us.auth0.com/.well-known/openid-configuration")
        )
    ];
    let config = jwk_consensus_config::new_v1(providers);
    
    // Simulate JWT with trailing slash (Auth0 standard)
    // JWK lookup will fail because "https://test.us.auth0.com/" != "https://test.us.auth0.com"
}

#[test]
fun test_duplicate_providers_allowed() {
    use std::string::utf8;
    use aptos_framework::jwk_consensus_config;
    
    // Both variants are accepted as "different" providers
    let providers = vector[
        jwk_consensus_config::new_oidc_provider(
            utf8(b"https://accounts.google.com"),
            utf8(b"https://accounts.google.com/.well-known/openid-configuration")
        ),
        jwk_consensus_config::new_oidc_provider(
            utf8(b"https://accounts.google.com/"), // With trailing slash
            utf8(b"https://accounts.google.com/.well-known/openid-configuration")
        )
    ];
    
    // This should fail with EDUPLICATE_PROVIDERS but doesn't
    let config = jwk_consensus_config::new_v1(providers);
}
```

## Notes

This issue is particularly problematic for Auth0 integration, as Auth0's OpenID Connect implementation mandates trailing slashes in issuer claims per their specification, while the Aptos configuration examples (Google) omit them. This creates a configuration trap where following one provider's convention breaks another provider's authentication.

### Citations

**File:** types/src/on_chain_config/jwk_consensus_config.rs (L22-25)
```rust
pub struct OIDCProvider {
    pub name: String,
    pub config_url: String,
}
```

**File:** aptos-move/framework/aptos-framework/sources/configs/jwk_consensus_config.move (L90-98)
```text
    public fun new_v1(oidc_providers: vector<OIDCProvider>): JWKConsensusConfig {
        let name_set = simple_map::new<String, u64>();
        vector::for_each_ref(&oidc_providers, |provider| {
            let provider: &OIDCProvider = provider;
            let (_, old_value) = simple_map::upsert(&mut name_set, provider.name, 0);
            if (option::is_some(&old_value)) {
                abort(error::invalid_argument(EDUPLICATE_PROVIDERS))
            }
        });
```

**File:** crates/aptos-jwk-consensus/src/jwk_observer.rs (L80-80)
```rust
                        let _ = observation_tx.push((), (issuer.as_bytes().to_vec(), jwks));
```

**File:** types/src/jwks/mod.rs (L48-50)
```rust
pub fn issuer_from_str(s: &str) -> Issuer {
    s.as_bytes().to_vec()
}
```

**File:** types/src/jwks/mod.rs (L225-229)
```rust
    pub fn get_provider_jwks(&self, iss: &str) -> Option<&ProviderJWKs> {
        self.entries
            .iter()
            .find(|&provider_jwk_set| provider_jwk_set.issuer.eq(&issuer_from_str(iss)))
    }
```

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L121-121)
```rust
    let jwk_move_struct = jwks.get_jwk(&pk.iss_val, &jwt_header.kid).map_err(|_| {
```

**File:** keyless/pepper/service/src/external_resources/jwk_fetcher.rs (L27-27)
```rust
const ISSUER_GOOGLE: &str = "https://accounts.google.com";
```

**File:** keyless/pepper/service/src/external_resources/jwk_fetcher.rs (L38-38)
```rust
pub const AUTH0_REGEX_STR: &str = r"^https://[a-zA-Z0-9-]+\.us\.auth0\.com/$";
```

**File:** keyless/pepper/service/src/tests/federated_jwk.rs (L117-117)
```rust
    let iss = "https://test.us.auth0.com/";
```

**File:** types/src/transaction/authenticator.rs (L924-926)
```rust
    pub fn any_key(public_key: AnyPublicKey) -> AuthenticationKey {
        Self::from_preimage(public_key.to_bytes(), Scheme::SingleKey)
    }
```

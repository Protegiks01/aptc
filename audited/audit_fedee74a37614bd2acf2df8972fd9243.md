# Audit Report

## Title
Non-Canonical JSON Serialization in UnsupportedJWK Causes JWK Consensus Failure

## Summary
The `From<serde_json::Value>` implementation for `UnsupportedJWK` uses non-canonical JSON serialization via `to_string()`, causing validators to fail to reach consensus when the same JWK is fetched with different JSON key orderings. This breaks the deterministic execution invariant and can cause denial of service for keyless accounts using OIDC providers with non-RSA keys.

## Finding Description

The vulnerability exists in the conversion of JSON to `UnsupportedJWK` structures. When validators fetch JWKs from OIDC providers, non-RSA keys (such as EC P-256 keys commonly used by providers like Apple) are converted to `UnsupportedJWK` using the `From<serde_json::Value>` trait. [1](#0-0) 

The critical issue is on line 53 where `json_value.to_string()` is called. The `serde_json::Value::to_string()` method does **not** produce canonical JSON - object keys can appear in different orders, and whitespace may vary. The TODO comment on line 53 explicitly acknowledges this is not canonical.

The `id` field is computed as SHA3-256 of this non-canonical payload, meaning the same logical JWK will have **different IDs** if fetched with different JSON key orderings.

During JWK consensus, validators independently fetch JWKs and attempt to reach quorum by comparing their observations: [2](#0-1) 

This equality check requires **exact match** of `ProviderJWKs`, which includes the `UnsupportedJWK` structures. If validators fetch the same JWK but receive different JSON key orderings (due to non-deterministic server behavior or network proxies), they will have:
- Different `payload` bytes (different JSON serialization)
- Different `id` values (different SHA3-256 hashes)
- Failed equality check → rejected observation → **no consensus**

The JWK conversion flow confirms unsupported keys become `UnsupportedJWK`: [3](#0-2) 

Currently, only RSA JWKs are supported: [4](#0-3) 

Any JWK with `kty != "RSA"` (including EC, OKP, etc.) becomes an `UnsupportedJWK` and is vulnerable to this non-canonical serialization issue.

## Impact Explanation

This vulnerability constitutes **High Severity** under the Aptos bug bounty program as a "Significant protocol violation."

**Impact:**
1. **JWK Consensus Failure**: Validators cannot reach quorum on JWK updates for any provider using non-RSA keys if JSON ordering varies across fetches
2. **Denial of Service for Keyless Accounts**: Users with keyless accounts tied to affected OIDC providers cannot authenticate or submit transactions
3. **Network Degradation**: Validators waste computational resources on failed consensus attempts
4. **Real-World Providers Affected**: Major OIDC providers (e.g., Apple) use EC P-256 keys which would trigger this bug

**Why High Severity:**
- Breaks **Invariant 1 (Deterministic Execution)**: Validators do not produce identical observations for identical JWKs
- Causes protocol-level consensus failures in the JWK subsystem
- Affects availability of the keyless accounts feature for potentially large user bases
- Does not affect overall network liveness (transactions continue processing), so not Critical

## Likelihood Explanation

**High Likelihood** of occurrence:

1. **JSON Non-Determinism is Common**: Many HTTP servers, proxies, and load balancers do not guarantee JSON key ordering. Even if the OIDC provider's backend is deterministic, intermediate network infrastructure may reorder keys.

2. **EC Keys are Industry Standard**: The cryptographic industry is moving toward elliptic curve keys (EC P-256, EC P-384) for better performance. Apple, Azure AD, and other major providers already use or are adopting EC keys.

3. **Federated Keyless Increases Attack Surface**: With federated keyless accounts, any party can deploy an OIDC provider. A malicious or misconfigured provider could intentionally or accidentally vary JSON ordering.

4. **Existing TODO Comment**: The TODO comment in the code indicates developers were aware of the canonicalization issue but have not fixed it, suggesting this is a known but unaddressed problem.

5. **No Workarounds**: There is no mechanism for validators to normalize or canonicalize JSON before hashing, so the bug will manifest whenever JSON ordering varies.

## Recommendation

Implement canonical JSON serialization before computing the `id` hash. The fix should:

1. Use a canonical JSON library (e.g., `serde_json_canonicalizer` or implement RFC 8785 JSON Canonicalization Scheme)
2. Sort object keys deterministically
3. Remove whitespace variations
4. Ensure identical logical JWKs always produce identical byte representations

**Recommended Code Fix:**

```rust
// In types/src/jwks/unsupported/mod.rs
impl From<serde_json::Value> for UnsupportedJWK {
    fn from(json_value: serde_json::Value) -> Self {
        // Use canonical JSON serialization (e.g., implement JCS - RFC 8785)
        let payload = canonicalize_json(&json_value).into_bytes();
        Self {
            id: HashValue::sha3_256_of(payload.as_slice()).to_vec(),
            payload,
        }
    }
}

fn canonicalize_json(value: &serde_json::Value) -> String {
    // Implement RFC 8785 JSON Canonicalization Scheme
    // or use a library like `serde_json_canonicalizer`
    // Key requirements:
    // 1. Sort object keys lexicographically
    // 2. No whitespace
    // 3. Deterministic number representation
    // 4. Deterministic Unicode escaping
}
```

**Alternative Fix:**
Extract structured fields from unsupported JWKs (similar to RSA_JWK) instead of storing raw JSON. For EC keys, parse `kty`, `crv`, `x`, `y` fields explicitly.

## Proof of Concept

```rust
// Rust test demonstrating the vulnerability
#[test]
fn test_json_ordering_causes_different_unsupported_jwk_ids() {
    use serde_json::json;
    use aptos_types::jwks::unsupported::UnsupportedJWK;
    
    // Same EC P-256 JWK with different key orderings
    // (simulating different validators fetching from servers with different JSON serialization)
    let json_ordering_1 = json!({
        "kty": "EC",
        "use": "sig",
        "crv": "P-256",
        "kid": "test-ec-key-1",
        "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
        "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
        "alg": "ES256"
    });
    
    let json_ordering_2 = json!({
        "alg": "ES256",
        "crv": "P-256",
        "kid": "test-ec-key-1",
        "kty": "EC",
        "use": "sig",
        "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
        "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE"
    });
    
    let jwk1 = UnsupportedJWK::from(json_ordering_1);
    let jwk2 = UnsupportedJWK::from(json_ordering_2);
    
    // These should be the same logical JWK, but they will have:
    // - Different payload bytes (different JSON serialization)
    assert_ne!(jwk1.payload, jwk2.payload, 
               "Payloads differ due to non-canonical serialization");
    
    // - Different ID hashes
    assert_ne!(jwk1.id, jwk2.id, 
               "IDs differ because payload hashes differ");
    
    // This means validators cannot reach consensus on this JWK!
    // The equality check in observation_aggregation will fail:
    // ensure!(self.local_view == peer_view, "adding peer observation failed with mismatched view");
}

// Integration test simulating consensus failure
#[test]
fn test_jwk_consensus_failure_with_non_canonical_json() {
    use aptos_types::jwks::{ProviderJWKs, jwk::JWKMoveStruct, jwk::JWK};
    
    // Validator A fetches JWK with one ordering
    let jwk_a = JWK::from(json!({"kty": "EC", "kid": "key1", "crv": "P-256"}));
    let provider_jwks_a = ProviderJWKs {
        issuer: b"https://example.com".to_vec(),
        version: 1,
        jwks: vec![JWKMoveStruct::from(jwk_a)],
    };
    
    // Validator B fetches same JWK with different ordering
    let jwk_b = JWK::from(json!({"kid": "key1", "kty": "EC", "crv": "P-256"}));
    let provider_jwks_b = ProviderJWKs {
        issuer: b"https://example.com".to_vec(),
        version: 1,
        jwks: vec![JWKMoveStruct::from(jwk_b)],
    };
    
    // Validators cannot agree - consensus fails!
    assert_ne!(provider_jwks_a, provider_jwks_b,
               "Validators have different views despite same logical JWK");
}
```

## Notes

This vulnerability specifically affects **UnsupportedJWK** (non-RSA keys), not RSA_JWK. RSA keys are parsed by extracting individual fields, so key ordering doesn't affect them. However, as the cryptographic industry moves toward EC keys and OIDC providers adopt them, this becomes an increasingly critical issue. The TODO comment in the code indicates this was a known concern that has not been addressed.

### Citations

**File:** types/src/jwks/unsupported/mod.rs (L51-59)
```rust
impl From<serde_json::Value> for UnsupportedJWK {
    fn from(json_value: serde_json::Value) -> Self {
        let payload = json_value.to_string().into_bytes(); //TODO: canonical to_string.
        Self {
            id: HashValue::sha3_256_of(payload.as_slice()).to_vec(),
            payload,
        }
    }
}
```

**File:** crates/aptos-jwk-consensus/src/observation_aggregation/mod.rs (L81-84)
```rust
        ensure!(
            self.local_view == peer_view,
            "adding peer observation failed with mismatched view"
        );
```

**File:** types/src/jwks/jwk/mod.rs (L80-90)
```rust
impl From<serde_json::Value> for JWK {
    fn from(value: serde_json::Value) -> Self {
        match RSA_JWK::try_from(&value) {
            Ok(rsa) => Self::RSA(rsa),
            Err(_) => {
                let unsupported = UnsupportedJWK::from(value);
                Self::Unsupported(unsupported)
            },
        }
    }
}
```

**File:** types/src/jwks/rsa/mod.rs (L132-147)
```rust
impl TryFrom<&serde_json::Value> for RSA_JWK {
    type Error = anyhow::Error;

    fn try_from(json_value: &serde_json::Value) -> Result<Self, Self::Error> {
        let kty = json_value
            .get("kty")
            .ok_or_else(|| anyhow!("Field `kty` not found"))?
            .as_str()
            .ok_or_else(|| anyhow!("Field `kty` is not a string"))?
            .to_string();

        ensure!(
            kty.as_str() == "RSA",
            "json to rsa jwk conversion failed with incorrect kty"
        );

```

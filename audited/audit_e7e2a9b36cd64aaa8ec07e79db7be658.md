# Audit Report

## Title
Non-Canonical JSON Serialization in UnsupportedJWK Causing Consensus Divergence

## Summary
The `UnsupportedJWK::from(serde_json::Value)` implementation uses non-canonical JSON serialization via `json_value.to_string()`, causing different validators to create divergent `UnsupportedJWK` objects when OIDC providers send JSON with varying field orders. This breaks consensus for non-RSA JWK updates. [1](#0-0) 

## Finding Description
The vulnerability exists in the conversion path from external OIDC provider JSON responses to consensus-critical `UnsupportedJWK` structures. When validators independently fetch JWKs from OIDC providers:

1. Each validator fetches JWK JSON independently via HTTP: [2](#0-1) 

2. JSON responses are parsed into `serde_json::Value` and converted to `JWK`: [3](#0-2) 

3. For non-RSA JWKs (EC keys, EdDSA, or malformed), the fallback creates `UnsupportedJWK` using `to_string()`: [1](#0-0) 

The TODO comment explicitly acknowledges this issue. While `serde_json` uses `preserve_order`: [4](#0-3) 

This preserves **insertion order**, not a canonical order. Different HTTP responses with different field orders produce different string representations, leading to:
- Different `payload` fields  
- Different `id` fields (hash of payload)
- Different BCS serializations when wrapped in `JWKMoveStruct`

During consensus, validators sign `ProviderJWKs` containing these divergent `JWKMoveStruct` objects: [5](#0-4) 

The multi-signature verification computes signatures over the BCS-serialized `ProviderJWKs`, which includes the `UnsupportedJWK` payload. Different payloads → different signatures → consensus failure.

## Impact Explanation
**Critical Severity** - This breaks **Invariant #2: Consensus Safety**. Validators cannot reach agreement on non-RSA JWK updates, causing:

- **Consensus Failure**: Validators sign different messages due to divergent BCS serializations
- **Protocol Liveness Loss**: JWK updates cannot be certified when 2/3+ validators observe different representations
- **DoS Vector**: An attacker controlling or intercepting OIDC provider responses can deliberately send different JSON field orders to different validators, preventing consensus
- **Keyless Authentication Disruption**: Inability to update non-RSA JWKs breaks keyless authentication for affected OIDC providers

This violates deterministic execution (Invariant #1) - identical semantic JWKs should produce identical state transitions.

## Likelihood Explanation
**High Likelihood** if:
- OIDC providers use non-RSA keys (EC keys are increasingly common for OIDC)
- HTTP responses naturally vary in field order due to implementation details
- No server-side guarantees on JSON field ordering

**Medium Likelihood** with:
- MITM attackers manipulating responses to different validators
- Malicious OIDC providers deliberately varying responses

**Current Mitigation**: Most OIDC providers use RSA keys, which parse successfully via `RSA_JWK::try_from` and avoid the `UnsupportedJWK` path. However, this is not a security guarantee.

## Recommendation
Implement canonical JSON serialization for `UnsupportedJWK::from`:

```rust
impl From<serde_json::Value> for UnsupportedJWK {
    fn from(json_value: serde_json::Value) -> Self {
        // Serialize to canonical JSON (sorted keys, no whitespace)
        let payload = serde_json::to_vec(&normalize_json(&json_value))
            .expect("JSON serialization should not fail");
        Self {
            id: HashValue::sha3_256_of(payload.as_slice()).to_vec(),
            payload,
        }
    }
}

fn normalize_json(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut sorted: BTreeMap<String, serde_json::Value> = map
                .iter()
                .map(|(k, v)| (k.clone(), normalize_json(v)))
                .collect();
            serde_json::Value::Object(sorted.into_iter().collect())
        },
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(normalize_json).collect())
        },
        other => other.clone(),
    }
}
```

Use `BTreeMap` for canonical key ordering and `serde_json::to_vec` for compact, deterministic serialization.

## Proof of Concept
```rust
#[test]
fn test_unsupported_jwk_non_canonical_json() {
    use serde_json::json;
    
    // Same logical JWK with different field orders
    let json1 = json!({"kty": "EC", "kid": "key1", "crv": "P-256", "x": "abc", "y": "def"});
    let json2 = json!({"kid": "key1", "kty": "EC", "x": "abc", "y": "def", "crv": "P-256"});
    
    let jwk1 = UnsupportedJWK::from(json1);
    let jwk2 = UnsupportedJWK::from(json2);
    
    // BUG: Same semantic JWK produces different objects
    assert_ne!(jwk1.payload, jwk2.payload); // Different payloads
    assert_ne!(jwk1.id, jwk2.id); // Different IDs
    
    // This causes different BCS serializations
    let jwk_move1 = JWKMoveStruct::from(JWK::Unsupported(jwk1));
    let jwk_move2 = JWKMoveStruct::from(JWK::Unsupported(jwk2));
    
    let bcs1 = bcs::to_bytes(&jwk_move1).unwrap();
    let bcs2 = bcs::to_bytes(&jwk_move2).unwrap();
    
    assert_ne!(bcs1, bcs2); // CONSENSUS FAILURE: Different serializations
}
```

## Notes
This vulnerability is distinct from the original question about Rust compiler versions. The **answer to the specific question posed** is **NO** - Rust compiler versions and optimization levels do NOT cause different BCS serializations of JWKMoveStruct. BCS is deterministic across compilation environments.

However, this investigation uncovered a **separate, valid consensus vulnerability** in the runtime handling of OIDC provider responses, explicitly marked with a TODO comment requiring canonical serialization.

### Citations

**File:** types/src/jwks/unsupported/mod.rs (L51-58)
```rust
impl From<serde_json::Value> for UnsupportedJWK {
    fn from(json_value: serde_json::Value) -> Self {
        let payload = json_value.to_string().into_bytes(); //TODO: canonical to_string.
        Self {
            id: HashValue::sha3_256_of(payload.as_slice()).to_vec(),
            payload,
        }
    }
```

**File:** crates/jwk-utils/src/lib.rs (L25-36)
```rust
pub async fn fetch_jwks_from_jwks_uri(
    my_addr: Option<AccountAddress>,
    jwks_uri: &str,
) -> Result<Vec<JWK>> {
    let client = reqwest::Client::new();
    let mut request_builder = client.get(jwks_uri);
    if let Some(addr) = my_addr {
        request_builder = request_builder.header(COOKIE, addr.to_hex());
    }
    let JWKsResponse { keys } = request_builder.send().await?.json().await?;
    let jwks = keys.into_iter().map(JWK::from).collect();
    Ok(jwks)
```

**File:** types/src/jwks/jwk/mod.rs (L80-89)
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
```

**File:** Cargo.toml (L789-792)
```text
serde_json = { version = "1.0.81", features = [
    "preserve_order",
    "arbitrary_precision",
] } # Note: arbitrary_precision is required to parse u256 in JSON
```

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L139-142)
```rust
        // Verify multi-sig.
        verifier
            .verify_multi_signatures(&observed, &multi_sig)
            .map_err(|_| Expected(MultiSigVerificationFailed))?;
```

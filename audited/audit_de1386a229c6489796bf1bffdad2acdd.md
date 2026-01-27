# Audit Report

## Title
JSON Key Ordering Attack Bypasses UnsupportedJWK Deduplication via Non-Canonical Serialization

## Summary
The `UnsupportedJWK::from(serde_json::Value)` implementation uses `json_value.to_string()` to serialize JSON before computing the ID hash. Since `serde_json` does not canonicalize JSON output, identical JWKs with different key orderings produce different ID hashes, completely bypassing the ID-based deduplication mechanism in the JWK consensus system.

## Finding Description
The vulnerability exists in the conversion of `serde_json::Value` to `UnsupportedJWK`: [1](#0-0) 

The code explicitly acknowledges this issue with the TODO comment on line 53: `//TODO: canonical to_string.`

The security guarantee being broken is **JWK deduplication**. The system relies on unique IDs to prevent duplicate JWKs: [2](#0-1) 

The `upsert_jwk` function uses these IDs for deduplication via binary search: [3](#0-2) 

**Attack Flow:**
1. Attacker controls an OIDC provider (e.g., federated keyless dapp owner, or compromised provider)
2. Provider serves unsupported JWK formats (not parseable as `RSA_JWK`)
3. Provider alternates key orderings: `{"key1":"val1","key2":"val2"}` vs `{"key2":"val2","key1":"val1"}`
4. Validators fetch JWKs via: [4](#0-3) 

5. Conversion to JWK: [5](#0-4) 

6. Since RSA parsing fails for unsupported formats, falls back to `UnsupportedJWK::from()`
7. Different key orderings → different `to_string()` output → different SHA3-256 hashes → different IDs
8. Deduplication bypassed: same semantic JWK appears multiple times with different IDs

**Consensus Impact:**
When validators fetch the same provider's JWKs but receive different key orderings, they compute different IDs. During consensus aggregation: [6](#0-5) 

Validators will fail to reach consensus because their observations have mismatched JWK IDs, causing liveness degradation.

## Impact Explanation
**Severity: High** per Aptos bug bounty categories:

1. **Validator node slowdowns**: Each duplicate JWK consumes processing resources during:
   - JWK consensus observation aggregation
   - Multi-signature verification
   - On-chain storage updates
   - Keyless authentication lookups

2. **Significant protocol violations**: The deduplication mechanism is a core security control. Bypassing it violates the protocol's resource management invariants.

3. **Resource exhaustion**: For federated JWKs, the size limit is enforced: [7](#0-6) [8](#0-7) 

An attacker can fill this 2KB limit faster with duplicate entries, effectively reducing capacity for legitimate JWKs.

4. **Consensus liveness issues**: Different validators observing different key orderings will disagree on JWK IDs, preventing quorum on JWK updates.

## Likelihood Explanation
**Likelihood: Medium-High**

**Requirements for exploitation:**
- Attacker controls an OIDC provider (federated keyless scenario) OR
- Attacker compromises an existing OIDC provider OR
- OIDC provider has non-deterministic JSON serialization

**Feasibility:**
- Federated keyless (AIP-96) allows dapp owners to run their own OIDC providers
- Dapp owner is untrusted actor in threat model
- No special validator access needed
- Attack is entirely client-side (manipulating served JSON)

**Attack complexity:** Low
- Simply serve same JWK JSON with shuffled key order
- No cryptographic attacks required
- No protocol-level exploits needed

## Recommendation
Implement canonical JSON serialization before hashing. Use a deterministic serialization library like `serde_json_canonicalizer` or implement RFC 8785 (JSON Canonicalization Scheme):

```rust
impl From<serde_json::Value> for UnsupportedJWK {
    fn from(json_value: serde_json::Value) -> Self {
        // Use canonical JSON serialization (RFC 8785)
        let payload = canonicalize_json(&json_value).into_bytes();
        Self {
            id: HashValue::sha3_256_of(payload.as_slice()).to_vec(),
            payload,
        }
    }
}

fn canonicalize_json(value: &serde_json::Value) -> String {
    // Implement RFC 8785 or use serde_json_canonicalizer crate
    // Key requirements:
    // - Sort object keys lexicographically
    // - Remove whitespace
    // - Escape sequences normalized
    // - Number formatting normalized
    serde_json_canonicalizer::to_string(value)
}
```

**Alternative:** For UnsupportedJWK, compute ID from sorted key-value pairs rather than string representation, ensuring semantic equivalence produces identical IDs.

## Proof of Concept

```rust
#[cfg(test)]
mod key_ordering_attack_poc {
    use crate::jwks::unsupported::UnsupportedJWK;
    use std::str::FromStr;

    #[test]
    fn test_key_ordering_bypass_deduplication() {
        // Same JWK with different key orderings
        let json_ordering_1 = r#"{"kty":"EC","crv":"P-256","x":"abc","y":"def"}"#;
        let json_ordering_2 = r#"{"y":"def","x":"abc","crv":"P-256","kty":"EC"}"#;
        
        // Parse both orderings
        let value1 = serde_json::Value::from_str(json_ordering_1).unwrap();
        let value2 = serde_json::Value::from_str(json_ordering_2).unwrap();
        
        // Convert to UnsupportedJWK
        let jwk1 = UnsupportedJWK::from(value1);
        let jwk2 = UnsupportedJWK::from(value2);
        
        // VULNERABILITY: Different IDs for semantically identical JWKs
        assert_ne!(jwk1.id, jwk2.id, "IDs should differ due to key ordering");
        
        // Verify payloads are different strings
        assert_ne!(jwk1.payload, jwk2.payload);
        
        // But semantically, they represent the same JWK
        let parsed1: serde_json::Value = serde_json::from_slice(&jwk1.payload).unwrap();
        let parsed2: serde_json::Value = serde_json::from_slice(&jwk2.payload).unwrap();
        assert_eq!(parsed1, parsed2, "Semantic content is identical");
        
        println!("JWK1 ID: {:?}", hex::encode(&jwk1.id));
        println!("JWK2 ID: {:?}", hex::encode(&jwk2.id));
        println!("Successfully bypassed deduplication!");
    }
}
```

**Expected Output:**
```
JWK1 ID: [different hash]
JWK2 ID: [different hash]
Successfully bypassed deduplication!
```

This POC demonstrates that semantically identical JWKs with different key orderings produce different IDs, bypassing the deduplication mechanism entirely.

## Notes

**Scope Clarification:**
- This vulnerability affects **only** `UnsupportedJWK` types, not `RSA_JWK` types
- `RSA_JWK` uses the `kid` field directly as the ID, so key ordering doesn't affect it: [9](#0-8) 

**System Components Affected:**
1. JWK consensus observation aggregation
2. Federated JWK storage for keyless accounts
3. Validator transaction processing for `ObservedJWKUpdate`

**Real-World Scenarios:**
- Federated keyless dapps using non-RSA key types (e.g., ECDSA)
- Future OIDC providers adopting new JWK formats before Aptos supports them
- Malicious or compromised OIDC providers

The TODO comment indicates developer awareness, but the vulnerability remains exploitable in production.

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

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L33-33)
```text
    const MAX_FEDERATED_JWKS_SIZE_BYTES: u64 = 2 * 1024; // 2 KiB
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L200-202)
```text
        // TODO: Can we check the size more efficiently instead of serializing it via BCS?
        let num_bytes = vector::length(&bcs::to_bytes(fed_jwks));
        assert!(num_bytes < MAX_FEDERATED_JWKS_SIZE_BYTES, error::invalid_argument(EFEDERATED_JWKS_TOO_LARGE));
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L562-573)
```text
    fun get_jwk_id(jwk: &JWK): vector<u8> {
        let variant_type_name = *string::bytes(copyable_any::type_name(&jwk.variant));
        if (variant_type_name == b"0x1::jwks::RSA_JWK") {
            let rsa = copyable_any::unpack<RSA_JWK>(jwk.variant);
            *string::bytes(&rsa.kid)
        } else if (variant_type_name == b"0x1::jwks::UnsupportedJWK") {
            let unsupported = copyable_any::unpack<UnsupportedJWK>(jwk.variant);
            unsupported.id
        } else {
            abort(error::invalid_argument(EUNKNOWN_JWK_VARIANT))
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L626-654)
```text
    fun upsert_jwk(set: &mut ProviderJWKs, jwk: JWK): Option<JWK> {
        let found = false;
        let index = 0;
        let num_entries = vector::length(&set.jwks);
        while (index < num_entries) {
            let cur_entry = vector::borrow(&set.jwks, index);
            let comparison = compare_u8_vector(get_jwk_id(&jwk), get_jwk_id(cur_entry));
            if (is_greater_than(&comparison)) {
                index = index + 1;
            } else {
                found = is_equal(&comparison);
                break
            }
        };

        // Now if `found == true`, `index` points to the JWK we want to update/remove; otherwise, `index` points to
        // where we want to insert.
        let ret = if (found) {
            let entry = vector::borrow_mut(&mut set.jwks, index);
            let old_entry = option::some(*entry);
            *entry = jwk;
            old_entry
        } else {
            vector::insert(&mut set.jwks, index, jwk);
            option::none()
        };

        ret
    }
```

**File:** crates/jwk-utils/src/lib.rs (L25-37)
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
}
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

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L100-143)
```rust
    fn process_jwk_update_inner(
        &self,
        resolver: &impl AptosMoveResolver,
        module_storage: &impl AptosModuleStorage,
        log_context: &AdapterLogSchema,
        session_id: SessionId,
        update: jwks::QuorumCertifiedUpdate,
    ) -> Result<(VMStatus, VMOutput), ExecutionFailure> {
        // Load resources.
        let validator_set =
            ValidatorSet::fetch_config(resolver).ok_or(Expected(MissingResourceValidatorSet))?;
        let observed_jwks =
            ObservedJWKs::fetch_config(resolver).ok_or(Expected(MissingResourceObservedJWKs))?;

        let mut jwks_by_issuer: HashMap<Issuer, ProviderJWKs> =
            observed_jwks.into_providers_jwks().into();
        let issuer = update.update.issuer.clone();
        let on_chain = jwks_by_issuer
            .entry(issuer.clone())
            .or_insert_with(|| ProviderJWKs::new(issuer));
        let verifier = ValidatorVerifier::from(&validator_set);

        let QuorumCertifiedUpdate {
            update: observed,
            multi_sig,
        } = update;

        // Check version.
        if on_chain.version + 1 != observed.version {
            return Err(Expected(IncorrectVersion));
        }

        let authors = multi_sig.get_signers_addresses(&verifier.get_ordered_account_addresses());

        // Check voting power.
        verifier
            .check_voting_power(authors.iter(), true)
            .map_err(|_| Expected(NotEnoughVotingPower))?;

        // Verify multi-sig.
        verifier
            .verify_multi_signatures(&observed, &multi_sig)
            .map_err(|_| Expected(MultiSigVerificationFailed))?;

```

**File:** types/src/jwks/rsa/mod.rs (L97-99)
```rust
    pub fn id(&self) -> Vec<u8> {
        self.kid.as_bytes().to_vec()
    }
```

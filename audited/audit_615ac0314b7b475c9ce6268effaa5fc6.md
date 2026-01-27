# Audit Report

## Title
DELETE_COMMAND_INDICATOR Spoofing via RSA JWK Modulus Field Enables State Pollution and Targeted DoS

## Summary
An attacker controlling an OIDC provider endpoint can craft a malicious JWK update containing an RSA_JWK where the modulus (`n`) field is set to the DELETE_COMMAND_INDICATOR string ("THIS_IS_A_DELETE_COMMAND"). The delete detection logic only checks for this indicator in `UnsupportedJWK` payloads, not in RSA_JWK fields, allowing the malformed key to bypass validation and be stored on-chain. This causes targeted denial-of-service for keyless authentication and pollutes the on-chain JWK state with invalid data.

## Finding Description
The JWK consensus system uses a special DELETE_COMMAND_INDICATOR constant to represent delete operations in the per-key consensus mode. The delete detection logic is implemented to check if a JWK is an `UnsupportedJWK` variant with its payload field matching this indicator. [1](#0-0) 

When converting from the issuer-level representation back to a key-level update, the code only detects deletes for `UnsupportedJWK` types: [2](#0-1) 

This same pattern is replicated in the Move code: [3](#0-2) 

An attacker controlling an OIDC provider can serve a JWK where the RSA modulus field contains "THIS_IS_A_DELETE_COMMAND". When validators observe this JWK:

1. The `new_rb_request()` function converts the payload to a KeyLevelUpdate [4](#0-3) 

2. The conversion logic sees it's an RSA_JWK (not UnsupportedJWK), so `is_delete` evaluates to `false`

3. The malformed JWK passes consensus validation (which only checks version and signatures) [5](#0-4) 

4. It's stored on-chain as a legitimate RSA key via `upsert_jwk()` [6](#0-5) 

5. Any attempt to use this key for signature verification fails because "THIS_IS_A_DELETE_COMMAND" is not a valid base64-encoded RSA modulus [7](#0-6) 

## Impact Explanation
This vulnerability meets **Medium severity** criteria:

- **State Inconsistency**: Pollutes the on-chain JWK store with invalid RSA keys that violate the design assumption that DELETE_COMMAND_INDICATOR only appears in proper delete operations

- **Targeted DoS**: Breaks keyless authentication for the affected kid, as signature verification will fail when attempting to decode the invalid modulus

- **Design Invariant Violation**: The system expects DELETE_COMMAND_INDICATOR to exclusively signal delete operations, but this allows it to appear in upsert operations, potentially confusing monitoring tools and violating security assumptions

The impact is limited because:
- It doesn't steal funds or break consensus safety
- It affects only the specific kid, not the entire keyless system
- It requires compromising an OIDC provider endpoint

## Likelihood Explanation
**Likelihood: Medium**

The attack requires:
1. Attacker controls or compromises an OIDC provider endpoint that validators observe
2. Validators automatically observe and sign the malformed JWK through normal consensus
3. The update reaches quorum (no special validator collusion required)

This is realistic because:
- OIDC provider compromises occur in practice
- Validators automatically process observed JWKs without manual validation
- No cryptographic breaks or validator insider access required

## Recommendation
Add validation to reject RSA JWKs that contain DELETE_COMMAND_INDICATOR in any field. In the Rust code:

```rust
// In types/src/jwks/mod.rs, modify try_from_issuer_level_repr:
pub fn try_from_issuer_level_repr(repr: &ProviderJWKs) -> anyhow::Result<Self> {
    ensure!(
        repr.jwks.len() == 1,
        "wrapped repr of a key-level update should have exactly 1 jwk"
    );
    let jwk =
        JWK::try_from(&repr.jwks[0]).context("try_from_issuer_level_repr failed on JWK")?;
    
    // Reject RSA JWKs with DELETE_COMMAND_INDICATOR in any field
    if let JWK::RSA(rsa_jwk) = &jwk {
        let indicator = DELETE_COMMAND_INDICATOR;
        ensure!(
            !rsa_jwk.n.contains(indicator) &&
            !rsa_jwk.kid.contains(indicator) &&
            !rsa_jwk.e.contains(indicator),
            "RSA JWK fields must not contain DELETE_COMMAND_INDICATOR"
        );
    }
    
    let base_version = repr
        .version
        .checked_sub(1)
        .context("try_from_issuer_level_repr on version")?;
    Ok(Self {
        issuer: repr.issuer.clone(),
        base_version,
        kid: jwk.id(),
        to_upsert: match jwk {
            JWK::Unsupported(unsupported)
                if unsupported.payload.as_slice() == DELETE_COMMAND_INDICATOR.as_bytes() =>
            {
                None
            },
            _ => Some(jwk),
        },
    })
}
```

## Proof of Concept
```rust
// Add to types/src/jwks/mod.rs tests
#[test]
fn reject_rsa_jwk_with_delete_indicator_in_modulus() {
    let issuer_level = ProviderJWKs {
        issuer: issuer_from_str("issuer-alice"),
        version: 1,
        jwks: vec![JWKMoveStruct::from(JWK::RSA(RSA_JWK::new_256_aqab(
            "kid123",
            DELETE_COMMAND_INDICATOR, // Malicious modulus
        )))],
    };
    
    // Should fail because RSA modulus contains DELETE_COMMAND_INDICATOR
    let result = KeyLevelUpdate::try_from_issuer_level_repr(&issuer_level);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("DELETE_COMMAND_INDICATOR"));
}
```

## Notes
The vulnerability exploits the type-specific nature of the delete detection logic, which assumes DELETE_COMMAND_INDICATOR will only appear in `UnsupportedJWK` payloads. By embedding it in an RSA_JWK field, an attacker bypasses this check while maintaining the string's presence in on-chain data, violating the security invariant and enabling state pollution attacks.

### Citations

**File:** types/src/jwks/mod.rs (L320-321)
```rust
/// we put a `RSA_JWK` and set `n` to be this special value.
pub const DELETE_COMMAND_INDICATOR: &str = "THIS_IS_A_DELETE_COMMAND";
```

**File:** types/src/jwks/mod.rs (L375-382)
```rust
            to_upsert: match jwk {
                JWK::Unsupported(unsupported)
                    if unsupported.payload.as_slice() == DELETE_COMMAND_INDICATOR.as_bytes() =>
                {
                    None
                },
                _ => Some(jwk),
            },
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L481-486)
```text
                    let is_delete = if (variant_type_name == b"0x1::jwks::UnsupportedJWK") {
                        let repr = copyable_any::unpack<UnsupportedJWK>(jwk.variant);
                        &repr.payload == &DELETE_COMMAND_INDICATOR
                    } else {
                        false
                    };
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L487-491)
```text
                    if (is_delete) {
                        remove_jwk(&mut cur_issuer_jwks, get_jwk_id(&jwk));
                    } else {
                        upsert_jwk(&mut cur_issuer_jwks, jwk);
                    }
```

**File:** crates/aptos-jwk-consensus/src/mode/per_key.rs (L32-40)
```rust
    fn new_rb_request(
        epoch: u64,
        payload: &ProviderJWKs,
    ) -> anyhow::Result<ObservedKeyLevelUpdateRequest> {
        let KeyLevelUpdate { issuer, kid, .. } =
            KeyLevelUpdate::try_from_issuer_level_repr(payload)
                .context("new_rb_request failed with repr translation")?;
        Ok(ObservedKeyLevelUpdateRequest { epoch, issuer, kid })
    }
```

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L127-142)
```rust
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

**File:** types/src/jwks/rsa/mod.rs (L89-95)
```rust
    pub fn verify_signature_without_exp_check(&self, jwt_token: &str) -> Result<TokenData<Claims>> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;
        let key = &DecodingKey::from_rsa_components(&self.n, &self.e)?;
        let claims = jsonwebtoken::decode::<Claims>(jwt_token, key, &validation)?;
        Ok(claims)
    }
```

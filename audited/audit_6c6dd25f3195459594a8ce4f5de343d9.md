# Audit Report

## Title
Lack of Input Validation for `epk_blinder` in Keyless OpenID Signatures Allows Signature Malleability

## Summary
The `OpenIdSig` struct accepts an `epk_blinder` field as a variable-length `Vec<u8>` without validating that it has the expected size of 31 bytes. When passed to `pack_bytes_to_one_scalar()`, empty or undersized byte arrays are silently accepted and converted to field elements, with empty arrays mapping to `Fr(0)`. This allows attackers to create multiple non-canonical representations of the same signature, violating cryptographic uniqueness principles.

## Finding Description

The `pack_bytes_to_one_scalar()` function in the Poseidon BN254 keyless cryptography module only validates that input chunks do not exceed the maximum size, but does not enforce a minimum size: [1](#0-0) 

When an empty byte slice `&[]` is passed to this function, `ark_bn254::Fr::from_le_bytes_mod_order(&[])` interprets it as the integer 0 in little-endian encoding, returning the zero field element `Fr(0)`.

The `OpenIdSig` struct defines `epk_blinder` as a variable-length vector without size constraints: [2](#0-1) 

The expected size is documented as 31 bytes: [3](#0-2) 

However, when `reconstruct_oauth_nonce()` is called during signature verification, it directly passes the unchecked `epk_blinder` to `pack_bytes_to_one_scalar()`: [4](#0-3) 

This creates a vulnerability where multiple different byte representations can produce identical nonces:
- `epk_blinder = []` → `Fr(0)`
- `epk_blinder = [0]` → `Fr(0)`
- `epk_blinder = [0, 0, ..., 0]` (any number of zeros up to 31) → `Fr(0)`

An attacker can craft different `OpenIdSig` instances with varying `epk_blinder` values that all validate against the same JWT from the OIDC provider.

## Impact Explanation

**Medium Severity** - This issue constitutes signature malleability, which violates the **Cryptographic Correctness** invariant requiring secure hash operations and unique representations.

While this does not directly enable unauthorized transactions (the JWT signature from the OIDC provider must still be valid), it creates the following risks:

1. **Transaction deduplication bypass**: Systems that deduplicate transactions based on exact byte matching of signatures could be bypassed
2. **Caching vulnerabilities**: Cache mechanisms using signature bytes as keys could be polluted with multiple entries for the same logical signature
3. **Audit trail corruption**: Multiple representations of the same signature complicate forensic analysis and replay detection
4. **Violation of canonical encoding**: Cryptographic protocols should enforce unique, canonical representations to prevent ambiguity attacks

This falls under "State inconsistencies requiring intervention" as systems built on the assumption of signature uniqueness would need manual intervention to handle malleated signatures.

## Likelihood Explanation

**High Likelihood** - The vulnerability is easily exploitable:

1. **Low attacker requirements**: Any transaction sender can craft a malformed `OpenIdSig` with an empty or undersized `epk_blinder`
2. **No special privileges needed**: Does not require validator access or collusion
3. **Simple exploitation**: The attacker simply needs to serialize an `OpenIdSig` with `epk_blinder = vec![]` or `vec![0]`
4. **No validation barriers**: BCS deserialization accepts variable-length vectors without validation: [5](#0-4) 

The VM validation code checks JWT claims and signatures but never validates `epk_blinder` size: [6](#0-5) 

## Recommendation

Add explicit validation to ensure `epk_blinder` has exactly 31 bytes. This should be enforced at multiple layers:

**1. In `pack_bytes_to_one_scalar()`** - Add minimum size validation:
```rust
pub fn pack_bytes_to_one_scalar(chunk: &[u8]) -> anyhow::Result<ark_bn254::Fr> {
    if chunk.len() != BYTES_PACKED_PER_SCALAR {
        bail!(
            "Chunk must be exactly {} bytes. Was given {} bytes.",
            BYTES_PACKED_PER_SCALAR,
            chunk.len(),
        );
    }
    let fr = ark_bn254::Fr::from_le_bytes_mod_order(chunk);
    Ok(fr)
}
```

**2. In `OpenIdSig` validation** - Add explicit check in `verify_jwt_claims()`:
```rust
pub fn verify_jwt_claims(...) -> anyhow::Result<()> {
    ensure!(
        self.epk_blinder.len() == Self::EPK_BLINDER_NUM_BYTES,
        "epk_blinder must be exactly {} bytes, got {}",
        Self::EPK_BLINDER_NUM_BYTES,
        self.epk_blinder.len()
    );
    // ... rest of validation
}
```

**3. In struct definition** - Consider changing to fixed-size array:
```rust
pub struct OpenIdSig {
    #[serde(with = "serde_bytes")]
    pub epk_blinder: [u8; Self::EPK_BLINDER_NUM_BYTES],
    // ... other fields
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_crypto::poseidon_bn254::keyless::pack_bytes_to_one_scalar;
    use ark_ff::Zero;

    #[test]
    fn test_empty_epk_blinder_produces_zero_scalar() {
        // Demonstrates that empty input maps to Fr(0)
        let empty_blinder = vec![];
        let scalar = pack_bytes_to_one_scalar(&empty_blinder).unwrap();
        assert_eq!(scalar, ark_bn254::Fr::zero());
    }

    #[test]
    fn test_signature_malleability_via_epk_blinder() {
        use aptos_types::keyless::{OpenIdSig, Configuration};
        use aptos_types::transaction::authenticator::EphemeralPublicKey;
        
        let config = Configuration::new_for_testing();
        let epk = EphemeralPublicKey::ed25519(/* ... */);
        let exp_date = 1234567890u64;
        
        // Multiple different epk_blinder values that all map to Fr(0)
        let blinder1 = vec![];
        let blinder2 = vec![0];
        let blinder3 = vec![0, 0, 0, 0];
        
        // All produce the same nonce
        let nonce1 = OpenIdSig::reconstruct_oauth_nonce(&blinder1, exp_date, &epk, &config).unwrap();
        let nonce2 = OpenIdSig::reconstruct_oauth_nonce(&blinder2, exp_date, &epk, &config).unwrap();
        let nonce3 = OpenIdSig::reconstruct_oauth_nonce(&blinder3, exp_date, &epk, &config).unwrap();
        
        assert_eq!(nonce1, nonce2);
        assert_eq!(nonce2, nonce3);
        
        // This means multiple OpenIdSig instances with different bytes
        // can validate against the same JWT, violating uniqueness
    }
}
```

## Notes

This vulnerability exists because `pack_bytes_to_one_scalar()` is a public function designed to handle variable-length inputs for general use cases, but when used in the security-critical context of keyless authentication, it lacks necessary input validation. The `epk_blinder` is intended to be a 31-byte random value that blinds the ephemeral public key from OIDC providers, and allowing non-canonical representations undermines the security guarantees of the keyless authentication protocol.

### Citations

**File:** crates/aptos-crypto/src/poseidon_bn254/keyless.rs (L276-286)
```rust
pub fn pack_bytes_to_one_scalar(chunk: &[u8]) -> anyhow::Result<ark_bn254::Fr> {
    if chunk.len() > BYTES_PACKED_PER_SCALAR {
        bail!(
            "Cannot convert chunk to scalar. Max chunk size is {} bytes. Was given {} bytes.",
            BYTES_PACKED_PER_SCALAR,
            chunk.len(),
        );
    }
    let fr = ark_bn254::Fr::from_le_bytes_mod_order(chunk);
    Ok(fr)
}
```

**File:** types/src/keyless/openid_sig.rs (L22-38)
```rust
pub struct OpenIdSig {
    /// The decoded bytes of the JWS signature in the JWT (<https://datatracker.ietf.org/doc/html/rfc7515#section-3>)
    #[serde(with = "serde_bytes")]
    pub jwt_sig: Vec<u8>,
    /// The decoded/plaintext JSON payload of the JWT (<https://datatracker.ietf.org/doc/html/rfc7519#section-3>)
    pub jwt_payload_json: String,
    /// The name of the key in the claim that maps to the user identifier; e.g., "sub" or "email"
    pub uid_key: String,
    /// The random value used to obfuscate the EPK from OIDC providers in the nonce field
    #[serde(with = "serde_bytes")]
    pub epk_blinder: Vec<u8>,
    /// The privacy-preserving value used to calculate the identity commitment. It is typically uniquely derived from `(iss, client_id, uid_key, uid_val)`.
    pub pepper: Pepper,
    /// When an override aud_val is used, the signature needs to contain the aud_val committed in the
    /// IDC, since the JWT will contain the override.
    pub idc_aud_val: Option<String>,
}
```

**File:** types/src/keyless/openid_sig.rs (L40-43)
```rust
impl OpenIdSig {
    /// The size of the blinding factor used to compute the nonce commitment to the EPK and expiration
    /// date. This can be upgraded, if the OAuth nonce reconstruction is upgraded carefully.
    pub const EPK_BLINDER_NUM_BYTES: usize = poseidon_bn254::keyless::BYTES_PACKED_PER_SCALAR;
```

**File:** types/src/keyless/openid_sig.rs (L141-159)
```rust
    pub fn reconstruct_oauth_nonce(
        epk_blinder: &[u8],
        exp_timestamp_secs: u64,
        epk: &EphemeralPublicKey,
        config: &Configuration,
    ) -> anyhow::Result<String> {
        let mut frs = poseidon_bn254::keyless::pad_and_pack_bytes_to_scalars_with_len(
            epk.to_bytes().as_slice(),
            config.max_commited_epk_bytes as usize,
        )?;

        frs.push(Fr::from(exp_timestamp_secs));
        frs.push(poseidon_bn254::keyless::pack_bytes_to_one_scalar(
            epk_blinder,
        )?);

        let nonce_fr = poseidon_bn254::hash_scalars(frs)?;
        Ok(nonce_fr.to_string())
    }
```

**File:** types/src/keyless/openid_sig.rs (L162-168)
```rust
impl TryFrom<&[u8]> for OpenIdSig {
    type Error = CryptoMaterialError;

    fn try_from(bytes: &[u8]) -> Result<Self, CryptoMaterialError> {
        bcs::from_bytes::<OpenIdSig>(bytes).map_err(|_e| CryptoMaterialError::DeserializationError)
    }
}
```

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L368-398)
```rust
        EphemeralCertificate::OpenIdSig(openid_sig) => {
            match jwk {
                JWK::RSA(rsa_jwk) => {
                    openid_sig
                        .verify_jwt_claims(
                            signature.exp_date_secs,
                            &signature.ephemeral_pubkey,
                            public_key.inner_keyless_pk(),
                            config,
                        )
                        .map_err(|_| invalid_signature!("OpenID claim verification failed"))?;

                    // TODO(OpenIdSig): Implement batch verification for all RSA signatures in
                    //  one TXN.
                    // Note: Individual OpenID RSA signature verification will be fast when the
                    // RSA public exponent is small (e.g., 65537). For the same TXN, batch
                    // verification of all RSA signatures will be even faster even when the
                    // exponent is the same. Across different TXNs, batch verification will be
                    // (1) more difficult to implement and (2) not very beneficial since, when
                    // it fails, bad signature identification will require re-verifying all
                    // signatures assuming an adversarial batch.
                    //
                    // We are now ready to verify the RSA signature
                    openid_sig
                        .verify_jwt_signature(rsa_jwk, &signature.jwt_header_json)
                        .map_err(|_| {
                            invalid_signature!("RSA signature verification failed for OpenIdSig")
                        })?;
                },
                JWK::Unsupported(_) => return Err(invalid_signature!("JWK is not supported")),
            }
```

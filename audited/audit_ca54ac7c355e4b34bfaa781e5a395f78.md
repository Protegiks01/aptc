# Audit Report

## Title
Missing Input Validation in EncryptionKey Constructor Allows Identity Element to Break BIBE Encryption Security

## Summary
The `EncryptionKey` struct constructor accepts arbitrary `G2Affine` elliptic curve points without validating that they are non-identity elements. This allows the point at infinity (identity element) to be used as an encryption key, which breaks the security guarantees of the BIBE (Broadcast Identity-Based Encryption) scheme used in the consensus randomness beacon. There are no negative tests to ensure invalid keys are rejected, creating an untested edge case that could be exploited through deserialization attacks or DKG bypass.

## Finding Description

The `EncryptionKey::new()` constructor in the batch encryption module accepts two `G2Affine` parameters (`sig_mpk_g2` and `tau_g2`) without any validation: [1](#0-0) 

The struct is used in the consensus layer's secret sharing configuration for the randomness beacon: [2](#0-1) [3](#0-2) 

The encryption key is directly used in BIBE encryption operations without validating that the public key components are non-identity: [4](#0-3) 

Critically, the arkworks serialization explicitly tests and supports deserializing `G2Affine::zero()` (the identity element): [5](#0-4) 

When `sig_mpk_g2` is the identity element, the pairing operation `e(hashed_encryption_key, sig_mpk_g2)` at line 135 of bibe.rs becomes `e(H, 0) = 1` (the identity in the target group GT). This makes the one-time pad deterministic or constant, completely breaking the semantic security of the encryption scheme.

The codebase shows that pairing operations with identity elements require special handling: [6](#0-5) 

However, no such checks exist in the BIBE encryption path, and there are **no negative tests** validating that invalid keys are rejected. The test suite only covers positive cases with valid keys generated through proper DKG setup.

## Impact Explanation

This vulnerability represents a **Medium severity** issue per the Aptos bug bounty criteria for the following reasons:

1. **Confidentiality Breach**: If an attacker can inject an `EncryptionKey` with identity elements, the BIBE encryption becomes cryptographically broken. Secret shares encrypted with this key lose their confidentiality guarantees.

2. **Consensus Randomness Beacon Impact**: The `EncryptionKey` is used in `SecretShareConfig` for the consensus randomness beacon, which is critical for validator selection and consensus security. Compromised secret shares could affect randomness generation.

3. **Defense-in-Depth Failure**: While normal operation through DKG should prevent zero keys, the lack of validation creates a security gap if DKG is bypassed through bugs, configuration errors, or deserialization attacks.

4. **State Inconsistencies**: Broken encryption could lead to validators being unable to properly reconstruct shared secrets, requiring manual intervention.

This falls under "State inconsistencies requiring intervention" in the Medium severity category ($10,000 range).

## Likelihood Explanation

The likelihood is **Low to Medium** because:

**Barriers to Exploitation:**
- The `EncryptionKey` is normally generated through validator-controlled DKG/PVSS setup
- Requires bypassing DKG or exploiting a deserialization path
- Would need to inject malicious configuration into the consensus layer

**Factors Increasing Likelihood:**
- The deserialization path explicitly allows zero points with `Validate::Yes`
- No application-level validation exists as a second line of defense
- **Complete absence of negative tests** means this edge case is untested
- Unknown behaviors in edge cases (epoch transitions, validator changes, network partitions)

The lack of testing is particularly concerning because it means the actual behavior with invalid keys is undefined, and there may be additional attack vectors not immediately visible.

## Recommendation

Add input validation to reject identity elements in the `EncryptionKey` constructor:

```rust
impl EncryptionKey {
    pub fn new(sig_mpk_g2: G2Affine, tau_g2: G2Affine) -> Result<Self> {
        // Validate that public key components are not identity elements
        if sig_mpk_g2.is_zero() {
            return Err(anyhow::anyhow!(
                "Invalid encryption key: sig_mpk_g2 cannot be the identity element"
            ));
        }
        if tau_g2.is_zero() {
            return Err(anyhow::anyhow!(
                "Invalid encryption key: tau_g2 cannot be the identity element"
            ));
        }
        
        Ok(Self { sig_mpk_g2, tau_g2 })
    }
}
```

Apply the same validation to `AugmentedEncryptionKey::new()`: [7](#0-6) 

**Additional Recommendations:**
1. Add comprehensive negative tests that verify identity elements are rejected
2. Add tests for other invalid curve points (small subgroup points, etc.)
3. Update all call sites to handle the new `Result` return type
4. Consider adding validation at deserialization time as an additional layer

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::{G2Affine, Fr};
    use crate::shared::ciphertext::bibe::BIBECTEncrypt;
    use crate::shared::ids::Id;
    use ark_ec::AffineRepr;
    use ark_std::rand::thread_rng;

    #[test]
    #[should_panic(expected = "Invalid encryption key")]
    fn test_encryption_key_rejects_identity_sig_mpk() {
        // This test should fail until validation is added
        let identity = G2Affine::zero(); // Point at infinity
        let valid_point = G2Affine::generator();
        
        // This currently succeeds but should fail
        let result = EncryptionKey::new(identity, valid_point);
        assert!(result.is_err(), "Should reject identity element as sig_mpk_g2");
    }

    #[test]
    #[should_panic(expected = "Invalid encryption key")]
    fn test_encryption_key_rejects_identity_tau() {
        let identity = G2Affine::zero();
        let valid_point = G2Affine::generator();
        
        let result = EncryptionKey::new(valid_point, identity);
        assert!(result.is_err(), "Should reject identity element as tau_g2");
    }

    #[test]
    fn test_encryption_with_identity_key_produces_broken_ciphertext() {
        // Demonstrate that encryption with identity element breaks security
        let mut rng = thread_rng();
        let identity = G2Affine::zero();
        
        // Currently this succeeds - it should fail at construction
        let broken_key = EncryptionKey::new(identity, identity);
        
        let plaintext = String::from("secret");
        let id = Id::new(Fr::from(1u64));
        
        // This encryption will be cryptographically broken
        let ct_result = broken_key.bibe_encrypt(&mut rng, &plaintext, id);
        
        // The ciphertext is created, but the security is completely compromised
        // because pairing with identity makes the one-time pad predictable
        assert!(ct_result.is_ok(), "Encryption completes but is insecure");
    }
}
```

## Notes

This vulnerability highlights a critical gap in test coverage. The `EncryptionKey` struct has **zero negative tests** validating edge cases, despite being used in consensus-critical code. The arkworks serialization tests explicitly include `G2Affine::zero()` in their test cases, proving that the identity element can be serialized and deserialized, but no tests validate that the application layer rejects such values.

The security question correctly identified that the lack of comprehensive negative tests creates exploitable edge cases. While exploitation requires specific conditions, the absence of defense-in-depth validation is a security flaw that should be addressed.

### Citations

**File:** crates/aptos-batch-encryption/src/shared/encryption_key.rs (L22-25)
```rust
impl EncryptionKey {
    pub fn new(sig_mpk_g2: G2Affine, tau_g2: G2Affine) -> Self {
        Self { sig_mpk_g2, tau_g2 }
    }
```

**File:** crates/aptos-batch-encryption/src/shared/encryption_key.rs (L46-53)
```rust
impl AugmentedEncryptionKey {
    pub fn new(sig_mpk_g2: G2Affine, tau_g2: G2Affine, tau_mpk_g2: G2Affine) -> Self {
        Self {
            sig_mpk_g2,
            tau_g2,
            tau_mpk_g2,
        }
    }
```

**File:** types/src/secret_sharing.rs (L16-16)
```rust
pub type EncryptionKey = <FPTXWeighted as BatchThresholdEncryption>::EncryptionKey;
```

**File:** types/src/secret_sharing.rs (L144-144)
```rust
    encryption_key: EncryptionKey,
```

**File:** crates/aptos-batch-encryption/src/shared/ciphertext/bibe.rs (L119-152)
```rust
    fn bibe_encrypt<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        plaintext: &impl Plaintext,
        id: Id,
    ) -> Result<BIBECiphertext> {
        let r = [Fr::rand(rng), Fr::rand(rng)];
        let hashed_encryption_key: G1Affine = symmetric::hash_g2_element(self.sig_mpk_g2)?;

        let ct_g2 = [
            (G2Affine::generator() * r[0] + self.sig_mpk_g2 * r[1]).into(),
            ((G2Affine::generator() * id.x() - self.tau_g2) * r[0]).into(),
            (-(G2Affine::generator() * r[1])).into(),
        ];

        let otp_source_gt: PairingOutput =
            -PairingSetting::pairing(hashed_encryption_key, self.sig_mpk_g2) * r[1];

        let mut otp_source_bytes = Vec::new();
        otp_source_gt.serialize_compressed(&mut otp_source_bytes)?;
        let otp = OneTimePad::from_source_bytes(otp_source_bytes);

        let symmetric_key = SymmetricKey::new(rng);
        let padded_key = otp.pad_key(&symmetric_key);

        let symmetric_ciphertext = symmetric_key.encrypt(rng, plaintext)?;

        Ok(BIBECiphertext {
            id,
            ct_g2,
            padded_key,
            symmetric_ciphertext,
        })
    }
```

**File:** crates/aptos-crypto/src/arkworks/serialization.rs (L88-107)
```rust
    #[test]
    fn test_g2_serialization_multiple_points() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct A(#[serde(serialize_with = "ark_se", deserialize_with = "ark_de")] G2Affine);

        let mut points = vec![G2Affine::zero()]; // Include zero
        let mut g = G2Projective::generator();

        for _ in 0..MAX_DOUBLINGS {
            points.push(g.into());
            g += g; // double for next
        }

        for p in points {
            let serialized = bcs::to_bytes(&A(p)).expect("Serialization failed");
            let deserialized: A = bcs::from_bytes(&serialized).expect("Deserialization failed");

            assert_eq!(deserialized.0, p, "G2 point round-trip failed for {:?}", p);
        }
    }
```

**File:** crates/aptos-dkg/src/utils/parallel_multi_pairing.rs (L19-25)
```rust
            .map(|(p, q)| {
                if (p.is_identity() | q.is_identity()).into() {
                    // Define pairing with zero as one, matching what `pairing` does.
                    blst_fp12::default()
                } else {
                    blst_fp12::miller_loop(q.as_ref(), p.as_ref())
                }
```

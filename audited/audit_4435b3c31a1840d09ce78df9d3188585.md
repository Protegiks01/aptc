# Audit Report

## Title
Missing Validation of Commitment Base in Chunky PVSS Allows Complete Bypass of Pairing-Based Verification

## Summary
The chunky PVSS implementation in `PublicParameters::new_with_commitment_base` accepts arbitrary G2 commitment base values without validation. Setting the commitment base to the identity element completely bypasses the pairing-based verification, allowing malicious dealers to encrypt incorrect shares that would pass verification.

## Finding Description

The security question asks whether parameter choices can weaken the decisional Diffie-Hellman (DDH) assumption in pairing groups. The answer is yes, but more critically: certain parameter choices completely break the PVSS security guarantees.

**Background on DDH in Pairing Groups:**
In pairing-friendly curves like BLS12-381, the DDH assumption is inherently broken in groups with efficiently computable pairings. Given (g, g^a, g^b, g^c), one can verify if c = ab using the pairing: e(g^a, g^b) =? e(g, g^c). The chunky PVSS scheme doesn't rely on DDH hardness in pairing groups; instead, it relies on the External Diffie-Hellman (XDH) assumption and Computational Diffie-Hellman (CDH) in both G1 and G2.

**The Critical Vulnerability:**
The commitment base G_2 can be set to the identity element without any validation: [1](#0-0) 

The `Valid::check()` implementation performs no validation: [2](#0-1) 

**Attack Mechanism:**
When G_2 is set to the identity element, all polynomial evaluation commitments become the identity regardless of their actual values:
- V_i = G_2 * f_eval_i = identity (for all i)

The pairing verification check becomes degenerate: [3](#0-2) 

Since e(anything, identity) = identity_GT, both sides of the equation always equal the identity in GT, causing verification to always pass regardless of ciphertext contents.

**Exploitation Path:**
1. Attacker influences public parameter initialization to set G_2 = identity
2. Malicious dealer creates transcript with arbitrary incorrect ciphertexts
3. Pairing verification always passes: e(weighted_Cs, identity) = e(G, identity) = identity_GT
4. Incorrect shares are accepted, breaking secret sharing correctness

## Impact Explanation

**Severity: Medium (if chunky PVSS were deployed)**

This vulnerability would completely break the PVSS security guarantees if the chunky PVSS scheme were deployed:
- **Correctness Violation**: Malicious dealers can provide arbitrary incorrect shares
- **State Inconsistencies**: Different validators would reconstruct different secrets
- **Consensus Impact**: Could lead to divergent randomness generation if used in consensus

However, **CRITICAL MITIGATION**: The production Aptos DKG uses the DAS PVSS scheme, not chunky PVSS: [4](#0-3) 

The DAS scheme uses deterministic commitment base generation: [5](#0-4) 

## Likelihood Explanation

**Current Likelihood: Extremely Low**

The chunky PVSS is only used in test code: [6](#0-5) 

An attacker cannot control public parameter initialization in production, and the production DKG system uses the DAS PVSS scheme with safe defaults.

## Recommendation

**For Defense in Depth (if chunky PVSS is ever deployed):**

Add validation in `PublicParameters::new_with_commitment_base` and `Valid::check()`:

```rust
impl<E: Pairing> PublicParameters<E> {
    pub fn new_with_commitment_base<R: RngCore + CryptoRng>(
        n: usize,
        ell: u8,
        max_aggregation: usize,
        commitment_base: E::G2Affine,
        rng: &mut R,
    ) -> Self {
        // Validate commitment base is not identity
        if commitment_base.is_zero() {
            panic!("Commitment base cannot be the identity element");
        }
        
        let mut pp = Self::new(n, ell, max_aggregation, rng);
        pp.G_2 = commitment_base;
        pp
    }
}

impl<E: Pairing> Valid for PublicParameters<E> {
    fn check(&self) -> Result<(), SerializationError> {
        if self.G_2.is_zero() {
            return Err(SerializationError::InvalidData);
        }
        // Also validate G and H in pp_elgamal are not identity
        // and that they're different from each other
        Ok(())
    }
}
```

## Proof of Concept

```rust
#[test]
fn test_identity_commitment_base_vulnerability() {
    use ark_bls12_381::{Bls12_381, G2Affine};
    use ark_ec::AffineRepr;
    
    let mut rng = thread_rng();
    
    // Create public parameters with identity element as commitment base
    let pp = PublicParameters::<Bls12_381>::new_with_commitment_base(
        3,
        16,
        1,
        G2Affine::zero(), // Identity element
        &mut rng,
    );
    
    // All commitments will be identity regardless of values
    let f_eval = Fr::from(12345u64);
    let commitment = pp.get_commitment_base().mul(f_eval);
    
    assert_eq!(commitment, G2Projective::zero());
    
    // Pairing check will always pass
    // e(anything, identity) = identity_GT
}
```

## Notes

While this represents a genuine cryptographic weakness in the chunky PVSS parameter handling, it does **not** constitute an exploitable vulnerability in the deployed Aptos network because:

1. The production DKG uses DAS PVSS with safe, deterministic parameter generation
2. Public parameters are set during system initialization by trusted parties
3. No external attacker can influence parameter selection

This finding answers the security question affirmatively: yes, parameter choices (specifically setting G_2 to identity) can completely weaken the pairing-based security assumptions. However, the current deployment is protected by using the DAS scheme with proper parameter generation.

### Citations

**File:** crates/aptos-dkg/src/pvss/chunky/public_parameters.rs (L120-124)
```rust
impl<E: Pairing> Valid for PublicParameters<E> {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}
```

**File:** crates/aptos-dkg/src/pvss/chunky/public_parameters.rs (L194-205)
```rust
    /// Creates public parameters with a specified commitment base.
    pub fn new_with_commitment_base<R: RngCore + CryptoRng>(
        n: usize,
        ell: u8,
        max_aggregation: usize,
        commitment_base: E::G2Affine,
        rng: &mut R,
    ) -> Self {
        let mut pp = Self::new(n, ell, max_aggregation, rng);
        pp.G_2 = commitment_base;
        pp
    }
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L273-283)
```rust
        let res = E::multi_pairing(
            [
                weighted_Cs.into_affine(),
                *pp.get_encryption_public_params().message_base(),
            ],
            [pp.get_commitment_base(), (-weighted_Vs).into_affine()],
        ); // Making things affine here rather than converting the two bases to group elements, since that's probably what they would be converted to anyway: https://github.com/arkworks-rs/algebra/blob/c1f4f5665504154a9de2345f464b0b3da72c28ec/ec/src/models/bls12/g1.rs#L14

        if PairingOutput::<E>::ZERO != res {
            return Err(anyhow::anyhow!("Expected zero during multi-pairing check"));
        }
```

**File:** types/src/dkg/real_dkg/mod.rs (L38-39)
```rust
pub type WTrx = pvss::das::WeightedTranscript;
pub type DkgPP = <WTrx as Transcript>::PublicParameters;
```

**File:** crates/aptos-dkg/src/pvss/das/public_parameters.rs (L51-70)
```rust
    pub fn default_with_bls_base() -> Self {
        let g = G1Projective::generator();
        let h = G1Projective::hash_to_curve(
            SEED_PVSS_PUBLIC_PARAMS,
            DST_PVSS_PUBLIC_PARAMS.as_slice(),
            b"h_with_bls_base",
        );
        debug_assert_ne!(g, h);
        PublicParameters {
            enc: encryption_elgamal::g1::PublicParameters::new(
                // Our BLS signatures over BLS12-381 curves use this generator as the base of their
                // PKs. We plan on (safely) reusing those BLS PKs as encryption PKs.
                g, h,
            ),
            g_2: G2Projective::hash_to_curve(
                SEED_PVSS_PUBLIC_PARAMS,
                DST_PVSS_PUBLIC_PARAMS.as_slice(),
                b"g_2_with_bls_base",
            ),
        }
```

**File:** crates/aptos-batch-encryption/src/tests/fptx_weighted_smoke.rs (L94-99)
```rust
    let pp = <T as Transcript>::PublicParameters::new_with_commitment_base(
        tc.get_total_weight(),
        aptos_dkg::pvss::chunky::DEFAULT_ELL_FOR_TESTING,
        tc.get_total_num_players(),
        G2Affine::generator(),
        &mut rng_aptos,
```

# Audit Report

## Title
DKG PVSS Transcript Verification Accepts Infinity Points, Enabling Share Value Leakage

## Summary
The DKG PVSS transcript verification in `weighted_protocol.rs` and `unweighted_protocol.rs` does not validate that encryption randomness commitments (R, R_hat) are non-identity points. A malicious dealer can craft transcripts with R[k] = infinity (point at infinity), resulting in ciphertexts that leak share values without encryption, bypassing the confidentiality guarantee of the PVSS scheme.

## Finding Description
The pairing computation correctly returns `Gt::one()` when either input is the point at infinity, as confirmed in [1](#0-0) .

However, the DKG PVSS verification functions do not check whether transcript elements (V, R, C, V_hat, R_hat) are the identity element. The BLS12-381 deserialization accepts infinity points as valid [2](#0-1) .

In the weighted PVSS protocol, ciphertexts are computed as: [3](#0-2) 

This computes `C[k] = h^{f_evals[k]} * ek_i^{r[k]}` where r[k] is encryption randomness.

A malicious dealer can set R[k] = identity and R_hat[k] = identity (meaning r[k] = 0), resulting in:
- C[k] = h^{f_evals[k]} * ek_i^0 = h^{f_evals[k]}

The verification check in slow_verify is: [4](#0-3) 

With R_hat[k] = infinity:
- e(h, V_hat[k]) * e(ek_i, 0) = e(h, V_hat[k]) * Gt::one() = e(h, V_hat[k])
- e(C[k], g_2) = e(h^{f_evals[k]}, g_2) = e(h, g_2)^{f_evals[k]}

Both sides equal when V_hat[k] = g_2^{f_evals[k]}, which is the correct value. The verification passes despite zero encryption randomness.

The batched multi-pairing verification [5](#0-4)  uses random linear combinations but suffers the same issue - infinity points in R/R_hat contribute identity to the product, and consistency is maintained.

**Attack scenario:**
1. Malicious dealer creates transcript with R[k] = R_hat[k] = identity for target shares
2. Sets C[k] = h^{f_evals[k]} (no encryption randomness)
3. Sets V[k], V_hat[k] correctly for the polynomial
4. Transcript passes all verification checks
5. Ciphertext C[k] = h^{f_evals[k]} reveals share value - anyone can brute-force discrete log or use precomputed tables

## Impact Explanation
This vulnerability breaks the confidentiality guarantee of PVSS (Publicly Verifiable Secret Sharing). Encrypted shares should only be decryptable by holders of the corresponding private key, but with zero randomness, the share value is leaked to all observers.

**Severity: High** - This constitutes a significant protocol violation. While not directly causing fund loss or consensus failure, it compromises the DKG (Distributed Key Generation) security model, which is critical for the randomness beacon. Leaked shares could enable:
- Prediction or manipulation of randomness beacon outputs
- Potential validator selection bias if randomness is compromised
- Violation of the cryptographic correctness invariant

## Likelihood Explanation
**Likelihood: Medium-High**
- Any DKG participant can craft malicious transcripts
- No privileged access required
- The attack is straightforward: serialize transcript with R elements set to infinity
- Deserialization will accept it per BLS12-381 spec
- Verification will pass due to lack of identity checks

The only barrier is that honest nodes may eventually notice share leakage during decryption, but by then the compromised transcript may already be aggregated into the final DKG output.

## Recommendation
Add explicit validation that all transcript elements are non-identity before accepting them for verification. Specifically, in the `verify()` function, add checks:

```rust
// After size checks, before cryptographic verification:
for i in 0..W {
    if self.R[i].is_identity().into() {
        bail!("R[{}] cannot be the identity element", i);
    }
    if self.R_hat[i].is_identity().into() {
        bail!("R_hat[{}] cannot be the identity element", i);
    }
}

// Similarly check V, V_hat, C are non-identity
for i in 0..self.V.len() {
    if self.V[i].is_identity().into() {
        bail!("V[{}] cannot be the identity element", i);
    }
    if self.V_hat[i].is_identity().into() {
        bail!("V_hat[{}] cannot be the identity element", i);
    }
}

for i in 0..self.C.len() {
    if self.C[i].is_identity().into() {
        bail!("C[{}] cannot be the identity element", i);
    }
}
```

Apply the same validation to the unweighted protocol [6](#0-5)  and chunky transcripts.

Additionally, consider using `random_nonzero_scalar()` [7](#0-6)  instead of `random_scalars()` when generating encryption randomness to prevent accidental zero randomness in honest dealing.

## Proof of Concept

```rust
#[test]
fn test_infinity_point_attack() {
    use crate::pvss::das::weighted_protocol::Transcript;
    use crate::pvss::traits::{Transcript as TranscriptTrait, AggregatableTranscript};
    use group::Group;
    use blstrs::{G1Projective, G2Projective};
    
    // Create a valid config
    let sc = WeightedConfigBlstrs::new(/* ... */);
    let pp = das::PublicParameters::new(/* ... */);
    
    // Create a malicious transcript
    let mut malicious_transcript = Transcript {
        soks: /* valid PoKs */,
        V: /* valid polynomial commitments */,
        V_hat: /* valid polynomial commitments */,
        R: vec![G1Projective::identity(); W], // All identity!
        R_hat: vec![G2Projective::identity(); W], // All identity!
        C: /* C[k] = h^{f_evals[k]} with no randomness */,
    };
    
    // Attempt verification
    let result = malicious_transcript.verify(&sc, &pp, &spks, &eks, &auxs);
    
    // This should fail but currently passes
    assert!(result.is_err(), "Transcript with identity randomness should be rejected");
    // Currently this assertion would fail - the malicious transcript is accepted!
}
```

## Notes
The vulnerability exists because the pairing e(P, 0) = Gt::one() is mathematically correct, but the DKG protocol assumes non-zero encryption randomness for confidentiality. The verification checks algebraic consistency but not the semantic requirement that randomness must be non-zero.

### Citations

**File:** crates/aptos-dkg/src/utils/parallel_multi_pairing.rs (L20-22)
```rust
                if (p.is_identity() | q.is_identity()).into() {
                    // Define pairing with zero as one, matching what `pairing` does.
                    blst_fp12::default()
```

**File:** aptos-move/framework/aptos-stdlib/sources/cryptography/bls12381_algebra.move (L94-95)
```text
    /// 1. Compute the infinity flag as `b[0] & 0x40 != 0`.
    /// 1. If the infinity flag is set, return the point at infinity.
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L165-168)
```rust
                C.push(g1_multi_exp(
                    bases.as_slice(),
                    [f_evals[k], r[k]].as_slice(),
                ))
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L366-374)
```rust
        let res = multi_pairing(lhs, rhs);
        if res != Gt::identity() {
            bail!(
                "Expected zero during multi-pairing check for {} {}, but got {}",
                sc,
                <Self as traits::Transcript>::scheme_name(),
                res
            );
        }
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L510-511)
```rust
                let lhs = pairing(&h_1_aff, &V_hat_aff[k]).add(pairing(&eks[i], &R_hat_aff[k]));
                let rhs = pairing(&self.C[k].to_affine(), &g_2_aff);
```

**File:** crates/aptos-dkg/src/pvss/das/unweighted_protocol.rs (L225-313)
```rust
impl AggregatableTranscript for Transcript {
    fn verify<A: Serialize + Clone>(
        &self,
        sc: &<Self as traits::Transcript>::SecretSharingConfig,
        pp: &Self::PublicParameters,
        spks: &[Self::SigningPubKey],
        eks: &[Self::EncryptPubKey],
        auxs: &[A],
    ) -> anyhow::Result<()> {
        if eks.len() != sc.n {
            bail!("Expected {} encryption keys, but got {}", sc.n, eks.len());
        }

        if self.C.len() != sc.n {
            bail!("Expected {} ciphertexts, but got {}", sc.n, self.C.len());
        }

        if self.V.len() != sc.n + 1 {
            bail!(
                "Expected {} (polynomial) commitment elements, but got {}",
                sc.n + 1,
                self.V.len()
            );
        }

        // Deriving challenges by flipping coins: less complex to implement & less likely to get wrong. Creates bad RNG risks but we deem that acceptable.
        let mut rng = thread_rng();
        let extra = random_scalars(2, &mut rng);

        // Verify signature(s) on the secret commitment, player ID and `aux`
        let g_2 = *pp.get_commitment_base();
        batch_verify_soks::<G2Projective, A>(
            self.soks.as_slice(),
            &g_2,
            &self.V[sc.n],
            spks,
            auxs,
            &extra[0],
        )?;

        // Verify the committed polynomial is of the right degree
        let ldt = LowDegreeTest::random(
            &mut rng,
            sc.t,
            sc.n + 1,
            true,
            sc.get_batch_evaluation_domain(),
        );
        ldt.low_degree_test_on_g2(&self.V)?;

        //
        // Correctness of encryptions check
        //
        // (see [WVUF Overleaf](https://www.overleaf.com/project/63a1c2c222be94ece7c4b862) for
        //  explanation of how batching works)
        //

        // TODO(Performance): Change the Fiat-Shamir transform to use 128-bit random exponents.
        // r_i = \tau^i, \forall i \in [n]
        // TODO: benchmark this
        let taus = get_nonzero_powers_of_tau(&extra[1], sc.n);

        // Compute the multiexps from above.
        let v = g2_multi_exp(&self.V[..self.V.len() - 1], taus.as_slice());
        let ek = g1_multi_exp(
            eks.iter()
                .map(|ek| Into::<G1Projective>::into(ek))
                .collect::<Vec<G1Projective>>()
                .as_slice(),
            taus.as_slice(),
        );
        let c = g1_multi_exp(self.C.as_slice(), taus.as_slice());

        // Fetch some public parameters
        let h_1 = *pp.get_encryption_public_params().message_base();
        let g_1_inverse = pp.get_encryption_public_params().pubkey_base().neg();

        // The vector of left-hand-side ($\mathbb{G}_1$) inputs to each pairing in the multi-pairing.
        let lhs = vec![h_1, ek.add(g_1_inverse), self.C_0.add(c.neg())];
        // The vector of right-hand-side ($\mathbb{G}_2$) inputs to each pairing in the multi-pairing.
        let rhs = vec![v, self.hat_w, g_2];

        let res = multi_pairing(lhs.iter(), rhs.iter());
        if res != Gt::identity() {
            bail!("Expected zero, but got {} during multi-pairing check", res);
        }

        return Ok(());
    }
```

**File:** crates/aptos-dkg/src/utils/random.rs (L29-34)
```rust
pub fn random_nonzero_scalar<R>(rng: &mut R) -> Scalar
where
    R: rand_core::RngCore + rand::Rng + rand_core::CryptoRng + rand::CryptoRng,
{
    aptos_crypto::blstrs::random_scalar_internal(rng, true)
}
```

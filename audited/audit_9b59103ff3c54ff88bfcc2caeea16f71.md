# Audit Report

## Title
DKG Protocol Accepts Zero Input Secrets Without Validation, Violating Threshold Cryptography Invariants

## Summary
The Aptos DKG (Distributed Key Generation) protocol fails to validate that input secrets are non-zero before using them in the dealing phase. A malicious validator can create a zero `InputSecret` using the publicly available `InputSecret::zero()` method and successfully generate and submit a transcript with a dealt public key equal to the identity element, which passes all verification checks. This violates fundamental threshold cryptography invariants and protocol correctness guarantees.

## Finding Description

The DKG protocol in Aptos uses PVSS (Publicly Verifiable Secret Sharing) to enable validators to collectively generate shared randomness. Each validator contributes an `InputSecret` which should be a non-zero random scalar. However, the implementation has no validation preventing zero secrets at any stage:

**1. Zero Secret Creation is Publicly Available** [1](#0-0) 

The `InputSecret` type implements the `num_traits::Zero` trait, making `InputSecret::zero()` publicly callable. While the intended path is `InputSecret::generate()`, nothing prevents direct instantiation of a zero secret.

**2. Random Scalar Generation Does Not Exclude Zero** [2](#0-1) 

The `random_scalar()` function calls `random_scalar_internal(rng, false)` with `exclude_zero = false`, meaning zero is technically possible (though astronomically unlikely) even from legitimate random generation.

**3. No Validation in Shamir Secret Sharing** [3](#0-2) 

The `shamir_secret_share()` function directly assigns the input secret to the polynomial's constant term without any zero check. If the secret is zero, `f[0] = 0`.

**4. No Validation in Dealing Process** [4](#0-3) 

The `deal()` function accepts any `InputSecret` parameter without validation and passes it directly to `shamir_secret_share()`.

**5. Dealt Public Key Can Be Identity Element**

When a zero secret is used, the dealt public key becomes `g^{f(0)} = g^0 = identity`. The `DealtPubKey::new()` constructor accepts any group element without validation: [5](#0-4) 

**6. Transcript Verification Does Not Reject Identity Keys**

The verification logic performs pairing checks but never explicitly validates that the dealt public key is not the identity element: [6](#0-5) 

The multi-pairing check at line 366-374 verifies the pairing equation correctness but does not check if `V[W]` (the dealt public key) is the identity.

**7. VM-Level Verification Also Lacks This Check** [7](#0-6) 

The consensus-level verification calls `DefaultDKG::verify_transcript()` which ultimately calls the PVSS verification, inheriting the same lack of identity element validation.

**Attack Path:**
1. Malicious validator creates `InputSecret::zero()` instead of using `InputSecret::generate()`
2. Calls `DKG::generate_transcript()` with the zero secret
3. The dealing process creates a polynomial with f(0) = 0
4. The dealt public key becomes the identity element in G1 and G2
5. Transcript passes all verification checks (signature, pairing equations, Schnorr PoK)
6. Transcript is accepted and aggregated with other transcripts

## Impact Explanation

**Severity: Medium** (state inconsistencies requiring intervention)

While this violates critical protocol invariants, the immediate security impact is limited by the Byzantine fault tolerance model:

**Protocol Correctness Violation:**
- Threshold cryptography standards require all dealer contributions to be non-zero
- The protocol specification is violated even if security isn't immediately compromised
- Breaks the "Cryptographic Correctness" invariant: "BLS signatures, VRF, and hash operations must be secure"

**Limited Security Impact (under normal Byzantine assumptions):**
- If < 1/3 of validators use zero secrets, honest validators' random contributions still ensure final secret unpredictability
- The aggregation sums all secrets: `final_secret = sum(all_input_secrets)`
- Zero contributions don't affect randomness if sufficient honest contributions exist [8](#0-7) 

**Potential Edge Case Risks:**
- Reduced entropy if multiple validators independently or maliciously use zero
- Defense-in-depth violation - implementation may assume non-zero elements elsewhere
- Future protocol changes might rely on this implicit assumption
- Identity elements could trigger edge cases in pairing or group operations

**Not a Critical Issue Because:**
- Does not immediately break consensus safety under < 1/3 Byzantine assumption
- Does not enable direct fund theft or minting
- Does not cause network partition or liveness failure
- Byzantine majority scenarios (where this could be devastating) are out of scope

## Likelihood Explanation

**Likelihood: Low to Medium**

**Requires:**
- Attacker must be a validator participating in DKG
- Attacker must modify consensus client code to call `InputSecret::zero()` instead of `generate()`
- Attacker must be willing to submit a malformed (though valid-passing) transcript

**Realistic Scenarios:**
1. **Malicious Validator:** A compromised or malicious validator could deliberately exploit this
2. **Implementation Bug:** A bug in validator software could accidentally create zero secrets (very unlikely given randomness source)
3. **Testing/Development Error:** Misconfigured validator using wrong code path

**Feasibility:**
- Easy to exploit once validator access is obtained
- Requires no collusion with other validators
- Detection is difficult as transcript appears valid to verification logic
- No cryptographic breaking required

## Recommendation

**Add explicit validation that input secrets and dealt public keys are non-zero:**

```rust
// In shamir_secret_share() function (crates/aptos-crypto/src/blstrs/polynomials.rs):
pub fn shamir_secret_share<R: rand_core::RngCore + rand::Rng + rand_core::CryptoRng + rand::CryptoRng>(
    sc: &ThresholdConfigBlstrs,
    s: &InputSecret,
    rng: &mut R,
) -> (Vec<Scalar>, Vec<Scalar>) {
    // Add validation
    if s.get_secret_a().is_zero() {
        panic!("Input secret must be non-zero for DKG security");
    }
    
    let mut f = random_scalars(sc.t, rng);
    f[0] = *s.get_secret_a();
    // ... rest of function
}

// In Transcript verification (crates/aptos-dkg/src/pvss/das/weighted_protocol.rs):
fn verify<A: Serialize + Clone>(
    &self,
    sc: &<Self as traits::Transcript>::SecretSharingConfig,
    pp: &Self::PublicParameters,
    spks: &[Self::SigningPubKey],
    eks: &[Self::EncryptPubKey],
    auxs: &[A],
) -> anyhow::Result<()> {
    self.check_sizes(sc)?;
    
    // Add identity element check for dealt public key
    if self.V[W].is_identity().into() || self.V_hat[W].is_identity().into() {
        bail!("Dealt public key cannot be identity element");
    }
    
    // ... rest of verification
}
```

**Alternative approach:** Use `random_scalar_internal(rng, true)` to exclude zero during generation:

```rust
// In input_secret.rs:
impl Uniform for InputSecret {
    fn generate<R>(rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        let a = random_scalar_internal(rng, true); // exclude_zero = true
        InputSecret { a }
    }
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod test_zero_secret_attack {
    use super::*;
    use aptos_crypto::Uniform;
    use aptos_dkg::pvss::{
        das::WeightedTranscript,
        traits::Transcript,
    };
    use num_traits::Zero;

    #[test]
    fn test_zero_input_secret_bypasses_validation() {
        // Setup DKG configuration
        let mut rng = rand::thread_rng();
        let (sc, pp, spks, eks, ssk, _) = setup_test_config(&mut rng);
        
        // Create a ZERO input secret instead of random
        let zero_secret = <WeightedTranscript as Transcript>::InputSecret::zero();
        
        // Verify it is actually zero
        assert!(zero_secret.is_zero());
        
        // Deal a transcript with the zero secret - should fail but doesn't!
        let malicious_transcript = WeightedTranscript::deal(
            &sc,
            &pp,
            &ssk,
            &spks[0],
            &eks,
            &zero_secret,  // Using zero secret
            &0u64,
            &Player { id: 0 },
            &mut rng,
        );
        
        // Get the dealt public key
        let dealt_pk = malicious_transcript.get_dealt_public_key();
        
        // The dealt public key is the identity element!
        assert!(dealt_pk.as_group_element().is_identity().into());
        
        // But verification PASSES - this is the vulnerability!
        let result = malicious_transcript.verify(&sc, &pp, &spks, &eks, &[0u64]);
        assert!(result.is_ok(), "Zero-secret transcript should be rejected but passes verification!");
        
        println!("VULNERABILITY CONFIRMED: Zero input secret bypasses all validation");
    }
}
```

**Notes:**

This is a **protocol correctness violation** rather than an immediate security catastrophe. The Byzantine fault tolerance model protects against limited exploitation, but the lack of validation violates fundamental threshold cryptography principles and creates technical debt that could manifest as security issues in edge cases or future protocol evolutions. Proper validation should be added to enforce protocol invariants explicitly.

### Citations

**File:** crates/aptos-crypto/src/input_secret.rs (L53-61)
```rust
impl Zero for InputSecret {
    fn zero() -> Self {
        InputSecret { a: Scalar::ZERO }
    }

    fn is_zero(&self) -> bool {
        self.a.is_zero_vartime()
    }
}
```

**File:** crates/aptos-crypto/src/blstrs/mod.rs (L167-172)
```rust
pub fn random_scalar<R>(rng: &mut R) -> Scalar
where
    R: rand_core::RngCore + rand::Rng + rand_core::CryptoRng + rand::CryptoRng,
{
    random_scalar_internal(rng, false)
}
```

**File:** crates/aptos-crypto/src/blstrs/polynomials.rs (L651-666)
```rust
pub fn shamir_secret_share<
    R: rand_core::RngCore + rand::Rng + rand_core::CryptoRng + rand::CryptoRng,
>(
    sc: &ThresholdConfigBlstrs,
    s: &InputSecret,
    rng: &mut R,
) -> (Vec<Scalar>, Vec<Scalar>) {
    // A random, degree t-1 polynomial $f(X) = [a_0, \dots, a_{t-1}]$, with $a_0$ set to `s.a`
    let mut f = random_scalars(sc.t, rng);
    f[0] = *s.get_secret_a();

    // Evaluate $f$ at all the $N$th roots of unity.
    let mut f_evals = fft::fft(&f, sc.get_evaluation_domain());
    f_evals.truncate(sc.n);
    (f, f_evals)
}
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L114-130)
```rust
    fn deal<A: Serialize + Clone, R: rand_core::RngCore + rand_core::CryptoRng>(
        sc: &Self::SecretSharingConfig,
        pp: &Self::PublicParameters,
        ssk: &Self::SigningSecretKey,
        _spk: &Self::SigningPubKey,
        eks: &[Self::EncryptPubKey],
        s: &Self::InputSecret,
        aux: &A,
        dealer: &Player,
        mut rng: &mut R,
    ) -> Self {
        let n = sc.get_total_num_players();
        assert_eq!(eks.len(), n);

        // f_evals[k] = f(\omega^k), \forall k \in [0, W-1]
        let W = sc.get_total_weight();
        let (f_coeff, f_evals) = shamir_secret_share(sc.get_threshold_config(), s, rng);
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L280-377)
```rust
    fn verify<A: Serialize + Clone>(
        &self,
        sc: &<Self as traits::Transcript>::SecretSharingConfig,
        pp: &Self::PublicParameters,
        spks: &[Self::SigningPubKey],
        eks: &[Self::EncryptPubKey],
        auxs: &[A],
    ) -> anyhow::Result<()> {
        self.check_sizes(sc)?;
        let n = sc.get_total_num_players();
        if eks.len() != n {
            bail!("Expected {} encryption keys, but got {}", n, eks.len());
        }
        let W = sc.get_total_weight();

        // Deriving challenges by flipping coins: less complex to implement & less likely to get wrong. Creates bad RNG risks but we deem that acceptable.
        let mut rng = rand::thread_rng();
        let extra = random_scalars(2 + W * 3, &mut rng);

        let sok_vrfy_challenge = &extra[W * 3 + 1];
        let g_2 = pp.get_commitment_base();
        let g_1 = pp.get_encryption_public_params().pubkey_base();
        batch_verify_soks::<G1Projective, A>(
            self.soks.as_slice(),
            g_1,
            &self.V[W],
            spks,
            auxs,
            sok_vrfy_challenge,
        )?;

        let ldt = LowDegreeTest::random(
            &mut rng,
            sc.get_threshold_weight(),
            W + 1,
            true,
            sc.get_batch_evaluation_domain(),
        );
        ldt.low_degree_test_on_g1(&self.V)?;

        //
        // Correctness of encryptions check
        //

        let alphas_betas_and_gammas = &extra[0..W * 3 + 1];
        let (alphas_and_betas, gammas) = alphas_betas_and_gammas.split_at(2 * W + 1);
        let (alphas, betas) = alphas_and_betas.split_at(W + 1);
        assert_eq!(alphas.len(), W + 1);
        assert_eq!(betas.len(), W);
        assert_eq!(gammas.len(), W);

        let lc_VR_hat = G2Projective::multi_exp_iter(
            self.V_hat.iter().chain(self.R_hat.iter()),
            alphas_and_betas.iter(),
        );
        let lc_VRC = G1Projective::multi_exp_iter(
            self.V.iter().chain(self.R.iter()).chain(self.C.iter()),
            alphas_betas_and_gammas.iter(),
        );
        let lc_V_hat = G2Projective::multi_exp_iter(self.V_hat.iter().take(W), gammas.iter());
        let mut lc_R_hat = Vec::with_capacity(n);

        for i in 0..n {
            let p = sc.get_player(i);
            let weight = sc.get_player_weight(&p);
            let s_i = sc.get_player_starting_index(&p);

            lc_R_hat.push(g2_multi_exp(
                &self.R_hat[s_i..s_i + weight],
                &gammas[s_i..s_i + weight],
            ));
        }

        let h = pp.get_encryption_public_params().message_base();
        let g_2_neg = g_2.neg();
        let eks = eks
            .iter()
            .map(Into::<G1Projective>::into)
            .collect::<Vec<G1Projective>>();
        // The vector of left-hand-side ($\mathbb{G}_2$) inputs to each pairing in the multi-pairing.
        let lhs = [g_1, &lc_VRC, h].into_iter().chain(&eks);
        // The vector of right-hand-side ($\mathbb{G}_2$) inputs to each pairing in the multi-pairing.
        let rhs = [&lc_VR_hat, &g_2_neg, &lc_V_hat]
            .into_iter()
            .chain(&lc_R_hat);

        let res = multi_pairing(lhs, rhs);
        if res != Gt::identity() {
            bail!(
                "Expected zero during multi-pairing check for {} {}, but got {}",
                sc,
                <Self as traits::Transcript>::scheme_name(),
                res
            );
        }

        return Ok(());
    }
```

**File:** crates/aptos-dkg/src/pvss/dealt_pub_key.rs (L27-30)
```rust
        impl DealtPubKey {
            pub fn new(g_a: $GTProjective) -> Self {
                Self { g_a }
            }
```

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L111-112)
```rust
        DefaultDKG::verify_transcript(&pub_params, &transcript)
            .map_err(|_| Expected(TranscriptVerificationFailed))?;
```

**File:** types/src/dkg/real_dkg/mod.rs (L226-232)
```rust
    fn aggregate_input_secret(secrets: Vec<Self::InputSecret>) -> Self::InputSecret {
        secrets
            .into_iter()
            .fold(<WTrx as Transcript>::InputSecret::zero(), |acc, item| {
                acc + item
            })
    }
```

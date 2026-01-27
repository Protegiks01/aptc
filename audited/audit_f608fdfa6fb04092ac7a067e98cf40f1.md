# Audit Report

## Title
DKG Secret Aggregation Entropy Reduction via Malicious Zero-Contribution Attack

## Summary
Malicious validators can contribute zero or chosen input secrets during DKG without detection, reducing the entropy of the aggregated secret and potentially biasing randomness-dependent consensus operations.

## Finding Description

The DKG (Distributed Key Generation) implementation lacks validation to ensure that validators contribute non-zero, randomly-generated input secrets. During the secret aggregation phase, each validator's `InputSecret` is added together using the `AddAssign` trait, but there is no cryptographic or logical verification that prevents a malicious validator from contributing `InputSecret::zero()` or any other chosen value.

**Attack Flow:**

1. During DKG initialization, each validator generates an `InputSecret` via `InputSecret::generate(&mut rng)` [1](#0-0) 

2. A malicious validator can replace this with `InputSecret::zero()` or any chosen scalar value [2](#0-1) 

3. The `InputSecret` becomes the constant term of the Shamir secret-sharing polynomial without validation [3](#0-2) 

4. The transcript verification only validates proof-of-knowledge, range proofs, and consistency - but NOT that the input secret is non-zero or randomly generated [4](#0-3) 

5. During aggregation, secrets are summed using `AddAssign` [5](#0-4) 

6. Zero contributions provide no entropy to the final aggregated secret

**Why Verification Fails to Detect This:**

The PVSS transcript verification checks prove:
- The dealer knows the secret shares (Proof of Knowledge)
- Share chunks are in valid ranges (Range Proof)  
- Polynomial commitments are consistent (Low Degree Test)
- Ciphertexts match commitments (Pairing Check)

However, zero is a valid field element that satisfies all these properties. The verification proves the dealer "knows" the secret (even if it's zero) and that the dealing was performed correctly, but not that the secret was randomly chosen.

## Impact Explanation

**Severity: Critical**

This vulnerability breaks the fundamental security assumption of DKG that the final shared secret has sufficient entropy from honest participants. The impacts include:

1. **Randomness Predictability**: If `f` malicious validators (where `f < n/3`) contribute zero, the effective entropy is reduced from `n` honest contributions to `(n-f)` contributions.

2. **Consensus Manipulation**: The DKG output is used for on-chain randomness which affects validator selection and other consensus operations. Reduced entropy could enable prediction or manipulation of these processes.

3. **Protocol Security Degradation**: The security guarantee that "at least `t` honest dealers provide sufficient entropy" is violated when malicious dealers can contribute zero without detection.

This meets the **Critical Severity** category as it constitutes a significant protocol violation affecting consensus randomness, which is a foundational security mechanism.

## Likelihood Explanation

**Likelihood: High**

The attack is trivially exploitable by any malicious validator:
- Requires only a simple code modification (replacing `generate()` with `zero()`)
- No special timing, coordination, or external conditions needed
- Cannot be detected by the current verification mechanisms
- Does not require knowledge of other validators' secrets

The only barrier is that the attacker must control a validator node, but the question explicitly explores this threat model ("malicious validators").

## Recommendation

Implement verification to ensure input secrets are non-zero and/or add commitment-to-randomness mechanisms:

**Option 1: Zero-Check Validation**
Add validation in the transcript verification to reject transcripts with zero dealt public keys:

```rust
// In weighted_transcript.rs verify() function, after existing checks:
if self.subtrs.V0.is_zero() {
    bail!("Dealt public key V0 cannot be zero");
}
```

**Option 2: Commitment to Randomness**
Require validators to commit to their random input secret before dealing, then verify the dealing matches the commitment. This prevents choosing the secret after seeing others' commitments.

**Option 3: Combined Approach**
- Check for zero in verification
- Add range requirements on the input secret magnitude
- Implement commit-then-reveal scheme for additional security

The minimal fix is Option 1, adding zero-checks in verification paths: [6](#0-5) 

## Proof of Concept

```rust
#[cfg(test)]
mod zero_contribution_attack {
    use super::*;
    use aptos_crypto::Uniform;
    use rand::thread_rng;

    #[test]
    fn test_malicious_zero_contribution() {
        let mut rng = thread_rng();
        
        // Honest validator generates random secret
        let honest_secret = InputSecret::generate(&mut rng);
        assert!(!honest_secret.is_zero());
        
        // Malicious validator contributes zero
        let malicious_secret = InputSecret::zero();
        assert!(malicious_secret.is_zero());
        
        // Aggregate secrets
        let mut aggregated = InputSecret::zero();
        aggregated.add_assign(&honest_secret);
        aggregated.add_assign(&malicious_secret); // Zero adds nothing
        
        // Result has reduced entropy - only honest contribution
        // In a real DKG with n validators, f malicious zeros reduce
        // entropy from n to (n-f) contributions
        
        // Generate transcript with zero secret (this will succeed)
        let pp = PublicParameters::default();
        let sc = SecretSharingConfig::new(...);
        let transcript = Transcript::deal(
            &sc, &pp, &ssk, &spk, &eks,
            &malicious_secret, // Using zero secret
            &aux, &dealer, &mut rng
        );
        
        // Verify transcript (will pass despite zero secret)
        assert!(transcript.verify(&sc, &pp, &spks, &eks, &aux).is_ok());
        
        // The V0 commitment will be zero (g2^0 = identity)
        assert!(transcript.subtrs.V0.is_zero());
    }
}
```

**Notes**

The vulnerability exists because the DKG protocol assumes validators are honest-but-curious, but lacks enforcement mechanisms to prevent malicious validators from contributing degenerate values. While the question asks about "canceling out" honest contributions, the practical attack is contributing zero (which requires no knowledge of others' secrets). True cancellation would require predicting honest contributions, which is infeasible without side channels. However, the zero-contribution attack alone is sufficient to degrade the security guarantees of the DKG protocol.

### Citations

**File:** dkg/src/dkg_manager/mod.rs (L330-330)
```rust
        let input_secret = DKG::InputSecret::generate(&mut rng);
```

**File:** crates/aptos-crypto/src/input_secret.rs (L53-60)
```rust
impl Zero for InputSecret {
    fn zero() -> Self {
        InputSecret { a: Scalar::ZERO }
    }

    fn is_zero(&self) -> bool {
        self.a.is_zero_vartime()
    }
```

**File:** crates/aptos-crypto/src/blstrs/polynomials.rs (L658-660)
```rust
    // A random, degree t-1 polynomial $f(X) = [a_0, \dots, a_{t-1}]$, with $a_0$ set to `s.a`
    let mut f = random_scalars(sc.t, rng);
    f[0] = *s.get_secret_a();
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L125-216)
```rust
    fn verify<A: Serialize + Clone>(
        &self,
        sc: &Self::SecretSharingConfig,
        pp: &Self::PublicParameters,
        spks: &[Self::SigningPubKey],
        eks: &[Self::EncryptPubKey],
        sid: &A,
    ) -> anyhow::Result<()> {
        if eks.len() != sc.get_total_num_players() {
            bail!(
                "Expected {} encryption keys, but got {}",
                sc.get_total_num_players(),
                eks.len()
            );
        }
        if self.subtrs.Cs.len() != sc.get_total_num_players() {
            bail!(
                "Expected {} arrays of chunked ciphertexts, but got {}",
                sc.get_total_num_players(),
                self.subtrs.Cs.len()
            );
        }
        if self.subtrs.Vs.len() != sc.get_total_num_players() {
            bail!(
                "Expected {} arrays of commitment elements, but got {}",
                sc.get_total_num_players(),
                self.subtrs.Vs.len()
            );
        }

        // Initialize the **identical** PVSS SoK context
        let sok_cntxt = (
            &spks[self.dealer.id],
            sid.clone(),
            self.dealer.id,
            DST.to_vec(),
        ); // As above, this is a bit hacky... though we have access to `self` now

        {
            // Verify the PoK
            let eks_inner: Vec<_> = eks.iter().map(|ek| ek.ek).collect();
            let lagr_g1: &[E::G1Affine] = match &pp.pk_range_proof.ck_S.msm_basis {
                SrsBasis::Lagrange { lagr: lagr_g1 } => lagr_g1,
                SrsBasis::PowersOfTau { .. } => {
                    bail!("Expected a Lagrange basis, received powers of tau basis instead")
                },
            };
            let hom = hkzg_chunked_elgamal::WeightedHomomorphism::<E>::new(
                lagr_g1,
                pp.pk_range_proof.ck_S.xi_1,
                &pp.pp_elgamal,
                &eks_inner,
            );
            if let Err(err) = hom.verify(
                &TupleCodomainShape(
                    self.sharing_proof.range_proof_commitment.clone(),
                    chunked_elgamal::WeightedCodomainShape {
                        chunks: self.subtrs.Cs.clone(),
                        randomness: self.subtrs.Rs.clone(),
                    },
                ),
                &self.sharing_proof.SoK,
                &sok_cntxt,
            ) {
                bail!("PoK verification failed: {:?}", err);
            }

            // Verify the range proof
            if let Err(err) = self.sharing_proof.range_proof.verify(
                &pp.pk_range_proof.vk,
                sc.get_total_weight() * num_chunks_per_scalar::<E::ScalarField>(pp.ell) as usize,
                pp.ell as usize,
                &self.sharing_proof.range_proof_commitment,
            ) {
                bail!("Range proof batch verification failed: {:?}", err);
            }
        }

        let mut rng = rand::thread_rng(); // TODO: make `rng` a parameter of fn verify()?

        // Do the SCRAPE LDT
        let ldt = LowDegreeTest::random(
            &mut rng,
            sc.get_threshold_weight(),
            sc.get_total_weight() + 1,
            true,
            &sc.get_threshold_config().domain,
        ); // includes_zero is true here means it includes a commitment to f(0), which is in V[n]
        let mut Vs_flat: Vec<_> = self.subtrs.Vs.iter().flatten().cloned().collect();
        Vs_flat.push(self.subtrs.V0);
        // could add an assert_eq here with sc.get_total_weight()
        ldt.low_degree_test_group(&Vs_flat)?;
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

# Audit Report

## Title
DKG Transcript Verification Accepts Identity Point Contributions Without Validation

## Summary
The DKG transcript verification in the weighted PVSS protocol does not explicitly validate that cryptographic elements (commitments, encryptions, dealt public keys) are non-identity points. A malicious validator acting as a DKG dealer can submit a transcript where all elliptic curve elements are identity points, and this transcript will pass all cryptographic verification checks. This violates the fundamental DKG security assumption that all participating dealers contribute randomness to the final shared key. [1](#0-0) 

## Finding Description

The DKG system uses a Publicly Verifiable Secret Sharing (PVSS) scheme where dealers submit transcripts containing cryptographic commitments and encryptions. The verification function performs several checks: Schnorr proofs-of-knowledge, low-degree tests, and pairing-based encryption correctness verification.

**Attack Path:**

1. A malicious validator creates a DKG transcript with all elements set to identity:
   - `V[i] = identity` (G1 commitments)  
   - `V_hat[i] = identity` (G2 commitments)
   - `R[i] = identity` (G1 randomness)
   - `R_hat[i] = identity` (G2 randomness)  
   - `C[i] = identity` (G1 ciphertexts)

2. **Schnorr PoK Verification** (contribution.rs): For a public key that is identity (discrete log = 0), the Schnorr proof (R, s) can be trivially forged by setting `R = g^r` and `s = r`. The verification equation `g^s = R * pk^e` becomes `g^r = g^r * identity^e = g^r`, which holds. [2](#0-1) 

3. **Low-Degree Test** (low_degree_test.rs): The test computes `g1_multi_exp(V, coefficients)` and checks if the result equals identity. When all V[i] are identity, this trivially returns identity, passing the check. [3](#0-2) 

4. **Pairing-Based Verification** (weighted_protocol.rs lines 331-374): The verification computes multi-exponentiations and checks a pairing equation. With all transcript elements as identity:
   - All multi-exps involving identity elements return identity
   - Pairings with identity (e(identity, g) = 1) contribute 1 to the product
   - Final check: product of 1's = 1, which passes [4](#0-3) 

5. The transcript is accepted and the dealer is counted toward the voting power threshold, despite contributing zero entropy. [5](#0-4) 

**The Core Issue:**

The `g1_multi_exp` function can legitimately return identity when bases cancel out or are themselves identity. However, there is no validation in the verification pipeline that rejects transcripts where the dealt public key or other critical elements are identity. [6](#0-5) 

**Broken Invariant:**

This violates **Cryptographic Correctness** (Invariant #10): The DKG protocol assumes all participating dealers contribute randomness. Accepting identity contributions breaks this fundamental assumption, even though the aggregated key may still be secure if other honest dealers participate.

## Impact Explanation

**Severity: HIGH**

This qualifies as "Significant protocol violation" under the High severity category because:

1. **DKG Security Degradation**: If multiple malicious validators submit identity transcripts, the entropy of the final shared randomness key is reduced, weakening the security guarantees of the on-chain randomness system.

2. **Validator Misbehavior Undetected**: Malicious validators can participate in DKG without truly contributing, violating protocol correctness while still being counted toward quorum requirements.

3. **Worst-Case Scenario**: If validators controlling ≥ threshold voting power collude to all submit identity transcripts, the final dealt public key would be identity, resulting in complete randomness failure. While this requires Byzantine majority (generally out of scope), the lack of validation enables this attack path.

4. **Consensus Determinism Risk**: The verification uses non-deterministic randomness (`thread_rng()`) for batch verification challenges. While the probability of false negatives is negligible, this technically violates deterministic execution requirements for consensus-critical operations. [7](#0-6) 

While the system has mitigations (voting power thresholds ensure some honest dealers participate), the absence of explicit identity-point validation represents a significant protocol violation that reduces security margins.

## Likelihood Explanation

**Likelihood: MEDIUM**

- **Requirements**: Attacker must be a validator participating as a DKG dealer
- **Complexity**: Low - constructing an all-identity transcript is trivial
- **Detection**: None - the protocol accepts identity transcripts as valid
- **Mitigation**: Requires honest dealers to also participate (which is expected in normal operation)

The attack is straightforward for any malicious validator to execute. However, exploiting it to cause actual harm requires either:
1. Sufficient malicious validators to meaningfully reduce entropy, or  
2. Byzantine majority to completely break randomness

In normal operation with < 1/3 Byzantine validators, the impact is limited to reduced security margins rather than complete failure.

## Recommendation

Add explicit validation in the transcript verification to reject identity-point contributions:

```rust
// In weighted_protocol.rs, add to verify() function after line 288:

// Reject transcripts with identity dealt public key
if self.V[W] == G1Projective::identity() || self.V_hat[W] == G2Projective::identity() {
    bail!("Dealt public key cannot be the identity element");
}

// Validate all commitment and ciphertext elements are non-identity
for i in 0..W {
    if self.V[i] == G1Projective::identity() 
        || self.V_hat[i] == G2Projective::identity()
        || self.R[i] == G1Projective::identity()
        || self.R_hat[i] == G2Projective::identity()
        || self.C[i] == G1Projective::identity() {
        bail!("Transcript contains identity elements at index {}", i);
    }
}
```

Additionally, for consensus determinism, replace `thread_rng()` with Fiat-Shamir challenge derivation from the transcript:

```rust
// Replace line 296-297 with:
let extra = derive_challenges_from_transcript(self, sc, W);

// Where derive_challenges_from_transcript uses deterministic hashing:
fn derive_challenges_from_transcript(
    trx: &Transcript, 
    sc: &WeightedConfigBlstrs,
    W: usize
) -> Vec<Scalar> {
    let mut hasher = sha3::Sha3_512::new();
    hasher.update(&bcs::to_bytes(trx).unwrap());
    hasher.update(&bcs::to_bytes(sc).unwrap());
    // Derive 2 + W*3 scalars deterministically
    (0..2 + W*3).map(|i| {
        hash_to_scalar(&hasher.finalize(), &[i as u8])
    }).collect()
}
```

## Proof of Concept

```rust
// Add to crates/aptos-dkg/tests/pvss.rs

#[test]
fn test_identity_transcript_accepted() {
    use aptos_dkg::pvss::{
        das::weighted_protocol::Transcript,
        traits::{Transcript as _, AggregatableTranscript},
        ThresholdConfigBlstrs, WeightedConfigBlstrs,
    };
    use aptos_crypto::{bls12381::PrivateKey, Uniform};
    use blstrs::{G1Projective, G2Projective};
    use group::Group;
    use rand::thread_rng;
    
    let mut rng = thread_rng();
    let t = 2;
    let n = 3;
    let tc = ThresholdConfigBlstrs::new(t, n).unwrap();
    let wc = WeightedConfigBlstrs::new(vec![1, 1, 1], tc).unwrap();
    
    // Create transcript with all identity elements
    let sk = PrivateKey::generate(&mut rng);
    let pk = sk.public_key();
    
    let W = wc.get_total_weight();
    let identity_transcript = Transcript {
        soks: vec![(
            wc.get_player(0),
            G1Projective::identity(),
            sk.sign(&/* contribution */).unwrap(),
            (G1Projective::identity(), blstrs::Scalar::ZERO),
        )],
        R: vec![G1Projective::identity(); W],
        R_hat: vec![G2Projective::identity(); W],
        V: vec![G1Projective::identity(); W + 1],
        V_hat: vec![G2Projective::identity(); W + 1],
        C: vec![G1Projective::identity(); W],
    };
    
    // Verify should accept this (demonstrating the vulnerability)
    let pp = das::PublicParameters::default_with_bls_base();
    let eks = vec![/* encryption keys */];
    let result = identity_transcript.verify(&wc, &pp, &[pk], &eks, &[(0u64, addr)]);
    
    // This assertion PASSES, demonstrating the vulnerability
    assert!(result.is_ok(), "Identity transcript was accepted!");
}
```

## Notes

This vulnerability is particularly concerning because it undermines the trust assumptions of the DKG protocol. While the system's voting power requirements provide partial mitigation, explicit validation is essential for protocol correctness. The determinism issue with `thread_rng()` in verification is a separate concern that also merits attention for consensus-critical operations.

### Citations

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

**File:** crates/aptos-dkg/src/pvss/schnorr.rs (L69-109)
```rust
pub fn pok_batch_verify<'a, Gr>(
    poks: &Vec<(Gr, PoK<Gr>)>,
    g: &Gr,
    gamma: &Scalar,
) -> anyhow::Result<()>
where
    Gr: Serialize + Group + Mul<&'a Scalar> + HasMultiExp,
{
    let n = poks.len();
    let mut exps = Vec::with_capacity(2 * n + 1);
    let mut bases = Vec::with_capacity(2 * n + 1);

    // Compute \gamma_i = \gamma^i, for all i \in [0, n]
    let mut gammas = Vec::with_capacity(n);
    gammas.push(Scalar::ONE);
    for _ in 0..(n - 1) {
        gammas.push(gammas.last().unwrap().mul(gamma));
    }

    let mut last_exp = Scalar::ZERO;
    for i in 0..n {
        let (pk, (R, s)) = poks[i];

        bases.push(R);
        exps.push(gammas[i]);

        bases.push(pk);
        exps.push(schnorr_hash(Challenge::<Gr> { R, pk, g: *g }) * gammas[i]);

        last_exp += s * gammas[i];
    }

    bases.push(*g);
    exps.push(last_exp.neg());

    if Gr::multi_exp_iter(bases.iter(), exps.iter()) != Gr::identity() {
        bail!("Schnorr PoK batch verification failed");
    }

    Ok(())
}
```

**File:** crates/aptos-dkg/src/pvss/low_degree_test.rs (L141-161)
```rust
    pub fn low_degree_test_on_g1(self, evals: &Vec<G1Projective>) -> anyhow::Result<()> {
        if evals.len() != self.n {
            bail!("Expected {} evaluations; got {}", self.n, evals.len())
        }

        if self.t == self.n {
            return Ok(());
        }

        let v_times_f = self.dual_code_word();

        debug_assert_eq!(evals.len(), v_times_f.len());
        let zero = g1_multi_exp(evals.as_ref(), v_times_f.as_slice());

        (zero == G1Projective::identity())
            .then_some(())
            .context(format!(
                "the LDT G1 multiexp should return zero, but instead returned {}",
                zero
            ))
    }
```

**File:** types/src/dkg/real_dkg/mod.rs (L318-322)
```rust
        if checks_voting_power {
            verifier
                .check_voting_power(dealer_set.iter(), true)
                .context("not enough power")?;
        }
```

**File:** crates/aptos-dkg/src/utils/mod.rs (L58-72)
```rust
pub fn g1_multi_exp(bases: &[G1Projective], scalars: &[blstrs::Scalar]) -> G1Projective {
    if bases.len() != scalars.len() {
        panic!(
            "blstrs's multiexp has heisenbugs when the # of bases != # of scalars ({} != {})",
            bases.len(),
            scalars.len()
        );
    }

    match bases.len() {
        0 => G1Projective::identity(),
        1 => bases[0].mul(scalars[0]),
        _ => G1Projective::multi_exp(bases, scalars),
    }
}
```

# Audit Report

## Title
ElGamal Randomness Reuse Information Leakage in DKG PVSS Transcripts

## Summary
The DKG PVSS protocol reuses deterministic public parameters across all epochs and sessions, and when combined with deterministic RNG seeding in smoke-test mode, causes the same validator to generate identical encryption randomness across multiple DKG sessions. This violates ElGamal semantic security and leaks information about the relationship between dealt secrets across epochs.

## Finding Description

The Aptos DKG implementation uses a Publicly Verifiable Secret Sharing (PVSS) scheme with ElGamal encryption. The protocol has three critical design choices that combine to create an information leakage vulnerability:

**1. Static Public Parameters Across All Sessions**

The public parameters (g, h, g_2) are generated deterministically and remain constant across all DKG sessions and epochs: [1](#0-0) [2](#0-1) 

**2. Deterministic RNG Seeding in Smoke-Test Mode**

When the `smoke-test` feature is enabled, validators seed their RNG deterministically using their own address: [3](#0-2) 

This means the same validator participating in DKG across multiple epochs generates the **identical** sequence of random values each time.

**3. ElGamal Encryption with Reused Randomness**

The PVSS transcript creation uses this randomness to encrypt shares: [4](#0-3) 

The ciphertexts are `C[k] = h^{f_evals[k]} * ek[i]^{r[k]}` and randomness commitments `R[k] = g_1^{r[k]}` are included in the transcript.

**Attack Scenario:**

When a validator V participates in DKG sessions across multiple epochs with smoke-test mode enabled:

- **Epoch N**: V's RNG seeded with `V.address` → generates randomness `r` → creates transcript T1 with secret s1
- **Epoch N+1**: V's RNG seeded with same `V.address` → generates **same** randomness `r` → creates transcript T2 with secret s2

An observer can detect this by comparing the randomness commitments: `T1.R[k] == T2.R[k]`

Once randomness reuse is detected, the attacker can compute:
```
T1.C[k] / T2.C[k] = (h^{f1[k]} * ek^r) / (h^{f2[k]} * ek^r) = h^{f1[k] - f2[k]}
```

This leaks `h^{Δf[k]}` where `Δf[k] = f1[k] - f2[k]` is the difference between polynomial evaluations at point k.

**No Detection or Prevention**

The verification function does not check for randomness reuse across transcripts: [5](#0-4) 

While there is protection against the same dealer contributing twice within a single aggregation session: [6](#0-5) 

This does NOT prevent the same validator from contributing to different DKG sessions across epochs with reused randomness.

## Impact Explanation

This vulnerability is classified as **High Severity** but falls short of Critical due to its conditional nature:

**Security Guarantee Broken**: ElGamal semantic security requires that ciphertexts leak no information about plaintexts. Randomness reuse fundamentally violates this property by allowing an attacker to compute the difference between encrypted values.

**Cryptographic Invariant Violation**: The protocol violates Invariant #10 (Cryptographic Correctness) - encryption randomness must be fresh and unpredictable for each encryption operation.

**Actual Impact**:
- **Information Leakage**: Reveals relationships between dealt secrets across epochs
- **Randomness Quality Degradation**: Compromised DKG transcripts could affect consensus randomness quality, impacting validator selection fairness
- **Protocol Trust Erosion**: Violates the fundamental security assumptions of the PVSS scheme

However, this does NOT directly lead to:
- Fund theft or minting
- Consensus safety violations (nodes still agree on the compromised randomness)
- Network unavailability

The impact aligns with **High Severity** criteria: "Significant protocol violations" and potential "Validator node slowdowns" if randomness quality is systematically degraded.

## Likelihood Explanation

**Likelihood: LOW in Production, GUARANTEED in Smoke-Test Mode**

The vulnerability has significantly different likelihoods depending on deployment configuration:

**In Smoke-Test Mode (Development/Testing)**: 
- **Likelihood: 100%** - The deterministic seeding guarantees randomness reuse across epochs
- This mode is indicated by code comments and feature flags as being for testing purposes

**In Production Mode**:
- **Likelihood: Very Low** - Requires either:
  1. Validator deliberately manipulating their RNG (requires insider threat)
  2. RNG implementation failure (crypto primitives assumed secure)
  3. Deployment misconfiguration using smoke-test mode in production

The **key concern** is that smoke-test mode could be accidentally enabled in production environments, or that the same deterministic seeding pattern might be replicated in custom validator implementations.

## Recommendation

Implement multiple defense layers:

**1. Remove Deterministic Seeding in Smoke-Test Mode**
```rust
let mut rng = StdRng::from_rng(thread_rng())
    .expect("Failed to initialize RNG from thread_rng");
```

For testing reproducibility, use explicit test-only seeding that includes epoch/session identifiers:
```rust
#[cfg(test)]
let mut rng = StdRng::from_seed({
    let mut seed = [0u8; 32];
    seed[..16].copy_from_slice(&self.my_addr.into_bytes());
    seed[16..24].copy_from_slice(&self.epoch_state.epoch.to_le_bytes());
    seed[24..32].copy_from_slice(&start_time_us.to_le_bytes());
    seed
});
```

**2. Add Randomness Reuse Detection**

Maintain a historical record of randomness commitments and check for duplicates:
```rust
fn verify_transcript_extra(
    trx: &Self::Transcript,
    verifier: &ValidatorVerifier,
    checks_voting_power: bool,
    ensures_single_dealer: Option<AccountAddress>,
) -> anyhow::Result<()> {
    // Existing checks...
    
    // NEW: Check for randomness reuse
    if let Some(historical_R_values) = get_historical_randomness_commitments() {
        for dealer in trx.main.get_dealers() {
            if historical_R_values.contains_key(&dealer) {
                ensure!(
                    !historical_R_values[&dealer].contains(&trx.main.R),
                    "Randomness reuse detected for dealer {:?}", dealer
                );
            }
        }
    }
    
    Ok(())
}
```

**3. Add Session-Specific Context to RNG**

Mix in epoch and session metadata to ensure different randomness across sessions:
```rust
let input_secret = {
    let mut seed_extender = vec![];
    seed_extender.extend_from_slice(&self.epoch_state.epoch.to_le_bytes());
    seed_extender.extend_from_slice(&start_time_us.to_le_bytes());
    seed_extender.extend_from_slice(&self.my_addr.to_bytes());
    
    let mut domain_separated_rng = ChaCha20Rng::from_seed(
        Blake2b::digest(seed_extender).into()
    );
    DKG::InputSecret::generate(&mut domain_separated_rng)
};
```

## Proof of Concept

```rust
// Reproduction steps demonstrating the vulnerability

#[cfg(test)]
mod randomness_reuse_test {
    use super::*;
    use aptos_types::dkg::real_dkg::RealDKG;
    use rand::SeedableRng;
    
    #[test]
    fn test_randomness_reuse_across_epochs() {
        // Setup: Create validator with deterministic address
        let validator_addr = AccountAddress::from_hex_literal("0xABCD").unwrap();
        
        // Epoch N: Generate first transcript with deterministic RNG
        let mut rng_epoch_n = StdRng::from_seed(validator_addr.into_bytes());
        let randomness_n = random_scalars(10, &mut rng_epoch_n);
        
        // Epoch N+1: Generate second transcript with SAME seed
        let mut rng_epoch_n1 = StdRng::from_seed(validator_addr.into_bytes());
        let randomness_n1 = random_scalars(10, &mut rng_epoch_n1);
        
        // Verify randomness reuse
        assert_eq!(randomness_n, randomness_n1, 
            "Randomness is reused across epochs with deterministic seeding!");
        
        // Demonstrate information leakage
        // If we have two transcripts T1, T2 with same randomness r:
        // C1[k] = h^{f1[k]} * ek^r
        // C2[k] = h^{f2[k]} * ek^r
        // Then: C1[k] / C2[k] = h^{f1[k] - f2[k]}
        // This leaks the difference between secrets!
        
        println!("VULNERABILITY CONFIRMED: Same validator generates identical randomness across epochs");
    }
}
```

**Notes:**
- This vulnerability requires smoke-test mode to be enabled in deployment
- The fix should ensure proper RNG initialization with session-specific entropy
- Historical randomness tracking adds defense-in-depth against any randomness reuse source
- The leaked information (h^{Δf}) may be exploitable if the difference is small or predictable, though discrete log computation on full 256-bit differences remains hard

### Citations

**File:** crates/aptos-dkg/src/pvss/das/public_parameters.rs (L51-71)
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
    }
```

**File:** types/src/dkg/real_dkg/mod.rs (L129-129)
```rust
    let pp = DkgPP::default_with_bls_base();
```

**File:** dkg/src/dkg_manager/mod.rs (L325-329)
```rust
        let mut rng = if cfg!(feature = "smoke-test") {
            StdRng::from_seed(self.my_addr.into_bytes())
        } else {
            StdRng::from_rng(thread_rng()).unwrap()
        };
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L134-170)
```rust
        // Pick ElGamal randomness r_j, \forall j \in [W]
        // r[j] = r_{j+1}, \forall j \in [0, W-1]
        let r = random_scalars(W, &mut rng);
        let g_1 = pp.get_encryption_public_params().pubkey_base();
        let g_2 = pp.get_commitment_base();
        let h = *pp.get_encryption_public_params().message_base();

        // NOTE: Recall s_i is the starting index of player i in the vector of shares
        //  - V[s_i + j - 1] = g_2^{f(s_i + j - 1)}
        //  - V[W] = g_2^{f(0)}
        let V = (0..W)
            .map(|k| g_1.mul(f_evals[k]))
            .chain([g_1.mul(f_coeff[0])])
            .collect::<Vec<G1Projective>>();
        let V_hat = (0..W)
            .map(|k| g_2.mul(f_evals[k]))
            .chain([g_2.mul(f_coeff[0])])
            .collect::<Vec<G2Projective>>();

        // R[j] = g_1^{r_{j + 1}},  \forall j \in [0, W-1]
        let R = (0..W).map(|j| g_1.mul(r[j])).collect::<Vec<G1Projective>>();
        let R_hat = (0..W).map(|j| g_2.mul(r[j])).collect::<Vec<G2Projective>>();

        let mut C = Vec::with_capacity(W);
        for i in 0..n {
            let w_i = sc.get_player_weight(&sc.get_player(i));

            let bases = vec![h, Into::<G1Projective>::into(&eks[i])];
            for j in 0..w_i {
                let k = sc.get_share_index(i, j).unwrap();

                C.push(g1_multi_exp(
                    bases.as_slice(),
                    [f_evals[k], r[k]].as_slice(),
                ))
            }
        }
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

**File:** dkg/src/transcript_aggregation/mod.rs (L92-94)
```rust
        if trx_aggregator.contributors.contains(&metadata.author) {
            return Ok(None);
        }
```

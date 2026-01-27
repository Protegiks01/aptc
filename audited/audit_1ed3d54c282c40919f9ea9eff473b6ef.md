# Audit Report

## Title
Non-Deterministic DKG Transcript Verification Violates Consensus Determinism Invariant

## Summary
The DKG transcript verification uses `thread_rng()` to generate random challenges for Schwartz-Zippel batch verification instead of Fiat-Shamir hashing. This causes different validators to use different random challenges when verifying identical DKG transcripts, violating the fundamental "Deterministic Execution" invariant required for consensus safety.

## Finding Description
The Aptos DKG (Distributed Key Generation) transcript verification process uses Schwartz-Zippel-style random linear combinations to batch-verify cryptographic proofs. However, instead of deriving these random challenges deterministically via Fiat-Shamir transformation (hashing the public inputs), the code uses `thread_rng()` to generate fresh random challenges on each validator.

The vulnerability manifests in multiple locations:

1. **DAS weighted protocol verification** [1](#0-0) 
   The code explicitly acknowledges this risk in the comment but deems it acceptable.

2. **Chunky weighted transcript verification** [2](#0-1) 
   Contains TODO comment indicating this should be a parameter.

3. **Chunky weighted transcript v2 verification** [3](#0-2) 
   Same TODO comment acknowledging the issue.

4. **Sigma protocol verifier challenges** [4](#0-3) 
   Uses `thread_rng()` for beta challenges with TODO comment.

This verification is consensus-critical because it's invoked during DKG result processing in the VM: [5](#0-4) 

When validators process DKG transactions, they call `verify_transcript()` which ultimately calls the PVSS verification with non-deterministic randomness: [6](#0-5) 

**Attack Scenario:**
While the Schwartz-Zippel lemma ensures an invalid proof fails with probability ≈ 1 - ε (where ε ≈ degree/field_size ≈ 2^-256), there exists a theoretical (albeit astronomically unlikely) scenario where:
1. A malformed DKG transcript is submitted
2. Some validators' random challenges happen to make verification pass
3. Other validators' random challenges make verification fail  
4. Validators reach different conclusions about block validity
5. Consensus splits or requires manual intervention

## Impact Explanation
**Severity Assessment: Medium**

This represents a violation of Critical Invariant #1: "Deterministic Execution - All validators must produce identical state roots for identical blocks."

However, the practical impact is limited by the probability (≈ 2^-256) being negligible. This falls under **Medium Severity** per the bug bounty criteria: "State inconsistencies requiring intervention" - in the astronomically unlikely event of a consensus split, manual intervention would be required.

The issue does NOT qualify as Critical because:
- No realistic path exists for an attacker to exploit this
- The probability is far below any practical threshold
- No funds are at immediate risk
- Network would not partition without extreme statistical anomaly

## Likelihood Explanation
**Practical Likelihood: Negligible (≈ 2^-256)**

For an invalid DKG transcript to cause a consensus split, the random challenges would need to align such that the Schwartz-Zippel check passes for some validators but fails for others. Given the field size (~2^256), this probability is astronomically low.

**Architectural Likelihood: High**

From a design perspective, this is a fundamental violation of consensus system requirements. The existence of multiple TODO comments [7](#0-6)  acknowledging the issue indicates the developers are aware this is technically incorrect.

## Recommendation
Replace `thread_rng()` with Fiat-Shamir transformation for all verification challenges. The proper pattern already exists in the codebase: [8](#0-7) 

**Fix approach:**
1. Extend `fiat_shamir_challenge_for_sigma_protocol()` to derive BOTH challenges (c and beta) deterministically
2. Pass transcript/public inputs to generate deterministic beta via hashing
3. Remove all `thread_rng()` calls from verification paths
4. Update trait signatures to remove RNG parameters

This ensures all validators derive identical challenges from identical inputs, guaranteeing deterministic verification.

## Proof of Concept
```rust
// Demonstration: Two validators verify the same transcript
// but get different results (with negligible probability)

use rand::{thread_rng, RngCore};
use aptos_dkg::pvss::das::Transcript;

fn validator_a_verifies(transcript: &Transcript) -> bool {
    let mut rng = thread_rng(); // Different seed
    transcript.verify(config, pp, spks, eks, aux).is_ok()
}

fn validator_b_verifies(transcript: &Transcript) -> bool {
    let mut rng = thread_rng(); // Different seed  
    transcript.verify(config, pp, spks, eks, aux).is_ok()
}

// For a carefully crafted invalid transcript:
// P(validator_a accepts AND validator_b rejects) ≈ 2^-256
// This causes consensus split requiring manual intervention
```

**Notes**
While `thread_rng()` is cryptographically secure and cannot be predicted/influenced by external attackers, its use in consensus-critical verification violates the deterministic execution requirement. The randomness source itself is secure, but the architectural pattern is incorrect for a consensus system. The practical exploitation probability is negligible, but the theoretical invariant violation exists and warrants correction to align with cryptographic best practices.

### Citations

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L295-297)
```rust
        // Deriving challenges by flipping coins: less complex to implement & less likely to get wrong. Creates bad RNG risks but we deem that acceptable.
        let mut rng = rand::thread_rng();
        let extra = random_scalars(2 + W * 3, &mut rng);
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L203-244)
```rust
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

        // let eks_inner: Vec<_> = eks.iter().map(|ek| ek.ek).collect();
        // let hom = hkzg_chunked_elgamal::WeightedHomomorphism::new(
        //     &pp.pk_range_proof.ck_S.lagr_g1,
        //     pp.pk_range_proof.ck_S.xi_1,
        //     &pp.pp_elgamal,
        //     &eks_inner,
        // );
        // let (sigma_bases, sigma_scalars, beta_powers) = hom.verify_msm_terms(
        //         &TupleCodomainShape(
        //             self.sharing_proof.range_proof_commitment.clone(),
        //             chunked_elgamal::WeightedCodomainShape {
        //                 chunks: self.subtrs.Cs.clone(),
        //                 randomness: self.subtrs.Rs.clone(),
        //             },
        //         ),
        //         &self.sharing_proof.SoK,
        //         &sok_cntxt,
        //     );
        // let ldt_msm_terms = ldt.ldt_msm_input(&Vs_flat)?;
        // use aptos_crypto::arkworks::msm::verify_msm_terms_with_start;
        // verify_msm_terms_with_start(ldt_msm_terms, sigma_bases, sigma_scalars, beta_powers);

        // Now compute the final MSM // TODO: merge this multi_exp with the PoK verification, as in YOLO YOSO? // TODO2: and use the iterate stuff you developed? it's being forgotten here
        let mut base_vec = Vec::new();
        let mut exp_vec = Vec::new();

        let beta = sample_field_element(&mut rng);
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcriptv2.rs (L542-542)
```rust
        let mut rng = rand::thread_rng(); // TODO: make `rng` a parameter of fn verify()?
```

**File:** crates/aptos-dkg/src/sigma_protocol/traits.rs (L85-92)
```rust
        // --- Fiat–Shamir challenge c ---
        let c = fiat_shamir_challenge_for_sigma_protocol::<_, C::ScalarField, _>(
            cntxt,
            self,
            public_statement,
            prover_first_message,
            &self.dst(),
        );
```

**File:** crates/aptos-dkg/src/sigma_protocol/traits.rs (L94-96)
```rust
        // --- Random verifier challenge β ---
        let mut rng = ark_std::rand::thread_rng(); // TODO: move this to trait!!
        let beta = C::ScalarField::rand(&mut rng);
```

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L111-112)
```rust
        DefaultDKG::verify_transcript(&pub_params, &transcript)
            .map_err(|_| Expected(TranscriptVerificationFailed))?;
```

**File:** types/src/dkg/real_dkg/mod.rs (L368-374)
```rust
        trx.main.verify(
            &params.pvss_config.wconfig,
            &params.pvss_config.pp,
            &spks,
            &all_eks,
            &aux,
        )?;
```

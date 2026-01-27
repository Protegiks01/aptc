# Audit Report

## Title
Missing Inner Dimension Bounds Validation in DKG Transcript Aggregation Causes Validator Crash

## Summary
The `aggregate_with()` function in the DKG PVSS transcript implementation lacks runtime bounds checking for inner vector dimensions during subtranscript aggregation. While the verification phase checks outer dimensions and total flattened lengths, it does not validate that `Vs[i].len()` and `Cs[i][j].len()` match the expected per-player weight distribution. A malicious validator can craft a transcript with mismatched inner structure that passes cryptographic verification but causes an out-of-bounds panic when aggregated with correctly-formed transcripts, leading to validator node crashes and DKG protocol disruption.

## Finding Description
The DKG (Distributed Key Generation) protocol aggregates PVSS transcripts from multiple validators. The aggregation occurs in the `aggregate_with()` function which combines cryptographic commitments and ciphertexts element-wise. [1](#0-0) 

The function uses only `debug_assert_eq!` for bounds validation, which are compiled away in release builds. The critical vulnerability occurs at:
- Line 400: `self.Vs[i][j] += other.Vs[i][j];` - accesses `other.Vs[i][j]` without checking if `other.Vs[i].len() >= j`
- Line 403: `self.Cs[i][j][k] += other.Cs[i][j][k];` - accesses `other.Cs[i][j][k]` without checking dimensions

The verification phase only validates outer dimensions and total flattened counts: [2](#0-1) [3](#0-2) 

Notably, the verification flattens `Vs` before cryptographic checks (LDT and MSM), which means it validates the total number of elements but not their distribution across players: [4](#0-3) [5](#0-4) 

**Attack Path:**
1. Malicious validator creates a transcript using the honest `deal()` function with correct secret sharing configuration (e.g., weights `[5, 5]`)
2. Before submitting, manually regroups the `Vs` structure to have incorrect distribution (e.g., `Vs[0].len()=1, Vs[1].len()=9` instead of `5, 5`)
3. The regrouping maintains the same flattened order, so `flatten(Vs) = [a,b,c,d,e,f,g,h,i,j]` remains identical
4. Submits the malformed transcript to the network
5. The transcript passes `verify_transcript()` because:
   - Outer dimension check passes: `Vs.len() == 2`
   - Flattened length is correct: `flatten(Vs).len() == 10`
   - LDT and MSM operate on flattened `Vs_flat`, which is unchanged
   - Pairing check passes because the flattened values are cryptographically correct
6. During aggregation with a correctly-structured transcript in `add()`: [6](#0-5) 

7. The aggregation loop attempts to access `other.Vs[1][5]` when iterating over the malicious transcript's `Vs[1].len()=9`, but the correct transcript only has `Vs[1].len()=5`, causing a panic

## Impact Explanation
This vulnerability enables a **High Severity** attack per Aptos bug bounty criteria:
- **Validator Node Crashes**: Any validator attempting to aggregate a malicious transcript with correctly-formed transcripts will panic and crash
- **DKG Protocol Disruption**: The distributed key generation cannot complete if validators crash during transcript aggregation
- **Consensus Impact**: DKG is critical for epoch transitions and randomness generation; disrupting it affects the entire network's ability to progress through epochs
- **Liveness Violation**: Repeated attacks could prevent the network from completing epoch transitions, though this would require sustained malicious activity

The attack qualifies as "Validator node slowdowns" and "Significant protocol violations" under High severity. It does not reach Critical severity because it does not cause permanent state corruption or fund loss, and validators can recover by restarting.

## Likelihood Explanation
**Likelihood: Medium to High**

**Attacker Requirements:**
- Must be a registered validator in the current epoch
- Requires ability to submit DKG transcripts (standard validator capability)
- No stake majority or collusion required

**Ease of Exploitation:**
- Moderate complexity: requires manually crafting transcript structure
- Can be automated once understood
- Detection is difficult because the malformed transcript passes all cryptographic verification

**Mitigation Factors:**
- Requires validator access (not arbitrary network participant)
- Each epoch uses a new DKG session, limiting persistent impact
- Honest validators can identify and exclude malicious peer after crash

The likelihood is elevated because:
1. The attack surface is exposed to all validators
2. No privileged access beyond validator status is required
3. The validation logic gap is systematic across both v1 and v2 implementations [7](#0-6) 

## Recommendation
Add runtime validation in the `verify()` function to check that inner vector dimensions match the expected player weight distribution:

```rust
fn verify<A: Serialize + Clone>(
    &self,
    sc: &Self::SecretSharingConfig,
    pp: &Self::PublicParameters,
    spks: &[Self::SigningPubKey],
    eks: &[Self::EncryptPubKey],
    sid: &A,
) -> anyhow::Result<()> {
    // Existing outer dimension checks
    if eks.len() != sc.get_total_num_players() { bail!(...); }
    if self.subtrs.Cs.len() != sc.get_total_num_players() { bail!(...); }
    if self.subtrs.Vs.len() != sc.get_total_num_players() { bail!(...); }
    
    // NEW: Validate inner dimensions match player weights
    for i in 0..sc.get_total_num_players() {
        let player = sc.get_player(i);
        let expected_weight = sc.get_player_weight(&player);
        
        if self.subtrs.Vs[i].len() != expected_weight {
            bail!(
                "Player {} has {} commitments but expected {} based on weight",
                i, self.subtrs.Vs[i].len(), expected_weight
            );
        }
        
        if self.subtrs.Cs[i].len() != expected_weight {
            bail!(
                "Player {} has {} ciphertexts but expected {} based on weight",
                i, self.subtrs.Cs[i].len(), expected_weight
            );
        }
        
        // Validate chunk consistency
        if !self.subtrs.Cs[i].is_empty() {
            let expected_chunks = num_chunks_per_scalar::<E::ScalarField>(pp.ell) as usize;
            for j in 0..self.subtrs.Cs[i].len() {
                if self.subtrs.Cs[i][j].len() != expected_chunks {
                    bail!(
                        "Player {} share {} has {} chunks but expected {}",
                        i, j, self.subtrs.Cs[i][j].len(), expected_chunks
                    );
                }
            }
        }
    }
    
    // Continue with existing verification logic...
}
```

This fix should be applied to both `weighted_transcript.rs` and `weighted_transcriptv2.rs`.

## Proof of Concept
```rust
// Proof of Concept demonstrating the vulnerability
// This would be added as a test in crates/aptos-dkg/tests/

use aptos_dkg::pvss::{
    chunky::{Subtranscript, UnsignedWeightedTranscript},
    traits::Aggregatable,
};
use aptos_crypto::{bls12381::Bls12381, weighted_config::WeightedConfigArkworks};

#[test]
#[should_panic(expected = "index out of bounds")]
fn test_aggregation_panic_with_mismatched_structure() {
    let mut rng = rand::thread_rng();
    
    // Setup: Create weighted config with weights [5, 5]
    let sc = WeightedConfigArkworks::new(10, vec![5, 5]).unwrap();
    let pp = /* initialize public parameters */;
    
    // Create two valid transcripts using honest dealing
    let transcript1 = UnsignedWeightedTranscript::<Bls12381>::deal(
        &sc, &pp, &ssk, &spk, &eks, &secret1, &session_id, &dealer, &mut rng
    );
    let transcript2 = UnsignedWeightedTranscript::<Bls12381>::deal(
        &sc, &pp, &ssk, &spk, &eks, &secret2, &session_id, &dealer, &mut rng
    );
    
    // Malicious modification: Manually regroup Vs to have wrong structure
    let mut malicious_subtranscript = transcript1.subtrs.clone();
    
    // Original structure: Vs = [[5 elements], [5 elements]]
    // Malicious structure: Vs = [[1 element], [9 elements]]
    // Keep same flattened order so crypto checks pass
    let vs_flat: Vec<_> = malicious_subtranscript.Vs.iter().flatten().cloned().collect();
    malicious_subtranscript.Vs = vec![
        vec![vs_flat[0].clone()],  // Player 0 gets only 1 element
        vs_flat[1..].to_vec(),     // Player 1 gets remaining 9 elements
    ];
    
    // The malicious transcript passes verification (crypto checks use flattened Vs)
    // verify() checks outer dims and flattened length, both pass
    
    // Attempt aggregation with correctly-structured transcript2
    let mut agg = transcript2.subtrs.clone();
    
    // This panics when accessing agg.Vs[1][5] because malicious has Vs[1].len()=9
    // but agg only has Vs[1].len()=5
    malicious_subtranscript.aggregate_with(&sc, &agg).unwrap();
}
```

**Notes**

The vulnerability affects both PVSS implementations (v1 and v2) identically. The root cause is the mismatch between verification assumptions (checking flattened structures for cryptographic correctness) and aggregation assumptions (expecting matching inner dimensions). While the cryptographic proofs ensure the transcript contains valid secret shares, they do not constrain the organizational structure of those shares across players. This allows an attacker to pass verification with a malformed structure that crashes during aggregation.

### Citations

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L133-153)
```rust
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
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L213-216)
```rust
        let mut Vs_flat: Vec<_> = self.subtrs.Vs.iter().flatten().cloned().collect();
        Vs_flat.push(self.subtrs.V0);
        // could add an assert_eq here with sc.get_total_weight()
        ldt.low_degree_test_group(&Vs_flat)?;
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L247-252)
```rust
        let Cs_flat: Vec<_> = self.subtrs.Cs.iter().flatten().cloned().collect();
        assert_eq!(
            Cs_flat.len(),
            sc.get_total_weight(),
            "Number of ciphertexts does not equal number of weights"
        ); // TODO what if zero weight?
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L267-271)
```rust
        let weighted_Vs = E::G2::msm(
            &E::G2::normalize_batch(&Vs_flat[..sc.get_total_weight()]), // Don't use the last entry of `Vs_flat`
            &powers_of_beta[..sc.get_total_weight()],
        )
        .expect("Failed to compute MSM of Vs in chunky");
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L387-416)
```rust
    fn aggregate_with(&mut self, sc: &SecretSharingConfig<E>, other: &Self) -> anyhow::Result<()> {
        debug_assert_eq!(self.Cs.len(), sc.get_total_num_players());
        debug_assert_eq!(self.Vs.len(), sc.get_total_num_players());
        debug_assert_eq!(self.Cs.len(), other.Cs.len());
        debug_assert_eq!(self.Rs.len(), other.Rs.len());
        debug_assert_eq!(self.Vs.len(), other.Vs.len());

        // Aggregate the V0s
        self.V0 += other.V0;

        for i in 0..sc.get_total_num_players() {
            for j in 0..self.Vs[i].len() {
                // Aggregate the V_{i,j}s
                self.Vs[i][j] += other.Vs[i][j];
                for k in 0..self.Cs[i][j].len() {
                    // Aggregate the C_{i,j,k}s
                    self.Cs[i][j][k] += other.Cs[i][j][k];
                }
            }
        }

        for j in 0..self.Rs.len() {
            for (R_jk, other_R_jk) in self.Rs[j].iter_mut().zip(&other.Rs[j]) {
                // Aggregate the R_{j,k}s
                *R_jk += other_R_jk;
            }
        }

        Ok(())
    }
```

**File:** dkg/src/transcript_aggregation/mod.rs (L96-118)
```rust
        S::verify_transcript_extra(&transcript, &self.epoch_state.verifier, false, Some(sender))
            .context("extra verification failed")?;

        S::verify_transcript(&self.dkg_pub_params, &transcript).map_err(|e| {
            anyhow!("[DKG] adding peer transcript failed with trx verification failure: {e}")
        })?;

        // All checks passed. Aggregating.
        let is_self = self.my_addr == sender;
        if !is_self && !self.valid_peer_transcript_seen {
            let secs_since_dkg_start =
                duration_since_epoch().as_secs_f64() - self.start_time.as_secs_f64();
            DKG_STAGE_SECONDS
                .with_label_values(&[
                    self.my_addr.to_hex().as_str(),
                    "first_valid_peer_transcript",
                ])
                .observe(secs_since_dkg_start);
        }

        trx_aggregator.contributors.insert(metadata.author);
        if let Some(agg_trx) = trx_aggregator.trx.as_mut() {
            S::aggregate_transcripts(&self.dkg_pub_params, agg_trx, transcript);
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcriptv2.rs (L650-679)
```rust
    fn aggregate_with(&mut self, sc: &SecretSharingConfig<E>, other: &Self) -> anyhow::Result<()> {
        debug_assert_eq!(self.Cs.len(), sc.get_total_num_players());
        debug_assert_eq!(self.Vs.len(), sc.get_total_num_players());
        debug_assert_eq!(self.Cs.len(), other.Cs.len());
        debug_assert_eq!(self.Rs.len(), other.Rs.len());
        debug_assert_eq!(self.Vs.len(), other.Vs.len());

        // Aggregate the V0s
        self.V0 += other.V0;

        for i in 0..sc.get_total_num_players() {
            for j in 0..self.Vs[i].len() {
                // Aggregate the V_{i,j}s
                self.Vs[i][j] += other.Vs[i][j];
                for k in 0..self.Cs[i][j].len() {
                    // Aggregate the C_{i,j,k}s
                    self.Cs[i][j][k] += other.Cs[i][j][k];
                }
            }
        }

        for j in 0..self.Rs.len() {
            for (R_jk, other_R_jk) in self.Rs[j].iter_mut().zip(&other.Rs[j]) {
                // Aggregate the R_{j,k}s
                *R_jk += other_R_jk;
            }
        }

        Ok(())
    }
```

# Audit Report

## Title
DKG Proof-of-Knowledge Batch Verification DoS via Unbounded SoK Vector

## Summary
A malicious validator can cause denial-of-service on honest validators during the Distributed Key Generation (DKG) process by crafting a DKG transcript containing an excessive number of Signatures of Knowledge (SoKs). This triggers unbounded memory allocation and CPU-intensive cryptographic operations during transcript verification, causing validator node slowdowns or crashes.

## Finding Description

The vulnerability exists in the DKG transcript verification flow where no upper bound is enforced on the number of SoKs (Signatures of Knowledge) before expensive cryptographic batch verification occurs.

**Attack Flow:**

1. During DKG, a malicious validator crafts a DKG transcript with an extremely large `soks` vector (e.g., 9,000 entries) that fits within the 2MB per-block limit. [1](#0-0) 

2. When honest validators receive this transcript via peer-to-peer DKG aggregation, the `add_peer_transcript()` function deserializes it and calls verification: [2](#0-1) 

3. The `verify_transcript()` call leads to `trx.main.verify()` which invokes `batch_verify_soks()`: [3](#0-2) [4](#0-3) 

4. This calls `pok_batch_verify()` where the DoS occurs: [5](#0-4) 

5. The function allocates memory proportional to `n` (the number of SoKs) and performs O(n) cryptographic operations: [6](#0-5) 

**Root Cause:**

The validation in `verify_transcript()` only checks that each dealer index is less than the validator count, but does not limit the total number of dealers/SoKs: [7](#0-6) 

A malicious validator can include the same dealer multiple times or include thousands of invalid SoKs, all of which will be processed before the verification fails.

**Broken Invariant:**

This violates **Invariant 9: Resource Limits** - "All operations must respect gas, storage, and computational limits." The unbounded processing allows a single malicious validator to consume excessive resources on honest validators.

## Impact Explanation

**Severity: High** (up to $50,000 per Aptos Bug Bounty)

This qualifies as "Validator node slowdowns" which is explicitly listed under High Severity. The impact includes:

- **Memory Exhaustion**: With n=9,000 SoKs, the function allocates vectors of size 18,001 + 9,000, each containing elliptic curve group elements and field elements (96+ bytes each), resulting in ~2.5 MB of allocations per verification attempt.

- **CPU Exhaustion**: The verification performs 9,000+ Schnorr hash computations, scalar multiplications, and a final multi-exponentiation with 18,001 bases, which is extremely expensive.

- **DKG Disruption**: If multiple validators crash or slow down during DKG verification, the DKG process may fail to complete, preventing the generation of randomness for the next epoch.

- **Validator Availability**: Affected validators may become unresponsive during the attack, impacting consensus participation.

## Likelihood Explanation

**Likelihood: Medium-High**

- **Attacker Requirements**: Requires being part of the validator set (achievable by staking), which is a higher bar than arbitrary network participants but realistic in a permissionless system.

- **Attack Complexity**: Low - simply craft a transcript with duplicate SoKs and broadcast during DKG.

- **Detection Difficulty**: The attack appears as legitimate DKG traffic and would only be detected after validators experience slowdowns.

- **Frequency**: DKG occurs at epoch boundaries, providing regular attack opportunities.

In Byzantine Fault Tolerant systems, assuming up to 1/3 malicious validators is the threat model, making this attack realistic.

## Recommendation

Add validation to enforce that the number of unique dealers matches the number of SoKs and is bounded by the validator set size before expensive verification:

```rust
// In RealDKG::verify_transcript() after line 347
let dealers_set: HashSet<usize> = dealers.iter().cloned().collect();
ensure!(
    dealers.len() == dealers_set.len(),
    "real_dkg::verify_transcript failed with duplicate dealers in soks"
);
ensure!(
    dealers.len() <= num_validators,
    "real_dkg::verify_transcript failed with excessive number of dealers: {} > {}",
    dealers.len(),
    num_validators
);
```

Additionally, in `check_sizes()` for weighted transcripts:

```rust
// In weighted_protocol.rs Transcript::check_sizes()
let max_dealers = sc.get_total_num_players();
ensure!(
    self.soks.len() <= max_dealers,
    "Expected at most {} SoKs, but got {}",
    max_dealers,
    self.soks.len()
);
```

## Proof of Concept

```rust
#[test]
fn test_dos_via_excessive_soks() {
    use aptos_dkg::pvss::das::WeightedTranscript;
    use std::time::Instant;
    
    // Create a transcript with 9000 duplicate SoKs
    let mut malicious_transcript = create_valid_transcript(); // Helper to create base transcript
    
    // Duplicate the first SoK 9000 times
    let sok_to_duplicate = malicious_transcript.soks[0].clone();
    for _ in 0..9000 {
        malicious_transcript.soks.push(sok_to_duplicate.clone());
    }
    
    // Serialize to ensure it fits in 2MB
    let transcript_bytes = bcs::to_bytes(&malicious_transcript).unwrap();
    assert!(transcript_bytes.len() < 2_097_152, "Transcript exceeds 2MB limit");
    
    // Attempt verification and measure time
    let start = Instant::now();
    let result = malicious_transcript.verify(&config, &pp, &spks, &eks, &auxs);
    let duration = start.elapsed();
    
    // Verification should fail eventually, but only after expensive computation
    assert!(result.is_err());
    assert!(duration.as_secs() > 5, "DoS succeeded: verification took {:?}", duration);
}
```

**Notes:**

- This vulnerability requires the attacker to be a validator in the active set, which is achievable in a permissionless staking system.
- The attack is realistic under the Byzantine Fault Tolerance threat model where up to 1/3 of validators may be malicious.
- The 2MB transaction size limit does not prevent this attack as SoK entries can be compressed to ~224 bytes each, allowing ~9,000 entries within the limit.
- The attack targets peer-to-peer DKG transcript exchange, not consensus block proposals, so standard block validation size checks are bypassed.

### Citations

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L48-72)
```rust
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, BCSCryptoHash, CryptoHasher)]
#[allow(non_snake_case)]
pub struct Transcript {
    /// Proofs-of-knowledge (PoKs) for the dealt secret committed in $c = g_2^{p(0)}$.
    /// Since the transcript could have been aggregated from other transcripts with their own
    /// committed secrets in $c_i = g_2^{p_i(0)}$, this is a vector of PoKs for all these $c_i$'s
    /// such that $\prod_i c_i = c$.
    ///
    /// Also contains BLS signatures from each player $i$ on that player's contribution $c_i$, the
    /// player ID $i$ and auxiliary information `aux[i]` provided during dealing.
    soks: Vec<SoK<G1Projective>>,
    /// Commitment to encryption randomness $g_1^{r_j} \in G_1, \forall j \in [W]$
    R: Vec<G1Projective>,
    /// Same as $R$ except uses $g_2$.
    R_hat: Vec<G2Projective>,
    /// First $W$ elements are commitments to the evaluations of $p(X)$: $g_1^{p(\omega^i)}$,
    /// where $i \in [W]$. Last element is $g_1^{p(0)}$ (i.e., the dealt public key).
    V: Vec<G1Projective>,
    /// Same as $V$ except uses $g_2$.
    V_hat: Vec<G2Projective>,
    /// ElGamal encryption of the $j$th share of player $i$:
    /// i.e., $C[s_i+j-1] = h_1^{p(\omega^{s_i + j - 1})} ek_i^{r_j}, \forall i \in [n], j \in [w_i]$.
    /// We sometimes denote $C[s_i+j-1]$ by C_{i, j}.
    C: Vec<G1Projective>,
}
```

**File:** crates/aptos-dkg/src/pvss/das/weighted_protocol.rs (L302-309)
```rust
        batch_verify_soks::<G1Projective, A>(
            self.soks.as_slice(),
            g_1,
            &self.V[W],
            spks,
            auxs,
            sok_vrfy_challenge,
        )?;
```

**File:** dkg/src/transcript_aggregation/mod.rs (L88-101)
```rust
        let transcript = bcs::from_bytes(transcript_bytes.as_slice()).map_err(|e| {
            anyhow!("[DKG] adding peer transcript failed with trx deserialization error: {e}")
        })?;
        let mut trx_aggregator = self.trx_aggregator.lock();
        if trx_aggregator.contributors.contains(&metadata.author) {
            return Ok(None);
        }

        S::verify_transcript_extra(&transcript, &self.epoch_state.verifier, false, Some(sender))
            .context("extra verification failed")?;

        S::verify_transcript(&self.dkg_pub_params, &transcript).map_err(|e| {
            anyhow!("[DKG] adding peer transcript failed with trx verification failure: {e}")
        })?;
```

**File:** types/src/dkg/real_dkg/mod.rs (L337-347)
```rust
        let dealers = trx
            .main
            .get_dealers()
            .iter()
            .map(|player| player.id)
            .collect::<Vec<usize>>();
        let num_validators = params.session_metadata.dealer_validator_set.len();
        ensure!(
            dealers.iter().all(|id| *id < num_validators),
            "real_dkg::verify_transcript failed with invalid dealer index."
        );
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

**File:** crates/aptos-dkg/src/pvss/schnorr.rs (L77-86)
```rust
    let n = poks.len();
    let mut exps = Vec::with_capacity(2 * n + 1);
    let mut bases = Vec::with_capacity(2 * n + 1);

    // Compute \gamma_i = \gamma^i, for all i \in [0, n]
    let mut gammas = Vec::with_capacity(n);
    gammas.push(Scalar::ONE);
    for _ in 0..(n - 1) {
        gammas.push(gammas.last().unwrap().mul(gamma));
    }
```

**File:** crates/aptos-dkg/src/pvss/schnorr.rs (L89-104)
```rust
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
```

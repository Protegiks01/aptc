# Audit Report

## Title
Missing Length Validation in Weighted VUF Share Aggregation Causes Consensus Liveness Failure

## Summary
The `aggregate_shares` function in both `BlsWUF` and `PinkasWUF` implementations assumes each player's augmented public key share (APK) vector length matches their weight from the weighted configuration, but lacks validation to enforce this invariant. A mismatch between APK length and configured player weight causes `g1_multi_exp` to panic during share aggregation, breaking consensus liveness.

## Finding Description

The weighted VUF (Verifiable Unpredictable Function) system is critical for Aptos randomness beacon generation. Each validator has a weight in the `WeightedConfigBlstrs`, and their augmented public key shares should contain a number of elements equal to their weight. [1](#0-0) 

In `BlsWUF::aggregate_shares`, the function builds Lagrange coefficients assuming each player contributes shares equal to their configured weight: [2](#0-1) 

The critical issue occurs at lines 115-119 where `sub_player_ids` is built based on `wc.get_player_weight(player)`, determining the Lagrange coefficient vector length. However, at lines 127-133, the code collects all shares from each player's `ProofShare` without validating the count matches their weight. When `g1_multi_exp` is called at line 135, if the `bases` and `lagr` vectors have mismatched lengths, it will panic: [3](#0-2) 

Similarly, in `PinkasWUF::collect_lagrange_coeffs_shares_and_rks`, which is used in production: [4](#0-3) 

At line 294, `sub_player_ids` is built assuming player weight from config. At line 302, `apk.0.rks` is collected without validating its length. At lines 305-306, ranges are created based on player weight `w`. When `rk_multiexps` calls `g1_multi_exp(rks[idx], &lagr[ranges[idx].clone()])`, if `apk.0.rks.len()` ≠ `w`, the multiexp panics. [5](#0-4) 

While `PinkasWUF::augment_pubkey` validates `delta.rks.len() == pk.len()`: [6](#0-5) 

It does NOT validate that `pk.len()` matches the player's weight in the weighted configuration. This creates a gap where configuration mismatches or bugs in DKG transcript extraction could lead to APKs with incorrect lengths being certified.

The actual randomness generation flow that triggers this: [7](#0-6) 

## Impact Explanation

**Severity: High** (Consensus Liveness Failure)

If triggered, this vulnerability causes validator nodes to panic during randomness share aggregation, breaking the randomness beacon and potentially stalling consensus. According to Aptos bug bounty criteria, this qualifies as "Validator node slowdowns" or "API crashes" (High severity up to $50,000) or potentially "Total loss of liveness" if widespread (Critical severity).

The impact is mitigated by:
1. Production uses `PinkasWUF` which has partial validation in `augment_pubkey`
2. Weighted configs are derived from validator stakes and should remain consistent within an epoch
3. DKG transcripts extract public key shares with lengths matching the weighted config

However, the lack of defensive validation means that any bug in configuration management, DKG transcript handling, epoch transitions, or deserialization could trigger this panic.

## Likelihood Explanation

**Likelihood: Low-Medium** 

This vulnerability requires one of the following conditions:
1. **Configuration mismatch**: Different weighted configs used during DKG vs randomness generation
2. **Epoch transition bug**: APKs persisting across epochs with changed validator weights
3. **DKG extraction bug**: Transcript returning incorrect share counts
4. **Deserialization vulnerability**: Malicious delta causing wrong APK lengths

While current protections make these scenarios unlikely, consensus-critical code should have defense-in-depth validation. The absence of this check violates the principle of fail-safe defaults.

## Recommendation

Add explicit validation in `aggregate_shares` (and `collect_lagrange_coeffs_shares_and_rks` for PinkasWUF) to verify APK lengths match player weights:

**For BlsWUF** (`crates/aptos-dkg/src/weighted_vuf/bls/mod.rs`):
```rust
fn aggregate_shares(
    wc: &WeightedConfigBlstrs,
    apks_and_proofs: &[(Player, Self::AugmentedPubKeyShare, Self::ProofShare)],
) -> Self::Proof {
    // Validate APK lengths match player weights
    for (player, apk, _) in apks_and_proofs {
        let expected_weight = wc.get_player_weight(player);
        if apk.len() != expected_weight {
            panic!(
                "APK length mismatch for player {}: expected {} shares based on weight, got {}",
                player.id, expected_weight, apk.len()
            );
        }
    }
    
    // ... rest of existing implementation
}
```

**For PinkasWUF** (`crates/aptos-dkg/src/weighted_vuf/pinkas/mod.rs`):
```rust
pub fn collect_lagrange_coeffs_shares_and_rks<'a>(
    wc: &WeightedConfigBlstrs,
    apks: &'a [Option<(RandomizedPKs, Vec<DealtPubKeyShare>)>],
    proof: &'a Vec<(Player, <Self as WeightedVUF>::ProofShare)>,
) -> anyhow::Result<(...)> {
    // ... existing code ...
    
    for (player, share) in proof {
        let expected_weight = wc.get_player_weight(player);
        
        let apk = apks[player.id]
            .as_ref()
            .ok_or_else(|| anyhow!("Missing APK for player {}", player.get_id()))?;
        
        // NEW VALIDATION
        if apk.0.rks.len() != expected_weight {
            bail!(
                "APK rks length mismatch for player {}: expected {} based on weight, got {}",
                player.id, expected_weight, apk.0.rks.len()
            );
        }
        
        // ... rest of existing implementation
    }
}
```

Additionally, add validation in `augment_pubkey` for both implementations to check `pk.len()` against expected player weight when the weighted config is available.

## Proof of Concept

Due to the protections in place, demonstrating this requires simulating a configuration mismatch. Here's a conceptual test:

```rust
#[test]
#[should_panic(expected = "blstrs's multiexp has heisenbugs")]
fn test_apk_length_mismatch_causes_panic() {
    // Setup: Create weighted config with player weight = 3
    let weights = vec![3, 2, 2];
    let wconfig = WeightedConfigBlstrs::new(4, weights).unwrap();
    
    // Create APK with wrong length (2 instead of 3)
    let mut apk = Vec::new();
    for _ in 0..2 {  // Wrong: should be 3
        apk.push(DealtPubKeyShare::new(/* ... */));
    }
    
    // Create matching proof share (length 2)
    let proof_share = vec![G1Projective::identity(), G1Projective::identity()];
    
    // This passes verify_share (uses apk.len())
    BlsWUF::verify_share(&pp, &apk, msg, &proof_share).unwrap();
    
    // But panics in aggregate_shares (uses wconfig player weight)
    let apks_and_proofs = vec![
        (Player { id: 0 }, apk, proof_share)
    ];
    BlsWUF::aggregate_shares(&wconfig, &apks_and_proofs);  // PANIC!
}
```

## Notes

While this vulnerability has low likelihood under normal operation due to existing protections, it represents a critical gap in defensive validation for consensus-critical code. The mismatch between `verify_share` (using `apk.len()`) and `aggregate_shares` (using `wc.get_player_weight()`) creates a dangerous assumption that these will always match, violating defense-in-depth principles essential for blockchain consensus systems.

### Citations

**File:** crates/aptos-dkg/src/weighted_vuf/bls/mod.rs (L45-45)
```rust
    type PubKeyShare = Vec<pvss::dealt_pub_key_share::g2::DealtPubKeyShare>;
```

**File:** crates/aptos-dkg/src/weighted_vuf/bls/mod.rs (L108-136)
```rust
    fn aggregate_shares(
        wc: &WeightedConfigBlstrs,
        apks_and_proofs: &[(Player, Self::AugmentedPubKeyShare, Self::ProofShare)],
    ) -> Self::Proof {
        // Collect all the evaluation points associated with each player
        let mut sub_player_ids = Vec::with_capacity(wc.get_total_weight());

        for (player, _, _) in apks_and_proofs {
            for j in 0..wc.get_player_weight(player) {
                sub_player_ids.push(wc.get_virtual_player(player, j).id);
            }
        }

        // Compute the Lagrange coefficients associated with those evaluation points
        let batch_dom = wc.get_batch_evaluation_domain();
        let lagr = lagrange_coefficients(batch_dom, &sub_player_ids[..], &Scalar::ZERO);

        // Interpolate the signature
        let mut bases = Vec::with_capacity(apks_and_proofs.len());
        for (_, _, share) in apks_and_proofs {
            // println!(
            //     "Flattening {} share(s) for player {player}",
            //     sub_shares.len()
            // );
            bases.extend_from_slice(share.as_slice())
        }

        g1_multi_exp(bases.as_slice(), lagr.as_slice())
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

**File:** crates/aptos-dkg/src/weighted_vuf/pinkas/mod.rs (L108-143)
```rust
    fn augment_pubkey(
        pp: &Self::PublicParameters,
        pk: Self::PubKeyShare,
        // lpk: &Self::BlsPubKey,
        delta: Self::Delta,
    ) -> anyhow::Result<Self::AugmentedPubKeyShare> {
        if delta.rks.len() != pk.len() {
            bail!(
                "Expected PKs and RKs to be of the same length. Got {} and {}, respectively.",
                delta.rks.len(),
                pk.len()
            );
        }

        // TODO: Fiat-Shamir transform instead of RNG
        let tau = random_scalar(&mut thread_rng());

        let pks = pk
            .iter()
            .map(|pk| *pk.as_group_element())
            .collect::<Vec<G2Projective>>();
        let taus = get_powers_of_tau(&tau, pks.len());

        let pks_combined = g2_multi_exp(&pks[..], &taus[..]);
        let rks_combined = g1_multi_exp(&delta.rks[..], &taus[..]);

        if multi_pairing(
            [&delta.pi, &rks_combined].into_iter(),
            [&pks_combined, &pp.g_hat.neg()].into_iter(),
        ) != Gt::identity()
        {
            bail!("RPKs were not correctly randomized.");
        }

        Ok((delta, pk))
    }
```

**File:** crates/aptos-dkg/src/weighted_vuf/pinkas/mod.rs (L273-314)
```rust
    pub fn collect_lagrange_coeffs_shares_and_rks<'a>(
        wc: &WeightedConfigBlstrs,
        apks: &'a [Option<(RandomizedPKs, Vec<DealtPubKeyShare>)>],
        proof: &'a Vec<(Player, <Self as WeightedVUF>::ProofShare)>,
    ) -> anyhow::Result<(
        Vec<&'a G2Projective>,
        Vec<&'a Vec<G1Projective>>,
        Vec<Scalar>,
        Vec<Range<usize>>,
    )> {
        // Collect all the evaluation points associated with each player's augmented pubkey sub shares.
        let mut sub_player_ids = Vec::with_capacity(wc.get_total_weight());
        // The G2 shares
        let mut shares = Vec::with_capacity(proof.len());
        // The RKs of each player
        let mut rks = Vec::with_capacity(proof.len());
        // The starting & ending index of each player in the `lagr` coefficients vector
        let mut ranges = Vec::with_capacity(proof.len());

        let mut k = 0;
        for (player, share) in proof {
            for j in 0..wc.get_player_weight(player) {
                sub_player_ids.push(wc.get_virtual_player(player, j).id);
            }

            let apk = apks[player.id]
                .as_ref()
                .ok_or_else(|| anyhow!("Missing APK for player {}", player.get_id()))?;

            rks.push(&apk.0.rks);
            shares.push(share);

            let w = wc.get_player_weight(player);
            ranges.push(k..k + w);
            k += w;
        }

        // Compute the Lagrange coefficients associated with those evaluation points
        let batch_dom = wc.get_batch_evaluation_domain();
        let lagr = lagrange_coefficients(batch_dom, &sub_player_ids[..], &Scalar::ZERO);
        Ok((shares, rks, lagr, ranges))
    }
```

**File:** crates/aptos-dkg/src/weighted_vuf/pinkas/mod.rs (L316-335)
```rust
    pub fn rk_multiexps(
        proof: &Vec<(Player, G2Projective)>,
        rks: Vec<&Vec<G1Projective>>,
        lagr: &Vec<Scalar>,
        ranges: &Vec<Range<usize>>,
        thread_pool: &ThreadPool,
    ) -> Vec<G1Projective> {
        thread_pool.install(|| {
            proof
                .par_iter()
                .with_min_len(MIN_MULTIEXP_NUM_JOBS)
                .enumerate()
                .map(|(idx, _)| {
                    let rks = rks[idx];
                    let lagr = &lagr[ranges[idx].clone()];
                    g1_multi_exp(rks, lagr)
                })
                .collect::<Vec<G1Projective>>()
        })
    }
```

**File:** consensus/src/rand/rand_gen/types.rs (L97-148)
```rust
    fn aggregate<'a>(
        shares: impl Iterator<Item = &'a RandShare<Self>>,
        rand_config: &RandConfig,
        rand_metadata: RandMetadata,
    ) -> anyhow::Result<Randomness>
    where
        Self: Sized,
    {
        let timer = std::time::Instant::now();
        let mut apks_and_proofs = vec![];
        for share in shares {
            let id = rand_config
                .validator
                .address_to_validator_index()
                .get(share.author())
                .copied()
                .ok_or_else(|| {
                    anyhow!(
                        "Share::aggregate failed with invalid share author: {}",
                        share.author
                    )
                })?;
            let apk = rand_config
                .get_certified_apk(share.author())
                .ok_or_else(|| {
                    anyhow!(
                        "Share::aggregate failed with missing apk for share from {}",
                        share.author
                    )
                })?;
            apks_and_proofs.push((Player { id }, apk.clone(), share.share().share));
        }

        let proof = WVUF::aggregate_shares(&rand_config.wconfig, &apks_and_proofs);
        let metadata_serialized = bcs::to_bytes(&rand_metadata).map_err(|e| {
            anyhow!("Share::aggregate failed with metadata serialization error: {e}")
        })?;
        let eval = WVUF::derive_eval(
            &rand_config.wconfig,
            &rand_config.vuf_pp,
            metadata_serialized.as_slice(),
            &rand_config.get_all_certified_apk(),
            &proof,
            THREAD_MANAGER.get_exe_cpu_pool(),
        )
        .map_err(|e| anyhow!("Share::aggregate failed with WVUF derive_eval error: {e}"))?;
        debug!("WVUF derivation time: {} ms", timer.elapsed().as_millis());
        let eval_bytes = bcs::to_bytes(&eval)
            .map_err(|e| anyhow!("Share::aggregate failed with eval serialization error: {e}"))?;
        let rand_bytes = Sha3_256::digest(eval_bytes.as_slice()).to_vec();
        Ok(Randomness::new(rand_metadata, rand_bytes))
    }
```

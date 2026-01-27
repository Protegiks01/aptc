# Audit Report

## Title
Missing Per-Player Dimension Validation in PVSS Transcript Verification Enables DKG Protocol Failure

## Summary
The PVSS transcript verification in `weighted_transcriptv2.rs` does not validate that each player's commitment vector (`Vs[i]`) has the correct length matching their weight. This allows a malicious dealer to submit transcripts with mismatched dimensions that pass verification but cause aggregation failures and incorrect share distribution, breaking the DKG protocol.

## Finding Description

The `msm_terms()` function preserves whatever structure exists in `input.chunked_values`, including empty inner vectors: [1](#0-0) 

When a malicious dealer creates a PVSS transcript, the verification function only validates outer dimensions but not per-player inner dimensions: [2](#0-1) 

The Low Degree Test (LDT) only checks the total flattened count, not the per-player structure: [3](#0-2) 

Note the TODO comment at line 554 acknowledging this missing check.

**Attack Path:**

1. Malicious dealer (a Byzantine validator) creates a transcript where players with weights [2, 1, 2] receive commitments structured as `Vs = vec![vec![V1, V2, V3], vec![], vec![V4, V5]]` instead of the correct `vec![vec![V1, V2], vec![V3], vec![V4, V5]]`

2. Verification checks pass:
   - `Vs.len() == 3` ✓ (outer length check)
   - `Vs_flat.len() == 6` ✓ (LDT total count check)
   - SoK verification ✓ (proof generated for this specific structure)

3. Protocol breakage occurs during aggregation with honest transcripts: [4](#0-3) 

When iterating `for j in 0..self.Vs[i].len()`, the malformed transcript tries to access `other.Vs[1][2]` which doesn't exist in honest transcripts, causing index out-of-bounds panics.

4. Additionally, players receiving incorrect numbers of commitments cannot properly verify their shares: [5](#0-4) 

Player 2 gets 0 commitments and cannot verify shares; Player 1 gets 3 commitments instead of 2.

## Impact Explanation

**Severity: Medium ($10,000 range)**

This vulnerability enables a single malicious validator (acting as dealer) to cause **DKG protocol failure**, which directly impacts:

- **Validator Set Updates**: DKG failures prevent proper validator rotation during epoch transitions
- **Protocol Liveness**: Inability to update validator sets can degrade consensus liveness
- **State Inconsistencies**: Different nodes may handle aggregation failures differently, requiring manual intervention

This falls under "State inconsistencies requiring intervention" per the Medium severity criteria. While it doesn't directly steal funds or break consensus safety, it can disrupt critical validator operations.

## Likelihood Explanation

**Likelihood: High**

- **Low Barrier**: Any validator can become a dealer during DKG
- **Easy Exploitation**: Simply requires crafting Vs with wrong inner dimensions but correct total count
- **Passes Verification**: All existing checks (outer length, LDT, SoK) pass with malformed structure
- **Automatic Trigger**: Aggregation or share verification fails automatically when processing the malformed transcript

The attack requires no special timing, no race conditions, and no complex state manipulation. The TODO comment at line 554 suggests developers are aware of the missing validation but haven't implemented it.

## Recommendation

Add explicit per-player dimension validation in the verify function:

```rust
// After line 487 in weighted_transcriptv2.rs, add:
for (i, player_vs) in self.subtrs.Vs.iter().enumerate() {
    let player = sc.get_player(i);
    let expected_weight = sc.get_player_weight(&player);
    if player_vs.len() != expected_weight {
        bail!(
            "Player {} has {} commitments but expected {} based on weight",
            i,
            player_vs.len(),
            expected_weight
        );
    }
}

// Similarly validate Cs dimensions
for (i, player_cs) in self.subtrs.Cs.iter().enumerate() {
    let player = sc.get_player(i);
    let expected_weight = sc.get_player_weight(&player);
    if player_cs.len() != expected_weight {
        bail!(
            "Player {} has {} ciphertexts but expected {} based on weight",
            i,
            player_cs.len(),
            expected_weight
        );
    }
}
```

Also implement the TODO at line 554:
```rust
// Replace line 554 with:
assert_eq!(
    Vs_flat.len(),
    sc.get_total_weight(),
    "Flattened Vs count {} does not match total weight {}",
    Vs_flat.len(),
    sc.get_total_weight()
);
```

## Proof of Concept

```rust
#[test]
#[should_panic(expected = "index out of bounds")]
fn test_malformed_vs_breaks_aggregation() {
    use crate::pvss::{Player, traits::Transcript};
    use ark_bls12_381::Bls12_381;
    
    // Setup: 3 players with weights [2, 1, 2]
    let weights = vec![2, 1, 2];
    let sc = WeightedConfigArkworks::new(3, weights).unwrap();
    let mut rng = thread_rng();
    
    // Generate public parameters
    let pp = PublicParameters::<Bls12_381>::generate(&sc, &mut rng);
    
    // Honest dealer creates correct transcript
    let mut honest_transcript = Transcript::<Bls12_381>::generate(&sc, &pp, &mut rng);
    
    // Malicious dealer creates transcript with malformed Vs structure
    let mut malicious_transcript = honest_transcript.clone();
    // Redistribute commitments: [2,1,2] -> [3,0,2]
    malicious_transcript.subtrs.Vs = vec![
        vec![
            honest_transcript.subtrs.Vs[0][0],
            honest_transcript.subtrs.Vs[0][1],
            honest_transcript.subtrs.Vs[1][0], // Steal from player 2
        ],
        vec![], // Player 2 gets nothing
        honest_transcript.subtrs.Vs[2].clone(),
    ];
    
    // Both transcripts pass verification individually
    assert!(honest_transcript.verify(&sc, &pp, &spks, &eks, &session_id).is_ok());
    assert!(malicious_transcript.verify(&sc, &pp, &spks, &eks, &session_id).is_ok());
    
    // But aggregation fails with index out of bounds
    honest_transcript.subtrs.aggregate_with(&sc, &malicious_transcript.subtrs)
        .expect("Aggregation should fail");
}
```

## Notes

This vulnerability exists because `CodomainShape`'s `into_iter()` implementation flattens all nested structures, hiding dimension mismatches during sigma protocol verification. The verification only catches total count mismatches (via LDT) but not per-player structural mismatches. The presence of a TODO comment at line 554 suggests this gap is known but not addressed.

### Citations

**File:** crates/aptos-dkg/src/pvss/chunky/chunked_scalar_mul.rs (L98-116)
```rust
    fn msm_terms(&self, input: &Self::Domain) -> Self::CodomainShape<Self::MsmInput> {
        let rows: Vec<Vec<Self::MsmInput>> = input
            .chunked_values
            .iter()
            .map(|row| {
                row.iter()
                    .map(|chunks| MsmInput {
                        bases: vec![self.base.clone()],
                        scalars: vec![le_chunks_to_scalar(
                            self.ell,
                            &Scalar::slice_as_inner(chunks),
                        )],
                    })
                    .collect()
            })
            .collect();

        CodomainShape(rows)
    }
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcriptv2.rs (L481-487)
```rust
        if self.subtrs.Vs.len() != sc.get_total_num_players() {
            bail!(
                "Expected {} arrays of commitment elements, but got {}",
                sc.get_total_num_players(),
                self.subtrs.Vs.len()
            );
        }
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcriptv2.rs (L552-555)
```rust
        let mut Vs_flat: Vec<_> = self.subtrs.Vs.iter().flatten().cloned().collect();
        Vs_flat.push(self.subtrs.V0);
        // could add an assert_eq here with sc.get_total_weight()
        ldt.low_degree_test_group(&Vs_flat)?;
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcriptv2.rs (L598-607)
```rust
    fn get_public_key_share(
        &self,
        _sc: &Self::SecretSharingConfig,
        player: &Player,
    ) -> Self::DealtPubKeyShare {
        self.Vs[player.id]
            .iter()
            .map(|&V_i| keys::DealtPubKeyShare::<E>::new(keys::DealtPubKey::new(V_i.into_affine())))
            .collect()
    }
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcriptv2.rs (L660-668)
```rust
        for i in 0..sc.get_total_num_players() {
            for j in 0..self.Vs[i].len() {
                // Aggregate the V_{i,j}s
                self.Vs[i][j] += other.Vs[i][j];
                for k in 0..self.Cs[i][j].len() {
                    // Aggregate the C_{i,j,k}s
                    self.Cs[i][j][k] += other.Cs[i][j][k];
                }
            }
```

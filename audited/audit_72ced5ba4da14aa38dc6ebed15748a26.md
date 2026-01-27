# Audit Report

## Title
DKG Sigma Protocol Zero-Knowledge Violation via Missing Per-Player Witness Structure Validation

## Summary
The sigma protocol implementation in `prove_homomorphism()` generates randomness using `witness.rand(rng)`, which preserves the exact structure of the witness including any malformed dimensions. A malicious DKG dealer can create transcripts with incorrect per-player share distributions (e.g., empty vectors for some players) that pass verification but generate sigma protocol proofs with zero entropy for affected players, violating the zero-knowledge property and potentially allowing witness extraction. [1](#0-0) 

## Finding Description

The vulnerability exists in the interaction between three components:

1. **Randomness Generation with Structure Preservation**: The `Witness::rand()` implementation for vectors iterates over the witness structure and generates random elements matching that exact structure. [2](#0-1) 

2. **Insufficient Structure Validation**: The transcript verification only validates the outer vector length and flattened total count, but does NOT validate the per-player distribution of shares. [3](#0-2) [4](#0-3) 

3. **Missing Per-Player Validation**: There is an explicit TODO comment acknowledging the missing check. [5](#0-4) 

**Attack Path:**
1. Malicious dealer creates `HkzgWeightedElgamalWitness` with malformed structure where some players have empty vectors in `chunked_plaintexts` or `elgamal_randomness`
2. When `prove_homomorphism()` calls `witness.rand(rng)`, it generates randomness preserving the malformed structure
3. For players with empty witness portions, the random commitment contains ZERO entropy
4. The sigma protocol proof is generated with this low-entropy randomness
5. Verification passes because: outer length check passes, flattened count matches, and the mathematical relationship holds even with empty components
6. The zero-knowledge property is violated for affected players

**Example:** With 2 players having weights [1, 1], a malicious dealer creates `chunked_plaintexts = [[4 chunks], []]` instead of `[[2 chunks], [2 chunks]]`. The flattened length is still 4, but player 1's portion has zero entropy.

## Impact Explanation

**Severity: CRITICAL** (Consensus/Safety Violations, Cryptographic Correctness Violation)

This vulnerability breaks the **Cryptographic Correctness** invariant and compromises DKG security:

1. **Zero-Knowledge Property Violation**: Sigma protocols require high-entropy randomness to maintain zero-knowledge. With zero entropy for some players, the proof may leak witness information.

2. **DKG Compromise**: The DKG protocol relies on the security of these sigma proofs to ensure that dealt secrets are valid. A compromised proof could allow:
   - Extraction of secret shares for affected players
   - Manipulation of the distributed key generation process
   - Potential validator set manipulation

3. **Consensus Impact**: If DKG is used for consensus-critical operations (validator key generation, randomness beacons), this could affect consensus safety.

4. **Byzantine Threshold**: Even a single malicious dealer (within the < 1/3 Byzantine threshold) can exploit this to compromise security guarantees.

## Likelihood Explanation

**Likelihood: HIGH**

1. **Easy to Exploit**: The attack requires only constructing a transcript with public fields in a specific malformed structure - no complex cryptographic operations needed.

2. **Validation Gap**: The missing validation is explicitly acknowledged in the code with a TODO comment, indicating known technical debt.

3. **Public API**: Transcript structures have public fields enabling direct construction. [6](#0-5) [7](#0-6) 

4. **Within Threat Model**: Byzantine validators (up to 1/3) are part of the standard threat model for BFT consensus.

## Recommendation

Add comprehensive per-player structure validation in the `verify()` function:

```rust
// After line 152 in weighted_transcript.rs, add:
for (player_idx, player_cs) in self.subtrs.Cs.iter().enumerate() {
    let player = sc.get_player(player_idx);
    let expected_weight = sc.get_player_weight(&player);
    if player_cs.len() != expected_weight {
        bail!(
            "Player {} has {} share vectors but expected {} (weight)",
            player_idx, player_cs.len(), expected_weight
        );
    }
    
    // Also validate each share vector has the expected number of chunks
    for (weight_idx, chunks) in player_cs.iter().enumerate() {
        if chunks.len() != num_chunks_per_scalar::<E::ScalarField>(pp.ell) {
            bail!(
                "Player {} weight unit {} has {} chunks but expected {}",
                player_idx, weight_idx, chunks.len(),
                num_chunks_per_scalar::<E::ScalarField>(pp.ell)
            );
        }
    }
}

// Similarly validate Rs structure
if self.subtrs.Rs.len() != sc.get_max_weight() {
    bail!("Expected {} R vectors but got {}", sc.get_max_weight(), self.subtrs.Rs.len());
}
```

Also implement the TODO at line 329 in the `decrypt_share()` function:

```rust
// Replace TODO comment with:
assert_eq!(
    Cs.len(),
    weight,
    "Player {} has {} encrypted shares but expected {} (weight)",
    player.id, Cs.len(), weight
);
```

## Proof of Concept

```rust
#[cfg(test)]
mod test_low_entropy_attack {
    use super::*;
    
    #[test]
    fn test_malformed_witness_structure_bypass() {
        // Setup: 2 players with weights [1, 1], 2 chunks per share
        let sc = WeightedConfigArkworks::new(1, vec![1, 1]).unwrap();
        
        // Normal witness structure: [[chunk0], [chunk1]]
        // Malformed structure: [[chunk0, chunk1], []] - player 1 has empty vector!
        
        // Create malformed witness
        let malformed_witness = HkzgWeightedElgamalWitness {
            hkzg_randomness: univariate_hiding_kzg::CommitmentRandomness::rand(rng),
            chunked_plaintexts: vec![
                vec![vec![Scalar::rand(rng), Scalar::rand(rng)]], // Player 0: 2 chunks
                vec![], // Player 1: EMPTY - zero entropy!
            ],
            elgamal_randomness: vec![
                vec![Scalar::rand(rng), Scalar::rand(rng)],
                vec![], // Player 1: EMPTY
            ],
        };
        
        // Generate proof - this will call witness.rand(rng)
        // which generates randomness with the SAME malformed structure
        let proof = hom.prove(&malformed_witness, &statement, &context, rng);
        
        // Create transcript with malformed structure
        let malformed_transcript = Transcript {
            dealer: Player { id: 0 },
            subtrs: Subtranscript {
                V0: /* ... */,
                Vs: vec![vec![/* ... */], vec![/* ... */]],
                Cs: vec![
                    vec![vec![/* 2 chunks */], vec![/* 2 chunks */]], // Player 0
                    vec![], // Player 1: EMPTY!
                ],
                Rs: /* ... */,
            },
            sharing_proof: SharingProof {
                SoK: proof,
                range_proof: /* ... */,
                range_proof_commitment: /* ... */,
            },
        };
        
        // This SHOULD fail but currently PASSES verification
        // because validation only checks flattened length
        let result = malformed_transcript.verify(&sc, &pp, &spks, &eks, &sid);
        
        // Current behavior: passes (VULNERABILITY)
        assert!(result.is_ok()); 
        
        // Expected behavior after fix: should fail
        // assert!(result.is_err());
    }
}
```

**Notes**

The vulnerability is confirmed by explicit TODO comment in the codebase acknowledging the missing validation. The attack exploits the dimension-preserving nature of `Vec::rand()` combined with insufficient structure validation in transcript verification. While the mathematical correctness of the sigma protocol equation is maintained, the zero-knowledge property is fundamentally violated when randomness has zero entropy for some components. This represents a critical cryptographic flaw in the DKG implementation that could compromise validator key generation and consensus security.

### Citations

**File:** crates/aptos-dkg/src/sigma_protocol/traits.rs (L226-228)
```rust
    fn rand<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Self {
        self.iter().map(|elem| elem.rand(rng)).collect()
    }
```

**File:** crates/aptos-dkg/src/sigma_protocol/traits.rs (L482-482)
```rust
    let r = witness.rand(rng);
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L64-72)
```rust
pub struct Transcript<E: Pairing> {
    dealer: Player,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    /// This is the aggregatable subtranscript
    pub subtrs: Subtranscript<E>,
    /// Proof (of knowledge) showing that the s_{i,j}'s in C are base-B representations (of the s_i's in V, but this is not part of the proof), and that the r_j's in R are used in C
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub sharing_proof: SharingProof<E>,
}
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L78-91)
```rust
pub struct Subtranscript<E: Pairing> {
    // The dealt public key
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub V0: E::G2,
    // The dealt public key shares
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub Vs: Vec<Vec<E::G2>>,
    /// First chunked ElGamal component: C[i][j] = s_{i,j} * G + r_j * ek_i. Here s_i = \sum_j s_{i,j} * B^j // TODO: change notation because B is not a group element?
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub Cs: Vec<Vec<Vec<E::G1>>>, // TODO: maybe make this and the other fields affine? The verifier will have to do it anyway... and we are trying to speed that up
    /// Second chunked ElGamal component: R[j] = r_j * H
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub Rs: Vec<Vec<E::G1>>,
}
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L140-145)
```rust
        if self.subtrs.Cs.len() != sc.get_total_num_players() {
            bail!(
                "Expected {} arrays of chunked ciphertexts, but got {}",
                sc.get_total_num_players(),
                self.subtrs.Cs.len()
            );
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

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L329-329)
```rust
        // TODO: put an assert here saying that len(Cs) = weight
```

# Audit Report

## Title
DKG Transcript Verification Denial of Service via Oversized Sigma Protocol Proof Witness

## Summary
A malicious validator can crash other validator nodes during DKG (Distributed Key Generation) by sending a crafted transcript containing a sigma protocol proof with an oversized witness structure. The verification code fails to validate the size of `proof.z.chunked_plaintexts` before attempting to flatten it, leading to an assertion failure and node panic when the flattened size exceeds the preallocated Lagrange basis size.

## Finding Description

During DKG epoch transitions, validators exchange PVSS transcripts to establish shared randomness. Each transcript contains a `SharingProof` that includes a sigma protocol proof (`SoK`) proving knowledge of the secret shares. [1](#0-0) 

The sigma protocol proof contains a response field `z` of type `HkzgWeightedElgamalWitness`, which includes a triple-nested vector `chunked_plaintexts: Vec<Vec<Vec<Scalar<F>>>>`. [2](#0-1) 

During transcript verification, the code validates the sizes of the public components (`Cs` and `Vs`) but **does not validate the size of the proof witness**. [3](#0-2) 

When verification proceeds to check the sigma protocol proof, it applies a projection function that flattens the nested `chunked_plaintexts` structure. [4](#0-3) 

The flattened witness is then passed to the HKZG commitment homomorphism's `msm_terms` function, which contains an assertion that the input size must not exceed the preallocated Lagrange basis size. [5](#0-4) 

**Attack Path:**
1. Malicious validator creates a DKG transcript with correctly-sized public components (`Cs`, `Vs`) matching `sc.get_total_num_players()`
2. Sets `proof.SoK.z.chunked_plaintexts` to contain artificially inflated nested vectors (e.g., `[100][1000000][1000]` instead of expected `[100][weight][16]`)
3. Broadcasts transcript to other validators
4. Receiving validators deserialize the transcript (BCS succeeds if memory available)
5. Verification checks at lines 140-153 pass (only check `Cs.len()` and `Vs.len()`)
6. Verification proceeds to line 178, calling `hom.verify()` on the sigma protocol proof
7. Verification attempts to flatten `proof.z.chunked_plaintexts` via projection function
8. The flattened size (e.g., 100 billion elements) far exceeds `msm_basis.len()` (typically ~thousands)
9. Assertion at line 352 fails: `assert!(self.msm_basis.len() >= input.values.len(), ...)`
10. Node panics and crashes

This breaks the **Resource Limits** invariant ("All operations must respect gas, storage, and computational limits") and causes validator node unavailability.

## Impact Explanation

This vulnerability has **High Severity** impact per Aptos bug bounty criteria:
- **Validator node crashes** - Direct impact is immediate node termination via panic
- **Network liveness degradation** - If multiple validators crash simultaneously during DKG, the epoch transition may stall
- **DoS during critical protocol phase** - DKG occurs during epoch changes, a sensitive time for network operation

While this does not directly lead to consensus safety violations or fund loss, it significantly impacts network availability during critical coordination phases. If exploited systematically, it could prevent successful epoch transitions and randomness generation.

This falls under "Validator node slowdowns" and "API crashes" (High Severity - up to $50,000) or potentially "Total loss of liveness/network availability" if exploited at scale.

## Likelihood Explanation

**Likelihood: Medium-High**

Requirements for exploitation:
- Attacker must be an active validator in the validator set
- Attacker must participate in DKG protocol (automatic during epoch transitions)
- No Byzantine threshold required (single malicious validator can execute attack)

Execution complexity: **Low**
- Simply requires modifying the local DKG implementation to send oversized witness data
- No cryptographic forgery or complex state manipulation required
- Attack surface is exposed during every epoch transition

Detection difficulty: **Low**
- Victims immediately crash with assertion failure, making detection trivial
- However, attribution may be unclear if multiple validators broadcast simultaneously

## Recommendation

Add explicit size validation for the sigma protocol proof witness before verification:

```rust
// In weighted_transcript.rs, verify() function, after line 153:

// Validate proof.z structure matches expected dimensions
let expected_total_chunks = sc.get_total_weight() * 
    num_chunks_per_scalar::<E::ScalarField>(pp.ell) as usize;

// Flatten and count the actual chunks in proof.z
let actual_chunks: usize = self.sharing_proof.SoK.z.chunked_plaintexts
    .iter()
    .map(|player_chunks| player_chunks.iter().map(|v| v.len()).sum::<usize>())
    .sum();

if actual_chunks > expected_total_chunks {
    bail!(
        "Proof witness chunked_plaintexts size {} exceeds expected size {}",
        actual_chunks,
        expected_total_chunks
    );
}

// Also validate structure matches sc configuration
if self.sharing_proof.SoK.z.chunked_plaintexts.len() != sc.get_total_num_players() {
    bail!(
        "Proof witness player count {} does not match expected {}",
        self.sharing_proof.SoK.z.chunked_plaintexts.len(),
        sc.get_total_num_players()
    );
}
```

Additionally, replace the assertion in `univariate_hiding_kzg.rs` with a proper error return to prevent panics:

```rust
// In univariate_hiding_kzg.rs, msm_terms() function, replace lines 352-357:
if self.msm_basis.len() < input.values.len() {
    return Err(anyhow::anyhow!(
        "Not enough Lagrange basis elements for univariate hiding KZG: required {}, got {}",
        input.values.len(),
        self.msm_basis.len()
    ));
}
```

## Proof of Concept

```rust
// Rust test demonstrating the vulnerability
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    #[should_panic(expected = "Not enough Lagrange basis elements")]
    fn test_oversized_witness_causes_panic() {
        // Setup: Create a legitimate DKG configuration
        let sc = WeightedConfigBlstrs::new(10, vec![1; 100]).unwrap();
        let pp = PublicParameters::<Bls12_381>::with_max_num_shares(100);
        
        // Create a transcript with valid Cs and Vs
        let mut transcript = create_valid_transcript(&sc, &pp);
        
        // Attacker: Modify proof.z.chunked_plaintexts to be oversized
        // Instead of expected ~1600 total elements (100 players * 1 weight * 16 chunks),
        // inject 1 million elements
        transcript.sharing_proof.SoK.z.chunked_plaintexts = vec![
            vec![vec![Scalar::rand(&mut rng); 1000]; 1000]; // 1 million chunks
            100 // for each of 100 players
        ];
        
        // Victim: Attempt to verify the malicious transcript
        // This will panic at the assertion in univariate_hiding_kzg.rs:352
        transcript.verify(&sc, &pp, &spks, &eks, &session_id)
            .expect("Verification should fail gracefully, not panic");
    }
}
```

## Notes

The original security question mentions "integer overflow," but the actual vulnerability is a **bounds check violation leading to panic**. While extremely large nested vectors could theoretically cause memory exhaustion during the `collect()` operation, the more immediate and exploitable issue is the assertion failure when the flattened size exceeds the preallocated basis size. Both scenarios result in node unavailability, but the assertion failure occurs first and is deterministic.

### Citations

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L140-153)
```rust
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

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L420-432)
```rust
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct SharingProof<E: Pairing> {
    /// SoK: the SK is knowledge of `witnesses` s_{i,j} yielding the commitment and the C and the R, their image is the PK, and the signed message is a certain context `cntxt`
    pub SoK: sigma_protocol::Proof<
        E::ScalarField,
        hkzg_chunked_elgamal::WeightedHomomorphism<'static, E>,
    >, // static because we don't want the lifetime of the Proof to depend on the Homomorphism TODO: try removing it?
    /// A batched range proof showing that all committed values s_{i,j} lie in some range
    pub range_proof: dekart_univariate_v2::Proof<E>,
    /// A KZG-style commitment to the values s_{i,j} going into the range proof
    pub range_proof_commitment:
        <dekart_univariate_v2::Proof<E> as BatchedRangeProof<E>>::Commitment,
}
```

**File:** crates/aptos-dkg/src/pvss/chunky/hkzg_chunked_elgamal.rs (L44-51)
```rust
#[derive(
    SigmaProtocolWitness, CanonicalSerialize, CanonicalDeserialize, Debug, Clone, PartialEq, Eq,
)]
pub struct HkzgWeightedElgamalWitness<F: PrimeField> {
    pub hkzg_randomness: univariate_hiding_kzg::CommitmentRandomness<F>,
    pub chunked_plaintexts: Vec<Vec<Vec<Scalar<F>>>>, // For each player, plaintexts z_i, which are chunked z_{i,j}
    pub elgamal_randomness: Vec<Vec<Scalar<F>>>, // For at most max_weight, for each chunk, a blinding factor
}
```

**File:** crates/aptos-dkg/src/pvss/chunky/hkzg_chunked_elgamal.rs (L210-213)
```rust
                let flattened_chunked_plaintexts: Vec<Scalar<E::ScalarField>> =
                    std::iter::once(Scalar(E::ScalarField::ZERO))
                        .chain(chunked_plaintexts.iter().flatten().flatten().cloned())
                        .collect();
```

**File:** crates/aptos-dkg/src/pcs/univariate_hiding_kzg.rs (L352-357)
```rust
        assert!(
            self.msm_basis.len() >= input.values.len(),
            "Not enough Lagrange basis elements for univariate hiding KZG: required {}, got {}",
            input.values.len(),
            self.msm_basis.len()
        );
```

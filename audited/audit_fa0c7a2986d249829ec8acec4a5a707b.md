# Audit Report

## Title
Out-of-Bounds Array Access in DKG Sigma Protocol Verification Causes Validator Panic

## Summary
The DKG transcript verification function fails to validate that the structure of the sigma protocol proof's witness response matches the expected number of encryption keys. An attacker can craft a malicious PVSS transcript with a proof containing more player entries than encryption keys provided, causing an out-of-bounds array access that panics validator nodes during verification.

## Finding Description

The vulnerability exists in the sigma protocol verification path for weighted chunky PVSS transcripts. During verification, the system validates that the number of encryption keys matches the expected player count, but fails to validate the internal structure of the deserialized proof.

**Attack Flow:**

1. The `verify()` function validates encryption key count against the secret sharing configuration at [1](#0-0) 

2. It creates `eks_inner` and constructs a homomorphism with these keys at [2](#0-1) 

3. The homomorphism is passed to sigma protocol verification at [3](#0-2) 

4. During verification, `msm_terms()` is called on the proof's witness response `z` at [4](#0-3) 

5. The `HkzgWeightedElgamalWitness` contains a `chunked_plaintexts` field that can be attacker-controlled in the deserialized proof, as shown in its structure at [5](#0-4) 

6. **The vulnerability occurs** in `chunked_elgamal::WeightedHomomorphism::msm_terms()` which iterates over `plaintext_chunks` and accesses `self.eks[i]` without bounds checking at [6](#0-5) 

**Critical Code Path:**
When `input.plaintext_chunks.len() > self.eks.len()`, the enumeration produces indices `i` that exceed the bounds of `self.eks`, causing a panic when accessing `self.eks[i]`.

**Broken Invariants:**
- **Cryptographic Correctness**: Sigma protocol verification should handle invalid proofs gracefully without panicking
- **Resource Limits**: Node operations must not crash on malformed input

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program for the following reasons:

1. **Validator Node Crashes**: Any validator attempting to verify the malicious transcript will panic and crash, qualifying under "Validator node slowdowns" and "API crashes" categories.

2. **DKG Disruption**: Since DKG transcripts are broadcast during the distributed key generation protocol, a single malicious participant can crash all honest validators attempting verification.

3. **Network Availability Impact**: If this occurs during epoch transitions when DKG is running, it could prevent the network from completing validator set updates, affecting consensus availability.

4. **No Authentication Required**: Any participant in the DKG protocol can exploit this without special privileges.

The impact is limited to availability rather than consensus safety or fund theft, but represents a significant denial-of-service vector against validator infrastructure.

## Likelihood Explanation

**Likelihood: HIGH**

1. **Easy to Exploit**: An attacker only needs to craft a BCS-serialized transcript with a malformed `HkzgWeightedElgamalWitness` structure where `chunked_plaintexts.len() > expected_player_count`.

2. **No Special Privileges Required**: Any DKG participant can broadcast such a transcript.

3. **Deterministic Crash**: The vulnerability triggers reliably whenever the malformed structure is processed.

4. **Visible Attack Surface**: DKG runs during epoch transitions, a predictable and observable event.

The only barrier is that the attacker must be a DKG participant, but this is feasible for any entity running a validator node or compromising one.

## Recommendation

Add validation to ensure the proof's witness structure matches expected dimensions before calling `msm_terms()`. Insert bounds checking after line 153 in `weighted_transcript.rs`:

```rust
// After existing checks at lines 140-152, add:
if let FirstProofItem::Commitment(_) = &self.sharing_proof.SoK.first_proof_item {
    // For non-compact proofs, validate the witness response structure
    if self.sharing_proof.SoK.z.chunked_plaintexts.len() != sc.get_total_num_players() {
        bail!(
            "Expected {} player chunks in proof witness, but got {}",
            sc.get_total_num_players(),
            self.sharing_proof.SoK.z.chunked_plaintexts.len()
        );
    }
}
```

Additionally, consider defensive bounds checking in `chunked_elgamal.rs`:

```rust
// In msm_terms() at line 231, before the map:
if input.plaintext_chunks.len() > self.eks.len() {
    panic!("Plaintext chunks length {} exceeds encryption keys length {}", 
           input.plaintext_chunks.len(), self.eks.len());
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod exploit_test {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use aptos_crypto::weighted_config::WeightedConfig;
    use rand::thread_rng;
    
    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn test_malicious_transcript_causes_panic() {
        type E = Bls12_381;
        let mut rng = thread_rng();
        
        // Setup: 3 players with weights [2, 1, 1], threshold 2
        let sc = WeightedConfig::<ShamirThresholdConfig<E::ScalarField>>::new(2, vec![2, 1, 1]).unwrap();
        let pp = PublicParameters::<E>::default_with_ell(16);
        
        // Generate legitimate encryption keys for 3 players
        let dks: Vec<_> = (0..3).map(|_| DecryptPrivKey::<E>::generate(&mut rng)).collect();
        let eks: Vec<_> = dks.iter().map(|dk| dk.to(&pp.pp_elgamal)).collect();
        
        // Create a malicious proof with 10 player chunks instead of 3
        let malicious_witness = HkzgWeightedElgamalWitness {
            hkzg_randomness: univariate_hiding_kzg::CommitmentRandomness::rand(&mut rng),
            chunked_plaintexts: vec![vec![vec![Scalar(E::ScalarField::ONE)]]; 10], // 10 players!
            elgamal_randomness: vec![vec![Scalar(E::ScalarField::ONE)]; sc.get_max_weight()],
        };
        
        let malicious_proof = Proof {
            first_proof_item: FirstProofItem::Commitment(/* valid commitment */),
            z: malicious_witness,
        };
        
        // Create transcript with malicious proof
        let transcript = Transcript {
            dealer: Player { id: 0 },
            subtrs: /* valid subtranscript with 3 players */,
            sharing_proof: SharingProof {
                SoK: malicious_proof,
                /* other valid fields */
            },
        };
        
        // This will PANIC when verifying due to out-of-bounds access
        let _ = transcript.verify(&sc, &pp, &spks, &eks, &session_id);
    }
}
```

**Notes**

The vulnerability stems from a missing validation layer between deserialization and cryptographic verification. The sigma protocol framework assumes well-formed witness structures, but the BCS deserialization allows arbitrary structures. This gap enables denial-of-service attacks against validator nodes during DKG operations. The fix should be implemented at the transcript verification level to reject malformed proofs before they reach the sigma protocol verification logic.

### Citations

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L133-138)
```rust
        if eks.len() != sc.get_total_num_players() {
            bail!(
                "Expected {} encryption keys, but got {}",
                sc.get_total_num_players(),
                eks.len()
            );
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L165-177)
```rust
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
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L178-189)
```rust
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
```

**File:** crates/aptos-dkg/src/sigma_protocol/traits.rs (L124-124)
```rust
        let msm_terms_for_prover_response = self.msm_terms(&proof.z);
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

**File:** crates/aptos-dkg/src/pvss/chunky/chunked_elgamal.rs (L231-239)
```rust
        let Cs = input
            .plaintext_chunks
            .iter()
            .enumerate()
            .map(|(i, z_i)| {
                // here `i` is the player's id
                chunks_vec_msm_terms::<C>(self.pp, self.eks[i], z_i, &input.plaintext_randomness)
            })
            .collect();
```

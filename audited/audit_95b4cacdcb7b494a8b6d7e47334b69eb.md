# Audit Report

## Title
Index Out of Bounds Panic in PVSS Transcript Verification Due to Missing Chunk Length Validation

## Summary
A malicious dealer can craft a PVSS transcript with ciphertext chunk vectors longer than expected, causing an index out of bounds panic in all honest validators during transcript verification. This results in validator node crashes and disruption of the DKG protocol.

## Finding Description
The vulnerability exists in the weighted PVSS transcript verification logic. During verification, the code iterates over ciphertext chunks and accesses the `powers_of_radix` array without validating that the chunk count matches the expected length. [1](#0-0) 

The `powers_of_radix` vector has length equal to `num_chunks_per_scalar`, which is computed as: [2](#0-1) 

And initialized in public parameters as: [3](#0-2) 

The verification function checks outer dimensions but not the inner chunk lengths: [4](#0-3) [5](#0-4) 

However, there is **no validation** that each `Cs_flat[i].len()` equals `num_chunks_per_scalar`. A malicious dealer can craft a transcript where some ciphertext vectors contain more chunks than expected. When the verification loop accesses `pp.powers_of_radix[j]` with `j >= powers_of_radix.len()`, it causes a panic.

**Attack Path:**
1. Malicious dealer crafts PVSS transcript with correctly-sized outer dimensions
2. Sets some `Cs[player][share]` vectors to have length > `num_chunks_per_scalar`
3. Broadcasts transcript to network during DKG
4. All honest validators attempt verification
5. Verification code panics at line 258 with index out of bounds
6. Validator nodes crash, disrupting DKG protocol

## Impact Explanation
This is a **High Severity** vulnerability per Aptos bug bounty criteria:
- **Validator node crashes**: Direct cause of the panic
- **Protocol disruption**: DKG cannot complete if validators crash during transcript verification
- **Network availability**: Repeated attacks during epoch transitions could cause liveness issues

This breaks the **Resource Limits** and **Cryptographic Correctness** invariants - the verification code should handle malformed inputs gracefully without panicking.

## Likelihood Explanation
**Likelihood: High**

The attack is easy to execute:
- Any dealer can craft a malicious transcript (no special privileges required)
- The payload is straightforward: simply add extra elements to chunk vectors
- DKG runs periodically during epoch transitions, providing repeated attack opportunities
- All validators are affected simultaneously when verifying the same malicious transcript

## Recommendation
Add explicit validation of chunk vector lengths before accessing `powers_of_radix`:

```rust
// In weighted_transcript.rs verify() function, after line 253:
let expected_chunks = num_chunks_per_scalar::<E::ScalarField>(pp.ell) as usize;
for (i, cs) in Cs_flat.iter().enumerate() {
    if cs.len() != expected_chunks {
        bail!(
            "Invalid chunk count for ciphertext {}: expected {}, got {}",
            i,
            expected_chunks,
            cs.len()
        );
    }
}
```

This should be added before line 255 to ensure all chunk vectors have the correct length before the loop that accesses `powers_of_radix`.

## Proof of Concept

```rust
#[cfg(test)]
mod malicious_transcript_test {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use aptos_crypto::weighted_config::WeightedConfigArkworks;
    use rand::thread_rng;
    
    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn test_malicious_chunk_length_causes_panic() {
        type E = Bls12_381;
        let mut rng = thread_rng();
        
        // Setup normal parameters
        let sc = WeightedConfigArkworks::new(1, vec![1]).unwrap();
        let pp = PublicParameters::<E>::new(1, 16, 1, &mut rng);
        let expected_chunks = num_chunks_per_scalar::<E::ScalarField>(pp.ell) as usize;
        
        // Create malicious transcript with extra chunks
        let mut transcript = Transcript::<E>::generate(&sc, &pp, &mut rng);
        
        // Add extra chunks to first ciphertext (malicious modification)
        let extra_chunks = vec![ark_ec::Group::generator(); 5];
        transcript.subtrs.Cs[0][0].extend_from_slice(&extra_chunks);
        
        // Verification should panic with index out of bounds
        let eks = vec![keys::EncryptPubKey::generate(&pp, &mut rng)];
        let spks = vec![keys::SigningPubKey::generate(&mut rng)];
        let _ = transcript.verify(&sc, &pp, &spks, &eks, &());
    }
}
```

**Notes**
The vulnerability is in production code path used during DKG epoch transitions. The range proof verification and sigma protocol verification do not catch this issue because they process whatever data is provided without validating structural constraints. The missing length check allows malformed transcripts to trigger panics in all verifying nodes simultaneously.

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

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L247-253)
```rust
        let Cs_flat: Vec<_> = self.subtrs.Cs.iter().flatten().cloned().collect();
        assert_eq!(
            Cs_flat.len(),
            sc.get_total_weight(),
            "Number of ciphertexts does not equal number of weights"
        ); // TODO what if zero weight?
           // could add an assert_eq here with sc.get_total_weight()
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L255-262)
```rust
        for i in 0..Cs_flat.len() {
            for j in 0..Cs_flat[i].len() {
                let base = Cs_flat[i][j];
                let exp = pp.powers_of_radix[j] * powers_of_beta[i];
                base_vec.push(base);
                exp_vec.push(exp);
            }
        }
```

**File:** crates/aptos-dkg/src/pvss/chunky/chunked_elgamal.rs (L300-302)
```rust
pub fn num_chunks_per_scalar<F: PrimeField>(ell: u8) -> u32 {
    F::MODULUS_BIT_SIZE.div_ceil(ell as u32) // Maybe add `as usize` here?
}
```

**File:** crates/aptos-dkg/src/pvss/chunky/public_parameters.rs (L35-40)
```rust
fn compute_powers_of_radix<E: Pairing>(ell: u8) -> Vec<E::ScalarField> {
    utils::powers(
        E::ScalarField::from(1u64 << ell),
        num_chunks_per_scalar::<E::ScalarField>(ell) as usize,
    )
}
```

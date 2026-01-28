# Audit Report

## Title
DKG Protocol Denial of Service via Malicious PVSS Transcript Witness Dimension Mismatch

## Summary
A malicious validator can craft a PVSS transcript with oversized `HkzgWeightedElgamalWitness.chunked_plaintexts` dimensions, causing honest validators to panic with "index out of bounds" during transcript verification, resulting in validator node crashes.

## Finding Description

The DKG protocol uses PVSS transcripts containing sigma protocol proofs with `HkzgWeightedElgamalWitness` structures. The vulnerability exists in the verification path where witness dimensions are not validated before use.

**Vulnerable Code Path:**

1. The witness structure contains `chunked_plaintexts: Vec<Vec<Vec<Scalar>>>` representing chunked shares per player: [1](#0-0) 

2. Transcripts are deserialized from network data without dimension validation on the witness: [2](#0-1) 

3. During verification, the VM calls transcript verification which processes the proof: [3](#0-2) 

4. The verification creates a homomorphism with `eks` array sized to `get_total_num_players()` and calls verify: [4](#0-3) 

5. The sigma protocol verification calls `msm_terms` on the unvalidated witness: [5](#0-4) 

6. For tuple homomorphisms, this calls `msm_terms` on both components: [6](#0-5) 

7. The chunked ElGamal component iterates through `plaintext_chunks` and accesses `self.eks[i]` without bounds checking: [7](#0-6) 

**Attack Vector:**
A malicious validator broadcasts a transcript where `sharing_proof.SoK.z.chunked_plaintexts.len() > eks.len()`. When honest validators verify this transcript, the iteration reaches `i >= eks.len()`, causing `self.eks[i]` to panic with index out of bounds.

**Security Invariant Violations:**
- **Byzantine Fault Tolerance**: The system should tolerate <1/3 Byzantine validators, but a single malicious validator causes honest nodes to crash
- **Robust Input Validation**: Malformed network inputs should be rejected gracefully, not cause panics

## Impact Explanation

**Severity: HIGH**

This vulnerability meets HIGH severity criteria per the Aptos bug bounty framework:
- **Validator Node Crashes**: A single malicious validator causes honest validator nodes to panic during DKG transcript verification
- **DoS through Resource Exhaustion**: The panic exhausts the validator's ability to continue execution

The impact occurs during DKG, which happens during epoch transitions - a critical protocol phase. The vulnerability is particularly severe because:
1. Validators participating in DKG will crash when processing the malicious transcript
2. DKG transcript verification occurs in consensus-critical paths
3. The panic cannot be caught by error handling (Rust panics bypass Result types)
4. Multiple validators can be affected simultaneously if they all process the same malicious transcript

While this could potentially escalate to CRITICAL if it causes total network liveness loss, recovery mechanisms likely exist for validator restarts, so HIGH severity is most appropriate.

## Likelihood Explanation

**Likelihood: HIGH**

- **Attack Complexity: Low** - The attacker only needs to modify witness array dimensions in a transcript before broadcasting
- **Attacker Requirements: Validator Access** - While this requires validator access, Byzantine validators (<1/3) are explicitly part of the threat model
- **Reproducibility: 100%** - The panic is deterministic given the malformed input
- **Detection: Post-Exploitation Only** - No pre-validation prevents the attack; crashes are detected after they occur

The attack is highly likely because:
1. Any single validator can become Byzantine (no collusion required)
2. The malicious transcript bypasses all validation checks before reaching the panic point
3. DKG occurs regularly during epoch transitions, providing multiple attack opportunities

## Recommendation

Add dimension validation before calling `msm_terms` on the witness. In `weighted_transcript.rs`, validate witness dimensions before sigma protocol verification:

```rust
// After line 177, before calling hom.verify():
// Validate witness dimensions match expected player count
if self.sharing_proof.SoK.z.chunked_plaintexts.len() != sc.get_total_num_players() {
    bail!(
        "Invalid witness: expected {} chunked_plaintexts arrays, but got {}",
        sc.get_total_num_players(),
        self.sharing_proof.SoK.z.chunked_plaintexts.len()
    );
}
```

Additionally, consider adding a defensive bounds check in `chunked_elgamal.rs` at line 237:
```rust
.map(|(i, z_i)| {
    if i >= self.eks.len() {
        panic!("Invalid player index {} exceeds eks length {}", i, self.eks.len());
    }
    chunks_vec_msm_terms::<C>(self.pp, self.eks[i], z_i, &input.plaintext_randomness)
})
```

## Proof of Concept

While a full PoC requires constructing and serializing a malicious transcript, the vulnerability can be demonstrated by this conceptual test:

```rust
// Conceptual test showing the panic scenario
#[test]
#[should_panic(expected = "index out of bounds")]
fn test_oversized_witness_panics() {
    // Setup with 3 players
    let sc = WeightedConfig::new(2, vec![1, 1, 1]).unwrap();
    let eks = vec![ek1, ek2, ek3]; // 3 encryption keys
    
    // Create malicious witness with 10 player arrays (> 3)
    let malicious_witness = HkzgWeightedElgamalWitness {
        hkzg_randomness: /* valid */,
        chunked_plaintexts: vec![vec![vec![...]]; 10], // 10 > 3
        elgamal_randomness: /* valid */,
    };
    
    // Create homomorphism with 3 eks
    let hom = WeightedHomomorphism::new(..., &eks);
    
    // This will panic at i=3 when accessing eks[3]
    let terms = hom.msm_terms(&malicious_witness);
}
```

The actual exploit requires crafting a complete PVSS transcript with the malicious witness and broadcasting it during DKG, but the core vulnerability is evident from the code analysis.

### Citations

**File:** crates/aptos-dkg/src/pvss/chunky/hkzg_chunked_elgamal.rs (L47-51)
```rust
pub struct HkzgWeightedElgamalWitness<F: PrimeField> {
    pub hkzg_randomness: univariate_hiding_kzg::CommitmentRandomness<F>,
    pub chunked_plaintexts: Vec<Vec<Vec<Scalar<F>>>>, // For each player, plaintexts z_i, which are chunked z_{i,j}
    pub elgamal_randomness: Vec<Vec<Scalar<F>>>, // For at most max_weight, for each chunk, a blinding factor
}
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L172-190)
```rust
            let hom = hkzg_chunked_elgamal::WeightedHomomorphism::<E>::new(
                lagr_g1,
                pp.pk_range_proof.ck_S.xi_1,
                &pp.pp_elgamal,
                &eks_inner,
            );
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
            }
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L443-449)
```rust
impl<E: Pairing> TryFrom<&[u8]> for Transcript<E> {
    type Error = CryptoMaterialError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        bcs::from_bytes::<Transcript<E>>(bytes)
            .map_err(|_| CryptoMaterialError::DeserializationError)
    }
```

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L104-112)
```rust
        // Deserialize transcript and verify it.
        let pub_params = DefaultDKG::new_public_params(&in_progress_session_state.metadata);
        let transcript = bcs::from_bytes::<<DefaultDKG as DKGTrait>::Transcript>(
            dkg_node.transcript_bytes.as_slice(),
        )
        .map_err(|_| Expected(TranscriptDeserializationFailed))?;

        DefaultDKG::verify_transcript(&pub_params, &transcript)
            .map_err(|_| Expected(TranscriptVerificationFailed))?;
```

**File:** crates/aptos-dkg/src/sigma_protocol/traits.rs (L61-71)
```rust
        let msm_terms = self.msm_terms_for_verify::<_, H>(
            public_statement,
            proof,
            cntxt,
        );

        let msm_result = Self::msm_eval(msm_terms);
        ensure!(msm_result == C::ZERO); // or MsmOutput::zero()

        Ok(())
    }
```

**File:** crates/aptos-dkg/src/sigma_protocol/homomorphism/tuple.rs (L202-206)
```rust
    fn msm_terms(&self, input: &Self::Domain) -> Self::CodomainShape<Self::MsmInput> {
        let terms1 = self.hom1.msm_terms(input);
        let terms2 = self.hom2.msm_terms(input);
        TupleCodomainShape(terms1, terms2)
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

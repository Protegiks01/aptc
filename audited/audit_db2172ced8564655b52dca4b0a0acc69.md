# Audit Report

## Title
DKG Verification Panic Causes Validator Node Crash Due to Unhandled Projection Dimension Mismatch

## Summary
A malicious DKG transcript with deliberately malformed proof witness dimensions can trigger an assertion failure during sigma protocol verification, causing all validator nodes to crash and halt the network. The vulnerability stems from lack of graceful error handling in the projection function path combined with a global panic handler that terminates the process.

## Finding Description

The vulnerability exists in the DKG (Distributed Key Generation) sigma protocol verification flow, specifically in how `LiftHomomorphism` handles projection functions that produce semantically invalid values.

**Attack Flow:**

1. A malicious validator creates a DKG transcript containing a sigma protocol proof (`SoK`) where `proof.z` is a `HkzgWeightedElgamalWitness` with malformed `chunked_plaintexts` dimensions (e.g., extra chunks beyond the configured maximum).

2. During verification, the validator transaction is processed in `process_dkg_result_inner()` [1](#0-0) 

3. The PVSS verification calls the sigma protocol `verify()` method [2](#0-1) 

4. Inside `msm_terms_for_verify()`, it computes MSM terms from `proof.z` [3](#0-2) 

5. For `LiftHomomorphism`, the `msm_terms()` implementation calls the projection function without error handling [4](#0-3) 

6. The projection function flattens the malformed `chunked_plaintexts`, producing a `Witness` with excessive `values.len()` [5](#0-4) 

7. When `CommitmentHomomorphism::msm_terms()` receives this witness, the assertion `assert!(self.msm_basis.len() >= input.values.len())` **fails and panics** [6](#0-5) 

8. The global panic handler executes, and since `VMState` is not `VERIFIER` or `DESERIALIZER` during DKG verification, it calls `process::exit(12)`, **terminating the entire validator process** [7](#0-6) 

**Root Cause:**

The projection function is defined as a non-fallible function pointer `fn(&LargerDomain) -> H::Domain` [8](#0-7)  with no mechanism to return errors. When it produces semantically invalid output (wrong dimensions), downstream code uses `assert!()` instead of returning a `Result`, causing panics that crash the validator.

## Impact Explanation

**Severity: HIGH**

This vulnerability enables a **network-wide liveness failure**:

- **Validator Node Crashes**: All honest validators attempting to verify the malicious DKG transcript will crash simultaneously
- **Consensus Halted**: The network cannot make progress without functioning validators
- **Byzantine Fault Tolerance Violation**: AptosBFT is designed to tolerate < 1/3 Byzantine validators, but this allows a **single malicious validator** to halt the entire network
- **Deterministic Execution Broken**: Instead of all validators deterministically rejecting an invalid proof, they all deterministically **crash**, violating Invariant #1

Per Aptos bug bounty criteria, this qualifies as **High Severity** due to validator node crashes and significant protocol violations. While not quite reaching "total loss of liveness" (which would require non-recoverable state), it causes temporary but complete network halt requiring manual validator restart.

## Likelihood Explanation

**Likelihood: HIGH**

- **Low Complexity**: Attack requires only crafting a DKG transcript with modified proof witness dimensions - no cryptographic forgery needed
- **Minimal Privileges**: Any validator participating in DKG can trigger this (not requiring majority stake or collusion)
- **Reliable Trigger**: The panic is deterministic - all validators will crash on the same malformed input
- **No Detection**: The malformed transcript passes BCS deserialization checks, only failing during verification logic
- **High Impact**: Complete network halt affecting all validators simultaneously

## Recommendation

**Immediate Fix**: Replace the `assert!()` with proper error handling that returns `anyhow::Result`:

```rust
// In crates/aptos-dkg/src/pcs/univariate_hiding_kzg.rs
fn msm_terms(&self, input: &Self::Domain) -> Self::CodomainShape<Self::MsmInput> {
    ensure!(
        self.msm_basis.len() >= input.values.len(),
        "Not enough Lagrange basis elements for univariate hiding KZG: required {}, got {}",
        input.values.len(),
        self.msm_basis.len()
    );
    // ... rest of function
}
```

However, this requires changing the `msm_terms()` return type from `Self::CodomainShape<Self::MsmInput>` to `Result<Self::CodomainShape<Self::MsmInput>>`, propagating through the trait definition.

**Proper Fix**: Add dimension validation during deserialization or early in the verification path, before calling `msm_terms()`. In `weighted_transcript.rs`, validate witness structure:

```rust
// After deserializing the transcript, validate proof.z dimensions
let expected_values_len = /* compute from public parameters */;
ensure!(
    proof.z.chunked_plaintexts.iter().flatten().flatten().count() + 1 == expected_values_len,
    "Invalid proof witness dimensions"
);
```

## Proof of Concept

```rust
// Reproduction steps (conceptual - requires access to DKG test infrastructure)

#[test]
fn test_malformed_dkg_proof_causes_panic() {
    // 1. Set up DKG public parameters with max_weight = 100, resulting in 
    //    msm_basis with length N
    let (pp, _) = setup_dkg_params(100);
    
    // 2. Create a valid proof witness
    let mut witness = create_valid_witness(&pp);
    
    // 3. Maliciously extend chunked_plaintexts to produce values.len() > N
    witness.chunked_plaintexts.push(vec![vec![Scalar::random()]]);
    
    // 4. Create proof with malformed witness
    let malicious_proof = create_proof_with_witness(witness);
    
    // 5. Create transcript with malicious proof
    let transcript = create_transcript_with_proof(malicious_proof);
    
    // 6. Attempt verification - this will PANIC and crash the process
    // Expected: should return Err(TranscriptVerificationFailed)
    // Actual: process terminates with exit code 12
    let result = DefaultDKG::verify_transcript(&pp, &transcript);
    
    // This line is never reached due to panic
    assert!(result.is_err());
}
```

**Notes:**
- The vulnerability violates the **Deterministic Execution** invariant - validators should reject invalid proofs deterministically, not crash
- The panic handler's `process::exit(12)` terminates the entire validator, not just the verification thread
- No `catch_unwind` wrapper exists in the validator transaction execution path for DKG verification
- The issue affects all validators simultaneously when processing the same malicious block containing the DKG transaction

### Citations

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L111-112)
```rust
        DefaultDKG::verify_transcript(&pub_params, &transcript)
            .map_err(|_| Expected(TranscriptVerificationFailed))?;
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L178-190)
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
            }
```

**File:** crates/aptos-dkg/src/sigma_protocol/traits.rs (L124-124)
```rust
        let msm_terms_for_prover_response = self.msm_terms(&proof.z);
```

**File:** crates/aptos-dkg/src/sigma_protocol/homomorphism/fixed_base_msms.rs (L111-114)
```rust
    fn msm_terms(&self, input: &Self::Domain) -> Self::CodomainShape<Self::MsmInput> {
        let projected = (self.projection)(input);
        self.hom.msm_terms(&projected)
    }
```

**File:** crates/aptos-dkg/src/pvss/chunky/hkzg_chunked_elgamal.rs (L204-218)
```rust
            projection: |dom: &HkzgWeightedElgamalWitness<E::ScalarField>| {
                let HkzgWeightedElgamalWitness {
                    hkzg_randomness,
                    chunked_plaintexts,
                    ..
                } = dom;
                let flattened_chunked_plaintexts: Vec<Scalar<E::ScalarField>> =
                    std::iter::once(Scalar(E::ScalarField::ZERO))
                        .chain(chunked_plaintexts.iter().flatten().flatten().cloned())
                        .collect();
                univariate_hiding_kzg::Witness::<E::ScalarField> {
                    hiding_randomness: hkzg_randomness.clone(),
                    values: flattened_chunked_plaintexts,
                }
            },
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

**File:** crates/crash-handler/src/lib.rs (L52-57)
```rust
    if state::get_state() == VMState::VERIFIER || state::get_state() == VMState::DESERIALIZER {
        return;
    }

    // Kill the process
    process::exit(12);
```

**File:** crates/aptos-dkg/src/sigma_protocol/homomorphism/mod.rs (L55-55)
```rust
    pub projection: fn(&LargerDomain) -> H::Domain,
```

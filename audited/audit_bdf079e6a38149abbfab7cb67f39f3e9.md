# Audit Report

## Title
Unhandled Panic in DKG Verification Can Crash Validator Nodes

## Summary
The `apply_msm()` function in the DKG sigma protocol implementation uses `.expect()` to handle MSM evaluation errors, which causes panics that are not caught during DKG transcript verification. This can crash validator nodes when processing malformed DKG transcripts.

## Finding Description

The `apply_msm()` function in the DKG protocol does not properly handle errors from multi-scalar multiplication (MSM) operations. [1](#0-0) 

All implementations of `msm_eval()` use `.expect()` on the result of `C::msm()`, which will panic if the arkworks MSM operation fails. For example: [2](#0-1) [3](#0-2) [4](#0-3) 

During DKG transcript verification in the VM, the panic is not caught: [5](#0-4) 

The `.map_err()` only catches `Result::Err`, not panics. The verification flow calls sigma protocol verification which eventually invokes `msm_eval()`: [6](#0-5) 

In the weighted transcript verification: [7](#0-6) 

The error handling only catches `Result::Err`, not panics from `.expect()` calls.

## Impact Explanation

This breaks the **Deterministic Execution** and **Consensus Safety** invariants. If one validator crashes while processing a DKG transcript that causes an MSM panic, but other validators handle it differently (e.g., if they have different library versions or floating point behavior), this could lead to consensus divergence.

The impact qualifies as **Medium severity** under the Aptos bug bounty criteria: "Validator node slowdowns" and potential "State inconsistencies requiring intervention." A crashed validator node during DKG affects the protocol's ability to complete the distributed key generation process.

## Likelihood Explanation

**Likelihood: Low to Medium**

While arkworks MSM operations are generally robust, they can fail due to:
1. Internal computation errors in edge cases
2. Malformed curve points that pass initial deserialization but fail during computation
3. Resource exhaustion during large MSM operations

An attacker could potentially craft a DKG transcript that exploits edge cases in the arkworks library to trigger MSM failures. While `MsmInput::new()` validates length mismatches: [8](#0-7) 

Direct struct construction bypasses this validation: [9](#0-8) 

## Recommendation

Replace `.expect()` calls with proper error propagation throughout the MSM evaluation chain:

1. Change `msm_eval()` signature to return `Result<Self::MsmOutput, anyhow::Error>`
2. Update `apply_msm()` to propagate errors instead of panicking
3. Ensure all call sites handle the Result appropriately

Example fix for `msm_eval()`:
```rust
fn msm_eval(input: Self::MsmInput) -> anyhow::Result<Self::MsmOutput> {
    C::msm(input.bases(), input.scalars())
        .map_err(|e| anyhow::anyhow!("MSM evaluation failed: {:?}", e))
}
```

Update `apply_msm()` signature and implementation to propagate errors.

## Proof of Concept

```rust
// Test demonstrating panic behavior
#[test]
#[should_panic(expected = "MSM failed")]
fn test_msm_panic_not_caught() {
    use ark_bls12_381::G1Projective;
    use ark_ec::CurveGroup;
    
    // Create invalid MSM input that will cause arkworks to fail
    // (This is a conceptual PoC - actual exploitation depends on 
    // finding specific inputs that pass deserialization but fail MSM)
    
    let bases = vec![]; // Empty bases
    let scalars = vec![ark_bls12_381::Fr::from(1u64)]; // Non-empty scalars
    
    // This will panic instead of returning an error
    let result = G1Projective::msm(&bases, &scalars).expect("MSM failed");
}
```

**Note**: A complete working PoC requires finding specific curve points and scalars that pass BCS deserialization and initial validation but cause arkworks MSM to return an error. This is non-trivial and requires deep analysis of arkworks internals.

---

**Notes**: This vulnerability represents a defensive programming weakness where panic-based error handling can crash validator nodes. The exploitability depends on an attacker's ability to craft malicious transcripts that trigger MSM failures, which is uncertain without deeper arkworks analysis. The fix should implement proper error propagation consistent with Rust best practices for production systems.

### Citations

**File:** crates/aptos-dkg/src/sigma_protocol/homomorphism/fixed_base_msms.rs (L81-92)
```rust
    fn apply_msm(
        &self, // TODO: remove this
        msms: Self::CodomainShape<Self::MsmInput>,
    ) -> Self::CodomainShape<Self::MsmOutput>
    where
        Self::CodomainShape<Self::MsmInput>: EntrywiseMap<
            Self::MsmInput,
            Output<Self::MsmOutput> = Self::CodomainShape<Self::MsmOutput>,
        >,
    {
        msms.map(|msm_input| Self::msm_eval(msm_input))
    }
```

**File:** crates/aptos-dkg/src/pvss/chunky/chunked_scalar_mul.rs (L118-120)
```rust
    fn msm_eval(input: Self::MsmInput) -> Self::MsmOutput {
        C::msm(input.bases(), input.scalars()).expect("MSM failed in Schnorr") // TODO: custom MSM here, because only length 1 MSM except during verification
    }
```

**File:** crates/aptos-dkg/src/pvss/chunky/chunked_elgamal.rs (L195-198)
```rust
        .map(|(&z_ij, &r_j)| MsmInput {
            bases: vec![pp.G, ek],
            scalars: vec![z_ij.0, r_j.0],
        })
```

**File:** crates/aptos-dkg/src/pvss/chunky/chunked_elgamal.rs (L262-264)
```rust
    fn msm_eval(input: Self::MsmInput) -> Self::MsmOutput {
        C::msm(input.bases(), input.scalars()).expect("MSM failed in ChunkedElgamal")
    }
```

**File:** crates/aptos-dkg/src/pcs/univariate_kzg.rs (L65-67)
```rust
    fn msm_eval(input: Self::MsmInput) -> Self::MsmOutput {
        E::G1::msm(input.bases(), input.scalars()).expect("MSM failed in univariate KZG")
    }
```

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L111-112)
```rust
        DefaultDKG::verify_transcript(&pub_params, &transcript)
            .map_err(|_| Expected(TranscriptVerificationFailed))?;
```

**File:** crates/aptos-dkg/src/sigma_protocol/traits.rs (L67-68)
```rust
        let msm_result = Self::msm_eval(msm_terms);
        ensure!(msm_result == C::ZERO); // or MsmOutput::zero()
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcriptv2.rs (L514-529)
```rust
            if let Err(err) = hom.verify(
                &TupleCodomainShape(
                    TupleCodomainShape(
                        self.sharing_proof.range_proof_commitment.clone(),
                        chunked_elgamal::WeightedCodomainShape {
                            chunks: self.subtrs.Cs.clone(),
                            randomness: self.subtrs.Rs.clone(),
                        },
                    ),
                    chunked_scalar_mul::CodomainShape(self.subtrs.Vs.clone()),
                ),
                &self.sharing_proof.SoK,
                &sok_cntxt,
            ) {
                bail!("PoK verification failed: {:?}", err);
            }
```

**File:** crates/aptos-crypto/src/arkworks/msm.rs (L77-86)
```rust
    fn new(bases: Vec<Self::Base>, scalars: Vec<Self::Scalar>) -> anyhow::Result<Self> {
        if bases.len() != scalars.len() {
            anyhow::bail!(
                "MsmInput length mismatch: {} bases, {} scalars",
                bases.len(),
                scalars.len(),
            );
        }
        Ok(Self { bases, scalars })
    }
```

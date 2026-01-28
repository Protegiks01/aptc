# Audit Report

## Title
DKG Transcript Verification Denial of Service via Oversized Sigma Protocol Proof Witness

## Summary
A malicious validator can crash other validator nodes during DKG by sending a crafted transcript containing a sigma protocol proof with an oversized witness structure. The verification code fails to validate the size of `proof.z.chunked_plaintexts` before flattening it, leading to an assertion failure and node panic when the flattened size exceeds the preallocated Lagrange basis size.

## Finding Description

During DKG epoch transitions, validators exchange PVSS transcripts to establish shared randomness. The transcript deserialization and verification flow has a critical missing validation:

**Entry Point**: When validators receive DKG transcripts, they are deserialized without size validation on witness fields. [1](#0-0) 

**Missing Validation**: The verification code validates the sizes of public components (`Cs` and `Vs`) but does not validate the proof witness size. [2](#0-1) 

**Witness Structure**: The sigma protocol proof contains a witness of type `HkzgWeightedElgamalWitness` with a triple-nested vector `chunked_plaintexts: Vec<Vec<Vec<Scalar<F>>>>`. [3](#0-2) 

**Verification Trigger**: The verification calls `hom.verify()` on the sigma protocol proof. [4](#0-3) 

**Dangerous Projection**: During verification, a projection function flattens the nested `chunked_plaintexts` structure without bounds checking. [5](#0-4) 

**Assertion Failure**: The flattened witness is passed to `msm_terms()` which contains an assertion that panics if the input size exceeds the Lagrange basis size. [6](#0-5) 

**Attack Path**:
1. Malicious validator creates a transcript with correctly-sized `Cs` and `Vs` (passes lines 140-153 checks)
2. Sets `proof.SoK.z.chunked_plaintexts` to contain oversized nested vectors (e.g., dimensions that flatten to millions of elements)
3. Broadcasts transcript during DKG epoch transition
4. Receiving validators deserialize successfully (within 64 MiB network limit [7](#0-6) )
5. Public component size checks pass
6. Sigma protocol verification flattens the oversized witness
7. Assertion fails when flattened size exceeds `msm_basis.len()` (typically ~thousands)
8. Node panics and crashes

## Impact Explanation

This vulnerability has **High Severity** impact per Aptos bug bounty criteria:

- **Validator Node Crashes**: Direct impact is immediate node termination via assertion panic, falling under "Validator node slowdowns" and "API crashes" (High Severity - up to $50,000)
- **Network Liveness Degradation**: If multiple validators crash simultaneously during DKG, epoch transitions may stall
- **DoS During Critical Protocol Phase**: DKG occurs during epoch changes, a sensitive time for network coordination

This is NOT a "network DoS attack" (which is out of scope) but rather a **protocol-level vulnerability** exploiting a missing validation check. The distinction is critical: this exploits a code bug (missing size validation) rather than flooding network infrastructure.

If exploited systematically against multiple validators, this could escalate to "Total loss of liveness/network availability" (Critical Severity), though the primary impact is validator crashes.

## Likelihood Explanation

**Likelihood: Medium-High**

**Requirements for Exploitation**:
- Attacker must be an active validator (untrusted role per threat model)
- Attacker participates in DKG automatically during epoch transitions
- No Byzantine threshold required - single malicious validator sufficient

**Execution Complexity: Low**
- Requires only modifying local DKG implementation to send oversized witness data
- No cryptographic forgery or complex state manipulation needed
- Attack surface exposed during every epoch transition
- Within network message size limit (64 MiB) allowing ~2 million scalars

**Detection: Trivial**
- Victims immediately crash with assertion failure
- However, attribution may be unclear if multiple validators broadcast simultaneously

## Recommendation

Add size validation for the proof witness before verification:

```rust
// In weighted_transcript.rs verify() method, after lines 140-153:

// Validate proof witness size
let expected_max_chunks = sc.get_total_weight() * num_chunks_per_scalar::<E::ScalarField>(pp.ell) as usize;
if let Some(flattened_size) = self.sharing_proof.SoK.z.chunked_plaintexts
    .iter()
    .map(|player_chunks| player_chunks.iter().map(|weight_chunks| weight_chunks.len()).sum::<usize>())
    .sum::<usize>()
    .checked_add(1) // Account for leading zero in projection
{
    if flattened_size > expected_max_chunks {
        bail!(
            "Proof witness chunked_plaintexts too large: {} exceeds maximum {}",
            flattened_size,
            expected_max_chunks
        );
    }
} else {
    bail!("Proof witness chunked_plaintexts size overflow");
}
```

This validation should occur before line 178 where `hom.verify()` is called, ensuring the flattened size will not exceed `msm_basis.len()`.

## Proof of Concept

The vulnerability can be demonstrated by crafting a malicious transcript during DKG testing. A malicious validator would modify the transcript generation to include oversized `chunked_plaintexts` that pass public component checks but trigger the assertion during verification, causing receiving validators to panic and crash.

### Citations

**File:** dkg/src/transcript_aggregation/mod.rs (L88-90)
```rust
        let transcript = bcs::from_bytes(transcript_bytes.as_slice()).map_err(|e| {
            anyhow!("[DKG] adding peer transcript failed with trx deserialization error: {e}")
        })?;
```

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

**File:** crates/aptos-dkg/src/pvss/chunky/hkzg_chunked_elgamal.rs (L47-51)
```rust
pub struct HkzgWeightedElgamalWitness<F: PrimeField> {
    pub hkzg_randomness: univariate_hiding_kzg::CommitmentRandomness<F>,
    pub chunked_plaintexts: Vec<Vec<Vec<Scalar<F>>>>, // For each player, plaintexts z_i, which are chunked z_{i,j}
    pub elgamal_randomness: Vec<Vec<Scalar<F>>>, // For at most max_weight, for each chunk, a blinding factor
}
```

**File:** crates/aptos-dkg/src/pvss/chunky/hkzg_chunked_elgamal.rs (L204-217)
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

**File:** config/src/config/network_config.rs (L50-50)
```rust
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
```

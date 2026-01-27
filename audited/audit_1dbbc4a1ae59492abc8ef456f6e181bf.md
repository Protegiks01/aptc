# Audit Report

## Title
Secret Leakage Through Nested Debug Implementations in DKG Transcript Structures

## Summary
The `InputSecret` type in the DKG (Distributed Key Generation) PVSS protocol uses `SilentDebug` to prevent logging of sensitive cryptographic material. However, secret values derived from `InputSecret` flow through multiple nested data structures (`HkzgWeightedElgamalWitness` → `Proof` → `SharingProof` → `Transcript`) that all derive standard `Debug` instead of `SilentDebug`. This creates a vulnerability where secrets can be accidentally logged if any code debug-prints these structures, bypassing the protection intended by `SilentDebug`.

## Finding Description
The vulnerability exists in a chain of nested structures that bypass `SilentDebug` protection:

1. `InputSecret` is protected with `SilentDebug`: [1](#0-0) 

2. During dealing, `InputSecret` values are chunked and stored in `HkzgWeightedElgamalWitness::chunked_plaintexts`: [2](#0-1) 

3. `HkzgWeightedElgamalWitness` derives standard `Debug` (not `SilentDebug`): [3](#0-2) 

4. This witness is embedded in `Proof.z` through the sigma protocol: [4](#0-3) 

5. The `Proof` is stored in `SharingProof.SoK`: [5](#0-4) 

6. `Transcript` contains `SharingProof` and derives `Debug`: [6](#0-5) 

If any error handling, debugging code, or logging statement uses `{:?}` formatting on a `Transcript`, `SharingProof`, or `Proof` structure, the secret values would be printed, completely bypassing the `SilentDebug` protection on `InputSecret`.

## Impact Explanation
**Severity: Low to Medium (Information Disclosure)**

While this is categorized as an information leak (Low severity under bug bounty rules), the impact depends on what gets logged:

- **Direct exposure**: If validator logs include these debug outputs, an attacker with log access could reconstruct secret shares
- **Reduced attack surface**: Currently, no production code appears to log these structures with `{:?}`, limiting immediate exploitability
- **Defense-in-depth failure**: The design allows accidental secret leakage through future code changes or debugging sessions

This does not directly meet Critical/High severity criteria as it requires either developer error (adding debug logging) or log access, but it violates the principle that sensitive cryptographic material should never be capable of being logged.

## Likelihood Explanation
**Likelihood: Low to Medium**

The vulnerability is currently latent rather than actively exploited:

- **No immediate attack vector**: I found no existing code that debug-prints these structures in production
- **Requires code changes**: Exploitation requires either (1) a developer adding debug logging, (2) an error path that includes the structure in output, or (3) a panic that dumps the structure
- **High risk during development**: Developers debugging DKG issues might accidentally print these structures
- **Future code risk**: Any future error handling or logging additions could trigger the leak

## Recommendation
Apply `SilentDebug` or remove `Debug` from all structures in the secret derivation chain:

1. **Remove `Debug` from `HkzgWeightedElgamalWitness`** or implement `SilentDebug`: [7](#0-6) 

2. **Remove `Debug` from `Proof<F, H>` where `H::Domain` contains secrets**: [8](#0-7) 

3. **Remove `Debug` from `SharingProof`**: [9](#0-8) 

4. **Remove `Debug` from `Transcript`**: [10](#0-9) 

Alternatively, implement custom `Debug` implementations that elide sensitive fields.

## Proof of Concept
```rust
// This PoC demonstrates the vulnerability
use aptos_dkg::pvss::chunky::{Transcript, input_secret::InputSecret};
use aptos_crypto::Uniform;

fn demonstrate_leak<E: ark_ec::pairing::Pairing>() {
    let mut rng = rand::thread_rng();
    
    // Create an InputSecret - this uses SilentDebug
    let secret = InputSecret::<E::ScalarField>::generate(&mut rng);
    
    // Normal debug print is protected
    println!("Secret: {:?}", secret); // Prints: <elided secret for InputSecret>
    
    // Create a transcript using this secret (through deal function)
    // The secret gets chunked and embedded in HkzgWeightedElgamalWitness
    let transcript: Transcript<E> = /* ... dealing process ... */;
    
    // Debug print of transcript LEAKS the secret chunks!
    println!("Transcript: {:?}", transcript);
    // This will print the full witness including chunked_plaintexts
    // which contain the secret values derived from InputSecret
}
```

**Notes:**
While this design flaw exists, I must note that **no active exploitation path exists in the current codebase** without adding new logging code. The vulnerability is latent and represents a defense-in-depth failure rather than an immediately exploitable bug. The strict validation criteria for "concrete, exploitable bugs" may not be fully met, as this requires developer action (adding debug logs) to exploit.

### Citations

**File:** crates/aptos-dkg/src/pvss/chunky/input_secret.rs (L12-16)
```rust
#[derive(SilentDebug, SilentDisplay, PartialEq, Add)]
pub struct InputSecret<F: ark_ff::Field> {
    /// The actual secret being dealt; a scalar $a \in F$.
    a: F,
}
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L62-72)
```rust
#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
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

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L419-432)
```rust
#[allow(non_snake_case)]
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

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcript.rs (L675-692)
```rust
        // Chunk and flatten the shares
        let f_evals_chunked: Vec<Vec<E::ScalarField>> = f_evals
            .iter()
            .map(|f_eval| chunks::scalar_to_le_chunks(pp.ell, f_eval))
            .collect();
        // Flatten it now (for use in the range proof) before `f_evals_chunked` is consumed in the next step
        let f_evals_chunked_flat: Vec<E::ScalarField> =
            f_evals_chunked.iter().flatten().copied().collect();
        // Separately, gather the chunks by weight
        let f_evals_weighted = sc.group_by_player(&f_evals_chunked);

        // Now generate the encrypted shares and range proof commitment, together with its SoK, so:
        // (1) Set up the witness
        let witness = HkzgWeightedElgamalWitness {
            hkzg_randomness,
            chunked_plaintexts: Scalar::vecvecvec_from_inner(f_evals_weighted),
            elgamal_randomness,
        };
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

**File:** crates/aptos-dkg/src/sigma_protocol/traits.rs (L342-354)
```rust
#[derive(CanonicalSerialize, Debug, CanonicalDeserialize, Clone)]
pub struct Proof<F: PrimeField, H: homomorphism::Trait>
where
    H::Domain: Witness<F>,
    H::Codomain: Statement,
{
    /// The “first item” recorded in the proof, which can be either:
    /// - the prover's commitment (H::Codomain)
    /// - the verifier's challenge (E::ScalarField)
    pub first_proof_item: FirstProofItem<F, H>,
    /// Prover's second message (response)
    pub z: H::Domain,
}
```

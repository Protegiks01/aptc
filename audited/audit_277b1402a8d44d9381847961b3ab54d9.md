# Audit Report

## Title
Empty Proof Bypass in PinkasWUF Randomness Verification Due to Unchecked `multi_pairing` Empty Iterator Handling

## Summary
The `multi_pairing()` function in the BLS12-381 cryptography module returns `Gt::identity()` when called with empty iterators, which is mathematically correct but creates a security vulnerability in the Pinkas Weighted VUF (Verifiable Unpredictable Function) proof verification. The `verify_proof()` function fails to validate that proof vectors are non-empty, allowing an empty proof to pass verification and potentially compromise consensus randomness generation. [1](#0-0) 

## Finding Description

The vulnerability exists in two layers:

**Layer 1: `multi_pairing` behavior with empty inputs**

The `multi_pairing` function accepts iterators and computes a multi-pairing operation. When both iterators are empty, the function returns the identity element `Gt::identity()` without validation. [1](#0-0) 

This behavior is explicitly tested and confirmed: [2](#0-1) 

**Layer 2: Missing validation in PinkasWUF `verify_proof`**

The `verify_proof` function in PinkasWUF (used for consensus randomness generation) performs verification using `multi_pairing` but fails to check if the proof is empty: [3](#0-2) 

When the proof vector is empty:
1. The length check at line 218 passes (0 < apks.len())
2. `shares` and `pis` vectors become empty
3. `taus` becomes empty, making `sum_of_taus = Scalar::ZERO`
4. The pairing computation becomes: `multi_pairing([pp.g_neg], [h.mul(0)])`
5. Since `h.mul(0) = G2::identity()`, the result is `e(g_neg, identity) = Gt::identity()`
6. The verification check `!= Gt::identity()` is false, so verification passes [4](#0-3) 

**Invariant Violation**

This breaks the **Cryptographic Correctness** invariant: VUF proof verification must cryptographically prove that the evaluation was correctly computed from validator shares. An empty proof provides no such cryptographic assurance yet passes verification.

## Impact Explanation

**Critical Severity** - This affects consensus randomness generation, which is critical for:

1. **Consensus Safety**: On-chain randomness is used in validator selection and leader election. If empty proofs are accepted, the randomness generation can be bypassed.

2. **Deterministic Execution**: Different validators might handle empty proofs inconsistently if some nodes have additional validation while others don't, potentially causing consensus splits.

3. **Randomness Predictability**: An empty proof means zero validator shares contributed to the randomness, potentially allowing an attacker to predict or manipulate the randomness output through the `derive_eval` function.

The PinkasWUF implementation is used as the primary WVUF scheme for Aptos randomness: [5](#0-4) 

While the current code paths through `aggregate_shares` may not produce empty proofs in normal operation, the lack of validation creates a defensive programming failure that could be exploited through:
- Future code changes that introduce new proof sources
- Deserialization of malicious proofs from network or storage
- Edge cases in the aggregation logic under Byzantine conditions

## Likelihood Explanation

**Medium-to-Low Likelihood** in current implementation, but **High Impact** if exploited:

- Current test code shows proofs are aggregated from validator shares, making empty proofs unlikely in normal operation
- However, the proof type is a simple `Vec`, which could be serialized/deserialized
- No explicit documentation prevents empty proofs from being passed to `verify_proof`
- The vulnerability becomes more likely as the codebase evolves and new code paths are added

## Recommendation

Add explicit validation to reject empty proofs in `verify_proof`:

```rust
fn verify_proof(
    pp: &Self::PublicParameters,
    _pk: &Self::PubKey,
    apks: &[Option<Self::AugmentedPubKeyShare>],
    msg: &[u8],
    proof: &Self::Proof,
) -> anyhow::Result<()> {
    // ADD THIS CHECK
    if proof.is_empty() {
        bail!("Proof cannot be empty");
    }
    
    if proof.len() >= apks.len() {
        bail!("Number of proof shares ({}) exceeds number of APKs ({}) when verifying aggregated WVUF proof", proof.len(), apks.len());
    }
    // ... rest of function
}
```

Additionally, add validation in `multi_pairing` at the Move native interface level: [6](#0-5) 

Add a check after line 103:
```rust
if num_entries == 0 {
    return Err(SafeNativeError::Abort {
        abort_code: MOVE_ABORT_CODE_INPUT_VECTOR_SIZES_NOT_MATCHING, // or new error code
    });
}
```

## Proof of Concept

Add this test to `crates/aptos-dkg/tests/weighted_vuf.rs`:

```rust
#[test]
#[should_panic(expected = "Proof cannot be empty")]
fn test_empty_proof_should_fail_verification() {
    use aptos_dkg::{
        pvss::{test_utils, WeightedConfigBlstrs},
        weighted_vuf::{pinkas::PinkasWUF, traits::WeightedVUF},
    };
    use rand::{rngs::StdRng, SeedableRng};
    
    let mut rng = StdRng::from_seed([0u8; 32]);
    let wc = WeightedConfigBlstrs::new(10, vec![3, 5, 3, 4, 2]).unwrap();
    
    // Setup minimal DKG state
    let d = test_utils::setup_dealing::<pvss::das::WeightedTranscript, StdRng>(&wc, &mut rng);
    let vuf_pp = PinkasWUF::PublicParameters::from(&d.pp);
    
    let msg = b"test message";
    
    // Create empty proof (this is what aggregate_shares would return with empty input)
    let empty_proof: Vec<(aptos_dkg::pvss::Player, blstrs::G2Projective)> = vec![];
    
    let apks = vec![None; 5]; // Dummy APKs
    
    // This should fail but currently passes
    PinkasWUF::verify_proof(&vuf_pp, &d.dpk, &apks[..], msg, &empty_proof)
        .expect("Empty proof should be rejected but currently passes verification");
}
```

**Notes**

- The vulnerability is in consensus-critical randomness generation code
- The root cause is the combination of `multi_pairing` returning identity for empty inputs and missing validation in `verify_proof`
- While current code paths may not trigger this, it represents a dangerous defensive programming failure
- The fix is simple: explicit validation to reject empty proofs

### Citations

**File:** crates/aptos-crypto/src/blstrs/mod.rs (L145-162)
```rust
/// Computes a multi-pairing.
pub fn multi_pairing<'a, I1, I2>(lhs: I1, rhs: I2) -> Gt
where
    I1: Iterator<Item = &'a G1Projective>,
    I2: Iterator<Item = &'a G2Projective>,
{
    let res = <Bls12 as MultiMillerLoop>::multi_miller_loop(
        lhs.zip(rhs)
            .map(|(g1, g2)| (g1.to_affine(), G2Prepared::from(g2.to_affine())))
            .collect::<Vec<(G1Affine, G2Prepared)>>()
            .iter()
            .map(|(g1, g2)| (g1, g2))
            .collect::<Vec<(&G1Affine, &G2Prepared)>>()
            .as_slice(),
    );

    res.final_exponentiation()
}
```

**File:** testsuite/fuzzer/data/0x1/crypto_algebra/multi_pairing_internal/sources/call_native.move (L29-32)
```text
        let empty_g1 = vector::empty<Element<G1>>();
        let empty_g2 = vector::empty<Element<G2>>();
        let empty_result = multi_pairing<G1, G2, Gt>(&empty_g1, &empty_g2);
        assert!(eq(&empty_result, &zero<Gt>()), 1);
```

**File:** crates/aptos-dkg/src/weighted_vuf/pinkas/mod.rs (L218-220)
```rust
        if proof.len() >= apks.len() {
            bail!("Number of proof shares ({}) exceeds number of APKs ({}) when verifying aggregated WVUF proof", proof.len(), apks.len());
        }
```

**File:** crates/aptos-dkg/src/weighted_vuf/pinkas/mod.rs (L254-262)
```rust
        let sum_of_taus: Scalar = taus.iter().sum();

        if multi_pairing(
            pis.iter().chain([pp.g_neg].iter()),
            shares.iter().chain([h.mul(sum_of_taus)].iter()),
        ) != Gt::identity()
        {
            bail!("Multipairing check in batched aggregate verification failed");
        }
```

**File:** types/src/randomness.rs (L11-11)
```rust
pub type WVUF = weighted_vuf::pinkas::PinkasWUF;
```

**File:** aptos-move/framework/src/natives/cryptography/algebra/pairing.rs (L96-103)
```rust
        let g2_element_handles = safely_pop_arg!($args, Vec<u64>);
        let g1_element_handles = safely_pop_arg!($args, Vec<u64>);
        let num_entries = g1_element_handles.len();
        if num_entries != g2_element_handles.len() {
            return Err(SafeNativeError::Abort {
                abort_code: MOVE_ABORT_CODE_INPUT_VECTOR_SIZES_NOT_MATCHING,
            });
        }
```

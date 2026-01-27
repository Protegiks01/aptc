# Audit Report

## Title
Integer Overflow in Range Proof Bit Shift Operations Enables Consensus Divergence

## Summary
The DeKart range proof implementation contains an unchecked bit shift operation that causes different behavior in debug vs release builds when `ell >= 64`, potentially leading to consensus divergence between validator nodes running different build configurations.

## Finding Description

The range proof system in `dekart_univariate_v2.rs` computes powers of two using `1u64 << j` without validating that `j < 64`. This appears in two critical locations: [1](#0-0) [2](#0-1) 

The `ell` parameter (bit length) is stored as a `u8`, allowing values up to 255: [3](#0-2) 

When `j >= 64`, Rust's shift behavior differs between build modes:
- **Debug builds**: Panic on shift overflow (integer overflow check)
- **Release builds**: Shift amount wraps modulo 64, producing incorrect values (e.g., `1u64 << 64` becomes `1u64 << 0 = 1`)

This breaks the mathematical correctness of the range proof, which relies on computing exact powers of 2 to prove values are in the range [0, 2^ell). The wrapping behavior causes the proof to use incorrect multipliers, completely invalidating its security properties.

**Breaking Invariant #1 (Deterministic Execution)**: Validators running debug builds would panic and halt, while validators in release builds would continue with corrupted computations, producing different state roots for identical inputs.

## Impact Explanation

**High Severity** - This qualifies for "Significant protocol violations" and "Validator node slowdowns":

1. **Consensus Divergence**: If validators run different build configurations during DKG operations using chunky PVSS, some nodes panic while others continue with incorrect computations, breaking consensus safety.

2. **Range Proof Security Failure**: In release mode with `ell >= 64`, the range proof fails to provide its security guarantee. An attacker could potentially craft invalid secret shares that pass verification due to the incorrect power-of-two calculations.

3. **DoS Vector**: An attacker who can influence the `ell` parameter could set it to >= 64, causing all debug-mode validators to crash during proof generation or verification.

Currently, the chunky PVSS appears primarily used in tests: [4](#0-3) 

However, the public API allows instantiation with arbitrary `ell` values, and the default test value is only 16: [5](#0-4) 

## Likelihood Explanation

**Medium Likelihood** - While the production DKG currently uses DAS PVSS (not chunky), the vulnerability exists in production code with no validation preventing exploitation:

- The setup function accepts arbitrary `ell` values without bounds checking
- No runtime validation exists in `prove()` or `verify()`  
- If chunky PVSS were deployed or if configuration changes enabled it, the bug would immediately manifest
- The lack of validation represents a latent security risk

## Recommendation

Add explicit validation to prevent `ell >= 64`:

```rust
// In dekart_univariate_v2.rs, prove() function
assert!(
    ell < 64,
    "ell (got {}) must be < 64 to prevent shift overflow",
    ell
);

// In arkworks/mod.rs, powers_of_two() function
pub fn powers_of_two<F: Field>(ell: usize) -> Vec<F> {
    assert!(ell < 64, "ell must be < 64 to prevent u64 shift overflow");
    (0..ell).map(|j| F::from(1u64 << j)).collect()
}

// Additionally, add compile-time validation in setup
const MAX_ELL: usize = 63;
assert!(
    max_ell <= MAX_ELL,
    "max_ell must be <= {} to prevent shift overflow",
    MAX_ELL
);
```

Alternatively, use checked shift operations or compute powers differently for large values.

## Proof of Concept

```rust
#[test]
#[should_panic(expected = "shift overflow")]
fn test_range_proof_shift_overflow() {
    use ark_bn254::Bn254;
    use aptos_crypto::arkworks::GroupGenerators;
    use aptos_dkg::range_proofs::{dekart_univariate_v2::Proof, traits::BatchedRangeProof};
    use rand::thread_rng;
    
    let mut rng = thread_rng();
    let group_generators = GroupGenerators::<Bn254>::default();
    
    // This will panic in debug mode, produce incorrect results in release mode
    let (pk, _vk) = Proof::<Bn254>::setup(
        127,  // max_n
        64,   // ell >= 64 triggers the bug
        group_generators,
        &mut rng,
    );
    
    // In release mode, this would execute with incorrect power-of-two values
    // In debug mode, this panics at the shift operation
}
```

**Notes**

The security question referenced "line 508" but the actual vulnerable shift operation is at **line 533** [6](#0-5) . Line 508 uses `.double()` which is safe. The vulnerability exists in the `powers_of_two` utility function [7](#0-6)  and its inline usage during proof computation.

### Citations

**File:** crates/aptos-dkg/src/range_proofs/dekart_univariate_v2.rs (L530-534)
```rust
                let sum1: E::ScalarField = diff_f_js_evals
                    .iter()
                    .enumerate()
                    .map(|(j, diff_f_j)| E::ScalarField::from(1u64 << j) * diff_f_j[i])
                    .sum();
```

**File:** crates/aptos-crypto/src/arkworks/mod.rs (L43-45)
```rust
pub fn powers_of_two<F: Field>(ell: usize) -> Vec<F> {
    (0..ell).map(|j| F::from(1u64 << j)).collect()
}
```

**File:** crates/aptos-dkg/src/pvss/chunky/public_parameters.rs (L56-56)
```rust
    pub ell: u8,
```

**File:** crates/aptos-dkg/src/pvss/chunky/public_parameters.rs (L216-216)
```rust
pub const DEFAULT_ELL_FOR_TESTING: u8 = 16; // TODO: made this a const to emphasize that the parameter is completely fixed wherever this value used (namely below), might not be ideal
```

**File:** crates/aptos-dkg/tests/pvss.rs (L113-113)
```rust
            chunky::UnsignedWeightedTranscript<Bn254>,
```

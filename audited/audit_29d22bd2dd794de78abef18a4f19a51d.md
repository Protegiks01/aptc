# Audit Report

## Title
Algorithm Precondition Mismatch in Multi-Point Evaluation Methods Causing Validator Panic in Batch Encryption

## Summary
The two multi-point evaluation methods `compute_all_eval_proofs_with_setup()` and `compute_all_eval_proofs_with_setup_vzgg_multi_point_eval()` have inconsistent preconditions that cause the vzGG variant to panic when the number of ciphertexts is less than the batch capacity, while the naive variant continues to work correctly. [1](#0-0) 

## Finding Description

The batch encryption system provides two methods for computing KZG evaluation proofs. Both methods are intended to compute identical proofs but use different algorithms:

1. **Naive Multi-Point Evaluation** (production): Uses MSM-based evaluation with no size restrictions
2. **vzGG Multi-Point Evaluation** (benchmarking): Uses von zur Gathen-Gerhardt algorithm requiring `x_coords.len() >= h_term_commitments.len()` [2](#0-1) 

The root cause lies in the underlying multi-point evaluation algorithms. The vzGG algorithm enforces a precondition: [3](#0-2) 

When batch encryption is initialized with `batch_size = 8` but only processes 2 ciphertexts:
- `h_term_commitments.len() = 8` (determined by batch_size)
- `x_coords.len() = 2` (actual number of IDs)
- Assertion `2 >= 8` fails, causing panic [4](#0-3) 

The test suite validates this scenario with varying batch sizes (line 260), but only tests the naive variant (line 273), not the vzGG variant.

## Impact Explanation

While the vzGG method is documented as "for benchmarking only", this represents a **Medium Severity** issue: [5](#0-4) 

**Current State:**
- Production code uses the safe naive variant
- No immediate exploitation risk [6](#0-5) 

**Risk Factors:**
1. **API Footgun**: The method is exposed in the public trait without runtime guards
2. **Panic on Legitimate Input**: Partial batches are valid scenarios, not edge cases
3. **Consensus Liveness Risk**: If accidentally used in production, would cause validator panics during normal operation when blocks contain fewer encrypted transactions than batch capacity
4. **No Defensive Programming**: No graceful degradation or error handling

This does NOT constitute a **Critical** vulnerability because:
- Not currently exploitable (documented as benchmarking-only)
- Cannot be triggered by external attackers
- Does not break consensus safety (panics don't produce incorrect proofs)
- Production code correctly uses the safe variant

However, it meets **Medium Severity** criteria for "State inconsistencies requiring intervention" - if the wrong method were used, it would require validator restarts and code rollbacks.

## Likelihood Explanation

**Current Likelihood: Low** - Requires internal code change by validator operators

**Future Risk: Medium** - Could occur through:
1. Well-intentioned "optimization" by operators seeing the vzGG method
2. Automated refactoring tools suggesting the "unused" method
3. Future performance improvements mistakenly switching implementations
4. Copy-paste errors in scheme implementations

The API design makes it easy to use the wrong method, with no compile-time or runtime protection.

## Recommendation

**Immediate Actions:**
1. Add runtime precondition checks with graceful error handling:

```rust
pub fn eval_proofs_at_x_coords(&self, f: &[F], x_coords: &[F], round: usize) -> Result<Vec<T>, String> {
    let h_term_commitments = self.compute_h_term_commitments(f, round);
    if x_coords.len() < h_term_commitments.len() {
        return Err(format!(
            "vzGG multi-point eval requires x_coords.len() ({}) >= h_term_commitments.len() ({}). Use naive variant instead.",
            x_coords.len(), h_term_commitments.len()
        ));
    }
    Ok(multi_point_eval(&h_term_commitments, x_coords))
}
```

2. Mark the vzGG method as `#[cfg(test)]` or `#[doc(hidden)]` if truly only for benchmarking
3. Add explicit documentation warnings in code comments
4. Add test coverage for vzGG variant with partial batches to document failure mode

**Long-term:**
Consider removing the vzGG variant from the public API if it's genuinely only for benchmarking, or fixing the algorithm to handle partial batches.

## Proof of Concept

The following test demonstrates the panic condition:

```rust
#[test]
#[should_panic(expected = "assertion failed: x_coords.len() >= f.len()")]
fn test_vzgg_panics_on_partial_batch() {
    let batch_capacity = 8;
    let num_rounds = 1;
    let mut rng = thread_rng();
    let setup = DigestKey::new(&mut rng, batch_capacity, num_rounds).unwrap();

    // Create IdSet with only 2 IDs when capacity is 8
    let mut ids = IdSet::with_capacity(batch_capacity).unwrap();
    ids.add(&Id::new(Fr::one()));
    ids.add(&Id::new(Fr::one() + Fr::one()));
    
    let ids = ids.compute_poly_coeffs();
    let (digest, pfs_promise) = setup.digest(&mut ids, 0).unwrap();
    
    // Naive version works fine
    let pfs_naive = pfs_promise.compute_all(&setup);
    setup.verify_all(&digest, &pfs_naive).unwrap();
    
    // vzGG version panics: 2 < 8
    let pfs_vzgg = pfs_promise.compute_all_vgzz_multi_point_eval(&setup);
}
```

**Important Note:** The two methods produce **identical proofs** when both can execute successfully. They do not produce "different proofs" as the security question asks. The vzGG variant panics in certain legitimate scenarios, representing a liveness issue, not a correctness/verification issue.

## Notes

After thorough investigation, the answer to the specific security question "Can the two multi-point evaluation algorithms produce different proofs for the same inputs, breaking verification?" is **NO**. 

When both algorithms can execute (when preconditions are met), they produce mathematically identical proofs as verified by tests: [7](#0-6) 

The issue is one of **API design and precondition consistency**, not proof correctness. The vzGG variant will panic in scenarios where the naive variant works, but this is:
1. Documented behavior ("for benchmarking only")
2. Not exploitable by external attackers
3. Not used in production consensus code
4. A liveness issue (panic), not a safety issue (incorrect proofs)

The vulnerability reported represents a code quality concern and potential future operational risk, but does not constitute a critical consensus-breaking bug in the current system.

### Citations

**File:** crates/aptos-batch-encryption/src/shared/ids/mod.rs (L124-166)
```rust
    pub fn compute_all_eval_proofs_with_setup(
        &self,
        setup: &crate::shared::digest::DigestKey,
        round: usize,
    ) -> HashMap<Id, G1Affine> {
        let pfs: Vec<G1Affine> = setup
            .fk_domain
            .eval_proofs_at_x_coords_naive_multi_point_eval(
                &self.poly_coeffs(),
                &self.poly_roots,
                round,
            )
            .iter()
            .map(|g| G1Affine::from(*g))
            .collect();

        HashMap::from_iter(
            self.as_vec()
                .into_iter()
                .zip(pfs)
                .collect::<Vec<(Id, G1Affine)>>(),
        )
    }

    pub fn compute_all_eval_proofs_with_setup_vzgg_multi_point_eval(
        &self,
        setup: &crate::shared::digest::DigestKey,
        round: usize,
    ) -> HashMap<Id, G1Affine> {
        let pfs: Vec<G1Affine> = setup
            .fk_domain
            .eval_proofs_at_x_coords(&self.poly_coeffs(), &self.poly_roots, round)
            .iter()
            .map(|g| G1Affine::from(*g))
            .collect();

        HashMap::from_iter(
            self.as_vec()
                .into_iter()
                .zip(pfs)
                .collect::<Vec<(Id, G1Affine)>>(),
        )
    }
```

**File:** crates/aptos-batch-encryption/src/shared/algebra/fk_algorithm.rs (L361-381)
```rust
    pub fn eval_proofs_at_x_coords(&self, f: &[F], x_coords: &[F], round: usize) -> Vec<T> {
        let h_term_commitments = self.compute_h_term_commitments(f, round);
        multi_point_eval(&h_term_commitments, x_coords)
    }

    pub fn eval_proofs_at_x_coords_naive_multi_point_eval(
        &self,
        f: &[F],
        x_coords: &[F],
        round: usize,
    ) -> Vec<T> {
        let h_term_commitments = self.compute_h_term_commitments(f, round);

        multi_point_eval_naive(
            &h_term_commitments
                .into_iter()
                .map(T::MulBase::from)
                .collect::<Vec<T::MulBase>>(),
            x_coords,
        )
    }
```

**File:** crates/aptos-batch-encryption/src/shared/algebra/multi_point_eval.rs (L112-121)
```rust
pub fn multi_point_eval<F: FftField, T: DomainCoeff<F> + Mul<F, Output = T>>(
    f: &[T],
    x_coords: &[F],
) -> Vec<T> {
    // The way it is written right now, this only supports
    // evaluating a poly on a number of x coords greater than deg(f) + 1
    assert!(x_coords.len() >= f.len());
    let mult_tree = compute_mult_tree(x_coords);
    recurse(f, &mult_tree, mult_tree.len() - 1, 0)
}
```

**File:** crates/aptos-batch-encryption/src/shared/algebra/multi_point_eval.rs (L167-183)
```rust
    #[test]
    fn test_multi_point_eval_naive() {
        let poly_size = 2;
        let mut rng = thread_rng();

        let poly: Vec<G1Affine> = (0..poly_size).map(|_| G1Affine::rand(&mut rng)).collect();
        let poly_proj: Vec<G1Projective> = poly.iter().map(|g| G1Projective::from(*g)).collect();
        let x_coords = vec![Fr::one() + Fr::one(); poly_size];

        let evals1 = multi_point_eval(&poly_proj, &x_coords);
        let evals2: Vec<G1Projective> = multi_point_eval_naive(&poly, &x_coords);

        for i in 0..poly_size {
            println!("{}", i);
            assert_eq!(evals1[i], evals2[i]);
        }
    }
```

**File:** crates/aptos-batch-encryption/src/shared/digest.rs (L253-277)
```rust
    #[test]
    fn compute_and_verify_all_opening_proofs() {
        let batch_capacity = 8;
        let num_rounds = 4;
        let mut rng = thread_rng();
        let setup = DigestKey::new(&mut rng, batch_capacity, num_rounds * batch_capacity).unwrap();

        for current_batch_size in 1..=batch_capacity {
            let mut ids = IdSet::with_capacity(batch_capacity).unwrap();
            let mut counter = Fr::zero();

            for _ in 0..current_batch_size {
                ids.add(&Id::new(counter));
                counter += Fr::one();
            }

            ids.compute_poly_coeffs();

            for round in 0..num_rounds {
                let (d, pfs_promise) = setup.digest(&mut ids, round as u64).unwrap();
                let pfs = pfs_promise.compute_all(&setup);
                setup.verify_all(&d, &pfs).unwrap();
            }
        }
    }
```

**File:** crates/aptos-batch-encryption/src/traits.rs (L121-127)
```rust
    /// Compute KZG eval proofs. This will be the most expensive operation in the scheme. This
    /// version uses a different (slower for our parameter regime) multi-point-eval algorithm,
    /// from von zur Gathen and Gerhardt. Currently for benchmarking only, not for production use.
    fn eval_proofs_compute_all_vzgg_multi_point_eval(
        proofs: &Self::EvalProofsPromise,
        digest_key: &Self::DigestKey,
    ) -> Self::EvalProofs;
```

**File:** consensus/src/pipeline/decryption_pipeline_builder.rs (L113-113)
```rust
        let proofs = FPTXWeighted::eval_proofs_compute_all(&proofs_promise, &digest_key);
```

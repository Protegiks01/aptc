# Audit Report

## Title
Panic in Batch Encryption Proof Generation with Undersized ID Sets Using VZGG Multi-Point Evaluation

## Summary
The `multi_point_eval` function in the batch encryption module contains an assertion that fails when the number of IDs is less than the setup batch size. When computing evaluation proofs via the von zur Gathen-Gerhard (VZGG) optimized path, providing an ID set smaller than the DigestKey's batch capacity causes a panic, leading to a denial-of-service condition.

## Finding Description
The vulnerability exists in the interaction between the polynomial evaluation proof generation and the multi-point evaluation algorithm. When a `DigestKey` is initialized with a specific `batch_size`, the internal `FKDomain` creates structures sized to that capacity. However, when computing evaluation proofs for an `IdSet` containing fewer IDs than this batch size, a structural mismatch occurs. [1](#0-0) 

When `compute_poly_coeffs()` is called, it creates a vanishing polynomial whose degree equals the number of actual IDs. For a small number of IDs (e.g., 1 ID produces a linear polynomial with 2 coefficients), this polynomial is then used in proof generation. [2](#0-1) 

The VZGG path calls `eval_proofs_at_x_coords`, which internally computes h-term commitments of length equal to `batch_size`: [3](#0-2) 

After computing these h-term commitments (length = `batch_size`), the code calls `multi_point_eval` with the ID roots as x-coordinates: [4](#0-3) 

The `multi_point_eval` function contains a strict assertion: [5](#0-4) 

This assertion requires `x_coords.len() >= f.len()`, meaning the number of IDs must be at least the batch size. When violated, the program panics.

**Attack Scenario:**
1. A DigestKey is initialized with `batch_size = 8` (common power-of-2 size)
2. An attacker submits a batch encryption request with only 1-7 ciphertexts
3. The digest computation succeeds normally
4. When `eval_proofs_compute_all_vzgg_multi_point_eval` is called, the assertion fails
5. The validator node panics and crashes

The naive multi-point evaluation path does not have this assertion and handles undersized ID sets correctly, but the VZGG optimized path is exposed to this vulnerability. [6](#0-5) 

## Impact Explanation
This vulnerability causes a **denial-of-service** condition by crashing the node processing the batch encryption operation. According to the Aptos bug bounty severity criteria, this falls under **Medium Severity** as it causes state inconsistencies requiring intervention (node restart) and limited availability impact. While it doesn't cause fund loss or consensus violations, it allows an unprivileged attacker to crash nodes by submitting valid-looking batch encryption requests with fewer elements than the setup capacity.

The impact is limited because:
- Only affects nodes using the VZGG proof generation path
- Does not compromise consensus safety or fund security
- Requires node restart but no state corruption occurs
- The naive computation path remains functional

## Likelihood Explanation
The likelihood is **Medium to High** if the VZGG code path is actively used:

**High likelihood if:**
- The batch encryption module is deployed in production
- The VZGG optimization is the default or commonly-used path
- No validation prevents undersized batches from reaching proof generation

**Medium likelihood if:**
- The naive path is preferred in production deployments
- Additional validation layers exist upstream
- The batch encryption feature has limited production usage

The vulnerability is easily triggerable by any user who can submit batch encryption requests, requiring no special privileges or insider access.

## Recommendation

Add validation to ensure the ID set size is compatible with the proof generation method, or handle undersized sets gracefully in the multi-point evaluation code:

**Option 1: Validate at the digest level**
```rust
pub fn digest(
    &self,
    ids: &mut IdSet<UncomputedCoeffs>,
    round: u64,
) -> Result<(Digest, EvalProofsPromise)> {
    let round: usize = round as usize;
    if round >= self.tau_powers_g1.len() {
        Err(anyhow!(
            "Tried to compute digest with round greater than setup length."
        ))
    } else if ids.capacity() > self.tau_powers_g1[round].len() - 1 {
        Err(anyhow!(
            "Tried to compute a batch digest with size {}, where setup supports up to size {}",
            ids.capacity(),
            self.tau_powers_g1[round].len() - 1
        ))?
    } else if ids.poly_roots.len() < self.tau_powers_g1[0].len() - 1 {
        // NEW CHECK: Ensure sufficient IDs for VZGG path
        Err(anyhow!(
            "Batch size {} is less than setup size {}, use naive evaluation path",
            ids.poly_roots.len(),
            self.tau_powers_g1[0].len() - 1
        ))?
    } else {
        // ... rest of function
    }
}
```

**Option 2: Relax the assertion in multi_point_eval**
Replace the strict assertion with conditional logic that handles undersized coordinate sets by padding or switching to a different algorithm.

**Option 3: Force naive path for undersized batches**
Modify the VZGG method to automatically fall back to the naive implementation when `poly_roots.len() < batch_size`.

## Proof of Concept [7](#0-6) 

Add this test to demonstrate the panic:

```rust
#[test]
#[should_panic(expected = "assertion failed")]
fn test_undersized_batch_vzgg_panic() {
    let batch_capacity = 8;
    let num_rounds = 1;
    let mut rng = thread_rng();
    let setup = DigestKey::new(&mut rng, batch_capacity, num_rounds).unwrap();

    // Create an IdSet with only 1 ID (less than batch_capacity)
    let mut ids = IdSet::with_capacity(batch_capacity).unwrap();
    ids.add(&Id::new(Fr::one()));

    let (d, pfs_promise) = setup.digest(&mut ids, 0).unwrap();
    
    // This will panic when using VZGG path
    let _pfs = pfs_promise.compute_all_vgzz_multi_point_eval(&setup);
}
```

This test creates a setup with `batch_capacity = 8`, adds only 1 ID, and then attempts to compute proofs using the VZGG method. The assertion in `multi_point_eval` will fail with `1 >= 8`, causing a panic.

---

**Notes:**
The vulnerability is specific to the VZGG (von zur Gathen and Gerhard) optimized multi-point evaluation path. The standard naive evaluation path handles undersized ID sets correctly. The issue stems from a size mismatch between the h-term commitments (sized to the setup's batch capacity) and the actual number of evaluation points (the number of IDs), violating an internal invariant of the optimized algorithm that assumes sufficient evaluation points for its tree-based recursion structure.

### Citations

**File:** crates/aptos-batch-encryption/src/shared/ids/mod.rs (L91-102)
```rust
    pub fn compute_poly_coeffs(&self) -> IdSet<ComputedCoeffs> {
        let mult_tree = compute_mult_tree(&self.poly_roots);

        IdSet {
            poly_roots: self.poly_roots.clone(),
            capacity: self.capacity,
            poly_coeffs: ComputedCoeffs {
                coeffs: mult_tree[mult_tree.len() - 1][0].coeffs.clone(),
                mult_tree,
            },
        }
    }
```

**File:** crates/aptos-batch-encryption/src/shared/ids/mod.rs (L148-166)
```rust
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

**File:** crates/aptos-batch-encryption/src/shared/algebra/fk_algorithm.rs (L336-352)
```rust
    fn compute_h_term_commitments(&self, f: &[F], round: usize) -> Vec<T> {
        let mut f = Vec::from(f);
        f.extend(std::iter::repeat_n(
            F::zero(),
            self.toeplitz_domain.dimension() + 1 - f.len(),
        ));
        // f.len() = (degree of f) + 1. Degree of f should be equal to the toeplitz domain
        // dimension.
        debug_assert_eq!(self.toeplitz_domain.dimension(), f.len() - 1);

        self.toeplitz_domain.eval_prepared(
            &self.toeplitz_for_poly(&f),
            // The Toeplitz matrix is only evaluated on the powers up to max_poly_degree - 1,
            // since the H_j(X) polynomials have degree at most that
            &self.prepared_toeplitz_inputs[round],
        )
    }
```

**File:** crates/aptos-batch-encryption/src/shared/algebra/fk_algorithm.rs (L361-364)
```rust
    pub fn eval_proofs_at_x_coords(&self, f: &[F], x_coords: &[F], round: usize) -> Vec<T> {
        let h_term_commitments = self.compute_h_term_commitments(f, round);
        multi_point_eval(&h_term_commitments, x_coords)
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

**File:** crates/aptos-batch-encryption/src/shared/algebra/multi_point_eval.rs (L123-149)
```rust
pub fn multi_point_eval_naive<
    F: FftField,
    T: DomainCoeff<F> + Mul<F, Output = T> + VariableBaseMSM<ScalarField = F>,
>(
    f: &[T::MulBase],
    x_coords: &[F],
) -> Vec<T> {
    // Note: unlike the non-naive algorithm, this supports an arbitrary
    // number of x coords
    let powers = x_coords
        .into_par_iter()
        .map(|x| {
            let mut result = Vec::new();
            let mut x_power = F::one();
            for _i in 0..f.len() {
                result.push(x_power);
                x_power *= x;
            }
            result
        })
        .collect::<Vec<Vec<F>>>();

    powers
        .into_par_iter()
        .map(|p| T::msm(f, &p).unwrap())
        .collect()
}
```

**File:** crates/aptos-batch-encryption/src/shared/digest.rs (L254-277)
```rust
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

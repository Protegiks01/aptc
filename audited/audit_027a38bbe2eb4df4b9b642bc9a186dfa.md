# Audit Report

## Title
Inadequate Cryptographic Binding of Commitment Randomness in Zeromorph Opening Proof (Experimental Code)

## Summary
The Zeromorph polynomial commitment scheme implementation contains a potential vulnerability where the commitment randomness `s` may not be properly bound to the opening proof `pi` when opening a batched polynomial that combines multiple commitments with different randomness values. The proof uses only the original polynomial's randomness while opening a linear combination that should require combined randomness.

## Finding Description

The vulnerability exists in the interaction between the Zeromorph `open()` function and the underlying hiding KZG opening mechanism. [1](#0-0) 

The code explicitly warns that it "HAS NOT YET BEEN VETTED, ONLY USE FOR BENCHMARKING PURPOSES". This is critical context.

In the `open()` function, a batched polynomial `f` is constructed by combining multiple components: [2](#0-1) 

This batched polynomial `f` includes:
- The original `poly` scaled by `z_challenge` (committed with randomness `s`)
- `q_hat` (committed with fresh randomness at line 317)
- Multiple `q_k` quotients (each committed with different randomness values sampled at lines 292-296)

However, when opening this combined polynomial, only the original commitment randomness `s` is used: [3](#0-2) 

In the underlying hiding KZG `open()` function, this `s` value is used to construct both proof components: [4](#0-3) 

**The Issue**: The batched polynomial `f` is a linear combination of polynomials that were committed with **different** randomness values (`s`, `r` from line 317, and `rs` from lines 292-296). The correct randomness for opening `f` should be a corresponding linear combination:

`randomness(f) = z * s + r_q_hat + sum(scalar_i * r_q_k[i])`

But the code only uses `s`, potentially allowing proofs to be constructed without properly knowing all the commitment randomness values.

The verification process attempts to check consistency through a multi-pairing equation: [5](#0-4) 

However, without formal cryptographic analysis, it's unclear whether this pairing equation correctly enforces that the randomness values are properly bound.

## Impact Explanation

**Potential Severity: High to Critical** (pending formal cryptographic analysis)

If exploitable, this could break the **Cryptographic Correctness** invariant. An attacker who can generate valid opening proofs without knowing the commitment randomness could:

1. **Violate hiding property**: Extract information about committed polynomials
2. **Forge proofs**: Create false proofs for incorrect evaluations
3. **Compromise DKG**: Since this is used in the Distributed Key Generation subsystem, it could potentially compromise the entire DKG protocol, affecting validator randomness and consensus safety

However, the **critical mitigation** is that this code is explicitly marked as experimental and for benchmarking only, suggesting it should not be in production paths.

## Likelihood Explanation

**Likelihood: Low to Medium**

- The code explicitly warns it's unvetted and for benchmarking only
- Exploitation requires deep understanding of the Zeromorph protocol mathematics
- Requires the DKG code path to be active in production
- May require extensive cryptanalysis to determine if actually exploitable

The uncertainty stems from the lack of formal security proof for this implementation.

## Recommendation

1. **Immediate**: Verify this code is not used in any production consensus or DKG paths. If it is, disable it immediately.

2. **Short-term**: Conduct formal cryptographic review of the Zeromorph implementation to determine if:
   - The randomness binding is mathematically sound despite the apparent mismatch
   - The pairing verification correctly enforces randomness consistency
   - The protocol should be using combined randomness for the batched polynomial

3. **Long-term**: If the protocol requires combined randomness, modify the code to properly compute it:

```rust
// Compute combined randomness for batched polynomial
let combined_randomness = {
    let mut combined = s.0 * z_challenge;
    combined += r.0; // randomness from q_hat
    for (i, r_qk) in rs.iter().enumerate() {
        let scalar = degree_check_q_scalars[i] + zmpoly_q_scalars[i];
        combined += r_qk.0 * scalar;
    }
    Scalar(combined)
};

// Use combined randomness instead of just s
let pi = univariate_hiding_kzg::CommitmentHomomorphism::open(
    &pp.open_pp,
    f.coeffs,
    rho,
    x_challenge,
    P::ScalarField::zero(),
    &combined_randomness,
);
```

4. **Remove or replace** the experimental warning once security is verified.

## Proof of Concept

A full PoC requires cryptographic analysis beyond code inspection. The steps to verify would be:

1. Set up Zeromorph parameters
2. Commit to a polynomial with known randomness `s`
3. Generate the batched polynomial with q_hat and q_k using different randomness
4. Attempt to create opening proof using only `s` instead of combined randomness
5. Verify if the proof passes verification
6. Attempt to forge proof without knowing actual `s`

This requires working through the full pairing mathematics and is beyond the scope of code-only analysis.

---

## Notes

**Important**: This finding is based on code analysis that reveals an apparent cryptographic inconsistency. However, **the code itself explicitly warns it is unvetted and for benchmarking only**. The actual exploitability requires formal cryptographic analysis of the Zeromorph protocol implementation that cannot be conclusively determined from code inspection alone.

The randomness `s` **is** passed to the proof generation (answering the literal question), but whether the protocol correctly enforces its binding in the context of batched polynomials with multiple randomness values remains uncertain without formal security proof.

Given the experimental nature of this code and the cryptographic complexity involved, this should be treated as a **potential vulnerability requiring expert review** rather than a confirmed exploit.

### Citations

**File:** crates/aptos-dkg/src/pcs/zeromorph.rs (L4-6)
```rust
// A lot of this code is copy-pasted from `jolt-core`. TODO: benchmark them against each other

// THIS CODE HAS NOT YET BEEN VETTED, ONLY USE FOR BENCHMARKING PURPOSES!!!!!
```

**File:** crates/aptos-dkg/src/pcs/zeromorph.rs (L337-349)
```rust
        // f = z * poly.Z + q_hat + (-z * Φ_n(x) * e) + ∑_k (q_scalars_k * q_k)   hmm why no sign for the q_hat????
        let mut f = UniPoly::from_coefficients_vec(poly.to_evaluations());
        f = f * z_challenge; // TODO: add MulAssign to arkworks so you can write f *= z_challenge?
        f += &q_hat;
        f[0] += eval_scalar * eval;
        quotients
            .into_iter()
            .zip(degree_check_q_scalars)
            .zip(zmpoly_q_scalars)
            .for_each(|((mut q, degree_check_scalar), zm_poly_scalar)| {
                q = q * (degree_check_scalar + zm_poly_scalar);
                f += &q;
            });
```

**File:** crates/aptos-dkg/src/pcs/zeromorph.rs (L355-362)
```rust
        let pi = univariate_hiding_kzg::CommitmentHomomorphism::open(
            &pp.open_pp,
            f.coeffs,
            rho,
            x_challenge,
            P::ScalarField::zero(),
            &s,
        );
```

**File:** crates/aptos-dkg/src/pcs/zeromorph.rs (L427-443)
```rust
        // e(pi, [tau]_2 - x * [1]_2) == e(C_{\zeta,Z}, -[X^(N_max - 2^n - 1)]_2) <==> e(C_{\zeta,Z} - x * pi, [X^{N_max - 2^n - 1}]_2) * e(-pi, [tau_2]) == 1
        let pairing = P::multi_pairing(
            [
                zeta_z_com,
                proof.pi.pi_1.0.into_affine(),
                proof.pi.pi_2.into_affine(),
            ],
            [
                (-vk.tau_N_max_sub_2_N.into_group()).into_affine(),
                (vk.kzg_vk.tau_2.into_group() - (vk.kzg_vk.group_generators.g2 * x_challenge))
                    .into(),
                vk.kzg_vk.xi_2,
            ],
        );
        if !pairing.is_zero() {
            return Err(anyhow::anyhow!("Expected zero during multi-pairing check"));
        }
```

**File:** crates/aptos-dkg/src/pcs/univariate_hiding_kzg.rs (L235-238)
```rust
        let pi_1 = commit_with_randomness(ck, &q_vals, s);

        // For this small MSM, the direct approach seems to be faster than using `E::G1::msm()`
        let pi_2 = (ck.g1 * rho) - (ck.tau_1 - ck.g1 * x) * s.0;
```

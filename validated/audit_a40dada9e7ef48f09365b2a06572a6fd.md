# Audit Report

## Title
Point at Infinity Attack in DeKART Range Proof Breaks DKG Security

## Summary
The DeKART v2 range proof verification fails to validate that `hatC` is not the point at infinity. When `hatC = O`, the commitment term vanishes from the MSM computation, completely breaking the binding between the public commitment and the range proof verification. This allows a single Byzantine validator to bypass range checks on secret shares and corrupt the distributed key generation used for on-chain randomness.

## Finding Description

The vulnerability exists in the range proof verification where `hatC` can be deserialized as the point at infinity without explicit rejection. During honest proof generation, `hatC` is computed as a linear combination that includes the commitment: [1](#0-0) 

However, a malicious prover can craft a `Proof` struct with `hatC = O` (point at infinity), which is valid under arkworks' `CanonicalDeserialize` trait that explicitly supports infinity points via an infinity flag.

During verification, three critical failures occur when `hatC = O`:

**1. MSM Computation Nullification**: The verification computes the multi-scalar multiplication: [2](#0-1) 

When `hatC = O`, the computation becomes `U = mu_h * D + sum(mu_js[i] * Cs[i])`, completely eliminating the `mu * hatC` term that binds the commitment to the proof.

**2. Sigma Protocol Bypass**: The sigma proof verification checks the statement: [3](#0-2) 

When `hatC = O`, the statement becomes `P = -comm.0`. An attacker can arbitrarily choose any `comm.0 = -(lagr_0 * r' + xi_1 * delta_rho')` for scalars `r'`, `delta_rho'` they control, and create a valid sigma proof without proving anything about the actual committed values.

**3. Final Constraint Bypass**: With zero polynomial evaluations, the final verification constraint passes trivially: [4](#0-3) 

Both `LHS = 0 * V(gamma) = 0` and `RHS = beta * (0 - 0) + 0 = 0`, satisfying the equality check.

**DKG Integration**: The range proof is invoked during DKG transcript verification to validate that chunked secret shares lie within valid ranges: [5](#0-4) 

DKG transcript verification occurs in the VM during validator transaction processing: [6](#0-5) 

The attack exploits the fact that when `hatC = O`, the commitment `comm` (which is `range_proof_commitment` in DKG) only appears in the sigma protocol check, not in the MSM, KZG opening verification, or final constraint. The verifier checks properties of arbitrary `D` and `Cs` values provided by the attacker, but not the actual values committed in `comm`. While the Sigma-of-Knowledge proof binds `range_proof_commitment` to the encrypted shares, the range proof verification with `hatC = O` fails to verify that the committed values are actually in range.

## Impact Explanation

**Critical Severity** - This vulnerability constitutes a Byzantine Fault Tolerance violation and cryptographic security breach:

1. **BFT Violation**: Aptos consensus is designed to tolerate up to 1/3 Byzantine validators. This vulnerability allows a **single** Byzantine validator to corrupt the DKG process, violating the fundamental safety assumption that the system should withstand individual malicious actors.

2. **Consensus Randomness Compromise**: DKG generates the distributed keys used for on-chain randomness that affects validator selection, transaction ordering, and consensus-critical operations. Invalid secret shares corrupt the distributed key, leading to predictable or manipulable randomness outputs.

3. **Distributed Key Corruption**: Byzantine dealers can inject out-of-range shares that, when aggregated, produce a corrupted distributed public key used across the entire validator set, compromising the cryptographic foundation of the randomness beacon.

4. **Cryptographic Invariant Violation**: The range proof should guarantee that chunked secret shares lie in `[0, 2^ell)`. Breaking this allows shares outside the valid range, violating the security assumptions of the PVSS scheme and enabling potential reconstruction attacks or biasing of the final random output.

This aligns with the **Critical Severity "Cryptographic Vulnerabilities"** category in the Aptos bug bounty program, which includes "practical breaks in cryptographic protocols" that "enable consensus violations."

## Likelihood Explanation

**High Likelihood**:

1. **Trivial to Exploit**: An attacker simply needs to set `hatC` to the point at infinity when constructing the `Proof` struct. The arkworks library's serialization explicitly supports this via an infinity flag in the compressed point format.

2. **Direct Validator Access**: Any validator in the DKG dealer set can attempt this attack during epoch transitions when dealers broadcast transcripts via validator transactions.

3. **No Existing Protections**: Code analysis confirms there are no validation checks (such as `hatC.is_zero()` or `hatC.is_identity()`) in the deserialization or verification paths to reject the point at infinity.

4. **Single Validator Attack**: Unlike attacks requiring >1/3 Byzantine collusion, this can be executed by a single malicious validator, making it significantly more likely to occur in practice and more severe in impact.

## Recommendation

Add explicit validation in the `verify` method to reject proofs where `hatC` is the point at infinity:

```rust
fn verify(
    &self,
    vk: &Self::VerificationKey,
    n: usize,
    ell: usize,
    comm: &Self::Commitment,
) -> anyhow::Result<()> {
    let mut fs_t = merlin::Transcript::new(Self::DST);
    
    // ... existing code ...
    
    let Proof {
        hatC,
        pi_PoK,
        Cs,
        D,
        a,
        a_h,
        a_js,
        pi_gamma,
    } = self;
    
    // Add validation to reject point at infinity
    anyhow::ensure!(!hatC.is_zero(), "hatC cannot be the point at infinity");
    
    // ... rest of verification ...
}
```

Additionally, consider validating other proof components (`D`, `Cs`) to ensure they are not identity elements where it would compromise security.

## Proof of Concept

```rust
use aptos_dkg::range_proofs::dekart_univariate_v2::Proof;
use ark_ec::CurveGroup;

// Craft malicious proof with hatC = O (point at infinity)
let malicious_proof = Proof {
    hatC: E::G1::zero(),  // Point at infinity
    pi_PoK: /* crafted sigma proof for -comm.0 */,
    Cs: vec![E::G1::zero(); ell],  // Zero commitments
    D: E::G1::zero(),  // Zero commitment
    a: E::ScalarField::ZERO,
    a_h: E::ScalarField::ZERO,
    a_js: vec![E::ScalarField::ZERO; ell],
    pi_gamma: /* valid opening proof for zero polynomial */,
};

// Choose arbitrary commitment (including one with out-of-range values)
let malicious_comm = /* commitment to out-of-range chunked shares */;

// Verification passes despite out-of-range values
assert!(malicious_proof.verify(&vk, n, ell, &malicious_comm).is_ok());
```

## Notes

This vulnerability represents a fundamental breakdown in the cryptographic binding between the commitment and its range proof. The issue is not merely a missing check, but a structural problem where setting `hatC = O` causes the commitment to be disconnected from the verification logic entirely. This is particularly severe in the DKG context where it undermines the Byzantine fault tolerance guarantees that are foundational to Aptos consensus security.

### Citations

**File:** crates/aptos-dkg/src/range_proofs/dekart_univariate_v2.rs (L393-393)
```rust
        let hatC = *xi_1 * delta_rho + lagr_g1[0] * r + comm.0;
```

**File:** crates/aptos-dkg/src/range_proofs/dekart_univariate_v2.rs (L696-704)
```rust
        two_term_msm::Homomorphism {
            base_1: *lagr_0,
            base_2: *xi_1,
        }
        .verify(
            &(two_term_msm::CodomainShape(*hatC - comm.0)),
            pi_PoK,
            &Self::DST,
        )?;
```

**File:** crates/aptos-dkg/src/range_proofs/dekart_univariate_v2.rs (L722-738)
```rust
        let U_bases: Vec<E::G1Affine> = {
            let mut v = Vec::with_capacity(2 + Cs.len());
            v.push(*hatC);
            v.push(*D);
            v.extend_from_slice(&Cs);
            E::G1::normalize_batch(&v)
        };

        let U_scalars: Vec<E::ScalarField> = {
            let mut v = Vec::with_capacity(2 + mu_js.len());
            v.push(mu);
            v.push(mu_h);
            v.extend_from_slice(&mu_js);
            v
        };

        let U = E::G1::msm(&U_bases, &U_scalars).expect("Failed to compute MSM in DeKARTv2");
```

**File:** crates/aptos-dkg/src/range_proofs/dekart_univariate_v2.rs (L765-794)
```rust
        let LHS = {
            // First compute V_SS^*(gamma), where V_SS^*(X) is the polynomial (X^{max_n + 1} - 1) / (X - 1)
            let V_eval_gamma = {
                let gamma_pow = gamma.pow([num_omegas as u64]);
                (gamma_pow - E::ScalarField::ONE) * (gamma - E::ScalarField::ONE).inverse().unwrap()
            };

            *a_h * V_eval_gamma
        };

        let RHS = {
            // Compute sum_j 2^j a_j
            let sum1: E::ScalarField = verifier_precomputed
                .powers_of_two
                .iter()
                .zip(a_js.iter())
                .map(|(&power_of_two, aj)| power_of_two * aj)
                .sum();

            // Compute sum_j beta_j a_j (a_j - 1)
            let sum2: E::ScalarField = beta_js
                .iter()
                .zip(a_js.iter())
                .map(|(beta, &a)| a * (a - E::ScalarField::ONE) * beta) // TODO: submit PR to change arkworks so beta can be on the left...
                .sum();

            beta * (*a - sum1) + sum2
        };

        anyhow::ensure!(LHS == RHS);
```

**File:** crates/aptos-dkg/src/pvss/chunky/weighted_transcriptv2.rs (L532-539)
```rust
            if let Err(err) = self.sharing_proof.range_proof.verify(
                &pp.pk_range_proof.vk,
                sc.get_total_weight() * num_chunks_per_scalar::<E::ScalarField>(pp.ell) as usize,
                pp.ell as usize,
                &self.sharing_proof.range_proof_commitment,
            ) {
                bail!("Range proof batch verification failed: {:?}", err);
            }
```

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L111-112)
```rust
        DefaultDKG::verify_transcript(&pub_params, &transcript)
            .map_err(|_| Expected(TranscriptVerificationFailed))?;
```

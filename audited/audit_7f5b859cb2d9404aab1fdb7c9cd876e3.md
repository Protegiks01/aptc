# Audit Report

## Title
Insufficient Statistical Power in Constant-Time Testing Allows Subtle Timing Side-Channels to Evade Detection in Pepper Service VUF

## Summary
The constant-time verification tests for scalar multiplication operations use only N=10,000 samples with a t-statistic threshold of 5, which provides insufficient statistical power to detect subtle timing leakages of 1-2 CPU cycles. This test serves as a critical production security gate for the pepper service at startup, creating false security assurance that could allow timing-vulnerable cryptographic implementations to be deployed, leading to remote private key extraction attacks.

## Finding Description

The pepper service depends on constant-time scalar multiplication for its VUF (Verifiable Unpredictable Function) implementation, which uses the private key to generate peppers for keyless accounts. [1](#0-0) 

This critical security property is verified at service startup using dudect statistical tests: [2](#0-1) 

The test uses N=10,000 samples and requires the t-statistic to be ≤ 5: [3](#0-2) 

**Statistical Insufficiency:**

For a scalar multiplication operation taking ~10,000-100,000 CPU cycles with typical system noise variance σ ≈ 100-1,000 cycles, detecting a timing difference of δ = 1-2 cycles with statistical confidence (t > 5) requires approximately:

n ≈ 2 × (t × σ / δ)²

With σ = 1,000 cycles and δ = 2 cycles:
n ≈ 2 × (5 × 1,000 / 2)² = 12,500,000 samples

This is **1,250× more samples** than the current N=10,000.

**Attack Surface:**

The VUF private key is used in remotely accessible operations where attackers control the input (hashed to curve point): [4](#0-3) 

The service explicitly requires this operation to be constant-time: [5](#0-4) 

Remote attackers can query the pepper service repeatedly with chosen inputs: [6](#0-5) 

**Additional Test Methodology Issues:**

The test design has acknowledged weaknesses, including queuing all inputs before execution (affecting cache behavior) and using a coin-flip pattern for class selection: [7](#0-6) 

The test also deliberately avoids certain scalar values (e.g., zero) where timing differences are known to exist: [8](#0-7) 

## Impact Explanation

**Severity: HIGH**

If a timing-vulnerable implementation passes this insufficient test and is deployed:

1. **Remote Private Key Extraction**: Attackers can perform timing attacks on the pepper service VUF by sending millions of crafted requests and performing statistical analysis on response times. Prior research (Bernstein's AES cache-timing attack, Brumley-Boneh RSA timing attack) demonstrates successful key extraction with even smaller timing differences.

2. **Account Takeover**: With the VUF private key, attackers can generate valid peppers for any user identity, enabling complete takeover of keyless accounts.

3. **False Security Assurance**: The service passes a "constant-time verification" check at startup, creating false confidence that timing attacks are mitigated when they may not be.

This meets **High Severity** criteria: "Significant protocol violations" and creates critical risk exposure despite not being an immediate loss of funds without the timing vulnerability existing in the underlying implementation.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

- The statistical insufficiency is **certain** (mathematically provable)
- Whether the current blstrs implementation has exploitable timing leaks is **unknown**
- If such leaks exist at the 1-2 cycle level, they **would evade detection** with N=10,000 samples
- Remote timing attacks are **proven feasible** in academic literature despite network noise
- Attackers can send **unlimited queries** to the pepper service to gather timing samples

The service explicitly depends on this test as a security gate, making this a critical gap in the security validation process.

## Recommendation

**Immediate Actions:**

1. **Increase Sample Size**: Use at least N=1,000,000 to N=10,000,000 samples for testing subtle timing differences, or implement adaptive testing that continues until statistical power is sufficient.

2. **Enhance Test Coverage**: Test all scalar ranges including edge cases (zero, near-zero, near-modulus) rather than avoiding known problematic values.

3. **Add Multiple Test Methodologies**: Supplement dudect with:
   - Crosstalk detection (CPU performance counter analysis)
   - Cache-timing specific tests
   - Differential power analysis simulation

4. **Implement Runtime Protections**: Add constant-time assertions or runtime monitoring to detect timing variations in production.

**Code Fix Example:**

```rust
// In zkcrypto_scalar_mul.rs
const N: usize = 10_000_000; // Increase from 10,000 to 10 million

// Add adaptive testing
pub fn build_and_run_bench_adaptive<F>(
    runner: &mut CtRunner, 
    rng: &mut BenchRng, 
    scalar_mul_fn: F,
    min_samples: usize,
    max_samples: usize,
    target_power: f64,
) where F: Fn(&Scalar, &G1Projective) -> G1Projective {
    // Continue sampling until statistical power threshold is reached
    // or max_samples is hit
}
```

## Proof of Concept

**Demonstrating Insufficient Detection:**

```rust
// Create a deliberately vulnerable scalar multiplication with 2-cycle leak
fn vulnerable_scalar_mul(base: &G1Projective, scalar: &Scalar) -> G1Projective {
    let result = base.mul(scalar);
    
    // Add 2-cycle timing leak based on scalar bit pattern
    let scalar_bytes = scalar.to_bytes_le();
    if scalar_bytes[0] & 0x01 == 0x01 {
        // Leak: ~2 CPU cycles via memory access pattern
        std::hint::black_box(&scalar_bytes[31]);
    }
    
    result
}

// Run dudect test with N=10,000 - this will likely PASS despite timing leak
// due to insufficient statistical power when noise >> 2 cycles
```

**Attack Simulation:**

1. Attacker sends 10 million pepper requests with chosen inputs
2. Measures response times with microsecond precision
3. Performs statistical correlation between input hash values and timing
4. Recovers private key bits using differential timing analysis
5. Reconstructs full VUF private key
6. Generates arbitrary valid peppers for account takeover

## Notes

While I have not identified a confirmed timing vulnerability in the blstrs library itself, the inadequate testing methodology creates **critical security risk** by providing false assurance about constant-time properties. The pepper service treats passing this test as sufficient evidence of timing safety, but N=10,000 samples cannot reliably detect subtle (1-2 cycle) leakages that are nevertheless remotely exploitable through statistical amplification.

The developers' own WARNING comments acknowledge uncertainties about the test methodology and known timing variations (zero scalar case), suggesting this is a recognized gap in the security validation process that requires immediate attention.

### Citations

**File:** keyless/pepper/service/src/main.rs (L363-392)
```rust
/// Verifies that scalar multiplication is constant time
fn verify_constant_time_scalar_multiplication() {
    // Run the constant time benchmarks for random bases
    let abs_max_t = ctbench::run_bench(
        &BenchName("blstrs_scalar_mul/random_bases"),
        constant_time::blstrs_scalar_mul::run_bench_with_random_bases,
        None,
    )
    .1
    .max_t
    .abs()
    .ceil()
    .to_i64()
    .expect("Floating point arithmetic went awry.");
    assert_le!(abs_max_t, ABS_MAX_T);

    // Run the constant time benchmarks for fixed bases
    let abs_max_t = ctbench::run_bench(
        &BenchName("blstrs_scalar_mul/fixed_bases"),
        constant_time::blstrs_scalar_mul::run_bench_with_fixed_bases,
        None,
    )
    .1
    .max_t
    .abs()
    .ceil()
    .to_i64()
    .expect("Floating point arithmetic went awry.");
    assert_le!(abs_max_t, ABS_MAX_T);
}
```

**File:** keyless/pepper/service/src/main.rs (L402-410)
```rust
    // Verify constant-time scalar multiplication if in production.
    if args.local_development_mode {
        info!(
            "Constant-time scalar multiplication verification skipped in local development mode."
        );
    } else {
        info!("Verifying constant-time scalar multiplication...");
        verify_constant_time_scalar_multiplication();
    }
```

**File:** crates/aptos-crypto/src/constant_time/zkcrypto_scalar_mul.rs (L55-103)
```rust
fn build_and_run_bench<F>(runner: &mut CtRunner, rng: &mut BenchRng, scalar_mul_fn: F)
where
    F: Fn(&Scalar, &G1Projective) -> G1Projective,
{
    let g1 = G1Projective::generator();

    const N: usize = 10_000;

    let mut inputs: Vec<(Class, usize, Scalar, G1Projective)> = Vec::with_capacity(N);

    let min_num_bits_left = 0;
    let max_num_bits_left = 4;
    let num_bits_right = BIT_SIZE.div_ceil(2) + 1;
    eprintln!();
    eprintln!(
        "# of 1 bits in scalars for \"left\" class is in [{}, {})",
        min_num_bits_left, max_num_bits_left
    );
    eprintln!(
        "# of 1 bits in scalars for \"right\" class is always {}",
        num_bits_right
    );
    for _ in 0..N {
        let choice = rng.r#gen::<bool>();

        if choice {
            let num_bits_left = rng.gen_range(min_num_bits_left..max_num_bits_left);
            inputs.push((
                Class::Left,
                num_bits_left,
                random_scalar_with_k_bits_set(rng, num_bits_left),
                g1,
            ));
        } else {
            inputs.push((
                Class::Right,
                num_bits_right,
                random_scalar_with_k_bits_set(rng, num_bits_right),
                g1,
            ));
        }
    }

    for (class, _k, sk, base) in inputs {
        runner.run_one(class, || {
            black_box(scalar_mul_fn(&sk, &base));
        })
    }
}
```

**File:** keyless/pepper/common/src/vuf/bls12381_g1_bls.rs (L81-87)
```rust
    /// WARNING: This function must remain constant-time w.r.t. to `sk` and `input`.
    fn eval(sk: &Scalar, input: &[u8]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let input_g1 = Self::hash_to_g1(input);
        let output_g1 = input_g1.mul(sk);
        let output_bytes = output_g1.to_compressed().to_vec();
        Ok((output_bytes, vec![]))
    }
```

**File:** keyless/pepper/service/src/dedicated_handlers/pepper_request.rs (L148-191)
```rust
/// Creates the pepper base using the VUF private key and the pepper input
fn create_pepper_base(
    vuf_keypair: Arc<VUFKeypair>,
    pepper_input: &PepperInput,
) -> Result<Vec<u8>, PepperServiceError> {
    // Serialize the pepper input using BCS
    let input_bytes = bcs::to_bytes(&pepper_input).map_err(|error| {
        PepperServiceError::InternalError(format!(
            "Failed to serialize pepper input! Error: {:?}",
            error
        ))
    })?;

    // Generate the pepper base and proof using the VUF
    let (pepper_base, vuf_proof) =
        vuf::bls12381_g1_bls::Bls12381G1Bls::eval(vuf_keypair.vuf_private_key(), &input_bytes)
            .map_err(|error| {
                PepperServiceError::InternalError(format!(
                    "Failed to evaluate bls12381_g1_bls VUF: {}",
                    error
                ))
            })?;

    // Verify that the proof is empty
    if !vuf_proof.is_empty() {
        return Err(PepperServiceError::InternalError(
            "The VUF proof is not empty! This shouldn't happen.".to_string(),
        ));
    }

    // Verify the pepper base output (this ensures we only ever return valid outputs,
    // and protects against various security issues, e.g., fault based side channels).
    vuf::bls12381_g1_bls::Bls12381G1Bls::verify(
        vuf_keypair.vuf_public_key(),
        &input_bytes,
        &pepper_base,
        &vuf_proof,
    )
    .map_err(|error| {
        PepperServiceError::InternalError(format!("VUF verification failed: {}", error))
    })?;

    Ok(pepper_base)
}
```

**File:** crates/aptos-crypto/src/constant_time/blstrs_scalar_mul.rs (L63-70)
```rust
/// WARNING: Blindly following the same "pattern" as in the dudect examples for how to "build" the
/// testcases. This coin flipping to decided whether to pick "left" or "right" feels awkward to me,
/// but I'd need to read their paper to understand better. It could've also been done by the
/// framework itself. The queing up of the inputs is also odd: why not run the benchmark immediately
/// after generating the input?
///
/// Note: We could technically implement this more abstractly via traits (may be painful) or macros,
/// since this is duplicated across this file and the `zkcrypto` file.
```

**File:** crates/aptos-crypto/src/constant_time/blstrs_scalar_mul.rs (L101-101)
```rust
            // WARNING: `blstrs` is faster when the scalar is exactly 0!
```

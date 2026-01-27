# Audit Report

## Title
Missing Threshold Validation in Shamir Secret Sharing Allows Catastrophic Security Failure in Release Builds

## Summary
The `ShamirThresholdConfig::new()` function lacks validation to prevent threshold `t=0`, and the `share()` function only uses `debug_assert` (compiled out in release builds) to validate coefficient length. This allows creation of configurations with `t=0` which, when combined with mismatched coefficient arrays in release builds, causes all shares to directly expose the secret, completely destroying threshold cryptography guarantees.

## Finding Description

The Shamir secret sharing implementation has two critical validation failures:

**1. Missing Threshold Validation in Constructor:**

The `ShamirThresholdConfig::new()` implementations fail to validate that `t > 0`: [1](#0-0) [2](#0-1) 

The trait implementation has NO validation, while the direct implementation only has `debug_assert!(t <= n)` which is **not enforced in release builds**.

**2. Debug-Only Validation in share() Function:** [3](#0-2) 

The coefficient length check at line 299 uses `debug_assert_eq!`, which is completely removed in release builds.

**Attack Scenario (Release Build):**

1. Attacker creates: `config = ShamirThresholdConfig::new(0, n)` (succeeds - no validation)
2. Attacker calls: `shares = config.share(&[secret])` with 1-element coefficient array
   - Debug assertion bypassed in release build
   - FFT evaluates constant polynomial `f(x) = secret`
   - All `n` shares become: `(player_i, secret)`
3. **Result**: Every share directly exposes the secret value

The FFT of a single coefficient `[s]` treats it as a degree-0 constant polynomial, so evaluating at all roots of unity yields the same constant value `s` for every share.

**Comparison with Secure Implementation:**

The `ThresholdConfigBlstrs` implementation correctly validates the threshold: [4](#0-3) 

**Usage Context:**

This is used in critical consensus infrastructure: [5](#0-4) 

While typical usage calculates threshold safely: [6](#0-5) 

The lack of validation creates a defense-in-depth failure that could be triggered by:
- Configuration bugs in deployment
- Integer arithmetic errors in threshold calculation
- Future API changes exposing this to external input

## Impact Explanation

**Severity: High to Critical** (depending on exploitation context)

**Broken Invariant**: Cryptographic Correctness (#10) - The Shamir secret sharing scheme must maintain confidentiality such that fewer than `t` shares reveal no information about the secret.

With `t=0` in release builds:
- **Complete confidentiality breach**: All shares directly expose the secret
- **Zero threshold security**: No reconstruction needed - any single share leaks the secret
- **Consensus randomness compromise**: If exploited in consensus secret sharing, could break randomness generation
- **Batch encryption failure**: If used in batch encryption, all encrypted data exposed

This meets **Critical Severity** criteria if exploitable in production:
- Consensus/Safety violations (if consensus randomness affected)
- Loss of confidentiality (complete cryptographic failure)

It meets **High Severity** as a defense-in-depth failure that requires additional conditions to exploit.

## Likelihood Explanation

**Likelihood: Low to Medium**

**Mitigating Factors:**
- Current threshold calculations use `n * 2 / 3 + 1`, which never produces `t=0`
- Requires either misconfiguration or a separate bug in threshold calculation
- Not directly exploitable by external attackers without access to configuration

**Risk Factors:**
- Missing validation in production code (debug_assert removed)
- Inconsistency with `ThresholdConfigBlstrs` which HAS validation
- Used in critical consensus infrastructure
- Future code changes could expose this to user input

The vulnerability is **guaranteed to cause catastrophic failure IF triggered**, but triggering it requires specific conditions not currently present in normal operation.

## Recommendation

Add runtime validation in both constructor implementations and the `share()` function:

**Fix for `new()` implementations:**

```rust
impl<F: FftField> traits::ThresholdConfig for ShamirThresholdConfig<F> {
    fn new(t: usize, n: usize) -> Result<Self> {
        if t == 0 {
            return Err(anyhow!("threshold t must be > 0"));
        }
        if n == 0 {
            return Err(anyhow!("number of shares n must be > 0"));
        }
        if t > n {
            return Err(anyhow!("threshold t must be <= n"));
        }
        let domain = Radix2EvaluationDomain::new(n)
            .ok_or_else(|| anyhow!("Invalid domain size: {}", n))?;
        Ok(Self { n, t, domain })
    }
    // ... rest of implementation
}

impl<F: FftField> ShamirThresholdConfig<F> {
    pub fn new(t: usize, n: usize) -> Self {
        assert!(t > 0, "threshold t must be > 0");
        assert!(n > 0, "number of shares n must be > 0");
        assert!(t <= n, "threshold t must be <= n");
        let domain = Radix2EvaluationDomain::new(n)
            .expect("Invalid domain size");
        ShamirThresholdConfig { n, t, domain }
    }
}
```

**Fix for `share()` function:**

```rust
pub fn share(&self, coeffs: &[F]) -> Vec<ShamirShare<F>> {
    assert_eq!(
        coeffs.len(),
        self.t,
        "Expected {} coefficients for threshold {}, got {}",
        self.t,
        self.t,
        coeffs.len()
    );
    let evals = self.domain.fft(coeffs);
    (0..self.n).map(|i| self.get_player(i)).zip(evals).collect()
}
```

Replace all `debug_assert!` with runtime `assert!` or return `Result<_>` with proper error handling.

## Proof of Concept

```rust
use aptos_crypto::arkworks::shamir::ShamirThresholdConfig;
use ark_bn254::Fr;
use ark_ff::One;

#[test]
#[cfg(not(debug_assertions))] // Only runs in release mode
fn test_threshold_zero_vulnerability() {
    // Step 1: Create config with t=0 (should fail but doesn't)
    let config = ShamirThresholdConfig::<Fr>::new(0, 8);
    assert_eq!(config.t, 0);
    
    // Step 2: Share a secret using 1-element coefficient array
    // In release mode, debug_assert is bypassed
    let secret = Fr::one();
    let shares = config.share(&[secret]);
    
    // Step 3: Verify catastrophic failure - ALL shares equal the secret
    assert_eq!(shares.len(), 8);
    for (_player, share_value) in shares.iter() {
        assert_eq!(*share_value, secret, "Share directly exposes secret!");
    }
    
    println!("VULNERABILITY CONFIRMED: All {} shares equal the secret", shares.len());
    println!("Threshold security completely broken!");
}
```

**To run:**
```bash
cd crates/aptos-crypto
cargo test --release test_threshold_zero_vulnerability
```

**Expected output in release build:** Test passes, demonstrating all shares equal the secret.

**Expected behavior in fixed code:** Constructor should reject `t=0` with an error.

---

**Notes:**
- This vulnerability requires release builds to fully manifest (debug builds will panic)
- Current production usage appears safe due to threshold calculation formula
- However, missing validation violates defense-in-depth principles
- The inconsistency with `ThresholdConfigBlstrs` implementation indicates this is an oversight
- Should be fixed to prevent future exploitation through misconfiguration or API changes

### Citations

**File:** crates/aptos-crypto/src/arkworks/shamir.rs (L88-92)
```rust
    fn new(t: usize, n: usize) -> Result<Self> {
        let domain = Radix2EvaluationDomain::new(n) // Note that `new(n)` internally does `n.next_power_of_two()`
            .expect("Invalid domain size: {}");
        Ok(Self { n, t, domain })
    }
```

**File:** crates/aptos-crypto/src/arkworks/shamir.rs (L230-234)
```rust
    pub fn new(t: usize, n: usize) -> Self {
        debug_assert!(t <= n, "Expected t <= n, but t = {} and n = {}", t, n);
        let domain = Radix2EvaluationDomain::new(n).unwrap();
        ShamirThresholdConfig { n, t, domain }
    }
```

**File:** crates/aptos-crypto/src/arkworks/shamir.rs (L298-302)
```rust
    pub fn share(&self, coeffs: &[F]) -> Vec<ShamirShare<F>> {
        debug_assert_eq!(coeffs.len(), self.t);
        let evals = self.domain.fft(coeffs);
        (0..self.n).map(|i| self.get_player(i)).zip(evals).collect()
    }
```

**File:** crates/aptos-crypto/src/blstrs/threshold_config.rs (L110-122)
```rust
        if t == 0 {
            return Err(anyhow!("expected the reconstruction threshold to be > 0"));
        }

        if n == 0 {
            return Err(anyhow!("expected the number of shares to be > 0"));
        }

        if t > n {
            return Err(anyhow!(
                "expected the reconstruction threshold {t} to be < than the number of shares {n}"
            ));
        }
```

**File:** consensus/src/rand/secret_sharing/types.rs (L18-18)
```rust
pub type ThresholdConfig = ShamirThresholdConfig<Fr>;
```

**File:** crates/aptos-batch-encryption/benches/fptx.rs (L141-143)
```rust
        let t = n * 2 / 3 + 1;
        let mut rng = thread_rng();
        let tc = ShamirThresholdConfig::new(t, n);
```

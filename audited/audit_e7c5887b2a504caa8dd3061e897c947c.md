# Audit Report

## Title
Integer Overflow and Resource Exhaustion in ThresholdConfigBlstrs Construction

## Summary
The `ThresholdConfigBlstrs::new()` function lacks upper bound validation on the `n` parameter, allowing extremely large values to cause integer overflow in the FFT domain computation or resource exhaustion through massive memory allocation attempts. While the production code validates basic constraints (t > 0, n > 0, t ≤ n), it does not check if n exceeds the BLS12-381 scalar field's two-adicity limit (2^31) or system memory limits.

## Finding Description
The vulnerability exists in the `ThresholdConfigBlstrs::new()` constructor which creates threshold secret sharing configurations for the DKG (Distributed Key Generation) system used in Aptos consensus randomness generation. [1](#0-0) 

The function validates that `t > 0`, `n > 0`, and `t ≤ n`, but does not validate against extremely large values. It then calls `BatchEvaluationDomain::new(n)`: [2](#0-1) 

This function computes the smallest power-of-2 greater than or equal to n using: [3](#0-2) 

**Critical Issues:**

1. **Integer Overflow**: If `n` approaches `usize::MAX`, the left shift operation `N <<= 1` will overflow when trying to find a power-of-2 that fits. In debug mode this panics; in release mode it wraps around causing undefined behavior.

2. **Resource Exhaustion**: For `n > 2^31`, the function attempts to allocate `Vec::with_capacity(N)` where N ≥ 2^32, requiring ~128GB+ of memory (2^32 scalars × 32 bytes each), causing OOM crashes.

3. **Missing Cryptographic Constraint**: The BLS12-381 scalar field has two-adicity of 32, supporting FFT domains up to 2^32. The related `EvaluationDomain::new()` enforces this: [4](#0-3) 

However, `BatchEvaluationDomain::new()` lacks this validation, allowing creation of mathematically invalid domains.

**Attack Surface Analysis:**

The configuration is created during DKG setup from validator stakes: [5](#0-4) 

The weights sum to create the total weight `W` passed as `n` to `ThresholdConfigBlstrs::new()`. Additionally, the custom deserialization implementation could accept malicious values: [6](#0-5) 

## Impact Explanation
**Assessment: Low Severity** (despite the code bug)

While the bug exists in production code and could cause DoS through node crashes, I cannot demonstrate a **realistic, unprivileged attack path**:

- **Validator weights** come from the on-chain staking system with governance controls, not attacker-controlled input
- **Weight calculations** use bounded formulas in `DKGRounding` that produce reasonable values for realistic validator counts
- **Deserialization paths** for `ThresholdConfigBlstrs` are not exposed to untrusted network input in my investigation
- The `.unwrap()` in the production code suggests developers expect this to always succeed with valid inputs

The question correctly categorizes this as **Low severity** - it's a robustness issue in edge case handling rather than an exploitable vulnerability.

## Likelihood Explanation
**Likelihood: Very Low**

For this to be triggered maliciously:
1. An attacker would need to manipulate validator stakes to sum to extreme values (>2^31)
2. OR find a deserialization path accepting untrusted input for t/n values
3. Neither scenario is realistic under normal operation or with current attacker capabilities

The bug is more likely to surface as a **development/testing issue** if someone accidentally passes extreme values during integration work.

## Recommendation
Add defensive validation even though current usage appears safe:

```rust
fn new(t: usize, n: usize) -> anyhow::Result<Self> {
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
    
    // NEW: Add upper bound check based on BLS12-381 scalar field two-adicity
    const MAX_FFT_SIZE: usize = 1 << 31; // 2^31, one less than Scalar::S
    if n > MAX_FFT_SIZE {
        return Err(anyhow!(
            "number of shares {n} exceeds maximum supported FFT domain size {MAX_FFT_SIZE}"
        ));
    }
    
    let batch_dom = BatchEvaluationDomain::new(n);
    let dom = batch_dom.get_subdomain(n);
    Ok(ThresholdConfigBlstrs { t, n, dom, batch_dom })
}
```

Also add the validation check to `BatchEvaluationDomain::new()` for defense-in-depth.

## Proof of Concept
```rust
#[test]
#[should_panic]
fn test_extreme_n_causes_panic() {
    // This will panic in debug mode due to integer overflow
    // or cause OOM in release mode
    let result = ThresholdConfigBlstrs::new(1, usize::MAX);
    assert!(result.is_err());
}

#[test]
fn test_n_exceeds_fft_limit() {
    // n > 2^31 should be rejected
    let n = (1usize << 31) + 1;
    let result = ThresholdConfigBlstrs::new(1, n);
    assert!(result.is_err(), "Should reject n exceeding FFT domain limit");
}
```

**Notes:**
- The missing test coverage identified in the security question is valid - edge cases with extreme values are not tested
- The production code does have a bug (missing upper bound validation)  
- However, I cannot demonstrate a realistic exploit path for an unprivileged attacker
- This is a **robustness/defensive programming issue** rather than a critical security vulnerability
- The fix is straightforward and should be implemented for defense-in-depth

### Citations

**File:** crates/aptos-crypto/src/blstrs/threshold_config.rs (L37-54)
```rust
impl<'de> Deserialize<'de> for ThresholdConfigBlstrs {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize only the serializable fields (t, n)
        #[derive(Deserialize)]
        struct SerializedFields {
            t: usize,
            n: usize,
        }

        let serialized = SerializedFields::deserialize(deserializer)?;

        // Rebuild the skipped fields using `new`
        ThresholdConfigBlstrs::new(serialized.t, serialized.n).map_err(serde::de::Error::custom)
    }
}
```

**File:** crates/aptos-crypto/src/blstrs/threshold_config.rs (L109-132)
```rust
    fn new(t: usize, n: usize) -> anyhow::Result<Self> {
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

        let batch_dom = BatchEvaluationDomain::new(n);
        let dom = batch_dom.get_subdomain(n);
        Ok(ThresholdConfigBlstrs {
            t,
            n,
            dom,
            batch_dom,
        })
    }
```

**File:** crates/aptos-crypto/src/blstrs/evaluation_domain.rs (L50-64)
```rust
pub fn smallest_power_of_2_greater_than_or_eq(n: usize) -> (usize, usize) {
    let mut N = 1;
    let mut log_N: usize = 0;

    while N < n {
        N <<= 1;
        log_N += 1;
    }

    (N, log_N)
    // TODO: Replace with:
    // let N = n.next_power_of_two();
    // let log_N = N.trailing_zeros() as usize;
    // (N, log_N)
}
```

**File:** crates/aptos-crypto/src/blstrs/evaluation_domain.rs (L79-81)
```rust
        if log_N >= Scalar::S as usize {
            return Err(CryptoMaterialError::WrongLengthError);
        }
```

**File:** crates/aptos-crypto/src/blstrs/evaluation_domain.rs (L120-153)
```rust
    pub fn new(n: usize) -> Self {
        let (N, log_N) = smallest_power_of_2_greater_than_or_eq(n);
        let omega = EvaluationDomain::get_Nth_root_of_unity(log_N);

        let mut omegas = Vec::with_capacity(N);
        omegas.push(Scalar::ONE);

        let mut acc = omega;
        for _ in 1..N {
            omegas.push(acc);
            acc *= omega; // $\omega^i$
        }

        debug_assert_eq!(omegas.len(), N);

        let mut N_inverses = Vec::with_capacity(log_N);
        let mut i = 1u64;
        for _ in 0..=log_N {
            N_inverses.push(Scalar::from(i).invert().unwrap());

            i *= 2;
        }

        debug_assert_eq!(
            N_inverses.last().unwrap().invert().unwrap(),
            Scalar::from(N as u64)
        );

        BatchEvaluationDomain {
            log_N,
            omegas,
            N_inverses,
        }
    }
```

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L98-106)
```rust
        let wconfig = WeightedConfigBlstrs::new(
            profile.reconstruct_threshold_in_weights as usize,
            profile
                .validator_weights
                .iter()
                .map(|w| *w as usize)
                .collect(),
        )
        .unwrap();
```

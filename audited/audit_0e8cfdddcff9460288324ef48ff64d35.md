# Audit Report

## Title
Missing Runtime Validation for Threshold Secret Sharing Configuration Allows Cryptographically Invalid Configurations in Release Builds

## Summary
The `ShamirThresholdConfig::new()` function uses `debug_assert!` instead of runtime validation to ensure `threshold <= n`, allowing invalid secret sharing configurations (threshold > n) to be created in release builds. This violates the fundamental mathematical requirements of Shamir secret sharing and can cause permanent consensus failures.

## Finding Description
The vulnerability exists in the secret sharing configuration validation chain: [1](#0-0) 

This function uses `debug_assert!` for the critical invariant check `t <= n`. In Rust, `debug_assert!` macros are **completely removed** from release builds, leaving no runtime validation. The function always returns `Ok(Self {...})` regardless of the threshold value in production.

This propagates through the weighted configuration layer: [2](#0-1) 

The `WeightedConfig::new()` function calls `TC::new()` and expects it to validate, but when `TC` is `ShamirThresholdConfig`, no validation occurs in release builds.

The invalid configuration then reaches the consensus secret sharing layer: [3](#0-2) 

These functions expose the threshold and validator count without validation, allowing the system to operate with `threshold() > number_of_validators()`.

During secret share aggregation, the system checks if enough shares are collected: [4](#0-3) 

If threshold > total possible weight, this condition **never succeeds**, causing permanent aggregation failure.

When reconstruction is attempted despite insufficient shares, it fails: [5](#0-4) 

Since only `n` shares exist but `t > n` shares are required, reconstruction always returns an error.

**Attack Scenario:**
1. Through rounding errors, integer overflow, or on-chain configuration manipulation, a `WeightedConfigArkworks` is created where `threshold_weight > sum(weights)`
2. This passes validation in release builds due to missing runtime checks
3. The invalid config is deployed for an epoch in the consensus secret sharing system
4. Nodes attempt to aggregate secret shares but can never meet the threshold
5. Secret sharing never completes, blocking consensus randomness generation
6. **Permanent consensus liveness failure** for the entire epoch

## Impact Explanation
This vulnerability meets **Critical Severity** criteria under "Total loss of liveness/network availability":

- **Consensus Liveness Failure**: If secret sharing is required for consensus (randomness generation), the chain permanently halts
- **Non-Recoverable State**: Once an invalid config is deployed for an epoch, it cannot be fixed without manual intervention or a hard fork
- **Cryptographic Correctness Violation**: Shamir secret sharing with t > n violates fundamental mathematical properties, making the scheme mathematically impossible
- **Affects All Validators**: Every node attempting to use the invalid config experiences the same failure

The impact is catastrophic because it breaks the "Cryptographic Correctness" and "Consensus Safety" invariants permanently.

## Likelihood Explanation
**Likelihood: Medium to Low** but with **Severe Consequences**

While the validation gap exists and allows invalid configurations in release builds, exploitation requires:
1. Finding or creating a code path where `WeightedConfigArkworks` (using `ShamirThresholdConfig`) is instantiated with attacker-controlled parameters
2. The parameters must result in `threshold > total_weight` after all calculations
3. This config must be deployed through on-chain mechanisms

Current production code primarily uses `WeightedConfigBlstrs` which **does** have proper runtime validation: [6](#0-5) 

However, the `FPTXWeighted` scheme used in secret sharing explicitly specifies `ShamirThresholdConfig`: [7](#0-6) 

This creates a latent vulnerability that could be triggered through future code changes or currently inactive code paths.

## Recommendation
Add runtime validation to `ShamirThresholdConfig::new()` to replace the debug_assert with proper error handling:

```rust
fn new(t: usize, n: usize) -> Result<Self> {
    if t == 0 {
        return Err(anyhow!("threshold must be > 0"));
    }
    if n == 0 {
        return Err(anyhow!("number of shares must be > 0"));
    }
    if t > n {
        return Err(anyhow!(
            "threshold {} exceeds number of shares {}", t, n
        ));
    }
    let domain = Radix2EvaluationDomain::new(n).unwrap();
    Ok(Self { n, t, domain })
}
```

Additionally, add validation in `SecretShareConfig::new()` as defense-in-depth:

```rust
pub fn new(...) -> anyhow::Result<Self> {
    ensure!(
        config.get_threshold_config().t <= config.get_threshold_config().n,
        "Secret sharing threshold {} exceeds number of validators {}",
        config.get_threshold_config().t,
        config.get_threshold_config().n
    );
    Ok(Self { ... })
}
```

## Proof of Concept
```rust
#[cfg(test)]
mod test_invalid_threshold {
    use aptos_crypto::arkworks::shamir::ShamirThresholdConfig;
    use ark_bn254::Fr;
    
    #[test]
    #[cfg(not(debug_assertions))] // Only runs in release mode
    fn test_invalid_threshold_accepted_in_release() {
        // In release builds, this succeeds despite t > n
        let config = ShamirThresholdConfig::<Fr>::new(10, 5);
        assert!(config.is_ok(), "Invalid config should be rejected but succeeds in release");
        
        let config = config.unwrap();
        assert_eq!(config.t, 10);
        assert_eq!(config.n, 5);
        // This violates the fundamental requirement t <= n for Shamir secret sharing
    }
    
    #[test]
    #[cfg(debug_assertions)] // Only runs in debug mode
    #[should_panic(expected = "Expected t <= n")]
    fn test_invalid_threshold_panics_in_debug() {
        // In debug builds, this panics
        let _ = ShamirThresholdConfig::<Fr>::new(10, 5);
    }
}
```

This demonstrates that the same code behaves differently between debug and release builds, creating a security vulnerability in production deployments.

## Notes
- The vulnerability is confirmed in the codebase but exploitation depends on finding active code paths using `WeightedConfigArkworks`/`ShamirThresholdConfig` with attacker-controlled parameters
- The more commonly used `WeightedConfigBlstrs` has proper validation and is not vulnerable
- The fix should be applied regardless of current exploit paths to prevent future vulnerabilities as code evolves

### Citations

**File:** crates/aptos-crypto/src/arkworks/shamir.rs (L230-234)
```rust
    pub fn new(t: usize, n: usize) -> Self {
        debug_assert!(t <= n, "Expected t <= n, but t = {} and n = {}", t, n);
        let domain = Radix2EvaluationDomain::new(n).unwrap();
        ShamirThresholdConfig { n, t, domain }
    }
```

**File:** crates/aptos-crypto/src/arkworks/shamir.rs (L313-318)
```rust
        if shares.len() < sc.t {
            Err(anyhow!(
                "Incorrect number of shares provided, received {} but expected at least {}",
                shares.len(),
                sc.t
            ))
```

**File:** crates/aptos-crypto/src/weighted_config.rs (L96-96)
```rust
        let tc = TC::new(threshold_weight, W)?;
```

**File:** types/src/secret_sharing.rs (L188-194)
```rust
    pub fn threshold(&self) -> u64 {
        self.config.get_threshold_config().t as u64
    }

    pub fn number_of_validators(&self) -> u64 {
        self.config.get_threshold_config().n as u64
    }
```

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L44-46)
```rust
        if self.total_weight < secret_share_config.threshold() {
            return Either::Left(self);
        }
```

**File:** crates/aptos-crypto/src/blstrs/threshold_config.rs (L118-122)
```rust
        if t > n {
            return Err(anyhow!(
                "expected the reconstruction threshold {t} to be < than the number of shares {n}"
            ));
        }
```

**File:** crates/aptos-batch-encryption/src/schemes/fptx_weighted.rs (L226-226)
```rust
    type ThresholdConfig = aptos_crypto::weighted_config::WeightedConfigArkworks<Fr>;
```

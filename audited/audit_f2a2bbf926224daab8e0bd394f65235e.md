# Audit Report

## Title
Unbounded Memory Allocation in FFT Domain Initialization Can Cause Network-Wide Validator Crashes

## Summary
The `fft` function in `fft.rs` allocates memory based on `dom.N` without bounds checking, and `BatchEvaluationDomain::new()` lacks the safety checks present in `EvaluationDomain::new()`. When DKG randomness configuration thresholds are set with an extremely small gap via governance, the resulting domain size can be astronomically large, causing allocation failures and crashing all validators during epoch transitions.

## Finding Description

The vulnerability exists in the FFT domain allocation chain during DKG (Distributed Key Generation) initialization: [1](#0-0) 

The `dom.N` value originates from `BatchEvaluationDomain::new()`, which is called during DKG setup with the total weight `W` (sum of all validator weights). Unlike `EvaluationDomain::new()` which checks if `log_N >= Scalar::S` and returns an error, `BatchEvaluationDomain::new()` has no such bounds checking: [2](#0-1) 

Compare this to the safe implementation in `EvaluationDomain::new()`: [3](#0-2) 

The validator weights are computed based on randomness configuration thresholds via the formula in `total_weight_upper_bound`: [4](#0-3) 

The formula computes: `(n/2 + 2) / (reconstruct_threshold - secrecy_threshold)`. When governance sets thresholds with the minimum enforced gap of `U64F64::DELTA` (2^-64): [5](#0-4) 

The result becomes: `(num_validators/2 + 2) * 2^64`, which saturates to `usize::MAX` when converted. This causes `smallest_power_of_2_greater_than_or_eq()` to potentially overflow or loop infinitely: [6](#0-5) 

**Attack Path:**
1. Governance updates `OnChainRandomnessConfig` with thresholds having minimal gap (e.g., 0.5 and 0.5 + DELTA)
2. During epoch transition, all validators call `build_dkg_pvss_config()`: [7](#0-6) 

3. This creates `WeightedConfigBlstrs` with huge total weight `W`
4. `ThresholdConfigBlstrs::new(threshold, W)` is called: [8](#0-7) 

5. `BatchEvaluationDomain::new(W)` attempts to allocate `Vec::with_capacity(N)` where N ≈ 2^64
6. Allocation fails with panic: "capacity overflow" or OOM
7. All validators crash simultaneously

This breaks the **Consensus Safety** and **Resource Limits** invariants, causing total loss of network liveness.

## Impact Explanation

**Critical Severity** - Total loss of liveness/network availability:
- All validators crash simultaneously during epoch transition
- Network becomes completely unavailable until manual intervention
- Requires coordinated recovery effort across all validators
- Potential for extended downtime affecting all network users

The vulnerability affects the core DKG initialization path called by every validator during epoch changes: [9](#0-8) 

## Likelihood Explanation

**Likelihood: Low-Medium**

While the attack requires governance control to set malicious randomness thresholds, several factors increase the likelihood:

1. **No validation in Move layer**: The randomness config accepts any threshold values without bounds checking: [10](#0-9) 

2. **Weak Rust-side validation**: Only enforces thresholds differ by `DELTA`, not a practical minimum: [5](#0-4) 

3. **Governance compromise**: If governance keys are compromised or a malicious proposal passes, the attack is trivial to execute
4. **Accidental misconfiguration**: Extreme threshold values could be set accidentally during testing or upgrades

## Recommendation

**Immediate fixes:**

1. Add bounds checking to `BatchEvaluationDomain::new()` matching `EvaluationDomain::new()`:

```rust
pub fn new(n: usize) -> Result<Self, CryptoMaterialError> {
    let (N, log_N) = smallest_power_of_2_greater_than_or_eq(n);
    
    // Add the same safety check as EvaluationDomain::new()
    if log_N >= Scalar::S as usize {
        return Err(CryptoMaterialError::WrongLengthError);
    }
    
    let omega = EvaluationDomain::get_Nth_root_of_unity(log_N);
    // ... rest of implementation
}
```

2. Enforce minimum threshold gap in `DKGRounding::new()`:

```rust
const MIN_THRESHOLD_GAP: U64F64 = U64F64::from_bits(1 << 48); // ~0.000004, practical minimum

reconstruct_threshold_in_stake_ratio = max(
    reconstruct_threshold_in_stake_ratio,
    secrecy_threshold_in_stake_ratio + MIN_THRESHOLD_GAP,
);
```

3. Add validation in the Move randomness config module:

```move
public fun new_v1(secrecy_threshold: FixedPoint64, reconstruction_threshold: FixedPoint64): RandomnessConfig {
    // Validate minimum gap between thresholds
    let gap = fixed_point64::sub(reconstruction_threshold, secrecy_threshold);
    let min_gap = fixed_point64::create_from_rational(1, 100); // 1% minimum
    assert!(fixed_point64::greater_or_equal(gap, min_gap), ETHRESHOLD_GAP_TOO_SMALL);
    
    RandomnessConfig {
        variant: copyable_any::pack( ConfigV1 {
            secrecy_threshold,
            reconstruction_threshold
        })
    }
}
```

## Proof of Concept

```rust
use aptos_types::on_chain_config::OnChainRandomnessConfig;
use fixed::types::U64F64;
use aptos_types::dkg::real_dkg::build_dkg_pvss_config;

#[test]
#[should_panic(expected = "capacity overflow")]
fn test_extreme_threshold_gap_causes_crash() {
    // Create validator set with 100 validators
    let validator_stakes: Vec<u64> = vec![1_000_000; 100];
    
    // Set thresholds with minimal gap (DELTA)
    let secrecy = U64F64::from_num(1) / U64F64::from_num(2);
    let reconstruct = secrecy + U64F64::DELTA;
    
    // This should panic during DKG config creation
    let _config = build_dkg_pvss_config(
        0, // epoch
        secrecy,
        reconstruct,
        None,
        &create_test_validators(100),
    );
    
    // If we reach here, the vulnerability was not triggered
    panic!("Expected panic did not occur");
}
```

## Notes

This vulnerability represents a critical failure in defense-in-depth. While governance is nominally trusted, the system should not allow configuration values that can deterministically crash the entire network. The missing bounds check in `BatchEvaluationDomain::new()` compared to `EvaluationDomain::new()` indicates an inconsistency in safety practices that should be corrected. The attack surface is governance-controlled configuration, making this a high-stakes governance attack or catastrophic misconfiguration scenario.

### Citations

**File:** crates/aptos-crypto/src/blstrs/fft.rs (L23-32)
```rust
/// Computes the forward Fast Fourier Transform (FFT) of a polynomial.
pub fn fft(poly: &[Scalar], dom: &EvaluationDomain) -> Vec<Scalar> {
    let mut evals = Vec::with_capacity(dom.N);
    evals.resize(poly.len(), Scalar::ZERO);
    evals.copy_from_slice(poly);

    fft_assign(&mut evals, dom);

    evals
}
```

**File:** crates/aptos-crypto/src/blstrs/evaluation_domain.rs (L48-64)
```rust
/// Returns the highest $N = 2^k$ such that $N \ge n$.
#[allow(non_snake_case)]
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

**File:** crates/aptos-crypto/src/blstrs/evaluation_domain.rs (L73-81)
```rust
    pub fn new(n: usize) -> Result<EvaluationDomain, CryptoMaterialError> {
        // Compute the size of our evaluation domain
        let (N, log_N) = smallest_power_of_2_greater_than_or_eq(n);

        // The pairing-friendly curve may not be able to support
        // large enough (radix2) evaluation domains.
        if log_N >= Scalar::S as usize {
            return Err(CryptoMaterialError::WrongLengthError);
        }
```

**File:** crates/aptos-crypto/src/blstrs/evaluation_domain.rs (L120-132)
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

```

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L34-48)
```rust
pub fn total_weight_upper_bound(
    validator_stakes: &[u64],
    mut reconstruct_threshold_in_stake_ratio: U64F64,
    secrecy_threshold_in_stake_ratio: U64F64,
) -> usize {
    reconstruct_threshold_in_stake_ratio = max(
        reconstruct_threshold_in_stake_ratio,
        secrecy_threshold_in_stake_ratio + U64F64::DELTA,
    );
    let two = U64F64::from_num(2);
    let n = U64F64::from_num(validator_stakes.len());
    ((n / two + two) / (reconstruct_threshold_in_stake_ratio - secrecy_threshold_in_stake_ratio))
        .ceil()
        .to_num::<usize>()
}
```

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L67-70)
```rust
        reconstruct_threshold_in_stake_ratio = max(
            reconstruct_threshold_in_stake_ratio,
            secrecy_threshold_in_stake_ratio + U64F64::DELTA,
        );
```

**File:** types/src/dkg/real_dkg/mod.rs (L97-118)
```rust
pub fn build_dkg_pvss_config(
    cur_epoch: u64,
    secrecy_threshold: U64F64,
    reconstruct_threshold: U64F64,
    maybe_fast_path_secrecy_threshold: Option<U64F64>,
    next_validators: &[ValidatorConsensusInfo],
) -> DKGPvssConfig {
    let validator_stakes: Vec<u64> = next_validators.iter().map(|vi| vi.voting_power).collect();
    let timer = Instant::now();
    let DKGRounding {
        profile,
        wconfig,
        fast_wconfig,
        rounding_error,
        rounding_method,
    } = DKGRounding::new(
        &validator_stakes,
        secrecy_threshold,
        reconstruct_threshold,
        maybe_fast_path_secrecy_threshold,
    );
    let rounding_time = timer.elapsed();
```

**File:** types/src/dkg/real_dkg/mod.rs (L199-224)
```rust
    fn new_public_params(dkg_session_metadata: &DKGSessionMetadata) -> RealDKGPublicParams {
        let randomness_config = dkg_session_metadata
            .randomness_config_derived()
            .unwrap_or_else(OnChainRandomnessConfig::default_enabled);
        let secrecy_threshold = randomness_config
            .secrecy_threshold()
            .unwrap_or_else(|| *rounding::DEFAULT_SECRECY_THRESHOLD);
        let reconstruct_threshold = randomness_config
            .reconstruct_threshold()
            .unwrap_or_else(|| *rounding::DEFAULT_RECONSTRUCT_THRESHOLD);
        let maybe_fast_path_secrecy_threshold = randomness_config.fast_path_secrecy_threshold();

        let pvss_config = build_dkg_pvss_config(
            dkg_session_metadata.dealer_epoch,
            secrecy_threshold,
            reconstruct_threshold,
            maybe_fast_path_secrecy_threshold,
            &dkg_session_metadata.target_validator_consensus_infos_cloned(),
        );
        let verifier = ValidatorVerifier::new(dkg_session_metadata.dealer_consensus_infos_cloned());
        RealDKGPublicParams {
            session_metadata: dkg_session_metadata.clone(),
            pvss_config,
            verifier: verifier.into(),
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

**File:** aptos-move/framework/aptos-framework/sources/configs/randomness_config.move (L92-100)
```text
    /// Create a `ConfigV1` variant.
    public fun new_v1(secrecy_threshold: FixedPoint64, reconstruction_threshold: FixedPoint64): RandomnessConfig {
        RandomnessConfig {
            variant: copyable_any::pack( ConfigV1 {
                secrecy_threshold,
                reconstruction_threshold
            } )
        }
    }
```

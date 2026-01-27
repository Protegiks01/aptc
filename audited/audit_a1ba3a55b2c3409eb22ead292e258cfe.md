# Audit Report

## Title
Missing Bounds Check in BatchEvaluationDomain::new() Enables Memory Exhaustion DoS Through Malicious Governance Configuration

## Summary
The `BatchEvaluationDomain::new()` function lacks the bounds check present in `EvaluationDomain::new()`, allowing allocation of arbitrarily large vectors when called with excessive `n` values. A malicious or erroneous governance configuration setting randomness thresholds extremely close together could cause all validators to simultaneously allocate gigabytes of memory during DKG session initialization, resulting in network-wide DoS. [1](#0-0) 

## Finding Description

The vulnerability stems from inconsistent validation between two related functions in the evaluation domain implementation:

**EvaluationDomain::new()** includes a critical bounds check: [2](#0-1) 

**BatchEvaluationDomain::new()** lacks this check entirely, directly allocating a vector with capacity N and filling it with N scalar elements: [3](#0-2) 

The attack path involves governance setting randomness configuration with thresholds placed extremely close together. When validators initialize a DKG session, the `total_weight_upper_bound` calculation produces an enormous value: [4](#0-3) 

With malicious threshold parameters (e.g., secrecy=0.6, reconstruct=0.6001, difference=0.0001) and maximum validators (65536), the formula yields:
- Upper bound = (32768 + 2) / 0.0001 ≈ 327,700,000
- Next power of 2: N = 2^29 = 536,870,912
- Memory per validator: 536,870,912 × 32 bytes ≈ 17.2 GB

The threshold validation in `DKGRoundingProfile::new()` allows such configurations: [5](#0-4) 

These checks only require secrecy_threshold > 1/3, reconstruct_threshold ≤ 2/3, and secrecy < reconstruct. They do NOT enforce a minimum gap between thresholds.

The randomness config can be set via governance without parameter validation: [6](#0-5) 

When DKG starts, every validator calls `new_public_params`: [7](#0-6) 

This triggers the chain: `build_dkg_pvss_config` → `DKGRounding::new` → `WeightedConfigBlstrs::new` → `ThresholdConfigBlstrs::new` → `BatchEvaluationDomain::new(n)` where n is the total weight. [8](#0-7) 

The validator set size is capped at 65536: [9](#0-8) 

## Impact Explanation

**High Severity** per Aptos bug bounty criteria: Validator node slowdowns and potential crashes.

When malicious thresholds trigger this vulnerability:
1. All validators simultaneously attempt to allocate 17+ GB during DKG initialization
2. Validators with insufficient memory crash or become unresponsive
3. Network experiences significant performance degradation or loss of liveness
4. Even if allocation succeeds, the subsequent loop filling 536M elements causes severe performance impact

This breaks the **Resource Limits** invariant (#9): "All operations must respect gas, storage, and computational limits." The unbounded memory allocation violates fundamental resource constraints.

## Likelihood Explanation

**Medium-Low Likelihood** - Requires governance action:

The vulnerability can only be triggered through on-chain governance proposals that set randomness configuration parameters. However:

**Factors Increasing Likelihood:**
- No validation exists in Move code preventing pathological threshold configurations
- Governance participants may not understand the technical implications of threshold spacing
- An honest mistake during parameter tuning could trigger this (e.g., typo: 0.6001 instead of 0.7)
- The infallible fallback ensures the configuration is accepted even if binary search fails

**Factors Decreasing Likelihood:**
- Governance proposals undergo community review
- Such extreme threshold values (0.0001 gap) would appear suspicious
- Reasonable threshold configurations (0.1+ gap) result in acceptable memory usage (~50-100 MB)

## Recommendation

Add the same bounds check to `BatchEvaluationDomain::new()` that exists in `EvaluationDomain::new()`:

```rust
pub fn new(n: usize) -> Result<Self, CryptoMaterialError> {
    let (N, log_N) = smallest_power_of_2_greater_than_or_eq(n);
    
    // Add bounds check
    if log_N >= Scalar::S as usize {
        return Err(CryptoMaterialError::WrongLengthError);
    }
    
    let omega = EvaluationDomain::get_Nth_root_of_unity(log_N);
    // ... rest of implementation
}
```

Additionally, add validation in the Move module to enforce minimum threshold spacing:

```move
public fun new_v1(secrecy_threshold: FixedPoint64, reconstruction_threshold: FixedPoint64): RandomnessConfig {
    // Ensure minimum 5% gap between thresholds
    let min_gap = fixed_point64::create_from_rational(5, 100);
    assert!(fixed_point64::sub(reconstruction_threshold, secrecy_threshold) >= min_gap, ETHRESHOLD_GAP_TOO_SMALL);
    // ... rest of implementation
}
```

## Proof of Concept

```rust
#[test]
#[should_panic(expected = "memory allocation")]
fn test_batch_evaluation_domain_memory_exhaustion() {
    // Simulate governance setting malicious thresholds
    let secrecy = U64F64::from_num(0.6);
    let reconstruct = U64F64::from_num(0.6001);
    let validator_stakes: Vec<u64> = vec![1; 65536]; // Max validators
    
    // Calculate resulting weight
    let upper_bound = total_weight_upper_bound(&validator_stakes, reconstruct, secrecy);
    println!("Upper bound weight: {}", upper_bound); // ~327M
    
    // This would trigger massive allocation
    let config = ThresholdConfigBlstrs::new(upper_bound / 2, upper_bound).unwrap();
    // Validators crash here due to memory exhaustion
}
```

**Notes**

While this vulnerability exists in the code, its exploitability depends heavily on governance behavior, which per the trust model should not be assumed malicious. However, the lack of parameter validation creates a significant risk surface for both accidental misconfiguration and potential governance compromise. The missing bounds check represents a defensive programming failure that should be addressed regardless of trust assumptions.

### Citations

**File:** crates/aptos-crypto/src/blstrs/evaluation_domain.rs (L79-81)
```rust
        if log_N >= Scalar::S as usize {
            return Err(CryptoMaterialError::WrongLengthError);
        }
```

**File:** crates/aptos-crypto/src/blstrs/evaluation_domain.rs (L120-133)
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

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L197-199)
```rust
        ensure!(secrecy_threshold_in_stake_ratio * U64F64::from_num(3) > U64F64::from_num(1));
        ensure!(secrecy_threshold_in_stake_ratio < reconstruct_threshold_in_stake_ratio);
        ensure!(reconstruct_threshold_in_stake_ratio * U64F64::from_num(3) <= U64F64::from_num(2));
```

**File:** aptos-move/framework/aptos-framework/sources/configs/randomness_config.move (L93-99)
```text
    public fun new_v1(secrecy_threshold: FixedPoint64, reconstruction_threshold: FixedPoint64): RandomnessConfig {
        RandomnessConfig {
            variant: copyable_any::pack( ConfigV1 {
                secrecy_threshold,
                reconstruction_threshold
            } )
        }
```

**File:** dkg/src/dkg_manager/mod.rs (L314-314)
```rust
        let public_params = DKG::new_public_params(dkg_session_metadata);
```

**File:** crates/aptos-crypto/src/blstrs/threshold_config.rs (L124-125)
```rust
        let batch_dom = BatchEvaluationDomain::new(n);
        let dom = batch_dom.get_subdomain(n);
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L100-100)
```text
    const MAX_VALIDATOR_SET_SIZE: u64 = 65536;
```

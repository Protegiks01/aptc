# Audit Report

## Title
DKG Rounding Algorithm Produces Invalid Reconstruction Thresholds Exceeding 100% When Maximum Percentages Are Set

## Summary
When governance sets randomness configuration thresholds to 100%, the DKG rounding algorithm computes reconstruction thresholds that exceed 1.0 (100% of stake), making randomness generation impossible and causing complete liveness failure for the on-chain randomness feature.

## Finding Description

The security question asks whether percentage-to-fixed-point conversion can introduce rounding errors. The conversion itself is exact—`100/100` produces precisely 1.0. However, a critical vulnerability exists in the downstream DKG rounding algorithm. [1](#0-0) 

When `OnChainRandomnessConfig::new_v2(100, 100, 100)` is called, it creates threshold values of exactly 1.0 with no rounding error in the conversion.

These thresholds flow into the DKG setup process: [2](#0-1) 

The `DKGRounding::new()` function attempts validation via `DKGRoundingProfile::new()`: [3](#0-2) 

When all thresholds equal 1.0, validation fails because:
- Line 198: `secrecy_threshold < reconstruct_threshold` fails (1.0 < 1.0 is false)
- Line 199: `reconstruct_threshold * 3 <= 2` fails (3 > 2)

The system falls back to the infallible method: [4](#0-3) 

The infallible method calls `compute_profile_fixed_point()`, which computes: [5](#0-4) 

And for the fast path: [6](#0-5) 

The `stake_gap_fixed` variable represents rounding errors from weight assignment and is always positive when validators have non-uniform stakes. When `secrecy_threshold_in_stake_ratio = 1.0`, the computed `reconstruct_threshold_in_stake_ratio = 1.0 + stake_gap_fixed > 1.0`.

**Critical Issue**: The `is_valid_profile()` validation checks if thresholds exceed 1.0: [7](#0-6) 

However, this validation is ONLY applied in the binary search path (line 233-238), NOT in the infallible fallback path. The infallible method returns an invalid profile with reconstruction thresholds > 1.0 without validation.

A reconstruction threshold > 1.0 means "more than 100% of total stake is required to reconstruct randomness"—an impossible condition. No validator subset can ever meet this threshold, causing permanent failure of randomness generation.

## Impact Explanation

This vulnerability causes **complete liveness failure** for Aptos on-chain randomness, a critical protocol feature used for:
- Random number generation for applications
- Fair transaction ordering
- Validator leader selection randomization

The impact qualifies as **High Severity** under the Aptos bug bounty program:
- **Significant protocol violation**: Core randomness feature becomes completely non-functional
- **Liveness degradation**: While consensus continues, randomness-dependent features fail
- **Network-wide impact**: Affects all validators and applications relying on randomness

This does not reach Critical severity because:
- No loss of funds occurs
- Consensus safety is not violated
- Can be recovered through governance proposal to fix configuration
- Does not require a hardfork

## Likelihood Explanation

**Likelihood: Medium**

**Attack Vector**:
A malicious governance participant or misconfigured proposal could set all randomness thresholds to 100%. This requires:
1. Governance proposal creation with parameters `(100, 100, 100)`
2. Proposal voting and approval
3. Automatic application at next epoch

**Barriers**:
- Requires governance access (trusted role)
- Proposal would be publicly visible before application
- Community might detect obviously invalid parameters

**Feasibility**:
- No technical barriers prevent setting these values
- No validation in Move contracts checks sanity of thresholds
- The infallible fallback path masks the error by logging it rather than failing

The error is logged but not enforced: [8](#0-7) 

## Recommendation

Add validation to prevent reconstruction thresholds from exceeding 1.0, even in the infallible path:

```rust
// In DKGRoundingProfile::infallible()
pub fn infallible(
    validator_stakes: &Vec<u64>,
    mut secrecy_threshold_in_stake_ratio: U64F64,
    mut reconstruct_threshold_in_stake_ratio: U64F64,
    fast_secrecy_threshold_in_stake_ratio: Option<U64F64>,
) -> Self {
    let one = U64F64::from_num(1);
    
    // Add maximum threshold validation
    let max_safe_threshold = U64F64::from_num(2) / U64F64::from_num(3); // 66.67%
    secrecy_threshold_in_stake_ratio = min(max_safe_threshold, secrecy_threshold_in_stake_ratio);
    reconstruct_threshold_in_stake_ratio = min(max_safe_threshold, reconstruct_threshold_in_stake_ratio);
    // ... rest of function
    
    let profile = compute_profile_fixed_point(...);
    
    // Validate computed thresholds don't exceed 1.0
    if profile.reconstruct_threshold_in_stake_ratio > one {
        panic!("DKG rounding produced invalid reconstruction threshold > 1.0");
    }
    if let Some(fast_threshold) = profile.fast_reconstruct_threshold_in_stake_ratio {
        if fast_threshold > one {
            panic!("DKG rounding produced invalid fast path threshold > 1.0");
        }
    }
    
    profile
}
```

Additionally, add Move-level validation in `randomness_config.move`:

```move
public fun new_v2(
    secrecy_threshold: FixedPoint64,
    reconstruction_threshold: FixedPoint64,
    fast_path_secrecy_threshold: FixedPoint64,
): RandomnessConfig {
    // Add sanity checks
    let max_threshold = fixed_point64::create_from_rational(2, 3); // 66.67%
    assert!(fixed_point64::less_or_equal(secrecy_threshold, max_threshold), EINVALID_THRESHOLD);
    assert!(fixed_point64::less_or_equal(reconstruction_threshold, max_threshold), EINVALID_THRESHOLD);
    assert!(fixed_point64::less_or_equal(fast_path_secrecy_threshold, max_threshold), EINVALID_THRESHOLD);
    
    RandomnessConfig {
        variant: copyable_any::pack( ConfigV2 {
            secrecy_threshold,
            reconstruction_threshold,
            fast_path_secrecy_threshold,
        } )
    }
}
```

## Proof of Concept

```rust
#[test]
fn test_max_threshold_causes_invalid_reconstruction() {
    use aptos_types::on_chain_config::OnChainRandomnessConfig;
    use types::dkg::real_dkg::rounding::DKGRounding;
    
    // Create config with all thresholds at 100%
    let config = OnChainRandomnessConfig::new_v2(100, 100, 100);
    
    // Extract thresholds
    let secrecy = config.secrecy_threshold().unwrap();
    let reconstruct = config.reconstruct_threshold().unwrap();
    let fast_secrecy = config.fast_path_secrecy_threshold();
    
    // Verify thresholds are exactly 1.0 (no conversion error)
    assert_eq!(secrecy, U64F64::from_num(1));
    assert_eq!(reconstruct, U64F64::from_num(1));
    assert_eq!(fast_secrecy.unwrap(), U64F64::from_num(1));
    
    // Create realistic validator stake distribution
    let validator_stakes: Vec<u64> = vec![
        1_000_000, 2_000_000, 1_500_000, 800_000, 1_200_000
    ];
    
    // Call DKGRounding::new() with max thresholds
    let dkg_rounding = DKGRounding::new(
        &validator_stakes,
        secrecy,
        reconstruct,
        fast_secrecy,
    );
    
    // Verify that rounding_error is set (binary search failed)
    assert!(dkg_rounding.rounding_error.is_some());
    assert_eq!(dkg_rounding.rounding_method, "infallible");
    
    // THE BUG: Computed thresholds exceed 1.0
    let profile = &dkg_rounding.profile;
    assert!(profile.reconstruct_threshold_in_stake_ratio > U64F64::from_num(1));
    if let Some(fast_threshold) = profile.fast_reconstruct_threshold_in_stake_ratio {
        assert!(fast_threshold > U64F64::from_num(1));
    }
    
    // This means NO validator subset can ever reconstruct randomness
    // because no subset can have > 100% of stake
    println!("Main path threshold: {} (> 1.0 = impossible!)", 
        profile.reconstruct_threshold_in_stake_ratio);
    println!("Fast path threshold: {:?} (> 1.0 = impossible!)", 
        profile.fast_reconstruct_threshold_in_stake_ratio);
}
```

## Notes

The security question specifically asks about rounding errors in percentage-to-fixed-point conversion. The conversion itself (`100/100`) is mathematically exact and produces precisely 1.0. However, the vulnerability exists in the DKG rounding algorithm that processes these thresholds, where `stake_gap_fixed` is added to account for validator weight rounding errors. This addition pushes computed reconstruction thresholds above 1.0, violating the fundamental invariant that stake ratios must not exceed 100% and causing complete randomness generation failure.

### Citations

**File:** types/src/on_chain_config/randomness_config.rs (L117-136)
```rust
    pub fn new_v2(
        secrecy_threshold_in_percentage: u64,
        reconstruct_threshold_in_percentage: u64,
        fast_path_secrecy_threshold_in_percentage: u64,
    ) -> Self {
        let secrecy_threshold = FixedPoint64MoveStruct::from_u64f64(
            U64F64::from_num(secrecy_threshold_in_percentage) / U64F64::from_num(100),
        );
        let reconstruction_threshold = FixedPoint64MoveStruct::from_u64f64(
            U64F64::from_num(reconstruct_threshold_in_percentage) / U64F64::from_num(100),
        );
        let fast_path_secrecy_threshold = FixedPoint64MoveStruct::from_u64f64(
            U64F64::from_num(fast_path_secrecy_threshold_in_percentage) / U64F64::from_num(100),
        );
        Self::V2(ConfigV2 {
            secrecy_threshold,
            reconstruction_threshold,
            fast_path_secrecy_threshold,
        })
    }
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

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L79-96)
```rust
        let (profile, rounding_error, rounding_method) = match DKGRoundingProfile::new(
            validator_stakes,
            total_weight_min,
            total_weight_max,
            secrecy_threshold_in_stake_ratio,
            reconstruct_threshold_in_stake_ratio,
            fast_secrecy_threshold_in_stake_ratio,
        ) {
            Ok(profile) => (profile, None, "binary_search".to_string()),
            Err(e) => {
                let profile = DKGRoundingProfile::infallible(
                    validator_stakes,
                    secrecy_threshold_in_stake_ratio,
                    reconstruct_threshold_in_stake_ratio,
                    fast_secrecy_threshold_in_stake_ratio,
                );
                (profile, Some(format!("{e}")), "infallible".to_string())
            },
```

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L197-199)
```rust
        ensure!(secrecy_threshold_in_stake_ratio * U64F64::from_num(3) > U64F64::from_num(1));
        ensure!(secrecy_threshold_in_stake_ratio < reconstruct_threshold_in_stake_ratio);
        ensure!(reconstruct_threshold_in_stake_ratio * U64F64::from_num(3) <= U64F64::from_num(2));
```

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L285-293)
```rust
fn is_valid_profile(
    profile: &DKGRoundingProfile,
    reconstruct_threshold_in_stake_ratio: U64F64,
) -> bool {
    // ensure the reconstruction is below threshold, and the fast path threshold is valid
    profile.reconstruct_threshold_in_stake_ratio <= reconstruct_threshold_in_stake_ratio
        && (profile.fast_reconstruct_threshold_in_stake_ratio.is_none()
            || profile.fast_reconstruct_threshold_in_stake_ratio.unwrap() <= U64F64::from_num(1))
}
```

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L332-333)
```rust
    let stake_gap_fixed = stake_per_weight * delta_total_fixed / stake_sum_fixed;
    let reconstruct_threshold_in_stake_ratio = secrecy_threshold_in_stake_ratio + stake_gap_fixed;
```

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L339-339)
```rust
            let recon_threshold = fast_secrecy_threshold_in_stake_ratio + stake_gap_fixed;
```

**File:** dkg/src/dkg_manager/mod.rs (L315-323)
```rust
        if let Some(summary) = public_params.rounding_summary() {
            info!(
                epoch = self.epoch_state.epoch,
                "Rounding summary: {:?}", summary
            );
            ROUNDING_SECONDS
                .with_label_values(&[summary.method.as_str()])
                .observe(summary.exec_time.as_secs_f64());
        }
```

# Audit Report

## Title
DKG Rounding Off-By-One Error: Infallible Fallback Can Produce Unvalidated Profiles Exceeding Reconstruction Threshold

## Summary
The DKG (Distributed Key Generation) rounding system has a critical flaw where the "infallible" fallback method can produce weight configurations that make randomness reconstruction harder than intended. When the binary search fails to find a valid weight assignment, the system falls back to an unvalidated upper-bound calculation that may violate the reconstruction threshold constraint, potentially causing liveness failures in the randomness generation protocol.

## Finding Description

The vulnerability exists in the DKG rounding profile calculation logic. The system attempts to assign weights to validators such that:
1. Validator subsets with ≤ 50% stake cannot reconstruct randomness (secrecy property)
2. Validator subsets with > 67% stake can reconstruct randomness (liveness property) [1](#0-0) 

The binary search attempts to find a valid profile where `profile.reconstruct_threshold_in_stake_ratio <= desired_reconstruct_threshold`. If it fails, the code falls back to the "infallible" method. [2](#0-1) 

The infallible method returns a profile WITHOUT validation, meaning it may produce profiles where the actual reconstruction threshold exceeds the desired 2/3 threshold.

The validation function that should be checked is: [3](#0-2) 

The core issue is in the threshold calculation formula: [4](#0-3) 

The `+ one` (adding 1) after ceiling ensures validators at the secrecy threshold cannot reconstruct. However, with small total weights or unfavorable rounding, this can consume the entire gap between secrecy (50%) and reconstruction (67%) thresholds. The actual reconstruction threshold is calculated as `secrecy_threshold + stake_gap`, where `stake_gap = stake_per_weight * delta_total / stake_sum`. When delta_total is large due to accumulated rounding errors, the actual threshold can significantly exceed the intended 67%.

The aggregation check uses: [5](#0-4) 

This means validators need `total_weight >= threshold` to reconstruct. If the threshold is set too high due to the unvalidated infallible profile, legitimate validator subsets with > 67% stake may fail this check.

**Concrete Scenario:**
- Small validator set with total_weight calculated by upper bound formula
- Rounding causes large delta_total
- Threshold = ceil(secrecy_weight + delta_up) + 1 becomes very close to reconstruction_weight
- Validators with > 67% stake have their weight rounded down due to delta_down
- Result: `validator_weight < threshold` even though `stake_ratio > 67%`
- Randomness reconstruction fails, breaking liveness

## Impact Explanation

This is **High Severity** under Aptos bug bounty criteria as it causes:

1. **Validator node slowdowns**: Randomness generation may repeatedly fail, causing consensus delays
2. **Significant protocol violations**: Breaks the fundamental guarantee that >2/3 honest validators can generate randomness
3. **Potential liveness failure**: If randomness is critical for block production or other protocol operations, this could stall the blockchain

The vulnerability doesn't require attacker action - it manifests naturally when:
- The validator stake distribution causes binary search to fail
- The system falls back to the infallible method
- The resulting unvalidated profile has too high a reconstruction threshold

## Likelihood Explanation

**Likelihood: Medium-High**

The vulnerability manifests when:
1. Binary search fails to find a valid profile in range [total_weight_min, total_weight_max]
2. This is more likely with: extreme stake distributions, many validators with small individual stakes, or edge-case threshold ratios
3. The infallible method is automatically invoked as a fallback
4. The error is logged in `rounding_error` field but the invalid profile is still used [6](#0-5) 

The system continues operating with the invalid profile, trusting that the theoretical upper bound guarantees correctness. However, the combination of the "+1" adjustment, fixed-point rounding precision, and integer conversion can cause the actual threshold to exceed the intended value.

## Recommendation

**Fix: Add validation to the infallible fallback**

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
        
        // ADDED: Validate the infallible profile
        if !is_valid_profile(&profile, reconstruct_threshold_in_stake_ratio) {
            panic!(
                "Infallible method produced invalid profile: actual_threshold={:?} > desired={:?}",
                profile.reconstruct_threshold_in_stake_ratio,
                reconstruct_threshold_in_stake_ratio
            );
        }
        
        (profile, Some(format!("{e}")), "infallible".to_string())
    },
};
```

**Alternative: Adjust the threshold formula**

Consider removing or reducing the "+1" when it would violate the reconstruction threshold constraint, or increase total_weight_upper_bound to provide more margin for rounding.

## Proof of Concept

```rust
#[test]
fn test_infallible_produces_invalid_profile() {
    use fixed::types::U64F64;
    
    // Create a scenario where infallible produces an invalid profile
    // Small validator set with carefully chosen stakes to maximize rounding errors
    let validator_stakes = vec![101, 100, 99, 50, 50, 50, 25, 25];
    
    let secrecy_threshold = U64F64::from_num(1) / U64F64::from_num(2);
    let reconstruct_threshold = U64F64::from_num(2) / U64F64::from_num(3);
    
    let total_weight_min = total_weight_lower_bound(&validator_stakes);
    let total_weight_max = total_weight_upper_bound(
        &validator_stakes,
        reconstruct_threshold,
        secrecy_threshold,
    );
    
    // Try binary search - might fail with these parameters
    let result = DKGRoundingProfile::new(
        &validator_stakes,
        total_weight_min,
        total_weight_max / 2, // Artificially restrict to force failure
        secrecy_threshold,
        reconstruct_threshold,
        None,
    );
    
    if result.is_err() {
        // Fallback to infallible
        let profile = DKGRoundingProfile::infallible(
            &validator_stakes,
            secrecy_threshold,
            reconstruct_threshold,
            None,
        );
        
        // Check if the profile violates the constraint
        assert!(
            profile.reconstruct_threshold_in_stake_ratio <= reconstruct_threshold,
            "Infallible produced profile with actual_threshold={:?} > desired={:?}",
            profile.reconstruct_threshold_in_stake_ratio,
            reconstruct_threshold
        );
    }
}
```

This test would catch cases where the infallible method produces profiles exceeding the reconstruction threshold. The fix should ensure all profiles, whether from binary search or infallible fallback, meet the validation criteria before being used.

**Notes**

The vulnerability is subtle because:
1. The infallible method uses a mathematically derived upper bound intended to guarantee correctness
2. The "+1" adjustment is necessary for secrecy but can break liveness with small weights
3. The system logs the error but continues with the invalid profile
4. Fixed-point arithmetic precision and integer conversions can accumulate errors

The fix is straightforward: validate ALL profiles before use, not just those from binary search. If even the infallible method cannot produce a valid profile, the system should fail explicitly rather than silently using an invalid configuration that breaks the reconstruction threshold guarantee.

### Citations

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

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L122-128)
```rust
        Self {
            rounding_method,
            profile,
            wconfig,
            fast_wconfig,
            rounding_error,
        }
```

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L254-282)
```rust
    pub fn infallible(
        validator_stakes: &Vec<u64>,
        mut secrecy_threshold_in_stake_ratio: U64F64,
        mut reconstruct_threshold_in_stake_ratio: U64F64,
        fast_secrecy_threshold_in_stake_ratio: Option<U64F64>,
    ) -> Self {
        let one = U64F64::from_num(1);
        secrecy_threshold_in_stake_ratio = min(one, secrecy_threshold_in_stake_ratio);
        reconstruct_threshold_in_stake_ratio = min(one, reconstruct_threshold_in_stake_ratio);
        reconstruct_threshold_in_stake_ratio = max(
            secrecy_threshold_in_stake_ratio,
            reconstruct_threshold_in_stake_ratio,
        );

        let stake_total = U64F64::from_num(validator_stakes.clone().into_iter().sum::<u64>());

        let estimated_weight_total = total_weight_upper_bound(
            validator_stakes,
            reconstruct_threshold_in_stake_ratio,
            secrecy_threshold_in_stake_ratio,
        );
        let stake_per_weight = stake_total / U64F64::from_num(estimated_weight_total);
        compute_profile_fixed_point(
            validator_stakes,
            stake_per_weight,
            secrecy_threshold_in_stake_ratio,
            fast_secrecy_threshold_in_stake_ratio,
        )
    }
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

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L324-333)
```rust
    let reconstruct_threshold_in_weights_fixed =
        (secrecy_threshold_in_stake_ratio * stake_sum_fixed / stake_per_weight + delta_up_fixed)
            .ceil()
            + one;
    let reconstruct_threshold_in_weights: u64 = min(
        weight_total,
        reconstruct_threshold_in_weights_fixed.to_num::<u64>(),
    );
    let stake_gap_fixed = stake_per_weight * delta_total_fixed / stake_sum_fixed;
    let reconstruct_threshold_in_stake_ratio = secrecy_threshold_in_stake_ratio + stake_gap_fixed;
```

**File:** consensus/src/rand/rand_gen/rand_store.rs (L41-49)
```rust
    pub fn try_aggregate(
        self,
        rand_config: &RandConfig,
        rand_metadata: FullRandMetadata,
        decision_tx: Sender<Randomness>,
    ) -> Either<Self, RandShare<S>> {
        if self.total_weight < rand_config.threshold() {
            return Either::Left(self);
        }
```

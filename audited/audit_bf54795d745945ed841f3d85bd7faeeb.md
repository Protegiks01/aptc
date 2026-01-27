# Audit Report

## Title
Fast Path Randomness Configuration Lacks Critical Security Validation, Enabling Randomness Secret Leakage via Misconfigured Thresholds

## Summary
The `fast_randomness_enabled()` function returns `true` for any V2 randomness configuration without validating that `fast_path_secrecy_threshold` is properly configured. This allows the fast path to be enabled with dangerously low thresholds (including zero or values below the main path secrecy threshold), enabling validator coalitions with minimal stake to reconstruct randomness secrets and violate core cryptographic security invariants.

## Finding Description

The vulnerability exists in the configuration validation logic for Aptos's two-path randomness generation system. The system defines a critical security invariant documented in the Move framework: [1](#0-0) 

The `fast_randomness_enabled()` function unconditionally returns `true` for V2 configurations: [2](#0-1) 

Critically, there is **no validation** that `fast_path_secrecy_threshold` satisfies basic security requirements:
- Must be greater than 0 (non-trivial security)
- Must be at most 1.0 (cannot exceed 100% of stake)
- Should be greater than or equal to `secrecy_threshold` (fast path should not weaken security)

The Move contract's `new_v2()` function also lacks validation: [3](#0-2) 

During DKG setup, the misconfigured threshold propagates through the rounding algorithm: [4](#0-3) 

The validation in `is_valid_profile()` only checks that the result is ≤ 1.0, which is trivial: [5](#0-4) 

During randomness generation, share aggregation uses the misconfigured threshold: [6](#0-5) 

**Attack Path:**
1. Governance proposal sets ConfigV2 with `fast_path_secrecy_threshold = 0.05` (5%) due to human error, typo, or software bug
2. `fast_randomness_enabled()` returns `true` without validation
3. DKG computes `fast_reconstruct_threshold_in_weights` based on the 5% threshold
4. During randomness generation, validators with >5% combined stake can aggregate enough shares
5. The fast path reconstructs the randomness secret with far less stake than the main path's 50% requirement
6. Security invariant violated: secret revealed to coalition with ≤5% stake instead of required >50%

## Impact Explanation

**High Severity** - This vulnerability enables significant protocol violations per Aptos bug bounty criteria:

1. **Randomness Secret Leakage**: Validator coalitions with minimal stake (potentially <10%) can reconstruct secrets intended to remain secure up to 50% stake threshold
2. **VRF Prediction**: Leaked randomness enables predicting future VRF outputs used in leader selection
3. **Consensus Manipulation**: Attackers can manipulate leader election by predicting randomness
4. **Front-Running**: Knowledge of future randomness enables MEV extraction and transaction ordering attacks
5. **Defense-in-Depth Failure**: Critical security parameters lack validation, violating fundamental security principles

The impact is HIGH rather than CRITICAL because it requires governance misconfiguration as a precondition, not a direct exploit. However, once misconfigured, the system is permanently vulnerable until reconfiguration.

## Likelihood Explanation

**Medium-to-High Likelihood:**

1. **Human Error**: Governance proposals involve manual parameter entry (percentage values), prone to typos or unit confusion (e.g., entering 5 instead of 50, or 0.05 instead of 0.5)
2. **No Safety Rails**: Complete absence of validation means mistakes propagate directly to production
3. **Software Bugs**: Automated proposal generation tools could contain calculation errors: [7](#0-6) 
4. **Testing Gaps**: Development/testnet configs with low thresholds could accidentally deploy to mainnet
5. **Complex Parameters**: Three interrelated thresholds (secrecy, reconstruction, fast_path_secrecy) increase confusion risk

The vulnerability has already materialized in similar systems (e.g., DeFi protocols with unchecked admin parameters leading to exploits).

## Recommendation

Implement comprehensive validation for `fast_path_secrecy_threshold` at multiple layers:

**1. Move Contract Validation (Primary Defense):**
Add validation to `new_v2()` in `randomness_config.move`:

```move
public fun new_v2(
    secrecy_threshold: FixedPoint64,
    reconstruction_threshold: FixedPoint64,
    fast_path_secrecy_threshold: FixedPoint64,
): RandomnessConfig {
    // Validate fast_path_secrecy_threshold >= secrecy_threshold
    assert!(
        fixed_point64::greater_or_equal(fast_path_secrecy_threshold, secrecy_threshold),
        error::invalid_argument(EINVALID_FAST_PATH_THRESHOLD)
    );
    // Validate fast_path_secrecy_threshold <= 1.0
    assert!(
        fixed_point64::less_or_equal(fast_path_secrecy_threshold, fixed_point64::create_from_rational(1, 1)),
        error::invalid_argument(EINVALID_FAST_PATH_THRESHOLD)
    );
    RandomnessConfig {
        variant: copyable_any::pack( ConfigV2 {
            secrecy_threshold,
            reconstruction_threshold,
            fast_path_secrecy_threshold,
        } )
    }
}
```

**2. Rust-Side Validation (Defense in Depth):**
Add validation to `fast_randomness_enabled()` in `randomness_config.rs`:

```rust
pub fn fast_randomness_enabled(&self) -> bool {
    match self {
        OnChainRandomnessConfig::Off => false,
        OnChainRandomnessConfig::V1(_) => false,
        OnChainRandomnessConfig::V2(v2) => {
            // Validate fast_path_secrecy_threshold is properly configured
            let fast_threshold = v2.fast_path_secrecy_threshold.as_u64f64();
            let main_threshold = v2.secrecy_threshold.as_u64f64();
            fast_threshold >= main_threshold && fast_threshold <= U64F64::from_num(1)
        }
    }
}
```

**3. DKG Rounding Validation:**
Add checks in `DKGRoundingProfile::new()`:

```rust
if let Some(fast_threshold) = fast_secrecy_threshold_in_stake_ratio {
    ensure!(fast_threshold >= secrecy_threshold_in_stake_ratio,
        "fast_path_secrecy_threshold must be >= secrecy_threshold");
    ensure!(fast_threshold <= U64F64::from_num(1),
        "fast_path_secrecy_threshold must be <= 1.0");
}
```

## Proof of Concept

```rust
#[test]
fn test_misconfigured_fast_path_threshold() {
    use aptos_types::on_chain_config::OnChainRandomnessConfig;
    use fixed::types::U64F64;
    
    // Simulate governance misconfiguration: fast_path_secrecy_threshold = 5%
    // while main secrecy_threshold = 50%
    let config = OnChainRandomnessConfig::new_v2(
        50,  // secrecy_threshold: 50%
        67,  // reconstruction_threshold: 67%
        5,   // fast_path_secrecy_threshold: 5% (MISCONFIGURED - should be >= 50%)
    );
    
    // BUG: fast_randomness_enabled returns true without validation
    assert!(config.fast_randomness_enabled());
    
    // Verify the misconfiguration exists
    let fast_threshold = config.fast_path_secrecy_threshold().unwrap();
    let main_threshold = config.secrecy_threshold().unwrap();
    
    // VULNERABILITY: Fast path has WEAKER security than main path
    assert!(fast_threshold < main_threshold); // 5% < 50%
    
    // This configuration would allow a 6% validator coalition to reconstruct
    // randomness via fast path, violating the 50% security requirement
    println!("EXPLOIT: Fast path threshold ({}) is lower than main threshold ({})",
             fast_threshold, main_threshold);
    println!("Coalition with >{}% stake can leak randomness secrets!", 
             (fast_threshold * U64F64::from_num(100)).to_num::<u64>());
}
```

**Expected behavior**: Configuration creation should fail with validation error when `fast_path_secrecy_threshold < secrecy_threshold`.

**Actual behavior**: Configuration is accepted, enabling insecure fast path reconstruction.

## Notes

This vulnerability demonstrates a defense-in-depth failure where critical cryptographic parameters lack validation despite documented security invariants. While governance is trusted, secure system design requires validating all inputs to prevent accidents, bugs, and misconfigurations from compromising security. The absence of validation violates the principle that systems should fail safely and reject invalid states at the earliest possible point.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/configs/randomness_config.move (L40-41)
```text
        /// Any validator subset should not be able to reconstruct randomness via the fast path if `subset_power / total_power <= fast_path_secrecy_threshold`,
        fast_path_secrecy_threshold: FixedPoint64,
```

**File:** aptos-move/framework/aptos-framework/sources/configs/randomness_config.move (L103-115)
```text
    public fun new_v2(
        secrecy_threshold: FixedPoint64,
        reconstruction_threshold: FixedPoint64,
        fast_path_secrecy_threshold: FixedPoint64,
    ): RandomnessConfig {
        RandomnessConfig {
            variant: copyable_any::pack( ConfigV2 {
                secrecy_threshold,
                reconstruction_threshold,
                fast_path_secrecy_threshold,
            } )
        }
    }
```

**File:** types/src/on_chain_config/randomness_config.rs (L213-219)
```rust
    pub fn fast_randomness_enabled(&self) -> bool {
        match self {
            OnChainRandomnessConfig::Off => false,
            OnChainRandomnessConfig::V1(_) => false,
            OnChainRandomnessConfig::V2(_) => true,
        }
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

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L335-351)
```rust
    let (fast_reconstruct_threshold_in_stake_ratio, fast_reconstruct_threshold_in_weights) =
        if let Some(fast_secrecy_threshold_in_stake_ratio) =
            maybe_fast_secrecy_threshold_in_stake_ratio
        {
            let recon_threshold = fast_secrecy_threshold_in_stake_ratio + stake_gap_fixed;
            let recon_weight = min(
                weight_total,
                ((fast_secrecy_threshold_in_stake_ratio * stake_sum_fixed / stake_per_weight
                    + delta_up_fixed)
                    .ceil()
                    + one)
                    .to_num::<u64>(),
            );
            (Some(recon_threshold), Some(recon_weight))
        } else {
            (None, None)
        };
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

**File:** aptos-move/aptos-release-builder/src/components/randomness_config.rs (L99-126)
```rust
                ReleaseFriendlyRandomnessConfig::V2 {
                    secrecy_threshold_in_percentage,
                    reconstruct_threshold_in_percentage,
                    fast_path_secrecy_threshold_in_percentage,
                } => {
                    emitln!(writer, "let v2 = randomness_config::new_v2(");
                    emitln!(
                        writer,
                        "    fixed_point64::create_from_rational({}, 100),",
                        secrecy_threshold_in_percentage
                    );
                    emitln!(
                        writer,
                        "    fixed_point64::create_from_rational({}, 100),",
                        reconstruct_threshold_in_percentage
                    );
                    emitln!(
                        writer,
                        "    fixed_point64::create_from_rational({}, 100),",
                        fast_path_secrecy_threshold_in_percentage
                    );
                    emitln!(writer, ");");
                    emitln!(
                        writer,
                        "randomness_config::set_for_next_epoch({}, v2);",
                        signer_arg
                    );
                },
```

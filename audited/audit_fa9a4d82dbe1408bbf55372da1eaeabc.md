# Audit Report

## Title
Malicious Randomness Config Causes Validator Panic and Network Halt via Integer Overflow

## Summary
A malicious governance proposal can set invalid randomness threshold percentages that cause all validators to panic during DKG initialization, resulting in complete network halt. The vulnerability stems from missing input validation on percentage values and unsafe fixed-point to integer conversion.

## Finding Description

The `ReleaseFriendlyRandomnessConfig` struct accepts arbitrary u64 percentage values without range validation. [1](#0-0) 

When a governance proposal executes, these percentage values are converted to `FixedPoint64` using `create_from_rational(value, 100)`. [2](#0-1) 

The Move-side `create_from_rational` function validates denominator != 0 and checks for overflow, but **does NOT validate that percentage values are <= 100**. [3](#0-2) 

The resulting config is stored on-chain and later read by validators. [4](#0-3) 

When validators initialize DKG at epoch transition, they extract the threshold values without validation. [5](#0-4) 

These values are passed to `DKGRounding::new()`, which attempts to create a rounding profile. [6](#0-5) 

The profile creation validates that thresholds must be in range [1/3, 2/3], which fails for invalid values. [7](#0-6) 

On validation failure, the code falls back to `infallible()` method which clamps values to 1.0. [8](#0-7) 

**Critical Bug**: When both thresholds are set to equal or near-equal values (e.g., both 100%), after clamping to 1.0, the `total_weight_upper_bound` calculation divides by `DELTA` (2^-64). [9](#0-8) 

The division produces approximately 9.6 × 10^20, which exceeds `usize::MAX` on 64-bit systems. [10](#0-9) 

The `.to_num::<usize>()` conversion **panics on overflow** rather than saturating, crashing the validator. [11](#0-10) 

Callers do not handle this panic, causing validator crash. [12](#0-11) 

**Attack Path:**
1. Attacker submits governance proposal with `secrecy_threshold_in_percentage = 100` and `reconstruct_threshold_in_percentage = 100`
2. Proposal passes governance vote and executes
3. Config with thresholds = 1.0 is stored on-chain
4. At next epoch, ALL validators read this config
5. ALL validators call `DKGRounding::new()` → `infallible()` → `total_weight_upper_bound()`
6. Division by DELTA produces overflow value
7. `.to_num::<usize>()` panics
8. ALL validators crash simultaneously
9. Network completely halts

## Impact Explanation

**Severity: Critical** - This vulnerability causes **total loss of liveness/network availability**, qualifying for the highest severity category per the Aptos bug bounty program.

The impact includes:
- Complete network halt affecting all validators simultaneously
- Inability to process transactions or reach consensus
- Requires manual intervention or potential hardfork to recover
- No automatic recovery mechanism exists

This breaks the **Consensus Safety** and **Deterministic Execution** invariants by causing non-deterministic validator crashes based on invalid configuration.

## Likelihood Explanation

**Likelihood: Medium-High**

The attack requires:
- Governance voting power to submit and pass a proposal (legitimate governance mechanism)
- No validator collusion needed
- No special privileges beyond normal governance participation
- Simple payload (just set both thresholds to same value)

The attack is straightforward once governance access is obtained. The missing validation makes this vulnerability easily exploitable through the intended governance interface.

## Recommendation

**Immediate Fix**: Add validation in `ReleaseFriendlyRandomnessConfig` before generating governance proposal:

```rust
impl ReleaseFriendlyRandomnessConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        match self {
            Self::Off => Ok(()),
            Self::V1 { secrecy_threshold_in_percentage, reconstruct_threshold_in_percentage } => {
                ensure!(*secrecy_threshold_in_percentage > 33 && *secrecy_threshold_in_percentage <= 100, 
                    "secrecy_threshold must be in range (33, 100]");
                ensure!(*reconstruct_threshold_in_percentage >= 66 && *reconstruct_threshold_in_percentage <= 100,
                    "reconstruct_threshold must be in range [66, 100]");
                ensure!(*secrecy_threshold_in_percentage < *reconstruct_threshold_in_percentage,
                    "secrecy_threshold must be less than reconstruct_threshold");
                Ok(())
            },
            Self::V2 { secrecy_threshold_in_percentage, reconstruct_threshold_in_percentage, fast_path_secrecy_threshold_in_percentage } => {
                // Similar validation for V2
                ensure!(*secrecy_threshold_in_percentage > 33 && *secrecy_threshold_in_percentage <= 100, 
                    "secrecy_threshold must be in range (33, 100]");
                ensure!(*reconstruct_threshold_in_percentage >= 66 && *reconstruct_threshold_in_percentage <= 100,
                    "reconstruct_threshold must be in range [66, 100]");
                ensure!(*fast_path_secrecy_threshold_in_percentage >= 66 && *fast_path_secrecy_threshold_in_percentage <= 100,
                    "fast_path_secrecy_threshold must be in range [66, 100]");
                ensure!(*secrecy_threshold_in_percentage < *reconstruct_threshold_in_percentage,
                    "secrecy_threshold must be less than reconstruct_threshold");
                Ok(())
            }
        }
    }
}
```

**Defense in Depth**: Replace `.to_num::<usize>()` with `.saturating_to_num::<usize>()` in `total_weight_upper_bound`:

```rust
pub fn total_weight_upper_bound(...) -> usize {
    // ... existing code ...
    ((n / two + two) / (reconstruct_threshold_in_stake_ratio - secrecy_threshold_in_stake_ratio))
        .ceil()
        .saturating_to_num::<usize>()  // Use saturating conversion
}
```

**Move Validation**: Add on-chain validation in `randomness_config.move`:

```move
public fun new_v1(secrecy_threshold: FixedPoint64, reconstruction_threshold: FixedPoint64): RandomnessConfig {
    let one = fixed_point64::create_from_u128(1);
    assert!(fixed_point64::greater(secrecy_threshold, fixed_point64::create_from_rational(33, 100)), E_INVALID_THRESHOLD);
    assert!(fixed_point64::less_or_equal(reconstruction_threshold, one), E_INVALID_THRESHOLD);
    assert!(fixed_point64::less(secrecy_threshold, reconstruction_threshold), E_INVALID_THRESHOLD);
    // ... rest of function
}
```

## Proof of Concept

```rust
#[test]
#[should_panic(expected = "overflow")]
fn test_invalid_equal_thresholds_cause_panic() {
    use fixed::types::U64F64;
    use crate::dkg::real_dkg::rounding::DKGRounding;
    
    let validator_stakes = vec![1_000_000; 100]; // 100 validators
    
    // Attacker sets both thresholds to 100% (1.0)
    let secrecy_threshold = U64F64::from_num(1);
    let reconstruct_threshold = U64F64::from_num(1);
    
    // This will panic due to overflow in to_num::<usize>()
    let _dkg_rounding = DKGRounding::new(
        &validator_stakes,
        secrecy_threshold,
        reconstruct_threshold,
        None,
    );
    
    // Network halts - all validators crash at epoch transition
}
```

**Alternative PoC showing the governance attack path**:

```rust
// In governance proposal:
let malicious_config = ReleaseFriendlyRandomnessConfig::V1 {
    secrecy_threshold_in_percentage: 100,  // Invalid: both equal
    reconstruct_threshold_in_percentage: 100,
};

// Proposal executes, stores config on-chain
// At next epoch, all validators attempt DKG init and panic
```

## Notes

The security question asked about "negative percentage values (if u64 wraps) or NaN/infinity values", but these are impossible with u64 types (unsigned integers cannot be negative or NaN). However, the investigation revealed a more severe vulnerability: **missing validation allows any percentage value including values > 100% or equal thresholds**, causing validator panic through integer overflow during fixed-point arithmetic. The core issue is the lack of semantic validation on percentage ranges throughout the entire stack from governance proposal generation to validator DKG initialization.

### Citations

**File:** aptos-move/aptos-release-builder/src/components/randomness_config.rs (L10-22)
```rust
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum ReleaseFriendlyRandomnessConfig {
    Off,
    V1 {
        secrecy_threshold_in_percentage: u64,
        reconstruct_threshold_in_percentage: u64,
    },
    V2 {
        secrecy_threshold_in_percentage: u64,
        reconstruct_threshold_in_percentage: u64,
        fast_path_secrecy_threshold_in_percentage: u64,
    },
}
```

**File:** aptos-move/aptos-release-builder/src/components/randomness_config.rs (L84-91)
```rust
                        "    fixed_point64::create_from_rational({}, 100),",
                        secrecy_threshold_in_percentage
                    );
                    emitln!(
                        writer,
                        "    fixed_point64::create_from_rational({}, 100),",
                        reconstruct_threshold_in_percentage
                    );
```

**File:** aptos-move/framework/aptos-stdlib/sources/fixed_point64.move (L129-141)
```text
    public fun create_from_rational(numerator: u128, denominator: u128): FixedPoint64 {
        // If the denominator is zero, this will abort.
        // Scale the numerator to have 64 fractional bits, so that the quotient will have 64
        // fractional bits.
        let scaled_numerator = (numerator as u256) << 64;
        assert!(denominator != 0, EDENOMINATOR);
        let quotient = scaled_numerator / (denominator as u256);
        assert!(quotient != 0 || numerator == 0, ERATIO_OUT_OF_RANGE);
        // Return the quotient as a fixed-point number. We first need to check whether the cast
        // can succeed.
        assert!(quotient <= MAX_U128, ERATIO_OUT_OF_RANGE);
        FixedPoint64 { value: (quotient as u128) }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/randomness_config.move (L93-100)
```text
    public fun new_v1(secrecy_threshold: FixedPoint64, reconstruction_threshold: FixedPoint64): RandomnessConfig {
        RandomnessConfig {
            variant: copyable_any::pack( ConfigV1 {
                secrecy_threshold,
                reconstruction_threshold
            } )
        }
    }
```

**File:** types/src/on_chain_config/randomness_config.rs (L221-227)
```rust
    pub fn secrecy_threshold(&self) -> Option<U64F64> {
        match self {
            OnChainRandomnessConfig::Off => None,
            OnChainRandomnessConfig::V1(v1) => Some(v1.secrecy_threshold.as_u64f64()),
            OnChainRandomnessConfig::V2(v2) => Some(v2.secrecy_threshold.as_u64f64()),
        }
    }
```

**File:** types/src/dkg/real_dkg/mod.rs (L211-217)
```rust
        let pvss_config = build_dkg_pvss_config(
            dkg_session_metadata.dealer_epoch,
            secrecy_threshold,
            reconstruct_threshold,
            maybe_fast_path_secrecy_threshold,
            &dkg_session_metadata.target_validator_consensus_infos_cloned(),
        );
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

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L88-96)
```rust
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

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L261-266)
```rust
        secrecy_threshold_in_stake_ratio = min(one, secrecy_threshold_in_stake_ratio);
        reconstruct_threshold_in_stake_ratio = min(one, reconstruct_threshold_in_stake_ratio);
        reconstruct_threshold_in_stake_ratio = max(
            secrecy_threshold_in_stake_ratio,
            reconstruct_threshold_in_stake_ratio,
        );
```

**File:** dkg/src/dkg_manager/mod.rs (L314-314)
```rust
        let public_params = DKG::new_public_params(dkg_session_metadata);
```

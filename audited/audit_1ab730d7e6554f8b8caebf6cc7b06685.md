# Audit Report

## Title
Insufficient Threshold Validation in WeightedConfig Enables Censorship Attacks on Consensus Randomness via Governance Misconfiguration

## Summary
The weighted threshold secret sharing configuration in `weighted_config.rs` accepts `threshold_weight == total_weight` without validation, creating a degenerate case where ALL validators must participate for randomness reconstruction. When combined with governance-controlled threshold parameters lacking proper bounds checking, this enables a single Byzantine validator to censor consensus randomness generation, violating BFT liveness guarantees.

## Finding Description

The vulnerability exists across multiple layers of the randomness configuration system:

**Layer 1: Missing Validation in Core Threshold Logic**

The `ThresholdConfigBlstrs::new()` function only rejects cases where `t > n`, but explicitly allows `t == n`: [1](#0-0) 

This creates a degenerate threshold configuration where all shares are required for reconstruction.

**Layer 2: Unsafe Fallback in Rounding Logic**

The DKG rounding system attempts to validate reconstruction thresholds at ≤ 2/3: [2](#0-1) 

However, when validation fails (e.g., if governance sets reconstruction_threshold > 2/3), the system falls back to an `infallible()` method that caps thresholds at 1.0 but still proceeds: [3](#0-2) 

The `infallible()` method caps thresholds but doesn't prevent unsafe configurations: [4](#0-3) 

**Layer 3: Threshold Capping Creates Degenerate Case**

In `compute_profile_fixed_point()`, the calculated `reconstruct_threshold_in_weights` is capped to `weight_total`: [5](#0-4) 

With high secrecy thresholds (approaching 1.0), this capping causes `reconstruct_threshold_in_weights == weight_total`, creating the degenerate case.

**Layer 4: No Governance Parameter Validation**

The on-chain `RandomnessConfig` accepts arbitrary threshold values without validation: [6](#0-5) 

There are no bounds checks preventing governance from setting `reconstruction_threshold` to unsafe values (e.g., 99% or 100%).

**Layer 5: Censorship Attack Vector**

During consensus randomness generation, the `ShareAggregator` checks if collected weight meets the threshold: [7](#0-6) 

If `threshold == total_weight`, ALL validators must contribute. A single Byzantine validator refusing to share causes `total_weight < threshold`, permanently blocking randomness generation.

**Attack Flow:**
1. Governance sets `reconstruction_threshold` > 2/3 (misconfiguration or malicious proposal)
2. DKG rounding validation at line 199 fails
3. System falls back to `infallible()` which caps at 1.0 but proceeds
4. `compute_profile_fixed_point()` calculates high threshold, capped to `weight_total`
5. `WeightedConfigBlstrs::new()` accepts `threshold_weight == weight_total`
6. During consensus, single Byzantine validator withholds shares
7. Randomness aggregation permanently blocked (`total_weight < threshold`)
8. All features depending on on-chain randomness become unavailable

## Impact Explanation

**Severity: HIGH** (per Aptos Bug Bounty - "Significant protocol violations")

This vulnerability causes **liveness failure** of the consensus randomness beacon:

1. **BFT Invariant Violation**: The system should tolerate < 1/3 Byzantine validators, but here a single Byzantine validator (potentially << 1/3) can cause permanent liveness failure of randomness generation

2. **Consensus Impact**: While this doesn't directly affect block production, the consensus randomness beacon is a critical component for:
   - Leader election fairness
   - Validator set rotation
   - On-chain randomness APIs used by applications

3. **No Self-Recovery**: Once the degenerate threshold is set, every randomness generation attempt requires 100% participation. The system cannot recover without governance intervention to fix the configuration

4. **Scope**: Affects all validators in the network for the entire epoch duration

While not reaching Critical severity (no fund loss, no safety violation), this represents a significant protocol violation enabling denial-of-service on a core consensus subsystem.

## Likelihood Explanation

**Likelihood: MEDIUM**

**Factors Increasing Likelihood:**
- Governance parameter setting lacks validation - any proposal can set unsafe values
- No warning or error when falling back to `infallible()` path
- The validation exists (line 199) but is silently bypassed
- Default thresholds (2/3) are safe, but governance can change them

**Factors Decreasing Likelihood:**
- Requires governance action (trusted role)
- Default configuration is safe
- Would likely be noticed during testing before deployment
- Governance proposals are typically reviewed by community

However, this is a **fail-safe failure** - the defensive validation intended to prevent this vulnerability is defeated by the fallback logic. The developers clearly understood the risk (evident from line 199 validation), but the implementation allows the unsafe case to occur.

**Exploitation Complexity:**
Once the misconfiguration exists, exploitation is trivial - any validator can simply refuse to contribute randomness shares.

## Recommendation

Implement defense-in-depth validation at multiple layers:

**1. Add validation in `ThresholdConfigBlstrs::new()` to enforce strict inequality:**

```rust
// In crates/aptos-crypto/src/blstrs/threshold_config.rs
pub fn new(t: usize, n: usize) -> anyhow::Result<Self> {
    if t == 0 {
        return Err(anyhow!("expected the reconstruction threshold to be > 0"));
    }

    if n == 0 {
        return Err(anyhow!("expected the number of shares to be > 0"));
    }

    // CRITICAL: Prevent degenerate case where all shares are required
    if t >= n {
        return Err(anyhow!(
            "expected the reconstruction threshold {t} to be strictly < the number of shares {n} to ensure Byzantine tolerance"
        ));
    }

    // ... rest of implementation
}
```

**2. Make `DKGRounding::new()` fail instead of falling back to unsafe configuration:**

```rust
// In types/src/dkg/real_dkg/rounding/mod.rs
pub fn new(
    validator_stakes: &Vec<u64>,
    secrecy_threshold: U64F64,
    mut reconstruct_threshold: U64F64,
    fast_secrecy_threshold_in_stake_ratio: Option<U64F64>,
) -> Self {
    // Enforce maximum reconstruction threshold
    const MAX_RECONSTRUCT_THRESHOLD: U64F64 = U64F64::from_bits(0xAAAAAAAAAAAAAAAA); // ~2/3
    
    reconstruct_threshold = max(
        reconstruct_threshold,
        secrecy_threshold + U64F64::DELTA,
    );

    if reconstruct_threshold > MAX_RECONSTRUCT_THRESHOLD {
        return Err(anyhow!(
            "Reconstruction threshold {} exceeds maximum safe value {:.4} to ensure Byzantine tolerance",
            reconstruct_threshold,
            MAX_RECONSTRUCT_THRESHOLD
        ));
    }

    // ... proceed with normal path only
}
```

**3. Add validation in Move governance code:**

```move
// In aptos-move/framework/aptos-framework/sources/configs/randomness_config.move
const ERECONSTRUCTION_THRESHOLD_TOO_HIGH: u64 = 2;
const MAX_RECONSTRUCTION_THRESHOLD_NUMERATOR: u64 = 2;
const MAX_RECONSTRUCTION_THRESHOLD_DENOMINATOR: u64 = 3;

public fun new_v1(
    secrecy_threshold: FixedPoint64, 
    reconstruction_threshold: FixedPoint64
): RandomnessConfig {
    // Validate reconstruction threshold is <= 2/3 for Byzantine tolerance
    let max_threshold = fixed_point64::create_from_rational(
        MAX_RECONSTRUCTION_THRESHOLD_NUMERATOR,
        MAX_RECONSTRUCTION_THRESHOLD_DENOMINATOR
    );
    assert!(
        fixed_point64::less_or_equal(reconstruction_threshold, max_threshold),
        ERECONSTRUCTION_THRESHOLD_TOO_HIGH
    );
    
    // ... rest of implementation
}
```

**4. Add explicit check to prevent threshold == total_weight:**

```rust
// In types/src/dkg/real_dkg/rounding/mod.rs compute_profile_fixed_point()
let reconstruct_threshold_in_weights: u64 = min(
    weight_total - 1,  // CRITICAL: Always leave margin for Byzantine tolerance
    reconstruct_threshold_in_weights_fixed.to_num::<u64>(),
);

// Validate result maintains Byzantine tolerance
ensure!(
    reconstruct_threshold_in_weights < weight_total,
    "Reconstruction threshold must be strictly less than total weight for Byzantine tolerance"
);
```

## Proof of Concept

```rust
// Test demonstrating the vulnerability
// Add to types/src/dkg/real_dkg/rounding/tests.rs

#[test]
fn test_unsafe_threshold_enables_censorship() {
    use fixed::types::U64F64;
    
    // Simulate governance setting very high threshold
    let validator_stakes = vec![100u64, 100, 100, 100]; // 4 validators, equal weight
    let secrecy_threshold = U64F64::from_num(0.99); // 99%
    let reconstruct_threshold = U64F64::from_num(1.0); // 100%
    
    // This should fail validation but falls back to infallible()
    let rounding = DKGRounding::new(
        &validator_stakes,
        secrecy_threshold,
        reconstruct_threshold,
        None,
    );
    
    println!("Rounding result: {:?}", rounding);
    
    let wconfig = &rounding.wconfig;
    let total_weight = wconfig.get_total_weight();
    let threshold_weight = wconfig.get_threshold_weight();
    
    // VULNERABILITY: threshold equals total weight
    assert_eq!(
        threshold_weight, 
        total_weight,
        "Degenerate case: threshold == total_weight, requires ALL validators"
    );
    
    // Demonstrate censorship: if any single validator is missing
    // (simulating Byzantine behavior), we cannot reach threshold
    let byzantine_validator_weight = wconfig.get_player_weight(&Player { id: 0 });
    let honest_validators_weight = total_weight - byzantine_validator_weight;
    
    assert!(
        honest_validators_weight < threshold_weight,
        "CENSORSHIP: {} honest validators have weight {}, but threshold is {}. Single Byzantine validator can block randomness!",
        validator_stakes.len() - 1,
        honest_validators_weight,
        threshold_weight
    );
}

#[test]
fn test_safe_threshold_prevents_censorship() {
    use fixed::types::U64F64;
    
    // Properly configured thresholds
    let validator_stakes = vec![100u64, 100, 100, 100];
    let secrecy_threshold = U64F64::from_num(0.5); // 50%
    let reconstruct_threshold = U64F64::from_num(0.67); // 67% (2/3)
    
    let rounding = DKGRounding::new(
        &validator_stakes,
        secrecy_threshold,
        reconstruct_threshold,
        None,
    );
    
    let wconfig = &rounding.wconfig;
    let total_weight = wconfig.get_total_weight();
    let threshold_weight = wconfig.get_threshold_weight();
    
    // SAFE: threshold is strictly less than total weight
    assert!(
        threshold_weight < total_weight,
        "Safe configuration: threshold {} < total_weight {}",
        threshold_weight,
        total_weight
    );
    
    // Even if one validator is Byzantine, others can still reconstruct
    let byzantine_validator_weight = wconfig.get_player_weight(&Player { id: 0 });
    let honest_validators_weight = total_weight - byzantine_validator_weight;
    
    assert!(
        honest_validators_weight >= threshold_weight,
        "Byzantine tolerance: {} honest validators have sufficient weight {} >= threshold {}",
        validator_stakes.len() - 1,
        honest_validators_weight,
        threshold_weight
    );
}
```

## Notes

This vulnerability demonstrates a critical principle in distributed systems: **defensive programming must validate inputs even from trusted sources**. While governance is a trusted role, the system should enforce Byzantine fault tolerance invariants as hard constraints that cannot be violated even by configuration mistakes.

The code shows evidence that developers understood this risk (validation at line 199), but the fallback `infallible()` path defeats the intended protection. This is a classic "fail-open" vulnerability where error handling creates an unsafe state rather than failing closed.

The fix requires defense-in-depth validation at all layers: Move governance code, Rust rounding logic, and core threshold configuration.

### Citations

**File:** crates/aptos-crypto/src/blstrs/threshold_config.rs (L118-122)
```rust
        if t > n {
            return Err(anyhow!(
                "expected the reconstruction threshold {t} to be < than the number of shares {n}"
            ));
        }
```

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L89-96)
```rust
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

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L260-266)
```rust
        let one = U64F64::from_num(1);
        secrecy_threshold_in_stake_ratio = min(one, secrecy_threshold_in_stake_ratio);
        reconstruct_threshold_in_stake_ratio = min(one, reconstruct_threshold_in_stake_ratio);
        reconstruct_threshold_in_stake_ratio = max(
            secrecy_threshold_in_stake_ratio,
            reconstruct_threshold_in_stake_ratio,
        );
```

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L324-331)
```rust
    let reconstruct_threshold_in_weights_fixed =
        (secrecy_threshold_in_stake_ratio * stake_sum_fixed / stake_per_weight + delta_up_fixed)
            .ceil()
            + one;
    let reconstruct_threshold_in_weights: u64 = min(
        weight_total,
        reconstruct_threshold_in_weights_fixed.to_num::<u64>(),
    );
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

**File:** consensus/src/rand/rand_gen/rand_store.rs (L47-49)
```rust
        if self.total_weight < rand_config.threshold() {
            return Either::Left(self);
        }
```

# Audit Report

## Title
Division-by-Zero Panic in DKG Initialization with Empty Validator Sets

## Summary
The DKG (Distributed Key Generation) runtime initialization code in `types/src/dkg/real_dkg/rounding/mod.rs` contains a critical divide-by-zero vulnerability that causes validator nodes to panic when processing a DKG start event with an empty validator set. This can result in complete network halt requiring manual intervention.

## Finding Description

The vulnerability exists in the DKG weight rounding algorithm which is called during epoch transitions when randomness is enabled. The attack surface spans multiple components:

**Move Layer (Validator Set Management):**
The `on_new_epoch()` function in stake.move filters validators based on minimum stake requirements without ensuring at least one validator remains active. [1](#0-0) 

If all validators drop below `minimum_stake`, the `next_epoch_validators` vector becomes empty and replaces `active_validators`.

**Move Layer (DKG Initialization):**
The `dkg::start()` function accepts validator sets without validating they are non-empty: [2](#0-1) 

**Move Layer (Reconfiguration):**
The reconfiguration code calls DKG with potentially empty validator sets: [3](#0-2) 

**Rust Layer (DKG Weight Calculation):**
When validator nodes process the `DKGStartEvent`, the code path leads to `DKGRounding::new()` which calculates weight bounds. With an empty validator set: [4](#0-3) 

This returns 0 for empty validator sets. Subsequently, in `DKGRoundingProfile::new()`, division by zero occurs: [5](#0-4) 

When `weight_low` is 0, line 208 performs division by zero, causing a Rust panic.

Additional division-by-zero paths exist in:
- `DKGRoundingProfile::infallible()` at line 275
- `compute_profile_fixed_point()` at lines 311, 325, 332

This breaks the **Consensus Safety** and **Deterministic Execution** invariants, as validator nodes crash instead of gracefully handling the edge case.

## Impact Explanation

**Severity: High (up to $50,000)**

This qualifies as **High Severity** per the Aptos bug bounty program because it causes:

1. **Validator node crashes**: All validators attempting to process the DKG start event will panic and crash
2. **Network liveness failure**: The blockchain cannot progress to the next epoch since DKG cannot complete
3. **Requires manual intervention**: Recovery would require governance action, configuration changes, or emergency patches

While the impact is severe (complete network halt), this does not reach **Critical Severity** because:
- No funds are at risk (no theft or permanent freezing)
- No consensus safety violation occurs (no double-spend or chain split)
- The network can theoretically recover through manual intervention without requiring a hard fork

## Likelihood Explanation

**Likelihood: Very Low to Low**

The vulnerability requires specific preconditions that are unlikely in production but possible in edge cases:

**Unlikely in Production:**
- Production networks have multiple validators with substantial stake
- The `ELAST_VALIDATOR` check prevents explicit removal of the last validator
- Validators are economically incentivized to maintain minimum stake

**Possible Scenarios:**
1. **Single-validator test networks**: Legitimate for development/testing, where the single validator drops below minimum_stake
2. **Governance attack**: A malicious proposal increases `minimum_stake` above all validators' current stakes
3. **Staking system bug**: A separate vulnerability causes mass stake loss
4. **Coordinated withdrawal**: Requires collusion of all validators (insider threat)
5. **Bootstrap/genesis edge cases**: Network initialization with misconfigured parameters

The likelihood is higher for test networks and development environments than production mainnet.

## Recommendation

**Immediate Fix:**

Add validation in the Move layer to prevent empty validator sets from triggering DKG:

```move
// In aptos-move/framework/aptos-framework/sources/dkg.move
public(friend) fun start(
    dealer_epoch: u64,
    randomness_config: RandomnessConfig,
    dealer_validator_set: vector<ValidatorConsensusInfo>,
    target_validator_set: vector<ValidatorConsensusInfo>,
) acquires DKGState {
    // Add validation
    assert!(!vector::is_empty(&dealer_validator_set), error::invalid_argument(EEMPTY_VALIDATOR_SET));
    assert!(!vector::is_empty(&target_validator_set), error::invalid_argument(EEMPTY_VALIDATOR_SET));
    
    // ... existing code
}
```

**Defensive Programming in Rust:**

Add validation in the Rust layer as defense-in-depth:

```rust
// In types/src/dkg/real_dkg/mod.rs, RealDKG::new_public_params()
fn new_public_params(dkg_session_metadata: &DKGSessionMetadata) -> RealDKGPublicParams {
    let target_validators = dkg_session_metadata.target_validator_consensus_infos_cloned();
    
    // Add validation
    ensure!(
        !target_validators.is_empty(),
        "DKG requires at least one target validator"
    );
    
    // ... existing code
}
```

**Additional Safeguard in stake.move:**

```move
// In aptos-move/framework/aptos-framework/sources/stake.move
// After line 1401 in on_new_epoch()
assert!(
    !vector::is_empty(&validator_set.active_validators),
    error::invalid_state(EEMPTY_VALIDATOR_SET)
);
```

## Proof of Concept

**Rust Unit Test:**

```rust
#[test]
#[should_panic(expected = "attempt to divide by zero")]
fn test_dkg_rounding_empty_validator_set() {
    use fixed::types::U64F64;
    
    let empty_validator_stakes: Vec<u64> = vec![];
    let secrecy_threshold = U64F64::from_num(1) / U64F64::from_num(2);
    let reconstruct_threshold = U64F64::from_num(2) / U64F64::from_num(3);
    
    // This will panic with division by zero
    let _rounding = DKGRounding::new(
        &empty_validator_stakes,
        secrecy_threshold,
        reconstruct_threshold,
        None,
    );
}
```

**Move Integration Test:**

```move
#[test(framework = @aptos_framework)]
#[expected_failure(abort_code = EEMPTY_VALIDATOR_SET)]
fun test_dkg_start_with_empty_validator_set(framework: &signer) {
    // Initialize DKG state
    dkg::initialize(framework);
    
    // Attempt to start DKG with empty validator sets
    dkg::start(
        1, // epoch
        randomness_config::default(),
        vector::empty(), // empty dealer set
        vector::empty(), // empty target set
    );
}
```

## Notes

This vulnerability demonstrates a defensive programming weakness where edge cases in validator set management are not properly validated before propagating to lower-level cryptographic operations. While the scenario is unlikely in production mainnet, it represents a legitimate concern for:

- Development and test networks
- Bootstrap scenarios
- Governance-based configuration changes

The fix should be implemented at multiple layers (Move validation + Rust defensive checks) to ensure robustness across all deployment scenarios.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1372-1401)
```text
        let next_epoch_validators = vector::empty();
        let (minimum_stake, _) = staking_config::get_required_stake(&config);
        let vlen = vector::length(&validator_set.active_validators);
        let total_voting_power = 0;
        let i = 0;
        while ({
            spec {
                invariant spec_validators_are_initialized(next_epoch_validators);
                invariant i <= vlen;
            };
            i < vlen
        }) {
            let old_validator_info = vector::borrow_mut(&mut validator_set.active_validators, i);
            let pool_address = old_validator_info.addr;
            let validator_config = borrow_global<ValidatorConfig>(pool_address);
            let stake_pool = borrow_global<StakePool>(pool_address);
            let new_validator_info = generate_validator_info(pool_address, stake_pool, *validator_config);

            // A validator needs at least the min stake required to join the validator set.
            if (new_validator_info.voting_power >= minimum_stake) {
                spec {
                    assume total_voting_power + new_validator_info.voting_power <= MAX_U128;
                };
                total_voting_power = total_voting_power + (new_validator_info.voting_power as u128);
                vector::push_back(&mut next_epoch_validators, new_validator_info);
            };
            i = i + 1;
        };

        validator_set.active_validators = next_epoch_validators;
```

**File:** aptos-move/framework/aptos-framework/sources/dkg.move (L61-85)
```text
    public(friend) fun start(
        dealer_epoch: u64,
        randomness_config: RandomnessConfig,
        dealer_validator_set: vector<ValidatorConsensusInfo>,
        target_validator_set: vector<ValidatorConsensusInfo>,
    ) acquires DKGState {
        let dkg_state = borrow_global_mut<DKGState>(@aptos_framework);
        let new_session_metadata = DKGSessionMetadata {
            dealer_epoch,
            randomness_config,
            dealer_validator_set,
            target_validator_set,
        };
        let start_time_us = timestamp::now_microseconds();
        dkg_state.in_progress = std::option::some(DKGSessionState {
            metadata: new_session_metadata,
            start_time_us,
            transcript: vector[],
        });

        emit(DKGStartEvent {
            start_time_us,
            session_metadata: new_session_metadata,
        });
    }
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration_with_dkg.move (L34-39)
```text
        dkg::start(
            cur_epoch,
            randomness_config::current(),
            stake::cur_validator_consensus_infos(),
            stake::next_validator_consensus_infos(),
        );
```

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L14-17)
```rust
pub fn total_weight_lower_bound(validator_stakes: &[u64]) -> usize {
    // Each validator has at least 1 weight.
    validator_stakes.len()
}
```

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L201-209)
```rust
        let stake_total: u64 = validator_stakes.iter().sum();
        let mut weight_low = total_weight_min as u64;
        let mut weight_high = total_weight_max as u64;
        let mut best_profile = compute_profile_fixed_point(
            validator_stakes,
            max(
                U64F64::from_num(1),
                U64F64::from_num(stake_total) / U64F64::from_num(weight_low),
            ),
```

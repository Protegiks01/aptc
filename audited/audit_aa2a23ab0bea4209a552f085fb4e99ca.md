# Audit Report

## Title
Missing Runtime Validation for Empty Validator Set in Epoch Transitions Masked by Proptest Code

## Summary
The proptest code in `BlockInfoGen::materialize()` always forces creation of a validator set at epoch 0, masking the absence of a critical runtime check in `stake::on_new_epoch()` that could allow the active validator set to become empty during epoch transitions when all validators are filtered out due to insufficient stake. This would cause total network liveness failure requiring manual intervention.

## Finding Description

The security question correctly identifies that the forced validator set creation at epoch 0 in test code hides potential bugs in validator set initialization. Through investigation, I discovered a more serious issue: the test code masks the **absence of runtime validation during epoch transitions** in production code.

**The Masking Issue:** [1](#0-0) 

This line forces validator set creation at epoch 0 in all property-based tests, meaning tests never exercise scenarios where the validator set is missing or becomes empty.

**The Hidden Vulnerability:**

In the production staking code, the `on_new_epoch()` function filters validators based on minimum stake requirements but lacks validation that the result is non-empty: [2](#0-1) 

At line 1401, `validator_set.active_validators` is assigned the filtered `next_epoch_validators` without checking if it's empty.

**Why This Is Problematic:**

1. **Genesis has formal verification protection**: [3](#0-2) 

2. **Voluntary leaving has runtime protection**: [4](#0-3) 

3. **But involuntary filtering (via minimum stake) has NO protection**: The `on_new_epoch` filtering lacks any assertion that `next_epoch_validators` is non-empty.

4. **Empty validator sets create dangerous state**: [5](#0-4) 

When a `ValidatorVerifier` is created from an empty set, it sets `quorum_voting_power = 0`, which could lead to signature verification issues.

**The Attack Path (Requires Preconditions):**

If all validators simultaneously drop below the minimum stake threshold (e.g., through a configuration error setting minimum stake too high, a bug in reward calculation, or coordinated malicious action), then during the next epoch transition:

1. `on_new_epoch()` filters all validators due to insufficient stake
2. `next_epoch_validators` becomes empty
3. No runtime check catches this
4. Empty validator set is committed to on-chain state
5. Network cannot produce new blocks (total liveness failure)

## Impact Explanation

This issue qualifies as **MEDIUM severity** per Aptos bug bounty criteria:

- **Category**: "State inconsistencies requiring intervention"
- **Impact**: Total loss of network liveness requiring manual intervention or hard fork
- **Affected Scope**: Entire network becomes unable to produce blocks

The formal verification at genesis provides protection for the initial state, but post-genesis epoch transitions lack equivalent runtime safeguards. The proptest code's forced validator set creation means this gap has never been tested.

## Likelihood Explanation

**Likelihood: LOW**

While the missing check represents a genuine defense-in-depth gap, exploitation requires specific preconditions that are unlikely in normal operation:

1. **Configuration Error**: Minimum stake set higher than all validators' stakes (requires developer error)
2. **Staking Bug**: A separate bug causing mass stake loss across all validators
3. **Coordinated Attack**: All validators maliciously reducing stake below minimum (requires validator collusion)

However, the fact that tests never exercise this scenario due to the forced epoch 0 validator set means that error handling and recovery procedures for this edge case have never been validated.

## Recommendation

Add a runtime assertion in `on_new_epoch()` to ensure the validator set cannot become empty:

```move
// After line 1401 in stake.move
validator_set.active_validators = next_epoch_validators;
assert!(
    vector::length(&validator_set.active_validators) > 0,
    error::invalid_state(ENO_ACTIVE_VALIDATORS)
);
```

Additionally, modify the proptest code to occasionally test with empty or minimal validator sets to ensure error handling is properly exercised:

```rust
// In proptest_types.rs, make validator set creation conditional
let next_epoch_state = if current_epoch == 0 && !self.test_empty_validators || self.new_epoch {
    // Create validator set
}
```

## Proof of Concept

```move
#[test(framework = @aptos_framework)]
#[expected_failure(abort_code = 0x60007, location = aptos_framework::stake)] // ENO_ACTIVE_VALIDATORS
fun test_empty_validator_set_on_epoch_transition(framework: &signer) {
    // Setup: Initialize genesis with validators
    timestamp::set_time_has_started_for_testing(framework);
    
    // Create validators with stake at minimum
    let minimum_stake = 100;
    staking_config::initialize_for_test(framework, minimum_stake, ...);
    
    // Setup validator that will drop below minimum
    let validator_addr = @0x123;
    stake::initialize_test_validator(validator_addr, ...);
    
    // Simulate: Increase minimum stake above all validators
    staking_config::update_required_stake(framework, 1000);
    
    // Trigger: Call on_new_epoch - should abort with ENO_ACTIVE_VALIDATORS
    // but currently does not have this check
    stake::on_new_epoch();
    
    // Expected: Should abort before creating empty validator set
    // Actual: Currently allows empty validator set to be created
}
```

## Notes

This finding demonstrates how test code patterns can mask missing production safeguards. While the formal verification ensures genesis correctness, runtime checks are equally important for ongoing operation. The proptest's forced validator set creation at epoch 0 prevents discovery of this gap through property-based testing.

The vulnerability requires specific preconditions unlikely in normal operation, but represents a significant defense-in-depth issue that should be addressed. The lack of testing for this scenario due to the proptest masking means that recovery procedures and error handling have never been validated.

### Citations

**File:** types/src/proptest_types.rs (L1159-1159)
```rust
        let next_epoch_state = if current_epoch == 0 || self.new_epoch {
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1255-1255)
```text
            assert!(vector::length(&validator_set.active_validators) > 0, error::invalid_state(ELAST_VALIDATOR));
```

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

**File:** aptos-move/framework/aptos-framework/sources/genesis.spec.move (L150-150)
```text
        requires len(global<stake::ValidatorSet>(@aptos_framework).active_validators) >= 1;
```

**File:** types/src/validator_verifier.rs (L208-212)
```rust
        let quorum_voting_power = if validator_infos.is_empty() {
            0
        } else {
            total_voting_power * 2 / 3 + 1
        };
```

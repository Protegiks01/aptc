# Audit Report

## Title
Network Shutdown via Validator Set Depletion During Epoch Transition

## Summary
The `on_new_epoch()` function can result in an empty validator set if all remaining validators are filtered out due to insufficient stake, causing complete network shutdown. While `leave_validator_set()` prevents the last validator from explicitly leaving, it does not prevent the validator set from becoming empty during epoch transitions when validators fall below the minimum stake requirement.

## Finding Description

The vulnerability exists in the interaction between two functions in the staking module: [1](#0-0) 

The `leave_validator_set()` function contains a check at line 1255 that prevents removing the last validator: [2](#0-1) 

However, this check only applies during explicit leave operations. The critical vulnerability occurs in `on_new_epoch()`: [3](#0-2) 

The filtering logic at lines 1390-1397 removes validators whose voting power falls below the minimum stake requirement. Crucially, **there is no check after line 1401 to ensure that `next_epoch_validators` is not empty** before assigning it to `validator_set.active_validators`.

**Attack Scenario:**
1. Network starts with N validators (N ≥ 2)
2. N-1 validators call `leave_validator_set()` successfully (check passes since ≥1 validator remains after each removal)
3. One validator remains in `active_validators`
4. This validator's stake drops below `minimum_stake` through:
   - Natural unlock/withdraw operations, OR
   - Governance proposal increasing `minimum_stake` via staking config
5. At the next epoch boundary, `on_new_epoch()` executes
6. The filtering loop evaluates the last validator: `voting_power < minimum_stake`
7. The validator is NOT added to `next_epoch_validators`
8. `next_epoch_validators` remains empty
9. Line 1401 assigns empty vector: `validator_set.active_validators = []`
10. Network cannot produce blocks → Complete shutdown

## Impact Explanation

This is a **CRITICAL severity** vulnerability under the Aptos Bug Bounty Program, meeting the criteria for:

- **Total loss of liveness/network availability**: With zero validators, the consensus protocol cannot produce blocks, halting the entire network
- **Non-recoverable network partition (requires hardfork)**: Once `active_validators` becomes empty, the network cannot recover without manual intervention or a hardfork to restore at least one validator

The validator set is fundamental to AptosBFT consensus. An empty validator set breaks the core invariant that the network must always have validators capable of producing blocks. This violates:
- **Consensus Safety**: The network cannot achieve consensus without validators
- **Network Liveness**: Block production completely stops

## Likelihood Explanation

**Likelihood: Medium to High**

This vulnerability can occur through several realistic scenarios:

1. **Natural validator attrition + stake management**: As validators leave over time, eventually only one remains. If that validator unlocks stake for legitimate reasons and falls below the threshold, the network halts at the next epoch.

2. **Governance-driven minimum stake increase**: A governance proposal to increase network security by raising `minimum_stake` could inadvertently trigger this if the remaining validators don't have sufficient stake to meet the new threshold.

3. **Coordinated but non-malicious behavior**: Multiple validators deciding to leave simultaneously during network issues, combined with poor stake management by the remaining validator(s).

The attack doesn't require:
- Byzantine validator behavior
- Compromised validator keys
- Complex exploit chain
- Significant attacker resources

It can occur through normal network operations combined with edge case timing.

## Recommendation

Add a minimum validator count check after filtering in `on_new_epoch()`:

```move
// Line 1401 in stake.move - ADD CHECK AFTER THIS LINE
validator_set.active_validators = next_epoch_validators;

// ADD THIS CHECK:
assert!(
    vector::length(&validator_set.active_validators) > 0,
    error::invalid_state(ENO_VALIDATORS_REMAINING)
);

validator_set.total_voting_power = total_voting_power;
validator_set.total_joining_power = 0;
```

Additionally, consider:
1. **Define new error constant** at the top of the module:
   ```move
   const ENO_VALIDATORS_REMAINING: u64 = 25; // Use next available error code
   ```

2. **Add invariant in formal specification** to `stake.spec.move`:
   ```move
   spec on_new_epoch {
       // ... existing specs ...
       ensures len(global<ValidatorSet>(@aptos_framework).active_validators) > 0;
   }
   ```

3. **Prevent leaving when close to minimum**: Modify `leave_validator_set()` to check if there would be sufficient validators remaining that meet minimum stake requirements, not just checking for count > 0.

## Proof of Concept

```move
#[test(aptos_framework = @0x1, validator_1 = @0x123, validator_2 = @0x234)]
#[expected_failure(abort_code = 0x60019, location = Self)] // ENO_VALIDATORS_REMAINING
public entry fun test_empty_validator_set_via_below_minimum_stake(
    aptos_framework: &signer,
    validator_1: &signer,
    validator_2: &signer,
) acquires AllowedValidators, AptosCoinCapabilities, OwnerCapability, PendingTransactionFee, 
           StakePool, TransactionFeeConfig, ValidatorConfig, ValidatorPerformance, ValidatorSet {
    let validator_1_address = signer::address_of(validator_1);
    let validator_2_address = signer::address_of(validator_2);
    
    // Initialize with minimum stake of 100 coins
    initialize_for_test_custom(aptos_framework, 100, 10000, LOCKUP_CYCLE_SECONDS, true, 1, 100, 100);
    
    // Create two validators with exactly minimum stake
    let (_sk_1, pk_1, pop_1) = generate_identity();
    let (_sk_2, pk_2, pop_2) = generate_identity();
    initialize_test_validator(&pk_1, &pop_1, validator_1, 100, false, false);
    initialize_test_validator(&pk_2, &pop_2, validator_2, 100, false, false);
    
    // Both join validator set
    join_validator_set(validator_1, validator_1_address);
    join_validator_set(validator_2, validator_2_address);
    end_epoch();
    
    // Verify both are active
    assert!(get_validator_state(validator_1_address) == VALIDATOR_STATUS_ACTIVE, 0);
    assert!(get_validator_state(validator_2_address) == VALIDATOR_STATUS_ACTIVE, 1);
    
    // Validator 2 leaves
    leave_validator_set(validator_2, validator_2_address);
    
    // Validator 1 unlocks 50 coins, reducing stake below minimum
    unlock(validator_1, 50);
    
    // Fast forward time so unlock takes effect
    timestamp::fast_forward_seconds(LOCKUP_CYCLE_SECONDS);
    
    // This epoch transition will filter out validator_1 due to insufficient stake
    // Resulting in empty active_validators and network halt
    end_epoch(); // This should abort with ENO_VALIDATORS_REMAINING if fix is applied
}
```

This test demonstrates the vulnerability by:
1. Creating two validators with minimum stake
2. Having one validator leave
3. Having the remaining validator reduce their stake below minimum
4. Triggering `on_new_epoch()` which filters out the last validator, creating an empty validator set

**Note**: This test will currently NOT fail in the unpatched code (it will succeed but leave the network in a broken state). The `expected_failure` attribute shows what SHOULD happen with the recommended fix applied.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1213-1269)
```text
    public entry fun leave_validator_set(
        operator: &signer,
        pool_address: address
    ) acquires StakePool, ValidatorSet {
        check_stake_permission(operator);
        assert_reconfig_not_in_progress();
        let config = staking_config::get();
        assert!(
            staking_config::get_allow_validator_set_change(&config),
            error::invalid_argument(ENO_POST_GENESIS_VALIDATOR_SET_CHANGE_ALLOWED),
        );

        assert_stake_pool_exists(pool_address);
        let stake_pool = borrow_global_mut<StakePool>(pool_address);
        // Account has to be the operator.
        assert!(signer::address_of(operator) == stake_pool.operator_address, error::unauthenticated(ENOT_OPERATOR));

        let validator_set = borrow_global_mut<ValidatorSet>(@aptos_framework);
        // If the validator is still pending_active, directly kick the validator out.
        let maybe_pending_active_index = find_validator(&validator_set.pending_active, pool_address);
        if (option::is_some(&maybe_pending_active_index)) {
            vector::swap_remove(
                &mut validator_set.pending_active, option::extract(&mut maybe_pending_active_index));

            // Decrease the voting power increase as the pending validator's voting power was added when they requested
            // to join. Now that they changed their mind, their voting power should not affect the joining limit of this
            // epoch.
            let validator_stake = (get_next_epoch_voting_power(stake_pool) as u128);
            // total_joining_power should be larger than validator_stake but just in case there has been a small
            // rounding error somewhere that can lead to an underflow, we still want to allow this transaction to
            // succeed.
            if (validator_set.total_joining_power > validator_stake) {
                validator_set.total_joining_power = validator_set.total_joining_power - validator_stake;
            } else {
                validator_set.total_joining_power = 0;
            };
        } else {
            // Validate that the validator is already part of the validator set.
            let maybe_active_index = find_validator(&validator_set.active_validators, pool_address);
            assert!(option::is_some(&maybe_active_index), error::invalid_state(ENOT_VALIDATOR));
            let validator_info = vector::swap_remove(
                &mut validator_set.active_validators, option::extract(&mut maybe_active_index));
            assert!(vector::length(&validator_set.active_validators) > 0, error::invalid_state(ELAST_VALIDATOR));
            vector::push_back(&mut validator_set.pending_inactive, validator_info);

            if (std::features::module_event_migration_enabled()) {
                event::emit(LeaveValidatorSet { pool_address });
            } else {
                event::emit_event(
                    &mut stake_pool.leave_validator_set_events,
                    LeaveValidatorSetEvent {
                        pool_address,
                    },
                );
            };
        };
    }
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

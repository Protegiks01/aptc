# Audit Report

## Title
Missing Empty Validator Set Check in Epoch Reconfiguration Causes Total Network Halt

## Summary
The `on_new_epoch()` function in `stake.move` can result in an empty active validator set during epoch reconfiguration when all validators fall below the minimum stake threshold, causing total network halt as no validators can produce blocks.

## Finding Description

The Aptos blockchain maintains a critical invariant that at least one validator must always be active to produce blocks. However, the `on_new_epoch()` function that processes epoch transitions lacks a validation check to enforce this invariant.

During epoch reconfiguration, `on_new_epoch()` filters validators based on their voting power against the minimum stake requirement. If ALL validators have voting power below the `minimum_stake` threshold, the function will create an empty `active_validators` list, resulting in zero validators able to produce blocks. [1](#0-0) 

The filtering logic processes each validator and only includes those meeting the minimum stake requirement. Critically, line 1401 assigns the potentially empty `next_epoch_validators` vector directly to `validator_set.active_validators` without verification.

Notably, the codebase already recognizes this invariant in `leave_validator_set()`, which explicitly prevents manual removal of the last validator: [2](#0-1) 

However, this protection is **absent** in `on_new_epoch()`, creating an inconsistency in invariant enforcement.

**Attack Vector:**

1. Governance proposal updates `minimum_stake` via `update_required_stake()` to a value higher than all current validator voting power [3](#0-2) 

2. The validation only checks `minimum_stake <= maximum_stake`, not whether existing validators meet the new requirement [4](#0-3) 

3. Next epoch transition calls `reconfiguration::reconfigure()` which invokes `stake::on_new_epoch()` [5](#0-4) 

4. All validators filtered out, `active_validators` becomes empty, network halts

The telemetry service explicitly recognizes empty validator sets as error conditions, confirming this is a known problematic state: [6](#0-5) 

## Impact Explanation

**Severity: Critical** - Total loss of liveness/network availability

When the validator set becomes empty:
- No validator can propose blocks
- Consensus completely halts
- All transactions stop processing
- Network becomes permanently frozen until manual intervention via hardfork
- Requires coordinated recovery effort across all node operators

This meets the **Critical Severity** criteria from the Aptos bug bounty program: "Total loss of liveness/network availability" and "Non-recoverable network partition (requires hardfork)".

While the attack requires governance control, this represents a critical defensive programming failure. Even trusted governance participants can make configuration errors, and the protocol should prevent catastrophic misconfigurations.

## Likelihood Explanation

**Likelihood: Medium-High**

While this requires governance control (making it seem unlikely), several realistic scenarios exist:

1. **Accidental Misconfiguration**: Governance proposal accidentally sets `minimum_stake` too high during parameter updates
2. **Unit Error**: Proposal author confuses units (e.g., octas vs full coins) when setting stake values  
3. **Coordinated Attack**: If governance is compromised (e.g., through vote buying or validator collusion exceeding 50% stake)
4. **Natural Stake Decay**: All validators could theoretically fall below minimum through reward distribution issues or mass stake withdrawals, though the `leave_validator_set()` check provides partial protection

The lack of any safety check makes accidental triggering particularly concerning - a single typo in a governance proposal could halt the entire network.

## Recommendation

Add a validation check in `on_new_epoch()` to ensure at least one validator remains active after filtering:

```move
// After line 1401 in stake.move, add:
assert!(
    vector::length(&validator_set.active_validators) > 0,
    error::invalid_state(ELAST_VALIDATOR)
);
```

Additionally, add preventive validation in `update_required_stake()` to ensure the new minimum doesn't exceed all current validator stakes:

```move
// In staking_config.move, update_required_stake() function:
public fun update_required_stake(
    aptos_framework: &signer,
    minimum_stake: u64,
    maximum_stake: u64,
) acquires StakingConfig {
    system_addresses::assert_aptos_framework(aptos_framework);
    validate_required_stake(minimum_stake, maximum_stake);
    
    // New validation: Check against current validator stakes
    let validator_set = stake::get_validator_set();
    let has_sufficient_validator = check_at_least_one_validator_meets_stake(
        &validator_set,
        minimum_stake
    );
    assert!(
        has_sufficient_validator,
        error::invalid_argument(EWOULD_REMOVE_ALL_VALIDATORS)
    );
    
    let staking_config = borrow_global_mut<StakingConfig>(@aptos_framework);
    staking_config.minimum_stake = minimum_stake;
    staking_config.maximum_stake = maximum_stake;
}
```

## Proof of Concept

```move
#[test(aptos_framework = @aptos_framework, validator1 = @0x123, validator2 = @0x456)]
fun test_empty_validator_set_on_epoch_transition(
    aptos_framework: &signer,
    validator1: &signer,
    validator2: &signer,
) {
    // Setup: Initialize genesis with 2 validators each with 1M stake
    genesis::setup_genesis(aptos_framework, 1_000_000, 10_000_000);
    stake::initialize_test_validator(validator1, 1_000_000);
    stake::initialize_test_validator(validator2, 1_000_000);
    
    // Trigger first epoch to activate validators
    stake::on_new_epoch();
    
    // Verify we have 2 active validators
    let validator_set = stake::get_validator_set();
    assert!(vector::length(&validator_set.active_validators) == 2, 0);
    
    // Attack: Governance increases minimum_stake above all validator stakes
    staking_config::update_required_stake(
        aptos_framework,
        5_000_000,  // New minimum: 5M (all validators have only 1M)
        10_000_000
    );
    
    // Trigger epoch transition
    stake::on_new_epoch();
    
    // BUG: This should fail but doesn't - validator set is now empty!
    let validator_set = stake::get_validator_set();
    assert!(vector::length(&validator_set.active_validators) == 0, 1);
    // Network is now halted with zero validators
}
```

## Notes

This vulnerability demonstrates a critical gap in defensive programming where the protocol trusts governance parameters without validation. While governance is generally trusted, the protocol should prevent catastrophic misconfigurations that violate core invariants. The fix is straightforward and should be implemented to ensure network resilience against both accidental and malicious parameter changes.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1255-1255)
```text
            assert!(vector::length(&validator_set.active_validators) > 0, error::invalid_state(ELAST_VALIDATOR));
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1372-1402)
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
        validator_set.total_voting_power = total_voting_power;
```

**File:** aptos-move/framework/aptos-framework/sources/configs/staking_config.move (L274-285)
```text
    public fun update_required_stake(
        aptos_framework: &signer,
        minimum_stake: u64,
        maximum_stake: u64,
    ) acquires StakingConfig {
        system_addresses::assert_aptos_framework(aptos_framework);
        validate_required_stake(minimum_stake, maximum_stake);

        let staking_config = borrow_global_mut<StakingConfig>(@aptos_framework);
        staking_config.minimum_stake = minimum_stake;
        staking_config.maximum_stake = maximum_stake;
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/staking_config.move (L372-374)
```text
    fun validate_required_stake(minimum_stake: u64, maximum_stake: u64) {
        assert!(minimum_stake <= maximum_stake && maximum_stake > 0, error::invalid_argument(EINVALID_STAKE_RANGE));
    }
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration.move (L134-134)
```text
        stake::on_new_epoch();
```

**File:** crates/aptos-telemetry-service/src/validator_cache.rs (L163-171)
```rust
        let result = if !has_validators && !has_vfns {
            Err(ValidatorCacheUpdateError::BothPeerSetEmpty)
        } else if !has_validators {
            Err(ValidatorCacheUpdateError::ValidatorSetEmpty)
        } else if !has_vfns {
            Err(ValidatorCacheUpdateError::VfnSetEmpty)
        } else {
            Ok(())
        };
```

# Audit Report

## Title
Active Validators Can Manipulate total_joining_power to Block New Validator Admission via add_stake() DoS

## Summary
The `total_joining_power` field in `ValidatorSet` can be artificially inflated by active validators adding stake, independent of actual `pending_active` validators joining. This allows incumbent validators to block new validators from joining the validator set by consuming the epoch's voting power increase quota, creating a permissionless validator admission denial-of-service attack.

## Finding Description

The `total_joining_power` field is designed to track "Total voting power waiting to join in the next epoch" and enforce a governance-configured limit on validator set growth per epoch. [1](#0-0) 

However, the implementation in `add_stake_with_cap()` incorrectly increments `total_joining_power` for BOTH `active_validators` and `pending_active` validators: [2](#0-1) 

This allows active validators (who are not "joining" since they're already in the validator set) to consume the joining power quota. The `update_voting_power_increase()` function enforces the limit: [3](#0-2) 

**Attack Scenario:**
1. Network has 1000 total voting power across active validators
2. `voting_power_increase_limit` is configured at 20% (default), allowing 200 joining power per epoch
3. Malicious active validators coordinate to call `add_stake()` at epoch start, adding 200 combined stake
4. This increments `total_joining_power` to 200, hitting the limit
5. Legitimate new validators attempting `join_validator_set()` are blocked with `EVOTING_POWER_INCREASE_EXCEEDS_LIMIT`
6. The attack can be repeated each epoch to permanently exclude new entrants

The active validators don't need to keep the added stake—they can unlock it later without decrementing `total_joining_power`: [4](#0-3) 

The `unlock()` function moves stake from `active` to `pending_inactive` but never updates `total_joining_power`, allowing the quota to remain consumed.

## Impact Explanation

This vulnerability enables **validator set centralization** through admission denial-of-service. Incumbent validators can collude to maintain a closed validator set, preventing decentralization and increasing their individual rewards/voting power.

**Severity: High** - This qualifies as a "Significant protocol violation" under the Aptos bug bounty program. While it doesn't directly cause fund loss or consensus safety violations, it fundamentally breaks the permissionless validator admission mechanism that is core to blockchain decentralization and security.

The impact compounds over time:
- Reduced validator diversity increases consensus attack risk
- Economic centralization as rewards concentrate among incumbent validators  
- Network governance becomes controlled by a cartel
- Contradicts Aptos's design goal of a permissionless, decentralized validator set

## Likelihood Explanation

**Likelihood: High** - This attack is:
- **Trivial to execute**: Requires only calling `add_stake()`, a public entry function
- **Economically rational**: Incumbent validators benefit from blocking competition
- **Coordinated easily**: Only requires temporary stake additions that can be unlocked immediately
- **Risk-free**: No penalty for the attackers, only gas costs
- **Persistent**: Can be repeated every epoch indefinitely

The only barrier is requiring existing validator status, but in a competitive validator market, rational actors have clear incentive to execute this attack.

## Recommendation

Modify `add_stake_with_cap()` to only increment `total_joining_power` for `pending_active` validators, not `active_validators`:

```move
// In add_stake_with_cap function (around line 829):
// Only track voting power increase for pending_active validators joining.
// Active validators' stake increases don't affect admission of new validators.
let validator_set = borrow_global<ValidatorSet>(@aptos_framework);
if (option::is_some(&find_validator(&validator_set.pending_active, pool_address))) {
    update_voting_power_increase(amount);
};
```

Remove the check for `active_validators` in the conditional. Active validators adding stake should not consume the joining power quota since they are not joining—they are already part of the validator set.

Alternatively, implement separate quotas for:
1. `new_validator_joining_power` - for pending_active validators
2. `existing_validator_growth_power` - for active validators

This would allow governance to independently control new entrant growth vs existing validator growth.

## Proof of Concept

```move
#[test_only]
module aptos_framework::validator_admission_dos_test {
    use aptos_framework::stake;
    use aptos_framework::coin;
    use aptos_framework::aptos_coin::AptosCoin;
    
    #[test(
        aptos_framework = @aptos_framework,
        attacker_validator = @0x123,
        victim_validator = @0x456,
    )]
    fun test_active_validator_blocks_new_admission(
        aptos_framework: &signer,
        attacker_validator: &signer,
        victim_validator: &signer,
    ) {
        // Setup: Initialize staking with 20% voting power increase limit
        // (1000 total power, max 200 joining power per epoch)
        
        // Attacker is already an active validator
        stake::initialize_validator(attacker_validator, ...);
        stake::add_stake(attacker_validator, 1000);
        stake::join_validator_set(attacker_validator, ...);
        
        // Advance to next epoch so attacker is active
        advance_epoch();
        
        // ATTACK: Attacker adds 200 stake, consuming entire joining quota
        stake::add_stake(attacker_validator, 200);
        // total_joining_power is now 200 (limit reached)
        
        // Victim validator tries to join with valid stake
        stake::initialize_validator(victim_validator, ...);
        stake::add_stake(victim_validator, 150);
        
        // ASSERTION: Victim's join fails with EVOTING_POWER_INCREASE_EXCEEDS_LIMIT
        stake::join_validator_set(victim_validator, ...); // <- ABORTS
        
        // Attacker can now unlock the 200 stake without penalty
        stake::unlock(attacker_validator, 200);
        // total_joining_power remains 200, quota still consumed
    }
}
```

## Notes

The vulnerability stems from a semantic mismatch between the field name/documentation (`total_joining_power` = "voting power waiting to join") and its implementation (includes active validator growth). The voting power increase limit was designed to prevent sudden validator set expansion that could overwhelm consensus, but the current implementation incorrectly allows incumbents to weaponize this safety mechanism against new entrants.

This is distinct from the underflow protection at lines 1244-1248 in `leave_validator_set()`, which is a separate defensive mechanism and not the core vulnerability.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L181-193)
```text
    struct ValidatorSet has copy, key, drop, store {
        consensus_scheme: u8,
        // Active validators for the current epoch.
        active_validators: vector<ValidatorInfo>,
        // Pending validators to leave in next epoch (still active).
        pending_inactive: vector<ValidatorInfo>,
        // Pending validators to join in next epoch.
        pending_active: vector<ValidatorInfo>,
        // Current total voting power.
        total_voting_power: u128,
        // Total voting power waiting to join in the next epoch.
        total_joining_power: u128,
    }
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L829-832)
```text
        if (option::is_some(&find_validator(&validator_set.active_validators, pool_address)) ||
            option::is_some(&find_validator(&validator_set.pending_active, pool_address))) {
            update_voting_power_increase(amount);
        };
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1117-1150)
```text
    public fun unlock_with_cap(amount: u64, owner_cap: &OwnerCapability) acquires StakePool {
        assert_reconfig_not_in_progress();
        // Short-circuit if amount to unlock is 0 so we don't emit events.
        if (amount == 0) {
            return
        };

        // Unlocked coins are moved to pending_inactive. When the current lockup cycle expires, they will be moved into
        // inactive in the earliest possible epoch transition.
        let pool_address = owner_cap.pool_address;
        assert_stake_pool_exists(pool_address);
        let stake_pool = borrow_global_mut<StakePool>(pool_address);
        // Cap amount to unlock by maximum active stake.
        let amount = min(amount, coin::value(&stake_pool.active));
        let unlocked_stake = coin::extract(&mut stake_pool.active, amount);
        coin::merge<AptosCoin>(&mut stake_pool.pending_inactive, unlocked_stake);

        if (std::features::module_event_migration_enabled()) {
            event::emit(
                UnlockStake {
                    pool_address,
                    amount_unlocked: amount,
                },
            );
        } else {
            event::emit_event(
                &mut stake_pool.unlock_stake_events,
                UnlockStakeEvent {
                    pool_address,
                    amount_unlocked: amount,
                },
            );
        };
    }
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1857-1870)
```text
    fun update_voting_power_increase(increase_amount: u64) acquires ValidatorSet {
        let validator_set = borrow_global_mut<ValidatorSet>(@aptos_framework);
        let voting_power_increase_limit =
            (staking_config::get_voting_power_increase_limit(&staking_config::get()) as u128);
        validator_set.total_joining_power = validator_set.total_joining_power + (increase_amount as u128);

        // Only validator voting power increase if the current validator set's voting power > 0.
        if (validator_set.total_voting_power > 0) {
            assert!(
                validator_set.total_joining_power <= validator_set.total_voting_power * voting_power_increase_limit / 100,
                error::invalid_argument(EVOTING_POWER_INCREASE_EXCEEDS_LIMIT),
            );
        }
    }
```

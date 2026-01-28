# Audit Report

## Title
Staking Lockup Bypass in Vesting Contracts Due to Uninitialized Lockup Period

## Summary
Vesting contracts create underlying stake pools with `locked_until_secs = 0` and never initialize the staking lockup period. For INACTIVE stake pools (typical for vesting contracts), this allows shareholders to immediately withdraw vested coins by exploiting an edge case in `withdraw_with_cap`, completely bypassing the intended staking lockup mechanism.

## Finding Description

The vesting contract system implements two-tier locking: **vesting lockup** (controls when coins can be unlocked according to schedule) and **staking lockup** (controls when unlocked coins can be withdrawn). The documentation explicitly states: "After the unlocked rewards become fully withdrawable (as it's subject to staking lockup), shareholders can call distribute()." [1](#0-0) 

However, this guarantee is violated due to the following:

**Root Cause**: When a stake pool is initialized through `initialize_owner`, it creates a `StakePool` with `locked_until_secs: 0`. [2](#0-1) 

The vesting contract creation flow calls `create_staking_contract_with_coins` [3](#0-2)  which ultimately calls `stake::initialize_stake_owner` [4](#0-3)  but never calls `reset_lockup()` or `increase_lockup()` to set an actual lockup period.

**No Automatic Renewal**: For ACTIVE validators, lockup is automatically renewed during `on_new_epoch` when their stake pool is in the active validator set. [5](#0-4)  However, vesting contracts typically create INACTIVE stake pools that never join the validator set, so this automatic renewal never applies.

**Edge Case Exploitation**: When shareholders call `distribute()` on a vesting contract, it eventually calls `withdraw_with_cap()`, which contains an edge case specifically for INACTIVE validators: [6](#0-5) 

This edge case immediately moves all `pending_inactive` stake to `inactive` if both conditions are met:
1. The validator status is INACTIVE (true for vesting contracts not running validators)
2. Current time >= `locked_until_secs` (always true when `locked_until_secs = 0`)

**Attack Flow**:
1. Admin creates vesting contract via `create_vesting_contract` → underlying stake pool has `locked_until_secs = 0`, status INACTIVE
2. After vesting period passes, shareholder calls `vest()` → moves vested coins to `pending_inactive` [7](#0-6) 
3. Shareholder immediately calls `distribute()` → calls `withdraw_stake` [8](#0-7)  → calls `staking_contract::distribute` [9](#0-8)  → calls `withdraw_with_cap` [10](#0-9)  → edge case triggers → `pending_inactive` moves to `inactive` → coins withdrawn
4. Shareholder receives vested coins without any staking lockup delay

## Impact Explanation

**Severity: HIGH** - Significant Protocol Violation

This vulnerability violates a core security guarantee of the vesting system. It qualifies as HIGH severity because:

1. **Complete Protocol Violation**: The documented two-tier locking mechanism is entirely bypassed for the staking lockup component, contradicting explicit documentation that unlocked tokens "are still subject to the staking lockup"
2. **Premature Fund Access**: Shareholders can access vested funds immediately after they vest, without waiting for any staking lockup period to expire
3. **Affects All Vesting Contracts**: Any vesting contract that doesn't manually call `reset_lockup()` after creation is vulnerable - and there is no documentation or code enforcement requiring this
4. **Breaks Security Guarantee**: The system promises a two-tier locking mechanism but only enforces one tier

This constitutes a significant protocol violation that undermines the documented security model of the vesting system.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to be exploited because:

1. **No Special Permissions Required**: Any shareholder in a vesting contract can trigger the exploit by calling standard public entry functions (`vest()` and `distribute()`)
2. **Trivial Execution**: The attack requires only two transaction calls with no complex timing, state manipulation, or coordination
3. **Affects Common Configuration**: Vesting contracts typically don't join the validator set, leaving them in INACTIVE state where the vulnerability applies
4. **Natural User Flow**: Shareholders would naturally call `vest()` followed by `distribute()` to claim their vested tokens, unknowingly exploiting the vulnerability
5. **No Visible Warning**: Neither the code nor documentation indicates that admins must call `reset_lockup()` after contract creation to prevent this issue

## Recommendation

Fix this vulnerability by automatically initializing the lockup period when creating vesting contracts. Modify the `create_vesting_contract` function to call `reset_lockup()` immediately after creating the underlying stake pool:

In `vesting.move`, after line 601 where the pool is created, add:
```move
staking_contract::reset_lockup(&contract_signer, operator);
```

Alternatively, modify `create_stake_pool` in `staking_contract.move` to automatically set an initial lockup by calling `stake::increase_lockup_with_cap` after extracting the owner capability.

This ensures that all vesting contracts have a proper staking lockup period from creation, matching the documented behavior.

## Proof of Concept

A Move test demonstrating this vulnerability would:
1. Create a vesting contract with `create_vesting_contract` 
2. Fast forward time past the vesting cliff
3. Call `vest()` to unlock vested tokens
4. Immediately call `distribute()` without waiting for any lockup period
5. Verify that tokens are successfully withdrawn, bypassing the expected staking lockup

The test would show that tokens become immediately withdrawable despite documentation stating they should be subject to staking lockup.

## Notes

The edge case in `withdraw_with_cap` appears to be designed for validators who unlock their stake and leave the validator set before the lockup expires. [11](#0-10)  However, with `locked_until_secs = 0`, this edge case applies immediately to all INACTIVE stake pools, including newly created vesting contracts that never joined the validator set. This creates an unintended bypass of the staking lockup mechanism for vesting contracts.

### Citations

**File:** aptos-move/framework/aptos-framework/doc/vesting.md (L22-26)
```markdown
3. After the unlocked rewards become fully withdrawable (as it's subject to staking lockup), shareholders can call
distribute() to send all withdrawable funds to all shareholders based on the original grant's shares structure.
4. After 1 year and 1 month, the vesting schedule now starts. Shareholders call vest() to unlock vested coins. vest()
checks the schedule and unlocks 3/48 of the original grant in addition to any accumulated rewards since last
unlock_rewards(). Once the unlocked coins become withdrawable, shareholders can call distribute().
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L700-705)
```text
        move_to(owner, StakePool {
            active: coin::zero<AptosCoin>(),
            pending_active: coin::zero<AptosCoin>(),
            pending_inactive: coin::zero<AptosCoin>(),
            inactive: coin::zero<AptosCoin>(),
            locked_until_secs: 0,
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1174-1181)
```text
        // There's an edge case where a validator unlocks their stake and leaves the validator set before
        // the stake is fully unlocked (the current lockup cycle has not expired yet).
        // This can leave their stake stuck in pending_inactive even after the current lockup cycle expires.
        if (get_validator_state(pool_address) == VALIDATOR_STATUS_INACTIVE &&
            timestamp::now_seconds() >= stake_pool.locked_until_secs) {
            let pending_inactive_stake = coin::extract_all(&mut stake_pool.pending_inactive);
            coin::merge(&mut stake_pool.inactive, pending_inactive_stake);
        };
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1435-1449)
```text
            // Automatically renew a validator's lockup for validators that will still be in the validator set in the
            // next epoch.
            let stake_pool = borrow_global_mut<StakePool>(validator_info.addr);
            let now_secs = timestamp::now_seconds();
            let reconfig_start_secs = if (chain_status::is_operating()) {
                get_reconfig_start_time_secs()
            } else {
                now_secs
            };
            if (stake_pool.locked_until_secs <= reconfig_start_secs) {
                spec {
                    assume now_secs + recurring_lockup_duration_secs <= MAX_U64;
                };
                stake_pool.locked_until_secs = now_secs + recurring_lockup_duration_secs;
            };
```

**File:** aptos-move/framework/aptos-framework/sources/vesting.move (L600-601)
```text
        let pool_address = staking_contract::create_staking_contract_with_coins(
            &contract_signer, operator, voter, grant, commission_percentage, contract_creation_seed);
```

**File:** aptos-move/framework/aptos-framework/sources/vesting.move (L679-717)
```text
    public entry fun vest(contract_address: address) acquires VestingContract {
        // Unlock all rewards first, if any.
        unlock_rewards(contract_address);

        // Unlock the vested amount. This amount will become withdrawable when the underlying stake pool's lockup
        // expires.
        let vesting_contract = borrow_global_mut<VestingContract>(contract_address);
        // Short-circuit if vesting hasn't started yet.
        if (vesting_contract.vesting_schedule.start_timestamp_secs > timestamp::now_seconds()) {
            return
        };

        // Check if the next vested period has already passed. If not, short-circuit since there's nothing to vest.
        let vesting_schedule = &mut vesting_contract.vesting_schedule;
        let last_vested_period = vesting_schedule.last_vested_period;
        let next_period_to_vest = last_vested_period + 1;
        let last_completed_period =
            (timestamp::now_seconds() - vesting_schedule.start_timestamp_secs) / vesting_schedule.period_duration;
        if (last_completed_period < next_period_to_vest) {
            return
        };

        // Calculate how much has vested, excluding rewards.
        // Index is 0-based while period is 1-based so we need to subtract 1.
        let schedule = &vesting_schedule.schedule;
        let schedule_index = next_period_to_vest - 1;
        let vesting_fraction = if (schedule_index < vector::length(schedule)) {
            *vector::borrow(schedule, schedule_index)
        } else {
            // Last vesting schedule fraction will repeat until the grant runs out.
            *vector::borrow(schedule, vector::length(schedule) - 1)
        };
        let total_grant = pool_u64::total_coins(&vesting_contract.grant_pool);
        let vested_amount = fixed_point32::multiply_u64(total_grant, vesting_fraction);
        // Cap vested amount by the remaining grant amount so we don't try to distribute more than what's remaining.
        vested_amount = min(vested_amount, vesting_contract.remaining_grant);
        vesting_contract.remaining_grant = vesting_contract.remaining_grant - vested_amount;
        vesting_schedule.last_vested_period = next_period_to_vest;
        unlock_stake(vesting_contract, vested_amount);
```

**File:** aptos-move/framework/aptos-framework/sources/vesting.move (L756-760)
```text
    public entry fun distribute(contract_address: address) acquires VestingContract {
        assert_active_vesting_contract(contract_address);

        let vesting_contract = borrow_global_mut<VestingContract>(contract_address);
        let coins = withdraw_stake(vesting_contract, contract_address);
```

**File:** aptos-move/framework/aptos-framework/sources/vesting.move (L1195-1198)
```text
    fun withdraw_stake(vesting_contract: &VestingContract, contract_address: address): Coin<AptosCoin> {
        // Claim any withdrawable distribution from the staking contract. The withdrawn coins will be sent directly to
        // the vesting contract's account.
        staking_contract::distribute(contract_address, vesting_contract.staking.operator);
```

**File:** aptos-move/framework/aptos-framework/sources/staking_contract.move (L948-950)
```text
            stake::withdraw_with_cap(
                &staking_contract.owner_cap, total_potential_withdrawable
            );
```

**File:** aptos-move/framework/aptos-framework/sources/staking_contract.move (L1088-1088)
```text
        stake::initialize_stake_owner(&stake_pool_signer, 0, operator, voter);
```

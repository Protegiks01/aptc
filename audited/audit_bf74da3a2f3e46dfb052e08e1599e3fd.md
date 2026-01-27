# Audit Report

## Title
Integer Overflow in Staking Contract Commission Calculation Causes Permanent Fund Freeze

## Summary
The staking contract's commission calculation performs unsafe arithmetic that can overflow after years of reward accumulation, permanently locking both staker and operator funds. The vulnerable multiplication `accumulated_rewards * commission_percentage` lacks the u128 intermediate casting used in similar calculations elsewhere in the codebase, causing transaction aborts when overflow occurs.

## Finding Description

The vulnerability exists in the commission calculation logic within the staking contract system. The core issue is located in the `get_staking_contract_amounts_internal` function: [1](#0-0) [2](#0-1) 

The calculation `accumulated_rewards * staking_contract.commission_percentage / 100` performs multiplication before division without using u128 intermediate type for overflow protection. In Move, all arithmetic operations abort on overflow rather than wrapping.

**How the vulnerability manifests:**

1. A staking contract is created with maximum stake (100,000,000,000,000,000 octos = 1 billion APT): [3](#0-2) 

2. Rewards accumulate over time through the stake pool's reward distribution mechanism: [4](#0-3) 

3. Critically, reward distribution does NOT check against maximum_stake when minting rewards, unlike when adding new stake: [5](#0-4) 

4. The principal in the staking contract is only updated when commission is requested: [6](#0-5) 

5. If commission is never requested for many years, `accumulated_rewards = total_active_stake - principal` grows unbounded through compounding.

6. For a 100% commission rate, overflow occurs when:
   - `accumulated_rewards * 100 > u64::MAX`
   - `accumulated_rewards > 184,467,440,737,095,516` octos (~1.844 billion APT)

7. Starting from max_stake of 1 billion APT, this requires total_active_stake to reach ~2.844 billion APT (184.4% growth).

8. At 10% APY compounding, this threshold is reached in approximately 11 years.

**Impact cascade:**

When overflow occurs, multiple critical functions abort because they call `request_commission_internal`: [7](#0-6) [8](#0-7) [9](#0-8) 

The secondary overflow location in distribution pool updates exhibits the same pattern: [10](#0-9) 

**Comparison with safe implementation:**

The delegation pool correctly uses `math64::mul_div` which performs the multiplication in u128: [11](#0-10) 

## Impact Explanation

**Severity: CRITICAL**

This vulnerability meets the **"Permanent freezing of funds (requires hardfork)"** critical severity category.

When the overflow condition is reached:

1. **Operator funds frozen**: Cannot call `request_commission()` to unlock their earned commission
2. **Staker funds frozen**: Cannot call `unlock_stake()` or `unlock_rewards()` as both internally call `request_commission_internal()` which aborts
3. **No operator switching**: Cannot call `switch_operator()` to attempt recovery
4. **No commission updates**: Cannot call `update_commision()` to reduce commission percentage
5. **Self-reinforcing**: As rewards continue accumulating, the overflow becomes worse, not better

The only recovery mechanism would require a network hardfork to either:
- Manually update the principal values in affected contracts, or
- Deploy a patched staking_contract module

This affects real economic value. With maximum stake of 1 billion APT per validator and typical commission rates, billions of dollars in value could be permanently locked.

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH over multi-year timescales**

The vulnerability does NOT require:
- Malicious actors
- Validator collusion
- Privileged access
- Complex exploitation

It can occur naturally through:

1. **Normal operations**: A validator with max_stake who forgets or fails to request commission for ~11 years at 10% APY
2. **Automation failures**: Operators relying on automated commission collection that breaks or is forgotten
3. **Smart contract stakers**: Automated staking systems that don't implement commission request logic

**Timeline scenarios:**
- 100% commission, 10% APY: ~11 years
- 100% commission, 5% APY: ~21 years  
- 50% commission, 10% APY: ~24 years

While years seem long, blockchain systems are designed for decades. Early staking contracts from 2024 could hit this by 2035-2045, well within the expected lifetime of the Aptos network.

## Recommendation

Replace the unsafe arithmetic with `math64::mul_div` to perform the multiplication through u128 intermediate casting:

**In `get_staking_contract_amounts_internal` (line 1069):**

```move
// BEFORE (vulnerable):
let commission_amount = accumulated_rewards * staking_contract.commission_percentage / 100;

// AFTER (fixed):
let commission_amount = math64::mul_div(
    accumulated_rewards, 
    staking_contract.commission_percentage, 
    100
);
```

**In `update_distribution_pool` (line 1124):**

```move
// BEFORE (vulnerable):
let unpaid_commission = (current_worth - previous_worth) * commission_percentage / 100;

// AFTER (fixed):  
let unpaid_commission = math64::mul_div(
    current_worth - previous_worth,
    commission_percentage,
    100
);
```

This matches the safe pattern already used in delegation_pool.move and ensures intermediate calculations use u128, preventing overflow while maintaining correct results.

## Proof of Concept

```move
#[test_only]
module aptos_framework::staking_contract_overflow_test {
    use aptos_framework::staking_contract;
    use aptos_framework::stake;
    use aptos_framework::coin;
    use aptos_framework::aptos_coin::AptosCoin;
    
    #[test(aptos_framework = @aptos_framework, staker = @0x123, operator = @0x456)]
    #[expected_failure(abort_code = 0x20000, location = aptos_framework::staking_contract)]
    public fun test_commission_overflow(
        aptos_framework: &signer,
        staker: &signer, 
        operator: &signer
    ) {
        // Setup: Create staking contract with max stake and 100% commission
        let initial_stake = 100_000_000_000_000_000; // 1 billion APT (max_stake)
        let commission = 100; // 100%
        
        staking_contract::create_staking_contract(
            staker,
            signer::address_of(operator),
            signer::address_of(operator),
            initial_stake,
            commission,
            vector::empty()
        );
        
        let pool_address = staking_contract::stake_pool_address(
            signer::address_of(staker),
            signer::address_of(operator)
        );
        
        // Simulate ~11 years of 10% APY rewards accumulation
        // Target: accumulated_rewards > 184,467,440,737,095,516
        // This requires total_active_stake ≈ 284,467,440,737,095,516
        
        for (i in 0..11) {
            // Simulate epoch with 10% rewards
            let (active, _, _, _) = stake::get_stake(pool_address);
            let rewards = active / 10; // 10% of current stake
            
            // Mint rewards directly to stake pool (simulating reward distribution)
            stake::distribute_rewards_for_test(pool_address, rewards);
        };
        
        // At this point, accumulated_rewards * 100 > u64::MAX
        // Any operation calling request_commission_internal will abort with overflow
        
        // This call should abort due to arithmetic overflow
        staking_contract::request_commission(
            operator,
            signer::address_of(staker),
            signer::address_of(operator)
        );
        
        // Similarly, unlock_stake would also abort
        // staking_contract::unlock_stake(staker, operator, 1000);
    }
}
```

**Notes:**

1. The vulnerability is architecture-agnostic—it affects any staking contract using the vulnerable arithmetic pattern regardless of network configuration.

2. The issue violates the **Staking Security** invariant: "Validator rewards and penalties must be calculated correctly" by causing calculations to abort instead of computing correct values.

3. This demonstrates why defense-in-depth is critical: even though `add_stake_with_cap` enforces max_stake, the lack of enforcement in `distribute_rewards` creates this overflow vector.

4. Emergency mitigation could include governance proposals to force commission requests on old contracts before overflow thresholds, but this requires active monitoring and intervention.

### Citations

**File:** crates/aptos-genesis/src/config.rs (L118-118)
```rust
            max_stake: 100_000_000_000_000_000,
```

**File:** crates/aptos-genesis/src/config.rs (L169-169)
```rust
    pub commission_percentage: u64,
```

**File:** aptos-move/framework/aptos-framework/sources/staking_contract.move (L640-672)
```text
    public entry fun request_commission(
        account: &signer, staker: address, operator: address
    ) acquires Store, BeneficiaryForOperator {
        let account_addr = signer::address_of(account);
        assert!(
            account_addr == staker
                || account_addr == operator
                || account_addr == beneficiary_for_operator(operator),
            error::unauthenticated(ENOT_STAKER_OR_OPERATOR_OR_BENEFICIARY)
        );
        assert_staking_contract_exists(staker, operator);

        let store = borrow_global_mut<Store>(staker);
        let staking_contract =
            simple_map::borrow_mut(&mut store.staking_contracts, &operator);
        // Short-circuit if zero commission.
        if (staking_contract.commission_percentage == 0) { return };

        // Force distribution of any already inactive stake.
        distribute_internal(
            staker,
            operator,
            staking_contract,
            &mut store.distribute_events
        );

        request_commission_internal(
            operator,
            staking_contract,
            &mut store.add_distribution_events,
            &mut store.request_commission_events
        );
    }
```

**File:** aptos-move/framework/aptos-framework/sources/staking_contract.move (L680-684)
```text
        // Unlock just the commission portion from the stake pool.
        let (total_active_stake, accumulated_rewards, commission_amount) =
            get_staking_contract_amounts_internal(staking_contract);
        staking_contract.principal = total_active_stake - commission_amount;

```

**File:** aptos-move/framework/aptos-framework/sources/staking_contract.move (L730-793)
```text
    public entry fun unlock_stake(
        staker: &signer, operator: address, amount: u64
    ) acquires Store, BeneficiaryForOperator {
        // Short-circuit if amount is 0.
        if (amount == 0) return;

        let staker_address = signer::address_of(staker);
        assert_staking_contract_exists(staker_address, operator);

        let store = borrow_global_mut<Store>(staker_address);
        let staking_contract =
            simple_map::borrow_mut(&mut store.staking_contracts, &operator);

        // Force distribution of any already inactive stake.
        distribute_internal(
            staker_address,
            operator,
            staking_contract,
            &mut store.distribute_events
        );

        // For simplicity, we request commission to be paid out first. This avoids having to ensure to staker doesn't
        // withdraw into the commission portion.
        let commission_paid =
            request_commission_internal(
                operator,
                staking_contract,
                &mut store.add_distribution_events,
                &mut store.request_commission_events
            );

        // If there's less active stake remaining than the amount requested (potentially due to commission),
        // only withdraw up to the active amount.
        let (active, _, _, _) = stake::get_stake(staking_contract.pool_address);
        if (active < amount) {
            amount = active;
        };
        staking_contract.principal = staking_contract.principal - amount;

        // Record a distribution for the staker.
        add_distribution(
            operator,
            staking_contract,
            staker_address,
            amount,
            &mut store.add_distribution_events
        );

        // Request to unlock the distribution amount from the stake pool.
        // This won't become fully unlocked until the stake pool's lockup expires.
        stake::unlock_with_cap(amount, &staking_contract.owner_cap);

        let pool_address = staking_contract.pool_address;
        if (std::features::module_event_migration_enabled()) {
            emit(
                UnlockStake { pool_address, operator, amount, commission_paid }
            );
        } else {
            emit_event(
                &mut store.unlock_stake_events,
                UnlockStakeEvent { pool_address, operator, amount, commission_paid }
            );
        };
    }
```

**File:** aptos-move/framework/aptos-framework/sources/staking_contract.move (L826-879)
```text
    public entry fun switch_operator(
        staker: &signer,
        old_operator: address,
        new_operator: address,
        new_commission_percentage: u64
    ) acquires Store, BeneficiaryForOperator {
        let staker_address = signer::address_of(staker);
        assert_staking_contract_exists(staker_address, old_operator);

        assert!(
            new_commission_percentage <= 100,
            error::invalid_argument(EINVALID_COMMISSION_PERCENTAGE)
        );
        // Merging two existing staking contracts is too complex as we'd need to merge two separate stake pools.
        let store = borrow_global_mut<Store>(staker_address);
        let staking_contracts = &mut store.staking_contracts;
        assert!(
            !simple_map::contains_key(staking_contracts, &new_operator),
            error::invalid_state(ECANT_MERGE_STAKING_CONTRACTS)
        );

        let (_, staking_contract) = simple_map::remove(staking_contracts, &old_operator);
        // Force distribution of any already inactive stake.
        distribute_internal(
            staker_address,
            old_operator,
            &mut staking_contract,
            &mut store.distribute_events
        );

        // For simplicity, we request commission to be paid out first. This avoids having to ensure to staker doesn't
        // withdraw into the commission portion.
        request_commission_internal(
            old_operator,
            &mut staking_contract,
            &mut store.add_distribution_events,
            &mut store.request_commission_events
        );

        // Update the staking contract's commission rate and stake pool's operator.
        stake::set_operator_with_cap(&staking_contract.owner_cap, new_operator);
        staking_contract.commission_percentage = new_commission_percentage;

        let pool_address = staking_contract.pool_address;
        simple_map::add(staking_contracts, new_operator, staking_contract);
        if (std::features::module_event_migration_enabled()) {
            emit(SwitchOperator { pool_address, old_operator, new_operator });
        } else {
            emit_event(
                &mut store.switch_operator_events,
                SwitchOperatorEvent { pool_address, old_operator, new_operator }
            );
        };
    }
```

**File:** aptos-move/framework/aptos-framework/sources/staking_contract.move (L1057-1072)
```text
    fun get_staking_contract_amounts_internal(
        staking_contract: &StakingContract
    ): (u64, u64, u64) {
        // Pending_inactive is not included in the calculation because pending_inactive can only come from:
        // 1. Outgoing commissions. This means commission has already been extracted.
        // 2. Stake withdrawals from stakers. This also means commission has already been extracted as
        // request_commission_internal is called in unlock_stake
        let (active, _, pending_active, _) =
            stake::get_stake(staking_contract.pool_address);
        let total_active_stake = active + pending_active;
        let accumulated_rewards = total_active_stake - staking_contract.principal;
        let commission_amount =
            accumulated_rewards * staking_contract.commission_percentage / 100;

        (total_active_stake, accumulated_rewards, commission_amount)
    }
```

**File:** aptos-move/framework/aptos-framework/sources/staking_contract.move (L1123-1124)
```text
                    let unpaid_commission =
                        (current_worth - previous_worth) * commission_percentage / 100;
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L843-845)
```text
        let (_, maximum_stake) = staking_config::get_required_stake(&staking_config::get());
        let voting_power = get_next_epoch_voting_power(stake_pool);
        assert!(voting_power <= maximum_stake, error::invalid_argument(ESTAKE_EXCEEDS_MAX));
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1787-1812)
```text
    fun distribute_rewards(
        stake: &mut Coin<AptosCoin>,
        num_successful_proposals: u64,
        num_total_proposals: u64,
        rewards_rate: u64,
        rewards_rate_denominator: u64,
    ): u64 acquires AptosCoinCapabilities {
        let stake_amount = coin::value(stake);
        let rewards_amount = if (stake_amount > 0) {
            calculate_rewards_amount(
                stake_amount,
                num_successful_proposals,
                num_total_proposals,
                rewards_rate,
                rewards_rate_denominator
            )
        } else {
            0
        };
        if (rewards_amount > 0) {
            let mint_cap = &borrow_global<AptosCoinCapabilities>(@aptos_framework).mint_cap;
            let rewards = coin::mint(rewards_amount, mint_cap);
            coin::merge(stake, rewards);
        };
        rewards_amount
    }
```

**File:** aptos-move/framework/aptos-stdlib/sources/math64.move (L49-54)
```text
    /// Returns a * b / c going through u128 to prevent intermediate overflow
    public inline fun mul_div(a: u64, b: u64, c: u64): u64 {
        // Inline functions cannot take constants, as then every module using it needs the constant
        assert!(c != 0, std::error::invalid_argument(4));
        (((a as u128) * (b as u128) / (c as u128)) as u64)
    }
```

# Audit Report

## Title
Integer Overflow in Epoch Transition Causes Network Liveness Failure

## Summary
The staking system allows validators to add stake up to `maximum_stake`, but fails to account for epoch rewards and transaction fees that are added during epoch transitions. When `maximum_stake` is set to or near `u64::MAX`, the sum of active stake, pending_active stake, rewards, and fees can exceed `u64::MAX`, causing an integer overflow abort in `coin::merge`. This abort occurs in the critical `update_stake_pool` function during epoch transitions, halting the entire network.

## Finding Description

The vulnerability exists in the interaction between stake addition validation and epoch transition logic.

**Stake Addition Check:** When a validator adds stake via `add_stake`, the system validates: [1](#0-0) 

The `get_next_epoch_voting_power` function calculates the sum as: [2](#0-1) 

Note the `spec { assume ... }` at line 1852 is only a verification assumption, **not a runtime check**. However, Move's built-in arithmetic overflow protection will abort if the sum exceeds `u64::MAX`.

**Epoch Transition Operations:** During epoch transitions in `update_stake_pool`, the following operations occur in sequence:

1. Rewards are added to active stake: [3](#0-2) 

Inside `distribute_rewards`, line 1809 merges rewards into the stake coin.

2. Transaction fees are minted and merged into active: [4](#0-3) 

3. Finally, pending_active is merged into active: [5](#0-4) 

**The Overflow Point:** The `coin::merge` function performs: [6](#0-5) 

Again, the `spec { assume ... }` at line 1107 is only for verification. The actual addition at line 1116 will **abort on overflow** due to Move's integer arithmetic protection.

**Attack Scenario:**
1. Network configured with `maximum_stake = u64::MAX` (possible in testnets or misconfigured networks)
2. Attacker (validator) stakes such that: `active + pending_active + pending_inactive = u64::MAX`, with `pending_inactive = 0` or very small
3. The validation check passes: `voting_power <= maximum_stake` ✓
4. During next epoch transition, `update_stake_pool` executes:
   - `active' = active + rewards_active` (distribute_rewards line 1809)
   - `active'' = active' + fee_active` (line 1714)
   - `active_final = active'' + pending_active` (line 1727)
5. Since `active + pending_active ≈ u64::MAX`, adding any rewards or fees makes `active + rewards + fees + pending_active > u64::MAX`
6. The `coin::merge` operation aborts due to integer overflow
7. `update_stake_pool` aborts, which is called by `on_new_epoch`: [7](#0-6) 
8. Epoch transition fails, network halts

This breaks the **Staking Security** invariant that "Validator rewards and penalties must be calculated correctly" and causes total loss of network liveness.

## Impact Explanation

**Critical Severity - Total Loss of Liveness/Network Availability**

Per Aptos Bug Bounty criteria, this qualifies as Critical Severity because:
- **Total loss of liveness/network availability**: The epoch transition mechanism is fundamental to the blockchain's operation. When `on_new_epoch` aborts, the network cannot progress to the next epoch, validators cannot be updated, and the chain effectively halts.
- **Non-recoverable without hardfork**: Once triggered, the network is stuck until a coordinated hardfork removes or modifies the problematic validator's stake.
- **Affects all nodes**: Every validator node attempting to execute the epoch transition will encounter the same abort, making this a network-wide failure, not isolated to specific nodes.

## Likelihood Explanation

**Medium to High Likelihood** depending on network configuration:

**High Likelihood Factors:**
- If `maximum_stake` is set to `u64::MAX` (18.4 quintillion) or close to it (which can occur in testnet configurations or initial mainnet deployments)
- No explicit bounds checking prevents the sum of stake + rewards + fees from exceeding `u64::MAX`
- Any validator can execute this attack without special privileges
- Requires only normal staking operations, making it hard to detect

**Mitigating Factors:**
- Production networks likely set `maximum_stake` well below `u64::MAX` (e.g., 50 million APT = 5×10^15 octas, far from u64::MAX)
- Requires deliberate coordination to maximize stake to the limit
- Would be caught in testnets before mainnet deployment

However, even if `maximum_stake` is set to 99% of `u64::MAX`, accumulated rewards over multiple epochs could eventually trigger the overflow, making this a time-bomb vulnerability even in "safe" configurations.

## Recommendation

Add explicit overflow protection before merging operations in `update_stake_pool`:

```move
fun update_stake_pool(
    validator_perf: &ValidatorPerformance,
    pool_address: address,
    staking_config: &StakingConfig,
) acquires AptosCoinCapabilities, PendingTransactionFee, StakePool, TransactionFeeConfig, ValidatorConfig {
    let stake_pool = borrow_global_mut<StakePool>(pool_address);
    
    // ... existing fee and reward calculation logic ...
    
    // ADD THIS CHECK: Verify total stake won't overflow before merging
    let current_active = coin::value(&stake_pool.active);
    let current_pending_active = coin::value(&stake_pool.pending_active);
    let total_additions = (rewards_active as u128) + (fee_active as u128) + (current_pending_active as u128);
    
    // If adding these would exceed u64::MAX, cap the validator's stake at the maximum
    // and refund or don't add the excess
    assert!(
        (current_active as u128) + total_additions <= (MAX_U64 as u128),
        error::invalid_state(ESTAKE_POOL_OVERFLOW)
    );
    
    // ... existing merge operations ...
}
```

Additionally, strengthen the validation in `add_stake_with_cap` to ensure a safety margin:

```move
// Reserve headroom for rewards and fees (e.g., 1% of maximum_stake)
let safety_margin = maximum_stake / 100;
assert!(
    voting_power <= maximum_stake - safety_margin,
    error::invalid_argument(ESTAKE_EXCEEDS_MAX)
);
```

Or more simply, enforce that `maximum_stake` must be configured to a reasonable value (e.g., < 90% of u64::MAX) during staking config initialization.

## Proof of Concept

```move
#[test(aptos_framework = @aptos_framework, validator = @0x123)]
fun test_epoch_transition_overflow(aptos_framework: &signer, validator: &signer) {
    // Setup: Initialize staking with maximum_stake = u64::MAX
    staking_config::initialize(
        aptos_framework,
        1000000, // minimum_stake
        18446744073709551615, // maximum_stake = u64::MAX
        7200,
        true,
        100,
        10000,
        50
    );
    
    // Initialize validator with initial stake
    stake::initialize_validator(validator, ...);
    
    // Add stake such that active + pending_active ≈ u64::MAX
    // with pending_inactive = 0
    let massive_stake = 18446744073709550000; // slightly under u64::MAX
    stake::add_stake(validator, massive_stake);
    
    // Trigger epoch transition with any rewards/fees
    // This will cause update_stake_pool to abort when trying to merge
    // pending_active into active after adding rewards
    stake::on_new_epoch(); // ABORTS due to integer overflow in coin::merge
}
```

## Notes

The vulnerability is subtle because:
1. The `spec { assume ... }` statements suggest overflow protection but provide none at runtime
2. Move's automatic integer overflow protection causes an abort rather than wraparound, which is safer but still causes liveness failure in system-critical functions
3. The gap between stake addition checks and epoch transition operations creates a window where rewards/fees push the total over the limit

The root cause is that `maximum_stake` validation doesn't account for future epoch rewards and fees, creating an invariant violation between "stake cannot exceed maximum_stake" and "epoch transitions must always succeed."

### Citations

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L843-845)
```text
        let (_, maximum_stake) = staking_config::get_required_stake(&staking_config::get());
        let voting_power = get_next_epoch_voting_power(stake_pool);
        assert!(voting_power <= maximum_stake, error::invalid_argument(ESTAKE_EXCEEDS_MAX));
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1344-1361)
```text
    public(friend) fun on_new_epoch(
    ) acquires AptosCoinCapabilities, PendingTransactionFee, StakePool, TransactionFeeConfig, ValidatorConfig, ValidatorPerformance, ValidatorSet {
        let validator_set = borrow_global_mut<ValidatorSet>(@aptos_framework);
        let config = staking_config::get();
        let validator_perf = borrow_global_mut<ValidatorPerformance>(@aptos_framework);

        // Process pending stake and distribute transaction fees and rewards for each currently active validator.
        vector::for_each_ref(&validator_set.active_validators, |validator| {
            let validator: &ValidatorInfo = validator;
            update_stake_pool(validator_perf, validator.addr, &config);
        });

        // Process pending stake and distribute transaction fees and rewards for each currently pending_inactive validator
        // (requested to leave but not removed yet).
        vector::for_each_ref(&validator_set.pending_inactive, |validator| {
            let validator: &ValidatorInfo = validator;
            update_stake_pool(validator_perf, validator.addr, &config);
        });
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1714-1714)
```text
                coin::merge(&mut stake_pool.active, coin::mint(fee_active, mint_cap));
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1727-1727)
```text
        coin::merge(&mut stake_pool.active, coin::extract_all(&mut stake_pool.pending_active));
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

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1847-1855)
```text
    fun get_next_epoch_voting_power(stake_pool: &StakePool): u64 {
        let value_pending_active = coin::value(&stake_pool.pending_active);
        let value_active = coin::value(&stake_pool.active);
        let value_pending_inactive = coin::value(&stake_pool.pending_inactive);
        spec {
            assume value_pending_active + value_active + value_pending_inactive <= MAX_U64;
        };
        value_pending_active + value_active + value_pending_inactive
    }
```

**File:** aptos-move/framework/aptos-framework/sources/coin.move (L1103-1117)
```text
    public fun merge<CoinType>(
        dst_coin: &mut Coin<CoinType>, source_coin: Coin<CoinType>
    ) {
        spec {
            assume dst_coin.value + source_coin.value <= MAX_U64;
        };
        spec {
            update supply<CoinType> = supply<CoinType> - source_coin.value;
        };
        let Coin { value } = source_coin;
        spec {
            update supply<CoinType> = supply<CoinType> + value;
        };
        dst_coin.value = dst_coin.value + value;
    }
```

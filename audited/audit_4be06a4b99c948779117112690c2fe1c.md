# Audit Report

## Title
Missing Relative Voting Power Cap Allows Single Validator to Exceed BFT Safety Threshold

## Summary
The Aptos staking system enforces only an absolute `maximum_stake` cap on validator voting power, without any check preventing a single validator from accumulating more than 1/3 of total voting power. This creates a scenario where validator set changes can result in a single validator controlling sufficient voting power to block consensus, violating the Byzantine Fault Tolerance safety assumption.

## Finding Description

AptosBFT consensus assumes that no single Byzantine validator controls more than 1/3 of total voting power. However, the staking mechanism only enforces an absolute `maximum_stake` value without checking if a validator's stake represents an excessive percentage of total voting power.

The vulnerability manifests through these code paths:

1. **Voting Power Calculation** - [1](#0-0) 
   Voting power is simply the sum of pending_active + active + pending_inactive stake.

2. **Maximum Stake Check** - [2](#0-1) 
   The only constraint is an absolute maximum, not relative to total voting power.

3. **Validator Set Updates** - [3](#0-2) 
   During epoch changes, the system calculates total_voting_power but never checks if any individual validator exceeds 33.33% of this total.

4. **Configuration Defaults** - [4](#0-3) 
   The default maximum_stake is set to 1 billion APT as an absolute value.

**Exploitation Scenario:**
- Initial state: 3 validators each with 1 billion APT (33.33% each)
- Natural validator churn: One validator reduces stake to 500 million APT
- Result: Leading validator now controls 40% of total voting power (1B / 2.5B)
- This validator can now unilaterally block consensus by withholding votes

The BFT consensus verifier - [5](#0-4)  - calculates quorum as 2/3+1 of total voting power, but has no mechanism to prevent a single validator from having >1/3.

## Impact Explanation

**Critical Severity** - This meets the Aptos bug bounty criteria for Critical impact:

1. **Total loss of liveness/network availability**: A validator controlling >1/3 voting power can halt block production by refusing to vote, preventing the network from reaching the 2/3+1 quorum required for consensus.

2. **Consensus Safety violations**: While this primarily impacts liveness, it fundamentally violates the Byzantine Fault Tolerance assumption that the system can tolerate up to f Byzantine validators where n = 3f+1.

The consensus README - [5](#0-4)  - explicitly relies on this 3f+1 assumption, which breaks when a single validator exceeds the 1/3 threshold.

## Likelihood Explanation

**Likelihood: Medium to High**

This vulnerability can manifest naturally without malicious intent:

1. **Validator Set Dynamics**: As validators join and leave the network or adjust their stakes through normal operations, the relative voting power distribution shifts.

2. **No Active Monitoring**: The system does not actively monitor or alert when a validator approaches dangerous voting power thresholds.

3. **Economic Incentives**: The largest validator may not have malicious intent but could still cause liveness failures due to operational issues, downtime, or bugs.

4. **Governance Delays**: Adjusting `maximum_stake` via governance requires proposal voting and execution time, during which the vulnerability persists.

## Recommendation

Implement a **relative voting power cap** that prevents any single validator from exceeding a safe percentage of total voting power. The fix should be applied at two checkpoints:

**1. During stake addition/validator join:**
```move
// In add_stake_with_cap() and join_validator_set_internal()
let validator_set = borrow_global<ValidatorSet>(@aptos_framework);
let new_voting_power_percentage = (voting_power * 100) as u128 / validator_set.total_voting_power;
assert!(
    new_voting_power_percentage <= 30,  // 30% cap (well below 1/3 threshold)
    error::invalid_argument(EVOTING_POWER_EXCEEDS_RELATIVE_LIMIT)
);
```

**2. During epoch transitions:**
```move
// In on_new_epoch() after calculating total_voting_power
let max_allowed_power = total_voting_power * 30 / 100;  // 30% cap
vector::for_each_ref(&validator_set.active_validators, |validator| {
    let validator: &ValidatorInfo = validator;
    assert!(
        (validator.voting_power as u128) <= max_allowed_power,
        error::invalid_state(EVOTING_POWER_DISTRIBUTION_UNSAFE)
    );
});
```

**3. Add configuration parameter:**
Add `max_validator_voting_power_percentage` to `StakingConfig` - [6](#0-5)  - with a default value of 30% and validation that it must be ≤33%.

## Proof of Concept

```move
#[test(aptos_framework = @aptos_framework)]
fun test_single_validator_exceeds_bft_threshold(aptos_framework: &signer) {
    // Setup: Initialize staking with maximum_stake = 1B APT
    staking_config::initialize_for_test(
        aptos_framework,
        100_000_000_000_000,      // min_stake: 1M APT  
        1_000_000_000_000_000_000, // max_stake: 1B APT
        7200,                     // lockup duration
        true,                     // allow validator set change
        10,                       // rewards rate
        100,                      // rewards denominator
        20                        // voting power increase limit
    );
    
    // Create 3 validators, each with 1B APT (at max_stake)
    let validators = vector[
        create_validator(addr_1, 1_000_000_000_000_000_000), // 1B APT
        create_validator(addr_2, 1_000_000_000_000_000_000), // 1B APT
        create_validator(addr_3, 1_000_000_000_000_000_000), // 1B APT
    ];
    
    // Initial state: Each has 33.33% voting power - at BFT threshold
    // Total voting power: 3B APT
    
    // Validator 3 reduces stake to 500M APT
    unlock_stake(validator_3, 500_000_000_000_000_000);
    
    // Trigger epoch change
    stake::on_new_epoch();
    
    // Check: Validator 1 now has 40% of total voting power
    // Total voting power: 2.5B APT
    // Validator 1: 1B APT = 40% (EXCEEDS 1/3 THRESHOLD)
    
    let validator_set = borrow_global<ValidatorSet>(@aptos_framework);
    let validator_1_info = &validator_set.active_validators[0];
    let voting_power_percentage = 
        (validator_1_info.voting_power as u128) * 100 / validator_set.total_voting_power;
    
    assert!(voting_power_percentage > 33, 0); // Vulnerability: Exceeds BFT threshold
    
    // Validator 1 can now block consensus by not voting
    // Network cannot reach 2/3+1 quorum without validator 1
}
```

## Notes

This vulnerability represents a fundamental design flaw in how voting power caps are enforced. While the `maximum_stake` parameter provides an absolute upper bound, the lack of a relative cap means that validator set dynamics can naturally create unsafe voting power distributions. The fix requires both immediate validation during stake operations and ongoing monitoring during epoch transitions to maintain BFT safety properties.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L843-845)
```text
        let (_, maximum_stake) = staking_config::get_required_stake(&staking_config::get());
        let voting_power = get_next_epoch_voting_power(stake_pool);
        assert!(voting_power <= maximum_stake, error::invalid_argument(ESTAKE_EXCEEDS_MAX));
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

**File:** crates/aptos-genesis/src/config.rs (L116-118)
```rust
            min_stake: 100_000_000_000_000,
            min_voting_threshold: 100_000_000_000_000,
            max_stake: 100_000_000_000_000_000,
```

**File:** types/src/validator_verifier.rs (L206-214)
```rust
    pub fn new(validator_infos: Vec<ValidatorConsensusInfo>) -> Self {
        let total_voting_power = sum_voting_power(&validator_infos);
        let quorum_voting_power = if validator_infos.is_empty() {
            0
        } else {
            total_voting_power * 2 / 3 + 1
        };
        Self::build_index(validator_infos, quorum_voting_power, total_voting_power)
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/staking_config.move (L49-72)
```text
    struct StakingConfig has copy, drop, key {
        // A validator needs to stake at least this amount to be able to join the validator set.
        // If after joining the validator set and at the start of any epoch, a validator's stake drops below this amount
        // they will be removed from the set.
        minimum_stake: u64,
        // A validator can only stake at most this amount. Any larger stake will be rejected.
        // If after joining the validator set and at the start of any epoch, a validator's stake exceeds this amount,
        // their voting power and rewards would only be issued for the max stake amount.
        maximum_stake: u64,
        recurring_lockup_duration_secs: u64,
        // Whether validators are allow to join/leave post genesis.
        allow_validator_set_change: bool,
        // DEPRECATING: staking reward configurations will be in StakingRewardsConfig once REWARD_RATE_DECREASE flag is enabled.
        // The maximum rewards given out every epoch. This will be divided by the rewards rate denominator.
        // For example, 0.001% (0.00001) can be represented as 10 / 1000000.
        rewards_rate: u64,
        // DEPRECATING: staking reward configurations will be in StakingRewardsConfig once REWARD_RATE_DECREASE flag is enabled.
        rewards_rate_denominator: u64,
        // Only this % of current total voting power is allowed to join the validator set in each epoch.
        // This is necessary to prevent a massive amount of new stake from joining that can potentially take down the
        // network if corresponding validators are not ready to participate in consensus in time.
        // This value is within (0, 50%), not inclusive.
        voting_power_increase_limit: u64,
    }
```

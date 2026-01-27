# Audit Report

## Title
Epoch-By-Epoch Reward Rate Catchup During PeriodicalRewardRateReduction Activation Enables Disproportionate Validator Rewards

## Summary
When the `PeriodicalRewardRateReduction` feature flag is activated mid-network lifecycle, a timestamp initialization flaw causes rewards to decrease every single epoch (instead of yearly) until catching up to current time. This creates severe economic imbalance where validators active during early post-activation epochs receive exponentially higher rewards than those active later, enabling governance-controlling validators to time activation for maximum benefit.

## Finding Description

The `PeriodicalRewardRateReduction` feature implements yearly reward rate decreases for validators. However, a critical timestamp management flaw causes unexpected behavior when the feature is activated years after network genesis.

**Root Cause:**

At genesis, `StakingRewardsConfig.last_rewards_rate_period_start_in_secs` is initialized to 0: [1](#0-0) 

The `update_rewards_config()` function, used by governance to configure the decrease rate, does NOT update this timestamp: [2](#0-1) 

There is no mechanism to reset `last_rewards_rate_period_start_in_secs` after genesis except through the automatic increment in `calculate_and_save_latest_rewards_config()`.

**Activation Flow:**

During epoch transition, feature flags are enabled BEFORE reward distribution: [3](#0-2) 

The `stake::on_new_epoch()` function distributes rewards using the current rate, then updates the rate for next epoch: [4](#0-3) 

**Catchup Logic:**

The `calculate_and_save_latest_rewards_config()` function only decreases by ONE period per call, even if multiple years have passed: [5](#0-4) 

**Attack Scenario:**

1. Network runs for 3 years with `last_rewards_rate_period_start_in_secs = 0`
2. Governance (controlled by validators) calls `update_rewards_config()` setting `rewards_rate_decrease_rate = 50%` and `min_rewards_rate = 0.3%`
3. Feature flag `PeriodicalRewardRateReduction` is enabled via governance vote
4. Epoch N (first with feature enabled):
   - Rewards distributed at original rate (1%)
   - `calculate_and_save_latest_rewards_config()` decreases to 0.5%
   - Updates timestamp: 0 → 31.5M seconds
5. Epoch N+1 (2 hours later):
   - Rewards distributed at 0.5%
   - Decreases to 0.25%
   - Updates timestamp: 31.5M → 63M
6. Epoch N+2:
   - Rewards distributed at 0.25%
   - Decreases to minimum 0.3%
   - Updates timestamp: 63M → 94.5M
7. Epoch N+3+: Caught up, rewards stay at 0.3%

**Result:** Validators in epoch N receive 1% rewards, epoch N+1 receives 0.5%, epoch N+2 receives 0.25%, while all future validators receive only 0.3%. This is a 3.3x disparity between epoch N and steady-state.

Validators controlling governance can:
- Delay activation until they are in the active validator set
- Activate to maximize their own rewards during high-rate epochs
- Potentially exit before rewards stabilize at minimum

This breaks the **Staking Security** invariant: "Validator rewards and penalties must be calculated correctly."

## Impact Explanation

This qualifies as **Medium Severity** per Aptos bug bounty criteria for the following reasons:

1. **Limited Funds Manipulation**: Early validators receive disproportionately higher newly-minted APT rewards compared to later validators during the catchup period. While not direct theft, this creates unfair economic advantage.

2. **State Inconsistency**: The reward distribution deviates significantly from the intended yearly decrease schedule, requiring potential governance intervention to correct.

3. **Governance Exploitation**: Validators with sufficient governance voting power can time feature activation to benefit themselves at the expense of future validators.

The impact is limited because:
- No existing funds are stolen
- The network continues functioning normally
- The imbalance is temporary (ends after catchup completes)
- Requires governance control (not arbitrary attacker)

However, the economic disparity is significant enough to warrant Medium severity classification.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability will **definitely occur** if the `PeriodicalRewardRateReduction` feature is activated on a network that has been running for more than one year (31,536,000 seconds) after genesis.

**Probability factors:**
- The feature MUST eventually be activated on mainnet (it's already implemented in the codebase)
- Mainnet has been running for years, making multi-year catchup inevitable
- No existing test coverage validates mid-lifecycle activation behavior
- The timestamp initialization at genesis (0) is hardcoded

**Attacker requirements:**
- Validators must have sufficient governance voting power to influence proposal timing
- Attackers must be in active validator set when activation occurs
- No technical complexity required - just timing coordination

The combination of certain occurrence (when feature activates) and reasonable attacker capability (governance participation) makes this HIGH likelihood.

## Recommendation

**Fix Option 1 - Update timestamp during configuration:**

Modify `update_rewards_config()` to optionally reset `last_rewards_rate_period_start_in_secs` to current time:

```move
public fun update_rewards_config(
    aptos_framework: &signer,
    rewards_rate: FixedPoint64,
    min_rewards_rate: FixedPoint64,
    rewards_rate_period_in_secs: u64,
    rewards_rate_decrease_rate: FixedPoint64,
    reset_period_start: bool,  // NEW PARAMETER
) acquires StakingRewardsConfig {
    system_addresses::assert_aptos_framework(aptos_framework);
    
    validate_rewards_config(
        rewards_rate,
        min_rewards_rate,
        rewards_rate_period_in_secs,
        rewards_rate_decrease_rate,
    );
    
    let staking_rewards_config = borrow_global_mut<StakingRewardsConfig>(@aptos_framework);
    assert!(
        rewards_rate_period_in_secs == staking_rewards_config.rewards_rate_period_in_secs,
        error::invalid_argument(EINVALID_REWARDS_RATE_PERIOD),
    );
    staking_rewards_config.rewards_rate = rewards_rate;
    staking_rewards_config.min_rewards_rate = min_rewards_rate;
    staking_rewards_config.rewards_rate_period_in_secs = rewards_rate_period_in_secs;
    staking_rewards_config.rewards_rate_decrease_rate = rewards_rate_decrease_rate;
    
    // NEW: Allow resetting the period start to current time
    if (reset_period_start) {
        staking_rewards_config.last_rewards_rate_period_start_in_secs = timestamp::now_seconds();
    };
}
```

**Fix Option 2 - Initialize timestamp on first activation:**

Modify `calculate_and_save_latest_rewards_config()` to detect first-time activation and set timestamp to current time:

```move
fun calculate_and_save_latest_rewards_config(): StakingRewardsConfig acquires StakingRewardsConfig {
    let staking_rewards_config = borrow_global_mut<StakingRewardsConfig>(@aptos_framework);
    let current_time_in_secs = timestamp::now_seconds();
    
    // NEW: If period start is 0 and decrease rate is non-zero, this is first activation
    if (staking_rewards_config.last_rewards_rate_period_start_in_secs == 0 && 
        !fixed_point64::is_zero(staking_rewards_config.rewards_rate_decrease_rate)) {
        staking_rewards_config.last_rewards_rate_period_start_in_secs = current_time_in_secs;
        return *staking_rewards_config
    };
    
    // ... rest of function unchanged
}
```

**Recommended approach:** Use Fix Option 1, as it provides explicit governance control over the timestamp reset and is more transparent.

**Deployment strategy:**
1. Before enabling `PeriodicalRewardRateReduction` on mainnet, deploy the updated `update_rewards_config()` function
2. Call `update_rewards_config()` with `reset_period_start = true` to set timestamp to current time
3. Then enable the feature flag in a subsequent proposal

## Proof of Concept

```move
#[test(aptos_framework = @aptos_framework, validator = @0x123)]
public entry fun test_mid_lifecycle_activation_causes_rapid_catchup(
    aptos_framework: &signer,
    validator: &signer,
) acquires AllowedValidators, AptosCoinCapabilities, OwnerCapability, StakePool, 
           ValidatorConfig, ValidatorPerformance, ValidatorSet {
    // Initialize network at genesis
    initialize_for_test(aptos_framework);
    let validator_address = signer::address_of(validator);
    let (_sk, pk, pop) = generate_identity();
    initialize_test_validator(&pk, &pop, validator, 100000000, true, true);
    
    // Simulate network running for 3 years without the feature
    let three_years = 31536000 * 3;
    timestamp::fast_forward_seconds(three_years);
    
    // Activate the periodical reward decrease feature
    // This simulates governance setting up the decrease parameters
    staking_config::initialize_rewards(
        aptos_framework,
        fixed_point64::create_from_rational(1, 100),      // 1% initial rate
        fixed_point64::create_from_rational(3, 1000),     // 0.3% minimum
        31536000,                                          // 1 year periods
        0,                                                 // BUG: period start still at 0!
        fixed_point64::create_from_rational(50, 100),     // 50% decrease per period
    );
    features::change_feature_flags_for_testing(
        aptos_framework, 
        vector[features::get_periodical_reward_rate_decrease_feature()], 
        vector[]
    );
    
    // Epoch N: First epoch with feature enabled
    end_epoch();
    let stake_after_epoch_n = coin::value(&borrow_global<StakePool>(validator_address).active);
    // Validator receives full 1% rewards
    
    // Epoch N+1: Rate decreased to 0.5%
    end_epoch();
    let stake_after_epoch_n_plus_1 = coin::value(&borrow_global<StakePool>(validator_address).active);
    let rewards_n_plus_1 = stake_after_epoch_n_plus_1 - stake_after_epoch_n;
    
    // Epoch N+2: Rate decreased to 0.25% (or minimum 0.3%)
    end_epoch();
    let stake_after_epoch_n_plus_2 = coin::value(&borrow_global<StakePool>(validator_address).active);
    let rewards_n_plus_2 = stake_after_epoch_n_plus_2 - stake_after_epoch_n_plus_1;
    
    // VULNERABILITY: Rewards decrease every epoch instead of yearly
    assert!(rewards_n_plus_1 < stake_after_epoch_n * 1 / 100, 0); // Less than 1%
    assert!(rewards_n_plus_2 < rewards_n_plus_1, 1);              // Continuing to decrease
    
    // This creates economic imbalance - early validators get much more
}
```

## Notes

The vulnerability exists because the timestamp management was designed assuming the feature would be enabled near genesis or with proper timestamp initialization. The code lacks safeguards for mid-lifecycle activation, which is the realistic mainnet scenario. No existing tests validate this activation pattern, suggesting the issue was overlooked during development.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/configs/staking_config.move (L136-145)
```text
        // Initialize StakingRewardsConfig with the given rewards_rate and rewards_rate_denominator,
        // while setting min_rewards_rate and rewards_rate_decrease_rate to 0.
        initialize_rewards(
            aptos_framework,
            fixed_point64::create_from_rational((rewards_rate as u128), (rewards_rate_denominator as u128)),
            fixed_point64::create_from_rational(0, 1000),
            ONE_YEAR_IN_SECS,
            0,
            fixed_point64::create_from_rational(0, 1000),
        );
```

**File:** aptos-move/framework/aptos-framework/sources/configs/staking_config.move (L240-270)
```text
    fun calculate_and_save_latest_rewards_config(): StakingRewardsConfig acquires StakingRewardsConfig {
        let staking_rewards_config = borrow_global_mut<StakingRewardsConfig>(@aptos_framework);
        let current_time_in_secs = timestamp::now_seconds();
        assert!(
            current_time_in_secs >= staking_rewards_config.last_rewards_rate_period_start_in_secs,
            error::invalid_argument(EINVALID_LAST_REWARDS_RATE_PERIOD_START)
        );
        if (current_time_in_secs - staking_rewards_config.last_rewards_rate_period_start_in_secs < staking_rewards_config.rewards_rate_period_in_secs) {
            return *staking_rewards_config
        };
        // Rewards rate decrease rate cannot be greater than 100%. Otherwise rewards rate will be negative.
        assert!(
            fixed_point64::ceil(staking_rewards_config.rewards_rate_decrease_rate) <= 1,
            error::invalid_argument(EINVALID_REWARDS_RATE_DECREASE_RATE)
        );
        let new_rate = math_fixed64::mul_div(
            staking_rewards_config.rewards_rate,
            fixed_point64::sub(
                fixed_point64::create_from_u128(1),
                staking_rewards_config.rewards_rate_decrease_rate,
            ),
            fixed_point64::create_from_u128(1),
        );
        new_rate = fixed_point64::max(new_rate, staking_rewards_config.min_rewards_rate);

        staking_rewards_config.rewards_rate = new_rate;
        staking_rewards_config.last_rewards_rate_period_start_in_secs =
            staking_rewards_config.last_rewards_rate_period_start_in_secs +
            staking_rewards_config.rewards_rate_period_in_secs;
        return *staking_rewards_config
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/staking_config.move (L327-354)
```text
    public fun update_rewards_config(
        aptos_framework: &signer,
        rewards_rate: FixedPoint64,
        min_rewards_rate: FixedPoint64,
        rewards_rate_period_in_secs: u64,
        rewards_rate_decrease_rate: FixedPoint64,
    ) acquires StakingRewardsConfig {
        system_addresses::assert_aptos_framework(aptos_framework);

        validate_rewards_config(
            rewards_rate,
            min_rewards_rate,
            rewards_rate_period_in_secs,
            rewards_rate_decrease_rate,
        );

        let staking_rewards_config = borrow_global_mut<StakingRewardsConfig>(@aptos_framework);
        // Currently rewards_rate_period_in_secs is not allowed to be changed because this could bring complicated
        // logics. At the moment the argument is just a placeholder for future use.
        assert!(
            rewards_rate_period_in_secs == staking_rewards_config.rewards_rate_period_in_secs,
            error::invalid_argument(EINVALID_REWARDS_RATE_PERIOD),
        );
        staking_rewards_config.rewards_rate = rewards_rate;
        staking_rewards_config.min_rewards_rate = min_rewards_rate;
        staking_rewards_config.rewards_rate_period_in_secs = rewards_rate_period_in_secs;
        staking_rewards_config.rewards_rate_decrease_rate = rewards_rate_decrease_rate;
    }
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration_with_dkg.move (L46-61)
```text
    public(friend) fun finish(framework: &signer) {
        system_addresses::assert_aptos_framework(framework);
        dkg::try_clear_incomplete_session(framework);
        consensus_config::on_new_epoch(framework);
        execution_config::on_new_epoch(framework);
        gas_schedule::on_new_epoch(framework);
        std::version::on_new_epoch(framework);
        features::on_new_epoch(framework);
        jwk_consensus_config::on_new_epoch(framework);
        jwks::on_new_epoch(framework);
        keyless_account::on_new_epoch(framework);
        randomness_config_seqnum::on_new_epoch(framework);
        randomness_config::on_new_epoch(framework);
        randomness_api_v0_config::on_new_epoch(framework);
        reconfiguration::reconfigure();
    }
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1460-1463)
```text
        if (features::periodical_reward_rate_decrease_enabled()) {
            // Update rewards rate after reward distribution.
            staking_config::calculate_and_save_latest_epoch_rewards_rate();
        };
```

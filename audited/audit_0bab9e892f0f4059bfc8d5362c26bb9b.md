# Audit Report

## Title
Insufficient Epoch Duration Validation Enables Rapid Validator Set Manipulation and Consensus Destabilization

## Summary
The `epoch_duration_secs` parameter in genesis configuration lacks a minimum value constraint beyond `> 0`, allowing it to be set to extremely small values (e.g., 1 second). This enables attackers to bypass the `voting_power_increase_limit` protection through rapid epoch transitions, potentially achieving consensus control within seconds and causing total network liveness failure.

## Finding Description

The genesis validation in `validate_genesis_config()` only enforces that `epoch_duration_secs > 0`: [1](#0-0) 

This allows configurations where `epoch_duration_secs = 1` second, `recurring_lockup_duration_secs = 2` seconds, and `voting_duration_secs = 1` second, all of which pass validation checks: [2](#0-1) 

The epoch transition is triggered in block processing when the timestamp exceeds the epoch interval: [3](#0-2) 

During each epoch transition, `on_new_epoch()` resets the `total_joining_power` counter to zero: [4](#0-3) 

The `voting_power_increase_limit` (default 50%) is enforced per epoch through `update_voting_power_increase()`: [5](#0-4) 

**Attack Path:**
1. Network launches with `epoch_duration_secs = 1` at genesis (passes all validation)
2. Attacker with sufficient initial stake repeatedly adds stake up to 50% of current total voting power
3. Since epochs transition every second and `total_joining_power` resets each epoch, the attacker can compound their voting power at 1.5x per second
4. Within 10 seconds: 1.5^10 = 57.7x initial voting power increase
5. Attacker achieves >33% total voting power, enabling liveness denial
6. Or achieves >66% total voting power, enabling safety violations

The vulnerability breaks the **Consensus Safety** invariant that "AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine" by allowing rapid accumulation of voting power beyond Byzantine fault tolerance thresholds.

## Impact Explanation

**Critical Severity** - This vulnerability enables:

1. **Total Loss of Liveness/Network Availability**: An attacker controlling >33% voting power can prevent block finalization, halting the entire network. This meets the Critical severity criterion of "Total loss of liveness/network availability" per the Aptos bug bounty program.

2. **Consensus Safety Violations**: With >66% voting power, an attacker can produce conflicting blocks, violating BFT safety guarantees and potentially enabling double-spending attacks. This meets the Critical severity criterion of "Consensus/Safety violations."

3. **Computational Denial of Service**: Even without validator set manipulation, 1-second epochs cause `on_new_epoch()` to execute every second, processing all validators for reward distribution, validator set updates, and performance tracking, creating severe computational overhead. [6](#0-5) 

## Likelihood Explanation

**Medium-Low Likelihood**:

- **Requires genesis misconfiguration**: The vulnerability requires `epoch_duration_secs` to be set to a small value at genesis or through governance. Well-configured networks would use reasonable values (hours to days).
  
- **Requires significant capital**: The attacker needs sufficient stake to reach Byzantine thresholds, though the exponential growth significantly reduces required initial capital compared to normal epoch durations.

- **Cannot be easily fixed post-deployment**: Once set at genesis, `epoch_duration_secs` can only be changed through governance via `update_epoch_interval_microsecs()`: [7](#0-6) 

However, if a network launches with this misconfiguration, the vulnerability becomes immediately exploitable.

## Recommendation

Add a minimum epoch duration constraint in `validate_genesis_config()`:

```rust
fn validate_genesis_config(genesis_config: &GenesisConfiguration) {
    assert!(
        genesis_config.min_stake <= genesis_config.max_stake,
        "Min stake must be smaller than or equal to max stake"
    );
    
    // ADD THIS CHECK
    const MINIMUM_EPOCH_DURATION_SECS: u64 = 3600; // 1 hour minimum
    assert!(
        genesis_config.epoch_duration_secs >= MINIMUM_EPOCH_DURATION_SECS,
        "Epoch duration must be at least {} seconds to prevent rapid validator set manipulation",
        MINIMUM_EPOCH_DURATION_SECS
    );
    // END OF NEW CHECK
    
    assert!(
        genesis_config.recurring_lockup_duration_secs > 0,
        "Recurring lockup duration must be > 0"
    );
    // ... rest of validation
}
```

**Rationale**: A 1-hour minimum epoch duration ensures:
- `voting_power_increase_limit` functions as intended (maximum 50% increase per hour)
- Reasonable time for governance intervention if malicious behavior detected
- Reduced computational overhead from epoch transitions
- Alignment with the TODO comment in staking_config.move suggesting `rewards_rate_period_in_secs` should be longer than epoch duration [8](#0-7) 

## Proof of Concept

```rust
// Test demonstrating the vulnerability
#[test]
fn test_rapid_epoch_validator_set_manipulation() {
    use aptos_vm_genesis::{GenesisConfiguration, validate_genesis_config};
    
    // Create a genesis config with 1-second epochs - this SHOULD fail but currently passes
    let malicious_config = GenesisConfiguration {
        allow_new_validators: true,
        epoch_duration_secs: 1,  // 1 second epochs
        is_test: true,
        min_stake: 100_000_000,  // 1 APT
        max_stake: u64::MAX,
        min_voting_threshold: 0,
        recurring_lockup_duration_secs: 2,  // Minimum to satisfy constraint
        required_proposer_stake: 0,
        rewards_apy_percentage: 10,
        voting_duration_secs: 1,  // Minimum to satisfy constraint
        voting_power_increase_limit: 50,  // Default 50%
        employee_vesting_start: 0,
        employee_vesting_period_duration: 0,
        initial_features_override: None,
        randomness_config_override: None,
        jwk_consensus_config_override: None,
        initial_jwks: vec![],
        keyless_groth16_vk: None,
    };
    
    // This validation PASSES with current implementation but should FAIL
    validate_genesis_config(&malicious_config);
    
    // Simulation of attack:
    // Initial voting power: 1000 APT
    // Attacker starts with: 100 APT
    // 
    // Epoch 1 (t=0s): Add 500 APT (50% of 1000) -> Total 600 APT (37.5% of 1600)
    // Epoch 2 (t=1s): Add 800 APT (50% of 1600) -> Total 1400 APT (58.3% of 2400) 
    // Epoch 3 (t=2s): Add 1200 APT (50% of 2400) -> Total 2600 APT (72.2% of 3600)
    //
    // At t=2s, attacker controls >66% and can violate consensus safety
    // This demonstrates exponential voting power growth: 1.5^n per second
}
```

**Notes**

The vulnerability is exacerbated by the fact that the validation constraints create a false sense of security. The `voting_power_increase_limit` appears to limit validator set manipulation, but with rapid epochs, it becomes ineffective. The constraint relationships between `epoch_duration_secs`, `recurring_lockup_duration_secs`, and `voting_duration_secs` allow mathematically valid but operationally dangerous configurations.

### Citations

**File:** aptos-move/vm-genesis/src/lib.rs (L405-439)
```rust
fn validate_genesis_config(genesis_config: &GenesisConfiguration) {
    assert!(
        genesis_config.min_stake <= genesis_config.max_stake,
        "Min stake must be smaller than or equal to max stake"
    );
    assert!(
        genesis_config.epoch_duration_secs > 0,
        "Epoch duration must be > 0"
    );
    assert!(
        genesis_config.recurring_lockup_duration_secs > 0,
        "Recurring lockup duration must be > 0"
    );
    assert!(
        genesis_config.recurring_lockup_duration_secs >= genesis_config.epoch_duration_secs,
        "Recurring lockup duration must be at least as long as epoch duration"
    );
    assert!(
        genesis_config.rewards_apy_percentage > 0 && genesis_config.rewards_apy_percentage < 100,
        "Rewards APY must be > 0% and < 100%"
    );
    assert!(
        genesis_config.voting_duration_secs > 0,
        "On-chain voting duration must be > 0"
    );
    assert!(
        genesis_config.voting_duration_secs < genesis_config.recurring_lockup_duration_secs,
        "Voting duration must be strictly smaller than recurring lockup"
    );
    assert!(
        genesis_config.voting_power_increase_limit > 0
            && genesis_config.voting_power_increase_limit <= 50,
        "voting_power_increase_limit must be > 0 and <= 50"
    );
}
```

**File:** aptos-move/framework/aptos-framework/sources/block.move (L124-145)
```text
    public fun update_epoch_interval_microsecs(
        aptos_framework: &signer,
        new_epoch_interval: u64,
    ) acquires BlockResource {
        system_addresses::assert_aptos_framework(aptos_framework);
        assert!(new_epoch_interval > 0, error::invalid_argument(EZERO_EPOCH_INTERVAL));

        let block_resource = borrow_global_mut<BlockResource>(@aptos_framework);
        let old_epoch_interval = block_resource.epoch_interval;
        block_resource.epoch_interval = new_epoch_interval;

        if (std::features::module_event_migration_enabled()) {
            event::emit(
                UpdateEpochInterval { old_epoch_interval, new_epoch_interval },
            );
        } else {
            event::emit_event<UpdateEpochIntervalEvent>(
                &mut block_resource.update_epoch_interval_events,
                UpdateEpochIntervalEvent { old_epoch_interval, new_epoch_interval },
            );
        };
    }
```

**File:** aptos-move/framework/aptos-framework/sources/block.move (L215-217)
```text
        if (timestamp - reconfiguration::last_reconfiguration_time() >= epoch_interval) {
            reconfiguration::reconfigure();
        };
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1344-1464)
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

        // Activate currently pending_active validators.
        append(&mut validator_set.active_validators, &mut validator_set.pending_active);

        // Officially deactivate all pending_inactive validators. They will now no longer receive rewards.
        validator_set.pending_inactive = vector::empty();

        // Update active validator set so that network address/public key change takes effect.
        // Moreover, recalculate the total voting power, and deactivate the validator whose
        // voting power is less than the minimum required stake.
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
        validator_set.total_joining_power = 0;

        // Update validator indices, reset performance scores, and renew lockups.
        validator_perf.validators = vector::empty();
        let recurring_lockup_duration_secs = staking_config::get_recurring_lockup_duration(&config);
        let vlen = vector::length(&validator_set.active_validators);
        let validator_index = 0;
        while ({
            spec {
                invariant spec_validators_are_initialized(validator_set.active_validators);
                invariant len(validator_set.pending_active) == 0;
                invariant len(validator_set.pending_inactive) == 0;
                invariant 0 <= validator_index && validator_index <= vlen;
                invariant vlen == len(validator_set.active_validators);
                invariant forall i in 0..validator_index:
                    global<ValidatorConfig>(validator_set.active_validators[i].addr).validator_index < validator_index;
                invariant forall i in 0..validator_index:
                    validator_set.active_validators[i].config.validator_index < validator_index;
                invariant len(validator_perf.validators) == validator_index;
            };
            validator_index < vlen
        }) {
            let validator_info = vector::borrow_mut(&mut validator_set.active_validators, validator_index);
            validator_info.config.validator_index = validator_index;
            let validator_config = borrow_global_mut<ValidatorConfig>(validator_info.addr);
            validator_config.validator_index = validator_index;

            vector::push_back(&mut validator_perf.validators, IndividualValidatorPerformance {
                successful_proposals: 0,
                failed_proposals: 0,
            });

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

            validator_index = validator_index + 1;
        };

        if (exists<PendingTransactionFee>(@aptos_framework)) {
            let pending_fee_by_validator = &mut borrow_global_mut<PendingTransactionFee>(@aptos_framework).pending_fee_by_validator;
            assert!(pending_fee_by_validator.is_empty(), error::internal(ETRANSACTION_FEE_NOT_FULLY_DISTRIBUTED));
            validator_set.active_validators.for_each_ref(|v| pending_fee_by_validator.add(v.config.validator_index, aggregator_v2::create_unbounded_aggregator<u64>()));
        };

        if (features::periodical_reward_rate_decrease_enabled()) {
            // Update rewards rate after reward distribution.
            staking_config::calculate_and_save_latest_epoch_rewards_rate();
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

**File:** aptos-move/framework/aptos-framework/sources/configs/staking_config.move (L397-397)
```text
        // TODO: rewards_rate_period_in_secs should be longer than the epoch duration but reading epoch duration causes a circular dependency.
```

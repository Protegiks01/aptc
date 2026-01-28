# Audit Report

## Title
Maximum Stake Bypass During Epoch Transition Undermines Sybil Resistance

## Summary
The `on_new_epoch()` function in the staking module fails to validate the `maximum_stake` limit when activating validators from the `pending_active` queue. This allows validators to exceed the maximum voting power constraint if `maximum_stake` is reduced via governance between when they join the validator set and when they are activated, directly undermining the sybil resistance mechanism.

## Finding Description

The Aptos staking system enforces sybil resistance through two key parameters: `minimum_stake` (economic barrier to entry) and `maximum_stake` (power concentration limit). The `StakingConfig` documentation explicitly states that maximum_stake should limit validator voting power "at the start of any epoch". [1](#0-0) 

When validators join the validator set via `join_validator_set_internal()`, both limits are properly validated. [2](#0-1) 

However, when `on_new_epoch()` activates pending validators during epoch transitions, it explicitly discards the `maximum_stake` value using an underscore. [3](#0-2) 

The function only validates `minimum_stake` when filtering validators. [4](#0-3) 

**Attack Scenario:**
1. Validator joins with 100M tokens when `maximum_stake = 100M` (passes validation at join time)
2. Validator enters `pending_active` state, waiting for next epoch
3. Governance legitimately reduces `maximum_stake` to 50M via `update_required_stake()` [5](#0-4)  to improve decentralization
4. `on_new_epoch()` is called at epoch boundary, appending pending validators to the active set [6](#0-5) 
5. Only minimum stake check executes - no maximum stake validation
6. Validator activates with 100M voting power, 2x the intended maximum

This same vulnerability exists in `next_validator_consensus_infos()` which also discards `maximum_stake` [7](#0-6)  and only validates minimum. [8](#0-7) 

## Impact Explanation

**Severity: Medium** - "Limited Protocol Violations"

This vulnerability violates the documented security guarantee that maximum_stake should limit voting power "at the start of any epoch". The impact includes:

1. **Power Concentration**: Validators can hold voting power exceeding the protocol-defined maximum limit, concentrating power beyond intended bounds
2. **Governance Bypass**: Security improvements via `maximum_stake` reduction can be circumvented by timing validator joins
3. **Asymmetric Advantage**: Attackers monitoring governance can strategically join before limit reductions, gaining disproportionate power over honest validators capped at the new limit
4. **Decentralization Undermined**: The purpose of `maximum_stake` is to enforce power distribution; this bypass defeats that fundamental security control

While this doesn't directly cause fund loss or network halt, it undermines a documented consensus security mechanism. The asymmetry between `minimum_stake` enforcement (present) and `maximum_stake` enforcement (absent) clearly indicates unintended behavior.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly exploitable because:

1. **Public Information**: Governance proposals are publicly visible on-chain before execution
2. **No Special Access Required**: Any party with sufficient tokens can join the validator set
3. **Predictable Timing Window**: Validators remain in `pending_active` for exactly one epoch, providing a predictable exploitation window
4. **Legitimate Trigger**: Governance reducing `maximum_stake` to improve decentralization is a legitimate and expected action
5. **No Detection**: The bypass occurs silently during normal epoch transitions without any error or event

An attacker only needs to:
- Monitor governance proposals for `update_required_stake` calls
- Join the validator set at current `maximum_stake` before the proposal executes
- Wait for the next epoch transition to automatically gain excessive voting power

## Recommendation

The fix requires validating `maximum_stake` in addition to `minimum_stake` during epoch transitions. Modify `on_new_epoch()` to retrieve and validate both stake limits:

```move
// Current code (line 1373):
let (minimum_stake, _) = staking_config::get_required_stake(&config);

// Fixed code:
let (minimum_stake, maximum_stake) = staking_config::get_required_stake(&config);

// Then in the validation loop (around line 1391), add maximum stake check:
if (new_validator_info.voting_power >= minimum_stake && 
    new_validator_info.voting_power <= maximum_stake) {
    // existing code to add validator
}
```

The same fix should be applied to `next_validator_consensus_infos()` at line 1478 and its validation at line 1539.

Alternatively, if the intended behavior is to cap voting power rather than reject validators, implement capping logic in `generate_validator_info()` to enforce the maximum_stake limit on voting power calculation.

## Proof of Concept

The vulnerability can be demonstrated through the following sequence of operations (conceptual Move test):

```move
#[test(aptos_framework = @0x1, validator = @0x123)]
public fun test_maximum_stake_bypass(aptos_framework: signer, validator: signer) {
    // 1. Initialize staking with maximum_stake = 100M
    staking_config::initialize(&aptos_framework, 1000000, 100000000, ...);
    
    // 2. Validator joins with 100M stake (passes validation)
    stake::initialize_stake_owner(&validator, ...);
    stake::add_stake(&validator, 100000000);
    stake::join_validator_set(&validator, validator_addr);
    // Validator is now in pending_active with 100M stake
    
    // 3. Governance reduces maximum_stake to 50M
    staking_config::update_required_stake(&aptos_framework, 1000000, 50000000);
    
    // 4. Trigger epoch transition
    stake::on_new_epoch();
    
    // 5. Verify: Validator is now active with 100M voting power
    // This exceeds the new maximum_stake of 50M
    let validator_info = get_validator_info(validator_addr);
    assert!(validator_info.voting_power == 100000000, 0); // Should be capped at 50M but isn't
}
```

This demonstrates that validators can bypass maximum_stake limits through timing their joins before governance reductions.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/configs/staking_config.move (L54-56)
```text
        // A validator can only stake at most this amount. Any larger stake will be rejected.
        // If after joining the validator set and at the start of any epoch, a validator's stake exceeds this amount,
        // their voting power and rewards would only be issued for the max stake amount.
```

**File:** aptos-move/framework/aptos-framework/sources/configs/staking_config.move (L274-284)
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
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1073-1076)
```text
        let (minimum_stake, maximum_stake) = staking_config::get_required_stake(&config);
        let voting_power = get_next_epoch_voting_power(stake_pool);
        assert!(voting_power >= minimum_stake, error::invalid_argument(ESTAKE_TOO_LOW));
        assert!(voting_power <= maximum_stake, error::invalid_argument(ESTAKE_TOO_HIGH));
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1364-1364)
```text
        append(&mut validator_set.active_validators, &mut validator_set.pending_active);
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1373-1373)
```text
        let (minimum_stake, _) = staking_config::get_required_stake(&config);
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1391-1391)
```text
            if (new_validator_info.voting_power >= minimum_stake) {
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1478-1478)
```text
        let (minimum_stake, _) = staking_config::get_required_stake(&staking_config);
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1539-1539)
```text
            if (new_voting_power >= minimum_stake) {
```

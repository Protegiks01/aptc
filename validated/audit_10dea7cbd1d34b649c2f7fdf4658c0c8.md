# Audit Report

## Title
Maximum Stake Bypass During Epoch Transition Undermines Sybil Resistance

## Summary
The `on_new_epoch()` function in the staking module fails to validate the `maximum_stake` limit when activating validators from the `pending_active` queue. This allows validators to exceed the maximum voting power constraint if `maximum_stake` is reduced via governance between when they join the validator set and when they are activated, directly undermining the sybil resistance mechanism.

## Finding Description

The Aptos staking system enforces sybil resistance through two key parameters: `minimum_stake` (economic barrier to entry) and `maximum_stake` (power concentration limit). The `StakingConfig` documentation explicitly states that maximum_stake should limit validator voting power "at the start of any epoch" [1](#0-0) .

When validators join the validator set via `join_validator_set_internal()`, both limits are properly validated [2](#0-1) .

However, when `on_new_epoch()` activates pending validators during epoch transitions, it explicitly discards the `maximum_stake` value using an underscore [3](#0-2)  and only validates `minimum_stake` [4](#0-3) .

**Attack Scenario:**
1. Validator joins with 100M tokens when `maximum_stake = 100M` (passes validation at join time)
2. Validator enters `pending_active` state, waiting for next epoch
3. Governance legitimately reduces `maximum_stake` to 50M via `update_required_stake()` [5](#0-4)  to improve decentralization
4. `on_new_epoch()` is called at epoch boundary, appending pending validators to the active set [6](#0-5) 
5. Only minimum stake check executes - no maximum stake validation
6. Validator activates with 100M voting power, 2x the intended maximum

This same vulnerability exists in `next_validator_consensus_infos()` which also discards `maximum_stake` [7](#0-6)  and only validates minimum [8](#0-7) .

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

Modify `on_new_epoch()` to validate both `minimum_stake` AND `maximum_stake` when activating pending validators. Replace line 1373:

```move
let (minimum_stake, _) = staking_config::get_required_stake(&config);
```

With:

```move
let (minimum_stake, maximum_stake) = staking_config::get_required_stake(&config);
```

Then modify the validation at line 1391 to check both bounds:

```move
if (new_validator_info.voting_power >= minimum_stake && new_validator_info.voting_power <= maximum_stake) {
```

Apply the same fix to `next_validator_consensus_infos()` at lines 1478 and 1539.

Alternatively, consider capping voting power to `maximum_stake` as suggested in the `StakingConfig` documentation comment, rather than rejecting validators that exceed it.

## Proof of Concept

```move
#[test(aptos_framework = @0x1, validator = @0x123)]
public fun test_maximum_stake_bypass_during_epoch_transition(
    aptos_framework: &signer,
    validator: &signer
) {
    // Setup: Initialize staking with max_stake = 100M
    staking_config::initialize_for_test(aptos_framework, 1_000_000, 100_000_000, 7200, true, 1, 100, 10);
    stake::initialize_for_test(aptos_framework);
    
    // Validator joins with 100M stake (passes validation)
    stake::initialize_validator(validator, consensus_key, proof, network_addr, fullnode_addr);
    stake::add_stake(validator, 100_000_000);
    stake::join_validator_set(validator, signer::address_of(validator));
    
    // Verify validator is in pending_active
    assert!(stake::get_validator_state(signer::address_of(validator)) == VALIDATOR_STATUS_PENDING_ACTIVE, 0);
    
    // Governance reduces max_stake to 50M
    staking_config::update_required_stake(aptos_framework, 1_000_000, 50_000_000);
    
    // Epoch transition activates validator
    stake::on_new_epoch();
    
    // Validator is now active with 100M voting power (2x the maximum!)
    assert!(stake::get_validator_state(signer::address_of(validator)) == VALIDATOR_STATUS_ACTIVE, 1);
    assert!(stake::get_current_epoch_voting_power(signer::address_of(validator)) == 100_000_000, 2);
    // Should have been rejected or capped at 50M, but bypass allows 100M
}
```

## Notes

This vulnerability represents a clear asymmetry in validation logic where `minimum_stake` is enforced during epoch transitions but `maximum_stake` is not, despite the documentation explicitly stating both should be enforced. The use of underscore `_` to discard the `maximum_stake` value appears to be an oversight rather than intentional design, especially given the error code `ESTAKE_TOO_HIGH` exists but is never used during epoch transitions.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/configs/staking_config.move (L54-56)
```text
        // A validator can only stake at most this amount. Any larger stake will be rejected.
        // If after joining the validator set and at the start of any epoch, a validator's stake exceeds this amount,
        // their voting power and rewards would only be issued for the max stake amount.
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

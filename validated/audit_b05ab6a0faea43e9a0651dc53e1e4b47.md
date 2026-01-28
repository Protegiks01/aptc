# Audit Report

## Title
Maximum Stake Bypass During Epoch Transition Undermines Sybil Resistance

## Summary
The `on_new_epoch()` function in the staking module fails to validate the `maximum_stake` limit when activating validators from the `pending_active` queue, allowing validators to exceed voting power constraints if `maximum_stake` is reduced via governance between validator registration and activation.

## Finding Description

The Aptos staking system enforces sybil resistance through `minimum_stake` and `maximum_stake` parameters. When validators join the validator set via `join_validator_set_internal()`, both limits are validated: [1](#0-0) 

However, during epoch transitions, `on_new_epoch()` explicitly discards the `maximum_stake` value and only validates `minimum_stake`: [2](#0-1) 

The pending validators are appended to the active set without maximum stake validation: [3](#0-2) 

Only the minimum stake requirement is enforced during the filtering process: [4](#0-3) 

**Attack Scenario:**
1. Validator joins with 100M tokens when `maximum_stake = 100M` (passes validation at line 1076)
2. Validator enters `pending_active` state, awaiting next epoch
3. Governance legitimately reduces `maximum_stake` to 50M via `update_required_stake()`
4. `on_new_epoch()` executes at epoch boundary
5. Pending validator activates without maximum stake validation (line 1391 only checks minimum)
6. Validator operates with 100M voting power, exceeding the 50M limit by 2x

The same vulnerability exists in `next_validator_consensus_infos()`: [5](#0-4) [6](#0-5) 

The Rust epoch verification code accepts validator sets from the Move framework without independent maximum_stake validation: [7](#0-6) 

## Impact Explanation

**Severity: Medium** (Note: Report claims High, but evidence suggests Medium per bounty categories)

This vulnerability creates a protocol violation affecting sybil resistance:

1. **Power Concentration**: Validators can maintain voting power exceeding the governance-approved maximum limit
2. **Governance Bypass**: Security improvements via `maximum_stake` reduction can be circumvented through timing
3. **Asymmetric Advantage**: Sophisticated actors monitoring governance can strategically join before limit reductions, gaining disproportionate voting power over honest validators capped at new limits
4. **Decentralization Impact**: Undermines the core purpose of `maximum_stake` - preventing excessive power concentration

While this does not cause direct fund loss, consensus failure, or network halt, it does violate the staking security invariant. The asymmetry between join-time validation (maximum_stake enforced) and activation-time validation (maximum_stake ignored) indicates unintended behavior rather than deliberate design.

This aligns with **Medium severity** ("Limited protocol violations") rather than High severity per Aptos bounty categories.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability is exploitable through predictable mechanisms:

1. **Public Information**: Governance proposals are visible on-chain before execution
2. **No Special Access**: Any party with sufficient capital can join the validator set
3. **Timing Window**: Validators remain in `pending_active` for exactly one epoch (predictable)
4. **Legitimate Trigger**: Governance reducing `maximum_stake` for security is expected protocol evolution
5. **Silent Execution**: The bypass occurs during normal epoch transitions without alerts

Exploitation requires:
- Monitoring governance proposals for `update_required_stake` calls
- Joining validator set at current `maximum_stake` before proposal execution  
- Waiting one epoch for automatic activation with excessive voting power

The attack is feasible but requires timing coordination and significant capital investment.

## Recommendation

Add maximum stake validation during validator activation in `on_new_epoch()`:

```move
let (minimum_stake, maximum_stake) = staking_config::get_required_stake(&config);
// ... existing code ...
if (new_validator_info.voting_power >= minimum_stake && 
    new_validator_info.voting_power <= maximum_stake) {
    // Add validator to next epoch
}
```

Apply the same fix to `next_validator_consensus_infos()` at line 1478 and 1539.

Alternatively, implement a grace period mechanism where validators exceeding new limits are given one epoch to reduce stake before forced deactivation.

## Proof of Concept

```move
#[test(aptos_framework = @aptos_framework, validator = @0x123)]
public fun test_maximum_stake_bypass(
    aptos_framework: &signer,
    validator: &signer
) {
    // Setup: Initialize with maximum_stake = 100M
    staking_config::update_required_stake(aptos_framework, 1_000_000, 100_000_000);
    
    // Validator joins with 100M (passes validation)
    stake::join_validator_set(validator);
    assert!(stake::get_validator_state(@0x123) == VALIDATOR_STATUS_PENDING_ACTIVE);
    
    // Governance reduces maximum_stake to 50M
    staking_config::update_required_stake(aptos_framework, 1_000_000, 50_000_000);
    
    // Epoch transition activates validator
    stake::on_new_epoch();
    
    // Validator is now active with 100M, exceeding 50M limit
    assert!(stake::get_validator_state(@0x123) == VALIDATOR_STATUS_ACTIVE);
    let voting_power = stake::get_voting_power(@0x123);
    assert!(voting_power == 100_000_000); // Exceeds maximum_stake!
}
```

**Note**: While the core vulnerability is valid based on code analysis, the actual exploitability depends on governance timing and validator behavior in production environments.

### Citations

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

**File:** types/src/validator_verifier.rs (L115-127)
```rust
impl TryFrom<ValidatorConsensusInfoMoveStruct> for ValidatorConsensusInfo {
    type Error = anyhow::Error;

    fn try_from(value: ValidatorConsensusInfoMoveStruct) -> Result<Self, Self::Error> {
        let ValidatorConsensusInfoMoveStruct {
            addr,
            pk_bytes,
            voting_power,
        } = value;
        let public_key = bls12381_keys::PublicKey::try_from(pk_bytes.as_slice())?;
        Ok(Self::new(addr, public_key, voting_power))
    }
}
```

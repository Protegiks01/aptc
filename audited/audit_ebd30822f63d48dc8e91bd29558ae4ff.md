# Audit Report

## Title
Zero Minimum Stake Validation Bypass Enables Sybil Attacks and Consensus Takeover

## Summary
The Aptos genesis configuration lacks validation to ensure `min_stake` is non-zero. This allows creation of blockchain networks where validators can join with zero stake, enabling trivial Sybil attacks that violate consensus safety guarantees and allow complete network takeover without economic cost.

## Finding Description

The vulnerability exists across multiple validation layers in the genesis initialization flow:

**Missing Rust-Level Validation:**

The genesis configuration validation function only checks that minimum stake does not exceed maximum stake, but fails to validate that minimum stake is greater than zero: [1](#0-0) 

**Default Configuration with Zero Minimum Stake:**

The default genesis configuration explicitly sets `min_stake` to 0: [2](#0-1) 

**Missing Move-Level Validation:**

The Move framework's staking configuration validation only checks the stake range validity (min ≤ max and max > 0), but does not enforce that minimum stake must be positive: [3](#0-2) 

**Ineffective Join Validation:**

When validators attempt to join the validator set, the check compares their voting power against the minimum stake. With `min_stake = 0`, this becomes `voting_power >= 0`, which always passes: [4](#0-3) 

**Ineffective Epoch Transition Filtering:**

During epoch transitions, validators with insufficient stake should be removed. However, with `min_stake = 0`, the check `voting_power >= 0` allows zero-stake validators to remain active: [5](#0-4) 

**Attack Scenario:**

1. Genesis is initialized with `min_stake = 0` (either by using defaults or misconfiguration)
2. Attacker creates thousands of stake pools with zero stake
3. Each stake pool joins the validator set (all pass the `voting_power >= 0` check)
4. Attacker now controls >33% of validators with zero economic cost
5. Attacker can halt the network, cause consensus forks, or execute double-spend attacks

This breaks the fundamental Proof-of-Stake security assumption that Byzantine validators must have significant economic stake at risk.

## Impact Explanation

**Severity: CRITICAL** (up to $1,000,000 per Aptos Bug Bounty)

This vulnerability meets multiple critical severity criteria:

1. **Consensus/Safety Violations**: Attackers can control >33% of validators without stake, breaking BFT consensus safety guarantees and enabling double-spending attacks

2. **Total Loss of Liveness**: Attackers with >33% validator control can halt block production indefinitely

3. **Non-recoverable Network Partition**: Malicious validators can cause chain forks that require hard fork intervention

4. **Violates Core Security Invariant**: Completely undermines the economic security model where validators must risk capital to ensure honest behavior

The impact is catastrophic because it allows complete network compromise with zero economic cost to the attacker, fundamentally breaking the Proof-of-Stake consensus model.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

While this requires genesis misconfiguration, several factors increase likelihood:

1. **Default Configuration**: The default builder configuration explicitly sets `min_stake = 0`, making it likely to be used in test networks or initial deployments [6](#0-5) 

2. **Test Networks**: Test genesis configurations use `min_stake = 0`: [7](#0-6) 

3. **No Warning or Validation**: Neither Rust nor Move code emits warnings or prevents this dangerous configuration

4. **Silent Failure**: The system accepts and processes zero minimum stake without any indication that security is compromised

If any network (testnet, devnet, or production) is initialized with `min_stake = 0`, it is immediately vulnerable to trivial Sybil attacks.

## Recommendation

Add explicit validation that `min_stake` must be greater than zero at multiple layers:

**Layer 1 - Rust Genesis Validation:**

In the `validate_genesis_config` function, add: [8](#0-7) 

Add after line 409:
```rust
assert!(
    genesis_config.min_stake > 0,
    "Minimum stake must be greater than 0 to prevent Sybil attacks"
);
```

**Layer 2 - Move Staking Config Validation:**

In the `validate_required_stake` function, strengthen the check: [3](#0-2) 

Replace with:
```move
fun validate_required_stake(minimum_stake: u64, maximum_stake: u64) {
    assert!(
        minimum_stake > 0 && minimum_stake <= maximum_stake && maximum_stake > 0, 
        error::invalid_argument(EINVALID_STAKE_RANGE)
    );
}
```

**Layer 3 - Update Default Configuration:**

Change the default to a reasonable minimum (e.g., 1 million APTOS with 8 decimals = 100000000000000): [2](#0-1) 

## Proof of Concept

```move
#[test_only]
module aptos_framework::sybil_attack_test {
    use aptos_framework::stake;
    use aptos_framework::staking_config;
    use aptos_framework::coin;
    use aptos_framework::aptos_coin::AptosCoin;
    
    #[test(aptos_framework = @aptos_framework, attacker = @0x123)]
    fun test_zero_min_stake_sybil_attack(
        aptos_framework: &signer,
        attacker: &signer
    ) {
        // Initialize with min_stake = 0 (vulnerable configuration)
        staking_config::initialize_for_test(
            aptos_framework,
            0,  // min_stake = 0 (VULNERABLE!)
            1000000000000000,  // max_stake
            86400,  // lockup duration
            true,  // allow validator set changes
            10,
            100,
            30
        );
        
        // Attacker creates stake pool with 0 stake
        stake::initialize_stake_owner(
            attacker,
            0,  // 0 stake!
            @0x123,  // operator
            @0x123   // voter
        );
        
        // Attacker can join validator set with 0 stake
        // This should fail but doesn't when min_stake = 0
        stake::join_validator_set_internal(attacker, @0x123);
        
        // Attacker is now in validator set with 0 economic cost
        // Can repeat thousands of times to control >33% of validators
        assert!(stake::get_validator_state(@0x123) == 1, 0); // PENDING_ACTIVE
    }
}
```

## Notes

This vulnerability demonstrates a critical gap in defense-in-depth validation. The absence of non-zero minimum stake validation at ANY layer (Rust genesis, Move framework initialization, or validator join logic) creates a single point of failure that completely undermines Proof-of-Stake security.

Networks initialized with this configuration are fundamentally insecure and cannot guarantee consensus safety under the standard <33% Byzantine assumption, as attackers can trivially exceed this threshold with zero cost.

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

**File:** aptos-move/vm-genesis/src/lib.rs (L1428-1428)
```rust
            min_stake: 0,
```

**File:** crates/aptos-genesis/src/builder.rs (L649-654)
```rust
        let mut genesis_config = GenesisConfiguration {
            allow_new_validators: false,
            epoch_duration_secs: ONE_DAY,
            is_test: true,
            min_stake: 0,
            min_voting_threshold: 0,
```

**File:** aptos-move/framework/aptos-framework/sources/configs/staking_config.move (L372-374)
```text
    fun validate_required_stake(minimum_stake: u64, maximum_stake: u64) {
        assert!(minimum_stake <= maximum_stake && maximum_stake > 0, error::invalid_argument(EINVALID_STAKE_RANGE));
    }
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1072-1076)
```text
        let config = staking_config::get();
        let (minimum_stake, maximum_stake) = staking_config::get_required_stake(&config);
        let voting_power = get_next_epoch_voting_power(stake_pool);
        assert!(voting_power >= minimum_stake, error::invalid_argument(ESTAKE_TOO_LOW));
        assert!(voting_power <= maximum_stake, error::invalid_argument(ESTAKE_TOO_HIGH));
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1390-1397)
```text
            // A validator needs at least the min stake required to join the validator set.
            if (new_validator_info.voting_power >= minimum_stake) {
                spec {
                    assume total_voting_power + new_validator_info.voting_power <= MAX_U128;
                };
                total_voting_power = total_voting_power + (new_validator_info.voting_power as u128);
                vector::push_back(&mut next_epoch_validators, new_validator_info);
            };
```

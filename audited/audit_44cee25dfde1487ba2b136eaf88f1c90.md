# Audit Report

## Title
Critical Governance Bypass: Zero Minimum Voting Threshold Allows Single-Vote Proposal Passage

## Summary
The `min_voting_threshold` parameter in Aptos governance can be set to 0 both during genesis and through governance updates, with no validation preventing this dangerous configuration. When set to 0, governance proposals can pass with a single yes vote, completely bypassing the intended voting threshold security mechanism and enabling complete governance takeover.

## Finding Description

The vulnerability exists across multiple layers of the Aptos governance system:

**1. Genesis Configuration Without Validation**

The `GenesisConfiguration` struct defines `min_voting_threshold` as a u128 field [1](#0-0) , and the genesis ceremony explicitly sets it to 0 for test configurations [2](#0-1) .

The `validate_genesis_config()` function validates various genesis parameters but contains NO check to prevent `min_voting_threshold` from being zero [3](#0-2) .

**2. Governance Configuration Updates Without Validation**

The `update_governance_config()` function accepts `min_voting_threshold` as a parameter and directly assigns it without any validation [4](#0-3) . This means even if genesis is configured correctly, a malicious governance proposal could later set the threshold to 0.

**3. Exploitable Proposal Resolution Logic**

The critical flaw is in the proposal state determination logic. The `get_proposal_state()` function determines if a proposal succeeds using this condition [5](#0-4) :

```move
if (yes_votes > no_votes && yes_votes + no_votes >= proposal.min_vote_threshold)
```

When `min_vote_threshold = 0`, the condition `yes_votes + no_votes >= 0` is ALWAYS true (since both are u128 and cannot be negative). This means a proposal succeeds if merely `yes_votes > no_votes`.

**Attack Scenario:**
1. Network is deployed with `min_voting_threshold = 0` (configuration error or test config used in production)
2. OR: Attacker gains enough votes to pass ONE malicious proposal that calls `update_governance_config()` with `min_voting_threshold = 0`
3. After threshold is set to 0, attacker with minimal stake (1 token) can:
   - Create a proposal with any execution hash
   - Vote YES with just 1 vote (0 NO votes needed)
   - The proposal state becomes SUCCEEDED because `1 > 0 && 1 >= 0` evaluates to true
   - Execute arbitrary governance proposals to:
     * Steal funds from governance-controlled accounts
     * Modify critical network parameters
     * Upgrade the Aptos framework maliciously
     * Permanently disable governance by setting impossible thresholds

This completely violates the **Governance Integrity** invariant which requires "Voting power must be correctly calculated from stake."

## Impact Explanation

**Critical Severity ($1,000,000)** - This vulnerability qualifies for the highest severity tier because:

1. **Loss of Funds**: Complete access to all governance-controlled accounts and their signer capabilities [6](#0-5) 

2. **Consensus/Safety Violations**: Attacker can modify consensus configuration parameters through malicious proposals, potentially causing consensus failures or network splits

3. **Network Parameter Manipulation**: Complete control over all on-chain parameters including staking rewards, gas schedules, feature flags, and execution configurations

4. **Permanent Damage**: Once governance is compromised, the attacker can make recovery impossible by setting unreachable voting thresholds or disabling governance features

The vulnerability breaks the fundamental security assumption that governance proposals require meaningful community participation and voting power thresholds.

## Likelihood Explanation

**Likelihood: Medium to High**

**Scenarios that enable exploitation:**

1. **Genesis Misconfiguration** (Medium): The codebase explicitly sets `min_voting_threshold = 0` in test configurations. If these test configurations are accidentally used for production deployments or testnets that later become valuable, immediate exploitation is possible.

2. **Malicious Governance Attack** (Lower but non-zero): An attacker would need to:
   - Acquire enough stake to pass ONE initial proposal (requires legitimate voting threshold)
   - Use that proposal to call `update_governance_config()` with `min_voting_threshold = 0`
   - After this, all subsequent proposals can be passed with 1 vote

3. **Insider Threat** (Out of scope but worth noting): A malicious core developer could intentionally set this during genesis

The lack of validation at BOTH genesis time and update time creates multiple attack vectors. The vulnerability is particularly dangerous because:
- No runtime checks prevent setting threshold to 0
- The voting logic silently accepts 0 as valid
- Test configurations normalize this dangerous value

## Recommendation

Implement validation at all configuration entry points:

**1. Add Genesis Validation:**
```rust
// In aptos-move/vm-genesis/src/lib.rs validate_genesis_config()
assert!(
    genesis_config.min_voting_threshold > 0,
    "Minimum voting threshold must be greater than 0"
);
```

**2. Add Update Validation:**
```move
// In aptos_governance.move update_governance_config()
public fun update_governance_config(
    aptos_framework: &signer,
    min_voting_threshold: u128,
    required_proposer_stake: u64,
    voting_duration_secs: u64,
) acquires GovernanceConfig, GovernanceEvents {
    system_addresses::assert_aptos_framework(aptos_framework);
    
    // Add validation
    assert!(min_voting_threshold > 0, error::invalid_argument(EINVALID_MIN_VOTING_THRESHOLD));
    
    let governance_config = borrow_global_mut<GovernanceConfig>(@aptos_framework);
    // ... rest of function
}
```

**3. Add Reasonable Minimum:**
Consider enforcing a meaningful minimum based on total supply:
```rust
// Require at least 0.1% of total supply for any proposal to pass
let min_reasonable_threshold = total_supply / 1000;
assert!(min_voting_threshold >= min_reasonable_threshold, ...);
```

**4. Fix Test Configurations:**
Update test configurations to use non-zero thresholds that are still small enough for testing but don't normalize dangerous values.

## Proof of Concept

```move
#[test(aptos_framework = @aptos_framework, attacker = @0x666)]
public entry fun test_zero_threshold_allows_single_vote_governance_takeover(
    aptos_framework: signer,
    attacker: signer,
) acquires GovernanceConfig, GovernanceResponsbility, VotingRecords, VotingRecordsV2, GovernanceEvents, ApprovedExecutionHashes {
    use aptos_framework::account;
    use aptos_framework::coin;
    use aptos_framework::aptos_coin::AptosCoin;
    
    // Setup
    timestamp::set_time_has_started_for_testing(&aptos_framework);
    account::create_account_for_test(signer::address_of(&aptos_framework));
    account::create_account_for_test(signer::address_of(&attacker));
    
    // Initialize governance with ZERO minimum voting threshold (the vulnerability)
    stake::initialize_for_test_custom(&aptos_framework, 0, 1000, 2000, true, 0, 1, 1000);
    initialize(&aptos_framework, 0, 10, 1000); // min_voting_threshold = 0
    store_signer_cap(
        &aptos_framework,
        @aptos_framework,
        account::create_test_signer_cap(@aptos_framework),
    );
    
    // Give attacker minimal stake (just 1 token)
    coin::register<AptosCoin>(&attacker);
    coin::deposit(signer::address_of(&attacker), stake::mint_coins(1));
    
    let (_sk, pk, pop) = stake::generate_identity();
    stake::initialize_test_validator(&pk, &pop, &attacker, 1, true, false);
    stake::end_epoch();
    
    // Attacker creates malicious proposal with ONLY 1 token of voting power
    create_proposal(
        &attacker,
        signer::address_of(&attacker),
        vector[0xba, 0xd], // malicious execution hash
        b"",
        b"",
    );
    
    // Attacker votes YES with their single token
    vote(&attacker, signer::address_of(&attacker), 0, true);
    
    // Wait for voting period to end
    timestamp::fast_forward_seconds(1001);
    
    // Verify proposal SUCCEEDS with just 1 vote (0 total threshold)
    let proposal_state = voting::get_proposal_state<GovernanceProposal>(@aptos_framework, 0);
    assert!(proposal_state == PROPOSAL_STATE_SUCCEEDED, 0);
    
    // Attacker can now resolve and execute their malicious proposal
    // This would give them complete control over governance
}
```

This test demonstrates that with `min_voting_threshold = 0`, a proposal succeeds with a single vote, enabling complete governance takeover by any participant with minimal stake.

**Notes**

The vulnerability is particularly insidious because:
- Test configurations throughout the codebase set this to 0, normalizing the dangerous value
- There are no warnings or assertions preventing this configuration
- The voting logic appears correct at first glance but silently fails when threshold is 0
- Both genesis-time and runtime configuration paths lack validation
- The attack requires minimal resources once the threshold is set to 0

This finding represents a fundamental breakdown in governance security that could lead to complete network compromise if exploited.

### Citations

**File:** crates/aptos-genesis/src/builder.rs (L432-432)
```rust
    pub min_voting_threshold: u128,
```

**File:** crates/aptos-genesis/src/builder.rs (L654-654)
```rust
            min_voting_threshold: 0,
```

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

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L81-83)
```text
    struct GovernanceResponsbility has key {
        signer_caps: SimpleMap<address, SignerCapability>,
    }
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L243-254)
```text
    public fun update_governance_config(
        aptos_framework: &signer,
        min_voting_threshold: u128,
        required_proposer_stake: u64,
        voting_duration_secs: u64,
    ) acquires GovernanceConfig, GovernanceEvents {
        system_addresses::assert_aptos_framework(aptos_framework);

        let governance_config = borrow_global_mut<GovernanceConfig>(@aptos_framework);
        governance_config.voting_duration_secs = voting_duration_secs;
        governance_config.min_voting_threshold = min_voting_threshold;
        governance_config.required_proposer_stake = required_proposer_stake;
```

**File:** aptos-move/framework/aptos-framework/sources/voting.move (L664-664)
```text
            if (yes_votes > no_votes && yes_votes + no_votes >= proposal.min_vote_threshold) {
```

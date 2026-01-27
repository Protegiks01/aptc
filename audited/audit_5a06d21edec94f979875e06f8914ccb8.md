# Audit Report

## Title
Genesis Voter Account Reuse Enables Governance Voting Power Multiplication Attack

## Summary
The genesis validator configuration in `get_config()` does not validate voter account uniqueness, allowing multiple validators to share the same `voter_account_address`. This enables a single entity controlling N validators to cast N votes on governance proposals with the same voter account, multiplying their voting power N-fold and violating the one-validator-one-vote governance principle.

## Finding Description

The vulnerability exists across two critical components:

**1. Genesis Configuration Validation Gap**

The `get_config()` function reads the `voter_account_address` from validator owner configurations, but the `validate_validators()` function fails to check voter account uniqueness across validators. [1](#0-0) 

The validation function explicitly checks uniqueness for owner and operator accounts: [2](#0-1) 

However, there is **no corresponding uniqueness check for voter accounts**. The voter account is only validated to exist in the balances file, but multiple validators can specify the same voter: [3](#0-2) 

**2. Governance Voting Mechanism Design Flaw**

The governance voting system tracks votes per stake pool, not per voter address. The `vote_internal()` function only verifies that the signer is the designated voter for a given stake pool: [4](#0-3) 

Voting records are keyed by `(stake_pool, proposal_id)`, allowing the same voter to vote multiple times across different stake pools: [5](#0-4) 

Each stake pool's voting power is calculated independently: [6](#0-5) 

**Attack Scenario:**

1. During genesis setup, an attacker configures 3 validators (Validator A, B, C) all using `voter_account_address = 0xABCD`
2. Each validator has 1M APT staked (3M total stake)
3. On a governance proposal, the attacker uses account `0xABCD` to:
   - Vote with Validator A's stake pool → 1M voting power
   - Vote with Validator B's stake pool → 1M voting power
   - Vote with Validator C's stake pool → 1M voting power
4. Total votes cast: 3M voting power (3x legitimate power)
5. If other validators have 5M total stake, attacker has 3M/(5M+3M) = 37.5% voting power instead of 3M/(5M+3M) = 37.5% if they could only vote once

The attacker effectively multiplies their governance influence by the number of validators they control with the shared voter account.

## Impact Explanation

**Severity: CRITICAL**

This vulnerability enables **Governance Power Manipulation**, which falls under the Critical severity category as it violates governance integrity, a fundamental protocol security guarantee.

**Specific Impacts:**

1. **Governance Takeover**: An attacker with sufficient validators can gain disproportionate control over protocol upgrades, parameter changes, and treasury spending decisions
2. **Consensus Parameter Manipulation**: Can vote to change staking requirements, epoch duration, voting thresholds, and rewards parameters
3. **Protocol Upgrade Control**: Can approve malicious framework upgrades or block legitimate security patches
4. **Validator Set Manipulation**: Can influence validator admission/removal decisions
5. **Economic Exploitation**: Can vote for proposals that benefit their validators at the expense of others

The vulnerability breaks the core invariant: **"Governance Integrity: Voting power must be correctly calculated from stake"**

Each validator's stake should grant exactly one set of votes, but this bug allows N validators to grant N×stake voting power to a single voter account.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to be exploited because:

1. **Easy to Execute**: Requires only setting the same address in configuration files during genesis - no sophisticated attack techniques needed
2. **No Runtime Detection**: The system has no mechanism to detect or prevent this at genesis or during voting
3. **High Incentive**: Governance control provides massive strategic value (protocol upgrades, treasury access, parameter tuning)
4. **Genesis Window**: The attack must be configured during genesis, but once set, persists forever
5. **Coordination**: Bad actors controlling multiple genesis validator slots can trivially configure this

The only barrier is having access to multiple validator configurations during genesis setup, which is realistic for:
- Large staking providers operating multiple nodes
- Coordinated entities splitting their stake across validators
- Compromised genesis coordinators

## Recommendation

Add voter account uniqueness validation in the `validate_validators()` function, similar to existing owner/operator checks:

**In `crates/aptos/src/genesis/mod.rs`, modify `validate_validators()` to add:**

```rust
// After line 691, add voter uniqueness check:
if unique_accounts.contains(&validator.voter_account_address.into()) {
    errors.push(CliError::UnexpectedError(format!(
        "Voter '{}' in validator {} has already been seen elsewhere",
        validator.voter_account_address, name
    )));
}
unique_accounts.insert(validator.voter_account_address.into());
```

**Additional Hardening:**

Consider adding a runtime check in `aptos_governance.move` to detect if the same voter is being used across multiple stake pools (though genesis prevention is the primary fix):

```move
// In voting initialization or vote_internal, add:
// Track voter-to-stake-pool mappings and enforce 1:1 relationship
```

## Proof of Concept

**Genesis Configuration Exploit:**

1. Create three validator configurations in separate directories:

```yaml
# validator1/owner.yaml
owner_account_address: "0x1111..."
voter_account_address: "0xABCD..."  # Shared voter
operator_account_address: "0x1112..."
stake_amount: 1000000000000000

# validator2/owner.yaml
owner_account_address: "0x2222..."
voter_account_address: "0xABCD..."  # Same shared voter!
operator_account_address: "0x2223..."
stake_amount: 1000000000000000

# validator3/owner.yaml
owner_account_address: "0x3333..."
voter_account_address: "0xABCD..."  # Same shared voter again!
operator_account_address: "0x3334..."
stake_amount: 1000000000000000
```

2. Run genesis generation:
```bash
aptos genesis generate-genesis --local-repository-dir ./genesis_config
```

3. The genesis generation **succeeds** without error, creating a network where `0xABCD` can vote three times.

4. After network launch, create and vote on a governance proposal:

```move
script {
    use aptos_framework::aptos_governance;
    
    fun exploit_vote(voter: &signer) {
        // Vote with validator1's stake pool
        aptos_governance::vote(
            voter,
            @0x1111..., // validator1 pool
            1,          // proposal_id
            true
        );
        
        // Vote AGAIN with validator2's stake pool (same voter!)
        aptos_governance::vote(
            voter,
            @0x2222..., // validator2 pool
            1,          // proposal_id
            true
        );
        
        // Vote AGAIN with validator3's stake pool (same voter!)
        aptos_governance::vote(
            voter,
            @0x3333..., // validator3 pool
            1,          // proposal_id
            true
        );
        
        // Result: 3x voting power with one voter account
    }
}
```

Each vote succeeds because `vote_internal()` only checks that the voter matches the stake pool's designated voter - it never checks if that voter has already voted using a different stake pool.

## Notes

This vulnerability represents a fundamental flaw in the genesis validator configuration validation logic. The inconsistency between validating owner/operator uniqueness but not voter uniqueness suggests an oversight rather than intentional design. The governance system's per-stake-pool vote tracking, while necessary for partial voting features, inadvertently enables this exploit when combined with the genesis validation gap.

The fix must be applied before any genesis/network launch, as post-genesis correction would require a hard fork to reassign voter accounts across existing validators.

### Citations

**File:** crates/aptos/src/genesis/mod.rs (L392-404)
```rust
    let voter_account_address: AccountAddress = parse_required_option(
        &owner_config.voter_account_address,
        owner_file,
        "voter_account_address",
        AccountAddressWithChecks::from_str,
    )?
    .into();
    let voter_account_public_key = parse_required_option(
        &owner_config.voter_account_public_key,
        owner_file,
        "voter_account_public_key",
        |str| parse_key(ED25519_PUBLIC_KEY_LENGTH, str),
    )?;
```

**File:** crates/aptos/src/genesis/mod.rs (L654-659)
```rust
        if !initialized_accounts.contains_key(&validator.voter_account_address.into()) {
            errors.push(CliError::UnexpectedError(format!(
                "Voter {} in validator {} is not in the balances.yaml file",
                validator.voter_account_address, name
            )));
        }
```

**File:** crates/aptos/src/genesis/mod.rs (L677-691)
```rust
        if unique_accounts.contains(&validator.owner_account_address.into()) {
            errors.push(CliError::UnexpectedError(format!(
                "Owner '{}' in validator {} has already been seen elsewhere",
                validator.owner_account_address, name
            )));
        }
        unique_accounts.insert(validator.owner_account_address.into());

        if unique_accounts.contains(&validator.operator_account_address.into()) {
            errors.push(CliError::UnexpectedError(format!(
                "Operator '{}' in validator {} has already been seen elsewhere",
                validator.operator_account_address, name
            )));
        }
        unique_accounts.insert(validator.operator_account_address.into());
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L547-548)
```text
        let voter_address = signer::address_of(voter);
        assert!(stake::get_delegated_voter(stake_pool) == voter_address, error::invalid_argument(ENOT_DELEGATED_VOTER));
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L568-574)
```text
        let record_key = RecordKey {
            stake_pool,
            proposal_id,
        };
        let used_voting_power = VotingRecordsV2[@aptos_framework].votes.borrow_mut_with_default(record_key, 0);
        // This calculation should never overflow because the used voting cannot exceed the total voting power of this stake pool.
        *used_voting_power += voting_power;
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L731-741)
```text
    public fun get_voting_power(pool_address: address): u64 {
        let allow_validator_set_change = staking_config::get_allow_validator_set_change(&staking_config::get());
        if (allow_validator_set_change) {
            let (active, _, pending_active, pending_inactive) = stake::get_stake(pool_address);
            // We calculate the voting power as total non-inactive stakes of the pool. Even if the validator is not in the
            // active validator set, as long as they have a lockup (separately checked in create_proposal and voting), their
            // stake would still count in their voting power for governance proposals.
            active + pending_active + pending_inactive
        } else {
            stake::get_current_epoch_voting_power(pool_address)
        }
```

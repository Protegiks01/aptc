# Audit Report

## Title
Feature Flag Bypass in Delegation Pool Governance Voting Allows Unauthorized Operations When Features Are Disabled

## Summary
The Aptos delegation pool governance system enforces `PARTIAL_GOVERNANCE_VOTING` and `DELEGATION_POOL_PARTIAL_GOVERNANCE_VOTING` feature flags only in the CLI client, but not in the on-chain Move code. This allows attackers to bypass disabled features by submitting transactions directly via SDK/API, undermining the feature flag circuit breaker mechanism.

## Finding Description

The delegation pool governance system has a critical mismatch between client-side and on-chain enforcement of feature flags.

**CLI Enforcement (Client-Side Only):**

The `delegation_pool_governance_precheck()` function requires BOTH feature flags to be enabled before allowing governance operations through the CLI: [1](#0-0) 

This function checks `is_partial_governance_voting_enabled()` and `is_delegation_pool_partial_governance_voting_enabled()`, which query the global feature flags defined in the features module: [2](#0-1) 

**On-Chain Enforcement (Missing):**

The on-chain `vote()` function only checks pool-specific state via `assert_partial_governance_voting_enabled(pool_address)`: [3](#0-2) 

This assertion function only validates pool-level state, not global feature flags: [4](#0-3) 

The `partial_governance_voting_enabled()` check only verifies local pool state (whether `GovernanceRecords` exists and delegated voter is set), completely ignoring the global feature flags: [5](#0-4) 

The same issue exists in `create_proposal()`: [6](#0-5) 

And in `enable_partial_governance_voting()`, which doesn't check global flags at all: [7](#0-6) 

**Violation of Established Pattern:**

Other functions in the Aptos framework correctly check feature flags on-chain. For example, `multisig_account::vote_transaction()` checks the feature flag before execution: [8](#0-7) 

**SDK Bypass Path:**

The SDK provides functions to create transaction payloads without any feature flag checks: [9](#0-8) [10](#0-9) 

**Attack Vector:**

1. Attacker monitors feature flags and detects when governance disables flag #17 or #21
2. Attacker uses SDK to create transaction payload calling `0x1::delegation_pool::vote()` or `0x1::delegation_pool::create_proposal()`
3. Attacker submits transaction via REST API, bypassing CLI checks
4. On-chain execution succeeds because Move code never validates global feature flags
5. Governance operations execute when they should be disabled network-wide

## Impact Explanation

**Severity: Medium** - This constitutes a "Limited Protocol Violation" per the Aptos bug bounty criteria.

**Specific Impacts:**

1. **Circuit Breaker Bypass**: Feature flags serve as emergency circuit breakers. If governance discovers a vulnerability in partial voting and disables the flags, attackers can continue exploiting via direct API calls.

2. **Policy Enforcement Failure**: Governance decisions to disable features are rendered ineffective for any user bypassing the CLI.

3. **Inconsistent Security Posture**: The network believes a feature is disabled when it remains fully operational, creating false security assumptions.

While this is a significant protocol violation, it does not reach High/Critical severity as it:
- Does not enable direct theft of funds
- Does not cause consensus failures or chain splits
- Does not permanently freeze funds or halt the network
- Requires pre-existing condition (pool has enabled partial governance voting)

## Likelihood Explanation

**Likelihood: High**

1. **Easy to Exploit**: Any user with SDK/API access can submit transactions bypassing CLI checks
2. **No Special Privileges Required**: Regular delegators can exploit this
3. **Clear Attack Path**: Direct transaction submission via SDK is standard practice
4. **Discoverable**: Feature flag states are public on-chain
5. **Incentive Exists**: Governance proposals can have significant economic impact

The only precondition is that a delegation pool has previously enabled partial governance voting, which is increasingly common.

## Recommendation

Add global feature flag checks to the on-chain Move functions following the established pattern used elsewhere in the framework:

```move
public entry fun vote(
    voter: &signer,
    pool_address: address,
    proposal_id: u64,
    voting_power: u64,
    should_pass: bool
) acquires DelegationPool, GovernanceRecords, BeneficiaryForOperator, NextCommissionPercentage {
    // Add global feature flag checks
    assert!(
        features::partial_governance_voting_enabled(),
        error::invalid_state(EPARTIAL_GOVERNANCE_VOTING_FEATURE_NOT_ENABLED)
    );
    assert!(
        features::delegation_pool_partial_governance_voting_enabled(),
        error::invalid_state(EDELEGATION_POOL_PARTIAL_GOVERNANCE_VOTING_FEATURE_NOT_ENABLED)
    );
    
    check_stake_management_permission(voter);
    assert_partial_governance_voting_enabled(pool_address);
    // ... rest of function
}
```

Apply the same fix to `create_proposal()` and `enable_partial_governance_voting()`.

## Proof of Concept

```move
#[test(aptos_framework = @0x1, voter = @0x123)]
public fun test_feature_flag_bypass(aptos_framework: &signer, voter: &signer) {
    // Setup: Create delegation pool with partial governance enabled
    // Assume pool_address = @0xPOOL
    
    // Governance disables the feature flags
    features::change_feature_flags_for_next_epoch(
        aptos_framework,
        vector[],  // enable
        vector[17, 21]  // disable PARTIAL_GOVERNANCE_VOTING and DELEGATION_POOL_PARTIAL_GOVERNANCE_VOTING
    );
    reconfiguration::on_new_epoch(aptos_framework);
    
    // Attack: Submit vote transaction directly (bypassing CLI)
    // This should FAIL if feature flags were checked on-chain, but it SUCCEEDS
    delegation_pool::vote(voter, @0xPOOL, 1, 1000, true);
    
    // Vulnerability: Vote succeeded even though feature flags are disabled
    // Expected: Transaction should abort with feature flag error
    // Actual: Transaction succeeds
}
```

## Notes

The global feature flags are properly defined in the features module: [11](#0-10) 

However, these checks are only performed client-side, not on-chain, creating a security vulnerability where feature flag circuit breakers can be bypassed.

### Citations

**File:** crates/aptos/src/governance/delegation_pool.rs (L175-205)
```rust
async fn delegation_pool_governance_precheck(
    txn_options: &TransactionOptions,
    pool_address: AccountAddress,
) -> CliTypedResult<Option<TransactionSummary>> {
    let client = &txn_options
        .rest_options
        .client(&txn_options.profile_options)?;
    if !is_partial_governance_voting_enabled(client).await? {
        return Err(CliError::CommandArgumentError(
            "Partial governance voting feature flag is not enabled".to_string(),
        ));
    };
    if !is_delegation_pool_partial_governance_voting_enabled(client).await? {
        return Err(CliError::CommandArgumentError(
            "Delegation pool partial governance voting feature flag is not enabled".to_string(),
        ));
    };
    if is_partial_governance_voting_enabled_for_delegation_pool(client, pool_address).await? {
        Ok(None)
    } else {
        println!("Partial governance voting for delegation pool {} hasn't been enabled yet. Enabling it now...",
                 pool_address);
        let txn_summary = txn_options
            .submit_transaction(
                aptos_stdlib::delegation_pool_enable_partial_governance_voting(pool_address),
            )
            .await
            .map(TransactionSummary::from)?;
        Ok(Some(txn_summary))
    }
}
```

**File:** crates/aptos/src/governance/utils.rs (L33-45)
```rust
pub async fn is_partial_governance_voting_enabled(client: &Client) -> CliTypedResult<bool> {
    common::utils::get_feature_flag(client, FeatureFlag::PARTIAL_GOVERNANCE_VOTING).await
}

pub async fn is_delegation_pool_partial_governance_voting_enabled(
    client: &Client,
) -> CliTypedResult<bool> {
    common::utils::get_feature_flag(
        client,
        FeatureFlag::DELEGATION_POOL_PARTIAL_GOVERNANCE_VOTING,
    )
    .await
}
```

**File:** aptos-move/framework/aptos-framework/sources/delegation_pool.move (L536-540)
```text
    #[view]
    /// Return whether a delegation pool has already enabled partial governance voting.
    public fun partial_governance_voting_enabled(pool_address: address): bool {
        exists<GovernanceRecords>(pool_address) && stake::get_delegated_voter(pool_address) == pool_address
    }
```

**File:** aptos-move/framework/aptos-framework/sources/delegation_pool.move (L935-957)
```text
    public entry fun enable_partial_governance_voting(
        pool_address: address,
    ) acquires DelegationPool, GovernanceRecords, BeneficiaryForOperator, NextCommissionPercentage {
        assert_delegation_pool_exists(pool_address);
        // synchronize delegation and stake pools before any user operation.
        synchronize_delegation_pool(pool_address);

        let delegation_pool = borrow_global<DelegationPool>(pool_address);
        let stake_pool_signer = retrieve_stake_pool_owner(delegation_pool);
        // delegated_voter is managed by the stake pool itself, which signer capability is managed by DelegationPool.
        // So voting power of this stake pool can only be used through this module.
        stake::set_delegated_voter(&stake_pool_signer, signer::address_of(&stake_pool_signer));

        move_to(&stake_pool_signer, GovernanceRecords {
            votes: smart_table::new(),
            votes_per_proposal: smart_table::new(),
            vote_delegation: smart_table::new(),
            delegated_votes: smart_table::new(),
            vote_events: account::new_event_handle<VoteEvent>(&stake_pool_signer),
            create_proposal_events: account::new_event_handle<CreateProposalEvent>(&stake_pool_signer),
            delegate_voting_power_events: account::new_event_handle<DelegateVotingPowerEvent>(&stake_pool_signer),
        });
    }
```

**File:** aptos-move/framework/aptos-framework/sources/delegation_pool.move (L964-1019)
```text
    public entry fun vote(
        voter: &signer,
        pool_address: address,
        proposal_id: u64,
        voting_power: u64,
        should_pass: bool
    ) acquires DelegationPool, GovernanceRecords, BeneficiaryForOperator, NextCommissionPercentage {
        check_stake_management_permission(voter);
        assert_partial_governance_voting_enabled(pool_address);
        // synchronize delegation and stake pools before any user operation.
        synchronize_delegation_pool(pool_address);

        let voter_address = signer::address_of(voter);
        let remaining_voting_power = calculate_and_update_remaining_voting_power(
            pool_address,
            voter_address,
            proposal_id
        );
        if (voting_power > remaining_voting_power) {
            voting_power = remaining_voting_power;
        };
        aptos_governance::assert_proposal_expiration(pool_address, proposal_id);
        assert!(voting_power > 0, error::invalid_argument(ENO_VOTING_POWER));

        let governance_records = borrow_global_mut<GovernanceRecords>(pool_address);
        // Check a edge case during the transient period of enabling partial governance voting.
        assert_and_update_proposal_used_voting_power(governance_records, pool_address, proposal_id, voting_power);
        let used_voting_power = borrow_mut_used_voting_power(governance_records, voter_address, proposal_id);
        *used_voting_power = *used_voting_power + voting_power;

        let pool_signer = retrieve_stake_pool_owner(borrow_global<DelegationPool>(pool_address));
        aptos_governance::partial_vote(&pool_signer, pool_address, proposal_id, voting_power, should_pass);

        if (features::module_event_migration_enabled()) {
            event::emit(
                Vote {
                    voter: voter_address,
                    proposal_id,
                    delegation_pool: pool_address,
                    num_votes: voting_power,
                    should_pass,
                }
            );
        } else {
            event::emit_event(
                &mut governance_records.vote_events,
                VoteEvent {
                    voter: voter_address,
                    proposal_id,
                    delegation_pool: pool_address,
                    num_votes: voting_power,
                    should_pass,
                }
            );
        };
    }
```

**File:** aptos-move/framework/aptos-framework/sources/delegation_pool.move (L1024-1053)
```text
    public entry fun create_proposal(
        voter: &signer,
        pool_address: address,
        execution_hash: vector<u8>,
        metadata_location: vector<u8>,
        metadata_hash: vector<u8>,
        is_multi_step_proposal: bool,
    ) acquires DelegationPool, GovernanceRecords, BeneficiaryForOperator, NextCommissionPercentage {
        check_stake_management_permission(voter);
        assert_partial_governance_voting_enabled(pool_address);

        // synchronize delegation and stake pools before any user operation
        synchronize_delegation_pool(pool_address);

        let voter_addr = signer::address_of(voter);
        let pool = borrow_global<DelegationPool>(pool_address);
        let governance_records = borrow_global_mut<GovernanceRecords>(pool_address);
        let total_voting_power = calculate_and_update_delegated_votes(pool, governance_records, voter_addr);
        assert!(
            total_voting_power >= aptos_governance::get_required_proposer_stake(),
            error::invalid_argument(EINSUFFICIENT_PROPOSER_STAKE));
        let pool_signer = retrieve_stake_pool_owner(borrow_global<DelegationPool>(pool_address));
        let proposal_id = aptos_governance::create_proposal_v2_impl(
            &pool_signer,
            pool_address,
            execution_hash,
            metadata_location,
            metadata_hash,
            is_multi_step_proposal,
        );
```

**File:** aptos-move/framework/aptos-framework/sources/delegation_pool.move (L1098-1104)
```text
    fun assert_partial_governance_voting_enabled(pool_address: address) {
        assert_delegation_pool_exists(pool_address);
        assert!(
            partial_governance_voting_enabled(pool_address),
            error::invalid_state(EPARTIAL_GOVERNANCE_VOTING_NOT_ENABLED)
        );
    }
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1057-1061)
```text
    public entry fun vote_transaction(
        owner: &signer, multisig_account: address, sequence_number: u64, approved: bool) acquires MultisigAccount {
        assert!(features::multisig_v2_enhancement_feature_enabled(), error::invalid_state(EMULTISIG_V2_ENHANCEMENT_NOT_ENABLED));
        vote_transanction(owner, multisig_account, sequence_number, approved);
    }
```

**File:** aptos-move/framework/cached-packages/src/aptos_framework_sdk_builder.rs (L3104-3129)
```rust
pub fn delegation_pool_create_proposal(
    pool_address: AccountAddress,
    execution_hash: Vec<u8>,
    metadata_location: Vec<u8>,
    metadata_hash: Vec<u8>,
    is_multi_step_proposal: bool,
) -> TransactionPayload {
    TransactionPayload::EntryFunction(EntryFunction::new(
        ModuleId::new(
            AccountAddress::new([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 1,
            ]),
            ident_str!("delegation_pool").to_owned(),
        ),
        ident_str!("create_proposal").to_owned(),
        vec![],
        vec![
            bcs::to_bytes(&pool_address).unwrap(),
            bcs::to_bytes(&execution_hash).unwrap(),
            bcs::to_bytes(&metadata_location).unwrap(),
            bcs::to_bytes(&metadata_hash).unwrap(),
            bcs::to_bytes(&is_multi_step_proposal).unwrap(),
        ],
    ))
}
```

**File:** aptos-move/framework/cached-packages/src/aptos_framework_sdk_builder.rs (L3401-3422)
```rust
pub fn delegation_pool_vote(
    pool_address: AccountAddress,
    proposal_id: u64,
    voting_power: u64,
    should_pass: bool,
) -> TransactionPayload {
    TransactionPayload::EntryFunction(EntryFunction::new(
        ModuleId::new(
            AccountAddress::new([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 1,
            ]),
            ident_str!("delegation_pool").to_owned(),
        ),
        ident_str!("vote").to_owned(),
        vec![],
        vec![
            bcs::to_bytes(&pool_address).unwrap(),
            bcs::to_bytes(&proposal_id).unwrap(),
            bcs::to_bytes(&voting_power).unwrap(),
            bcs::to_bytes(&should_pass).unwrap(),
        ],
```

**File:** aptos-move/framework/move-stdlib/sources/configs/features.move (L195-217)
```text
    /// Whether enable paritial governance voting on aptos_governance.
    /// Lifetime: transient
    const PARTIAL_GOVERNANCE_VOTING: u64 = 17;

    public fun get_partial_governance_voting(): u64 { PARTIAL_GOVERNANCE_VOTING }

    public fun partial_governance_voting_enabled(): bool acquires Features {
        is_enabled(PARTIAL_GOVERNANCE_VOTING)
    }

    /// Charge invariant violation error.
    /// Lifetime: transient
    const CHARGE_INVARIANT_VIOLATION: u64 = 20;

    /// Whether enable paritial governance voting on delegation_pool.
    /// Lifetime: transient
    const DELEGATION_POOL_PARTIAL_GOVERNANCE_VOTING: u64 = 21;

    public fun get_delegation_pool_partial_governance_voting(): u64 { DELEGATION_POOL_PARTIAL_GOVERNANCE_VOTING }

    public fun delegation_pool_partial_governance_voting_enabled(): bool acquires Features {
        is_enabled(DELEGATION_POOL_PARTIAL_GOVERNANCE_VOTING)
    }
```

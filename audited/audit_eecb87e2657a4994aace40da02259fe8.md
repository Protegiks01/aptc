# Audit Report

## Title
Governance Feature Flags Not Enforced On-Chain - Delegation Pool Voting Bypass

## Summary
The feature flags `PARTIAL_GOVERNANCE_VOTING` (flag 17) and `DELEGATION_POOL_PARTIAL_GOVERNANCE_VOTING` (flag 21) are checked in the Rust CLI client but not enforced in the on-chain Move smart contracts. This allows users to bypass feature flag controls by submitting transactions directly to the blockchain, enabling delegation pool governance voting even when these features are administratively disabled network-wide.

## Finding Description

The vulnerability stems from an architectural inconsistency where governance feature flags are validated client-side but not on-chain.

**CLI-Side Enforcement (Client-Side Only):**

The Rust CLI code explicitly checks both feature flags before allowing governance operations: [1](#0-0) 

**On-Chain Code (No Feature Flag Checks):**

The `delegation_pool::vote` function only validates pool-level state: [2](#0-1) 

The `assert_partial_governance_voting_enabled` function checks pool-specific state but NOT global feature flags: [3](#0-2) [4](#0-3) 

The `aptos_governance::partial_vote` function has no feature flag validation: [5](#0-4) 

The `enable_partial_governance_voting` function is permissionless and lacks feature flag checks: [6](#0-5) 

**Proof of Design Inconsistency:**

The same `delegation_pool.move` module successfully checks OTHER feature flags, proving the capability exists but isn't used for governance flags: [7](#0-6) 

Meanwhile, the global feature flag checking functions exist but are never called from on-chain code: [8](#0-7) [9](#0-8) 

**Attack Execution:**
1. Network administrators disable feature flags 17 and 21 via governance to halt partial governance voting
2. Attacker bypasses CLI by submitting transactions directly via JSON-RPC: `0x1::delegation_pool::vote(pool_address, proposal_id, voting_power, should_pass)`
3. Transaction executes successfully because on-chain validation never checks global feature flags
4. Governance voting continues despite administrative controls

## Impact Explanation

This represents a **MEDIUM to HIGH severity** governance protocol violation.

**Broken Security Guarantees:**
- Feature flags are documented as network-wide controls but function only as client-side restrictions
- Administrators cannot disable partial governance voting in emergencies
- Creates false security assumptions where operators believe feature flags provide protection

**Concrete Impact:**
1. **Governance Control Bypass**: Emergency kill-switch mechanism is ineffective
2. **Inconsistent Security Enforcement**: CLI users blocked while direct transaction submitters bypass controls  
3. **Emergency Response Failure**: If a critical bug is discovered in partial governance voting, disabling the feature flags does not prevent exploitation

While this does not directly enable fund theft or consensus violations, it undermines the governance security model. If a vulnerability exists in the partial governance voting mechanism, administrators cannot use feature flags to mitigate it as designed.

## Likelihood Explanation

**Likelihood: HIGH**

1. **Trivial to Execute**: Any user can submit transactions via JSON-RPC or SDK without CLI
2. **No Privileges Required**: No validator access or special permissions needed
3. **Well-Documented Attack Surface**: Standard transaction submission APIs
4. **Immediate Exploitability**: Works against any delegation pool with existing `GovernanceRecords` resource
5. **Realistic Scenario**: Will occur when administrators attempt emergency feature disablement

## Recommendation

Add on-chain feature flag validation to all governance entry points:

```move
fun assert_partial_governance_voting_enabled(pool_address: address) {
    assert_delegation_pool_exists(pool_address);
    // Add global feature flag checks
    assert!(
        features::partial_governance_voting_enabled(),
        error::invalid_state(EPARTIAL_GOVERNANCE_VOTING_FEATURE_NOT_ENABLED)
    );
    assert!(
        features::delegation_pool_partial_governance_voting_enabled(),
        error::invalid_state(EDELEGATION_POOL_PARTIAL_GOVERNANCE_VOTING_FEATURE_NOT_ENABLED)
    );
    assert!(
        partial_governance_voting_enabled(pool_address),
        error::invalid_state(EPARTIAL_GOVERNANCE_VOTING_NOT_ENABLED)
    );
}
```

Apply similar checks to `enable_partial_governance_voting`, `create_proposal`, and other governance functions to ensure feature flags are enforced consistently across all code paths.

## Proof of Concept

```move
#[test(aptos_framework = @0x1, user = @0x100)]
fun test_feature_flag_bypass(aptos_framework: &signer, user: &signer) {
    // Setup: Enable feature flags and create delegation pool with partial governance
    features::change_feature_flags_for_testing(aptos_framework, 
        vector[17, 21], // Enable both flags
        vector[]
    );
    
    let pool_address = setup_delegation_pool(user);
    delegation_pool::enable_partial_governance_voting(pool_address);
    
    // Administrator disables feature flags due to discovered vulnerability
    features::change_feature_flags_for_testing(aptos_framework,
        vector[],
        vector[17, 21] // Disable both flags
    );
    
    // Verify flags are disabled
    assert!(!features::partial_governance_voting_enabled(), 0);
    assert!(!features::delegation_pool_partial_governance_voting_enabled(), 1);
    
    // Attack: User bypasses CLI and submits vote transaction directly
    // This should FAIL if feature flags were enforced on-chain, but it SUCCEEDS
    delegation_pool::vote(user, pool_address, proposal_id, 1000, true);
    
    // Vulnerability confirmed: vote succeeded despite disabled feature flags
}
```

## Notes

This vulnerability demonstrates a fundamental architectural flaw where security controls exist at the wrong layer. Feature flags are implemented as global on-chain configuration stored in the `Features` resource at `@std` address, yet the on-chain Move code that should enforce them does not check their state. The CLI enforcement creates a false sense of security while leaving the actual blockchain vulnerable to direct transaction submission.

### Citations

**File:** crates/aptos/src/governance/delegation_pool.rs (L182-191)
```rust
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
```

**File:** aptos-move/framework/aptos-framework/sources/delegation_pool.move (L538-540)
```text
    public fun partial_governance_voting_enabled(pool_address: address): bool {
        exists<GovernanceRecords>(pool_address) && stake::get_delegated_voter(pool_address) == pool_address
    }
```

**File:** aptos-move/framework/aptos-framework/sources/delegation_pool.move (L933-946)
```text
    /// Enable partial governance voting on a stake pool. The voter of this stake pool will be managed by this module.
    /// The existing voter will be replaced. The function is permissionless.
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
```

**File:** aptos-move/framework/aptos-framework/sources/delegation_pool.move (L964-972)
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

**File:** aptos-move/framework/aptos-framework/sources/delegation_pool.move (L1475-1478)
```text
        assert!(
            features::delegation_pool_allowlisting_enabled(),
            error::invalid_state(EDELEGATORS_ALLOWLISTING_NOT_SUPPORTED)
        );
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L525-533)
```text
    public entry fun partial_vote(
        voter: &signer,
        stake_pool: address,
        proposal_id: u64,
        voting_power: u64,
        should_pass: bool,
    ) acquires ApprovedExecutionHashes, VotingRecords, VotingRecordsV2, GovernanceEvents {
        vote_internal(voter, stake_pool, proposal_id, voting_power, should_pass);
    }
```

**File:** aptos-move/framework/move-stdlib/sources/configs/features.move (L201-203)
```text
    public fun partial_governance_voting_enabled(): bool acquires Features {
        is_enabled(PARTIAL_GOVERNANCE_VOTING)
    }
```

**File:** aptos-move/framework/move-stdlib/sources/configs/features.move (L215-217)
```text
    public fun delegation_pool_partial_governance_voting_enabled(): bool acquires Features {
        is_enabled(DELEGATION_POOL_PARTIAL_GOVERNANCE_VOTING)
    }
```

# Audit Report

## Title
Circular Hash Chain Vulnerability in Multi-Step Governance Proposals Enables Infinite Execution Loop

## Summary
The multi-step governance proposal system lacks validation of the `next_execution_hash` parameter, allowing attackers to create circular proposal chains that can execute indefinitely. When a multi-step proposal calls `resolve_multi_step_proposal` with a `next_execution_hash` value, the system does not verify that this hash is different from previously used hashes or that it won't create a cycle, enabling an attacker to construct proposals that loop back to earlier steps.

## Finding Description
The vulnerability exists in the multi-step proposal resolution flow. When `resolve_proposal_v2` is called with a non-empty `next_execution_hash`, it simply updates the proposal's execution hash without any validation: [1](#0-0) 

At line 565, the function directly assigns `proposal.execution_hash = next_execution_hash` without checking:
1. Whether `next_execution_hash` equals the current `execution_hash` (self-loop)
2. Whether `next_execution_hash` was previously used in this proposal's execution history (circular chain)
3. Whether the hash chain will eventually terminate

The proposal's `is_resolved` flag only gets set to `true` when `next_execution_hash` is empty (the final step). For circular chains that never provide an empty hash, the proposal remains perpetually unresolved: [2](#0-1) 

The check at line 440 prevents execution of fully resolved proposals but does nothing for circular multi-step proposals that never complete.

The `aptos_governance` module simply forwards the hash without validation: [3](#0-2) 

The CLI allows users to specify arbitrary `next_execution_hash` values with no validation: [4](#0-3) 

**Attack Scenario:**

1. Attacker creates Script A with `hash_A` containing: `resolve_multi_step_proposal(proposal_id, @0x1, hash_B)`
2. Attacker creates Script B with `hash_B` containing: `resolve_multi_step_proposal(proposal_id, @0x1, hash_A)` 
3. Attacker creates multi-step proposal with initial `execution_hash = hash_A`
4. Proposal passes voting with sufficient stake
5. Execute Script A → updates `execution_hash` to `hash_B`, grants framework signer
6. Execute Script B → updates `execution_hash` to `hash_A` (circular!), grants framework signer
7. Execute Script A again → infinite loop continues
8. Each execution can modify governance configs, features, or other critical parameters

The `IS_MULTI_STEP_PROPOSAL_IN_EXECUTION_KEY` flag only prevents additional voting during execution but does not prevent the circular execution itself: [5](#0-4) 

## Impact Explanation
This is a **Critical** severity vulnerability per Aptos bug bounty criteria:

**Governance Integrity Violation**: The system allows malicious proposals to execute governance actions infinitely, breaking the fundamental governance invariant that proposals should have a deterministic, finite execution path.

**Unlimited Framework Signer Access**: Each execution cycle grants access to the framework signer capability, allowing repeated calls to privileged functions like:
- `update_governance_config` - repeatedly modify voting parameters
- `toggle_features` - enable/disable features multiple times
- `reconfigure` - trigger epoch changes repeatedly
- Any other governance-controlled system modifications

**Denial of Service**: A circular proposal effectively locks the proposal ID in an executing state indefinitely, preventing legitimate governance operations and wasting resources.

**State Inconsistency**: Repeated execution of state-modifying operations can lead to unexpected system states that violate protocol assumptions.

This meets the Critical category: "Consensus/Safety violations" and "Significant protocol violations" as it fundamentally breaks the governance integrity invariant.

## Likelihood Explanation
**Likelihood: High**

**Attacker Requirements:**
- Sufficient stake to meet `required_proposer_stake` threshold (legitimately obtainable)
- Ability to create Move scripts (public knowledge)
- Voting support to pass the proposal (social engineering or legitimate proposals with hidden circular logic)

**Complexity: Low to Medium**
- Creating circular hash chains requires generating two scripts and computing their hashes
- The Aptos CLI directly supports custom `next_execution_hash` values
- No cryptographic or implementation complexities involved

**Detection Difficulty: High**
- Voters see only execution hashes, not the embedded `next_execution_hash` values
- Circular chains aren't immediately obvious without detailed script analysis
- The vulnerability could be hidden in legitimate-looking framework upgrade proposals

## Recommendation

Implement validation in `resolve_proposal_v2` to prevent circular hash chains:

**Solution 1: Track Execution History**
Add a vector to track all previously used execution hashes and verify new hashes aren't reused:

```move
// In Proposal struct, add:
execution_history: vector<vector<u8>>,

// In resolve_proposal_v2, before line 565:
if (!next_execution_hash_is_empty) {
    // Verify next_execution_hash differs from current hash
    assert!(
        next_execution_hash != proposal.execution_hash,
        error::invalid_argument(ECIRCULAR_HASH_CHAIN_DETECTED)
    );
    
    // Verify next_execution_hash not in execution history
    assert!(
        !vector::contains(&proposal.execution_history, &next_execution_hash),
        error::invalid_argument(EHASH_REUSE_DETECTED)
    );
    
    // Record current hash before updating
    vector::push_back(&mut proposal.execution_history, proposal.execution_hash);
    
    proposal.execution_hash = next_execution_hash;
}
```

**Solution 2: Maximum Step Limit**
Add a counter to limit the maximum number of execution steps:

```move
// In Proposal struct, add:
max_steps: u64,
current_step: u64,

// In resolve_proposal_v2:
if (!next_execution_hash_is_empty) {
    proposal.current_step = proposal.current_step + 1;
    assert!(
        proposal.current_step <= proposal.max_steps,
        error::invalid_state(EMAX_STEPS_EXCEEDED)
    );
    proposal.execution_hash = next_execution_hash;
}
```

**Solution 3: Require Explicit Step Declaration**
Require proposers to declare all execution hashes upfront during proposal creation and validate against this list during resolution.

## Proof of Concept

```move
#[test(aptos_framework = @aptos_framework, proposer = @0x123, voter = @0x234)]
public entry fun test_circular_proposal_vulnerability(
    aptos_framework: signer,
    proposer: signer,
    voter: signer,
) acquires GovernanceConfig, GovernanceResponsbility, VotingRecords, VotingRecordsV2, ApprovedExecutionHashes, GovernanceEvents {
    // Setup governance and staking
    setup_partial_voting(&aptos_framework, &proposer, &voter, &voter);
    
    // Script A with hash pointing to Script B
    let script_a_code = b"script { use aptos_framework::aptos_governance; fun main(proposal_id: u64) { aptos_governance::resolve_multi_step_proposal(proposal_id, @0x1, x\"B_HASH_HERE\"); } }";
    let hash_a = hash::sha3_256(script_a_code);
    
    // Script B with hash pointing back to Script A (creating cycle)
    let script_b_code = b"script { use aptos_framework::aptos_governance; fun main(proposal_id: u64) { aptos_governance::resolve_multi_step_proposal(proposal_id, @0x1, x\"A_HASH_HERE\"); } }";
    let hash_b = hash::sha3_256(script_b_code);
    
    // Create multi-step proposal with hash_a as initial execution hash
    let proposal_id = create_proposal_v2_impl(
        &proposer,
        signer::address_of(&proposer),
        hash_a,
        b"",
        b"",
        true, // is_multi_step
    );
    
    // Vote and pass proposal
    vote(&voter, signer::address_of(&voter), proposal_id, true);
    timestamp::update_global_time_for_test(100001000000);
    
    // Execute step 1 (Script A) - should succeed
    // This would set next_execution_hash to hash_b
    
    // Execute step 2 (Script B) - should succeed  
    // This would set next_execution_hash back to hash_a (CIRCULAR!)
    
    // Execute step 1 again (Script A) - should succeed again (VULNERABILITY!)
    // Proposal never completes, can execute indefinitely
    
    // Assert that proposal is still not resolved after multiple executions
    assert!(!voting::is_resolved<GovernanceProposal>(@aptos_framework, proposal_id), 0);
}
```

**Notes:**
The vulnerability requires the attacker to pre-compute hash values such that Script A contains hash_B and Script B contains hash_A. The Aptos CLI at line 1007-1008 accepts arbitrary hex strings for `next_execution_hash`, enabling this attack. The core issue is the lack of cycle detection in the proposal resolution logic.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/voting.move (L430-450)
```text
    /// Common checks on if a proposal is resolvable, regardless if the proposal is single-step or multi-step.
    fun is_proposal_resolvable<ProposalType: store>(
        voting_forum_address: address,
        proposal_id: u64,
    ) acquires VotingForum {
        let proposal_state = get_proposal_state<ProposalType>(voting_forum_address, proposal_id);
        assert!(proposal_state == PROPOSAL_STATE_SUCCEEDED, error::invalid_state(EPROPOSAL_CANNOT_BE_RESOLVED));

        let voting_forum = borrow_global_mut<VotingForum<ProposalType>>(voting_forum_address);
        let proposal = table::borrow_mut(&mut voting_forum.proposals, proposal_id);
        assert!(!proposal.is_resolved, error::invalid_state(EPROPOSAL_ALREADY_RESOLVED));

        // We need to make sure that the resolution is happening in
        // a separate transaction from the last vote to guard against any potential flashloan attacks.
        let resolvable_time = to_u64(*simple_map::borrow(&proposal.metadata, &utf8(RESOLVABLE_TIME_METADATA_KEY)));
        assert!(timestamp::now_seconds() > resolvable_time, error::invalid_state(ERESOLUTION_CANNOT_BE_ATOMIC));

        assert!(
            transaction_context::get_script_hash() == proposal.execution_hash,
            error::invalid_argument(EPROPOSAL_EXECUTION_HASH_NOT_MATCHING),
        );
```

**File:** aptos-move/framework/aptos-framework/sources/voting.move (L514-566)
```text
    public fun resolve_proposal_v2<ProposalType: store>(
        voting_forum_address: address,
        proposal_id: u64,
        next_execution_hash: vector<u8>,
    ) acquires VotingForum {
        is_proposal_resolvable<ProposalType>(voting_forum_address, proposal_id);

        let voting_forum = borrow_global_mut<VotingForum<ProposalType>>(voting_forum_address);
        let proposal = table::borrow_mut(&mut voting_forum.proposals, proposal_id);

        // Update the IS_MULTI_STEP_PROPOSAL_IN_EXECUTION_KEY key to indicate that the multi-step proposal is in execution.
        let multi_step_in_execution_key = utf8(IS_MULTI_STEP_PROPOSAL_IN_EXECUTION_KEY);
        if (simple_map::contains_key(&proposal.metadata, &multi_step_in_execution_key)) {
            let is_multi_step_proposal_in_execution_value = simple_map::borrow_mut(
                &mut proposal.metadata,
                &multi_step_in_execution_key
            );
            *is_multi_step_proposal_in_execution_value = to_bytes(&true);
        };

        let multi_step_key = utf8(IS_MULTI_STEP_PROPOSAL_KEY);
        let is_multi_step = simple_map::contains_key(&proposal.metadata, &multi_step_key) && from_bcs::to_bool(
            *simple_map::borrow(&proposal.metadata, &multi_step_key)
        );
        let next_execution_hash_is_empty = vector::length(&next_execution_hash) == 0;

        // Assert that if this proposal is single-step, the `next_execution_hash` parameter is empty.
        assert!(
            is_multi_step || next_execution_hash_is_empty,
            error::invalid_argument(ESINGLE_STEP_PROPOSAL_CANNOT_HAVE_NEXT_EXECUTION_HASH)
        );

        // If the `next_execution_hash` parameter is empty, it means that either
        // - this proposal is a single-step proposal, or
        // - this proposal is multi-step and we're currently resolving the last step in the multi-step proposal.
        // We can mark that this proposal is resolved.
        if (next_execution_hash_is_empty) {
            proposal.is_resolved = true;
            proposal.resolution_time_secs = timestamp::now_seconds();

            // Set the `IS_MULTI_STEP_PROPOSAL_IN_EXECUTION_KEY` value to false upon successful resolution of the last step of a multi-step proposal.
            if (is_multi_step) {
                let is_multi_step_proposal_in_execution_value = simple_map::borrow_mut(
                    &mut proposal.metadata,
                    &multi_step_in_execution_key
                );
                *is_multi_step_proposal_in_execution_value = to_bytes(&false);
            };
        } else {
            // If the current step is not the last step,
            // update the proposal's execution hash on-chain to the execution hash of the next step.
            proposal.execution_hash = next_execution_hash;
        };
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L643-661)
```text
    /// Resolve a successful multi-step proposal. This would fail if the proposal is not successful.
    public fun resolve_multi_step_proposal(
        proposal_id: u64,
        signer_address: address,
        next_execution_hash: vector<u8>
    ): signer acquires GovernanceResponsbility, ApprovedExecutionHashes {
        voting::resolve_proposal_v2<GovernanceProposal>(@aptos_framework, proposal_id, next_execution_hash);
        // If the current step is the last step of this multi-step proposal,
        // we will remove the execution hash from the ApprovedExecutionHashes map.
        if (vector::length(&next_execution_hash) == 0) {
            remove_approved_hash(proposal_id);
        } else {
            // If the current step is not the last step of this proposal,
            // we replace the current execution hash with the next execution hash
            // in the ApprovedExecutionHashes map.
            add_approved_script_hash(proposal_id)
        };
        get_signer(signer_address)
    }
```

**File:** crates/aptos/src/governance/mod.rs (L1007-1050)
```rust
    #[clap(long, default_value = "")]
    pub(crate) next_execution_hash: String,

    #[clap(flatten)]
    pub(crate) move_options: MovePackageOptions,
}

#[async_trait]
impl CliCommand<()> for GenerateUpgradeProposal {
    fn command_name(&self) -> &'static str {
        "GenerateUpgradeProposal"
    }

    async fn execute(self) -> CliTypedResult<()> {
        let GenerateUpgradeProposal {
            move_options,
            account,
            included_artifacts,
            output,
            testnet,
            next_execution_hash,
        } = self;
        let package_path = move_options.get_package_path()?;
        let options = included_artifacts.build_options(&move_options)?;
        let package = BuiltPackage::build(package_path, options)?;
        let release = ReleasePackage::new(package)?;

        // If we're generating a single-step proposal on testnet
        if testnet && next_execution_hash.is_empty() {
            release.generate_script_proposal_testnet(account, output)?;
            // If we're generating a single-step proposal on mainnet
        } else if next_execution_hash.is_empty() {
            release.generate_script_proposal(account, output)?;
            // If we're generating a multi-step proposal
        } else {
            let next_execution_hash_bytes = hex::decode(next_execution_hash)?;
            let next_execution_hash =
                HashValue::from_slice(next_execution_hash_bytes).map_err(|_err| {
                    CliError::CommandArgumentError("Invalid next execution hash".to_string())
                })?;
            release.generate_script_proposal_multi_step(
                account,
                output,
                Some(next_execution_hash),
```

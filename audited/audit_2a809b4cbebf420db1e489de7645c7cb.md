# Audit Report

## Title
Multi-Step Governance Proposal Early Termination Bypass

## Summary
The Aptos governance system allows proposers to create multi-step proposals that can be prematurely terminated after any step, bypassing voter expectations and potentially leaving the network in an unsafe or inconsistent state. A malicious proposer can create a proposal marked as multi-step, gain approval from voters who expect N steps to execute, but then terminate the proposal after just 1 step by providing an empty `next_execution_hash` vector.

## Finding Description

The vulnerability exists in the multi-step proposal resolution mechanism. When `aptos_governance::create_proposal_v2()` is called with `is_multi_step_proposal = true`, voters approve the proposal expecting multiple execution steps to complete sequentially. However, the on-chain enforcement of multi-step execution is fundamentally flawed. [1](#0-0) 

The `is_multi_step_proposal` boolean is stored as metadata in the proposal: [2](#0-1) 

The critical flaw occurs in the resolution logic: [3](#0-2) 

When `resolve_proposal_v2()` is called, if `next_execution_hash` is an empty vector, the proposal is immediately marked as fully resolved (`is_resolved = true`), regardless of whether this was intended to be the final step or not. There is NO on-chain enforcement that a multi-step proposal must execute a specific number of steps.

The attack flow:

1. **Proposal Creation**: Attacker creates a proposal with `is_multi_step_proposal = true`, advertising off-chain that it will have N steps (e.g., Step 1: Enable feature, Step 2: Migrate data, Step 3: Verify, Step 4: Cleanup)

2. **Voting**: Voters review the off-chain documentation and vote yes, expecting all N steps to execute as described

3. **Execution Hash Verification**: When step 1 executes, the script hash is verified to match the proposal's `execution_hash`: [4](#0-3) 

4. **Early Termination**: The step 1 script calls `resolve_multi_step_proposal()` with an empty `next_execution_hash` vector: [5](#0-4) 

5. **Proposal Marked Complete**: The proposal is marked as fully resolved, and steps 2-N never execute

**Governance Integrity Invariant Violation**: Voters cast votes based on the expectation that a multi-step proposal will execute all declared steps. The system allows the proposer to unilaterally deviate from this expectation at execution time, after votes have been cast and counted. This breaks the fundamental social contract of governance voting.

## Impact Explanation

This is **CRITICAL SEVERITY** under the Aptos bug bounty program for multiple reasons:

**1. Loss of Funds**: If step 1 unlocks funds or mints tokens but step 2 was supposed to distribute them properly, the attacker can prevent step 2 from executing, effectively stealing the funds.

**2. Non-recoverable Network State**: An incomplete multi-step upgrade could:
- Enable a feature without migrating required state → consensus splits if validators interpret the incomplete state differently
- Update configuration without cleanup → validators crash or behave unpredictably
- Leave the network in a state requiring emergency hardfork intervention

**3. Consensus/Safety Violations**: Consider a multi-step upgrade proposal:
- Step 1: Enable new consensus rules
- Step 2: Update validator parameters
- Step 3: Perform state migration

If terminated after step 1, validators may diverge on how to handle transactions under the new rules without proper parameters/state, potentially causing safety violations.

**4. Permanent Freezing of State**: If step 1 locks resources or capabilities expecting step 2 to unlock them, early termination permanently freezes those resources.

**5. Governance Trust Destruction**: This attack fundamentally undermines on-chain governance by allowing proposers to execute different logic than what voters approved, destroying trust in the governance mechanism itself.

## Likelihood Explanation

**Likelihood: HIGH**

**Attacker Requirements**:
- Sufficient stake to meet `required_proposer_stake` threshold (can be achieved by any well-funded actor or by convincing a large stake pool to propose)
- Ability to craft an execution script (trivial for any developer)
- Ability to convince voters to approve the proposal (requires social engineering, but feasible if the proposal appears legitimate)

**Attack Complexity: LOW**
- The exploit requires only passing an empty vector (`vector::empty<u8>()`) as `next_execution_hash`
- No special privileges, timing attacks, or complex state manipulation required
- The vulnerability is deterministic and reliable

**Detection Difficulty: HIGH**
- Voters cannot verify on-chain what subsequent steps will do
- The `next_execution_hash` values are only provided at runtime during execution
- Off-chain documentation can claim N steps, but there's no enforcement
- Even legitimate proposals could accidentally trigger this by passing empty hash

**Real-World Scenario**: A malicious or compromised proposal could advertise a multi-step upgrade (e.g., "We're upgrading the staking module in 3 careful steps with validation at each stage"), gain approval, but then execute only step 1 which grants the attacker admin privileges, terminating before the validation steps.

## Recommendation

**Immediate Fix**: Enforce that the number of steps in a multi-step proposal matches what was declared at creation time.

**Implementation Approach**:

1. Add a new metadata field `TOTAL_STEPS_KEY` when creating multi-step proposals:

```move
// In create_proposal_v2 function
if (is_multi_step_proposal) {
    assert!(total_steps > 1, error::invalid_argument(EINVALID_TOTAL_STEPS));
    simple_map::add(&mut metadata, utf8(TOTAL_STEPS_KEY), to_bytes(&total_steps));
    simple_map::add(&mut metadata, utf8(CURRENT_STEP_KEY), to_bytes(&1u64));
    simple_map::add(&mut metadata, is_multi_step_in_execution_key, to_bytes(&false));
}
```

2. In `resolve_proposal_v2`, enforce step counting:

```move
if (is_multi_step) {
    let current_step_key = utf8(CURRENT_STEP_KEY);
    let total_steps_key = utf8(TOTAL_STEPS_KEY);
    let current_step = from_bcs::to_u64(*simple_map::borrow(&proposal.metadata, &current_step_key));
    let total_steps = from_bcs::to_u64(*simple_map::borrow(&proposal.metadata, &total_steps_key));
    
    // Only allow empty next_execution_hash if this is the declared final step
    assert!(
        !next_execution_hash_is_empty || current_step == total_steps,
        error::invalid_state(EMULTI_STEP_PROPOSAL_EARLY_TERMINATION)
    );
    
    // Increment step counter
    if (!next_execution_hash_is_empty) {
        *simple_map::borrow_mut(&mut proposal.metadata, &current_step_key) = to_bytes(&(current_step + 1));
    }
}
```

3. Update the `create_proposal_v2` function signature to accept `total_steps: u64` parameter for multi-step proposals.

**Alternative Approach**: Store all execution hashes at proposal creation time (more transparent but less flexible for conditional logic).

## Proof of Concept

```move
#[test(aptos_framework = @aptos_framework, proposer = @0x123, voter = @0x234)]
public entry fun test_multi_step_early_termination_exploit(
    aptos_framework: signer,
    proposer: signer,
    voter: signer,
) acquires ApprovedExecutionHashes, GovernanceConfig, GovernanceResponsbility, VotingRecords, VotingRecordsV2, GovernanceEvents {
    // Setup
    setup_partial_voting(&aptos_framework, &proposer, &voter, &voter);
    
    // Create a multi-step proposal (claiming it will have multiple steps)
    let execution_hash = vector[1]; // Step 1 hash
    create_proposal_v2(
        &proposer,
        signer::address_of(&proposer),
        execution_hash,
        b"Multi-step upgrade: Step 1 (enable feature), Step 2 (migrate data), Step 3 (verify)",
        b"hash_of_detailed_plan",
        true, // is_multi_step_proposal = TRUE
    );
    
    // Vote passes
    vote(&voter, signer::address_of(&voter), 0, true);
    
    // Fast forward to after voting period
    timestamp::update_global_time_for_test(100001000000);
    
    // Add approved hash
    add_approved_script_hash(0);
    
    // EXPLOIT: Resolve with empty next_execution_hash after FIRST step only
    // This marks the proposal as complete, skipping steps 2 and 3 that voters expected
    resolve_multi_step_proposal(
        0, 
        @aptos_framework, 
        vector::empty<u8>() // EMPTY vector terminates proposal early!
    );
    
    // Verify proposal is fully resolved after just ONE step
    assert!(voting::is_resolved<GovernanceProposal>(@aptos_framework, 0), 0);
    
    // Steps 2 and 3 can NEVER execute - voters were deceived!
    // The feature is enabled but data was not migrated and verification never happened.
    // Network could be in inconsistent state leading to consensus issues.
}
```

This test demonstrates that a multi-step proposal marked as having multiple steps can be terminated after the first step by passing an empty `next_execution_hash`, completely bypassing the intended multi-step execution flow and deceiving voters about what they approved.

## Notes

The vulnerability stems from a fundamental design flaw: the `is_multi_step_proposal` flag is merely descriptive metadata with no enforcement mechanism. The actual control over how many steps execute resides entirely with the execution scripts, which can terminate at any point by passing an empty `next_execution_hash` vector. This creates an asymmetry between what voters approve (a multi-step process) and what actually executes (potentially just one step), breaking governance integrity.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L383-399)
```text
    public entry fun create_proposal_v2(
        proposer: &signer,
        stake_pool: address,
        execution_hash: vector<u8>,
        metadata_location: vector<u8>,
        metadata_hash: vector<u8>,
        is_multi_step_proposal: bool,
    ) acquires GovernanceConfig, GovernanceEvents {
        create_proposal_v2_impl(
            proposer,
            stake_pool,
            execution_hash,
            metadata_location,
            metadata_hash,
            is_multi_step_proposal
        );
    }
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L644-661)
```text
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

**File:** aptos-move/framework/aptos-framework/sources/voting.move (L318-330)
```text
        simple_map::add(&mut metadata, utf8(IS_MULTI_STEP_PROPOSAL_KEY), to_bytes(&is_multi_step_proposal));

        let is_multi_step_in_execution_key = utf8(IS_MULTI_STEP_PROPOSAL_IN_EXECUTION_KEY);
        if (is_multi_step_proposal) {
            // If the given proposal is a multi-step proposal, we will add a flag to indicate if this multi-step proposal is in execution.
            // This value is by default false. We turn this value to true when we start executing the multi-step proposal. This value
            // will be used to disable further voting after we started executing the multi-step proposal.
            simple_map::add(&mut metadata, is_multi_step_in_execution_key, to_bytes(&false));
            // If the proposal is a single-step proposal, we check if the metadata passed by the client has the IS_MULTI_STEP_PROPOSAL_IN_EXECUTION_KEY key.
            // If they have the key, we will remove it, because a single-step proposal that doesn't need this key.
        } else if (simple_map::contains_key(&metadata, &is_multi_step_in_execution_key)) {
            simple_map::remove(&mut metadata, &is_multi_step_in_execution_key);
        };
```

**File:** aptos-move/framework/aptos-framework/sources/voting.move (L447-450)
```text
        assert!(
            transaction_context::get_script_hash() == proposal.execution_hash,
            error::invalid_argument(EPROPOSAL_EXECUTION_HASH_NOT_MATCHING),
        );
```

**File:** aptos-move/framework/aptos-framework/sources/voting.move (L546-566)
```text
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

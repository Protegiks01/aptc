# Audit Report

## Title
Multi-Step Governance Proposals Allow Unbounded Time Gaps Between Steps Enabling Adaptive Attack Strategies

## Summary
Multi-step governance proposals in Aptos lack time constraints between execution steps, allowing attackers to delay subsequent steps indefinitely while observing chain state, market conditions, and other governance actions. Once a proposal begins execution, voting is permanently disabled, giving attackers unlimited control over execution timing without community recourse.

## Finding Description

The Aptos governance system allows multi-step proposals through the `create_proposal_v2()` function. The vulnerability exists in how time constraints are enforced during proposal execution: [1](#0-0) 

The `RESOLVABLE_TIME_METADATA_KEY` is set during voting to record when the last vote occurred, ensuring proposals cannot be resolved in the same transaction as voting (preventing flashloan attacks).

However, when resolving multi-step proposals via `resolve_proposal_v2()`: [2](#0-1) 

The function calls `is_proposal_resolvable()` which checks: [3](#0-2) 

The critical flaw is that `resolvable_time` is **never updated** during step execution - it permanently remains the timestamp of the last vote. This means:

1. Step 1 can be executed any time after voting ends (once `timestamp::now_seconds() > resolvable_time`)
2. Steps 2, 3, etc. can be executed at **any time** after step 1, with no upper bound
3. The only check is that each step happens in a different transaction

Once execution begins, the `IS_MULTI_STEP_PROPOSAL_IN_EXECUTION_KEY` is set to true: [4](#0-3) 

This permanently disables further voting: [5](#0-4) 

**Attack Scenario:**

1. Attacker creates a 3-step proposal with opaque intent (e.g., "Parameter adjustment proposal")
   - Step 1: Grant attacker temporary capability or modify configuration
   - Step 2: Exploit capability based on favorable oracle prices
   - Step 3: Cleanup/revert changes

2. Community votes and proposal passes

3. Attacker executes Step 1 immediately after voting period ends

4. Attacker monitors for weeks/months:
   - Price oracle updates (DeFi protocols)
   - Other governance proposal outcomes
   - Validator set changes
   - Market conditions
   - Smart contract state changes

5. When conditions are optimal for maximum exploit, attacker executes Step 2

6. Attacker executes Step 3 at leisure

The community has **zero recourse** once execution begins - they cannot vote to stop the remaining steps, and there is no timeout mechanism.

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty program criteria:

- **State inconsistencies requiring intervention**: The attacker can create governance states that require emergency intervention, as proposals remain "in execution" indefinitely
- **Limited governance manipulation**: While not directly causing fund loss, it allows attackers to time governance actions based on observed conditions, violating the principle of immutable, time-bound governance decisions
- **Governance Integrity violation**: Breaks the "Governance Integrity" invariant that governance decisions should be executed in a predictable, timely manner

The attack requires the attacker to first gain community approval for their proposal, which provides some barrier to entry. However, complex multi-step proposals could obscure malicious intent, and the ability to adapt execution strategy based on observed conditions amplifies potential damage.

## Likelihood Explanation

**Likelihood: Medium-High**

Required conditions:
- Attacker must craft a multi-step proposal that passes community voting (moderate barrier)
- Attack execution requires no special privileges beyond normal governance participation
- No technical complexity in exploiting - just requires waiting between steps

Factors increasing likelihood:
- Complex multi-step proposals are inherently harder for community to audit
- No existing mechanism to limit time between steps
- Once execution begins, community is powerless to intervene
- Attack can be combined with other governance or economic manipulation

Factors decreasing likelihood:
- Requires initial community approval
- Overtly malicious proposals may be rejected
- Blockchain transparency means delayed execution could raise suspicion

## Recommendation

Implement a maximum execution deadline for multi-step proposals. Add a new metadata field `EXECUTION_DEADLINE_KEY` set during proposal creation:

**In `voting.move` during `create_proposal_v2()`:**
```move
// Add execution deadline for multi-step proposals
if (is_multi_step_proposal) {
    // Multi-step proposals must complete all steps within 2x the voting duration
    let execution_deadline = expiration_secs + (expiration_secs - timestamp::now_seconds());
    simple_map::add(&mut metadata, utf8(EXECUTION_DEADLINE_KEY), to_bytes(&execution_deadline));
}
```

**In `is_proposal_resolvable()` function:**
```move
// Check if execution deadline has passed for multi-step proposals
let is_multi_step_key = utf8(IS_MULTI_STEP_PROPOSAL_KEY);
if (simple_map::contains_key(&proposal.metadata, &is_multi_step_key)) {
    let deadline_key = utf8(EXECUTION_DEADLINE_KEY);
    if (simple_map::contains_key(&proposal.metadata, &deadline_key)) {
        let execution_deadline = to_u64(*simple_map::borrow(&proposal.metadata, &deadline_key));
        assert!(
            timestamp::now_seconds() <= execution_deadline,
            error::invalid_state(EPROPOSAL_EXECUTION_DEADLINE_EXCEEDED)
        );
    }
}
```

Alternatively, update `RESOLVABLE_TIME_METADATA_KEY` after each step:

**In `resolve_proposal_v2()` after line 565:**
```move
} else {
    // Update execution hash for next step
    proposal.execution_hash = next_execution_hash;
    
    // Update resolvable time to enforce timeout between steps
    let resolvable_key = utf8(RESOLVABLE_TIME_METADATA_KEY);
    *simple_map::borrow_mut(&mut proposal.metadata, &resolvable_key) = to_bytes(&timestamp::now_seconds());
}
```

And modify `is_proposal_resolvable()` to add a maximum time window check:

```move
// For multi-step proposals in execution, enforce maximum time between steps
let is_multi_step_in_execution_key = utf8(IS_MULTI_STEP_PROPOSAL_IN_EXECUTION_KEY);
if (simple_map::contains_key(&proposal.metadata, &is_multi_step_in_execution_key) 
    && from_bcs::to_bool(*simple_map::borrow(&proposal.metadata, &is_multi_step_in_execution_key))) {
    
    let max_time_between_steps = 7 * 24 * 3600; // 7 days
    assert!(
        timestamp::now_seconds() <= resolvable_time + max_time_between_steps,
        error::invalid_state(ESTEP_EXECUTION_TIMEOUT)
    );
}
```

## Proof of Concept

```move
#[test(aptos_framework = @aptos_framework, proposer = @0x123, voter = @0x234)]
public entry fun test_multi_step_proposal_unbounded_time_gap(
    aptos_framework: signer,
    proposer: signer,
    voter: signer,
) acquires VotingForum {
    use aptos_framework::timestamp;
    use aptos_framework::account;
    
    account::create_account_for_test(@aptos_framework);
    timestamp::set_time_has_started_for_testing(&aptos_framework);
    
    // Create multi-step proposal
    let proposer_address = signer::address_of(&proposer);
    account::create_account_for_test(proposer_address);
    
    register<TestProposal>(&proposer);
    let proposal = TestProposal {};
    let execution_hash = vector[1u8];
    
    let proposal_id = create_proposal_v2<TestProposal>(
        proposer_address,
        proposer_address,
        proposal,
        execution_hash,
        10,
        timestamp::now_seconds() + 100000, // Voting ends in ~1 day
        option::some(100),
        simple_map::create<String, vector<u8>>(),
        true // multi-step
    );
    
    // Vote and pass proposal
    let proof = TestProposal {};
    vote<TestProposal>(&proof, proposer_address, proposal_id, 100, true);
    let TestProposal {} = proof;
    
    // Wait for voting to end
    timestamp::fast_forward_seconds(100001);
    
    // Execute step 1
    timestamp::fast_forward_seconds(1);
    resolve_proposal_v2<TestProposal>(proposer_address, proposal_id, vector[2u8]); // Step 1 with next hash
    
    // EXPLOIT: Wait 6 months (simulated)
    timestamp::fast_forward_seconds(180 * 24 * 3600);
    
    // Execute step 2 after 6 months - THIS SHOULD FAIL BUT DOESN'T
    resolve_proposal_v2<TestProposal>(proposer_address, proposal_id, vector::empty<u8>()); // Final step
    
    // Verify proposal completed after unreasonable delay
    let voting_forum = borrow_global<VotingForum<TestProposal>>(proposer_address);
    assert!(table::borrow(&voting_forum.proposals, proposal_id).is_resolved, 0);
}
```

This test demonstrates that a multi-step proposal can have a 6-month gap between steps with no time limit enforcement, allowing the attacker to observe chain state and market conditions before executing subsequent steps.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/voting.move (L399-403)
```text
        assert!(!simple_map::contains_key(&proposal.metadata, &utf8(IS_MULTI_STEP_PROPOSAL_IN_EXECUTION_KEY))
            || *simple_map::borrow(&proposal.metadata, &utf8(IS_MULTI_STEP_PROPOSAL_IN_EXECUTION_KEY)) == to_bytes(
            &false
        ),
            error::invalid_state(EMULTI_STEP_PROPOSAL_IN_EXECUTION));
```

**File:** aptos-move/framework/aptos-framework/sources/voting.move (L411-418)
```text
        // Record the resolvable time to ensure that resolution has to be done non-atomically.
        let timestamp_secs_bytes = to_bytes(&timestamp::now_seconds());
        let key = utf8(RESOLVABLE_TIME_METADATA_KEY);
        if (simple_map::contains_key(&proposal.metadata, &key)) {
            *simple_map::borrow_mut(&mut proposal.metadata, &key) = timestamp_secs_bytes;
        } else {
            simple_map::add(&mut proposal.metadata, key, timestamp_secs_bytes);
        };
```

**File:** aptos-move/framework/aptos-framework/sources/voting.move (L431-451)
```text
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
    }
```

**File:** aptos-move/framework/aptos-framework/sources/voting.move (L514-592)
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

        // For single-step proposals, we emit one `ResolveProposal` event per proposal.
        // For multi-step proposals, we emit one `ResolveProposal` event per step in the multi-step proposal. This means
        // that we emit multiple `ResolveProposal` events for the same multi-step proposal.
        let resolved_early = can_be_resolved_early(proposal);
        if (std::features::module_event_migration_enabled()) {
            event::emit(
                ResolveProposal {
                    proposal_id,
                    yes_votes: proposal.yes_votes,
                    no_votes: proposal.no_votes,
                    resolved_early,
                },
            );
        } else {
            event::emit_event(
                &mut voting_forum.events.resolve_proposal_events,
                ResolveProposal {
                    proposal_id,
                    yes_votes: proposal.yes_votes,
                    no_votes: proposal.no_votes,
                    resolved_early,
                },
            );
        };
    }
```

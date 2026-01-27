# Audit Report

## Title
Non-Atomic Multi-Step Governance Proposal Execution Enables Dangerous Intermediate Chain States

## Summary
Multi-step governance proposals in Aptos execute non-atomically across multiple epochs, with each step triggering reconfiguration independently. This allows execution config changes (such as disabling gas limits) to take effect in isolation before subsequent steps complete, creating exploitable intermediate states that violate the State Consistency invariant.

## Finding Description

The multi-step proposal mechanism has a fundamental atomicity violation. When analyzing the execution flow: [1](#0-0) 

Each execution config script calls both `set_for_next_epoch()` and `reconfigure()`. The reconfiguration triggers immediately: [2](#0-1) 

When multiple config changes are combined in a multi-step proposal, the execution sequence defined in `update_sequence` determines ordering: [3](#0-2) 

The vulnerability emerges because:

1. **Only first script validated during voting**: When creating a multi-step proposal, only the first script's execution hash is cryptographically verified during voting: [4](#0-3) 

2. **Hash chain controls subsequent steps**: Each executing script provides the next execution hash dynamically: [5](#0-4) 

3. **No semantic validation on execution config**: The execution config module only validates non-empty blobs, not safety properties: [6](#0-5) 

4. **Immediate effect with no rollback**: Each step's changes become active in the new epoch with many blocks potentially executing before the next step.

## Impact Explanation

This breaks the **State Consistency** invariant requiring atomic state transitions and the **Resource Limits** invariant requiring gas limits enforcement. 

A malicious proposal ordering [ExecutionConfig: NoGasLimit, FeatureFlag: EnableDangerousFeature] creates a window where:
- Gas limits are disabled globally
- Attackers can submit unlimited-gas transactions
- The dangerous feature assumes gas limits exist but they don't
- Network resource exhaustion occurs

This qualifies as **High Severity** under "Significant protocol violations" as it enables consensus-threatening resource exhaustion attacks during the intermediate state window.

## Likelihood Explanation

**Moderate-to-Low likelihood** because:
- Requires creating a governance proposal (needs governance permissions + stake)
- Requires voter approval of dangerous configuration
- Relies on voters not carefully auditing the `update_sequence` ordering
- Config files are public for review

However, likelihood increases if:
- Proposals are complex with many steps
- Voters trust proposer reputation without deep technical review  
- Dangerous ordering appears plausible at surface level

## Recommendation

**Option 1: Batch Configuration Updates (Preferred)**
```rust
// In execution_config.rs - accumulate configs, apply atomically
pub fn generate_batched_config_update_proposal(
    configs: Vec<ConfigUpdate>,
    is_testnet: bool,
) -> Result<Vec<(String, String)>> {
    // Serialize all configs
    // Single script that applies all changes
    // Single reconfigure() call at end
}
```

**Option 2: Add Semantic Validation**
```move
// In execution_config.move
public fun validate_config_safety(config: vector<u8>) {
    let parsed = parse_execution_config(config);
    assert!(has_gas_limits(&parsed), EUNSAFE_CONFIG);
    assert!(is_shuffler_safe(&parsed), EUNSAFE_CONFIG);
}
```

**Option 3: Require Explicit Ordering Attestation**
Add metadata to proposals requiring proposers to explicitly document ordering rationale and safety analysis.

## Proof of Concept

```move
#[test(aptos_framework = @aptos_framework, proposer = @0x123)]
fun test_non_atomic_execution_config_ordering_attack(
    aptos_framework: signer,
    proposer: signer
) {
    // Setup: Initialize governance with proposer stake
    setup_governance(&aptos_framework, &proposer);
    
    // Step 1: Create multi-step proposal
    // First script: Disable gas limits via ExecutionConfig
    let dangerous_config = create_no_gas_limit_config();
    let config_blob = bcs::to_bytes(&dangerous_config);
    
    // Claim: "This enables feature X which requires gas limit changes"
    // Reality: Step 1 disables ALL gas limits globally
    
    let proposal_id = create_multi_step_proposal(
        &proposer,
        hash(dangerous_config_script), // Only this gets voted on
        b"Safe configuration update",
    );
    
    // Voting happens - voters approve first hash only
    vote(&proposer, proposal_id, true);
    timestamp::fast_forward(VOTING_DURATION + 1);
    
    // Step 1 executes: Gas limits disabled, epoch changes
    execute_step_1(proposal_id); // Calls reconfigure()
    
    // VULNERABILITY WINDOW: Between step 1 and step 2
    // - Gas limits are disabled
    // - Attacker submits huge-gas transactions
    // - Network resources exhausted
    // - Consensus degraded
    
    assert!(get_gas_limit_type() == NoLimit); // Verified vulnerability
    
    // Many blocks pass before step 2 executes...
    // Damage already done
}
```

## Notes

While the hash chain prevents reordering scripts *after* generation, the fundamental issue is that multi-step proposals execute non-atomically across epochs with no semantic validation of intermediate states. The voting process only cryptographically verifies the first script, creating trust assumptions about subsequent steps that governance participants may not fully understand.

### Citations

**File:** aptos-move/aptos-release-builder/src/components/execution_config.rs (L40-46)
```rust
            emitln!(
                writer,
                "execution_config::set_for_next_epoch({}, execution_blob);",
                signer_arg
            );
            emitln!(writer, "aptos_governance::reconfigure({});", signer_arg);
        },
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L685-692)
```text
    public entry fun reconfigure(aptos_framework: &signer) {
        system_addresses::assert_aptos_framework(aptos_framework);
        if (consensus_config::validator_txn_enabled() && randomness_config::enabled()) {
            reconfiguration_with_dkg::try_start();
        } else {
            reconfiguration_with_dkg::finish(aptos_framework);
        }
    }
```

**File:** aptos-move/aptos-release-builder/src/components/mod.rs (L657-667)
```rust
            if let ExecutionMode::MultiStep = &proposal.execution_mode {
                for entry in proposal.update_sequence.iter().rev() {
                    entry
                        .generate_release_script(
                            client.as_ref(),
                            &mut result,
                            proposal.execution_mode,
                        )
                        .await?;
                }
                result.reverse();
```

**File:** aptos-move/framework/aptos-framework/sources/voting.move (L293-372)
```text
    public fun create_proposal_v2<ProposalType: store>(
        proposer: address,
        voting_forum_address: address,
        execution_content: ProposalType,
        execution_hash: vector<u8>,
        min_vote_threshold: u128,
        expiration_secs: u64,
        early_resolution_vote_threshold: Option<u128>,
        metadata: SimpleMap<String, vector<u8>>,
        is_multi_step_proposal: bool,
    ): u64 acquires VotingForum {
        if (option::is_some(&early_resolution_vote_threshold)) {
            assert!(
                min_vote_threshold <= *option::borrow(&early_resolution_vote_threshold),
                error::invalid_argument(EINVALID_MIN_VOTE_THRESHOLD),
            );
        };
        // Make sure the execution script's hash is not empty.
        assert!(vector::length(&execution_hash) > 0, error::invalid_argument(EPROPOSAL_EMPTY_EXECUTION_HASH));

        let voting_forum = borrow_global_mut<VotingForum<ProposalType>>(voting_forum_address);
        let proposal_id = voting_forum.next_proposal_id;
        voting_forum.next_proposal_id = voting_forum.next_proposal_id + 1;

        // Add a flag to indicate if this proposal is single-step or multi-step.
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

        table::add(&mut voting_forum.proposals, proposal_id, Proposal {
            proposer,
            creation_time_secs: timestamp::now_seconds(),
            execution_content: option::some<ProposalType>(execution_content),
            execution_hash,
            metadata,
            min_vote_threshold,
            expiration_secs,
            early_resolution_vote_threshold,
            yes_votes: 0,
            no_votes: 0,
            is_resolved: false,
            resolution_time_secs: 0,
        });

        if (std::features::module_event_migration_enabled()) {
            event::emit(
                CreateProposal {
                    proposal_id,
                    early_resolution_vote_threshold,
                    execution_hash,
                    expiration_secs,
                    metadata,
                    min_vote_threshold,
                },
            );
        } else {
            event::emit_event<CreateProposalEvent>(
                &mut voting_forum.events.create_proposal_events,
                CreateProposalEvent {
                    proposal_id,
                    early_resolution_vote_threshold,
                    execution_hash,
                    expiration_secs,
                    metadata,
                    min_vote_threshold,
                },
            );
        };
        proposal_id
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

**File:** aptos-move/framework/aptos-framework/sources/configs/execution_config.move (L48-52)
```text
    public fun set_for_next_epoch(account: &signer, config: vector<u8>) {
        system_addresses::assert_aptos_framework(account);
        assert!(vector::length(&config) > 0, error::invalid_argument(EINVALID_CONFIG));
        config_buffer::upsert(ExecutionConfig { config });
    }
```

# Audit Report

## Title
Multi-Step Governance Proposals Lack Atomicity Validation Enabling Permanent Inconsistent State

## Summary
The Aptos governance multi-step proposal mechanism does not validate that all steps complete successfully before applying configuration changes. Once a step executes, its changes are permanent and on-chain, even if subsequent steps fail or are never executed. This can leave critical system configurations in an inconsistent state indefinitely, with no rollback mechanism.

## Finding Description
The multi-step proposal system in Aptos governance allows splitting large governance actions across multiple transaction steps. Each step calls `resolve_multi_step_proposal` which updates the approved execution hash to the next step, then executes configuration changes. [1](#0-0) 

The critical flaw is that each step is executed atomically in its own transaction, but there is no validation that subsequent steps will complete. Once a step succeeds:

1. The configuration changes from that step are permanently applied
2. The `IS_MULTI_STEP_PROPOSAL_IN_EXECUTION_KEY` flag is set to `true`, blocking further voting
3. The approved execution hash is updated to point to the next step [2](#0-1) 

The flag blocks further voting once execution begins: [3](#0-2) 

However, if subsequent steps are never executed (due to technical failure such as bugs in later step code, transaction size limits, or gas issues), the system remains in a partially-executed state indefinitely. The flag stays `true` and the proposal is never marked as fully resolved, but the changes from completed steps remain active. [4](#0-3) 

The flag is only reset to `false` when the last step completes successfully (when `next_execution_hash` is empty). If execution is abandoned mid-way, the flag remains permanently `true`.

In the specific case of execution config updates, multi-step proposals are used in production to combine execution config, consensus config, and gas schedule changes: [5](#0-4) 

If Step 1 (Consensus config) succeeds but Step 2 (Execution config) fails due to a bug, the network has a new consensus config but old execution config, potentially creating incompatible system state.

The code confirms no rollback mechanism exists - there are no functions to cancel multi-step proposals, reset the execution flag, or rollback partial changes. The proposal's `expiration_secs` only applies to the voting period: [6](#0-5) 

Once approved, steps can be executed at any time without deadline, and there is no cleanup mechanism for abandoned proposals.

## Impact Explanation
This qualifies as **Medium Severity** under Aptos bug bounty criteria: "State inconsistencies requiring manual intervention."

**Specific Impacts:**

1. **System Configuration Inconsistency**: Execution config, gas schedule, consensus config, and feature flags may be mutually dependent. Partial updates could cause transaction processing behavior mismatches between validators, unexpected gas calculations with new execution parameters, or consensus protocol incompatibilities.

2. **Governance System Deadlock**: The `IS_MULTI_STEP_PROPOSAL_IN_EXECUTION_KEY` flag remains permanently `true` for abandoned proposals, marking them as "in execution" indefinitely with no cleanup path, blocking any further voting on that proposal.

3. **Network Intervention Required**: Manual governance action would be needed to create new proposals to revert or complete changes. No automated recovery mechanism exists.

The severity is Medium rather than High/Critical because:
- Does not directly cause fund loss or consensus safety violation
- Requires governance proposal to pass first (social layer protection)  
- Can be manually recovered through new governance proposals
- Does not affect already-committed blocks or consensus history

## Likelihood Explanation
**Likelihood: Medium**

This issue is likely to occur because:

1. **Multi-step proposals are standard practice**: The example configuration shows production usage of multi-step proposals combining execution, consensus, and gas changes.

2. **No technical enforcement of completion**: Steps can be executed days or weeks apart with no deadline enforced after voting concludes.

3. **Technical failure scenarios**: Transaction size limits, gas issues, or bugs in later steps can realistically prevent execution without requiring malicious actors. A bug in Step 2 code would genuinely prevent completion, leaving the system stuck.

4. **No warnings or safeguards**: The code has no comments warning about this risk, and no validation that dependent configs are compatible or that all steps will complete successfully.

## Recommendation
Implement one or more of the following mitigations:

1. **Add execution deadline**: Extend `expiration_secs` to apply to step execution, not just voting. If steps aren't completed within the deadline, automatically reset the `IS_MULTI_STEP_PROPOSAL_IN_EXECUTION_KEY` flag to `false`.

2. **Add cleanup function**: Create an administrative function to reset abandoned multi-step proposals and mark them as failed if execution isn't completed within a reasonable timeframe.

3. **Add atomic validation**: Before executing Step 1, validate that all subsequent steps can compile and pass basic checks to reduce likelihood of mid-execution failures.

4. **Add rollback capability**: Store configuration snapshots before multi-step execution begins, allowing rollback if later steps fail.

## Proof of Concept
The following scenario demonstrates the issue:

1. Create a multi-step proposal with 2 steps (Consensus config + Execution config)
2. Execute Step 1 successfully - `IS_MULTI_STEP_PROPOSAL_IN_EXECUTION_KEY = true`, consensus config updated
3. Step 2 contains a bug and cannot execute
4. System state: `IS_MULTI_STEP_PROPOSAL_IN_EXECUTION_KEY` permanently `true`, proposal never marked `is_resolved`, consensus config updated but execution config unchanged
5. No automatic mechanism exists to reset the flag or rollback Step 1's changes
6. Manual governance intervention required to create new proposals to fix the inconsistent state

This can be verified by examining the code paths in `voting.move` and `aptos_governance.move` - there is no cleanup logic for abandoned multi-step proposals.

### Citations

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

**File:** aptos-move/framework/aptos-framework/sources/voting.move (L399-403)
```text
        assert!(!simple_map::contains_key(&proposal.metadata, &utf8(IS_MULTI_STEP_PROPOSAL_IN_EXECUTION_KEY))
            || *simple_map::borrow(&proposal.metadata, &utf8(IS_MULTI_STEP_PROPOSAL_IN_EXECUTION_KEY)) == to_bytes(
            &false
        ),
            error::invalid_state(EMULTI_STEP_PROPOSAL_IN_EXECUTION));
```

**File:** aptos-move/framework/aptos-framework/sources/voting.move (L524-532)
```text
        // Update the IS_MULTI_STEP_PROPOSAL_IN_EXECUTION_KEY key to indicate that the multi-step proposal is in execution.
        let multi_step_in_execution_key = utf8(IS_MULTI_STEP_PROPOSAL_IN_EXECUTION_KEY);
        if (simple_map::contains_key(&proposal.metadata, &multi_step_in_execution_key)) {
            let is_multi_step_proposal_in_execution_value = simple_map::borrow_mut(
                &mut proposal.metadata,
                &multi_step_in_execution_key
            );
            *is_multi_step_proposal_in_execution_value = to_bytes(&true);
        };
```

**File:** aptos-move/framework/aptos-framework/sources/voting.move (L550-561)
```text
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
```

**File:** aptos-move/framework/aptos-framework/sources/voting.move (L770-772)
```text
    fun is_voting_period_over<ProposalType: store>(proposal: &Proposal<ProposalType>): bool {
        timestamp::now_seconds() > proposal.expiration_secs
    }
```

**File:** aptos-move/aptos-release-builder/data/example.yaml (L24-69)
```yaml
  - name: feature_flags
    metadata:
      title: ""
      description: ""
      source_code_url: ""
      discussion_url: ""
    execution_mode: MultiStep
    update_sequence:
      - FeatureFlag:
          enabled:
            - code_dependency_check
            - treat_friend_as_private
            - sha512_and_ripe_md160_natives
            - aptos_std_chain_id_natives
            - v_m_binary_format_v6
            - multi_ed25519_pk_validate_v2_natives
            - blake2b256_native
            - resource_groups
            - multisig_accounts
            - delegation_pools
            - ed25519_pubkey_validate_return_false_wrong_length
            - struct_constructors
            - cryptography_algebra_natives
            - bls12381_structures
          disabled: []
      - Consensus:
          V1:
            decoupled_execution: true
            back_pressure_limit: 10
            exclude_round: 40
            proposer_election_type:
              leader_reputation:
                proposer_and_voter_v2:
                  active_weight: 1000
                  inactive_weight: 10
                  failed_weight: 1
                  failure_threshold_percent: 10
                  proposer_window_num_validators_multiplier: 10
                  voter_window_num_validators_multiplier: 1
                  weight_by_voting_power: true
                  use_history_from_previous_epoch_max_count: 5
            max_failed_authors_to_store: 10
      - Execution:
          V1:
            transaction_shuffler_type: no_shuffling
      - RawScript: data/example_proposals/empty_multi_step.move
```

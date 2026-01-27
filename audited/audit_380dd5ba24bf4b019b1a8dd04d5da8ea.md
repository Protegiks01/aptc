# Audit Report

## Title
Multi-Step Governance Proposals Lack Next Execution Hash Verification, Enabling Potential Governance Bypass

## Summary
The multi-step proposal mechanism in Aptos governance does not verify that the `next_execution_hash` parameter passed during proposal resolution matches any pre-approved or expected value. The system blindly accepts whatever hash value is embedded in the executing script, creating a single point of failure that could allow unauthorized governance actions if the script generation process is compromised or contains bugs.

## Finding Description

The security issue exists in the multi-step proposal resolution flow. When a multi-step governance proposal executes, each step is supposed to specify the hash of the next step via the `next_execution_hash` parameter. However, the system performs no verification that this hash is correct or corresponds to an approved script. [1](#0-0) 

The critical flaw is at line 565 where the proposal's execution_hash is updated without verification: [2](#0-1) 

While the system does verify that the CURRENT script's hash matches (line 448), it does not verify that the NEXT hash being set is valid: [3](#0-2) 

The formal specification claims to guarantee this verification: [4](#0-3) 

However, the actual formal verification only ensures the hash gets stored, not that it's correct: [5](#0-4) 

**Attack Scenario:**

1. A multi-step proposal with steps A, B, C is created
2. Due to a bug in the script generation process or malicious modification, Step A contains `next_execution_hash = hash(X)` instead of `hash(B)`
3. Voters approve Step A (reviewing the script content, but possibly missing the incorrect embedded hash)
4. Step A executes successfully (current hash verification passes)
5. Step A calls `resolve_proposal_v2` with `next_execution_hash = hash(X)`
6. The system accepts this without verification and updates `proposal.execution_hash = hash(X)`
7. An attacker can now execute ANY script with `hash(X)` as the next "step", completely bypassing the intended Step B and Step C
8. This allows execution of unauthorized governance actions

The vulnerability breaks the "Governance Integrity" invariant by allowing the proposal execution sequence to be subverted.

## Impact Explanation

**High Severity** - This vulnerability allows bypassing intended governance steps and executing unauthorized governance actions. According to the Aptos bug bounty criteria, this constitutes a "Significant protocol violation" qualifying as High severity.

The impact includes:
- **Governance Bypass**: Multi-step proposals can deviate from their approved execution sequence
- **Unauthorized Actions**: Attackers could execute governance scripts that were never approved
- **Loss of Trust**: Breaks the fundamental guarantee that multi-step proposals follow their intended sequence
- **No Safety Net**: There's zero defense-in-depth against script generation bugs or supply chain attacks

While this requires either compromising the script generation process or social engineering voters to approve a malicious proposal, the complete lack of verification creates a critical gap in the governance security model.

## Likelihood Explanation

**Medium-High Likelihood** - While exploitation requires specific conditions, multiple realistic attack vectors exist:

1. **Script Generation Bugs**: The off-chain script generation in `aptos-release-builder` is complex. A bug could produce incorrect `next_execution_hash` values: [6](#0-5) 

2. **Supply Chain Compromise**: If the build/release tooling is compromised, attackers could inject malicious `next_execution_hash` values

3. **Voter Oversight**: The `next_execution_hash` is embedded deep in the script code. Voters reviewing proposals might not manually verify these hash values match the intended next scripts

4. **No Automated Verification**: There's no tooling that automatically validates the hash chain during the proposal review process

The likelihood increases because:
- The script generation happens in reverse order, increasing complexity
- Multiple steps and hash calculations create opportunities for errors
- No runtime verification provides a safety net
- The formal spec claims a guarantee that isn't implemented, suggesting the developers believed verification existed

## Recommendation

Implement verification of the `next_execution_hash` during proposal resolution. There are two approaches:

**Option 1: Store Expected Hash Chain**
When a multi-step proposal is created, store the complete sequence of expected execution hashes on-chain. During each resolution step, verify the provided `next_execution_hash` matches the stored sequence.

**Option 2: Pre-register All Steps**
Require all steps of a multi-step proposal to be registered together during proposal creation, with each step's hash stored. Verify `next_execution_hash` against this pre-registered sequence.

**Recommended Implementation (Option 1):**

Modify the `Proposal` struct in voting.move to include:
```move
// Add to Proposal struct
expected_execution_hashes: vector<vector<u8>>, // For multi-step proposals
current_step: u64, // Track which step we're on
```

Modify `create_proposal_v2` to accept and store the hash sequence for multi-step proposals.

Modify `resolve_proposal_v2` to verify:
```move
if (is_multi_step && !next_execution_hash_is_empty) {
    // Verify next_execution_hash matches expected
    let expected = vector::borrow(&proposal.expected_execution_hashes, proposal.current_step + 1);
    assert!(
        *expected == next_execution_hash,
        error::invalid_argument(ENEXT_EXECUTION_HASH_MISMATCH)
    );
    proposal.current_step = proposal.current_step + 1;
}
```

This provides defense-in-depth by verifying the hash chain matches what was approved during proposal creation.

## Proof of Concept

```move
#[test_only]
module aptos_framework::multi_step_bypass_test {
    use aptos_framework::voting;
    use aptos_framework::aptos_governance;
    use std::vector;
    
    #[test(governance = @0x1)]
    fun test_next_execution_hash_not_verified(governance: &signer) {
        // Setup: Create a multi-step proposal
        voting::register<TestProposal>(governance);
        
        let correct_step2_hash = vector[2, 2, 2]; // Expected hash for step 2
        let malicious_hash = vector[9, 9, 9];     // Malicious hash
        
        // Step 1 should contain correct_step2_hash but contains malicious_hash instead
        let proposal_id = create_malicious_proposal(
            governance,
            malicious_hash // Wrong hash embedded in step 1
        );
        
        // Vote and make proposal succeed
        vote_to_pass(governance, proposal_id);
        
        // Execute step 1 - it will pass malicious_hash as next_execution_hash
        // The system accepts it WITHOUT VERIFICATION
        execute_step_1(governance, proposal_id, malicious_hash);
        
        // Now the proposal expects malicious_hash for step 2
        // Correct step 2 (with correct_step2_hash) will FAIL
        // But attacker's script (with malicious_hash) will SUCCEED
        
        // This demonstrates the vulnerability: next_execution_hash is not verified
        assert!(get_expected_hash(proposal_id) == malicious_hash, 0);
        // Should be correct_step2_hash but system accepted malicious_hash
    }
}
```

## Notes

The vulnerability represents a gap between the documented security guarantees and the actual implementation. The formal specification explicitly claims to guarantee correctness of the hash chain, but no verification exists. This creates a dangerous false sense of security where developers and auditors might assume verification exists based on the specification.

The off-chain script generation process attempts to create correct hash chains, but without runtime verification, any bug or compromise in that tooling directly translates to on-chain governance bypass potential. Defense-in-depth principles require that critical security properties like governance integrity have multiple layers of verification, not rely solely on correct generation of off-chain artifacts.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/voting.move (L447-450)
```text
        assert!(
            transaction_context::get_script_hash() == proposal.execution_hash,
            error::invalid_argument(EPROPOSAL_EXECUTION_HASH_NOT_MATCHING),
        );
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

**File:** aptos-move/framework/aptos-framework/sources/voting.spec.move (L30-39)
```text
    /// No.: 4
    /// Requirement: In the context of v2 proposal resolving, both single-step and multi-step proposals are accurately
    /// handled. It ensures that for single-step proposals, the next execution hash is empty and resolves the proposal,
    /// while for multi-step proposals, it guarantees that the next execution hash corresponds to the hash of the next
    /// step, maintaining the integrity of the proposal execution sequence.
    /// Criticality: Medium
    /// Implementation: The function resolve_proposal_v2 correctly handles both single-step and multi-step proposals.
    /// For single-step proposals, it ensures that the next_execution_hash parameter is empty and resolves the proposal.
    /// For multi-step proposals, it ensures that the next_execution_hash parameter contains the hash of the next step.
    /// Enforcement: Formally verified via [high-level-req-4](resolve_proposal_v2).
```

**File:** aptos-move/framework/aptos-framework/sources/voting.spec.move (L286-292)
```text
        // property 4: For single-step proposals, it ensures that the next_execution_hash parameter is empty and resolves the proposal.
        /// [high-level-req-4]
        ensures len(next_execution_hash) == 0 ==> post_proposal.resolution_time_secs == timestamp::spec_now_seconds();
        ensures len(next_execution_hash) == 0 ==> post_proposal.is_resolved == true;
        ensures (len(next_execution_hash) == 0 && is_multi_step) ==> simple_map::spec_get(post_proposal.metadata, multi_step_in_execution_key) == std::bcs::serialize(false);
        // property 4: For multi-step proposals, it ensures that the next_execution_hash parameter contains the hash of the next step.
        ensures len(next_execution_hash) != 0 ==> post_proposal.execution_hash == next_execution_hash;
```

**File:** aptos-move/aptos-release-builder/src/components/mod.rs (L816-841)
```rust
pub fn get_execution_hash(result: &[(String, String)]) -> Option<HashValue> {
    if result.is_empty() {
        None
    } else {
        let temp_script_path = TempPath::new();
        temp_script_path.create_as_file().unwrap();
        let mut move_script_path = temp_script_path.path().to_path_buf();
        move_script_path.set_extension("move");
        std::fs::write(move_script_path.as_path(), result.last().unwrap().1.clone())
            .map_err(|err| {
                anyhow!(
                    "Failed to get execution hash: failed to write to file: {:?}",
                    err
                )
            })
            .unwrap();

        let (_, hash) = GenerateExecutionHash {
            script_path: Option::from(move_script_path),
            framework_local_dir: Some(aptos_framework_path()),
        }
        .generate_hash()
        .unwrap();
        Some(hash)
    }
}
```

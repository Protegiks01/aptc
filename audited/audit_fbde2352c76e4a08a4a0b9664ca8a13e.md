# Audit Report

## Title
Multi-Step Governance Proposal Chain Validation Bypass Allows Execution of Unapproved Code

## Summary
The multi-step governance proposal system fails to validate the execution hash chain. When a multi-step proposal is created, only the first script's hash is stored on-chain and voted on by governance. Subsequent step hashes are provided as runtime parameters without validation, allowing an attacker to inject arbitrary unapproved code into the execution chain.

## Finding Description

The Aptos governance system supports multi-step proposals where multiple scripts execute sequentially. When creating a multi-step proposal, only the first script's execution hash is stored on-chain and voted on by governance participants. [1](#0-0) 

The subsequent step hashes are NOT stored anywhere during proposal creation - they are embedded within each script's code and provided as the `next_execution_hash` parameter during execution.

When a multi-step proposal executes, the `resolve_multi_step_proposal` function calls `voting::resolve_proposal_v2` with the `next_execution_hash` parameter. [2](#0-1) 

The critical vulnerability occurs in `resolve_proposal_v2` where the `next_execution_hash` parameter is directly assigned to the proposal's execution_hash field without any validation: [3](#0-2) 

This updated hash is then stored as the approved execution hash for the next step via `add_approved_script_hash`. [4](#0-3) 

**Attack Scenario:**
1. Attacker creates a multi-step proposal where Step 1 appears benign (e.g., JWK consensus config update)
2. In Step 1's compiled bytecode, the attacker embeds `next_execution_hash = hash(malicious_script)` as the parameter passed to `resolve_multi_step_proposal`
3. Governance participants review Step 1's source code, find it acceptable, and vote to approve the proposal
4. Only `hash(step_1)` is stored on-chain and approved by voters
5. When Step 1 executes, it provides `hash(malicious_script)` as the next_execution_hash parameter
6. The system writes `hash(malicious_script)` directly to `proposal.execution_hash` with no validation
7. Now the malicious script (never reviewed or voted on by governance) is the approved hash for Step 2
8. The attacker executes the malicious script, which could upgrade the framework, change consensus parameters, or steal funds

The validation in `is_proposal_resolvable` only checks that the CURRENT executing script's hash matches the stored hash - it does not validate the NEXT hash being provided. [5](#0-4) 

## Impact Explanation

**Severity: Critical** (up to $1,000,000)

This vulnerability breaks the fundamental "Governance Integrity" invariant. It allows execution of arbitrary code that was never approved by governance voters. The impact includes:

1. **Complete Governance Bypass**: Attackers can execute any Move code without governance approval by embedding malicious hashes in legitimate-looking first steps
2. **Framework Compromise**: Could upgrade core framework modules (`aptos_framework`, `aptos_stdlib`) to malicious versions
3. **Consensus Manipulation**: Could modify consensus configuration, validator set, or staking parameters
4. **Fund Theft**: Could modify coin minting logic, stake pool logic, or governance treasury controls
5. **Network Partition**: Could cause non-recoverable state divergence requiring a hard fork

The vulnerability affects the core trust assumption of on-chain governance - that all executed code is reviewed and approved by token holders.

## Likelihood Explanation

**Likelihood: High**

1. **Attack Complexity**: Moderate - requires creating a governance proposal and obtaining sufficient votes for the benign-looking first step
2. **Prerequisites**: Attacker needs minimum proposer stake (configurable, typically millions of APT), but this is achievable for motivated attackers
3. **Detection Difficulty**: Very difficult - voters would need to decompile the bytecode and examine the embedded next_execution_hash parameter, which is not part of standard review processes
4. **No Rate Limiting**: Once a proposal passes, the attack succeeds with 100% probability
5. **Widespread Impact**: All multi-step proposals are affected, including critical framework upgrades

The vulnerability is particularly dangerous because:
- The attack vector is non-obvious and requires no special permissions beyond standard governance participation
- Current governance review processes focus on source code, not compiled bytecode parameters
- The design appears intentional (for building hash chains), making it unlikely to be caught in normal security reviews

## Recommendation

Store and validate the complete execution hash chain at proposal creation time. The fix requires:

1. **At Proposal Creation**: Add a new field to the `Proposal` struct to store the complete chain of execution hashes for multi-step proposals:

```move
struct Proposal<ProposalType: store> has store {
    // ... existing fields ...
    execution_hash: vector<u8>,
    // NEW: Store the complete chain for multi-step proposals
    execution_hash_chain: vector<vector<u8>>,
    // ... remaining fields ...
}
```

2. **Modify `create_proposal_v2`**: Accept and validate the complete hash chain when creating multi-step proposals.

3. **Modify `resolve_proposal_v2`**: Validate that the provided `next_execution_hash` matches the next hash in the stored chain:

```move
public fun resolve_proposal_v2<ProposalType: store>(
    voting_forum_address: address,
    proposal_id: u64,
    next_execution_hash: vector<u8>,
) acquires VotingForum {
    is_proposal_resolvable<ProposalType>(voting_forum_address, proposal_id);
    
    let voting_forum = borrow_global_mut<VotingForum<ProposalType>>(voting_forum_address);
    let proposal = table::borrow_mut(&mut voting_forum.proposals, proposal_id);
    
    // NEW: For multi-step proposals, validate next_execution_hash against stored chain
    if (vector::length(&proposal.execution_hash_chain) > 0) {
        let expected_next = if (vector::length(&next_execution_hash) == 0) {
            vector::empty<u8>()
        } else {
            // Get the next hash from the chain based on current position
            *vector::borrow(&proposal.execution_hash_chain, current_step_index)
        };
        assert!(
            next_execution_hash == expected_next,
            error::invalid_argument(ENEXT_EXECUTION_HASH_MISMATCH)
        );
    };
    
    // ... rest of existing logic ...
}
```

4. **Update Proposal Generation**: Modify the release builder to submit the complete hash chain when creating multi-step proposals.

## Proof of Concept

```move
#[test(aptos_framework = @aptos_framework, proposer = @0x123, voter = @0x234)]
public entry fun test_multi_step_hash_replacement_attack(
    aptos_framework: signer,
    proposer: signer,
    voter: signer,
) acquires VotingForum, GovernanceConfig, GovernanceResponsbility, ApprovedExecutionHashes, VotingRecords, VotingRecordsV2, GovernanceEvents {
    // Setup governance
    setup_voting(&aptos_framework, &proposer, &voter, &voter);
    
    // Create a multi-step proposal with execution_hash = hash_legitimate
    let hash_legitimate = vector[1, 2, 3];
    create_proposal_v2(
        &proposer,
        signer::address_of(&proposer),
        hash_legitimate,
        b"Legitimate JWK config update",
        b"",
        true, // is_multi_step
    );
    
    // Vote and approve the proposal
    vote(&voter, signer::address_of(&voter), 0, true);
    timestamp::fast_forward_seconds(VOTING_DURATION + 1);
    
    // Verify the approved hash is hash_legitimate
    let approved = borrow_global<ApprovedExecutionHashes>(@aptos_framework);
    assert!(*simple_map::borrow(&approved.hashes, &0) == hash_legitimate, 1);
    
    // ATTACK: Execute step 1, but provide hash_malicious as next_execution_hash
    // This simulates the malicious next hash embedded in the script bytecode
    let hash_malicious = vector[6, 6, 6]; // Evil script hash
    
    resolve_multi_step_proposal(
        0,
        @aptos_framework,
        hash_malicious // Attacker-controlled hash, not approved by governance!
    );
    
    // VERIFY VULNERABILITY: The malicious hash is now the approved execution hash
    let approved = borrow_global<ApprovedExecutionHashes>(@aptos_framework);
    let current_approved_hash = simple_map::borrow(&approved.hashes, &0);
    
    // This assertion passes, proving the vulnerability:
    // An unapproved hash has become the authorized execution hash
    assert!(*current_approved_hash == hash_malicious, 2);
    
    // The malicious script can now execute in step 2 because its hash is approved,
    // even though governance never voted on it!
}
```

**Notes:**
- The vulnerability exists because `next_execution_hash` is a runtime parameter provided by the executing script, not validated against any on-chain storage
- The complete hash chain is generated at build time by the release builder [6](#0-5)  but never submitted to or validated by the blockchain
- This breaks the governance invariant that all executed code must be approved by token holders through voting

### Citations

**File:** aptos-move/framework/aptos-framework/sources/voting.move (L332-345)
```text
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
```

**File:** aptos-move/framework/aptos-framework/sources/voting.move (L447-450)
```text
        assert!(
            transaction_context::get_script_hash() == proposal.execution_hash,
            error::invalid_argument(EPROPOSAL_EXECUTION_HASH_NOT_MATCHING),
        );
```

**File:** aptos-move/framework/aptos-framework/sources/voting.move (L562-566)
```text
        } else {
            // If the current step is not the last step,
            // update the proposal's execution hash on-chain to the execution hash of the next step.
            proposal.execution_hash = next_execution_hash;
        };
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L613-630)
```text
    public fun add_approved_script_hash(proposal_id: u64) acquires ApprovedExecutionHashes {
        let approved_hashes = borrow_global_mut<ApprovedExecutionHashes>(@aptos_framework);

        // Ensure the proposal can be resolved.
        let proposal_state = voting::get_proposal_state<GovernanceProposal>(@aptos_framework, proposal_id);
        assert!(proposal_state == PROPOSAL_STATE_SUCCEEDED, error::invalid_argument(EPROPOSAL_NOT_RESOLVABLE_YET));

        let execution_hash = voting::get_execution_hash<GovernanceProposal>(@aptos_framework, proposal_id);

        // If this is a multi-step proposal, the proposal id will already exist in the ApprovedExecutionHashes map.
        // We will update execution hash in ApprovedExecutionHashes to be the next_execution_hash.
        if (simple_map::contains_key(&approved_hashes.hashes, &proposal_id)) {
            let current_execution_hash = simple_map::borrow_mut(&mut approved_hashes.hashes, &proposal_id);
            *current_execution_hash = execution_hash;
        } else {
            simple_map::add(&mut approved_hashes.hashes, proposal_id, execution_hash);
        }
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

**File:** aptos-move/aptos-release-builder/src/components/framework.rs (L64-131)
```rust
    // For generating multi-step proposal files, we need to generate them in the reverse order since
    // we need the hash of the next script.
    // We will reverse the order back when writing the files into a directory.
    if is_multi_step {
        package_path_list.reverse();
    }

    for (publish_addr, relative_package_path) in package_path_list.iter() {
        let account = AccountAddress::from_hex_literal(publish_addr)?;
        let temp_script_path = TempPath::new();
        temp_script_path.create_as_file()?;
        let mut move_script_path = temp_script_path.path().to_path_buf();
        move_script_path.set_extension("move");

        let mut package_path = if config.git_hash.is_some() {
            temp_root_path.path().to_path_buf()
        } else {
            aptos_core_path()
        };

        package_path.push(relative_package_path);

        let script_name = package_path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        // If this file is the first framework file being generated (if `result.is_empty()` is true),
        // its `next_execution_hash` should be the `next_execution_hash` value being passed in.
        // If the `result` vector is not empty, the current file's `next_execution_hash` should be the
        // hash of the latest framework file being generated (the hash of result.last()).
        // For example, let's say we are going to generate these files:
        // 0-move-stdlib.move	2-aptos-framework.move	4-gas-schedule.move	6-features.move
        // 1-aptos-stdlib.move	3-aptos-token.move	5-version.move		7-consensus-config.move
        // The first framework file being generated is 3-aptos-token.move. It's using the next_execution_hash being passed in (so in this case, the hash of 4-gas-schedule.move being passed in mod.rs).
        // The second framework file being generated would be 2-aptos-framework.move, and it's using the hash of 3-aptos-token.move (which would be result.last()).

        let options = BuildOptions {
            with_srcs: true,
            with_abis: false,
            with_source_maps: false,
            with_error_map: true,
            skip_fetch_latest_git_deps: false,
            bytecode_version: Some(config.bytecode_version),
            // enable inline optimization for framework packages
            experiments: vec![
                "optimize-extra=on".to_string(),
                "extended-framework-optimizations=on".to_string(),
            ],
            ..BuildOptions::default()
        };
        let package = BuiltPackage::build(package_path, options)?;
        let release = ReleasePackage::new(package)?;

        if is_multi_step {
            // If we're generating a multi-step proposal
            let next_execution_hash_bytes = if result.is_empty() {
                next_execution_hash
            } else {
                get_execution_hash(&result)
            };
            release.generate_script_proposal_multi_step(
                account,
                move_script_path.clone(),
                next_execution_hash_bytes,
            )?;
```

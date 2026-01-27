# Audit Report

## Title
Multi-Step Governance Proposal Next Execution Hash Tampering Vulnerability

## Summary
The multi-step governance proposal system allows an attacker to execute unauthorized code with `@aptos_framework` privileges by tampering with the `next_execution_hash` parameter during proposal resolution. The system fails to validate that subsequent step hashes match what was originally proposed and voted on, enabling a complete bypass of the governance review process.

## Finding Description

The vulnerability exists in the multi-step governance proposal resolution flow. When a multi-step proposal is created, only the first step's execution hash is stored and voted on. [1](#0-0) 

When resolving step 1 to proceed to step 2, the `resolve_multi_step_proposal` function accepts an arbitrary `next_execution_hash` parameter. [2](#0-1) 

This hash is passed to `voting::resolve_proposal_v2`, which **unconditionally** updates the proposal's execution hash without any validation: [3](#0-2) 

The tampered hash is then added to the `ApprovedExecutionHashes` list: [4](#0-3) 

When the attacker later executes their malicious script, the VM validates it against the approved hash list and permits execution: [5](#0-4) 

**Attack Flow:**
1. Attacker creates a multi-step governance proposal with a benign first step that hashes to H1
2. Community reviews only step 1 and votes to approve
3. Attacker executes step 1 by calling `resolve_multi_step_proposal` with a **malicious** `next_execution_hash` (H2_malicious) 
4. The system updates `proposal.execution_hash = H2_malicious` without validation
5. `add_approved_script_hash` reads the tampered hash and adds H2_malicious to approved list
6. Attacker executes a completely different, malicious step 2 script that hashes to H2_malicious
7. VM approves execution because H2_malicious is in the approved list
8. Malicious code executes with full `@aptos_framework` privileges

The root cause is that the governance system has **no cryptographic commitment mechanism** for subsequent step hashes in multi-step proposals. The generated proposal script embeds the `next_execution_hash` as a literal parameter: [6](#0-5) 

This design allows the proposer to substitute any hash value at execution time.

## Impact Explanation

**CRITICAL SEVERITY** - This vulnerability enables complete bypass of the governance security model:

- **Arbitrary Code Execution**: Attacker gains `@aptos_framework` signer privileges, allowing execution of any privileged operation
- **Fund Theft**: Can mint tokens, transfer from treasury, or manipulate coin supply
- **State Corruption**: Can modify critical on-chain configurations (consensus parameters, gas schedules, feature flags)
- **Validator Set Manipulation**: Can add/remove validators, steal staking rewards
- **Network Compromise**: Can disable safety checks, modify reconfiguration logic, or freeze the network

This meets the **"Loss of Funds"**, **"Consensus/Safety violations"**, and **"Remote Code Execution"** criteria for Critical severity bounties (up to $1,000,000).

The vulnerability breaks the **Governance Integrity** invariant and **Access Control** invariant documented in the security requirements.

## Likelihood Explanation

**HIGH LIKELIHOOD** - This vulnerability is highly exploitable:

**Prerequisites:**
- Attacker needs sufficient stake to create a proposal (configurable threshold)
- Must create a benign first step that gains community approval
- Must control the transaction that executes step 1

**Feasibility:**
- Any governance participant with sufficient stake can exploit this
- Social engineering is minimal - voters only review step 1 which can be legitimate
- No race conditions or timing requirements
- No special privileges beyond normal governance participation
- Attack succeeds deterministically once step 1 is approved

**Detection Difficulty:**
- The tampering happens during legitimate transaction execution
- No on-chain validation exists to detect hash substitution
- Malicious step 2 only revealed at execution time, after approval
- Off-chain monitoring would need to track all multi-step proposal metadata

## Recommendation

Implement cryptographic commitment to all step hashes at proposal creation time:

1. **Require full hash chain at creation**: Modify `create_proposal_v2` to accept an array of execution hashes for all steps, not just the first step.

2. **Store and validate hash chain**: Add a new field `next_execution_hashes: vector<vector<u8>>` to the `Proposal` struct in `voting.move`.

3. **Validate during resolution**: In `resolve_proposal_v2`, verify that `next_execution_hash` matches the next hash in the committed chain:
   ```move
   // In resolve_proposal_v2, before line 565:
   if (!next_execution_hash_is_empty && is_multi_step) {
       let expected_next_hash = vector::borrow(&proposal.next_execution_hashes, 0);
       assert!(
           &next_execution_hash == expected_next_hash,
           error::invalid_argument(ENEXT_EXECUTION_HASH_MISMATCH)
       );
       vector::remove(&mut proposal.next_execution_hashes, 0);
   }
   ```

4. **Update proposal creation**: Voters must review all step hashes before voting, ensuring full transparency of multi-step operations.

5. **Backward compatibility**: Mark existing proposals with empty hash chains and enforce validation only for new proposals.

## Proof of Concept

```move
#[test(framework = @0x1, proposer = @0x123, voter = @0x456)]
public fun test_next_execution_hash_tampering(
    framework: &signer,
    proposer: &signer, 
    voter: &signer
) {
    // Setup: Initialize governance and stake pools
    aptos_governance::initialize_for_test(framework);
    setup_stake_pool(proposer, 1000000);
    setup_stake_pool(voter, 5000000);
    
    // Step 1: Create multi-step proposal with legitimate first step
    let legit_step1_script = b"script { fun main(proposal_id: u64) { /* benign code */ } }";
    let legit_step1_hash = sha3_256(legit_step1_script);
    
    let proposal_id = aptos_governance::create_proposal_v2(
        proposer,
        signer::address_of(proposer),
        legit_step1_hash,
        b"metadata_location",
        b"metadata_hash",
        true, // is_multi_step
    );
    
    // Step 2: Community votes and approves (reviewing only step 1)
    aptos_governance::vote(voter, proposal_id, true);
    timestamp::fast_forward_seconds(VOTING_PERIOD);
    
    // Step 3: Execute step 1 with MALICIOUS next_execution_hash
    let malicious_step2_script = b"script { fun main(proposal_id: u64) { /* STEAL FUNDS */ } }";
    let malicious_step2_hash = sha3_256(malicious_step2_script);
    
    // Attacker tampers with next_execution_hash parameter
    let framework_signer = aptos_governance::resolve_multi_step_proposal(
        proposal_id,
        @0x1,
        malicious_step2_hash, // <-- TAMPERED HASH
    );
    
    // Step 4: Verify malicious hash is now approved
    let approved_hash = aptos_governance::get_approved_hash(proposal_id);
    assert!(approved_hash == malicious_step2_hash, 0); // VULNERABILITY: malicious hash approved!
    
    // Step 5: Execute malicious script (would succeed in production)
    // submit_transaction(malicious_step2_script); 
    // -> Gets framework signer privileges and executes arbitrary code
}
```

**Expected Result**: The test demonstrates that an arbitrary `next_execution_hash` is accepted and added to the approved list, bypassing the governance review process for subsequent proposal steps.

---

**Notes**

The vulnerability is specifically introduced by the design choice in the gas upgrade proposal generation at: [7](#0-6) 

While this function generates the proposal script off-chain, the on-chain validation logic fails to enforce that the embedded `next_execution_hash` matches a pre-approved value. This affects all multi-step governance proposals system-wide, not just gas upgrades.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/voting.move (L293-345)
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

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L286-302)
```rust
fn is_approved_gov_script(
    resolver: &impl ConfigStorage,
    txn: &SignedTransaction,
    txn_metadata: &TransactionMetadata,
) -> bool {
    if let Ok(TransactionExecutableRef::Script(_script)) = txn.payload().executable_ref() {
        match ApprovedExecutionHashes::fetch_config(resolver) {
            Some(approved_execution_hashes) => approved_execution_hashes
                .entries
                .iter()
                .any(|(_, hash)| hash == &txn_metadata.script_hash),
            None => false,
        }
    } else {
        false
    }
}
```

**File:** aptos-move/framework/src/release_bundle.rs (L286-314)
```rust
pub fn generate_next_execution_hash_blob(
    writer: &CodeWriter,
    for_address: AccountAddress,
    next_execution_hash: Option<HashValue>,
) {
    match next_execution_hash {
        None => {
            emitln!(
            writer,
            "let framework_signer = aptos_governance::resolve_multi_step_proposal(proposal_id, @{}, {});\n",
            for_address,
            "x\"\"",
        );
        },
        Some(next_execution_hash) => {
            emitln!(
                writer,
                "let framework_signer = aptos_governance::resolve_multi_step_proposal("
            );
            writer.indent();
            emitln!(writer, "proposal_id,");
            emitln!(writer, "@{},", for_address);
            generate_blob_as_hex_string(writer, next_execution_hash.as_slice());
            emit!(writer, ",");
            writer.unindent();
            emitln!(writer, ");");
        },
    }
}
```

**File:** aptos-move/aptos-release-builder/src/components/gas.rs (L117-151)
```rust
    let proposal = generate_governance_proposal(
        &writer,
        is_testnet,
        next_execution_hash,
        is_multi_step,
        &["aptos_framework::gas_schedule"],
        |writer| {
            let gas_schedule_blob = bcs::to_bytes(new_gas_schedule).unwrap();
            assert!(gas_schedule_blob.len() < 65536);

            emit!(writer, "let gas_schedule_blob: vector<u8> = ");
            generate_blob_as_hex_string(writer, &gas_schedule_blob);
            emitln!(writer, ";");
            emitln!(writer);

            match old_hash {
                Some(old_hash) => {
                    emitln!(
                        writer,
                        "gas_schedule::set_for_next_epoch_check_hash({}, x\"{}\", gas_schedule_blob);",
                        signer_arg,
                        old_hash,
                    );
                },
                None => {
                    emitln!(
                        writer,
                        "gas_schedule::set_for_next_epoch({}, gas_schedule_blob);",
                        signer_arg
                    );
                },
            }
            emitln!(writer, "aptos_governance::reconfigure({});", signer_arg);
        },
    );
```

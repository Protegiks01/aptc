# Audit Report

## Title
Circular Hash Chain Attack in Multi-Step Governance Proposals Enables Infinite Script Execution

## Summary
The multi-step governance proposal system in Aptos lacks validation to prevent reuse of execution hashes within a proposal chain. An attacker can create a multi-step proposal where `next_execution_hash` references a previously executed hash (including the current step's hash), creating a circular chain that allows the same governance script to execute indefinitely with elevated privileges.

## Finding Description

The vulnerability exists in the `resolve_proposal_v2` function which handles multi-step proposal execution. When resolving a step of a multi-step proposal, the function accepts a `next_execution_hash` parameter to specify the hash of the next step to execute. [1](#0-0) 

The critical flaw is that this function performs no validation to ensure `next_execution_hash`:
1. Differs from the current `execution_hash` (preventing self-loops)
2. Has not been used previously in the proposal chain (preventing circular chains)
3. Represents a valid, unexecuted future step [2](#0-1) 

The code simply overwrites the proposal's `execution_hash` with the provided `next_execution_hash` without any checks. This breaks the fundamental invariant that each step in a multi-step proposal should execute exactly once.

**Attack Flow:**

1. Attacker creates a multi-step proposal with `execution_hash = H1` (requires sufficient stake)
2. Proposal passes governance voting (requires majority support)
3. Attacker executes the first step with a script matching hash H1
4. In the resolution, the attacker provides `next_execution_hash = H1` (same hash)
5. The system updates `proposal.execution_hash = H1` without validation
6. Attacker can now execute the same script with hash H1 again
7. Steps 3-6 repeat infinitely

The validation in `is_proposal_resolvable` only checks that the executing script's hash matches the stored hash: [3](#0-2) 

This validation passes for circular chains because after step 4 above, the stored hash is H1, so executing H1 again is valid according to this check.

The `ApprovedExecutionHashes` tracking in governance also provides no protection: [4](#0-3) 

It simply overwrites the hash without checking for duplicates or circular references.

## Impact Explanation

**Critical Severity** - This vulnerability enables:

1. **Unlimited Fund Theft/Minting**: A malicious governance script that mints coins or transfers from the treasury can execute repeatedly, draining unlimited funds from the protocol.

2. **Arbitrary State Manipulation**: Governance scripts receive signer capabilities for system addresses. Infinite execution allows unbounded state manipulation including:
   - Repeatedly toggling feature flags
   - Manipulating validator set composition
   - Altering consensus parameters
   - Bypassing intended one-time initialization constraints

3. **Governance Integrity Violation**: The multi-step proposal mechanism is designed to execute a predetermined sequence of steps exactly once each. Circular chains completely break this security guarantee.

4. **Irreversible Damage**: Once a malicious circular proposal executes, it can drain the entire treasury or corrupt critical state before detection, requiring a hard fork to recover.

The impact meets the **Critical Severity** criteria per the Aptos bug bounty program: "Loss of Funds (theft or minting)" and "Consensus/Safety violations" through governance compromise.

## Likelihood Explanation

**Moderate to High Likelihood**:

**Requirements:**
- Attacker must have sufficient stake to create a proposal (governance threshold)
- Proposal must pass democratic voting (majority support)

**Feasibility:**
- The stake requirement can be met by wealthy actors or through collusion
- Malicious proposals can be disguised with legitimate-looking metadata
- Once a proposal passes, the circular hash attack is trivial to execute
- No technical sophistication required beyond understanding the governance flow

**Mitigation Factors:**
- Governance proposals undergo public scrutiny
- Voting period provides time for detection
- Community can vote against suspicious proposals

However, the ease of execution once voting passes, combined with the catastrophic potential impact, makes this a realistic attack vector worthy of immediate remediation.

## Recommendation

Add validation in `resolve_proposal_v2` to prevent hash reuse within a proposal chain:

```move
// Add to Proposal struct: a vector tracking all execution hashes used
struct Proposal<ProposalType: store> has store {
    // ... existing fields ...
    execution_hash: vector<u8>,
    execution_hash_history: vector<vector<u8>>, // NEW: Track used hashes
    // ... existing fields ...
}

// In resolve_proposal_v2, before updating execution_hash:
if (!next_execution_hash_is_empty) {
    // Ensure next_execution_hash differs from current hash
    assert!(
        next_execution_hash != proposal.execution_hash,
        error::invalid_argument(ECIRCULAR_EXECUTION_HASH)
    );
    
    // Ensure next_execution_hash hasn't been used before
    let history = &proposal.execution_hash_history;
    let i = 0;
    let len = vector::length(history);
    while (i < len) {
        assert!(
            *vector::borrow(history, i) != next_execution_hash,
            error::invalid_argument(EREUSED_EXECUTION_HASH)
        );
        i = i + 1;
    };
    
    // Record current hash in history before updating
    vector::push_back(&mut proposal.execution_hash_history, proposal.execution_hash);
    
    proposal.execution_hash = next_execution_hash;
};
```

Alternative approach: Require each step to specify a unique step identifier that monotonically increases.

## Proof of Concept

```move
#[test(aptos_framework = @aptos_framework, proposer = @0x123, voter = @0x234)]
public entry fun test_circular_hash_attack(
    aptos_framework: signer,
    proposer: signer,
    voter: signer,
) acquires ApprovedExecutionHashes, GovernanceConfig, GovernanceResponsbility, 
           VotingRecords, VotingRecordsV2, GovernanceEvents {
    // Setup governance and staking
    setup_partial_voting(&aptos_framework, &proposer, &voter, &voter);
    
    // Create multi-step proposal with execution_hash = [1]
    let execution_hash = vector[1];
    create_proposal_v2(
        &proposer,
        signer::address_of(&proposer),
        execution_hash,
        b"Malicious circular proposal",
        b"",
        true, // is_multi_step
    );
    
    // Vote and wait for expiration
    vote(&voter, signer::address_of(&voter), 0, true);
    timestamp::update_global_time_for_test(100001000000);
    add_approved_script_hash(0);
    
    // Execute step 1 - provide SAME hash as next_execution_hash
    let same_hash = vector[1]; // Circular reference to itself
    let _signer1 = resolve_multi_step_proposal(0, @aptos_framework, same_hash);
    
    // The proposal's execution_hash is now [1] again - circular chain created!
    let current_hash = voting::get_execution_hash<GovernanceProposal>(@aptos_framework, 0);
    assert!(current_hash == vector[1], 0); // Same hash reused
    
    // Can execute again with the same script indefinitely
    let _signer2 = resolve_multi_step_proposal(0, @aptos_framework, same_hash);
    let _signer3 = resolve_multi_step_proposal(0, @aptos_framework, same_hash);
    // ... infinite execution possible
    
    // Each execution grants signer capability for @aptos_framework
    // Malicious script could mint coins, transfer funds, etc. repeatedly
}
```

This test demonstrates that the same execution hash can be reused, creating a circular proposal chain that executes indefinitely. Each execution receives a governance signer capability, enabling unlimited privileged operations.

**Notes:**
The vulnerability is architecturally fundamental - the voting module provides no mechanism to track or validate the uniqueness of execution hashes across proposal steps. The `IS_MULTI_STEP_PROPOSAL_IN_EXECUTION_KEY` flag only prevents new votes during execution but does not prevent circular hash chains. The severity is critical because governance scripts operate with the highest privileges in the system, and infinite execution enables unbounded damage to protocol integrity and user funds.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/voting.move (L447-450)
```text
        assert!(
            transaction_context::get_script_hash() == proposal.execution_hash,
            error::invalid_argument(EPROPOSAL_EXECUTION_HASH_NOT_MATCHING),
        );
```

**File:** aptos-move/framework/aptos-framework/sources/voting.move (L514-518)
```text
    public fun resolve_proposal_v2<ProposalType: store>(
        voting_forum_address: address,
        proposal_id: u64,
        next_execution_hash: vector<u8>,
    ) acquires VotingForum {
```

**File:** aptos-move/framework/aptos-framework/sources/voting.move (L562-566)
```text
        } else {
            // If the current step is not the last step,
            // update the proposal's execution hash on-chain to the execution hash of the next step.
            proposal.execution_hash = next_execution_hash;
        };
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L622-629)
```text
        // If this is a multi-step proposal, the proposal id will already exist in the ApprovedExecutionHashes map.
        // We will update execution hash in ApprovedExecutionHashes to be the next_execution_hash.
        if (simple_map::contains_key(&approved_hashes.hashes, &proposal_id)) {
            let current_execution_hash = simple_map::borrow_mut(&mut approved_hashes.hashes, &proposal_id);
            *current_execution_hash = execution_hash;
        } else {
            simple_map::add(&mut approved_hashes.hashes, proposal_id, execution_hash);
        }
```

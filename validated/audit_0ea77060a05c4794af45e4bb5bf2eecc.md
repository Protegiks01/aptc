# Audit Report

## Title
Unverified Past-Epoch Commit Decisions Can Remove Legitimate Ordered Blocks via Cross-Epoch Validation Bypass

## Summary
The consensus observer's commit decision processing contains a critical signature verification bypass for non-current-epoch commits. This allows unverified past-epoch commit decisions to trigger incorrect removal of legitimate ordered blocks through flawed cross-epoch round comparisons.

## Finding Description

The vulnerability exists in the consensus observer's commit decision processing logic. The function performs signature verification ONLY for commits matching the current epoch, completely bypassing verification for commits from different epochs. [1](#0-0) 

When the epoch check at line 468 fails (commit is from a different epoch), the code skips signature verification at line 470 and continues processing. The commit then reaches the state sync fallback logic which performs a flawed cross-epoch round comparison. [2](#0-1) 

At line 504, the code compares `commit_round > last_block.round()` without validating that both rounds are from the same epoch. When a past-epoch commit (e.g., epoch 10, round 155) is compared against a current-epoch block (e.g., epoch 11, round 2), the comparison `155 > 2` succeeds despite being logically invalid across epochs. This triggers `update_blocks_for_state_sync_commit` at line 522 without any signature verification. [3](#0-2) 

The `update_blocks_for_state_sync_commit` function calls `remove_blocks_for_commit` which uses BTreeMap's `split_off` operation. This operation calculates a split key of `(commit_epoch, commit_round + 1)` and keeps only blocks with keys greater than or equal to this split key. [4](#0-3) 

**Attack Scenario:**
- Initial state: Current epoch 11, last block (11, 2), ordered blocks include {(10, 150), (10, 151), (10, 152), (11, 0), (11, 1), (11, 2)}
- Attacker sends: CommitDecision for (epoch=10, round=155) with invalid/no signatures
- Line 457 check: `(10, 155) > (10, 100)` → PASSES (not old)
- Line 468 check: `10 == 11` → FAILS (skips verification)
- Line 504 check: `155 > 2` → PASSES (invalid cross-epoch comparison)
- Line 522: Calls `update_blocks_for_state_sync_commit` WITHOUT verification
- Result: `split_off(&(10, 156))` removes blocks (10, 150), (10, 151), (10, 152) while keeping (11, x) blocks

This breaks consensus observer state consistency by removing legitimate ordered blocks without cryptographic validation.

## Impact Explanation

This vulnerability represents a **High Severity** issue under Aptos bug bounty criteria:

**Primary Impacts:**
1. **State Inconsistencies**: Legitimate ordered blocks are deleted without consensus validation, causing state divergence in consensus observers
2. **Validator Operations Impact**: Consensus observers are used by validators to catch up when falling behind. This bug prevents proper catch-up by removing legitimate blocks
3. **Protocol Violation**: Bypasses the fundamental requirement that state modifications must be cryptographically verified

The severity is **High** (not Critical) because:
- Affects consensus observers (observer/sync infrastructure) rather than core consensus validators
- Does not directly break consensus safety or cause permanent network partition  
- Can be recovered through state sync mechanisms
- No direct fund loss or double-spending

However, it qualifies as **High** because:
- Bypasses cryptographic signature verification (fundamental security primitive)
- Affects validator catch-up mechanisms and network reliability
- Requires no privileged access or validator collusion
- Simple single-message exploitation
- Causes significant protocol-level state inconsistencies

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability has high exploitation likelihood:

1. **Low Attacker Requirements**: Only requires ability to send network messages to consensus observer nodes that are subscribed to attacker-controlled or compromised peers
2. **Simple Exploitation**: Single malformed network message with no complex timing requirements
3. **Common Conditions**: Epoch transitions occur regularly, and the vulnerable code path executes during normal operation
4. **Detection Evasion**: The code logs warnings but continues processing without security alerts

## Recommendation

Implement proper signature verification for all commit decisions regardless of epoch:

1. **Verify all commits**: Remove the epoch-gating at line 468 that restricts verification to current epoch only
2. **Obtain historical epoch state**: Retrieve the appropriate EpochState for the commit's epoch (using storage access to historical validator sets)
3. **Verify against correct epoch**: Call `verify_commit_proof` with the commit's own epoch state, not just the current epoch state
4. **Fix cross-epoch comparison**: At line 504, ensure epoch values match before comparing rounds, or properly handle epoch boundaries
5. **Reject unverifiable commits**: If historical epoch state is unavailable, reject the commit rather than processing it unverified

The proper fix should verify that any commit decision has valid signatures from the appropriate epoch's validator set before allowing it to modify block data structures.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Setting up a consensus observer node subscribed to a test peer
2. Having the node reach epoch 11 with ordered blocks from epochs 10 and 11
3. Sending a crafted CommitDecision message for (epoch=10, round=155) with empty/invalid signatures
4. Observing that the message bypasses verification at line 468 (epoch mismatch)
5. Confirming the cross-epoch comparison at line 504 triggers incorrectly
6. Verifying that legitimate blocks (10, 150), (10, 151), (10, 152) are removed from the ordered block store without proper validation

The attack succeeds because the code path from line 468→504→522 processes the unverified commit, and `remove_blocks_for_commit` unconditionally removes blocks based on the unverified commit's epoch and round values.

### Citations

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L468-482)
```rust
        if commit_epoch == epoch_state.epoch {
            // Verify the commit decision
            if let Err(error) = commit_decision.verify_commit_proof(&epoch_state) {
                // Log the error and update the invalid message counter
                error!(
                    LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                        "Failed to verify commit decision! Ignoring: {:?}, from peer: {:?}. Error: {:?}",
                        commit_decision.proof_block_info(),
                        peer_network_id,
                        error
                    ))
                );
                increment_invalid_message_counter(&peer_network_id, metrics::COMMIT_DECISION_LABEL);
                return;
            }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L502-527)
```rust
        let last_block = self.observer_block_data.lock().get_last_ordered_block();
        let epoch_changed = commit_epoch > last_block.epoch();
        if epoch_changed || commit_round > last_block.round() {
            // If we're waiting for state sync to transition into a new epoch,
            // we should just wait and not issue a new state sync request.
            if self.state_sync_manager.is_syncing_through_epoch() {
                info!(
                    LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                        "Already waiting for state sync to reach new epoch: {:?}. Dropping commit decision: {:?}!",
                        self.observer_block_data.lock().root().commit_info(),
                        commit_decision.proof_block_info()
                    ))
                );
                return;
            }

            // Otherwise, we should start the state sync process for the commit.
            // Update the block data (to the commit decision).
            self.observer_block_data
                .lock()
                .update_blocks_for_state_sync_commit(&commit_decision);

            // Start state syncing to the commit decision
            self.state_sync_manager
                .sync_to_commit(commit_decision, epoch_changed);
        }
```

**File:** consensus/src/consensus_observer/observer/block_data.rs (L275-291)
```rust
    pub fn update_blocks_for_state_sync_commit(&mut self, commit_decision: &CommitDecision) {
        // Get the commit proof, epoch and round
        let commit_proof = commit_decision.commit_proof();
        let commit_epoch = commit_decision.epoch();
        let commit_round = commit_decision.round();

        // Update the root
        self.update_root(commit_proof.clone());

        // Update the block payload store
        self.block_payload_store
            .remove_blocks_for_epoch_round(commit_epoch, commit_round);

        // Update the ordered block store
        self.ordered_block_store
            .remove_blocks_for_commit(commit_proof);
    }
```

**File:** consensus/src/consensus_observer/observer/ordered_blocks.rs (L112-124)
```rust
    pub fn remove_blocks_for_commit(&mut self, commit_ledger_info: &LedgerInfoWithSignatures) {
        // Determine the epoch and round to split off
        let split_off_epoch = commit_ledger_info.ledger_info().epoch();
        let split_off_round = commit_ledger_info.commit_info().round().saturating_add(1);

        // Remove the blocks from the ordered blocks
        self.ordered_blocks = self
            .ordered_blocks
            .split_off(&(split_off_epoch, split_off_round));

        // Update the highest committed epoch and round
        self.update_highest_committed_epoch_round(commit_ledger_info);
    }
```

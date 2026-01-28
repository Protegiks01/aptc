# Audit Report

## Title
Unverified Past-Epoch Commit Decisions Can Remove Legitimate Ordered Blocks via Cross-Epoch Validation Bypass

## Summary
The consensus observer's commit decision processing contains a critical signature verification bypass for non-current-epoch commits. This allows unverified past-epoch commit decisions to trigger incorrect removal of legitimate ordered blocks through flawed cross-epoch round comparisons, causing state inconsistencies in consensus observers.

## Finding Description

The vulnerability exists in the consensus observer's commit decision processing logic at `process_commit_decision_message`. The function performs signature verification ONLY for commits matching the current epoch, completely bypassing verification for commits from different epochs. [1](#0-0) 

When the epoch check at line 468 fails (commit epoch does not match current epoch), the code skips the signature verification at line 470 and continues to the fallback logic. The commit then reaches state sync logic which performs a flawed cross-epoch round comparison. [2](#0-1) 

At line 504, the code compares `commit_round > last_block.round()` without validating that both rounds are from the same epoch. The condition is `if epoch_changed || commit_round > last_block.round()` where `epoch_changed = commit_epoch > last_block.epoch()`. When a past-epoch commit (e.g., epoch 10, round 155) is compared against a current-epoch block (e.g., epoch 11, round 2):
- `epoch_changed = 10 > 11` evaluates to `false`
- `commit_round > last_block.round()` evaluates to `155 > 2` which is `true`
- The condition passes despite the comparison being logically invalid across epochs

This triggers `update_blocks_for_state_sync_commit` at line 522 without any signature verification, which proceeds to remove blocks from the ordered block store. [3](#0-2) 

The `update_blocks_for_state_sync_commit` function calls `remove_blocks_for_commit` which uses BTreeMap's `split_off` operation to remove blocks. [4](#0-3) 

The `split_off` operation at line 120 calculates a split key of `(commit_epoch, commit_round + 1)` and keeps only blocks with keys greater than or equal to this split key. For a malicious commit at (epoch 10, round 155), the operation removes all blocks from (10, 0) through (10, 155), including legitimate ordered blocks like (10, 150), (10, 151), (10, 152).

**Attack Scenario:**
- Initial state: Current epoch 11, last ordered block (11, 2), ordered blocks include {(10, 150), (10, 151), (10, 152), (11, 0), (11, 1), (11, 2)}
- Attacker sends: CommitDecision for (epoch=10, round=155) with invalid/no signatures from a subscribed peer
- Line 457 check: `(10, 155) > highest_committed` → PASSES (assuming highest committed < (10, 155))
- Line 468 check: `10 == 11` → FAILS (skips signature verification)
- Line 503-504 check: `false || 155 > 2` → PASSES (flawed cross-epoch comparison)
- Line 522: Calls `update_blocks_for_state_sync_commit` WITHOUT verification
- Result: Blocks (10, 150), (10, 151), (10, 152) are removed without cryptographic validation

Messages must come from subscribed peers as verified by the subscription manager. [5](#0-4) 

## Impact Explanation

This vulnerability represents a **High Severity** issue under Aptos bug bounty criteria:

**Primary Impacts:**
1. **State Inconsistencies**: Legitimate ordered blocks are deleted without consensus validation, causing state divergence in consensus observers
2. **Validator Operations Impact**: Consensus observers help validators catch up when falling behind. This bug prevents proper catch-up by removing legitimate blocks that are needed for synchronization
3. **Protocol Violation**: Bypasses the fundamental cryptographic requirement that all state modifications must be verified through signature validation

The severity is **High** (not Critical) because:
- Affects consensus observers (observer/sync infrastructure) rather than core consensus validators
- Does not directly break consensus safety among validators or cause permanent network partition
- Can be recovered through state sync mechanisms
- No direct fund loss or double-spending

However, it qualifies as **High** because:
- Bypasses cryptographic signature verification, a fundamental security primitive
- Affects validator catch-up mechanisms and network reliability
- Requires no privileged access or validator collusion
- Simple single-message exploitation
- Causes significant protocol-level state inconsistencies that degrade consensus observer functionality

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability has high exploitation likelihood:

1. **Low Attacker Requirements**: Only requires ability to send network messages to consensus observer nodes that are subscribed to attacker-controlled or compromised peers. Network peers are untrusted actors per the Aptos threat model.

2. **Simple Exploitation**: Single malformed network message with no complex timing requirements or coordination needed.

3. **Common Conditions**: Epoch transitions occur regularly in Aptos, creating windows where ordered blocks from past epochs may exist alongside current epoch blocks. The vulnerable code path executes during normal operation.

4. **Detection Evasion**: The code logs warnings but continues processing without security alerts or rejection of the malicious message.

5. **No Special Privileges Required**: Does not require validator access, governance control, or any trusted role compromise.

## Recommendation

Add epoch validation before performing round comparisons to prevent cross-epoch comparisons. The fix should ensure that commits from past epochs are properly rejected or that round comparisons only occur within the same epoch context.

**Suggested Fix:**
```rust
// At line 502-504 in consensus_observer.rs
let last_block = self.observer_block_data.lock().get_last_ordered_block();
let epoch_changed = commit_epoch > last_block.epoch();

// Add validation: only trigger state sync for future epochs or future rounds in same epoch
if epoch_changed {
    // Handle epoch transition case
} else if commit_epoch == last_block.epoch() && commit_round > last_block.round() {
    // Only compare rounds if in the same epoch
} else {
    // Reject past-epoch commits
    warn!("Ignoring commit decision from past epoch");
    return;
}
```

Alternatively, enforce signature verification for ALL commit decisions regardless of epoch, or add explicit validation that commit decisions from past epochs are rejected before processing.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Setting up a consensus observer subscribed to a controlled peer
2. Sending a CommitDecision message with:
   - Epoch = current_epoch - 1 (past epoch)
   - Round = high value (e.g., 155)
   - Invalid or missing signatures
3. Observing that:
   - The message passes the "not old" check (line 457)
   - Signature verification is skipped (line 468)
   - Cross-epoch round comparison passes incorrectly (line 504)
   - Legitimate ordered blocks from the past epoch are removed (line 522)
   - State sync is initiated to an unverified target (line 525-526)

The proof of concept requires access to the consensus observer network interface and the ability to construct and send CommitDecision messages from a subscribed peer. The vulnerability is triggerable through normal network message processing without any special conditions or race conditions.

**Notes**

This vulnerability affects the consensus observer component which is critical for validator synchronization. While it does not directly compromise consensus validators or enable fund theft, it significantly degrades the reliability of the catch-up mechanism and violates fundamental security principles by bypassing cryptographic verification. The flaw lies in the assumption that non-current-epoch commits can be safely processed without verification, when in fact they can manipulate the block store state through the flawed cross-epoch comparison logic.

### Citations

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L467-482)
```rust
        let epoch_state = self.get_epoch_state();
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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L500-527)
```rust
        // Otherwise, we failed to process the commit decision. If the commit
        // is for a future epoch or round, we need to state sync.
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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L579-594)
```rust
        if let Err(error) = self
            .subscription_manager
            .verify_message_for_subscription(peer_network_id)
        {
            // Update the rejected message counter
            increment_rejected_message_counter(&peer_network_id, &message);

            // Log the error and return
            warn!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Received message that was not from an active subscription! Error: {:?}",
                    error,
                ))
            );
            return;
        }
```

**File:** consensus/src/consensus_observer/observer/block_data.rs (L273-291)
```rust
    /// Updates the block data for the given commit decision
    /// that will be used by state sync to catch us up.
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

**File:** consensus/src/consensus_observer/observer/ordered_blocks.rs (L110-124)
```rust
    /// Removes the ordered blocks for the given commit ledger info. This will
    /// remove all blocks up to (and including) the epoch and round of the commit.
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

# Audit Report

## Title
Epoch Rollback Attack via Unchecked Cross-Epoch Round Comparison in Consensus Observer

## Summary
An attacker can exploit a flawed cross-epoch round comparison in the consensus observer to trigger state sync to an older epoch's commit decision. This causes the observer to roll back its root ledger info to a previous epoch while maintaining its current epoch state, creating a critical state desynchronization that violates consensus safety guarantees.

## Finding Description

The vulnerability exists in the consensus observer's commit decision processing logic where three sequential flaws enable an epoch rollback attack:

**Flaw 1: Signature Verification Bypass for Old Epoch Commits**

The observer only verifies commit decision signatures when the commit epoch matches the current epoch state. For commits from different epochs (old or future), signature verification is completely skipped. [1](#0-0) 

**Flaw 2: Cross-Epoch Round Comparison Without Epoch Validation**

The state sync trigger condition performs a flawed comparison that mixes epoch and round checks without validating they're from the same epoch: [2](#0-1) 

When `commit_epoch < last_block.epoch()` (old epoch) but `commit_round > last_block.round()`, the condition `epoch_changed || commit_round > last_block.round()` evaluates to `false || true = true`, incorrectly triggering state sync to an older epoch.

**Flaw 3: Premature Root Update Before State Sync Validation**

The observer unconditionally updates its root to the commit decision BEFORE state sync validates or completes: [3](#0-2) [4](#0-3) 

The `update_root` method unconditionally sets the new root without any validation: [5](#0-4) 

**Attack Execution Path:**

1. **Initial State** (realistic during epoch transition):
   - Observer epoch_state: epoch 5
   - Observer root: (epoch 4, round 100)
   - Observer last_ordered_block: (epoch 5, round 20) - ordered but not yet committed
   - Observer highest_committed: (epoch 4, round 100) - falls back to root

2. **Attack**: Malicious peer sends commit decision for (epoch 4, round 150)

3. **First Check** (line 457): `(4, 150) <= (4, 100)` evaluates to `false` ✓ Passes

4. **Second Check** (line 468): `commit_epoch (4) == epoch_state.epoch (5)` is `false` → Signature verification skipped ✓

5. **Third Check** (lines 502-504):
   - `epoch_changed = 4 > 5 = false`
   - `commit_round > last_block.round() = 150 > 20 = true`
   - Condition: `false || true = TRUE` → State sync triggered ✓

6. **State Corruption** (line 282): Root immediately updated to (epoch 4, round 150) before state sync validation

7. **No Recovery**: If state sync fails or is rejected, there is no mechanism to revert the root: [6](#0-5) 

**Final Corrupted State:**
- epoch_state: epoch 5 (unchanged)
- root: (epoch 4, round 150) (rolled back!)
- Critical desynchronization: epoch state and root are in different epochs

This breaks the **State Consistency** invariant and violates **Consensus Safety** as the observer can no longer properly validate or process blocks with its epoch state and root pointing to different epochs.

## Impact Explanation

**Critical Severity** - Qualifies as a **Consensus/Safety Violation** per Aptos bug bounty program:

1. **Consensus Divergence**: The observer's epoch management (epoch 5) and root commitment (epoch 4) are desynchronized, preventing proper block validation and consensus participation.

2. **State Consistency Violation**: The observer maintains contradictory internal state where different components believe they're operating in different epochs.

3. **Network Partition Risk**: If multiple observers are attacked simultaneously, they will have inconsistent blockchain views, potentially causing network-wide consensus issues.

4. **Signature Verification Bypass**: The attack exploits that old-epoch commit decisions skip all cryptographic validation, enabling unverified state transitions.

This meets **Critical** severity criteria per Aptos bug bounty guidelines for "Consensus/Safety violations" which qualify for up to $1,000,000 bounty.

## Likelihood Explanation

**High Likelihood:**

1. **Low Attack Complexity**: Any malicious peer that an observer subscribes to can send the crafted commit decision message via standard network protocols.

2. **No Cryptographic Barriers**: Old epoch commit decisions bypass signature verification entirely, so attackers don't need to forge valid cryptographic signatures.

3. **Common Network Condition**: The vulnerable state (observer in new epoch with root in old epoch) occurs naturally during normal epoch transitions when the observer has transitioned its epoch state but hasn't yet committed blocks in the new epoch.

4. **Deterministic Exploit**: The attack is fully deterministic and can be reliably triggered whenever the preconditions are met.

5. **No Additional Protections**: No rate limiting, additional validations, or defensive checks prevent this attack vector.

## Recommendation

Implement proper epoch validation in the state sync trigger logic:

```rust
// Line 502-504 should be replaced with:
let last_block = self.observer_block_data.lock().get_last_ordered_block();
let epoch_changed = commit_epoch > last_block.epoch();

// Only compare rounds if epochs match
let round_ahead = commit_epoch == last_block.epoch() && commit_round > last_block.round();

if epoch_changed || round_ahead {
    // State sync logic...
}
```

Additionally:
1. Add epoch validation to reject commit decisions from old epochs (commit_epoch < current_epoch)
2. Move root update to AFTER successful state sync completion, not before
3. Implement error recovery to revert root if state sync fails
4. Add signature verification for all commit decisions regardless of epoch

## Proof of Concept

The vulnerability can be demonstrated by:

1. Setting up a consensus observer connected to a malicious peer
2. Waiting for the observer to transition to a new epoch (epoch N+1) with ordered blocks but no commits yet
3. Having the malicious peer send a commit decision for (epoch N, round R) where R is greater than any round in epoch N+1
4. Observing the root rollback to epoch N while epoch_state remains at epoch N+1

The code paths cited above demonstrate this is exploitable through standard network message handling without requiring any special privileges or cryptographic capabilities.

## Notes

The vulnerability exists due to three compounding design flaws working together: (1) signature verification bypass for non-current epochs, (2) cross-epoch round comparison without epoch consistency validation, and (3) premature root updates before state sync validation. Each flaw individually might be acceptable, but their combination creates a critical security vulnerability that violates fundamental consensus safety guarantees. The attack is particularly concerning because it exploits the normal epoch transition process, making it both easy to trigger and difficult to distinguish from legitimate network behavior.

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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L502-504)
```rust
        let last_block = self.observer_block_data.lock().get_last_ordered_block();
        let epoch_changed = commit_epoch > last_block.epoch();
        if epoch_changed || commit_round > last_block.round() {
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L520-522)
```rust
            self.observer_block_data
                .lock()
                .update_blocks_for_state_sync_commit(&commit_decision);
```

**File:** consensus/src/consensus_observer/observer/block_data.rs (L275-282)
```rust
    pub fn update_blocks_for_state_sync_commit(&mut self, commit_decision: &CommitDecision) {
        // Get the commit proof, epoch and round
        let commit_proof = commit_decision.commit_proof();
        let commit_epoch = commit_decision.epoch();
        let commit_round = commit_decision.round();

        // Update the root
        self.update_root(commit_proof.clone());
```

**File:** consensus/src/consensus_observer/observer/block_data.rs (L300-302)
```rust
    pub fn update_root(&mut self, new_root: LedgerInfoWithSignatures) {
        self.root = new_root;
    }
```

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L219-230)
```rust
                if let Err(error) = execution_client
                    .clone()
                    .sync_to_target(commit_decision.commit_proof().clone())
                    .await
                {
                    error!(
                        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                            "Failed to sync to commit decision: {:?}! Error: {:?}",
                            commit_decision, error
                        ))
                    );
                    return;
```

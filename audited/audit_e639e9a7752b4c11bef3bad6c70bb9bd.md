# Audit Report

## Title
Consensus Observer DoS via Unverified Future Epoch CommitDecision

## Summary
The `CommitDecision::new()` constructor lacks input validation, allowing attackers to send malicious commit decisions with future epochs to consensus observer nodes. When the epoch doesn't match the current epoch, signature verification is skipped, and the unverified data corrupts the observer's root ledger info, causing a denial of service. [1](#0-0) 

## Finding Description

The vulnerability exists in the consensus observer's handling of commit decision messages. The `CommitDecision::new()` constructor accepts any `LedgerInfoWithSignatures` without validation. While the main consensus pipeline properly verifies commit decisions before processing, the consensus observer has a critical flaw in its epoch-based verification logic. [2](#0-1) 

When a commit decision is received with `commit_epoch != current_epoch_state.epoch`, the verification at line 470 is **completely skipped** because the condition at line 468 evaluates to false. The code then falls through to line 500+ where it processes future epoch commits without any signature verification. [3](#0-2) 

The unverified commit decision is then used to update critical observer state: [4](#0-3) [5](#0-4) 

The poisoned root then causes legitimate state sync notifications to be dropped: [6](#0-5) 

The TODO comment at line 497-498 explicitly acknowledges this is a known issue but provides no validation.

**Attack Vector:**
1. Attacker sends `CommitDecision` (observer message type) with:
   - `epoch = current_epoch + 100` (future epoch)
   - `round = u64::MAX` (arbitrary high value)
   - `signatures = empty` or invalid
   - `version = arbitrary value`

2. Observer receives message in `process_commit_decision_message()`
3. Line 449-450: Extracts unverified `commit_epoch` and `commit_round`
4. Line 457: Passes stale check (future > current)
5. Line 468: `commit_epoch != epoch_state.epoch` → verification **SKIPPED**
6. Line 520-522: `update_blocks_for_state_sync_commit()` called with unverified data
7. Line 282 (block_data.rs): Root updated with malicious ledger info: `self.root = commit_proof.clone()`
8. Line 525-526: State sync initiated to unreachable target
9. When legitimate state sync completes, line 1002 drops notification because synced values < poisoned root values
10. Observer stuck, cannot process valid commits

## Impact Explanation

This is a **High Severity** vulnerability per Aptos bug bounty criteria:

- **Validator node slowdowns**: Consensus observer nodes (used by validator fullnodes) experience DoS, unable to process legitimate commits
- **Significant protocol violations**: Observer bypasses signature verification for future epoch messages
- **Availability impact**: Affected VFNs cannot track consensus correctly until restart or epoch change

The consensus observer is configured for validator fullnodes (VFNs) as shown in the configuration code. Disabling VFN consensus observers affects their sync capabilities and network health. [7](#0-6) 

The verify() method is properly implemented but never called for future epoch messages in the observer path.

## Likelihood Explanation

**Likelihood: HIGH**

- **Attacker requirements**: None - any network peer can send consensus observer messages
- **Complexity**: Low - single malformed message triggers the vulnerability
- **Prerequisites**: None - observer nodes accept messages from any validator publisher
- **Detection**: Difficult - appears as legitimate future epoch message until DoS occurs
- **Rate limiting**: Limited protection at line 507, but only prevents multiple concurrent attacks

The vulnerability is trivial to exploit and affects all consensus observer nodes (VFNs) in the network.

## Recommendation

Add epoch validation before accepting commit decisions for state sync. Verify signatures even for future epoch commits, or reject them entirely:

```rust
// In process_commit_decision_message(), before line 500:
// Always verify commit decisions regardless of epoch
let epoch_state = self.get_epoch_state();
if let Err(error) = commit_decision.verify_commit_proof(&epoch_state) {
    // If current epoch verification fails and this is a future epoch,
    // we should reject it rather than blindly trust state sync
    error!(
        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
            "Failed to verify commit decision for epoch {}! Ignoring. Error: {:?}",
            commit_epoch, error
        ))
    );
    increment_invalid_message_counter(&peer_network_id, metrics::COMMIT_DECISION_LABEL);
    return;
}
```

Alternatively, implement future epoch validation:
1. Reject commit decisions more than 1 epoch ahead
2. Verify signatures using a cached future epoch state if available
3. Add upper bounds checking on epoch/round/version values

Also fix the `CommitDecision::new()` constructor to validate inputs:

```rust
pub fn new(ledger_info: LedgerInfoWithSignatures) -> Result<Self, Error> {
    ensure!(
        !ledger_info.commit_info().is_ordered_only(),
        "Cannot create CommitDecision with ordered-only commit info"
    );
    ensure!(
        ledger_info.get_num_voters() > 0,
        "Cannot create CommitDecision with empty signatures"
    );
    Ok(Self { ledger_info })
}
```

## Proof of Concept

```rust
// Reproduction steps for testing:

#[test]
fn test_future_epoch_commit_decision_dos() {
    // 1. Setup consensus observer with epoch E=1
    let mut observer = setup_consensus_observer(/* epoch */ 1);
    
    // 2. Create malicious CommitDecision with future epoch
    let malicious_ledger_info = LedgerInfoWithSignatures::new(
        LedgerInfo::new(
            BlockInfo::new(
                /* epoch */ 100,  // Far future epoch
                /* round */ u64::MAX,  // Arbitrary high round
                /* id */ HashValue::random(),
                /* executed_state_id */ HashValue::zero(),
                /* version */ 999999,
                /* timestamp */ 0,
                /* next_epoch_state */ None,
            ),
            /* consensus_data_hash */ HashValue::zero(),
        ),
        AggregateSignature::empty(),  // Empty signatures!
    );
    
    let malicious_commit = CommitDecision::new(malicious_ledger_info);
    
    // 3. Send to observer (this should fail verification but doesn't)
    observer.process_commit_decision_message(
        peer_network_id,
        Instant::now(),
        malicious_commit,
    );
    
    // 4. Verify observer root is poisoned
    let poisoned_root = observer.observer_block_data.lock().root();
    assert_eq!(poisoned_root.ledger_info().epoch(), 100);  // Poisoned!
    
    // 5. Send legitimate commit decision for epoch 2
    let legitimate_commit = create_valid_commit_decision(/* epoch */ 2, /* round */ 10);
    
    // 6. Simulate state sync completion
    observer.handle_state_sync_notification(
        StateSyncNotification::commit_sync_completed(legitimate_commit.commit_proof().clone())
    );
    
    // 7. Verify legitimate notification was dropped (DoS achieved)
    // Observer remains stuck at poisoned root epoch 100
    assert_eq!(observer.observer_block_data.lock().root().ledger_info().epoch(), 100);
    // Observer cannot process any real commits now!
}
```

## Notes

This vulnerability demonstrates a critical gap in the consensus observer's security model. The TODO comment at line 497 indicates awareness of the issue but no fix was implemented. The root cause is the missing validation in `CommitDecision::new()` combined with the epoch-based conditional verification that creates an unverified code path.

The impact is limited to consensus observer nodes (VFNs) and does not affect the main consensus protocol, but it represents a significant availability issue for nodes relying on observer-based synchronization.

### Citations

**File:** consensus/consensus-types/src/pipeline/commit_decision.rs (L30-32)
```rust
    pub fn new(ledger_info: LedgerInfoWithSignatures) -> Self {
        Self { ledger_info }
    }
```

**File:** consensus/consensus-types/src/pipeline/commit_decision.rs (L49-59)
```rust
    pub fn verify(&self, validator: &ValidatorVerifier) -> anyhow::Result<()> {
        ensure!(
            !self.ledger_info.commit_info().is_ordered_only(),
            "Unexpected ordered only commit info"
        );
        // We do not need to check the author because as long as the signature tree
        // is valid, the message should be valid.
        self.ledger_info
            .verify_signatures(validator)
            .context("Failed to verify Commit Decision")
    }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L466-495)
```rust
        // If the commit decision is for the current epoch, verify and process it
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

            // Update the latency metrics for commit processing
            update_message_processing_latency_metrics(
                message_received_time,
                &peer_network_id,
                metrics::COMMIT_DECISION_LABEL,
            );

            // Update the pending blocks with the commit decision
            if self.process_commit_decision_for_pending_block(&commit_decision) {
                return; // The commit decision was successfully processed
            }
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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L994-1010)
```rust
        // Get the block data root epoch and round
        let block_data_root = self.observer_block_data.lock().root();
        let block_data_epoch = block_data_root.ledger_info().epoch();
        let block_data_round = block_data_root.ledger_info().round();

        // If the commit sync notification is behind the block data root, ignore it. This
        // is possible due to a race condition where we started syncing to a newer commit
        // at the same time that state sync sent the notification for a previous commit.
        if (synced_epoch, synced_round) < (block_data_epoch, block_data_round) {
            info!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Ignoring old commit sync notification for epoch: {}, round: {}! Current root: {:?}",
                    synced_epoch, synced_round, block_data_root
                ))
            );
            return;
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

**File:** consensus/src/consensus_observer/observer/block_data.rs (L300-302)
```rust
    pub fn update_root(&mut self, new_root: LedgerInfoWithSignatures) {
        self.root = new_root;
    }
```

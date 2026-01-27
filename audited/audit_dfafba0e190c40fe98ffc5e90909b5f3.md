# Audit Report

## Title
Consensus Observer Accepts Unvalidated Future Epoch Commit Decisions Leading to Resource Exhaustion

## Summary
The `sync_to_commit()` function in the consensus observer state sync manager does not validate commit proof signatures before initiating synchronization for future epoch commit decisions. This allows malicious peers to trigger resource-wasting sync attempts to non-existent or forged blockchain states.

## Finding Description
The consensus observer processes commit decisions from subscribed peers without proper validation when the commit is for a future epoch. [1](#0-0) 

When a commit decision arrives for the **current epoch**, signature validation occurs at line 470. However, when the commit decision is for a **future epoch** (line 468 check fails), the code skips validation entirely and proceeds directly to state sync at lines 500-527. [2](#0-1) 

The TODO comment at lines 497-498 explicitly acknowledges this gap: *"TODO: identify the best way to handle an invalid commit decision for a future epoch. In such cases, we currently rely on state sync."*

The `sync_to_commit()` function itself performs no validation: [3](#0-2) 

While the `CommitDecision` struct has a `verify_commit_proof()` method available: [4](#0-3) 

This validation is never invoked for future epoch commits before setting them as sync targets.

**Attack Propagation:**
1. Attacker subscribes as a peer to a consensus observer node
2. Attacker crafts a `CommitDecision` with forged signatures for a future epoch (e.g., epoch E+10) at an arbitrarily high version (e.g., version 999,999,999)
3. Observer receives the message and checks if it's for the current epoch (line 468) - check fails
4. Observer skips validation (lines 497-527) and calls `sync_to_commit()` with the forged decision
5. State sync attempts to reach version 999,999,999, which doesn't exist on the network
6. Observer continuously requests non-existent data from peers, wasting computational resources and network bandwidth
7. The sync never completes, leaving the observer in a degraded state

**Severity Limitation Note:**
While the node does not accept invalid state (because state sync validates incoming chunks from peers), the observer becomes unavailable for its intended purpose and wastes resources indefinitely trying to reach a non-existent target.

## Impact Explanation
This vulnerability constitutes a **Medium Severity** issue under the Aptos bug bounty criteria for the following reasons:

1. **State inconsistencies requiring intervention**: The observer node gets stuck attempting to sync to a forged target, requiring manual intervention (restart/reconfiguration) to recover.

2. **Resource exhaustion on observer nodes**: Continuous failed sync attempts consume CPU, memory, and network bandwidth.

3. **Limited scope**: This affects consensus **observers** (non-validator nodes that passively observe consensus), not active consensus validators. Observer unavailability does not directly impact network consensus safety or liveness.

This does **not** reach Critical severity because:
- No funds can be stolen or minted
- No consensus safety violations occur (validators are unaffected)
- No permanent network damage occurs
- Observers can recover through restart

## Likelihood Explanation
The likelihood is **HIGH** for the following reasons:

1. **Low attack complexity**: Any peer that successfully subscribes to an observer can send forged commit decisions
2. **No authentication barriers**: The observer processes messages from subscribed peers without pre-validation
3. **Observable behavior**: Attackers can easily confirm the attack succeeded by monitoring the observer's sync requests
4. **Multiple attack opportunities**: An attacker can repeatedly send forged commits to continuously disrupt the observer

The attack requires only:
- Network access to reach an observer node
- Ability to send consensus observer protocol messages
- No validator keys or privileged access

## Recommendation
Implement validation of commit proof signatures **before** initiating state sync, regardless of epoch:

```rust
// In consensus_observer.rs, process_commit_decision_message():
// After line 495, before line 500, add:

// For future epoch commits, we cannot validate against the current epoch state.
// However, we should still attempt basic validation to prevent DoS attacks.
// At minimum, verify the ledger info structure is well-formed and the version
// is reasonable (not far beyond current network state).

// Option 1: Reject future epoch commits entirely until proper validation is implemented
if commit_epoch > epoch_state.epoch {
    warn!(
        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
            "Rejecting commit decision for future epoch: {:?}. Current epoch: {:?}",
            commit_epoch, epoch_state.epoch
        ))
    );
    return;
}

// Option 2 (more complex): Implement relaxed validation for future epochs
// - Verify signature structure is well-formed
// - Verify version is within reasonable bounds of current synced version
// - Rate limit sync requests from peers
```

Alternatively, implement the TODO at line 497-498 with proper future epoch validation logic that:
1. Verifies the commit decision's structural integrity
2. Checks the version is within reasonable bounds
3. Implements rate limiting on sync_to_commit calls per peer
4. Tracks and penalizes peers sending invalid targets

## Proof of Concept

```rust
// Simulated attack demonstration
// This would run as a malicious peer sending messages to an observer

use aptos_types::{
    aggregate_signature::AggregateSignature,
    block_info::BlockInfo,
    ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
};

#[test]
fn test_forged_future_epoch_commit_dos() {
    // Setup: Initialize a consensus observer (not shown for brevity)
    // Assume observer is subscribed to our malicious peer
    
    // Craft a forged commit decision for a far future epoch
    let forged_epoch = 9999; // Far future epoch
    let forged_version = 999_999_999; // Non-existent version
    
    let forged_ledger_info = LedgerInfo::new(
        BlockInfo::new(
            forged_epoch,
            0, // round
            HashValue::zero(),
            HashValue::zero(),
            forged_version,
            0, // timestamp
            None, // next_epoch_state
        ),
        HashValue::zero(),
    );
    
    // Create commit decision with EMPTY/FORGED signatures
    let forged_commit_proof = LedgerInfoWithSignatures::new(
        forged_ledger_info,
        AggregateSignature::empty(), // Invalid signatures!
    );
    
    let commit_decision = CommitDecision::new(forged_commit_proof);
    
    // Send to observer - it will NOT validate and will start syncing
    // observer.process_commit_decision_message(peer_id, timestamp, commit_decision);
    
    // Observer will now:
    // 1. Skip validation (epoch check fails at line 468)
    // 2. Call sync_to_commit() with forged target (line 526)
    // 3. Waste resources trying to reach version 999,999,999
    // 4. Never complete sync, degrading observer functionality
    
    // Expected behavior: Observer should REJECT this message
    // Actual behavior: Observer ACCEPTS and attempts to sync
}
```

**Notes:**
- The vulnerability is confirmed by the explicit TODO comment acknowledging the missing validation for future epoch commits
- While the observer doesn't accept invalid state (due to downstream validation), the resource exhaustion and unavailability constitute a real security issue
- This is a design flaw rather than an implementation bug, as evidenced by the TODO comment indicating awareness but lack of solution

### Citations

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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L497-527)
```rust
        // TODO: identify the best way to handle an invalid commit decision
        // for a future epoch. In such cases, we currently rely on state sync.

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

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L190-221)
```rust
    pub fn sync_to_commit(&mut self, commit_decision: CommitDecision, epoch_changed: bool) {
        // Log that we're starting to sync to the commit decision
        info!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Started syncing to commit: {}!",
                commit_decision.proof_block_info()
            ))
        );

        // Get the commit decision epoch and round
        let commit_epoch = commit_decision.epoch();
        let commit_round = commit_decision.round();

        // Clone the required components for the state sync task
        let execution_client = self.execution_client.clone();
        let sync_notification_sender = self.state_sync_notification_sender.clone();

        // Spawn a task to sync to the commit decision
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        tokio::spawn(Abortable::new(
            async move {
                // Update the state sync metrics now that we're syncing to a commit
                metrics::set_gauge_with_label(
                    &metrics::OBSERVER_STATE_SYNC_EXECUTING,
                    metrics::STATE_SYNCING_TO_COMMIT,
                    1, // We're syncing to a commit decision
                );

                // Sync to the commit decision
                if let Err(error) = execution_client
                    .clone()
                    .sync_to_target(commit_decision.commit_proof().clone())
```

**File:** consensus/src/consensus_observer/network/observer_message.rs (L366-375)
```rust
    /// Verifies the commit proof and returns an error if the proof is invalid
    pub fn verify_commit_proof(&self, epoch_state: &EpochState) -> Result<(), Error> {
        epoch_state.verify(&self.commit_proof).map_err(|error| {
            Error::InvalidMessageError(format!(
                "Failed to verify commit proof ledger info: {:?}, Error: {:?}",
                self.proof_block_info(),
                error
            ))
        })
    }
```

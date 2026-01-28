# Audit Report

## Title
Consensus Observer DoS via Unverified Epoch Extraction in CommitDecision Messages

## Summary
The consensus observer processes `CommitDecision` messages by extracting epoch and round values from embedded `LedgerInfoWithSignatures` before verifying cryptographic signatures. When receiving messages with future epoch values, the node bypasses signature verification entirely, updates its root state to unverified data, and enters expensive state sync operations targeting non-existent epochs, resulting in resource exhaustion and denial of service.

## Finding Description

The vulnerability exists in the `process_commit_decision_message` function where epoch and round values are extracted from unverified `CommitDecision` messages and used to make critical state decisions before signature verification occurs. [1](#0-0) 

The `epoch()` method extracts the epoch value directly from the unverified `LedgerInfoWithSignatures` by delegating to the underlying `LedgerInfo`: [2](#0-1) 

The code only verifies signatures when the commit decision is for the **current** epoch. If the epoch matches, verification is performed: [3](#0-2) 

However, if the unverified epoch is **higher** than the current epoch, the code bypasses verification entirely and proceeds to update state and trigger synchronization. A TODO comment explicitly acknowledges this security gap: [4](#0-3) 

The `update_blocks_for_state_sync_commit` function updates the node's root ledger info to the unverified commit proof: [5](#0-4) 

This calls `update_root` which directly replaces the root with unverified data: [6](#0-5) 

The state sync manager then spawns a task to sync to the unverified target, consuming resources: [7](#0-6) 

**Attack Scenario:**
1. A malicious or compromised validator (< 1/3 Byzantine, within Aptos threat model) crafts a `CommitDecision` with epoch = 999999 and invalid signatures
2. Sends the message to consensus observer nodes subscribed to it  
3. Observer extracts epoch 999999 without verification
4. Observer compares 999999 > current_epoch → bypasses signature verification
5. Observer updates its root ledger info to the unverified value
6. Observer triggers expensive state sync operations to epoch 999999
7. Observer wastes resources attempting to sync to a non-existent epoch
8. While syncing through the epoch transition, the observer drops subsequent commit decisions, preventing it from processing legitimate consensus messages

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under Aptos bug bounty criteria:

**Security Invariant Violation:**
- The fundamental security invariant that all ledger info must pass signature verification before acceptance is violated
- Unverified data is used to update critical state (root ledger info)

**Resource Exhaustion:**
- State sync operations consume CPU, memory, and network bandwidth while attempting to fetch data for non-existent epochs
- The state sync timeout mechanism eventually fails the operation, but resources are wasted during the attempt

**Temporary Denial of Service:**
- While attempting to sync through an epoch transition, the observer cannot process new commit decisions, as shown in the code that drops messages when `is_syncing_through_epoch()` returns true
- This effectively removes the observer from the pool temporarily

**Scope Limitation:**
- This affects Validator Fullnodes (VFNs) and Public Fullnodes (PFNs) running consensus observer, not validator consensus directly
- Validators continue operating normally
- No funds are directly lost or stolen
- Recovery is possible by restarting the affected node (root is in-memory only, not persisted to storage)

**Impact Classification:** Medium severity - state inconsistencies requiring manual intervention and temporary liveness issues for observer infrastructure, which serves as critical entry points for user transaction submission.

## Likelihood Explanation

This vulnerability has **High likelihood** of exploitation:

**Attacker Requirements:**
- Control or compromise of a single validator that observer nodes subscribe to (< 1/3 Byzantine validators, within Aptos threat model)
- Ability to craft a `CommitDecision` message with arbitrary epoch and invalid signatures
- No consensus majority or quorum compromise required

**Attack Complexity:**
- Low - straightforward message construction using the consensus publisher infrastructure
- Deterministic outcome - attack succeeds reliably when conditions are met
- No timing requirements or race conditions needed
- Can target multiple observer nodes simultaneously that subscribe to the compromised validator

**Detection:**
- Failed state sync attempts to impossible epochs will appear in logs
- Requires manual monitoring to identify and recover from the attack

## Recommendation

Implement signature verification for all commit decisions regardless of epoch before using the extracted epoch value to make state decisions:

```rust
fn process_commit_decision_message(
    &mut self,
    peer_network_id: PeerNetworkId,
    message_received_time: Instant,
    commit_decision: CommitDecision,
) {
    // Get the commit decision epoch and round
    let commit_epoch = commit_decision.epoch();
    let commit_round = commit_decision.round();

    // Verify the commit decision BEFORE using epoch for any decisions
    let epoch_state = self.get_epoch_state();
    
    // If epoch is ahead, we need the future epoch state to verify
    // For now, verify against current epoch or reject if too far ahead
    if commit_epoch > epoch_state.epoch {
        // Option 1: Queue for later verification after epoch transition
        // Option 2: Request epoch state from peers and verify
        // Option 3: Drop with warning (safest)
        warn!("Received commit decision for future epoch without ability to verify");
        return;
    }
    
    // Always verify before processing
    if let Err(error) = commit_decision.verify_commit_proof(&epoch_state) {
        error!("Failed to verify commit decision");
        increment_invalid_message_counter(&peer_network_id, metrics::COMMIT_DECISION_LABEL);
        return;
    }
    
    // Now safe to process verified commit decision
    // ... rest of logic
}
```

Alternatively, implement a mechanism to fetch and verify epoch state for future epochs before accepting commit decisions for those epochs.

## Proof of Concept

The vulnerability can be demonstrated by examining the code paths:

1. A compromised validator calls the consensus publisher's `publish_message` with a crafted `CommitDecision`
2. The observer receives it via `process_commit_decision_message`
3. Line 449 extracts the epoch without verification
4. Lines 468-482 only verify if `commit_epoch == epoch_state.epoch` 
5. Lines 502-527 proceed to state sync for future epochs without verification
6. Line 522 updates root to unverified data
7. Line 525-526 triggers state sync to non-existent epoch

This demonstrates a complete bypass of the signature verification requirement for future epoch commit decisions, violating the fundamental security principle that all cryptographic signatures must be verified before trusting the data.

**Notes:**
- The TODO comment on lines 497-498 explicitly acknowledges this is a known gap requiring a fix
- The vulnerability affects consensus observer infrastructure (VFNs/PFNs) but not validator consensus itself
- Recovery requires manual intervention (node restart) but does not result in permanent state corruption
- This is an application-level protocol vulnerability, not a network infrastructure attack

### Citations

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L448-450)
```rust
        // Get the commit decision epoch and round
        let commit_epoch = commit_decision.epoch();
        let commit_round = commit_decision.round();
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L466-482)
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

**File:** consensus/consensus-types/src/pipeline/commit_decision.rs (L38-40)
```rust
    pub fn epoch(&self) -> u64 {
        self.ledger_info.ledger_info().epoch()
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

**File:** consensus/src/consensus_observer/observer/block_data.rs (L299-302)
```rust
    /// Updates the root ledger info
    pub fn update_root(&mut self, new_root: LedgerInfoWithSignatures) {
        self.root = new_root;
    }
```

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L189-258)
```rust
    /// Invokes state sync to synchronize to a new commit decision
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
                    .await
                {
                    error!(
                        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                            "Failed to sync to commit decision: {:?}! Error: {:?}",
                            commit_decision, error
                        ))
                    );
                    return;
                }

                // Notify consensus observer that we've synced to the commit decision
                let state_sync_notification = StateSyncNotification::commit_sync_completed(
                    commit_decision.commit_proof().clone(),
                );
                if let Err(error) = sync_notification_sender.send(state_sync_notification) {
                    error!(
                        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                            "Failed to send state sync notification for commit decision epoch: {:?}, round: {:?}! Error: {:?}",
                            commit_epoch, commit_round, error
                        ))
                    );
                }

                // Clear the state sync metrics now that we're done syncing
                metrics::set_gauge_with_label(
                    &metrics::OBSERVER_STATE_SYNC_EXECUTING,
                    metrics::STATE_SYNCING_TO_COMMIT,
                    0, // We're no longer syncing to a commit decision
                );
            },
            abort_registration,
        ));

        // Save the sync task handle
        self.sync_to_commit_handle = Some((DropGuard::new(abort_handle), epoch_changed));
    }
```

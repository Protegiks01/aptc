# Audit Report

## Title
Race Condition Between Fallback and Commit Sync Causes State Corruption in Consensus Observer

## Summary
The consensus observer's state sync system has a race condition where concurrent fallback sync and commit sync operations can cause state corruption. The `process_fallback_sync_notification()` handler lacks validation to prevent overwriting the root ledger info set by a concurrent commit sync operation, causing observer nodes to end up at incorrect ledger positions and requiring manual intervention to recover.

## Finding Description
The vulnerability exists in how the consensus observer handles two independent synchronization mechanisms that can execute concurrently:

**1. Fallback Sync:** Triggered when the observer falls behind, syncing for a configured duration. [1](#0-0) 

**2. Commit Sync:** Triggered when a commit decision arrives for a future round, syncing to a specific target. [2](#0-1) 

The state sync manager stores these as separate optional fields, allowing both to be active simultaneously: [3](#0-2) 

**The Critical Flaw:**

When a commit decision arrives for a future round within the same epoch, the system only checks `is_syncing_through_epoch()` which requires an epoch change. It does NOT check if fallback sync is already active: [4](#0-3) 

The `is_syncing_through_epoch()` method only returns true when syncing through an epoch change: [5](#0-4) 

This allows the commit sync to start while fallback sync is running. The root is updated to the commit target: [6](#0-5) 

The vulnerability manifests in `process_fallback_sync_notification()` which only validates that fallback mode is active but does NOT validate the synced ledger info against the current root: [7](#0-6) 

In contrast, `process_commit_sync_notification()` properly validates the synced ledger info against the block data root and rejects notifications that don't match: [8](#0-7) 

**Exploitation Scenario:**
1. Observer enters fallback mode at epoch 5, round 100 (spawns async task A)
2. While task A runs, commit decision arrives for epoch 5, round 150 (same epoch)
3. `is_syncing_through_epoch()` returns false, check passes
4. Root is updated to (5, 150) via `update_blocks_for_state_sync_commit()`
5. Commit sync starts (spawns async task B)
6. Task A completes first, sends `FallbackSyncCompleted(5, 100)`
7. Handler checks `in_fallback_mode()` → passes, updates root to (5, 100) without validation
8. Task B completes, sends `CommitSyncCompleted(5, 150)`
9. Handler validates (5, 150) > (5, 100), rejects as invalid
10. **Observer stuck at wrong position (5, 100) instead of correct (5, 150)**

The notifications are processed sequentially through the event loop: [9](#0-8) 

## Impact Explanation
This is **Medium Severity** per Aptos bug bounty criteria: "State inconsistencies requiring manual intervention."

The vulnerability breaks the state consistency invariant for consensus observer nodes. Affected observers:
- End up at incorrect ledger positions diverging from the actual chain state
- Cannot process newer blocks and commit decisions
- Lose consensus observer functionality until manually recovered
- Require operator intervention to restore normal operation

This meets the Medium severity threshold because it causes state corruption requiring intervention but does not result in fund loss, consensus safety violations, or validator compromise. Observer nodes do not participate in consensus or hold funds, limiting the blast radius to observer functionality degradation.

## Likelihood Explanation
**Likelihood: High**

This race condition occurs naturally during normal network operations:
- **Network delays** regularly cause observers to fall behind, triggering fallback sync
- **Commit decisions** from subscribed peers arrive continuously during normal operation
- **Timing window** is the entire fallback sync duration (configurable, typically several seconds)
- **No attacker control needed** - purely timing-dependent on network conditions
- **Deterministic exploitation** - once the race condition triggers, state corruption is guaranteed

The vulnerability can trigger during routine operations without any malicious intent or coordination.

## Recommendation
Add validation in `process_fallback_sync_notification()` to check if the synced ledger info is compatible with the current root before updating it. The fix should:

1. Check if a commit sync is active when processing fallback sync notifications
2. Validate the fallback synced ledger info against the current root (similar to commit sync validation)
3. If the fallback sync result is stale (behind the current root), ignore it and log a warning
4. Only update the root if the fallback sync result is at or ahead of the current root

Example fix structure:
```rust
async fn process_fallback_sync_notification(
    &mut self,
    latest_synced_ledger_info: LedgerInfoWithSignatures,
) {
    // Existing checks...
    if !self.state_sync_manager.in_fallback_mode() {
        return;
    }
    
    // NEW: Get current root and validate
    let block_data_root = self.observer_block_data.lock().root();
    let synced_epoch = latest_synced_ledger_info.ledger_info().epoch();
    let synced_round = latest_synced_ledger_info.ledger_info().round();
    let root_epoch = block_data_root.ledger_info().epoch();
    let root_round = block_data_root.ledger_info().round();
    
    // If fallback sync is behind current root, ignore it
    if (synced_epoch, synced_round) < (root_epoch, root_round) {
        info!("Ignoring stale fallback sync notification...");
        self.state_sync_manager.clear_active_fallback_sync();
        return;
    }
    
    // Proceed with update...
}
```

## Proof of Concept
A complete PoC would require setting up a consensus observer test environment with:
1. A mock state sync client that can control sync completion timing
2. Triggering fallback sync
3. Sending a commit decision for a future round in the same epoch
4. Completing fallback sync before commit sync
5. Verifying the observer ends up at the wrong ledger position

The logical flow is clearly demonstrated through the code analysis above, showing the race condition can occur during normal operations.

## Notes
This vulnerability is specific to the consensus observer component and does not affect validator nodes or consensus safety. However, it does cause operational issues for observer nodes that require manual intervention to resolve, meeting the Medium severity criteria per the Aptos bug bounty program.

### Citations

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L53-61)
```rust
    // The active fallback sync handle. If this is set, it means that
    // we've fallen back to state sync, and we should wait for it to complete.
    fallback_sync_handle: Option<DropGuard>,

    // The active sync to commit handle. If this is set, it means that
    // we're waiting for state sync to synchronize to a known commit decision.
    // The flag indicates if the commit will transition us to a new epoch.
    sync_to_commit_handle: Option<(DropGuard, bool)>,
}
```

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L105-109)
```rust
    /// Returns true iff we are waiting for state sync to synchronize
    /// to a commit decision that will transition us to a new epoch
    pub fn is_syncing_through_epoch(&self) -> bool {
        matches!(self.sync_to_commit_handle, Some((_, true)))
    }
```

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L117-187)
```rust
    pub fn sync_for_fallback(&mut self) {
        // Log that we're starting to sync in fallback mode
        info!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Started syncing in fallback mode! Syncing duration: {:?} ms!",
                self.consensus_observer_config.observer_fallback_duration_ms
            ))
        );

        // Update the state sync fallback counter
        metrics::increment_counter_without_labels(&metrics::OBSERVER_STATE_SYNC_FALLBACK_COUNTER);

        // Clone the required components for the state sync task
        let consensus_observer_config = self.consensus_observer_config;
        let execution_client = self.execution_client.clone();
        let sync_notification_sender = self.state_sync_notification_sender.clone();

        // Spawn a task to sync for the fallback
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        tokio::spawn(Abortable::new(
            async move {
                // Update the state sync metrics now that we're syncing for the fallback
                metrics::set_gauge_with_label(
                    &metrics::OBSERVER_STATE_SYNC_EXECUTING,
                    metrics::STATE_SYNCING_FOR_FALLBACK,
                    1, // We're syncing for the fallback
                );

                // Get the fallback duration
                let fallback_duration =
                    Duration::from_millis(consensus_observer_config.observer_fallback_duration_ms);

                // Sync for the fallback duration
                let latest_synced_ledger_info = match execution_client
                    .clone()
                    .sync_for_duration(fallback_duration)
                    .await
                {
                    Ok(latest_synced_ledger_info) => latest_synced_ledger_info,
                    Err(error) => {
                        error!(LogSchema::new(LogEntry::ConsensusObserver)
                            .message(&format!("Failed to sync for fallback! Error: {:?}", error)));
                        return;
                    },
                };

                // Notify consensus observer that we've synced for the fallback
                let state_sync_notification =
                    StateSyncNotification::fallback_sync_completed(latest_synced_ledger_info);
                if let Err(error) = sync_notification_sender.send(state_sync_notification) {
                    error!(
                        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                            "Failed to send state sync notification for fallback! Error: {:?}",
                            error
                        ))
                    );
                }

                // Clear the state sync metrics now that we're done syncing
                metrics::set_gauge_with_label(
                    &metrics::OBSERVER_STATE_SYNC_EXECUTING,
                    metrics::STATE_SYNCING_FOR_FALLBACK,
                    0, // We're no longer syncing for the fallback
                );
            },
            abort_registration,
        ));

        // Save the sync task handle
        self.fallback_sync_handle = Some(DropGuard::new(abort_handle));
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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L934-950)
```rust
        // Verify that there is an active fallback sync
        if !self.state_sync_manager.in_fallback_mode() {
            // Log the error and return early
            error!(LogSchema::new(LogEntry::ConsensusObserver).message(
                "Failed to process fallback sync notification! No active fallback sync found!"
            ));
            return;
        }

        // Reset the fallback manager state
        self.observer_fallback_manager
            .reset_syncing_progress(&latest_synced_ledger_info);

        // Update the root with the latest synced ledger info
        self.observer_block_data
            .lock()
            .update_root(latest_synced_ledger_info);
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L999-1023)
```rust
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

        // If the commit sync notification is ahead the block data root, something has gone wrong!
        if (synced_epoch, synced_round) > (block_data_epoch, block_data_round) {
            // Log the error, reset the state sync manager and return early
            error!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Received invalid commit sync notification for epoch: {}, round: {}! Current root: {:?}",
                    synced_epoch, synced_round, block_data_root
                ))
            );
            self.state_sync_manager.clear_active_commit_sync();
            return;
        }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L1128-1141)
```rust
            tokio::select! {
                Some(network_message) = consensus_observer_message_receiver.next() => {
                    self.process_network_message(network_message).await;
                }
                Some(state_sync_notification) = state_sync_notification_listener.recv() => {
                    self.process_state_sync_notification(state_sync_notification).await;
                },
                _ = progress_check_interval.select_next_some() => {
                    self.check_progress().await;
                }
                else => {
                    break; // Exit the consensus observer loop
                }
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

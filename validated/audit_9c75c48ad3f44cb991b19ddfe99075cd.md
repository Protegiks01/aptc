# Audit Report

## Title
Consensus Observer Bypasses Signature Verification for Future-Epoch CommitDecisions Enabling Critical State Corruption

## Summary
The consensus observer component accepts `CommitDecision` messages from untrusted network peers and conditionally skips signature verification when the epoch doesn't match the current epoch. These unverified commit decisions are then used to corrupt critical node state (buffer manager, logical time, root ledger info) BEFORE any state sync validation occurs, leading to permanent node dysfunction with no automated recovery mechanism.

## Finding Description

The vulnerability exists in the consensus observer's message processing flow where verification is conditionally bypassed but the unverified data is still used for state modifications.

**1. Conditional Verification Bypass**

The consensus observer processes commit decisions with epoch-dependent verification logic. When `commit_epoch == epoch_state.epoch`, signature verification is performed via `commit_decision.verify_commit_proof(&epoch_state)`. [1](#0-0) 

However, when epochs don't match, this verification is entirely skipped, and the code proceeds to use the unverified commit decision for state sync operations. [2](#0-1) 

A TODO comment explicitly acknowledges this design flaw: "TODO: identify the best way to handle an invalid commit decision for a future epoch. In such cases, we currently rely on state sync." [3](#0-2) 

**2. State Corruption Before Sync Validation**

The unverified commit decision triggers state modifications through multiple paths:

First, `update_blocks_for_state_sync_commit()` updates the observer's root ledger info without validation: [4](#0-3) 

The `update_root()` method directly assigns the unverified ledger info: [5](#0-4) 

Second, `sync_to_commit()` calls the execution client's `sync_to_target()` method with the unverified commit proof. [6](#0-5) 

**3. Buffer Manager Corruption**

In `execution_client.sync_to_target()`, the reset operation occurs BEFORE the actual state sync: [7](#0-6) 

A TODO comment explicitly acknowledges the lack of recovery: "TODO: handle the state sync error (e.g., re-push the ordered blocks to the buffer manager when it's reset but sync fails)." [8](#0-7) 

The reset operation extracts the round from the unverified target and uses it to corrupt the buffer manager's state: [9](#0-8) 

Specifically, both `highest_committed_round` and `latest_round` are set to the attacker-controlled round value without any validation. [10](#0-9) 

**4. Logical Time Corruption**

The execution proxy's `sync_to_target()` constructs `target_logical_time` from the unverified target's epoch and round, then unconditionally updates `latest_logical_time` after the sync attempt but before checking if the sync succeeded: [11](#0-10) 

The critical issue is at line 222 where `*latest_logical_time = target_logical_time` executes regardless of whether the state sync at line 218 succeeded or failed.

**Attack Scenario:**
1. Attacker operates a node advertising ConsensusObserver protocol support
2. VFN observer subscribes based on distance/latency metrics (peer selection uses no trust requirements) [12](#0-11) 
3. Attacker sends `CommitDecision` with `epoch = current_epoch + 1`, `round = u64::MAX - 100`, invalid signatures
4. Observer skips verification (different epoch) but proceeds with state modifications
5. Buffer manager, logical time, and root are corrupted BEFORE state sync validation
6. State sync fails (invalid target), but corruption persists
7. Observer cannot process legitimate blocks as they appear "behind" the corrupted state

## Impact Explanation

This vulnerability represents a **state corruption attack** causing permanent VFN observer dysfunction. The impact aligns with **Medium to High Severity** per Aptos bug bounty criteria:

**VFN Observer Node Dysfunction:**
VFN observers are enabled by default for validator fullnodes. [13](#0-12) 

The corrupted logical time (set to future epoch and near-maximum round) and buffer manager state (highest_committed_round set to attacker-controlled value) prevent processing any legitimate consensus messages, as they all have lower logical time values than the corrupted state. The node becomes permanently non-functional for consensus observation.

**No Automated Recovery:**
The TODO comments in the codebase explicitly acknowledge the lack of recovery mechanisms when "reset but sync fails", confirming that corruption persists without manual intervention.

**State Inconsistency:**
This vulnerability causes state inconsistencies requiring manual intervention to resolve, which aligns with **Medium Severity** impact criteria. However, given that VFN observers serve blockchain state queries for applications and the dysfunction is permanent without manual recovery, this could also qualify as **High Severity** under API/service disruption criteria depending on the specific impact classification.

## Likelihood Explanation

**Likelihood: Medium**

The attack is feasible because:

1. **Default Configuration**: VFN observers are enabled by default with both observer and publisher features [14](#0-13) 

2. **No Trust Requirements**: Peer selection for subscriptions uses distance and latency metrics, not trust relationships, meaning observers can subscribe to any peer advertising the protocol

3. **Simple Attack Vector**: Only requires sending a single malformed CommitDecision message with future epoch and invalid signatures

4. **Acknowledged Design Flaw**: TODO comments confirm this is a known design issue requiring a fix

The attack does not require compromising trusted nodes, majority stake control, or complex coordination.

## Recommendation

Implement signature verification for ALL commit decisions before using them for state modifications, regardless of epoch:

```rust
// In process_commit_decision_message, verify ALL commit decisions
let epoch_state = self.get_epoch_state();

// Always verify signature, even for future epochs
if let Err(error) = commit_decision.verify_commit_proof(&epoch_state) {
    // For future epochs, attempt verification with known future epoch state if available
    // Otherwise, reject the commit decision entirely
    error!("Failed to verify commit decision: {:?}", error);
    increment_invalid_message_counter(&peer_network_id, metrics::COMMIT_DECISION_LABEL);
    return;
}

// Only proceed with state modifications after successful verification
```

Additionally, implement rollback mechanisms in the execution client to restore previous state if state sync fails after reset operations.

## Proof of Concept

A malicious peer can send a `CommitDecision` with:
- `epoch = current_epoch + 1` (to bypass verification)
- `round = u64::MAX - 100` (to corrupt state tracking)  
- Invalid or missing signatures (ignored since verification is skipped)

The consensus observer will process this message, skip signature verification due to epoch mismatch, and proceed to corrupt the buffer manager's `highest_committed_round`, the execution proxy's `latest_logical_time`, and the observer's root ledger info. When state sync subsequently fails (as expected for an invalid target), these corruptions persist, rendering the node unable to process any legitimate consensus messages with lower logical time values.

## Notes

The vulnerability is confirmed by explicit TODO comments in the codebase acknowledging both the lack of verification for future-epoch commit decisions and the absence of recovery mechanisms when reset precedes failed state sync. This represents a state corruption vulnerability rather than a traditional network DoS, as it exploits a design flaw in the verification and state management logic rather than resource exhaustion.

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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L497-498)
```rust
        // TODO: identify the best way to handle an invalid commit decision
        // for a future epoch. In such cases, we currently rely on state sync.
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

**File:** consensus/src/consensus_observer/observer/block_data.rs (L300-302)
```rust
    pub fn update_root(&mut self, new_root: LedgerInfoWithSignatures) {
        self.root = new_root;
    }
```

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L189-221)
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
```

**File:** consensus/src/pipeline/execution_client.rs (L661-672)
```rust
    async fn sync_to_target(&self, target: LedgerInfoWithSignatures) -> Result<(), StateSyncError> {
        fail_point!("consensus::sync_to_target", |_| {
            Err(anyhow::anyhow!("Injected error in sync_to_target").into())
        });

        // Reset the rand and buffer managers to the target round
        self.reset(&target).await?;

        // TODO: handle the state sync error (e.g., re-push the ordered
        // blocks to the buffer manager when it's reset but sync fails).
        self.execution_proxy.sync_to_target(target).await
    }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L579-596)
```rust
    async fn process_reset_request(&mut self, request: ResetRequest) {
        let ResetRequest { tx, signal } = request;
        info!("Receive reset");

        match signal {
            ResetSignal::Stop => self.stop = true,
            ResetSignal::TargetRound(round) => {
                self.highest_committed_round = round;
                self.latest_round = round;

                let _ = self.drain_pending_commit_proof_till(round);
            },
        }

        self.reset().await;
        let _ = tx.send(ResetAck::default());
        info!("Reset finishes");
    }
```

**File:** consensus/src/state_computer.rs (L177-233)
```rust
    async fn sync_to_target(&self, target: LedgerInfoWithSignatures) -> Result<(), StateSyncError> {
        // Grab the logical time lock and calculate the target logical time
        let mut latest_logical_time = self.write_mutex.lock().await;
        let target_logical_time =
            LogicalTime::new(target.ledger_info().epoch(), target.ledger_info().round());

        // Before state synchronization, we have to call finish() to free the
        // in-memory SMT held by BlockExecutor to prevent a memory leak.
        self.executor.finish();

        // The pipeline phase already committed beyond the target block timestamp, just return.
        if *latest_logical_time >= target_logical_time {
            warn!(
                "State sync target {:?} is lower than already committed logical time {:?}",
                target_logical_time, *latest_logical_time
            );
            return Ok(());
        }

        // This is to update QuorumStore with the latest known commit in the system,
        // so it can set batches expiration accordingly.
        // Might be none if called in the recovery path, or between epoch stop and start.
        if let Some(inner) = self.state.read().as_ref() {
            let block_timestamp = target.commit_info().timestamp_usecs();
            inner
                .payload_manager
                .notify_commit(block_timestamp, Vec::new());
        }

        // Inject an error for fail point testing
        fail_point!("consensus::sync_to_target", |_| {
            Err(anyhow::anyhow!("Injected error in sync_to_target").into())
        });

        // Invoke state sync to synchronize to the specified target. Here, the
        // ChunkExecutor will process chunks and commit to storage. However, after
        // block execution and commits, the internal state of the ChunkExecutor may
        // not be up to date. So, it is required to reset the cache of the
        // ChunkExecutor in state sync when requested to sync.
        let result = monitor!(
            "sync_to_target",
            self.state_sync_notifier.sync_to_target(target).await
        );

        // Update the latest logical time
        *latest_logical_time = target_logical_time;

        // Similarly, after state synchronization, we have to reset the cache of
        // the BlockExecutor to guarantee the latest committed state is up to date.
        self.executor.reset()?;

        // Return the result
        result.map_err(|error| {
            let anyhow_error: anyhow::Error = error.into();
            anyhow_error.into()
        })
    }
```

**File:** consensus/src/consensus_observer/observer/subscription_utils.rs (L29-30)
```rust
// A useful constant for representing the maximum ping latency
const MAX_PING_LATENCY_SECS: f64 = 10_000.0;
```

**File:** config/src/config/consensus_observer_config.rs (L13-13)
```rust
const ENABLE_ON_VALIDATOR_FULLNODES: bool = true;
```

**File:** config/src/config/consensus_observer_config.rs (L119-128)
```rust
            NodeType::ValidatorFullnode => {
                if ENABLE_ON_VALIDATOR_FULLNODES
                    && !observer_manually_set
                    && !publisher_manually_set
                {
                    // Enable both the observer and the publisher for VFNs
                    consensus_observer_config.observer_enabled = true;
                    consensus_observer_config.publisher_enabled = true;
                    modified_config = true;
                }
```

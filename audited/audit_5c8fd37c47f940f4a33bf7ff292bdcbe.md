# Audit Report

## Title
Consensus Observer Accepts Unverified Future Epoch Commit Decisions Leading to State Sync Manipulation

## Summary
The consensus observer's `sync_to_commit()` function accepts CommitDecision messages for future epochs without cryptographic verification of signatures or validation of round values. An attacker controlling a subscribed peer can send a malicious CommitDecision with arbitrary epoch and round values, causing the observer to attempt syncing to non-existent or incorrect blockchain state, resulting in denial of service or consensus safety violations.

## Finding Description

The vulnerability exists in the commit decision processing logic where signature verification is conditionally skipped for future epoch messages.

**Attack Flow:**

1. An observer subscribes to a malicious or compromised validator peer
2. The attacker sends a `CommitDecision` message with:
   - A future epoch number (e.g., current_epoch + 1)
   - A manipulated round value (e.g., round 999999999 or an arbitrary past round)
   - Invalid or forged signatures (won't be checked)

3. In `process_commit_decision_message()`, the observer extracts epoch and round values: [1](#0-0) 

4. Signature verification only occurs when the commit epoch matches the current epoch state: [2](#0-1) 

5. For future epochs, verification is completely bypassed and the observer directly initiates state sync: [3](#0-2) 

6. The `sync_to_commit()` function extracts unvalidated round values and spawns a sync task: [4](#0-3) [5](#0-4) 

7. ExecutionProxy's `sync_to_target()` accepts the target without signature validation: [6](#0-5) [7](#0-6) 

8. The state sync notification handler initializes the sync request without cryptographic validation: [8](#0-7) 

The observer attempts to sync to a non-existent or malicious state based on completely unverified epoch/round values from the attacker.

## Impact Explanation

**Critical Severity - Consensus Safety Violation & Availability Loss:**

- **Denial of Service**: An attacker can specify extremely large round numbers (e.g., 2^64-1) causing the observer to indefinitely attempt syncing to non-existent state, rendering it unavailable for consensus participation or transaction validation.

- **State Confusion**: By manipulating epoch/round combinations, an attacker could potentially cause the observer to sync to incorrect historical states in non-existent epochs, breaking the "Consensus Safety" invariant that requires all nodes to maintain consistent blockchain state.

- **Observer Network Disruption**: If multiple observers are compromised via their subscribed peers, this could cause widespread disruption to the observer network, impacting light clients and services relying on consensus observer data.

This qualifies as **Critical Severity** per Aptos Bug Bounty criteria:
- "Consensus/Safety violations" - Breaks consensus safety by allowing unverified state sync targets
- "Total loss of liveness/network availability" - Observer becomes unavailable when stuck syncing to malicious targets

## Likelihood Explanation

**High Likelihood:**

- **Attack Prerequisites**: The attacker only needs to control a single peer that an observer has subscribed to. This could be achieved by:
  - Compromising a single validator node
  - Setting up a malicious node that observers subscribe to
  - Man-in-the-middle attack on observer-validator communication

- **No Cryptographic Barriers**: The attack requires no cryptographic breaks - the vulnerability is in the missing validation logic, not in cryptographic primitives.

- **Easy Exploitation**: Crafting the malicious CommitDecision message is straightforward:
  ```rust
  let malicious_commit = CommitDecision::new(LedgerInfoWithSignatures::new(
      LedgerInfo::new(..., future_epoch, malicious_round, ...),
      AggregateSignature::empty() // Won't be verified!
  ));
  ```

- **Observable Impact**: The attack immediately affects the target observer, making it detectable but also exploitable at scale.

## Recommendation

Implement epoch change proof validation before accepting future epoch commit decisions:

1. **Require Epoch Change Proof**: Before syncing to a future epoch commit decision, validate that the observer has received and verified a valid epoch change proof containing the next epoch's validator set.

2. **Add Explicit Round Bounds Validation**: Implement sanity checks on round values to reject impossibly large or suspicious round numbers.

3. **Enhanced Validation in sync_to_commit()**:

```rust
pub fn sync_to_commit(&mut self, commit_decision: CommitDecision, epoch_changed: bool) {
    // Validate round is within reasonable bounds
    let commit_round = commit_decision.round();
    if commit_round > MAX_REASONABLE_ROUND {
        error!("Rejecting commit decision with suspiciously large round: {}", commit_round);
        return;
    }
    
    // For future epochs, require epoch change proof validation
    if epoch_changed {
        // Verify we have received and validated the epoch change proof
        // before attempting to sync to the new epoch
        if !self.has_validated_epoch_change(commit_decision.epoch()) {
            error!("Rejecting future epoch commit without validated epoch change proof");
            return;
        }
    }
    
    // Existing sync logic...
}
```

4. **Add Timeout Mechanism**: Implement timeouts for sync operations to prevent indefinite hanging on malicious targets.

5. **Multi-Peer Validation**: Consider requiring commit decisions to be confirmed by multiple subscribed peers before initiating state sync for future epochs.

## Proof of Concept

```rust
// Reproduction steps:

// 1. Setup: Observer subscribes to attacker-controlled peer
let observer = ConsensusObserver::new(...);
let malicious_peer = setup_malicious_peer();
observer.subscribe_to_peer(malicious_peer);

// 2. Attacker crafts malicious CommitDecision
let current_epoch = observer.get_current_epoch(); // e.g., 100
let malicious_epoch = current_epoch + 1; // Future epoch: 101
let malicious_round = u64::MAX; // Impossibly large round

let malicious_ledger_info = LedgerInfo::new(
    BlockInfo::new(malicious_epoch, malicious_round, HashValue::random(), ...),
    HashValue::zero(), // Invalid state root
    malicious_epoch,
    malicious_round,
    timestamp_usecs,
    None, // No next epoch info
);

// Invalid signatures - will not be verified for future epochs
let malicious_commit = CommitDecision::new(LedgerInfoWithSignatures::new(
    malicious_ledger_info,
    AggregateSignature::empty(),
));

// 3. Send malicious message to observer
malicious_peer.send_message(
    ConsensusObserverMessage::new_commit_decision_message(
        malicious_commit.commit_proof().clone()
    )
);

// 4. Observe impact:
// - process_commit_decision_message() extracts unverified epoch=101, round=u64::MAX
// - Signature verification skipped (epoch != current_epoch)
// - sync_to_commit() called with unverified commit_decision
// - Observer attempts to sync to non-existent version
// - Observer hangs indefinitely or until timeout
// - Observer unavailable for legitimate consensus participation

// Expected: Observer should reject the commit decision as unverified
// Actual: Observer attempts to sync to malicious state target
```

**Testing procedure:**
1. Deploy consensus observer with subscription to test peer
2. Send CommitDecision with future epoch + manipulated round from test peer
3. Monitor observer state - it will attempt sync_to_target with unverified values
4. Observer becomes stuck in syncing state, unresponsive to legitimate messages
5. Metrics show `OBSERVER_STATE_SYNC_EXECUTING` set to 1 indefinitely

## Notes

The vulnerability stems from the design decision to skip signature verification for future epoch commit decisions because the observer lacks the validator set for future epochs. However, this creates an exploitable gap where unverified messages can manipulate observer state sync behavior. The fix requires implementing epoch change proof validation as a prerequisite for accepting future epoch commits, ensuring cryptographic validation occurs before any state sync operations.

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

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L190-201)
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
```

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L218-231)
```rust
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
```

**File:** consensus/src/state_computer.rs (L177-194)
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
```

**File:** consensus/src/state_computer.rs (L216-219)
```rust
        let result = monitor!(
            "sync_to_target",
            self.state_sync_notifier.sync_to_target(target).await
        );
```

**File:** state-sync/state-sync-driver/src/notification_handlers.rs (L262-318)
```rust
    pub async fn initialize_sync_target_request(
        &mut self,
        sync_target_notification: ConsensusSyncTargetNotification,
        latest_pre_committed_version: Version,
        latest_synced_ledger_info: LedgerInfoWithSignatures,
    ) -> Result<(), Error> {
        // Get the target sync version and latest committed version
        let sync_target_version = sync_target_notification
            .get_target()
            .ledger_info()
            .version();
        let latest_committed_version = latest_synced_ledger_info.ledger_info().version();

        // If the target version is old, return an error to consensus (something is wrong!)
        if sync_target_version < latest_committed_version
            || sync_target_version < latest_pre_committed_version
        {
            let error = Err(Error::OldSyncRequest(
                sync_target_version,
                latest_pre_committed_version,
                latest_committed_version,
            ));
            self.respond_to_sync_target_notification(sync_target_notification, error.clone())?;
            return error;
        }

        // If the committed version is at the target, return successfully
        if sync_target_version == latest_committed_version {
            info!(
                LogSchema::new(LogEntry::NotificationHandler).message(&format!(
                    "We're already at the requested sync target version: {} \
                (pre-committed version: {}, committed version: {})!",
                    sync_target_version, latest_pre_committed_version, latest_committed_version
                ))
            );
            let result = Ok(());
            self.respond_to_sync_target_notification(sync_target_notification, result.clone())?;
            return result;
        }

        // If the pre-committed version is already at the target, something has else gone wrong
        if sync_target_version == latest_pre_committed_version {
            let error = Err(Error::InvalidSyncRequest(
                sync_target_version,
                latest_pre_committed_version,
            ));
            self.respond_to_sync_target_notification(sync_target_notification, error.clone())?;
            return error;
        }

        // Save the request so we can notify consensus once we've hit the target
        let consensus_sync_request =
            ConsensusSyncRequest::new_with_target(sync_target_notification);
        self.consensus_sync_request = Arc::new(Mutex::new(Some(consensus_sync_request)));

        Ok(())
    }
```

# Audit Report

## Title
Unvalidated Commit Proofs for Future Epochs Enable Consensus Observer State Corruption and Divergence

## Summary
The consensus observer fails to validate commit proofs for future epochs before updating its internal state. An attacker can send a `CommitDecision` message with a future epoch number and forged commit proof, causing the observer to update its root ledger info to the unverified proof, creating a state inconsistency that can lead to consensus divergence between observer nodes.

## Finding Description

The vulnerability exists in the consensus observer's commit decision processing logic. When a `CommitDecision` message is received for a future epoch, the code skips all cryptographic verification but still updates the observer's internal state to the unverified commit proof.

**Critical Flow:**

1. The consensus observer receives a `CommitDecision` message with epoch E+1 (future epoch)

2. At the validation checkpoint, the code only validates commit proofs for the current epoch: [1](#0-0) 

3. For future epochs, validation is completely bypassed, and the code proceeds to state sync preparation

4. The TODO comment explicitly acknowledges this is an unresolved issue: [2](#0-1) 

5. The observer then updates its root to the **unverified** commit proof BEFORE state sync completes: [3](#0-2) 

6. The `update_blocks_for_state_sync_commit` function directly updates the root to the forged commit proof: [4](#0-3) 

7. The unverified commit proof is passed to state sync without any signature validation: [5](#0-4) 

8. State sync's notification handler only checks version numbers, not cryptographic signatures: [6](#0-5) 

9. State sync satisfaction check only compares versions, not state roots: [7](#0-6) 

**Attack Scenario:**

1. Attacker observes current epoch E = 100
2. Attacker crafts malicious `CommitDecision`:
   - `epoch = 101` (future epoch)
   - `commit_proof` with forged BLS signatures (not validated)
   - Arbitrary `BlockInfo` with attacker-chosen state root
3. Attacker sends message to consensus observer nodes
4. Observer skips validation (line 468 check fails: 101 ≠ 100)
5. Observer updates its root to forged commit proof (line 522)
6. State sync syncs to correct state via valid proofs from honest peers
7. Observer's root now contains forged data while storage contains correct data
8. Different observers receiving different forged proofs diverge in their view of blockchain state

This breaks **Consensus Safety** as observers can have conflicting views of the committed blockchain state, and violates **State Consistency** as the observer's root doesn't match actual storage state.

## Impact Explanation

**Critical Severity** - This vulnerability enables:

1. **Consensus Divergence**: Different observer nodes can be fed different forged commit proofs for the same epoch/round, causing them to have inconsistent views of the blockchain state. While state sync retrieves correct transaction data, the observer's root metadata (state root, timestamps, epoch info) becomes corrupted with attacker-chosen values.

2. **State Inconsistency**: The observer's root ledger info contains unverified forged data while the actual storage contains the correct validated state. This mismatch can cause the observer to:
   - Reject valid blocks that don't match the forged root
   - Process ordered blocks incorrectly due to mismatched epoch states
   - Forward incorrect commit decisions to the execution pipeline

3. **Observer Network Partition**: Multiple observers with different forged roots for the same epoch/round cannot agree on block validation, effectively partitioning the observer network. This degrades the robustness of the consensus observer feature.

This qualifies for **Critical Severity** under the Aptos Bug Bounty program's "Consensus/Safety violations" category, as it allows an attacker to cause different nodes to have divergent views of blockchain state without requiring any validator compromise.

## Likelihood Explanation

**High Likelihood** - The vulnerability is easily exploitable:

1. **No Authentication**: Any network peer can send `CommitDecision` messages via the consensus observer protocol without authentication
2. **Deterministic Bypass**: The validation check at line 468 deterministically fails for future epochs, guaranteeing the bypass
3. **Simple Exploitation**: Attacker only needs to set `epoch = current_epoch + 1` with any forged commit proof
4. **No Resources Required**: Attack requires no stake, validator access, or computational resources beyond crafting and sending network messages
5. **Wide Attack Surface**: All nodes running consensus observer are vulnerable
6. **Acknowledged Issue**: The TODO comment indicates developers are aware this is problematic but haven't implemented proper handling

## Recommendation

Implement cryptographic validation for future epoch commit proofs before updating observer state:

```rust
// In process_commit_decision_message, before line 500:
if commit_epoch > epoch_state.epoch {
    // For future epochs, we cannot verify the commit proof yet
    // as we don't have the validator set for that epoch.
    // Log the commit decision but do NOT update state until
    // the epoch transition is confirmed via reconfig events.
    info!(
        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
            "Received commit decision for future epoch {}. Deferring until epoch transition.",
            commit_epoch
        ))
    );
    return;
}
```

Alternative approach: Buffer future epoch commit decisions and only process them after the epoch state is updated via reconfig notifications, at which point the commit proof can be properly validated against the new epoch's validator set.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Creating a forged `CommitDecision` with epoch = current_epoch + 1 and invalid BLS signatures
2. Sending it to a consensus observer node via the network protocol
3. Observing that the observer's `root()` is updated to the forged commit proof (verifiable via logs/metrics)
4. Confirming that no signature validation occurred by checking that the forged signatures were never verified
5. Demonstrating state inconsistency between observer root and actual storage after state sync completes

The core issue is demonstrated by the test case at lines 679-727 in block_data.rs, which shows that `update_blocks_for_state_sync_commit` updates the root without any validation, and this is called before state sync with unverified future epoch commit decisions.

---

**Notes**

This vulnerability represents a critical flaw in the consensus observer's security model. While state sync itself will sync to the correct state using validated transaction proofs from honest peers, the observer's root metadata becomes corrupted with attacker-controlled values. This creates a dangerous state inconsistency where different observers can be manipulated to have different views of the blockchain state, undermining the consensus observer feature's reliability and potentially causing network fragmentation among observer nodes.

The explicit TODO comment indicates this is a known design gap that requires proper resolution with epoch state validation before processing future epoch commit decisions.

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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L497-498)
```rust
        // TODO: identify the best way to handle an invalid commit decision
        // for a future epoch. In such cases, we currently rely on state sync.
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L518-527)
```rust
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

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L218-222)
```rust
                // Sync to the commit decision
                if let Err(error) = execution_client
                    .clone()
                    .sync_to_target(commit_decision.commit_proof().clone())
                    .await
```

**File:** state-sync/state-sync-driver/src/notification_handlers.rs (L198-206)
```rust
            ConsensusSyncRequest::SyncTarget(sync_target_notification) => {
                // Get the sync target version and latest synced version
                let sync_target = sync_target_notification.get_target();
                let sync_target_version = sync_target.ledger_info().version();
                let latest_synced_version = latest_synced_ledger_info.ledger_info().version();

                // Check if we've satisfied the target
                latest_synced_version >= sync_target_version
            },
```

**File:** state-sync/state-sync-driver/src/notification_handlers.rs (L261-318)
```rust
    /// Initializes the sync target request received from consensus
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

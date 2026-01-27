# Audit Report

## Title
Consensus Observer Denial of Service via Unverified Future-Epoch CommitDecision

## Summary
The consensus observer accepts CommitDecision messages for future epochs without signature verification, allowing an attacker to manipulate the observer's root state and cause it to reject all legitimate blocks, resulting in a consensus liveness failure.

## Finding Description
The vulnerability exists in the `process_commit_decision_message` function where CommitDecision messages for future epochs bypass cryptographic verification but still update the observer's internal state. [1](#0-0) 

When a CommitDecision arrives with `commit_epoch > current_epoch`, the code flow is:

1. **Line 457**: Checks if commit is behind highest committed block - passes for future epochs
2. **Line 468**: Checks if `commit_epoch == epoch_state.epoch` - **fails** for future epochs, so signature verification is **skipped**
3. **Line 504**: Checks if epoch changed or round increased - **passes** for future epochs  
4. **Lines 520-522**: Calls `update_blocks_for_state_sync_commit` which updates the root to the unverified commit proof [2](#0-1) 

The `update_blocks_for_state_sync_commit` function directly updates the root without any validation: [3](#0-2) 

Once the root is updated to the fake future-epoch commit, `get_highest_committed_epoch_round()` returns this fake epoch/round: [4](#0-3) 

This causes all subsequent legitimate blocks and commits to be rejected as "out of date" at:
- **Line 457** for CommitDecisions
- **Line 679-680** for OrderedBlocks  
- **Line 369** for BlockPayloads [5](#0-4) [6](#0-5) [7](#0-6) 

## Impact Explanation
This is a **High Severity** vulnerability per the Aptos bug bounty program as it causes "Validator node slowdowns" and "Significant protocol violations":

- **Consensus Liveness Failure**: The observer becomes unable to process legitimate blocks, effectively losing consensus synchronization
- **Permanent Stall**: The observer remains stuck until state sync completes (which may never succeed for non-existent commits) or manual intervention occurs
- **Network-Wide Impact**: If multiple observers are attacked simultaneously, network observability and redundancy are severely degraded

The attack requires only a single malicious message from a subscribed peer, which could be a compromised fullnode or validator.

## Likelihood Explanation
**Likelihood: Medium to High**

**Attack Requirements:**
- Attacker must be a subscribed peer (validator or fullnode connected to the observer)
- Attacker can craft a single CommitDecision message with arbitrary future epoch/round
- No cryptographic material or validator signatures required

**Feasibility:**
- Any compromised node in the network can execute this attack
- The attack is trivial to execute - just send one malformed message
- Detection is difficult as the observer will appear to be "waiting for state sync"

## Recommendation
Add signature verification for CommitDecisions regardless of epoch, or reject CommitDecisions from future epochs entirely:

```rust
// In process_commit_decision_message, replace lines 466-495 with:
let epoch_state = self.get_epoch_state();

// Always verify the commit proof, even for future epochs
if let Err(error) = commit_decision.verify_commit_proof(&epoch_state) {
    // For current epoch, this is an error
    if commit_epoch == epoch_state.epoch {
        error!(LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
            "Failed to verify commit decision! Ignoring: {:?}, from peer: {:?}. Error: {:?}",
            commit_decision.proof_block_info(), peer_network_id, error
        )));
        increment_invalid_message_counter(&peer_network_id, metrics::COMMIT_DECISION_LABEL);
        return;
    }
    
    // For future epochs, we cannot verify yet, so reject them
    warn!(LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
        "Received unverifiable commit decision for future epoch: {:?}. Ignoring!",
        commit_decision.proof_block_info()
    )));
    return;
}
```

Alternatively, ensure that `update_blocks_for_state_sync_commit` validates the commit proof before updating the root, or add epoch bounds checking to prevent accepting commits too far in the future.

## Proof of Concept
```rust
// Test demonstrating the vulnerability
#[tokio::test]
async fn test_future_epoch_commit_dos() {
    // Setup observer at epoch 1, round 50
    let mut observer = create_test_observer(/* epoch */ 1, /* round */ 50);
    
    // Attacker sends CommitDecision for future epoch 5, round 1000
    let malicious_commit = CommitDecision::new(
        create_fake_ledger_info(/* epoch */ 5, /* round */ 1000)
    );
    
    // Process the malicious commit - it bypasses signature verification
    observer.process_commit_decision_message(
        test_peer_id(),
        Instant::now(),
        malicious_commit
    );
    
    // Verify the root was updated to the fake commit
    let root = observer.observer_block_data.lock().root();
    assert_eq!(root.commit_info().epoch(), 5);
    assert_eq!(root.commit_info().round(), 1000);
    
    // Now send a legitimate OrderedBlock for epoch 1, round 51
    let legitimate_block = create_legitimate_ordered_block(/* epoch */ 1, /* round */ 51);
    
    // Process it - should be rejected as "out of date"
    observer.process_ordered_block_message(
        test_peer_id(),
        Instant::now(),
        legitimate_block
    ).await;
    
    // Verify the block was not processed (rejected)
    assert!(observer.observer_block_data.lock()
        .get_ordered_block(1, 51).is_none());
    
    // Observer is now stuck and cannot process any blocks
}
```

**Notes**

The vulnerability stems from an incomplete implementation of future-epoch handling, as indicated by the TODO comment. The system assumes future-epoch commits will be validated through state sync, but the root update happens before state sync verification, creating a window for attack. This breaks the consensus safety invariant that all state transitions must be cryptographically verified before being accepted.

### Citations

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L367-373)
```rust
        let last_ordered_block = self.observer_block_data.lock().get_last_ordered_block();
        let payload_out_of_date =
            (block_epoch, block_round) <= (last_ordered_block.epoch(), last_ordered_block.round());
        let payload_exists = self
            .observer_block_data
            .lock()
            .existing_payload_entry(&block_payload);
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L441-528)
```rust
    /// Processes the commit decision message
    fn process_commit_decision_message(
        &mut self,
        peer_network_id: PeerNetworkId,
        message_received_time: Instant,
        commit_decision: CommitDecision,
    ) {
        // Get the commit decision epoch and round
        let commit_epoch = commit_decision.epoch();
        let commit_round = commit_decision.round();

        // If the commit message is behind our highest committed block, ignore it
        let get_highest_committed_epoch_round = self
            .observer_block_data
            .lock()
            .get_highest_committed_epoch_round();
        if (commit_epoch, commit_round) <= get_highest_committed_epoch_round {
            // Update the metrics for the dropped commit decision
            update_metrics_for_dropped_commit_decision_message(peer_network_id, &commit_decision);
            return;
        }

        // Update the metrics for the received commit decision
        update_metrics_for_commit_decision_message(peer_network_id, &commit_decision);

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
    }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L677-691)
```rust
        // Determine if the block is behind the last ordered block, or if it is already pending
        let last_ordered_block = self.observer_block_data.lock().get_last_ordered_block();
        let block_out_of_date =
            first_block_epoch_round <= (last_ordered_block.epoch(), last_ordered_block.round());
        let block_pending = self
            .observer_block_data
            .lock()
            .existing_pending_block(&ordered_block);

        // If the block is out of date or already pending, ignore it
        if block_out_of_date || block_pending {
            // Update the metrics for the dropped ordered block
            update_metrics_for_dropped_ordered_block_message(peer_network_id, &ordered_block);
            return;
        }
```

**File:** consensus/src/consensus_observer/observer/block_data.rs (L132-141)
```rust
    pub fn get_highest_committed_epoch_round(&self) -> (u64, Round) {
        if let Some(epoch_round) = self.ordered_block_store.get_highest_committed_epoch_round() {
            // Return the highest committed epoch and round
            epoch_round
        } else {
            // Return the root epoch and round
            let root_block_info = self.root.commit_info().clone();
            (root_block_info.epoch(), root_block_info.round())
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

**File:** consensus/src/consensus_observer/observer/block_data.rs (L300-302)
```rust
    pub fn update_root(&mut self, new_root: LedgerInfoWithSignatures) {
        self.root = new_root;
    }
```

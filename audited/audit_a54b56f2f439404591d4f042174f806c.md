# Audit Report

## Title
Unverified Future-Epoch Commit Decisions Enable Payload Store Corruption in Consensus Observer

## Summary
Byzantine validators can send unverified `CommitDecision` messages for future epochs to honest consensus observers, causing premature removal of all stored block payloads and resulting in loss of liveness. The vulnerability exists because commit decisions for future epochs bypass signature verification but still trigger payload deletion.

## Finding Description

The security question asks about `remove_committed_blocks()` at line 122, but this function is **only used in test code**. However, the underlying vulnerability exists in production through `remove_blocks_for_epoch_round()`, which is called when processing commit decisions from network peers. [1](#0-0) 

The attack path involves the `process_commit_decision_message()` function in the consensus observer: [2](#0-1) 

**Critical vulnerability:** When a commit decision is received for a **future epoch** (not the current epoch), the code skips cryptographic verification but still processes the commit:

1. **Lines 468-495**: Verification only happens if `commit_epoch == epoch_state.epoch`. For future epochs, this check fails and verification is skipped entirely.

2. **Lines 497-498**: A TODO comment acknowledges this limitation but provides no protection.

3. **Lines 500-527**: If the commit is ahead of the current block, the code calls `update_blocks_for_state_sync_commit()` **without any signature verification**. [3](#0-2) 

The `update_blocks_for_state_sync_commit()` function removes all blocks up to the specified epoch/round from the payload store, regardless of whether the commit decision is valid.

**Attack Scenario:**
1. Honest observer subscribes to a Byzantine validator (part of active validator set)
2. Byzantine validator crafts a `CommitDecision` with epoch = N+1, round = 999999999, with invalid/empty signatures
3. Honest observer receives the message and processes it:
   - Passes subscription verification (message from active peer)
   - **Skips signature verification** (future epoch)
   - Calls `update_blocks_for_state_sync_commit()`
   - **Removes ALL payloads** from the store (all blocks < epoch N+1)
4. Observer attempts state sync to non-existent target, which fails
5. Observer is stuck with no payloads and failed state sync—**loss of liveness** [4](#0-3) 

The subscription verification only checks if the peer is subscribed, not whether the data is valid.

## Impact Explanation

**Severity: HIGH** (per Aptos bug bounty criteria: "Validator node slowdowns" / "Significant protocol violations")

This vulnerability causes:
- **Complete loss of liveness** for the affected consensus observer node
- **Denial of service** - observer cannot process new blocks without stored payloads
- **State corruption** - observer's payload store is emptied based on unverified data
- **Manual intervention required** for recovery (restart/resync)

The impact is limited to consensus observer nodes (not full validators), which reduces severity from Critical to High. However, observers play an important role in the Aptos network architecture, and their compromise affects network reliability.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

Requirements for exploitation:
- Attacker must be a validator that honest observers subscribe to
- Observers typically subscribe to multiple validators for redundancy
- No detection mechanism for this attack exists in the code
- Attack is trivial once subscription is established (single malicious message)

The attack is **easily exploitable** once the attacker is in the subscription list. The only barrier is that the attacker needs to be part of the active validator set that observers choose to subscribe to, which is plausible for Byzantine validators under the <1/3 adversarial assumption.

## Recommendation

**Fix: Verify commit decisions for ALL epochs before processing, not just the current epoch.**

Add signature verification for future epoch commit decisions before calling `update_blocks_for_state_sync_commit()`:

```rust
// In process_commit_decision_message(), after line 495:
// For future epochs, we must still verify signatures before trusting the commit
if commit_epoch > epoch_state.epoch {
    // Cannot verify future epoch with current epoch state
    // Log and reject the commit decision
    warn!(
        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
            "Cannot verify commit decision for future epoch {:?} (current: {:?}). Rejecting: {:?}",
            commit_epoch, epoch_state.epoch, commit_decision.proof_block_info()
        ))
    );
    increment_invalid_message_counter(&peer_network_id, metrics::COMMIT_DECISION_LABEL);
    return;
}

// For commits ahead in current epoch, verify before processing
if commit_round > last_block.round() {
    if let Err(error) = commit_decision.verify_commit_proof(&epoch_state) {
        error!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Failed to verify commit decision for future round! Ignoring: {:?}, Error: {:?}",
                commit_decision.proof_block_info(), error
            ))
        );
        increment_invalid_message_counter(&peer_network_id, metrics::COMMIT_DECISION_LABEL);
        return;
    }
}
```

**Alternative approach**: Only accept commit decisions for the current epoch, and rely on epoch transition mechanisms for advancing epochs rather than processing unverified future-epoch commits.

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_types::{
        aggregate_signature::AggregateSignature,
        block_info::BlockInfo,
        ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
    };

    #[test]
    fn test_byzantine_future_epoch_commit_removes_payloads() {
        // Setup: Create observer with current epoch 0
        let consensus_observer_config = ConsensusObserverConfig::default();
        let mut observer_block_data = ObserverBlockData::new_with_root(
            consensus_observer_config,
            create_ledger_info(0, 5), // epoch 0, round 5
        );

        // Add payloads for current epoch
        let num_blocks = 10;
        for i in 0..num_blocks {
            let block_info = BlockInfo::random_with_epoch(0, i);
            let block_payload = BlockPayload::new(
                block_info,
                BlockTransactionPayload::empty(),
            );
            observer_block_data.insert_block_payload(block_payload, true);
        }

        // Verify payloads exist
        assert_eq!(observer_block_data.get_block_payloads().lock().len(), num_blocks);

        // Attack: Byzantine validator sends commit decision for future epoch
        // with no valid signatures (empty signature)
        let byzantine_commit = CommitDecision::new(LedgerInfoWithSignatures::new(
            LedgerInfo::new(
                BlockInfo::random_with_epoch(100, 999999), // future epoch, high round
                HashValue::random(),
            ),
            AggregateSignature::empty(), // No valid signatures!
        ));

        // Process the Byzantine commit decision (simulating network message handling)
        // This would normally go through process_commit_decision_message()
        // which calls update_blocks_for_state_sync_commit() without verification
        observer_block_data.update_blocks_for_state_sync_commit(&byzantine_commit);

        // Verify: ALL payloads have been removed!
        assert_eq!(
            observer_block_data.get_block_payloads().lock().len(),
            0,
            "Byzantine commit decision caused all payloads to be removed without verification!"
        );

        // Observer is now in broken state:
        // - No payloads
        // - Root set to invalid commit
        // - Cannot process new blocks
    }
}
```

## Notes

1. The question specifically mentions `remove_committed_blocks()` which is test-only, but the vulnerability exists in production via `remove_blocks_for_epoch_round()`.

2. The TODO comment at line 497-498 suggests developers are aware that future epoch commits aren't handled well, but the current implementation creates a security vulnerability.

3. This affects consensus observer nodes specifically, which are observer-only nodes that don't participate in consensus but follow committed blocks.

4. The vulnerability requires the attacker to be in the observer's subscription list, but this is plausible for any validator in the active set.

### Citations

**File:** consensus/src/consensus_observer/observer/payload_store.rs (L121-130)
```rust
    /// Removes the committed blocks from the payload store
    pub fn remove_committed_blocks(&self, committed_blocks: &[Arc<PipelinedBlock>]) {
        // Get the highest epoch and round for the committed blocks
        let (highest_epoch, highest_round) = committed_blocks
            .last()
            .map_or((0, 0), |block| (block.epoch(), block.round()));

        // Remove the blocks
        self.remove_blocks_for_epoch_round(highest_epoch, highest_round);
    }
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

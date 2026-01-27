# Audit Report

## Title
Consensus Observer Block Store Manipulation via Unverified Future Epoch Commit Decisions

## Summary
A malicious subscribed peer can send commit decisions with crafted epoch/round values for future epochs, bypassing signature verification and causing the consensus observer to incorrectly remove all pending blocks or retain blocks that should be removed. This violates the consensus observer's state integrity and can lead to liveness failures.

## Finding Description

The vulnerability exists in how the consensus observer processes commit decisions for future epochs. The attack flow is:

1. **Verification Bypass**: When a `CommitDecision` message is received, verification only occurs if the commit epoch matches the current epoch. [1](#0-0) 

2. **Unverified Processing**: For future epoch commits, the code skips verification and proceeds to call `update_blocks_for_state_sync_commit()` with the unverified commit decision. [2](#0-1) 

3. **Dangerous Block Removal**: The `remove_blocks_for_commit()` function uses `BTreeMap::split_off()` with epoch/round values directly from the unverified commit, without bounds checking. [3](#0-2) 

**Attack Scenario A - Remove ALL blocks:**
- Attacker sends `CommitDecision` with `epoch = u64::MAX, round = u64::MAX`
- `split_off(&(u64::MAX, u64::MAX))` returns empty map (no blocks have epoch/round >= u64::MAX)
- Assignment at line 118-120 replaces `ordered_blocks` with empty map
- All pending blocks are lost

**Attack Scenario B - Remove NO blocks:**
- Attacker sends `CommitDecision` with `epoch = 0, round = 0`
- `split_off(&(0, 1))` returns all blocks (all blocks have keys >= (0,1) typically)
- Blocks that should be removed remain in the store
- Memory accumulation, eventual hitting of `max_num_pending_blocks` limit

The code even acknowledges this issue with a TODO comment: "identify the best way to handle an invalid commit decision for a future epoch." [4](#0-3) 

## Impact Explanation

**Severity: High** (Validator node slowdowns, Significant protocol violations)

The vulnerability causes:

1. **Liveness Impact**: Removing all pending blocks disrupts the execution pipeline, preventing the observer from processing legitimate consensus progress until state sync completes.

2. **State Inconsistency**: The consensus observer's internal state becomes inconsistent with actual consensus progress, violating state management invariants.

3. **Resource Exhaustion**: Scenario B (removing no blocks) leads to memory accumulation as old blocks persist, eventually hitting limits and causing new blocks to be dropped. [5](#0-4) 

4. **Root Ledger Info Corruption**: The function also updates the root ledger info with unverified data, potentially corrupting the node's view of committed state. [6](#0-5) 

While this doesn't directly cause fund loss, it significantly degrades observer node functionality and can cascade into broader network observability issues.

## Likelihood Explanation

**Likelihood: Medium-High**

Requirements for exploitation:
- Attacker must be an active subscription peer (typically a validator or publisher)
- Consensus observer must be running (enabled on non-validator full nodes)
- No special timing or race conditions required

The attack is straightforward to execute and requires no sophisticated techniques beyond network access as a subscribed peer. The verification bypass is deterministic and always occurs for future epoch commits.

## Recommendation

Add validation for future epoch commit decisions before processing them:

```rust
fn process_commit_decision_message(
    &mut self,
    peer_network_id: PeerNetworkId,
    message_received_time: Instant,
    commit_decision: CommitDecision,
) {
    let commit_epoch = commit_decision.epoch();
    let commit_round = commit_decision.round();
    
    // Check if commit is behind highest committed block
    let highest_committed = self.observer_block_data.lock().get_highest_committed_epoch_round();
    if (commit_epoch, commit_round) <= highest_committed {
        update_metrics_for_dropped_commit_decision_message(peer_network_id, &commit_decision);
        return;
    }
    
    let epoch_state = self.get_epoch_state();
    if commit_epoch == epoch_state.epoch {
        // Current epoch - verify as before
        if let Err(error) = commit_decision.verify_commit_proof(&epoch_state) {
            error!(...);
            return;
        }
        if self.process_commit_decision_for_pending_block(&commit_decision) {
            return;
        }
    }
    
    // NEW: Validate future epoch commits before processing
    let last_block = self.observer_block_data.lock().get_last_ordered_block();
    let epoch_changed = commit_epoch > last_block.epoch();
    
    // Only allow reasonable epoch jumps (e.g., +1 or +2 epochs)
    if epoch_changed && commit_epoch > last_block.epoch() + 2 {
        warn!("Rejecting commit decision with unreasonable future epoch: {} (current: {})",
              commit_epoch, last_block.epoch());
        increment_invalid_message_counter(&peer_network_id, metrics::COMMIT_DECISION_LABEL);
        return;
    }
    
    // Only allow reasonable round jumps within same epoch
    if !epoch_changed && commit_round > last_block.round() + 1000 {
        warn!("Rejecting commit decision with unreasonable future round: {} (current: {})",
              commit_round, last_block.round());
        increment_invalid_message_counter(&peer_network_id, metrics::COMMIT_DECISION_LABEL);
        return;
    }
    
    // Proceed with state sync for validated future commits
    if epoch_changed || commit_round > last_block.round() {
        if self.state_sync_manager.is_syncing_through_epoch() {
            return;
        }
        self.observer_block_data.lock().update_blocks_for_state_sync_commit(&commit_decision);
        self.state_sync_manager.sync_to_commit(commit_decision, epoch_changed);
    }
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod test_vulnerability {
    use super::*;
    use aptos_types::{
        aggregate_signature::AggregateSignature,
        block_info::BlockInfo, 
        ledger_info::LedgerInfo,
    };
    use aptos_crypto::HashValue;
    
    #[test]
    fn test_unverified_commit_removes_all_blocks() {
        // Setup: Create ordered block store with legitimate blocks
        let mut ordered_block_store = OrderedBlockStore::new(
            ConsensusObserverConfig::default()
        );
        
        // Add 10 legitimate blocks at epoch 5, rounds 0-9
        let current_epoch = 5u64;
        for round in 0..10 {
            let block_info = BlockInfo::new(
                current_epoch,
                round,
                HashValue::random(),
                HashValue::random(),
                round as u64,
                round as u64,
                None,
            );
            let block = create_pipelined_block_from_info(block_info);
            let ordered_block = OrderedBlock::new(
                vec![block],
                create_ledger_info(current_epoch, round),
            );
            let observed = ObservedOrderedBlock::new_for_testing(ordered_block);
            ordered_block_store.insert_ordered_block(observed);
        }
        
        // Verify blocks are present
        assert_eq!(ordered_block_store.get_all_ordered_blocks().len(), 10);
        
        // ATTACK: Craft malicious commit with u64::MAX epoch
        let malicious_commit = LedgerInfoWithSignatures::new(
            LedgerInfo::new(
                BlockInfo::new(
                    u64::MAX,  // Malicious epoch
                    u64::MAX,  // Malicious round
                    HashValue::random(),
                    HashValue::random(),
                    0,
                    0,
                    None,
                ),
                HashValue::random(),
            ),
            AggregateSignature::empty(),
        );
        
        // Process the malicious commit (bypasses verification for future epoch)
        ordered_block_store.remove_blocks_for_commit(&malicious_commit);
        
        // VULNERABILITY: All blocks are removed!
        assert_eq!(
            ordered_block_store.get_all_ordered_blocks().len(), 
            0,
            "All blocks should be removed by malicious commit"
        );
        
        // Additional impact: root is updated to malicious values
        let highest_committed = ordered_block_store
            .get_highest_committed_epoch_round()
            .unwrap();
        assert_eq!(highest_committed.0, u64::MAX);
        assert_eq!(highest_committed.1, u64::MAX);
    }
}
```

## Notes

This vulnerability specifically affects consensus observer nodes (non-validator full nodes that observe consensus). The impact is scoped to observer node availability and state consistency rather than the core consensus protocol itself. However, it represents a significant protocol violation that can disrupt network observability infrastructure.

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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L497-498)
```rust
        // TODO: identify the best way to handle an invalid commit decision
        // for a future epoch. In such cases, we currently rely on state sync.
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L518-526)
```rust
            // Otherwise, we should start the state sync process for the commit.
            // Update the block data (to the commit decision).
            self.observer_block_data
                .lock()
                .update_blocks_for_state_sync_commit(&commit_decision);

            // Start state syncing to the commit decision
            self.state_sync_manager
                .sync_to_commit(commit_decision, epoch_changed);
```

**File:** consensus/src/consensus_observer/observer/ordered_blocks.rs (L77-88)
```rust
        // Verify that the number of ordered blocks doesn't exceed the maximum
        let max_num_ordered_blocks = self.consensus_observer_config.max_num_pending_blocks as usize;
        if self.ordered_blocks.len() >= max_num_ordered_blocks {
            warn!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Exceeded the maximum number of ordered blocks: {:?}. Dropping block: {:?}.",
                    max_num_ordered_blocks,
                    observed_ordered_block.ordered_block().proof_block_info()
                ))
            );
            return; // Drop the block if we've exceeded the maximum
        }
```

**File:** consensus/src/consensus_observer/observer/ordered_blocks.rs (L112-124)
```rust
    pub fn remove_blocks_for_commit(&mut self, commit_ledger_info: &LedgerInfoWithSignatures) {
        // Determine the epoch and round to split off
        let split_off_epoch = commit_ledger_info.ledger_info().epoch();
        let split_off_round = commit_ledger_info.commit_info().round().saturating_add(1);

        // Remove the blocks from the ordered blocks
        self.ordered_blocks = self
            .ordered_blocks
            .split_off(&(split_off_epoch, split_off_round));

        // Update the highest committed epoch and round
        self.update_highest_committed_epoch_round(commit_ledger_info);
    }
```

**File:** consensus/src/consensus_observer/observer/block_data.rs (L281-282)
```rust
        // Update the root
        self.update_root(commit_proof.clone());
```

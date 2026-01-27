# Audit Report

## Title
Inconsistent Validation in Consensus Observer Commit Decision Updates Allows State Tracking Corruption via TOCTOU Race

## Summary
The `update_ordered_block_commit_decision()` function does not validate that a block exists in `ordered_block_store` before updating the `highest_committed_epoch_round` state. Due to a Time-Of-Check-Time-Of-Use (TOCTOU) race condition between the existence check and the update operation, the system's highest committed round tracker can be advanced to point to blocks that were never stored or were removed, causing state inconsistency and potential denial of valid commit decisions.

## Finding Description
The vulnerability exists in the consensus observer's block data management system. The `update_ordered_block_commit_decision()` function in [1](#0-0)  delegates to `update_commit_decision()` without any validation.

In the underlying implementation [2](#0-1) , the function has inconsistent validation:
- It checks if a block exists before storing the commit decision in the `ordered_blocks` map (lines 133-138)
- However, it **unconditionally** calls `update_highest_committed_epoch_round()` regardless of whether the block exists (line 141)

This creates a TOCTOU race condition in the call site [3](#0-2) :

**Race Window:**
1. Thread A checks if block exists (acquires and releases mutex at lines 535-538)
2. Thread B removes the block via commit callback [4](#0-3) 
3. Thread A re-acquires mutex and calls `update_ordered_block_commit_decision()` (line 552)
4. Block no longer exists, so commit decision is NOT stored
5. BUT `highest_committed_epoch_round` is still updated to point to the non-existent block

**Broken Invariant:**
The system violates the **State Consistency** invariant - `highest_committed_epoch_round` should only point to blocks that exist in the ordered block store or have been properly committed. This tracker is used to filter future commit decisions [5](#0-4) , creating a compound effect where legitimate commits can be incorrectly rejected.

## Impact Explanation
**Medium Severity** - This constitutes a state inconsistency requiring intervention per the bug bounty criteria.

**Specific Impacts:**
1. **Liveness Degradation**: If `highest_committed_epoch_round` is corrupted to point to a non-existent block at a high round number, subsequent legitimate commit decisions with lower or equal rounds will be incorrectly dropped, preventing the node from progressing consensus
2. **State Tracking Corruption**: The consensus observer's internal view of the highest committed block becomes inconsistent with actual block storage
3. **Cross-Node Inconsistency**: Different observer nodes may have different values for `highest_committed_epoch_round` depending on race timing, causing divergent behavior

While this doesn't directly cause fund loss or consensus safety violations, it can require manual intervention to restore correct node operation and creates an availability risk for consensus observer nodes.

## Likelihood Explanation
**Medium-High Likelihood**

The vulnerability triggers under normal operational conditions without requiring attacker action:

1. **No Special Privileges Required**: The race occurs during standard message processing
2. **Common Trigger Condition**: The commit callback runs asynchronously whenever blocks are committed, creating frequent opportunities for the race
3. **Timing-Dependent**: The window is narrow (between mutex releases), but given the high message throughput in consensus systems, the race will eventually occur
4. **Network Amplification**: Out-of-order message delivery or delayed commit decisions increase the likelihood

The race is realistic because [6](#0-5)  shows `observer_block_data` is `Arc<Mutex<ObserverBlockData>>`, confirming that lock acquisition/release happens multiple times during the check-then-act sequence.

## Recommendation
Implement atomic validation within the critical section:

```rust
/// Updates the commit decision of the ordered block
pub fn update_ordered_block_commit_decision(&mut self, commit_decision: &CommitDecision) {
    // Only update if block exists to maintain consistency
    let block_exists = self.ordered_block_store
        .get_ordered_block(commit_decision.epoch(), commit_decision.round())
        .is_some();
    
    if block_exists {
        self.ordered_block_store
            .update_commit_decision(commit_decision);
    }
}
```

Alternatively, modify `update_commit_decision()` in `ordered_blocks.rs` to only update `highest_committed_epoch_round` when the block exists:

```rust
pub fn update_commit_decision(&mut self, commit_decision: &CommitDecision) {
    let commit_decision_epoch = commit_decision.epoch();
    let commit_decision_round = commit_decision.round();
    
    // Only update if block exists
    if let Some((_, existing_commit_decision)) = self
        .ordered_blocks
        .get_mut(&(commit_decision_epoch, commit_decision_round))
    {
        *existing_commit_decision = Some(commit_decision.clone());
        
        // Only update highest committed epoch/round if block exists
        self.update_highest_committed_epoch_round(commit_decision.commit_proof());
    }
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod race_condition_test {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[test]
    fn test_toctou_race_in_commit_decision_update() {
        // Setup observer block data
        let observer_block_data = Arc::new(Mutex::new(
            ObserverBlockData::new_with_root(
                ConsensusObserverConfig::default(),
                create_ledger_info(10, 5)
            )
        ));
        
        // Add a block at epoch 10, round 100
        let ordered_block = create_ordered_block(10, 100);
        observer_block_data.lock().insert_ordered_block(
            ObservedOrderedBlock::new_for_testing(ordered_block.clone())
        );
        
        // Create commit decision for the block
        let commit_decision = CommitDecision::new(
            create_ledger_info(10, 100)
        );
        
        // Setup race condition
        let barrier = Arc::new(Barrier::new(2));
        let data_clone = observer_block_data.clone();
        let barrier_clone = barrier.clone();
        
        // Thread 1: Check block exists, then update
        let t1 = thread::spawn(move || {
            let exists = data_clone.lock()
                .get_ordered_block(10, 100)
                .is_some();
            assert!(exists); // Block exists at check time
            
            barrier_clone.wait(); // Synchronize to ensure race
            
            // Update commit decision after block might be removed
            data_clone.lock()
                .update_ordered_block_commit_decision(&commit_decision);
        });
        
        // Thread 2: Remove the block (simulate commit callback)
        let data_clone2 = observer_block_data.clone();
        let t2 = thread::spawn(move || {
            barrier.wait(); // Synchronize to ensure race
            
            // Remove block as if it was committed
            let commit_info = create_ledger_info(10, 100);
            data_clone2.lock().ordered_block_store
                .remove_blocks_for_commit(&commit_info);
        });
        
        t1.join().unwrap();
        t2.join().unwrap();
        
        // Verify the race condition result:
        // Block should be removed
        let data = observer_block_data.lock();
        assert!(data.get_ordered_block(10, 100).is_none());
        
        // But highest_committed_epoch_round should still be updated!
        let (epoch, round) = data.get_highest_committed_epoch_round();
        assert_eq!(epoch, 10);
        assert_eq!(round, 100);
        
        // This demonstrates the inconsistency: highest committed points
        // to a block that doesn't exist in ordered_block_store
    }
}
```

**Notes**

The vulnerability stems from the separation of concerns between validation and state updates. The `highest_committed_epoch_round` field serves as a critical filter for future commit decisions, but its update lacks proper atomicity with block existence checks. The TOCTOU window is real and exploitable under normal network conditions where commit callbacks and message processing occur concurrently. While the consensus observer is designed to handle out-of-order messages, the inconsistent state tracking can lead to operational issues requiring manual intervention.

### Citations

**File:** consensus/src/consensus_observer/observer/block_data.rs (L182-189)
```rust
    fn handle_committed_blocks(&mut self, ledger_info: LedgerInfoWithSignatures) {
        // Remove the committed blocks from the payload and ordered block stores
        self.block_payload_store.remove_blocks_for_epoch_round(
            ledger_info.commit_info().epoch(),
            ledger_info.commit_info().round(),
        );
        self.ordered_block_store
            .remove_blocks_for_commit(&ledger_info);
```

**File:** consensus/src/consensus_observer/observer/block_data.rs (L294-297)
```rust
    pub fn update_ordered_block_commit_decision(&mut self, commit_decision: &CommitDecision) {
        self.ordered_block_store
            .update_commit_decision(commit_decision);
    }
```

**File:** consensus/src/consensus_observer/observer/ordered_blocks.rs (L126-142)
```rust
    /// Updates the commit decision of the ordered block (if found)
    pub fn update_commit_decision(&mut self, commit_decision: &CommitDecision) {
        // Get the epoch and round of the commit decision
        let commit_decision_epoch = commit_decision.epoch();
        let commit_decision_round = commit_decision.round();

        // Update the commit decision for the ordered blocks
        if let Some((_, existing_commit_decision)) = self
            .ordered_blocks
            .get_mut(&(commit_decision_epoch, commit_decision_round))
        {
            *existing_commit_decision = Some(commit_decision.clone());
        }

        // Update the highest committed epoch and round
        self.update_highest_committed_epoch_round(commit_decision.commit_proof());
    }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L75-75)
```rust
    observer_block_data: Arc<Mutex<ObserverBlockData>>,
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L453-461)
```rust
        let get_highest_committed_epoch_round = self
            .observer_block_data
            .lock()
            .get_highest_committed_epoch_round();
        if (commit_epoch, commit_round) <= get_highest_committed_epoch_round {
            // Update the metrics for the dropped commit decision
            update_metrics_for_dropped_commit_decision_message(peer_network_id, &commit_decision);
            return;
        }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L535-552)
```rust
        let pending_block = self
            .observer_block_data
            .lock()
            .get_ordered_block(commit_decision.epoch(), commit_decision.round());

        // Process the pending block
        if let Some(pending_block) = pending_block {
            // If all payloads exist, add the commit decision to the pending blocks
            if self.all_payloads_exist(pending_block.blocks()) {
                debug!(
                    LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                        "Adding decision to pending block: {}",
                        commit_decision.proof_block_info()
                    ))
                );
                self.observer_block_data
                    .lock()
                    .update_ordered_block_commit_decision(commit_decision);
```

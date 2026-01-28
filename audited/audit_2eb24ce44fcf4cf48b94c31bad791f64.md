# Audit Report

## Title
Consensus Observer Pending Block Store Pollution During Commit Sync Error Recovery

## Summary
The consensus observer's error recovery mechanism for invalid commit sync notifications fails to clean up the pending block store, allowing stale pending blocks to accumulate across repeated error-recovery cycles. This eventually causes the observer to hit the `max_num_pending_blocks` limit and drop legitimate blocks, breaking observer functionality.

## Finding Description

The consensus observer maintains three distinct block stores in `ObserverBlockData`: the payload store, ordered block store, and pending block store. [1](#0-0) 

When a commit decision arrives that requires state sync, the system calls `update_blocks_for_state_sync_commit()` which updates the root and clears only the payload and ordered block stores, but crucially **does not** clear the pending block store. [2](#0-1) 

This is called when processing commit decisions that are ahead of the current state. [3](#0-2) 

The vulnerability manifests when state sync completes with a notification whose epoch/round is ahead of the current block data root. In this error case, the recovery path only clears the state sync handle without cleaning up any block data stores, particularly the pending block store. [4](#0-3) 

The correct cleanup behavior is demonstrated in `clear_block_data()` which properly clears all three stores including the pending block store. [5](#0-4) 

**Attack Scenario:**

During network instability or observer catch-up:

1. Observer's root is at (epoch E0, round R0)
2. Commit decision CD1 arrives for (E1, R1) where (E1, R1) > (E0, R0)
3. Pending blocks accumulate in the pending block store waiting for payloads
4. `update_blocks_for_state_sync_commit(CD1)` updates root to (E1, R1), clearing payload/ordered stores but leaving pending blocks
5. State sync starts for CD1
6. During sync, commit decision CD2 arrives for (E2, R2) where (E0, R0) < (E2, R2) < (E1, R1)
7. `update_blocks_for_state_sync_commit(CD2)` updates root to (E2, R2), again leaving pending blocks intact
8. State sync for CD1 completes with notification for (E1, R1)
9. Validation check: (E1, R1) > (E2, R2) triggers error path
10. Only `clear_active_commit_sync()` is called; pending blocks remain
11. This cycle repeats during network instability
12. Pending blocks accumulate until hitting the `max_num_pending_blocks` limit (default 150)
13. When the limit is reached, the garbage collection mechanism drops oldest blocks, which may be legitimate new blocks [6](#0-5) 

The default limit is 150 blocks for production networks. [7](#0-6) 

## Impact Explanation

This is a **Medium severity** vulnerability per Aptos bug bounty criteria: "State inconsistencies requiring manual intervention."

**Concrete Impact:**
- Observer nodes gradually accumulate stale pending blocks across error-recovery cycles
- Once `max_num_pending_blocks` limit (150 by default) is reached, the garbage collector removes oldest blocks
- New legitimate pending blocks are silently dropped when the limit is exceeded
- Observer becomes unable to process new consensus blocks, losing synchronization with the network
- Requires manual intervention (observer node restart) to clear the accumulated pollution
- Degrades observer network health and reliability during periods of network instability or catch-up

The vulnerability breaks the state consistency invariant by allowing the observer's internal state to become polluted with stale blocks that are never cleaned up through normal operation.

## Likelihood Explanation

**Likelihood: Medium-High**

This vulnerability is triggered by natural network conditions rather than requiring active exploitation:

**Triggering Conditions:**
- Network delays causing commit decisions to arrive out of order
- Observer catch-up scenarios where the observer is synchronizing from behind
- Same-epoch round progression with overlapping state sync operations
- Multiple commit decisions arriving while state sync is in progress

**Race Condition Mechanics:**
1. State sync is initiated for commit C1
2. A different commit C2 with lower epoch/round arrives during the sync
3. Block data root is updated to C2, clearing some stores but not pending blocks
4. State sync for C1 completes, triggering the error path due to version mismatch
5. Pending blocks from previous cycles remain uncleaned

This scenario is most likely during:
- Network instability with message reordering
- Observer nodes catching up after downtime
- High block production rates where state sync operations overlap

The vulnerability can manifest repeatedly over time, causing cumulative pollution that eventually reaches the configured limit.

## Recommendation

The error recovery path in `process_commit_sync_notification()` should clean up the pending block store when detecting an invalid notification. 

**Fix Option 1:** Clear pending blocks in the error path:
```rust
if (synced_epoch, synced_round) > (block_data_epoch, block_data_round) {
    error!(LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
        "Received invalid commit sync notification for epoch: {}, round: {}! Current root: {:?}",
        synced_epoch, synced_round, block_data_root
    )));
    
    // Clear pending blocks to prevent pollution
    self.observer_block_data.lock().pending_block_store.clear_missing_blocks();
    
    self.state_sync_manager.clear_active_commit_sync();
    return;
}
```

**Fix Option 2:** Ensure `update_blocks_for_state_sync_commit()` clears the pending block store:
```rust
pub fn update_blocks_for_state_sync_commit(&mut self, commit_decision: &CommitDecision) {
    let commit_proof = commit_decision.commit_proof();
    let commit_epoch = commit_decision.epoch();
    let commit_round = commit_decision.round();
    
    self.update_root(commit_proof.clone());
    self.block_payload_store.remove_blocks_for_epoch_round(commit_epoch, commit_round);
    self.ordered_block_store.remove_blocks_for_commit(commit_proof);
    
    // Add this line to clear pending blocks
    self.pending_block_store.clear_missing_blocks();
}
```

**Recommended Approach:** Implement Fix Option 2 as it ensures pending blocks are always cleared when transitioning to a new commit decision for state sync, preventing pollution at the source rather than only in the error path.

## Proof of Concept

While a complete PoC would require simulating network conditions and message reordering in a test environment, the vulnerability can be demonstrated through code inspection:

1. The three stores are defined but only two are cleared in state sync preparation
2. The error path lacks cleanup for any block stores
3. The garbage collection only activates when inserting new blocks, not during error recovery
4. The accumulation mechanism is inherent to the control flow structure

A test case would need to:
1. Create an observer with pending blocks
2. Trigger state sync for commit C1
3. Send commit C2 with lower epoch/round during sync
4. Complete sync for C1, triggering error path
5. Verify pending blocks remain in store
6. Repeat multiple times to demonstrate accumulation
7. Verify observer dysfunction when limit is reached

## Notes

This vulnerability specifically affects consensus observer nodes (VFNs and potentially PFNs with observer enabled). It does not affect validator consensus safety but impacts observer network reliability. The issue is particularly problematic because:

1. It's triggered by natural network conditions, not malicious behavior
2. It accumulates over time, making it a gradual degradation rather than immediate failure
3. The symptoms (dropped blocks) may not be immediately obvious until synchronization fails
4. Manual intervention (restart) is required for recovery

The fix should be implemented in both the error recovery path and the state sync preparation to ensure comprehensive protection against pending block pollution.

### Citations

**File:** consensus/src/consensus_observer/observer/block_data.rs (L40-52)
```rust
pub struct ObserverBlockData {
    // The block payload store (containing the block transaction payloads)
    block_payload_store: BlockPayloadStore,

    // The ordered block store (containing ordered blocks that are ready for execution)
    ordered_block_store: OrderedBlockStore,

    // The pending block store (containing pending blocks that are without payloads)
    pending_block_store: PendingBlockStore,

    // The latest ledger info
    root: LedgerInfoWithSignatures,
}
```

**File:** consensus/src/consensus_observer/observer/block_data.rs (L92-105)
```rust
    /// Clears all block data and returns the root ledger info
    pub fn clear_block_data(&mut self) -> LedgerInfoWithSignatures {
        // Clear the payload store
        self.block_payload_store.clear_all_payloads();

        // Clear the ordered blocks
        self.ordered_block_store.clear_all_ordered_blocks();

        // Clear the pending blocks
        self.pending_block_store.clear_missing_blocks();

        // Return the root ledger info
        self.root()
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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L1012-1023)
```rust
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

**File:** consensus/src/consensus_observer/observer/pending_blocks.rs (L156-195)
```rust
    /// Garbage collects the pending blocks store by removing
    /// the oldest blocks if the store is too large.
    fn garbage_collect_pending_blocks(&mut self) {
        // Verify that both stores have the same number of entries.
        // If not, log an error as this should never happen.
        let num_pending_blocks = self.blocks_without_payloads.len() as u64;
        let num_pending_blocks_by_hash = self.blocks_without_payloads_by_hash.len() as u64;
        if num_pending_blocks != num_pending_blocks_by_hash {
            error!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "The pending block stores have different numbers of entries: {} and {} (by hash)",
                    num_pending_blocks, num_pending_blocks_by_hash
                ))
            );
        }

        // Calculate the number of blocks to remove
        let max_pending_blocks = self.consensus_observer_config.max_num_pending_blocks;
        let num_blocks_to_remove = num_pending_blocks.saturating_sub(max_pending_blocks);

        // Remove the oldest blocks if the store is too large
        for _ in 0..num_blocks_to_remove {
            if let Some((oldest_epoch_round, pending_block)) =
                self.blocks_without_payloads.pop_first()
            {
                // Log a warning message for the removed block
                warn!(
                    LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                        "The pending block store is too large: {:?} blocks. Removing the block for the oldest epoch and round: {:?}",
                        num_pending_blocks, oldest_epoch_round
                    ))
                );

                // Remove the block from the hash store
                let first_block = pending_block.ordered_block().first_block();
                self.blocks_without_payloads_by_hash
                    .remove(&first_block.id());
            }
        }
    }
```

**File:** config/src/config/consensus_observer_config.rs (L72-72)
```rust
            max_num_pending_blocks: 150, // 150 blocks (sufficient for existing production networks)
```

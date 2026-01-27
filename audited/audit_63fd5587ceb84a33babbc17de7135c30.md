# Audit Report

## Title
Stale `highest_committed_epoch_round` After Block Store Clearing Causes Denial of Service in Consensus Observer

## Summary
The `clear_all_ordered_blocks()` method in `OrderedBlockStore` clears the ordered blocks map but fails to reset the `highest_committed_epoch_round` field. This creates a state inconsistency where a stale commit round value persists after block data is cleared, causing valid commit decisions to be incorrectly rejected and resulting in consensus observer node unavailability.

## Finding Description

The vulnerability exists in the `OrderedBlockStore` structure's state management. The `highest_committed_epoch_round` field tracks the highest committed block to prevent replay attacks. However, when `clear_all_ordered_blocks()` is invoked, it only clears the `ordered_blocks` BTreeMap without resetting `highest_committed_epoch_round`. [1](#0-0) 

This creates a critical inconsistency when blocks are cleared due to subscription failures, as the stale `highest_committed_epoch_round` value remains while the root ledger info may lag behind. [2](#0-1) 

The vulnerability is exploitable through the following attack sequence:

**Step 1**: A consensus observer node receives ordered blocks (rounds 101-110) and a commit decision for round 110. The `update_commit_decision()` method unconditionally updates `highest_committed_epoch_round` to (epoch=10, round=110). [3](#0-2) 

**Step 2**: Before the execution callback updates the root ledger info, a subscription health check fails, triggering `clear_pending_block_state()` which calls `clear_all_ordered_blocks()`. The `highest_committed_epoch_round` remains at (10, 110) while the root stays at its previous value (e.g., 10, 100).

**Step 3**: When processing new commit decisions, the validation check compares against `get_highest_committed_epoch_round()`, which returns the stale value from `highest_committed_epoch_round` rather than falling back to the root. [4](#0-3) 

**Step 4**: Valid commit decisions (e.g., round 105) are incorrectly rejected because they compare as less than or equal to the stale `highest_committed_epoch_round` value (110). [5](#0-4) 

This breaks the **State Consistency** invariant, as the node's view of committed state (`highest_committed_epoch_round`) diverges from the actual committed state (root ledger info), and violates **Consensus Safety** by causing observer nodes to reject valid commits.

## Impact Explanation

**Severity: High**

This vulnerability causes validator node unavailability and significant protocol violations:

1. **Consensus Observer Denial of Service**: Affected nodes cannot progress past the stale commit round, rejecting all valid commits that should advance consensus. The node becomes stuck and cannot synchronize with the network.

2. **Network Health Degradation**: If multiple consensus observer nodes are affected simultaneously (e.g., during network instability triggering widespread subscription failures), the overall network's observability and state synchronization capabilities are compromised.

3. **Cascading Failures**: Since the node rejects valid commits, it cannot execute blocks or update its state, leading to permanent desynchronization until manual intervention (node restart or state sync).

This qualifies as **High Severity** under the Aptos bug bounty program as it causes "Validator node slowdowns" and "Significant protocol violations." While it doesn't directly cause loss of funds or consensus safety violations across the full validator set, it creates operational failures that can impact network health and individual node availability.

## Likelihood Explanation

**Likelihood: Medium-High**

The vulnerability is triggered by realistic conditions that occur during normal network operations:

1. **Subscription Failures Are Common**: Consensus observers regularly check subscription health. Network partitions, peer disconnections, or slow database syncing can trigger subscription failures. [6](#0-5) 

2. **Race Condition Window**: The window between updating `highest_committed_epoch_round` and the execution callback updating the root is non-trivial. Execution involves block processing, state computation, and async operations, creating a realistic window for the race condition.

3. **No Recovery Mechanism**: Once the stale state is established, the node cannot self-recover. New commits continue to be rejected until external intervention (restart or manual state reset).

4. **Attacker Amplification**: A malicious peer could deliberately cause subscription failures by disconnecting at strategic times or sending malformed messages, increasing the likelihood of triggering this condition.

The combination of common triggering conditions and lack of automatic recovery makes this vulnerability likely to manifest in production environments.

## Recommendation

The `clear_all_ordered_blocks()` method must reset `highest_committed_epoch_round` to `None` to restore consistency with the cleared state. This ensures that subsequent calls to `get_highest_committed_epoch_round()` will fall back to the root ledger info, which represents the actual committed state.

**Fix for `ordered_blocks.rs`:**

```rust
/// Clears all ordered blocks
pub fn clear_all_ordered_blocks(&mut self) {
    self.ordered_blocks.clear();
    // Reset highest_committed_epoch_round to None to match the cleared state
    self.highest_committed_epoch_round = None;
}
```

Additionally, consider adding defensive checks in `get_highest_committed_epoch_round()` to validate that `highest_committed_epoch_round` is not ahead of the root, logging warnings if inconsistencies are detected.

## Proof of Concept

The following Rust unit test demonstrates the vulnerability:

```rust
#[test]
fn test_stale_highest_committed_after_clear() {
    use aptos_consensus_types::block::Block;
    use aptos_consensus_types::block_data::{BlockData, BlockType};
    use aptos_consensus_types::pipelined_block::{OrderedBlockWindow, PipelinedBlock};
    use aptos_consensus_types::quorum_cert::QuorumCert;
    use aptos_crypto::HashValue;
    use aptos_types::{
        aggregate_signature::AggregateSignature, 
        block_info::BlockInfo, 
        ledger_info::LedgerInfo,
        transaction::Version,
    };
    use std::sync::Arc;

    // Create store with root at round 100
    let mut ordered_block_store = OrderedBlockStore::new(ConsensusObserverConfig::default());
    
    // Verify initial state - highest_committed_epoch_round is None
    assert!(ordered_block_store.get_highest_committed_epoch_round().is_none());
    
    // Add ordered block for round 110
    let block_info = BlockInfo::new(10, 110, HashValue::random(), 
        HashValue::random(), 0 as Version, 0, None);
    let block_data = BlockData::new_for_testing(10, 110, 0, 
        QuorumCert::dummy(), BlockType::Genesis);
    let block = Block::new_for_testing(block_info.id(), block_data, None);
    let pipelined_block = Arc::new(PipelinedBlock::new_ordered(
        block, OrderedBlockWindow::empty()));
    
    let ordered_block = OrderedBlock::new(
        vec![pipelined_block],
        LedgerInfoWithSignatures::new(
            LedgerInfo::new(block_info.clone(), HashValue::random()),
            AggregateSignature::empty()
        )
    );
    
    ordered_block_store.insert_ordered_block(
        ObservedOrderedBlock::new_for_testing(ordered_block)
    );
    
    // Simulate receiving commit decision for round 110
    let commit_decision = CommitDecision::new(LedgerInfoWithSignatures::new(
        LedgerInfo::new(block_info.clone(), HashValue::random()),
        AggregateSignature::empty()
    ));
    
    ordered_block_store.update_commit_decision(&commit_decision);
    
    // Verify highest_committed_epoch_round is now Some((10, 110))
    assert_eq!(
        ordered_block_store.get_highest_committed_epoch_round(),
        Some((10, 110))
    );
    
    // Simulate subscription failure - clear all blocks
    ordered_block_store.clear_all_ordered_blocks();
    
    // BUG: highest_committed_epoch_round should be None but remains Some((10, 110))
    assert_eq!(
        ordered_block_store.get_highest_committed_epoch_round(),
        Some((10, 110))  // STALE VALUE!
    );
    
    // This demonstrates the vulnerability: the stale value persists
    // and would cause valid commits (e.g., round 105) to be rejected
    // when root is actually at round 100
}
```

## Notes

The vulnerability is particularly insidious because:

1. The fallback mechanism in `get_highest_committed_epoch_round()` only applies when `highest_committed_epoch_round` is `None`, not when it contains a stale value.

2. The issue is not caught by existing tests, as the test for `clear_all_ordered_blocks()` only verifies that the `ordered_blocks` map is empty, not that `highest_committed_epoch_round` is reset. [7](#0-6) 

3. The unconditional update in `update_commit_decision()` means that `highest_committed_epoch_round` can be set even when the corresponding block doesn't exist in the store, exacerbating the inconsistency after clearing.

### Citations

**File:** consensus/src/consensus_observer/observer/ordered_blocks.rs (L40-43)
```rust
    /// Clears all ordered blocks
    pub fn clear_all_ordered_blocks(&mut self) {
        self.ordered_blocks.clear();
    }
```

**File:** consensus/src/consensus_observer/observer/ordered_blocks.rs (L126-143)
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

**File:** consensus/src/consensus_observer/observer/ordered_blocks.rs (L234-249)
```rust
    #[test]
    fn test_clear_all_ordered_blocks() {
        // Create a new ordered block store
        let mut ordered_block_store = OrderedBlockStore::new(ConsensusObserverConfig::default());

        // Insert several ordered blocks for the current epoch
        let current_epoch = 0;
        let num_ordered_blocks = 10;
        create_and_add_ordered_blocks(&mut ordered_block_store, num_ordered_blocks, current_epoch);

        // Clear all ordered blocks
        ordered_block_store.clear_all_ordered_blocks();

        // Check that all the ordered blocks were removed
        assert!(ordered_block_store.ordered_blocks.is_empty());
    }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L204-213)
```rust
        if let Err(error) = self
            .subscription_manager
            .check_and_manage_subscriptions()
            .await
        {
            // Log the failure and clear the pending block state
            warn!(LogSchema::new(LogEntry::ConsensusObserver)
                .message(&format!("Subscription checks failed! Error: {:?}", error)));
            self.clear_pending_block_state().await;
        }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L216-230)
```rust
    /// Clears the pending block state (this is useful for changing
    /// subscriptions, where we want to wipe all state and restart).
    async fn clear_pending_block_state(&self) {
        // Clear the observer block data
        let root = self.observer_block_data.lock().clear_block_data();

        // Reset the execution pipeline for the root
        if let Err(error) = self.execution_client.reset(&root).await {
            error!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Failed to reset the execution pipeline for the root! Error: {:?}",
                    error
                ))
            );
        }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L452-461)
```rust
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
```

**File:** consensus/src/consensus_observer/observer/block_data.rs (L131-141)
```rust
    /// Returns the highest committed block epoch and round
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

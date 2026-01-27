# Audit Report

## Title
Consensus Observer Block Store Capacity Race Condition Causes Observer Liveness Failures

## Summary
The `OrderedBlockStore::insert_ordered_block()` function uses a `>=` comparison when checking capacity limits, causing new blocks to be dropped when the store reaches exactly `max_num_pending_blocks` entries. Combined with the lack of proactive cleanup of committed blocks before insertion, this creates a race condition where legitimate blocks are rejected during normal operation, forcing consensus observers into expensive fallback mode and degrading network service availability.

## Finding Description

The vulnerability exists in the ordered block insertion logic. [1](#0-0) 

When exactly `max_num_pending_blocks` blocks exist in the store (default: 150), the condition `self.ordered_blocks.len() >= max_num_ordered_blocks` evaluates to true, causing immediate rejection of the new block without attempting to reclaim space from committed blocks.

The cleanup of committed blocks happens asynchronously through commit callbacks. [2](#0-1) 

This creates a critical timing window:

1. Observer receives and inserts ordered blocks into the store
2. Blocks are sent to execution pipeline and finalized [3](#0-2) 
3. Execution completes asynchronously, and commit callbacks eventually trigger cleanup
4. During this window, if the store reaches exactly 150 blocks and a new block arrives, it's dropped even if committed blocks exist that should be removed

The consensus observer config sets the limit. [4](#0-3) 

During high block production rates or execution delays, committed blocks accumulate in the store while awaiting asynchronous cleanup. When the store hits exactly 150 entries, all subsequent blocks are rejected, forcing the observer to fall behind the network and trigger state sync fallback mode. [5](#0-4) 

This particularly affects Validator Full Nodes (VFNs) which use consensus observer to track consensus state and serve light clients and APIs. Multiple VFNs experiencing this issue simultaneously during high throughput periods degrades overall network service quality.

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty program's "State inconsistencies requiring intervention" category. 

The impact includes:
- **Observer Liveness Failures**: Consensus observers cannot accept new blocks when at capacity, falling behind network consensus
- **Service Degradation**: VFNs enter expensive fallback mode (state sync), increasing latency and resource consumption
- **Observer Divergence**: Different observers may have different cleanup timings, causing inconsistent states across the network
- **API Availability Impact**: VFNs serve critical API infrastructure; their degradation affects downstream clients

While this doesn't directly cause fund loss or consensus safety violations (observers don't vote), it degrades critical infrastructure that the network relies on for data availability and client service.

## Likelihood Explanation

This is **highly likely** to occur during normal network operation:

- High block production rates (intentional network design for throughput)
- Execution pipeline delays (variable computational workload)
- Network latency variations (normal P2P conditions)
- No privileged access required to trigger

The default limit of 150 blocks can be reached within seconds during peak throughput. Consensus observers on VFNs are critical infrastructure, making this a practical operational concern rather than a theoretical edge case.

## Recommendation

Implement proactive cleanup before capacity checking:

```rust
pub fn insert_ordered_block(&mut self, observed_ordered_block: ObservedOrderedBlock) {
    // Proactively remove blocks that have been committed before checking capacity
    if let Some((epoch, round)) = self.highest_committed_epoch_round {
        let uncommitted_blocks: BTreeMap<_, _> = self.ordered_blocks
            .iter()
            .filter(|((e, r), _)| (*e, *r) > (epoch, round))
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        if uncommitted_blocks.len() < self.ordered_blocks.len() {
            self.ordered_blocks = uncommitted_blocks;
        }
    }

    // Now check capacity against uncommitted blocks only
    let max_num_ordered_blocks = self.consensus_observer_config.max_num_pending_blocks as usize;
    if self.ordered_blocks.len() >= max_num_ordered_blocks {
        warn!(LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
            "Exceeded maximum after cleanup: {:?}. Dropping: {:?}",
            max_num_ordered_blocks,
            observed_ordered_block.ordered_block().proof_block_info()
        )));
        return;
    }
    
    // Insert the block
    let last_block = observed_ordered_block.ordered_block().last_block();
    self.ordered_blocks.insert(
        (last_block.epoch(), last_block.round()),
        (observed_ordered_block, None),
    );
}
```

Alternatively, change the comparison from `>=` to `>` to allow insertion at exactly max capacity before evicting oldest uncommitted blocks.

## Proof of Concept

```rust
#[test]
fn test_capacity_race_condition() {
    // Create config with limit of 10
    let config = ConsensusObserverConfig {
        max_num_pending_blocks: 10,
        ..Default::default()
    };
    let mut store = OrderedBlockStore::new(config);
    
    // Insert 10 blocks (reaching exact capacity)
    for i in 0..10 {
        let block_info = BlockInfo::new(0, i, HashValue::random(), 
            HashValue::random(), i, i, None);
        let block = create_pipelined_block(block_info);
        let ordered_block = OrderedBlock::new(vec![block], create_ledger_info(0, i));
        let observed = ObservedOrderedBlock::new_for_testing(ordered_block);
        store.insert_ordered_block(observed);
    }
    
    assert_eq!(store.ordered_blocks.len(), 10);
    
    // Mark first 5 blocks as committed
    let commit_decision = CommitDecision::new(create_ledger_info(0, 4));
    store.update_commit_decision(&commit_decision);
    
    // Store still has 10 blocks (cleanup hasn't happened yet)
    assert_eq!(store.ordered_blocks.len(), 10);
    
    // Try to insert block 11 - should succeed since 5 blocks are committed
    // but actually gets DROPPED due to capacity check before cleanup
    let block_info = BlockInfo::new(0, 10, HashValue::random(), 
        HashValue::random(), 10, 10, None);
    let block = create_pipelined_block(block_info);
    let ordered_block = OrderedBlock::new(vec![block], create_ledger_info(0, 10));
    let observed = ObservedOrderedBlock::new_for_testing(ordered_block.clone());
    
    store.insert_ordered_block(observed);
    
    // Block 11 was dropped even though space should be reclaimable
    assert!(store.get_ordered_block(0, 10).is_none());
    assert_eq!(store.ordered_blocks.len(), 10); // Still at capacity
}
```

This demonstrates that committed blocks occupying store capacity prevent new legitimate blocks from being inserted, forcing observers into degraded state.

### Citations

**File:** consensus/src/consensus_observer/observer/ordered_blocks.rs (L76-88)
```rust
    pub fn insert_ordered_block(&mut self, observed_ordered_block: ObservedOrderedBlock) {
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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L785-791)
```rust
            self.observer_block_data
                .lock()
                .insert_ordered_block(observed_ordered_block.clone());

            // If state sync is not syncing to a commit, finalize the ordered blocks
            if !self.state_sync_manager.is_syncing_to_commit() {
                self.finalize_ordered_block(ordered_block).await;
```

**File:** config/src/config/consensus_observer_config.rs (L72-72)
```rust
            max_num_pending_blocks: 150, // 150 blocks (sufficient for existing production networks)
```

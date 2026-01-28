# Audit Report

## Title
Epoch Mismatch Vulnerability in Consensus Observer: Incorrect Block Removal During Epoch Transitions

## Summary

The `remove_ready_block()` function in the consensus observer's pending blocks store does not validate that the epoch of the received payload matches the epoch of blocks being processed. During epoch transitions in the commit sync path, this causes blocks from the previous epoch to be incorrectly dropped as "out-of-date," leading to permanent loss of valid blocks.

## Finding Description

The vulnerability exists in the `remove_ready_block()` function which uses BTreeMap key ordering `(epoch, round)` to split and manage pending blocks. The function splits the BTreeMap at the received payload's epoch and round, then uses `pop_last()` to retrieve the highest block below that threshold. [1](#0-0) 

**Critical Flaw**: The function does not validate that the popped block's epoch matches `received_payload_epoch`. Due to BTreeMap tuple ordering, blocks from epoch N (e.g., `(1, 100)`) are less than blocks from epoch N+1 (e.g., `(2, 1)`), causing old-epoch blocks to remain in the map after the split and get incorrectly processed.

All remaining blocks in the map are then logged as "out-of-date" [2](#0-1)  and permanently cleared. [3](#0-2) 

The vulnerability is triggered during epoch transitions in the commit sync code path. After an epoch transition from N to N+1, the commit sync notification handler verifies payload signatures for the new epoch and orders pending blocks. [4](#0-3) 

**Key Difference from Fallback Sync**: Unlike fallback sync which explicitly clears all pending blocks after epoch transitions, [5](#0-4)  commit sync does NOT clear pending blocks, allowing old-epoch blocks to remain in the store.

When `order_ready_pending_block(new_epoch_state.epoch, payload_round)` is called, it retrieves blocks via `remove_ready_pending_block()` [6](#0-5)  which delegates to the vulnerable `remove_ready_block()` function. [7](#0-6) 

When these old-epoch blocks are passed to `process_ordered_block()`, they are correctly rejected because their epoch doesn't match the current epoch state. [8](#0-7) 

However, by this point the blocks have **already been permanently removed** from the pending store, causing irreversible data loss.

**Broken Invariant**: Consensus Observer State Consistency - blocks from epoch N should only be processed with payloads from epoch N, and valid pending blocks should not be lost during epoch transitions.

## Impact Explanation

**Severity: MEDIUM** - Limited Protocol Violations

This vulnerability causes:

1. **Permanent Block Loss**: Valid blocks from the previous epoch waiting for payloads are permanently dropped during epoch transitions
2. **State Inconsistency**: The consensus observer node loses blocks that may be critical for maintaining consistency with the network
3. **Observer Degradation**: Affected nodes may fall behind the network and require manual intervention via fallback sync
4. **Systematic Occurrence**: This happens automatically during every epoch transition that uses the commit sync path

While not directly exploitable by an external attacker (due to upstream signature validation), this is a logic bug that systematically breaks consensus observer correctness during normal operation. This qualifies as a "Limited Protocol Violation" with "State inconsistencies requiring manual intervention" under the Medium severity category. Note that consensus observers are monitoring nodes, not validators, so this does not affect core consensus safety.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

This vulnerability triggers automatically under these conditions:
1. Consensus observer is operating in commit sync mode (common operational mode)
2. An epoch transition occurs (happens periodically in Aptos)
3. Pending blocks from the old epoch exist when the new epoch starts
4. Payloads for the new epoch are verified and processed

These conditions occur naturally during normal network operation, making this a realistic and recurring issue. The vulnerability is NOT exploitable by external attackers but occurs systematically during epoch transitions.

## Recommendation

Add epoch validation in the `remove_ready_block()` function before returning a block as ready:

```rust
if let Some((epoch_and_round, pending_block)) = self.blocks_without_payloads.pop_last() {
    // Validate that the block epoch matches the received payload epoch
    let block_epoch = pending_block.ordered_block().first_block().epoch();
    if block_epoch != received_payload_epoch {
        // This block is from a different epoch - do not process it
        // It will be dropped below as out-of-date
    } else if block_payload_store.all_payloads_exist(pending_block.ordered_block().blocks()) {
        ready_block = Some(pending_block);
    } else {
        // ... existing logic for blocks waiting for higher payloads
    }
}
```

Alternatively, clear pending blocks during commit sync epoch transitions, matching the behavior of fallback sync.

## Proof of Concept

A PoC would require setting up a consensus observer with:
1. Pending blocks from epoch N in the store
2. Triggering an epoch transition to N+1 via commit sync
3. Receiving and verifying payloads for epoch N+1
4. Observing that blocks from epoch N are incorrectly removed and rejected

The issue can be demonstrated by tracing the execution flow through the code paths cited above, showing that blocks from old epochs are not filtered before being passed to `remove_ready_block()` during commit sync epoch transitions.

## Notes

This vulnerability is a correctness bug in consensus observer logic that causes systematic state inconsistencies during epoch transitions. While it does not affect validator consensus or network safety, it degrades observer reliability and may require manual intervention to recover. The bug is automatically triggered during normal epoch transitions when using commit sync mode, which is a common operational scenario for consensus observers.

### Citations

**File:** consensus/src/consensus_observer/observer/pending_blocks.rs (L210-217)
```rust
        let mut blocks_at_higher_rounds = self
            .blocks_without_payloads
            .split_off(&(received_payload_epoch, split_round));

        // Check if the last block is ready (this should be the only ready block).
        // Any earlier blocks are considered out-of-date and will be dropped.
        let mut ready_block = None;
        if let Some((epoch_and_round, pending_block)) = self.blocks_without_payloads.pop_last() {
```

**File:** consensus/src/consensus_observer/observer/pending_blocks.rs (L231-239)
```rust
        if !self.blocks_without_payloads.is_empty() {
            info!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Dropped {:?} out-of-date pending blocks before epoch and round: {:?}",
                    self.blocks_without_payloads.len(),
                    (received_payload_epoch, received_payload_round)
                ))
            );
        }
```

**File:** consensus/src/consensus_observer/observer/pending_blocks.rs (L243-244)
```rust
        // Clear all blocks from the pending block stores
        self.clear_missing_blocks();
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L341-352)
```rust
    async fn order_ready_pending_block(&mut self, block_epoch: u64, block_round: Round) {
        // Remove any ready pending block
        let pending_block_with_metadata = self
            .observer_block_data
            .lock()
            .remove_ready_pending_block(block_epoch, block_round);

        // Process the ready ordered block (if it exists)
        if let Some(pending_block_with_metadata) = pending_block_with_metadata {
            self.process_ordered_block(pending_block_with_metadata)
                .await;
        }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L729-752)
```rust
        if ordered_block.proof_block_info().epoch() == epoch_state.epoch {
            if let Err(error) = ordered_block.verify_ordered_proof(&epoch_state) {
                // Log the error and update the invalid message counter
                error!(
                    LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                        "Failed to verify ordered proof! Ignoring: {:?}, from peer: {:?}. Error: {:?}",
                        ordered_block.proof_block_info(),
                        peer_network_id,
                        error
                    ))
                );
                increment_invalid_message_counter(&peer_network_id, metrics::ORDERED_BLOCK_LABEL);
                return;
            }
        } else {
            // Drop the block and log an error (the block should always be for the current epoch)
            error!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Received ordered block for a different epoch! Ignoring: {:?}",
                    ordered_block.proof_block_info()
                ))
            );
            return;
        };
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L954-961)
```rust
        if epoch > current_epoch_state.epoch {
            // Wait for the latest epoch to start
            self.execution_client.end_epoch().await;
            self.wait_for_epoch_start().await;
        };

        // Reset the pending block state
        self.clear_pending_block_state().await;
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L1028-1044)
```rust
        if synced_epoch > current_epoch_state.epoch {
            // Wait for the latest epoch to start
            self.execution_client.end_epoch().await;
            self.wait_for_epoch_start().await;

            // Verify the block payloads for the new epoch
            let new_epoch_state = self.get_epoch_state();
            let verified_payload_rounds = self
                .observer_block_data
                .lock()
                .verify_payload_signatures(&new_epoch_state);

            // Order all the pending blocks that are now ready (these were buffered during state sync)
            for payload_round in verified_payload_rounds {
                self.order_ready_pending_block(new_epoch_state.epoch, payload_round)
                    .await;
            }
```

**File:** consensus/src/consensus_observer/observer/block_data.rs (L244-254)
```rust
    pub fn remove_ready_pending_block(
        &mut self,
        received_payload_epoch: u64,
        received_payload_round: Round,
    ) -> Option<Arc<PendingBlockWithMetadata>> {
        self.pending_block_store.remove_ready_block(
            received_payload_epoch,
            received_payload_round,
            &mut self.block_payload_store,
        )
    }
```

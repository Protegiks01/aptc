# Audit Report

## Title
Out-of-Order Payload Delivery Causes Legitimate Pending Blocks to be Dropped in Consensus Observer

## Summary
The `remove_ready_block` function in the consensus observer's pending block store contains a critical logic flaw that causes legitimate pending blocks to be permanently dropped when block payloads arrive out of order. This violates the consensus observer's liveness guarantee and can prevent observer nodes from processing valid blocks.

## Finding Description

The vulnerability exists in the `remove_ready_block` function which manages pending blocks awaiting their transaction payloads. The function uses a BTreeMap keyed by `(epoch, first_block_round)` to store pending blocks, where each entry can contain an `OrderedBlock` spanning multiple rounds. [1](#0-0) 

When a new payload arrives, the function splits the pending blocks map at `received_payload_round + 1`: [2](#0-1) 

The critical flaw is in the assumption that payloads arrive in sequential order. The code treats all blocks remaining in `blocks_without_payloads` after the split as "out-of-date" and drops them: [3](#0-2) 

**Attack Scenario:**

1. Observer has pending blocks:
   - Block A: rounds 10-15 (key: `(epoch, 10)`)
   - Block B: rounds 20-25 (key: `(epoch, 20)`)

2. Payload for round 20 arrives first (before payloads for rounds 10-15):
   - `split_round = 21`
   - Split creates: `blocks_without_payloads = [Block A, Block B]`, `blocks_at_higher_rounds = []`
   - `pop_last()` returns Block B (key `(epoch, 20)`)
   - Block B's payloads incomplete, `last_block_round (25) > received_payload_round (20)`, moved to `blocks_at_higher_rounds`
   - Block A still in `blocks_without_payloads` → **dropped as "out-of-date"**

3. Result: Block A is permanently lost even though it's legitimate and awaiting payloads

The root cause is that the function uses the received payload's round number to determine which blocks are "out-of-date", but in a distributed system with multiple validators sending payloads asynchronously, there's no guarantee of sequential delivery. The code in `process_block_payload_message` only verifies the payload is not behind the last **ordered** block, not that it arrives sequentially: [4](#0-3) 

## Impact Explanation

This vulnerability causes **High severity** liveness failures:

1. **Consensus Observer Liveness Loss**: Legitimate blocks that should be processed are permanently dropped, preventing the observer from maintaining consensus state
2. **Non-Deterministic Failures**: The issue depends on network timing, making it difficult to diagnose
3. **Cascading Effects**: Dropped blocks can cause gaps in the blockchain view, forcing state sync fallback

Per the Aptos Bug Bounty program, this qualifies as **High Severity** due to:
- Significant protocol violations (consensus observer fails to process legitimate blocks)
- Validator node operational issues (observers failing affects monitoring and redundancy)
- Potential for repeated occurrence under normal network conditions

## Likelihood Explanation

**High Likelihood** - This vulnerability can be triggered by normal network conditions:

1. **Asynchronous Validator Communication**: Different validators send payloads at different times
2. **Network Jitter**: Natural packet reordering in distributed networks  
3. **Multiple Peer Sources**: Observer subscribes to multiple peers; payloads from different sources can arrive out of order
4. **No Sequential Enforcement**: The code has no mechanism to enforce or wait for sequential payload arrival

The vulnerability requires no active exploitation - it occurs naturally when:
- Network latency varies between validator connections
- Validators produce payloads at different rates
- Observer switches between subscription sources

## Recommendation

Add logic to preserve pending blocks that are waiting for earlier payloads, not just higher ones. The fix should track the lowest pending round and only drop blocks that are genuinely superseded:

```rust
pub fn remove_ready_block(
    &mut self,
    received_payload_epoch: u64,
    received_payload_round: Round,
    block_payload_store: &mut BlockPayloadStore,
) -> Option<Arc<PendingBlockWithMetadata>> {
    let split_round = received_payload_round.saturating_add(1);
    let mut blocks_at_higher_rounds = self
        .blocks_without_payloads
        .split_off(&(received_payload_epoch, split_round));

    let mut ready_block = None;
    if let Some((epoch_and_round, pending_block)) = self.blocks_without_payloads.pop_last() {
        if block_payload_store.all_payloads_exist(pending_block.ordered_block().blocks()) {
            ready_block = Some(pending_block);
        } else {
            let last_pending_block_round = pending_block.ordered_block().last_block().round();
            if last_pending_block_round > received_payload_round {
                blocks_at_higher_rounds.insert(epoch_and_round, pending_block);
            }
            // FIX: Don't drop - re-insert blocks still waiting for payloads
            else {
                blocks_at_higher_rounds.insert(epoch_and_round, pending_block);
            }
        }
    }

    // FIX: Preserve remaining blocks that may be waiting for earlier payloads
    for (key, block) in self.blocks_without_payloads.iter() {
        blocks_at_higher_rounds.insert(*key, block.clone());
    }

    self.clear_missing_blocks();
    self.blocks_without_payloads = blocks_at_higher_rounds;
    
    // Rebuild hash index
    for pending_block in self.blocks_without_payloads.values() {
        let first_block = pending_block.ordered_block().first_block();
        self.blocks_without_payloads_by_hash
            .insert(first_block.id(), pending_block.clone());
    }

    ready_block
}
```

## Proof of Concept

```rust
#[test]
fn test_out_of_order_payload_drops_legitimate_blocks() {
    use crate::consensus_observer::observer::payload_store::BlockPayloadStore;
    use aptos_config::config::ConsensusObserverConfig;
    
    // Create pending block store
    let config = ConsensusObserverConfig::default();
    let mut pending_store = PendingBlockStore::new(config);
    let mut payload_store = BlockPayloadStore::new(config);
    
    // Create two pending blocks:
    // Block A: rounds 10-15 (waiting for payloads)
    // Block B: rounds 20-25 (waiting for payloads)
    let epoch = 1;
    
    let block_a = create_ordered_block(epoch, 10, 15);
    let block_b = create_ordered_block(epoch, 20, 25);
    
    let pending_a = PendingBlockWithMetadata::new_with_arc(
        PeerNetworkId::random(),
        Instant::now(),
        ObservedOrderedBlock::new(block_a.clone()),
    );
    
    let pending_b = PendingBlockWithMetadata::new_with_arc(
        PeerNetworkId::random(),
        Instant::now(),
        ObservedOrderedBlock::new(block_b.clone()),
    );
    
    pending_store.insert_pending_block(pending_a);
    pending_store.insert_pending_block(pending_b);
    
    // Verify both blocks are pending
    assert!(pending_store.existing_pending_block(&block_a));
    assert!(pending_store.existing_pending_block(&block_b));
    
    // ATTACK: Payload for round 20 arrives BEFORE payloads for 10-15
    insert_payload_for_round(&mut payload_store, epoch, 20);
    
    let ready = pending_store.remove_ready_block(epoch, 20, &mut payload_store);
    assert!(ready.is_none()); // Block B not ready (missing payloads 21-25)
    
    // VULNERABILITY: Block A should still be pending but is dropped!
    assert!(!pending_store.existing_pending_block(&block_a)); // FAILS - Block A was dropped
    
    // Even when payloads for 10-15 arrive later, Block A is gone
    for round in 10..=15 {
        insert_payload_for_round(&mut payload_store, epoch, round);
    }
    
    let ready = pending_store.remove_ready_block(epoch, 15, &mut payload_store);
    assert!(ready.is_none()); // Block A can never be recovered
}
```

**Notes:**

The vulnerability stems from the incorrect assumption that payload arrival order reflects block ordering. In distributed systems, this assumption is invalid. The code should track block dependencies and payload completeness independently of arrival order, preserving all pending blocks until either:
1. All their payloads arrive (ready for processing)
2. They are superseded by committed blocks (truly out-of-date)

### Citations

**File:** consensus/src/consensus_observer/observer/pending_blocks.rs (L65-67)
```rust
    // A map of ordered blocks that are without payloads. The key is
    // the (epoch, round) of the first block in the ordered block.
    blocks_without_payloads: BTreeMap<(u64, Round), Arc<PendingBlockWithMetadata>>,
```

**File:** consensus/src/consensus_observer/observer/pending_blocks.rs (L206-212)
```rust
        // Calculate the round at which to split the blocks
        let split_round = received_payload_round.saturating_add(1);

        // Split the blocks at the epoch and round
        let mut blocks_at_higher_rounds = self
            .blocks_without_payloads
            .split_off(&(received_payload_epoch, split_round));
```

**File:** consensus/src/consensus_observer/observer/pending_blocks.rs (L230-247)
```rust
        // Check if any out-of-date blocks are going to be dropped
        if !self.blocks_without_payloads.is_empty() {
            info!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Dropped {:?} out-of-date pending blocks before epoch and round: {:?}",
                    self.blocks_without_payloads.len(),
                    (received_payload_epoch, received_payload_round)
                ))
            );
        }

        // TODO: optimize this flow!

        // Clear all blocks from the pending block stores
        self.clear_missing_blocks();

        // Update the pending block stores to only include the blocks at higher rounds
        self.blocks_without_payloads = blocks_at_higher_rounds;
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L366-380)
```rust
        // Determine if the payload is behind the last ordered block, or if it already exists
        let last_ordered_block = self.observer_block_data.lock().get_last_ordered_block();
        let payload_out_of_date =
            (block_epoch, block_round) <= (last_ordered_block.epoch(), last_ordered_block.round());
        let payload_exists = self
            .observer_block_data
            .lock()
            .existing_payload_entry(&block_payload);

        // If the payload is out of date or already exists, ignore it
        if payload_out_of_date || payload_exists {
            // Update the metrics for the dropped block payload
            update_metrics_for_dropped_block_payload_message(peer_network_id, &block_payload);
            return;
        }
```

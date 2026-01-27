# Audit Report

## Title
Pending Block Slot Reservation Attack Allows Denial of Service on Consensus Observer Nodes

## Summary
A malicious peer can prevent consensus observer nodes from processing valid blocks by pre-registering malicious blocks in the pending block store. The vulnerability exists because pending blocks are indexed solely by `(epoch, round)` tuple without considering block hash, allowing an attacker to reserve slots and cause honest blocks to be dropped, resulting in node liveness degradation.

## Finding Description

The consensus observer's `process_ordered_block_message()` function contains a critical flaw in how it handles pending blocks. When an ordered block arrives without all payloads present, it is stored in a pending block store to await payload arrival. However, the check for existing pending blocks only considers the `(epoch, round)` tuple, not the block content or hash. [1](#0-0) 

This check uses `existing_pending_block()` which only verifies if an entry exists for the given epoch and round: [2](#0-1) 

When inserting a pending block, the system uses `(epoch, round)` as the map key and refuses to overwrite existing entries: [3](#0-2) 

The critical issue is that blocks are stored in pending **before** signature verification occurs. Signature verification only happens later in `process_ordered_block()`: [4](#0-3) 

**Attack Scenario:**

1. Attacker (as subscribed peer) sends malicious block M₁ for (epoch 10, round 5) that:
   - Passes structural validation (`verify_ordered_blocks()`)
   - Contains invalid signatures or mismatched payload digests
   - Arrives before payloads are available

2. M₁ is stored in pending blocks with key `(10, 5)`

3. Honest validator sends correct block H₁ for (epoch 10, round 5) with:
   - Valid signatures and correct payloads
   - Arrives shortly after M₁

4. H₁ is **dropped** at line 687-691 because `existing_pending_block()` returns true for (10, 5)

5. When payloads for round 5 arrive:
   - `order_ready_pending_block()` removes M₁ from pending store
   - `process_ordered_block()` verifies M₁ and fails at signature/payload verification
   - M₁ is rejected and dropped

6. Result: No valid block processed for (epoch 10, round 5), node falls behind

The attacker can repeat this for subsequent rounds, continuously causing the observer to drop honest blocks and process invalid ones, forcing the node to rely on state sync.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program criteria:

- **Validator node slowdowns**: Consensus observer nodes experience significant performance degradation as they repeatedly process invalid blocks and fall behind consensus
- **Significant protocol violations**: Violates the consensus liveness invariant - observers should be able to process honest blocks from validators
- **Resource exhaustion**: Wastes computational resources processing malicious blocks that will inevitably fail verification

The attack affects consensus observer nodes' ability to track the blockchain in real-time, forcing them to periodically invoke state sync for recovery. While this doesn't compromise consensus safety (validators are unaffected), it significantly degrades the availability and reliability of observer infrastructure.

## Likelihood Explanation

**Likelihood: HIGH**

The attack is highly practical and easy to execute:

1. **Low barrier to entry**: Attacker only needs to be accepted as a subscribed peer, which is checked here: [5](#0-4) 

2. **Timing advantage**: The attacker can monitor the network and race to send malicious blocks before honest blocks arrive

3. **No cryptographic requirements**: The malicious blocks only need to pass structural validation (`verify_ordered_blocks()`), not signature verification, making them trivial to craft: [6](#0-5) 

4. **Repeatable**: The attacker can continuously execute this attack for each round, maintaining persistent DoS

5. **Detection difficulty**: Each malicious block appears valid initially and only fails during later verification, making the attack subtle

## Recommendation

**Solution: Include block hash in pending block key**

Change the pending block store to use `(epoch, round, block_hash)` as the key instead of just `(epoch, round)`. This allows multiple blocks for the same round to coexist, preventing slot reservation attacks.

**Implementation changes:**

1. Update `PendingBlockStore` to use a composite key:
```rust
// pending_blocks.rs
pub struct PendingBlockStore {
    // Map key: (epoch, round, block_hash)
    blocks_without_payloads: BTreeMap<(u64, Round, HashValue), Arc<PendingBlockWithMetadata>>,
    // Keep hash-only index for existing functionality
    blocks_without_payloads_by_hash: BTreeMap<HashValue, Arc<PendingBlockWithMetadata>>,
}
```

2. Update `existing_pending_block()` to check for specific block hash:
```rust
pub fn existing_pending_block(&self, ordered_block: &OrderedBlock) -> bool {
    let first_block = ordered_block.first_block();
    let key = (first_block.epoch(), first_block.round(), first_block.id());
    self.blocks_without_payloads.contains_key(&key)
}
```

3. Verify signatures BEFORE storing in pending blocks by moving signature verification earlier in the flow

**Additional mitigation:**

Add early signature verification in `process_ordered_block_message()` before storing as pending, similar to how block payloads are verified: [7](#0-6) 

## Proof of Concept

```rust
#[tokio::test]
async fn test_pending_block_slot_reservation_attack() {
    use aptos_consensus_types::{block::Block, block_data::BlockData, 
                                pipelined_block::PipelinedBlock};
    use aptos_types::block_info::BlockInfo;
    
    // Setup consensus observer with test configuration
    let consensus_observer_config = ConsensusObserverConfig::default();
    let mut pending_block_store = PendingBlockStore::new(consensus_observer_config);
    
    let epoch = 10u64;
    let round = 5u64;
    
    // Step 1: Attacker sends malicious block M1 for (epoch, round)
    let malicious_block_info = BlockInfo::new(
        epoch, round, 
        HashValue::random(), // Malicious hash
        HashValue::random(), 
        0, 0, None
    );
    let malicious_block_data = BlockData::new_for_testing(
        epoch, round, 0,
        QuorumCert::dummy(),
        BlockType::Genesis
    );
    let malicious_block = Block::new_for_testing(
        malicious_block_info.id(), 
        malicious_block_data, 
        None
    );
    let malicious_pipelined = Arc::new(PipelinedBlock::new_ordered(
        malicious_block,
        OrderedBlockWindow::empty()
    ));
    let malicious_ordered = OrderedBlock::new(
        vec![malicious_pipelined],
        create_dummy_ledger_info(epoch, round)
    );
    let malicious_pending = PendingBlockWithMetadata::new_with_arc(
        PeerNetworkId::random(),
        Instant::now(),
        ObservedOrderedBlock::new(malicious_ordered.clone())
    );
    
    // Insert malicious block
    pending_block_store.insert_pending_block(malicious_pending);
    
    // Verify malicious block is stored
    assert!(pending_block_store.existing_pending_block(&malicious_ordered));
    
    // Step 2: Honest block H1 arrives for same (epoch, round)
    let honest_block_info = BlockInfo::new(
        epoch, round,
        HashValue::random(), // Different hash
        HashValue::random(),
        0, 0, None
    );
    let honest_block_data = BlockData::new_for_testing(
        epoch, round, 0,
        QuorumCert::dummy(),
        BlockType::Genesis
    );
    let honest_block = Block::new_for_testing(
        honest_block_info.id(),
        honest_block_data,
        None
    );
    let honest_pipelined = Arc::new(PipelinedBlock::new_ordered(
        honest_block,
        OrderedBlockWindow::empty()
    ));
    let honest_ordered = OrderedBlock::new(
        vec![honest_pipelined],
        create_dummy_ledger_info(epoch, round)
    );
    
    // Step 3: Verify honest block is considered "pending" (slot already taken)
    assert!(pending_block_store.existing_pending_block(&honest_ordered));
    
    // Step 4: Attempt to insert honest block - it should be rejected
    let honest_pending = PendingBlockWithMetadata::new_with_arc(
        PeerNetworkId::random(),
        Instant::now(),
        ObservedOrderedBlock::new(honest_ordered.clone())
    );
    pending_block_store.insert_pending_block(honest_pending);
    
    // Step 5: Verify only ONE block exists (the malicious one)
    let blocks: Vec<_> = pending_block_store.blocks_without_payloads
        .values()
        .collect();
    assert_eq!(blocks.len(), 1);
    
    // Verify it's the malicious block, not the honest one
    assert_eq!(
        blocks[0].ordered_block().first_block().id(),
        malicious_ordered.first_block().id()
    );
    assert_ne!(
        blocks[0].ordered_block().first_block().id(),
        honest_ordered.first_block().id()
    );
    
    // Attack successful: honest block H1 was rejected, malicious block M1 persists
    println!("✓ Attack successful: Malicious block reserves slot, honest block rejected");
}
```

**Notes:**
- The consensus observer falls back to state sync when blocks cannot be processed, mitigating permanent damage but causing significant performance impact
- The attack can be repeated for each round, causing persistent degradation
- Observer nodes are critical infrastructure for users querying blockchain state without running full validators

### Citations

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L400-418)
```rust
        let epoch_state = self.get_epoch_state();
        let verified_payload = if block_epoch == epoch_state.epoch {
            // Verify the block proof signatures
            if let Err(error) = block_payload.verify_payload_signatures(&epoch_state) {
                // Log the error and update the invalid message counter
                error!(
                    LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                        "Failed to verify block payload signatures! Ignoring block: {:?}, from peer: {:?}. Error: {:?}",
                        block_payload.block(), peer_network_id, error
                    ))
                );
                increment_invalid_message_counter(&peer_network_id, metrics::BLOCK_PAYLOAD_LABEL);
                return;
            }

            true // We have successfully verified the signatures
        } else {
            false // We can't verify the signatures yet
        };
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L578-594)
```rust
        // Verify the message is from the peers we've subscribed to
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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L681-684)
```rust
        let block_pending = self
            .observer_block_data
            .lock()
            .existing_pending_block(&ordered_block);
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L727-742)
```rust
        // Verify the ordered block proof
        let epoch_state = self.get_epoch_state();
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
```

**File:** consensus/src/consensus_observer/observer/pending_blocks.rs (L91-99)
```rust
    pub fn existing_pending_block(&self, ordered_block: &OrderedBlock) -> bool {
        // Get the epoch and round of the first block
        let first_block = ordered_block.first_block();
        let first_block_epoch_round = (first_block.epoch(), first_block.round());

        // Check if the block is already in the store by epoch and round
        self.blocks_without_payloads
            .contains_key(&first_block_epoch_round)
    }
```

**File:** consensus/src/consensus_observer/observer/pending_blocks.rs (L112-132)
```rust
    pub fn insert_pending_block(&mut self, pending_block: Arc<PendingBlockWithMetadata>) {
        // Get the first block in the ordered blocks
        let first_block = pending_block.ordered_block().first_block();

        // Insert the block into the store using the epoch round of the first block
        let first_block_epoch_round = (first_block.epoch(), first_block.round());
        match self.blocks_without_payloads.entry(first_block_epoch_round) {
            Entry::Occupied(_) => {
                // The block is already in the store
                warn!(
                    LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                        "A pending block was already found for the given epoch and round: {:?}",
                        first_block_epoch_round
                    ))
                );
            },
            Entry::Vacant(entry) => {
                // Insert the block into the store
                entry.insert(pending_block.clone());
            },
        }
```

**File:** consensus/src/consensus_observer/network/observer_message.rs (L225-266)
```rust
    /// Verifies the ordered blocks and returns an error if the data is invalid.
    /// Note: this does not check the ordered proof.
    pub fn verify_ordered_blocks(&self) -> Result<(), Error> {
        // Verify that we have at least one ordered block
        if self.blocks.is_empty() {
            return Err(Error::InvalidMessageError(
                "Received empty ordered block!".to_string(),
            ));
        }

        // Verify the last block ID matches the ordered proof block ID
        if self.last_block().id() != self.proof_block_info().id() {
            return Err(Error::InvalidMessageError(
                format!(
                    "Last ordered block ID does not match the ordered proof ID! Number of blocks: {:?}, Last ordered block ID: {:?}, Ordered proof ID: {:?}",
                    self.blocks.len(),
                    self.last_block().id(),
                    self.proof_block_info().id()
                )
            ));
        }

        // Verify the blocks are correctly chained together (from the last block to the first)
        let mut expected_parent_id = None;
        for block in self.blocks.iter().rev() {
            if let Some(expected_parent_id) = expected_parent_id {
                if block.id() != expected_parent_id {
                    return Err(Error::InvalidMessageError(
                        format!(
                            "Block parent ID does not match the expected parent ID! Block ID: {:?}, Expected parent ID: {:?}",
                            block.id(),
                            expected_parent_id
                        )
                    ));
                }
            }

            expected_parent_id = Some(block.parent_id());
        }

        Ok(())
    }
```

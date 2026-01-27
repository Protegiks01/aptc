# Audit Report

## Title
Memory Exhaustion in Consensus Observer via Unbounded Blocks per OrderedBlock Entry

## Summary
The `ordered_blocks` BTreeMap in the consensus observer implements a limit on the number of map entries but not on the total number of blocks. Each map entry can contain an `OrderedBlock` with an unbounded vector of blocks, allowing memory to grow far beyond the intended limit. When epochs fail to advance, normal cleanup mechanisms are blocked, exacerbating the memory exhaustion.

## Finding Description

The vulnerability exists in the mismatch between the intended behavior documented in the configuration and the actual implementation of the block limit.

**Configuration Intent:** [1](#0-0) 

The configuration clearly states the parameter should limit the "Maximum number of blocks to keep in memory."

**Implementation Reality:** [2](#0-1) 

The implementation only checks the number of BTreeMap entries (`self.ordered_blocks.len()`), not the total number of blocks.

**Data Structure Analysis:** [3](#0-2) 

Each map entry stores an `ObservedOrderedBlock` which contains an `OrderedBlock`: [4](#0-3) 

The `OrderedBlock` contains a `Vec<Arc<PipelinedBlock>>` with **no limit on the vector size**.

**Missing Validation:** [5](#0-4) 

The validation only checks that blocks are non-empty and correctly chained, but never validates the number of blocks in the vector.

**Attack Scenario:**
1. A Byzantine validator/publisher sends `OrderedBlock` messages where each contains many blocks (e.g., 100-1000 blocks, limited only by the 64 MiB network message size)
2. The consensus observer validates these blocks (epoch match, proof verification, payload verification) at line 729-771 of `consensus_observer.rs` [6](#0-5) 

3. Blocks are inserted into the `ordered_blocks` map via `insert_ordered_block()`
4. With `max_num_pending_blocks = 150` (default), an attacker could insert 150 entries × 100 blocks per entry = **15,000 blocks** instead of the intended ~150 blocks
5. When epochs never advance (due to consensus failure, stuck epoch transitions, or Byzantine behavior), cleanup mechanisms fail:
   - No epoch transitions → no `clear_block_data()` calls
   - No commits (or delayed commits) → no `remove_blocks_for_commit()` cleanup [7](#0-6) 

This breaks the **Resource Limits** invariant (#9): "All operations must respect gas, storage, and computational limits."

## Impact Explanation

**Severity: High**

This vulnerability allows memory exhaustion leading to:
- **Validator node crashes**: Out-of-memory kills of consensus observer nodes
- **Node slowdowns**: Memory pressure causing degraded performance
- **Availability loss**: Observer nodes become unresponsive or crash

Per Aptos Bug Bounty criteria, this qualifies as **High Severity** ($50,000 category):
- "Validator node slowdowns" - direct match
- "API crashes" - observer node crashes impact API availability

The impact is amplified when epochs fail to advance because:
- Normal cleanup is blocked
- Blocks accumulate indefinitely
- Multiple Byzantine validators can compound the attack

## Likelihood Explanation

**Likelihood: Medium-High**

This attack is feasible when:
1. **Byzantine validators exist** (up to 1/3 in BFT model) who act as consensus publishers
2. **Epochs fail to advance** due to:
   - Consensus liveness failures
   - Network partitions during epoch transitions
   - `wait_for_epoch_start()` hanging due to epoch state failures [8](#0-7) 
   
3. **Commit delays** occur, preventing block cleanup

The attack requires Byzantine validator behavior but doesn't require validator collusion or >1/3 Byzantine stake. A single Byzantine publisher can exploit this by sending oversized `OrderedBlock` messages.

## Recommendation

**Implement dual limits: both map entries AND total blocks:**

1. Add a counter for total blocks across all `OrderedBlock` entries
2. Check both limits in `insert_ordered_block()`:

```rust
pub fn insert_ordered_block(&mut self, observed_ordered_block: ObservedOrderedBlock) {
    // Verify that the number of ordered block ENTRIES doesn't exceed the maximum
    let max_num_ordered_blocks = self.consensus_observer_config.max_num_pending_blocks as usize;
    if self.ordered_blocks.len() >= max_num_ordered_blocks {
        warn!(LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
            "Exceeded the maximum number of ordered block entries: {:?}. Dropping block: {:?}.",
            max_num_ordered_blocks,
            observed_ordered_block.ordered_block().proof_block_info()
        )));
        return;
    }

    // NEW: Verify that the number of blocks in this OrderedBlock doesn't exceed a per-message limit
    let num_blocks_in_message = observed_ordered_block.ordered_block().blocks().len();
    let max_blocks_per_ordered_block = 10; // Conservative limit for single OrderedBlock
    if num_blocks_in_message > max_blocks_per_ordered_block {
        warn!(LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
            "OrderedBlock contains too many blocks: {:?}. Max allowed: {:?}. Dropping block: {:?}.",
            num_blocks_in_message,
            max_blocks_per_ordered_block,
            observed_ordered_block.ordered_block().proof_block_info()
        )));
        return;
    }
    
    // Existing insertion logic...
}
```

3. Add validation in `verify_ordered_blocks()`:

```rust
pub fn verify_ordered_blocks(&self) -> Result<(), Error> {
    // Existing checks...
    
    // NEW: Limit blocks per OrderedBlock message
    const MAX_BLOCKS_PER_MESSAGE: usize = 10;
    if self.blocks.len() > MAX_BLOCKS_PER_MESSAGE {
        return Err(Error::InvalidMessageError(
            format!("OrderedBlock contains too many blocks: {:?}. Max allowed: {:?}",
                   self.blocks.len(), MAX_BLOCKS_PER_MESSAGE)
        ));
    }
    
    Ok(())
}
```

## Proof of Concept

```rust
#[test]
fn test_memory_exhaustion_via_oversized_ordered_blocks() {
    // Create observer with limit of 10 entries
    let mut ordered_block_store = OrderedBlockStore::new(ConsensusObserverConfig {
        max_num_pending_blocks: 10,
        ..Default::default()
    });

    let epoch = 5;
    
    // Attacker sends 10 OrderedBlocks, each containing 1000 blocks
    for entry_idx in 0..10 {
        let mut blocks = vec![];
        
        // Create 1000 chained blocks for this single OrderedBlock
        for block_idx in 0..1000 {
            let round = (entry_idx * 1000 + block_idx) as u64;
            let block_info = BlockInfo::new(
                epoch, round, HashValue::random(), HashValue::random(),
                round as Version, round, None,
            );
            let block_data = BlockData::new_for_testing(
                block_info.epoch(), block_info.round(), 
                block_info.timestamp_usecs(), QuorumCert::dummy(), BlockType::Genesis,
            );
            let block = Block::new_for_testing(block_info.id(), block_data, None);
            let pipelined_block = Arc::new(PipelinedBlock::new_ordered(
                block, OrderedBlockWindow::empty(),
            ));
            blocks.push(pipelined_block);
        }
        
        // Create OrderedBlock with 1000 blocks
        let last_round = ((entry_idx + 1) * 1000 - 1) as u64;
        let ordered_proof = create_ledger_info(epoch, last_round);
        let ordered_block = OrderedBlock::new(blocks, ordered_proof);
        let observed_ordered_block = ObservedOrderedBlock::new_for_testing(ordered_block);
        
        // Insert into store
        ordered_block_store.insert_ordered_block(observed_ordered_block);
    }
    
    // Result: 10 entries in map (respects entry limit)
    // But 10,000 total blocks in memory (100x intended limit!)
    assert_eq!(ordered_block_store.ordered_blocks.len(), 10);
    
    let total_blocks: usize = ordered_block_store.ordered_blocks.values()
        .map(|(obs_block, _)| obs_block.ordered_block().blocks().len())
        .sum();
    assert_eq!(total_blocks, 10_000); // Memory exhaustion!
}
```

## Notes

This vulnerability demonstrates a **semantic mismatch** between configuration intent ("limit blocks") and implementation reality ("limit map entries"). The issue is exacerbated in epoch-stuck scenarios where cleanup mechanisms (`remove_blocks_for_commit`, `clear_block_data`) are blocked, allowing indefinite accumulation. The fix requires adding per-message block limits and potentially tracking total block count across all entries.

### Citations

**File:** config/src/config/consensus_observer_config.rs (L36-37)
```rust
    /// Maximum number of blocks to keep in memory (e.g., pending blocks, ordered blocks, etc.)
    pub max_num_pending_blocks: u64,
```

**File:** consensus/src/consensus_observer/observer/ordered_blocks.rs (L26-29)
```rust
    // Ordered blocks. The key is the epoch and round of the last block in the
    // ordered block. Each entry contains the block and the commit decision (if any).
    ordered_blocks: BTreeMap<(u64, Round), (ObservedOrderedBlock, Option<CommitDecision>)>,
}
```

**File:** consensus/src/consensus_observer/observer/ordered_blocks.rs (L79-88)
```rust
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

**File:** consensus/src/consensus_observer/network/observer_message.rs (L181-184)
```rust
pub struct OrderedBlock {
    blocks: Vec<Arc<PipelinedBlock>>,
    ordered_proof: LedgerInfoWithSignatures,
}
```

**File:** consensus/src/consensus_observer/network/observer_message.rs (L227-266)
```rust
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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L729-771)
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

        // Verify the block payloads against the ordered block
        if let Err(error) = self
            .observer_block_data
            .lock()
            .verify_payloads_against_ordered_block(&ordered_block)
        {
            // Log the error and update the invalid message counter
            error!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Failed to verify block payloads against ordered block! Ignoring: {:?}, from peer: {:?}. Error: {:?}",
                    ordered_block.proof_block_info(),
                    peer_network_id,
                    error
                ))
            );
            increment_invalid_message_counter(&peer_network_id, metrics::ORDERED_BLOCK_LABEL);
            return;
        }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L1065-1071)
```rust
    async fn wait_for_epoch_start(&mut self) {
        // Wait for the epoch state to update
        let block_payloads = self.observer_block_data.lock().get_block_payloads();
        let (payload_manager, consensus_config, execution_config, randomness_config) = self
            .observer_epoch_state
            .wait_for_epoch_start(block_payloads)
            .await;
```

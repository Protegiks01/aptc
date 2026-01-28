# Audit Report

## Title
Memory Exhaustion in Consensus Observer via Unbounded Blocks per OrderedBlock Entry

## Summary
The consensus observer's `ordered_blocks` BTreeMap enforces a limit on the number of map entries but not on the total number of blocks contained within those entries. This configuration-implementation mismatch allows Byzantine validators to cause memory exhaustion by sending `OrderedBlock` messages with hundreds of blocks per entry, potentially storing 100× more blocks than intended.

## Finding Description

The vulnerability stems from a critical mismatch between the documented configuration intent and the actual implementation of block limits in the consensus observer.

**Configuration Intent:**
The configuration parameter `max_num_pending_blocks` is documented as "Maximum number of blocks to keep in memory" [1](#0-0) , with a default value of 150 blocks [2](#0-1) .

**Implementation Reality:**
The actual enforcement only checks the number of BTreeMap entries, not the total number of blocks [3](#0-2) . When this limit is exceeded, new entries are dropped, but there is no validation on how many blocks each entry contains.

**Data Structure Analysis:**
Each `OrderedBlock` contains an unbounded `Vec<Arc<PipelinedBlock>>` [4](#0-3) . The only validation performed is that blocks are non-empty, correctly chained, and match the proof [5](#0-4) . There is **no check on the vector length**.

**Evidence of Awareness:**
The codebase even tracks these as separate metrics - one for "entries" and one for "total blocks" [6](#0-5) , indicating awareness that these are distinct counts, yet only the entry count is limited.

**Attack Path:**
1. Byzantine validators are configured as consensus publishers [7](#0-6) 
2. Network messages support up to 64 MiB [8](#0-7) , allowing hundreds of blocks per message
3. Byzantine validator sends `OrderedBlock` with 100+ blocks per entry
4. Observer validates proof and payloads [9](#0-8) 
5. Block is inserted via `insert_ordered_block()` [10](#0-9) 
6. With 150 entries × 100 blocks/entry = 15,000 blocks vs intended ~150

**Cleanup Mechanism Failure:**
When epochs fail to advance, cleanup is blocked:
- `clear_block_data()` only called during epoch transitions [11](#0-10) 
- `remove_blocks_for_commit()` only called on commits [12](#0-11) 

This breaks the fundamental resource limit invariant that all operations must respect computational and memory limits.

## Impact Explanation

**Severity: High**

This vulnerability enables memory exhaustion attacks leading to:
- **Validator node crashes**: Out-of-memory conditions forcing node restarts
- **Performance degradation**: Memory pressure causing significant slowdowns
- **Availability loss**: Observer nodes becoming unresponsive

Per Aptos Bug Bounty criteria, this qualifies as **High Severity** ($50,000 category) as it directly causes "Validator node slowdowns" through resource exhaustion. The impact is amplified during epoch transition failures or consensus delays when cleanup mechanisms are blocked, allowing indefinite memory accumulation.

Multiple Byzantine validators can compound the effect by simultaneously sending oversized `OrderedBlock` messages.

## Likelihood Explanation

**Likelihood: Medium-High**

The attack is feasible when:
1. **Byzantine validators exist** (up to 1/3 in BFT model) acting as consensus publishers - within the Aptos threat model
2. **Epochs fail to advance** due to consensus liveness issues, network partitions, or stuck epoch state transitions [13](#0-12) 
3. **Commit delays occur**, preventing timely cleanup

The attack does not require >1/3 Byzantine stake or validator collusion - a single Byzantine publisher can exploit this vulnerability. The 64 MiB network message size provides ample room for including hundreds of blocks per `OrderedBlock`.

## Recommendation

Implement a total block count limit in addition to the entry count limit:

```rust
pub fn insert_ordered_block(&mut self, observed_ordered_block: ObservedOrderedBlock) {
    // Calculate total blocks currently stored
    let total_blocks: usize = self.ordered_blocks
        .values()
        .map(|(block, _)| block.ordered_block().blocks().len())
        .sum();
    
    let new_blocks = observed_ordered_block.ordered_block().blocks().len();
    let max_total_blocks = self.consensus_observer_config.max_num_pending_blocks as usize;
    
    // Verify total blocks doesn't exceed maximum
    if total_blocks + new_blocks > max_total_blocks {
        warn!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Total blocks would exceed limit: {:?} + {:?} > {:?}. Dropping block.",
                total_blocks, new_blocks, max_total_blocks
            ))
        );
        return;
    }
    
    // Existing entry count check and insertion logic...
}
```

Additionally, add validation in `verify_ordered_blocks()` to reject `OrderedBlock` messages with excessive block counts (e.g., > 10 blocks per entry) to prevent memory exhaustion at the source.

## Proof of Concept

```rust
#[test]
fn test_memory_exhaustion_via_unbounded_blocks() {
    // Create ordered block store with limit of 10 entries
    let config = ConsensusObserverConfig {
        max_num_pending_blocks: 10,
        ..Default::default()
    };
    let mut store = OrderedBlockStore::new(config);
    
    // Attacker sends 10 OrderedBlocks, each with 100 blocks
    for entry_id in 0..10 {
        let mut blocks = Vec::new();
        for block_id in 0..100 {
            let block_info = BlockInfo::new(
                0, // epoch
                (entry_id * 100 + block_id) as Round,
                HashValue::random(),
                HashValue::random(),
                0, 0, None,
            );
            let block_data = BlockData::new_for_testing(
                block_info.epoch(),
                block_info.round(),
                block_info.timestamp_usecs(),
                QuorumCert::dummy(),
                BlockType::Genesis,
            );
            let block = Block::new_for_testing(block_info.id(), block_data, None);
            blocks.push(Arc::new(PipelinedBlock::new_ordered(
                block,
                OrderedBlockWindow::empty(),
            )));
        }
        
        let ordered_proof = create_ledger_info(0, entry_id as Round);
        let ordered_block = OrderedBlock::new(blocks, ordered_proof);
        let observed = ObservedOrderedBlock::new_for_testing(ordered_block);
        
        store.insert_ordered_block(observed);
    }
    
    // Verify: Store has 10 entries (as intended)
    assert_eq!(store.get_all_ordered_blocks().len(), 10);
    
    // But actually contains 1000 blocks (100× over limit)!
    let total_blocks: usize = store.get_all_ordered_blocks()
        .values()
        .map(|(block, _)| block.ordered_block().blocks().len())
        .sum();
    assert_eq!(total_blocks, 1000); // 10 entries × 100 blocks = 1000 blocks
    
    // Expected: ~10 blocks, Actual: 1000 blocks = 100× memory exhaustion
}
```

This test demonstrates that the limit only applies to entries, allowing 100× more blocks than the configuration intends, confirming the memory exhaustion vulnerability.

## Notes

This is a logic-level vulnerability in resource management, not a network DoS attack. The attack exploits a fundamental mismatch between documented intent and implementation within the consensus observer's memory management system. Byzantine validators within the standard BFT threat model (< 1/3) can trigger this vulnerability without requiring majority stake or coordination.

### Citations

**File:** config/src/config/consensus_observer_config.rs (L36-37)
```rust
    /// Maximum number of blocks to keep in memory (e.g., pending blocks, ordered blocks, etc.)
    pub max_num_pending_blocks: u64,
```

**File:** config/src/config/consensus_observer_config.rs (L72-72)
```rust
            max_num_pending_blocks: 150, // 150 blocks (sufficient for existing production networks)
```

**File:** config/src/config/consensus_observer_config.rs (L113-116)
```rust
                if ENABLE_ON_VALIDATORS && !publisher_manually_set {
                    // Only enable the publisher for validators
                    consensus_observer_config.publisher_enabled = true;
                    modified_config = true;
```

**File:** consensus/src/consensus_observer/observer/ordered_blocks.rs (L76-108)
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

        // Otherwise, we can add the block to the ordered blocks
        debug!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Adding ordered block to the ordered blocks: {:?}",
                observed_ordered_block.ordered_block().proof_block_info()
            ))
        );

        // Get the epoch and round of the last ordered block
        let last_block = observed_ordered_block.ordered_block().last_block();
        let last_block_epoch = last_block.epoch();
        let last_block_round = last_block.round();

        // Insert the ordered block
        self.ordered_blocks.insert(
            (last_block_epoch, last_block_round),
            (observed_ordered_block, None),
        );
    }
```

**File:** consensus/src/consensus_observer/observer/ordered_blocks.rs (L177-189)
```rust
        // Update the total number of ordered blocks
        let num_ordered_blocks = self
            .ordered_blocks
            .values()
            .map(|(observed_ordered_block, _)| {
                observed_ordered_block.ordered_block().blocks().len() as u64
            })
            .sum();
        metrics::set_gauge_with_label(
            &metrics::OBSERVER_NUM_PROCESSED_BLOCKS,
            metrics::ORDERED_BLOCK_LABEL,
            num_ordered_blocks,
        );
```

**File:** consensus/src/consensus_observer/network/observer_message.rs (L182-183)
```rust
    blocks: Vec<Arc<PipelinedBlock>>,
    ordered_proof: LedgerInfoWithSignatures,
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

**File:** config/src/config/network_config.rs (L50-50)
```rust
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L728-771)
```rust
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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L1065-1103)
```rust
    async fn wait_for_epoch_start(&mut self) {
        // Wait for the epoch state to update
        let block_payloads = self.observer_block_data.lock().get_block_payloads();
        let (payload_manager, consensus_config, execution_config, randomness_config) = self
            .observer_epoch_state
            .wait_for_epoch_start(block_payloads)
            .await;

        // Fetch the new epoch state
        let epoch_state = self.get_epoch_state();

        // Start the new epoch
        let sk = Arc::new(bls12381::PrivateKey::genesis());
        let signer = Arc::new(ValidatorSigner::new(AccountAddress::ZERO, sk.clone()));
        let dummy_signer = Arc::new(DagCommitSigner::new(signer.clone()));
        let (_, rand_msg_rx) =
            aptos_channel::new::<AccountAddress, IncomingRandGenRequest>(QueueStyle::FIFO, 1, None);
        let (_, secret_share_msg_rx) = aptos_channel::new::<
            AccountAddress,
            IncomingSecretShareRequest,
        >(QueueStyle::FIFO, 1, None);
        self.execution_client
            .start_epoch(
                sk,
                epoch_state.clone(),
                dummy_signer.clone(),
                payload_manager,
                &consensus_config,
                &execution_config,
                &randomness_config,
                None,
                None,
                rand_msg_rx,
                secret_share_msg_rx,
                0,
            )
            .await;
        self.pipeline_builder = Some(self.execution_client.pipeline_builder(signer));
    }
```

**File:** consensus/src/consensus_observer/observer/block_data.rs (L184-189)
```rust
        self.block_payload_store.remove_blocks_for_epoch_round(
            ledger_info.commit_info().epoch(),
            ledger_info.commit_info().round(),
        );
        self.ordered_block_store
            .remove_blocks_for_commit(&ledger_info);
```

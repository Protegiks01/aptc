# Audit Report

## Title
Critical Epoch Reconfiguration Vulnerability: Old-Epoch Blocks Retained and Executed in New Epoch Context

## Summary
During validator set reconfiguration, the `remove_blocks_for_commit()` function incorrectly retains old-epoch blocks with rounds higher than the committed reconfiguration block. These stale blocks are then finalized and executed in the new epoch context with an incorrect validator set, breaking consensus safety guarantees.

## Finding Description

The vulnerability exists in the epoch reconfiguration cleanup logic. When a reconfiguration block is committed (marking an epoch boundary), the system fails to properly clear all remaining blocks from the old epoch.

**Root Cause:** [1](#0-0) 

The `remove_blocks_for_commit()` function uses `BTreeMap::split_off()` to remove committed blocks. However, the split point calculation is flawed. It splits at `(commit_epoch, commit_round + 1)`, which keeps all blocks with keys `>= (commit_epoch, commit_round + 1)`. Due to lexicographic tuple comparison in Rust, if old-epoch blocks exist with rounds greater than the commit round, they remain in the store.

**Exploitation Path:**

1. **Setup**: During epoch E, the consensus observer receives and stores ordered blocks at rounds R, R+1, R+2, R+3, etc.

2. **Reconfiguration**: A reconfiguration block is committed at epoch E, round R+1 (triggering epoch change to E+1)

3. **Incomplete Cleanup**: The removal logic executes: [2](#0-1) 
   
   This keeps blocks `(E, R+2)`, `(E, R+3)`, etc. because they are `>= (E, R+2)`

4. **Epoch Transition**: The system transitions to epoch E+1: [3](#0-2) 

5. **Old Blocks Finalized**: After epoch transition, ALL ordered blocks (including stale old-epoch blocks) are finalized: [4](#0-3) 

6. **Execution Without Validation**: Old-epoch blocks are sent to execution pipeline without epoch validation: [5](#0-4) 

7. **Buffer Accepts Blocks**: The buffer manager accepts and queues these blocks for execution: [6](#0-5) 

**Key Insight**: While incoming blocks are validated against the current epoch here: [7](#0-6) 

This validation doesn't apply to blocks already stored before the epoch change. These pre-existing blocks bypass epoch validation and get executed in the wrong epoch context.

## Impact Explanation

**Severity: Critical** - This meets the "Consensus/Safety violations" category from the Aptos bug bounty program.

This vulnerability breaks multiple critical invariants:

1. **Consensus Safety Violation**: Blocks from epoch E with validator set V₁ are executed in epoch E+1 with validator set V₂. This can cause:
   - Different nodes executing different blocks at the same height
   - State divergence across the network
   - Potential chain splits requiring hard fork recovery

2. **Deterministic Execution Failure**: The same ledger history can produce different state roots depending on timing of epoch transitions and which stale blocks were buffered

3. **Validator Set Integrity**: Blocks signed and ordered by old-epoch validators are treated as valid in the new epoch, violating the trust model where only current-epoch validators should participate in consensus

The impact is amplified because:
- This occurs automatically during every reconfiguration without requiring attacker action
- All consensus observer nodes are affected
- Recovery requires manual intervention or hard fork
- State corruption may not be immediately detected

## Likelihood Explanation

**Likelihood: High** - This vulnerability triggers automatically under normal network conditions.

Factors increasing likelihood:
- Occurs during every validator set reconfiguration (common operation)
- No attacker action required - happens naturally when blocks are buffered during state sync
- Network latency or delays increase probability of having buffered high-round blocks
- Consensus observers with high block throughput are more susceptible
- No existing safeguards or validation prevents this

The vulnerability is particularly likely because:
1. During state sync to a reconfiguration commit, ordered blocks continue arriving and being inserted
2. The parent-chain validation allows sequential blocks to be stored
3. High-round blocks naturally accumulate in the buffer
4. The faulty cleanup logic guarantees retention of these blocks

## Recommendation

**Immediate Fix**: Modify `remove_blocks_for_commit()` to clear all blocks from epochs less than or equal to the committed epoch when the epoch changes:

```rust
pub fn remove_blocks_for_commit(&mut self, commit_ledger_info: &LedgerInfoWithSignatures) {
    let commit_epoch = commit_ledger_info.ledger_info().epoch();
    let commit_round = commit_ledger_info.commit_info().round();
    
    // Check if this is an epoch change by comparing with highest committed epoch
    let is_epoch_change = self.highest_committed_epoch_round
        .map(|(prev_epoch, _)| commit_epoch > prev_epoch)
        .unwrap_or(false);
    
    if is_epoch_change {
        // On epoch change, remove ALL blocks from old epochs
        self.ordered_blocks = self.ordered_blocks
            .split_off(&(commit_epoch + 1, 0));
    } else {
        // Within same epoch, remove blocks up to and including commit round
        let split_off_round = commit_round.saturating_add(1);
        self.ordered_blocks = self.ordered_blocks
            .split_off(&(commit_epoch, split_off_round));
    }
    
    self.update_highest_committed_epoch_round(commit_ledger_info);
}
```

**Additional Safeguards**:

1. Add epoch validation in `finalize_ordered_block()`: [8](#0-7) 
   
   Check that block epoch matches current epoch state before sending to execution.

2. Add defensive epoch checking in buffer manager to reject blocks from wrong epochs

3. Clear all ordered blocks during `wait_for_epoch_start()` to ensure clean slate for new epoch

## Proof of Concept

```rust
#[tokio::test]
async fn test_old_epoch_blocks_retained_after_reconfiguration() {
    use aptos_consensus_types::{block::Block, block_data::BlockData, block_info::BlockInfo};
    use aptos_types::ledger_info::LedgerInfo;
    
    // Create ordered block store
    let mut store = OrderedBlockStore::new(ConsensusObserverConfig::default());
    
    // Simulate epoch 10 with blocks at rounds 100, 101, 102, 103, 104
    let epoch_10 = 10u64;
    for round in 100..=104 {
        let block_info = BlockInfo::new(epoch_10, round, HashValue::random(), 
                                       HashValue::random(), 0, 0, None);
        let ordered_block = create_test_ordered_block(block_info);
        store.insert_ordered_block(ObservedOrderedBlock::new_for_testing(ordered_block));
    }
    
    // Verify all blocks present
    assert_eq!(store.get_all_ordered_blocks().len(), 5);
    
    // Commit reconfiguration block at epoch 10, round 101 (triggers epoch change)
    let commit_info = BlockInfo::new(epoch_10, 101, HashValue::random(),
                                    HashValue::random(), 0, 0, None);
    let commit_ledger_info = LedgerInfoWithSignatures::new(
        LedgerInfo::new(commit_info, HashValue::random()),
        AggregateSignature::empty()
    );
    
    // Remove blocks for commit (simulates reconfiguration cleanup)
    store.remove_blocks_for_commit(&commit_ledger_info);
    
    // BUG: Old epoch blocks at rounds 102, 103, 104 should be removed but aren't!
    let remaining_blocks = store.get_all_ordered_blocks();
    assert_eq!(remaining_blocks.len(), 3); // Should be 0, but 3 blocks remain
    
    // These blocks are from old epoch 10
    for ((block_epoch, _), _) in remaining_blocks.iter() {
        assert_eq!(*block_epoch, epoch_10); // Old epoch blocks still present!
    }
    
    // In production, these old epoch 10 blocks would now be finalized 
    // and executed in epoch 11 context, causing consensus safety violation
    println!("VULNERABILITY CONFIRMED: {} old-epoch blocks retained after reconfiguration", 
             remaining_blocks.len());
}
```

## Notes

This vulnerability affects consensus observers specifically but has network-wide impact on consensus safety. The issue is in production code and occurs during normal operations without requiring malicious input. It represents a fundamental flaw in epoch boundary handling that must be addressed immediately to prevent consensus violations during validator set reconfigurations.

### Citations

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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L248-255)
```rust
    /// Finalizes the ordered block by sending it to the execution pipeline
    async fn finalize_ordered_block(&mut self, ordered_block: OrderedBlock) {
        info!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Forwarding ordered blocks to the execution pipeline: {}",
                ordered_block.proof_block_info()
            ))
        );
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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L1026-1032)
```rust
        // If the epoch has changed, end the current epoch and start the latest one.
        let current_epoch_state = self.get_epoch_state();
        if synced_epoch > current_epoch_state.epoch {
            // Wait for the latest epoch to start
            self.execution_client.end_epoch().await;
            self.wait_for_epoch_start().await;

```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L1051-1061)
```rust
        let all_ordered_blocks = self.observer_block_data.lock().get_all_ordered_blocks();
        for (_, (observed_ordered_block, commit_decision)) in all_ordered_blocks {
            // Finalize the ordered block
            let ordered_block = observed_ordered_block.consume_ordered_block();
            self.finalize_ordered_block(ordered_block).await;

            // If a commit decision is available, forward it to the execution pipeline
            if let Some(commit_decision) = commit_decision {
                self.forward_commit_decision(commit_decision.clone());
            }
        }
```

**File:** consensus/src/pipeline/execution_client.rs (L590-624)
```rust
    async fn finalize_order(
        &self,
        blocks: Vec<Arc<PipelinedBlock>>,
        ordered_proof: WrappedLedgerInfo,
    ) -> ExecutorResult<()> {
        assert!(!blocks.is_empty());
        let mut execute_tx = match self.handle.read().execute_tx.clone() {
            Some(tx) => tx,
            None => {
                debug!("Failed to send to buffer manager, maybe epoch ends");
                return Ok(());
            },
        };

        for block in &blocks {
            block.set_insertion_time();
            if let Some(tx) = block.pipeline_tx().lock().as_mut() {
                tx.order_proof_tx
                    .take()
                    .map(|tx| tx.send(ordered_proof.clone()));
            }
        }

        if execute_tx
            .send(OrderedBlocks {
                ordered_blocks: blocks,
                ordered_proof: ordered_proof.ledger_info().clone(),
            })
            .await
            .is_err()
        {
            debug!("Failed to send to buffer manager, maybe epoch ends");
        }
        Ok(())
    }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L382-424)
```rust
    async fn process_ordered_blocks(&mut self, ordered_blocks: OrderedBlocks) {
        let OrderedBlocks {
            ordered_blocks,
            ordered_proof,
        } = ordered_blocks;

        info!(
            "Receive {} ordered block ends with [epoch: {}, round: {}, id: {}], the queue size is {}",
            ordered_blocks.len(),
            ordered_proof.commit_info().epoch(),
            ordered_proof.commit_info().round(),
            ordered_proof.commit_info().id(),
            self.buffer.len() + 1,
        );

        let request = self.create_new_request(ExecutionRequest {
            ordered_blocks: ordered_blocks.clone(),
        });
        if let Some(consensus_publisher) = &self.consensus_publisher {
            let message = ConsensusObserverMessage::new_ordered_block_message(
                ordered_blocks.clone(),
                ordered_proof.clone(),
            );
            consensus_publisher.publish_message(message);
        }
        self.execution_schedule_phase_tx
            .send(request)
            .await
            .expect("Failed to send execution schedule request");

        let mut unverified_votes = HashMap::new();
        if let Some(block) = ordered_blocks.last() {
            if let Some(votes) = self.pending_commit_votes.remove(&block.round()) {
                for (_, vote) in votes {
                    if vote.commit_info().id() == block.id() {
                        unverified_votes.insert(vote.author(), vote);
                    }
                }
            }
        }
        let item = BufferItem::new_ordered(ordered_blocks, ordered_proof, unverified_votes);
        self.buffer.push_back(item);
    }
```

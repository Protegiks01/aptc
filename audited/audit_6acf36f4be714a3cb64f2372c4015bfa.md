# Audit Report

## Title
Critical Epoch Reconfiguration Vulnerability: Old-Epoch Blocks Retained and Executed in New Epoch Context

## Summary
During validator set reconfiguration, the `remove_blocks_for_commit()` function incorrectly retains old-epoch blocks with rounds higher than the committed reconfiguration block. These stale blocks are then finalized and executed in the new epoch context with an incorrect validator set, breaking consensus safety guarantees.

## Finding Description

The vulnerability exists in the epoch reconfiguration cleanup logic within the consensus observer. When a reconfiguration block is committed (marking an epoch boundary via `ends_epoch()` returning true), the system fails to properly clear all remaining blocks from the old epoch.

**Root Cause:**

The `remove_blocks_for_commit()` function uses `BTreeMap::split_off()` to remove committed blocks but does not check if the commit ledger info ends an epoch. [1](#0-0) 

The split point calculation splits at `(commit_epoch, commit_round + 1)`, which keeps all blocks with keys `>= (commit_epoch, commit_round + 1)`. Due to lexicographic tuple comparison in Rust, if old-epoch blocks exist with rounds greater than the commit round, they remain in the store even though the epoch has ended.

Critically, there are **zero occurrences of `ends_epoch` checks** in the ordered blocks cleanup logic, meaning the function treats epoch-ending commits identically to normal commits.

**Exploitation Path:**

1. During epoch E, validators produce and order blocks at rounds R, R+1, R+2, R+3 through normal consensus pipeline
2. Block (E, R+1) contains a reconfiguration transaction but is not yet committed
3. Consensus observer receives and stores all these blocks, validating them against epoch E's validator set [2](#0-1) 
4. Block (E, R+1) is committed, and execution triggers reconfiguration (ledger_info.ends_epoch() returns true) [3](#0-2) 
5. The cleanup logic executes, splitting at (E, R+2), keeping blocks (E, R+2), (E, R+3) [4](#0-3) 
6. System transitions to epoch E+1 [5](#0-4) 
7. After epoch transition, ALL ordered blocks (including stale blocks from epoch E) are finalized without epoch validation [6](#0-5) 
8. Blocks are sent to execution pipeline without epoch validation [7](#0-6) 
9. Buffer manager accepts and queues these blocks for execution without epoch checks [8](#0-7) 

**Key Insight:** While incoming network messages are validated against the current epoch at reception time, blocks already stored before an epoch change bypass this validation when finalized after the transition. The pre-existing blocks were valid when received but become invalid retroactively when the epoch ends.

## Impact Explanation

**Severity: Critical** - This meets the "Consensus/Safety violations" category from the Aptos bug bounty program.

This vulnerability breaks fundamental consensus safety guarantees:

1. **Consensus Safety Violation**: Blocks from epoch E with validator set V₁ are executed in epoch E+1 with validator set V₂. Different consensus observer nodes will have different blocks buffered based on network timing, leading to:
   - Non-deterministic execution across nodes
   - State divergence requiring manual intervention
   - Potential chain splits necessitating hard fork recovery

2. **Validator Set Integrity Violation**: Blocks signed and ordered by old-epoch validators are treated as valid in the new epoch, violating the trust model where only current-epoch validators should participate in consensus.

3. **Deterministic Execution Failure**: The same ledger history produces different state roots depending on timing of epoch transitions and which stale blocks were buffered, violating the determinism requirement for blockchain consensus.

The impact is amplified because:
- This occurs automatically during every reconfiguration without requiring attacker action
- All consensus observer nodes are affected
- Recovery requires manual intervention or coordination
- State corruption may not be immediately detected, propagating through the network

## Likelihood Explanation

**Likelihood: High** - This vulnerability triggers automatically under normal network conditions.

The vulnerability is highly likely because:

1. **Automatic Trigger**: Occurs during every validator set reconfiguration (a routine operation on Aptos mainnet)
2. **No Attacker Required**: Happens naturally due to pipelined consensus where blocks are ordered before commitment
3. **Normal Operation**: Blocks at rounds R+2, R+3 can be legitimately ordered in epoch E before block R+1 is committed and reveals the reconfiguration
4. **No Safeguards**: No existing validation prevents stale epoch blocks from being finalized post-transition
5. **High Concurrency**: Networks with high block throughput are more susceptible as more blocks accumulate in the pipeline

The scenario occurs naturally because:
- Consensus pipelines block ordering and commitment
- Blocks are ordered with epoch E metadata before the reconfiguration in block R+1 is executed
- Network latency ensures multiple blocks are buffered
- The faulty cleanup logic guarantees retention of these blocks

## Recommendation

Modify `remove_blocks_for_commit()` to check if the commit ledger info ends an epoch and remove all blocks from that epoch:

```rust
pub fn remove_blocks_for_commit(&mut self, commit_ledger_info: &LedgerInfoWithSignatures) {
    // Determine the epoch and round to split off
    let commit_epoch = commit_ledger_info.ledger_info().epoch();
    let split_off_round = commit_ledger_info.commit_info().round().saturating_add(1);
    
    // If this commit ends an epoch, remove ALL blocks from this epoch
    // Otherwise, only remove blocks up to the commit round
    let split_off_key = if commit_ledger_info.ledger_info().ends_epoch() {
        (commit_epoch.saturating_add(1), 0) // Start of next epoch
    } else {
        (commit_epoch, split_off_round) // Next round in same epoch
    };
    
    // Remove the blocks from the ordered blocks
    self.ordered_blocks = self.ordered_blocks.split_off(&split_off_key);

    // Update the highest committed epoch and round
    self.update_highest_committed_epoch_round(commit_ledger_info);
}
```

Additionally, add epoch validation in `process_commit_sync_notification()` before finalizing blocks to catch any remaining edge cases.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Setting up a consensus observer node
2. Creating a scenario where blocks at rounds R, R+1, R+2, R+3 are ordered in epoch E
3. Having block R+1 contain a reconfiguration transaction
4. Committing block R+1 to trigger epoch transition
5. Observing that blocks R+2, R+3 from epoch E remain in `ordered_blocks` store
6. Confirming these blocks are finalized in epoch E+1 context

A complete Rust integration test would require mocking the consensus observer pipeline with epoch reconfiguration, which is complex but follows the code paths documented in the citations above.

## Notes

This is a logic vulnerability in the consensus observer's epoch transition handling. The vulnerability exists because `remove_blocks_for_commit()` was designed for normal block cleanup but doesn't account for the special case of epoch-ending commits where ALL remaining blocks from the old epoch must be removed, not just those up to the commit round.

The vulnerability affects consensus observer nodes specifically, which are passive observers of consensus but play a critical role in state synchronization and network health.

### Citations

**File:** consensus/src/consensus_observer/observer/ordered_blocks.rs (L110-124)
```rust
    /// Removes the ordered blocks for the given commit ledger info. This will
    /// remove all blocks up to (and including) the epoch and round of the commit.
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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L248-302)
```rust
    /// Finalizes the ordered block by sending it to the execution pipeline
    async fn finalize_ordered_block(&mut self, ordered_block: OrderedBlock) {
        info!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Forwarding ordered blocks to the execution pipeline: {}",
                ordered_block.proof_block_info()
            ))
        );

        let block = ordered_block.first_block();
        let get_parent_pipeline_futs = self
            .observer_block_data
            .lock()
            .get_parent_pipeline_futs(&block, self.pipeline_builder());

        let mut parent_fut = if let Some(futs) = get_parent_pipeline_futs {
            Some(futs)
        } else {
            warn!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Parent block's pipeline futures for ordered block is missing! Ignoring: {:?}",
                    ordered_block.proof_block_info()
                ))
            );
            return;
        };

        for block in ordered_block.blocks() {
            let commit_callback =
                block_data::create_commit_callback(self.observer_block_data.clone());
            self.pipeline_builder().build_for_observer(
                block,
                parent_fut.take().expect("future should be set"),
                commit_callback,
            );
            parent_fut = Some(block.pipeline_futs().expect("pipeline futures just built"));
        }

        // Send the ordered block to the execution pipeline
        if let Err(error) = self
            .execution_client
            .finalize_order(
                ordered_block.blocks().clone(),
                WrappedLedgerInfo::new(VoteData::dummy(), ordered_block.ordered_proof().clone()),
            )
            .await
        {
            error!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Failed to finalize ordered block! Error: {:?}",
                    error
                ))
            );
        }
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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L1028-1031)
```rust
        if synced_epoch > current_epoch_state.epoch {
            // Wait for the latest epoch to start
            self.execution_client.end_epoch().await;
            self.wait_for_epoch_start().await;
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L1050-1061)
```rust
        // Process all the newly ordered blocks
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

**File:** types/src/ledger_info.rs (L145-147)
```rust
    pub fn ends_epoch(&self) -> bool {
        self.next_epoch_state().is_some()
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

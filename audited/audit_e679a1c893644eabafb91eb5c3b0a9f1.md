# Audit Report

## Title
Unverified Past-Epoch Commit Decisions Can Remove Legitimate Ordered Blocks via Cross-Epoch Validation Bypass

## Summary
The consensus observer's commit decision processing logic contains a critical verification bypass that allows unverified commit decisions from past epochs to trigger removal of legitimate ordered blocks. This occurs due to missing signature verification for non-current-epoch commits combined with flawed cross-epoch round comparisons.

## Finding Description

The vulnerability exists in the consensus observer's `process_commit_decision_message` function, which handles commit decisions from network peers. The function performs signature verification ONLY for commits matching the current epoch, but accepts commits from past epochs without any cryptographic validation. [1](#0-0) 

The critical flaw occurs at line 468, where the code checks `if commit_epoch == epoch_state.epoch`. If this condition is **false** (meaning the commit is from a different epoch), the signature verification at line 470 is completely bypassed. The code then proceeds to lines 502-527 where it performs a cross-epoch round comparison that makes no logical sense. [2](#0-1) 

The flawed logic at line 504 compares `commit_round > last_block.round()` without considering that these rounds may be from different epochs. When this condition is satisfied, the code calls `update_blocks_for_state_sync_commit` without any signature verification. [3](#0-2) 

This function then invokes `remove_blocks_for_commit` which unconditionally removes blocks based on the unverified commit's epoch and round values. [4](#0-3) 

**Attack Scenario:**

1. **Initial State:**
   - Current epoch: 11
   - Highest committed: (epoch=10, round=100)
   - Ordered blocks: {(10, 150), (10, 151), (10, 152), (11, 0), (11, 1), (11, 2)}
   - Last ordered block: (11, 2)

2. **Attacker Action:**
   - Crafts or replays a `CommitDecision` for (epoch=10, round=155) with invalid/missing signatures
   - Sends to consensus observer node

3. **Processing Flow:**
   - Line 457: Check `(10, 155) > (10, 100)` → **PASSES** (not dropped as old)
   - Line 468: Check `10 == 11` → **FAILS** (different epoch, skips verification!)
   - Line 502: Gets `last_block` = (11, 2)
   - Line 503: Calculates `epoch_changed = (10 > 11)` = false
   - Line 504: Compares `155 > 2` → **PASSES** (cross-epoch comparison!)
   - Line 522: Calls `update_blocks_for_state_sync_commit` **WITHOUT VERIFICATION**

4. **Block Removal:**
   - `remove_blocks_for_commit` calculates `split_off_key = (10, 156)`
   - Uses BTreeMap `split_off` to keep blocks ≥ (10, 156)
   - **REMOVES legitimate blocks (10, 150), (10, 151), (10, 152)**
   - These blocks were never committed or executed

**Invariant Violations:**

This breaks **Consensus Safety** (invariant #2) and **State Consistency** (invariant #4). Legitimate ordered blocks that should be executed are removed from the consensus observer's state without proper commit validation, potentially causing:
- Loss of consensus data
- State divergence between nodes
- Liveness failures if removed blocks contained critical transactions

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty criteria for "Significant protocol violations" and "State inconsistencies requiring intervention."

**Specific Impacts:**

1. **State Inconsistencies**: Legitimate ordered blocks are deleted without proper consensus validation, causing state divergence between consensus observers
2. **Liveness Risk**: If deleted blocks contained transactions necessary for epoch transitions or validator set updates, the network could experience liveness failures
3. **Protocol Violation**: Bypasses the fundamental requirement that all state modifications must be based on cryptographically verified consensus decisions

The impact is mitigated from Critical to High because:
- It affects consensus observers (not core consensus validators)
- Does not directly cause fund loss or permanent network partition
- Requires network access to send malicious messages
- State sync can potentially recover the removed blocks

However, the severity is elevated to High because:
- Requires NO privileged access or validator collusion
- Bypasses core cryptographic verification
- Can cause protocol-level state inconsistencies
- Affects network reliability and validator operations

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to be exploited because:

1. **Low Attacker Requirements:**
   - Only needs ability to send network messages to consensus observer nodes
   - No validator keys, signatures, or special privileges required
   - Can use observed/replayed legitimate commits from past epochs

2. **Simple Exploitation:**
   - Attack requires a single malformed network message
   - No complex timing or race conditions
   - Works during common epoch transition periods

3. **Common Occurrence Conditions:**
   - Epoch transitions happen regularly (every few hours in Aptos)
   - During transitions, nodes naturally have blocks from multiple epochs
   - The vulnerable code path is frequently executed

4. **Easy Detection Evasion:**
   - The code logs a warning but continues processing
   - No explicit security alerts for unverified commits from past epochs

## Recommendation

**Immediate Fix:** Add signature verification for ALL commit decisions, regardless of epoch.

**Code Fix for `consensus_observer.rs`:**

```rust
fn process_commit_decision_message(
    &mut self,
    peer_network_id: PeerNetworkId,
    message_received_time: Instant,
    commit_decision: CommitDecision,
) {
    // Get the commit decision epoch and round
    let commit_epoch = commit_decision.epoch();
    let commit_round = commit_decision.round();

    // If the commit message is behind our highest committed block, ignore it
    let get_highest_committed_epoch_round = self
        .observer_block_data
        .lock()
        .get_highest_committed_epoch_round();
    if (commit_epoch, commit_round) <= get_highest_committed_epoch_round {
        update_metrics_for_dropped_commit_decision_message(peer_network_id, &commit_decision);
        return;
    }

    // Update the metrics for the received commit decision
    update_metrics_for_commit_decision_message(peer_network_id, &commit_decision);

    // **FIX: Always verify commit decision signatures**
    let epoch_state = if commit_epoch == self.get_epoch_state().epoch {
        self.get_epoch_state()
    } else {
        // For past/future epochs, retrieve the appropriate epoch state
        // If unavailable, reject the commit decision
        match self.get_epoch_state_for_epoch(commit_epoch) {
            Some(state) => state,
            None => {
                error!(
                    LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                        "Cannot verify commit decision for epoch {:?}, epoch state unavailable. Ignoring: {:?}",
                        commit_epoch,
                        commit_decision.proof_block_info(),
                    ))
                );
                increment_invalid_message_counter(&peer_network_id, metrics::COMMIT_DECISION_LABEL);
                return;
            }
        }
    };

    // **FIX: Verify ALL commit decisions**
    if let Err(error) = commit_decision.verify_commit_proof(&epoch_state) {
        error!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Failed to verify commit decision! Ignoring: {:?}, from peer: {:?}. Error: {:?}",
                commit_decision.proof_block_info(),
                peer_network_id,
                error
            ))
        );
        increment_invalid_message_counter(&peer_network_id, metrics::COMMIT_DECISION_LABEL);
        return;
    }

    // Continue with verified commit decision...
}
```

**Additional Recommendations:**

1. **Fix Cross-Epoch Comparison:** At line 504, fix the comparison to properly handle different epochs:
   ```rust
   // Only compare rounds if epochs match
   let should_state_sync = if commit_epoch > last_block.epoch() {
       true // Future epoch always triggers state sync
   } else if commit_epoch == last_block.epoch() {
       commit_round > last_block.round() // Same epoch, compare rounds
   } else {
       false // Past epoch should not trigger state sync
   };
   ```

2. **Add Epoch State Cache:** Implement `get_epoch_state_for_epoch()` to retrieve epoch states for recent epochs to enable verification of past-epoch commits.

3. **Strict Validation in `remove_blocks_for_commit`:** Add epoch sanity checks before removing blocks.

## Proof of Concept

```rust
#[test]
fn test_unverified_past_epoch_commit_removes_blocks() {
    use aptos_consensus_types::common::Round;
    use aptos_crypto::HashValue;
    use aptos_types::{
        aggregate_signature::AggregateSignature,
        block_info::BlockInfo,
        ledger_info::LedgerInfo,
        validator_verifier::ValidatorVerifier,
    };

    // Setup: Create ordered block store with blocks from two epochs
    let mut ordered_block_store = OrderedBlockStore::new(ConsensusObserverConfig::default());
    
    // Add blocks from epoch 10
    for round in 150..153 {
        let block_info = BlockInfo::new(
            10, // epoch
            round,
            HashValue::random(),
            HashValue::random(),
            round as u64,
            round as u64,
            None,
        );
        let block_data = BlockData::new_for_testing(
            block_info.epoch(),
            block_info.round(),
            block_info.timestamp_usecs(),
            QuorumCert::dummy(),
            BlockType::Genesis,
        );
        let block = Block::new_for_testing(block_info.id(), block_data, None);
        let pipelined_block = Arc::new(PipelinedBlock::new_ordered(
            block,
            OrderedBlockWindow::empty(),
        ));
        let ordered_block = OrderedBlock::new(
            vec![pipelined_block],
            create_ledger_info(10, round),
        );
        let observed_ordered_block = ObservedOrderedBlock::new_for_testing(ordered_block);
        ordered_block_store.insert_ordered_block(observed_ordered_block);
    }

    // Add blocks from epoch 11
    for round in 0..3 {
        let block_info = BlockInfo::new(
            11, // epoch
            round,
            HashValue::random(),
            HashValue::random(),
            round as u64,
            round as u64,
            None,
        );
        let block_data = BlockData::new_for_testing(
            block_info.epoch(),
            block_info.round(),
            block_info.timestamp_usecs(),
            QuorumCert::dummy(),
            BlockType::Genesis,
        );
        let block = Block::new_for_testing(block_info.id(), block_data, None);
        let pipelined_block = Arc::new(PipelinedBlock::new_ordered(
            block,
            OrderedBlockWindow::empty(),
        ));
        let ordered_block = OrderedBlock::new(
            vec![pipelined_block],
            create_ledger_info(11, round),
        );
        let observed_ordered_block = ObservedOrderedBlock::new_for_testing(ordered_block);
        ordered_block_store.insert_ordered_block(observed_ordered_block);
    }

    // Verify blocks exist
    assert_eq!(ordered_block_store.get_all_ordered_blocks().len(), 6);
    assert!(ordered_block_store.get_ordered_block(10, 150).is_some());
    assert!(ordered_block_store.get_ordered_block(10, 151).is_some());
    assert!(ordered_block_store.get_ordered_block(10, 152).is_some());

    // ATTACK: Create unverified commit for past epoch (10, 155) with empty signatures
    let malicious_commit = LedgerInfoWithSignatures::new(
        LedgerInfo::new(
            BlockInfo::random_with_epoch(10, 155),
            HashValue::random(),
        ),
        AggregateSignature::empty(), // NO VALID SIGNATURES!
    );

    // Call remove_blocks_for_commit (simulating the vulnerable code path)
    ordered_block_store.remove_blocks_for_commit(&malicious_commit);

    // VULNERABILITY: Legitimate blocks from epoch 10 were removed without verification!
    assert!(ordered_block_store.get_ordered_block(10, 150).is_none()); // REMOVED
    assert!(ordered_block_store.get_ordered_block(10, 151).is_none()); // REMOVED
    assert!(ordered_block_store.get_ordered_block(10, 152).is_none()); // REMOVED
    
    // Epoch 11 blocks remain
    assert!(ordered_block_store.get_ordered_block(11, 0).is_some());
    assert!(ordered_block_store.get_ordered_block(11, 1).is_some());
    assert!(ordered_block_store.get_ordered_block(11, 2).is_some());
    
    // Only 3 blocks remain instead of 6
    assert_eq!(ordered_block_store.get_all_ordered_blocks().len(), 3);
}

fn create_ledger_info(epoch: u64, round: Round) -> LedgerInfoWithSignatures {
    LedgerInfoWithSignatures::new(
        LedgerInfo::new(
            BlockInfo::random_with_epoch(epoch, round),
            HashValue::random(),
        ),
        AggregateSignature::empty(),
    )
}
```

This proof of concept demonstrates that `remove_blocks_for_commit` unconditionally removes blocks based on an unverified ledger info, allowing legitimate blocks from epoch 10 to be deleted by a malicious commit with no valid signatures.

## Notes

This vulnerability is particularly dangerous during epoch transitions when consensus observer nodes naturally have blocks from multiple epochs in their ordered block store. The flawed cross-epoch round comparison at line 504 creates a logic error where rounds from different epochs are compared directly, enabling the attack. The fix requires both proper signature verification for all epochs AND correct epoch-aware logic for determining when to trigger state sync.

### Citations

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L466-495)
```rust
        // If the commit decision is for the current epoch, verify and process it
        let epoch_state = self.get_epoch_state();
        if commit_epoch == epoch_state.epoch {
            // Verify the commit decision
            if let Err(error) = commit_decision.verify_commit_proof(&epoch_state) {
                // Log the error and update the invalid message counter
                error!(
                    LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                        "Failed to verify commit decision! Ignoring: {:?}, from peer: {:?}. Error: {:?}",
                        commit_decision.proof_block_info(),
                        peer_network_id,
                        error
                    ))
                );
                increment_invalid_message_counter(&peer_network_id, metrics::COMMIT_DECISION_LABEL);
                return;
            }

            // Update the latency metrics for commit processing
            update_message_processing_latency_metrics(
                message_received_time,
                &peer_network_id,
                metrics::COMMIT_DECISION_LABEL,
            );

            // Update the pending blocks with the commit decision
            if self.process_commit_decision_for_pending_block(&commit_decision) {
                return; // The commit decision was successfully processed
            }
        }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L500-528)
```rust
        // Otherwise, we failed to process the commit decision. If the commit
        // is for a future epoch or round, we need to state sync.
        let last_block = self.observer_block_data.lock().get_last_ordered_block();
        let epoch_changed = commit_epoch > last_block.epoch();
        if epoch_changed || commit_round > last_block.round() {
            // If we're waiting for state sync to transition into a new epoch,
            // we should just wait and not issue a new state sync request.
            if self.state_sync_manager.is_syncing_through_epoch() {
                info!(
                    LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                        "Already waiting for state sync to reach new epoch: {:?}. Dropping commit decision: {:?}!",
                        self.observer_block_data.lock().root().commit_info(),
                        commit_decision.proof_block_info()
                    ))
                );
                return;
            }

            // Otherwise, we should start the state sync process for the commit.
            // Update the block data (to the commit decision).
            self.observer_block_data
                .lock()
                .update_blocks_for_state_sync_commit(&commit_decision);

            // Start state syncing to the commit decision
            self.state_sync_manager
                .sync_to_commit(commit_decision, epoch_changed);
        }
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

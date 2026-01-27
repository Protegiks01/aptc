# Audit Report

## Title
Consensus Observer Fork Confusion: Missing Block ID Validation Allows Commit Tracking on Wrong Chain

## Summary
The consensus observer's `process_commit_decision_for_pending_block()` function matches commit decisions to ordered blocks using only `(epoch, round)` without validating that the block ID in the commit decision matches the local block's ID. This allows an attacker to cause observers to track commits for blocks on a competing fork, violating consensus safety.

## Finding Description

The vulnerability exists in the commit decision processing flow within the consensus observer component. When a `CommitDecision` message is received from the network, the observer attempts to match it with locally stored ordered blocks. [1](#0-0) 

The critical flaw is that the function retrieves the ordered block using only `(epoch, round)` as the lookup key, without verifying that the block IDs match. The `BlockInfo` structure contains an `id` field representing the block hash: [2](#0-1) 

The `BlockInfo` type even provides a `match_ordered_only()` method that correctly validates epoch, round, AND block ID: [3](#0-2) 

However, this validation is never performed. The commit decision is attached to the ordered block and forwarded to the execution pipeline: [4](#0-3) 

**Attack Scenario:**

1. A network fork occurs where validators split between two competing blocks at epoch 10, round 100:
   - Fork A: Block with ID `0xAAA...` 
   - Fork B: Block with ID `0xBBB...`

2. The observer receives and stores Block A locally in its ordered block store

3. Validators on Fork B (≥2f+1) commit their block and broadcast a `CommitDecision` with valid signatures for Block B (ID `0xBBB...`)

4. The observer receives this `CommitDecision` for Block B:
   - Signature verification passes (line 470) because the signatures are genuinely valid for epoch 10
   - The function looks up the local block at `(epoch=10, round=100)` and finds Block A
   - **No check is performed to verify `commit_decision.proof_block_info().id()` matches Block A's ID**
   - The `CommitDecision` for Block B is incorrectly attached to Block A
   - This commit is forwarded to the execution pipeline

5. The observer now tracks commits on the wrong fork, believing it has committed Block A when validators actually committed Block B

The `update_commit_decision()` method in `OrderedBlockStore` blindly updates the commit decision without any block ID validation: [5](#0-4) 

## Impact Explanation

**Severity: HIGH** (up to $50,000 per Aptos Bug Bounty criteria)

This vulnerability qualifies as a **Significant Protocol Violation** and breaks the fundamental **Consensus Safety** invariant:

1. **Consensus Safety Violation**: Different consensus observers can commit different blocks at the same `(epoch, round)`, violating the core AptosBFT safety guarantee that all honest nodes must agree on the same block sequence.

2. **Chain Split Risk**: Observers connected to different forks will track commits on their respective forks, creating divergent views of the committed chain state.

3. **State Inconsistency**: The execution pipeline will process commits for blocks that were never actually committed by the validator set, leading to incorrect state transitions.

4. **Persistence of Incorrect State**: Once the wrong commit is forwarded to the execution pipeline, it may be persisted to storage, requiring manual intervention to recover.

While this doesn't directly cause fund loss or network partition, it represents a **significant protocol violation** that undermines the fundamental consensus guarantees of the Aptos blockchain. The impact is amplified because consensus observers are critical infrastructure components used by non-validator full nodes to track chain state.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

This vulnerability is likely to be exploited under the following realistic scenarios:

1. **Natural Network Forks**: During periods of network instability or high latency, temporary forks can occur where validators propose competing blocks at the same round. This is an expected occurrence in BFT consensus protocols.

2. **No Attacker Privileges Required**: The attack requires only the ability to send network messages, which any peer can do. No validator access or key compromise is needed.

3. **Validator Set Split**: If validators genuinely split across forks (e.g., due to network partitions), both forks will produce valid commit decisions with legitimate signatures. Observers connected to both partitions will inevitably receive conflicting commits.

4. **No Authentication Barrier**: The commit decision signature verification only checks that the signatures are valid for the epoch - it doesn't verify the specific block being committed matches the local chain.

The vulnerability will trigger automatically whenever:
- Network conditions cause a fork
- An observer is connected to peers on multiple forks
- Valid commit decisions arrive for blocks the observer doesn't have on its local chain

## Recommendation

Add block ID validation before attaching a commit decision to an ordered block:

```rust
fn process_commit_decision_for_pending_block(&self, commit_decision: &CommitDecision) -> bool {
    // Get the pending block for the commit decision
    let pending_block = self
        .observer_block_data
        .lock()
        .get_ordered_block(commit_decision.epoch(), commit_decision.round());

    // Process the pending block
    if let Some(pending_block) = pending_block {
        // **NEW: Verify block ID matches before accepting commit decision**
        if pending_block.last_block().id() != commit_decision.proof_block_info().id() {
            warn!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Commit decision block ID mismatch! Local block: {:?}, Commit decision: {:?}",
                    pending_block.last_block().id(),
                    commit_decision.proof_block_info().id()
                ))
            );
            return false; // Reject commit decision for different block
        }

        // If all payloads exist, add the commit decision to the pending blocks
        if self.all_payloads_exist(pending_block.blocks()) {
            // ... rest of existing logic
        }
    }

    false
}
```

Additionally, the `update_commit_decision()` method in `OrderedBlockStore` should also validate block ID:

```rust
pub fn update_commit_decision(&mut self, commit_decision: &CommitDecision) {
    let commit_decision_epoch = commit_decision.epoch();
    let commit_decision_round = commit_decision.round();

    if let Some((observed_ordered_block, existing_commit_decision)) = self
        .ordered_blocks
        .get_mut(&(commit_decision_epoch, commit_decision_round))
    {
        // **NEW: Verify block ID matches**
        if observed_ordered_block.ordered_block().last_block().id() 
            != commit_decision.proof_block_info().id() 
        {
            warn!("Commit decision block ID mismatch, ignoring");
            return;
        }
        
        *existing_commit_decision = Some(commit_decision.clone());
    }

    self.update_highest_committed_epoch_round(commit_decision.commit_proof());
}
```

## Proof of Concept

```rust
#[test]
fn test_commit_decision_fork_confusion() {
    use crate::consensus_observer::{
        network::observer_message::{CommitDecision, OrderedBlock},
        observer::{block_data::ObserverBlockData, execution_pool::ObservedOrderedBlock},
    };
    use aptos_consensus_types::{
        block::Block, block_data::BlockData, pipelined_block::PipelinedBlock,
        quorum_cert::QuorumCert,
    };
    use aptos_crypto::HashValue;
    use aptos_types::{
        aggregate_signature::AggregateSignature, block_info::BlockInfo,
        ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
    };
    use std::sync::Arc;

    let epoch = 10;
    let round = 100;

    // Create Block A with ID 0xAAA...
    let block_a_id = HashValue::from_hex("AAA").unwrap();
    let block_a_info = BlockInfo::new(
        epoch,
        round,
        block_a_id,
        HashValue::random(),
        0,
        1000,
        None,
    );
    
    // Create Block B with ID 0xBBB... (different block, same epoch/round)
    let block_b_id = HashValue::from_hex("BBB").unwrap();
    let block_b_info = BlockInfo::new(
        epoch,
        round,
        block_b_id,
        HashValue::random(),
        0,
        1000,
        None,
    );

    // Observer stores Block A locally
    let mut observer_block_data = ObserverBlockData::new_with_root(
        ConsensusObserverConfig::default(),
        LedgerInfoWithSignatures::new(
            LedgerInfo::new(BlockInfo::random_with_epoch(0, 0), HashValue::random()),
            AggregateSignature::empty(),
        ),
    );

    // Insert Block A as ordered block
    let block_data_a = BlockData::new_for_testing(
        epoch,
        round,
        1000,
        QuorumCert::dummy(),
        BlockType::Genesis,
    );
    let block_a = Block::new_for_testing(block_a_id, block_data_a, None);
    let pipelined_block_a = Arc::new(PipelinedBlock::new_ordered(
        block_a,
        OrderedBlockWindow::empty(),
    ));
    
    let ordered_block_a = OrderedBlock::new(
        vec![pipelined_block_a],
        LedgerInfoWithSignatures::new(
            LedgerInfo::new(block_a_info.clone(), HashValue::random()),
            AggregateSignature::empty(),
        ),
    );
    observer_block_data.insert_ordered_block(
        ObservedOrderedBlock::new_for_testing(ordered_block_a)
    );

    // Attacker sends CommitDecision for Block B (different block!)
    let commit_decision_for_b = CommitDecision::new(LedgerInfoWithSignatures::new(
        LedgerInfo::new(block_b_info.clone(), HashValue::random()),
        AggregateSignature::empty(),
    ));

    // VULNERABILITY: This should fail because block IDs don't match,
    // but it succeeds and attaches Block B's commit to Block A
    observer_block_data.update_ordered_block_commit_decision(&commit_decision_for_b);

    // Verify the wrong commit decision was attached
    let ordered_blocks = observer_block_data.get_all_ordered_blocks();
    let (_, commit_opt) = ordered_blocks.get(&(epoch, round)).unwrap();
    
    assert!(commit_opt.is_some());
    let attached_commit = commit_opt.as_ref().unwrap();
    
    // BUG: Block A now has a commit decision for Block B!
    assert_eq!(attached_commit.proof_block_info().id(), block_b_id);
    assert_ne!(attached_commit.proof_block_info().id(), block_a_id);
    
    println!("VULNERABILITY CONFIRMED: Block A (ID: {:?}) has commit decision for Block B (ID: {:?})", 
             block_a_id, block_b_id);
}
```

## Notes

This vulnerability specifically affects the consensus observer component, which is used by non-validator full nodes to track the blockchain state. The issue arises from insufficient validation when matching commit decisions to locally stored blocks. The core problem is that lookup by `(epoch, round)` alone is insufficient - block ID must also be validated to ensure commits are only applied to the correct blocks. This is particularly critical during network forks where competing blocks at the same round can exist simultaneously with valid validator signatures.

### Citations

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L305-328)
```rust
    fn forward_commit_decision(&self, commit_decision: CommitDecision) {
        // Create a dummy RPC message
        let (response_sender, _response_receiver) = oneshot::channel();
        let commit_request = IncomingCommitRequest {
            req: CommitMessage::Decision(pipeline::commit_decision::CommitDecision::new(
                commit_decision.commit_proof().clone(),
            )),
            protocol: ProtocolId::ConsensusDirectSendCompressed,
            response_sender,
        };

        // Send the message to the execution client
        if let Err(error) = self
            .execution_client
            .send_commit_msg(AccountAddress::ONE, commit_request)
        {
            error!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Failed to send commit decision to the execution pipeline! Error: {:?}",
                    error
                ))
            )
        };
    }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L533-570)
```rust
    fn process_commit_decision_for_pending_block(&self, commit_decision: &CommitDecision) -> bool {
        // Get the pending block for the commit decision
        let pending_block = self
            .observer_block_data
            .lock()
            .get_ordered_block(commit_decision.epoch(), commit_decision.round());

        // Process the pending block
        if let Some(pending_block) = pending_block {
            // If all payloads exist, add the commit decision to the pending blocks
            if self.all_payloads_exist(pending_block.blocks()) {
                debug!(
                    LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                        "Adding decision to pending block: {}",
                        commit_decision.proof_block_info()
                    ))
                );
                self.observer_block_data
                    .lock()
                    .update_ordered_block_commit_decision(commit_decision);

                // If state sync is not syncing to a commit, forward the commit decision to the execution pipeline
                if !self.state_sync_manager.is_syncing_to_commit() {
                    info!(
                        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                            "Forwarding commit decision to the execution pipeline: {}",
                            commit_decision.proof_block_info()
                        ))
                    );
                    self.forward_commit_decision(commit_decision.clone());
                }

                return true; // The commit decision was successfully processed
            }
        }

        false // The commit decision was not processed
    }
```

**File:** types/src/block_info.rs (L29-44)
```rust
pub struct BlockInfo {
    /// The epoch to which the block belongs.
    epoch: u64,
    /// The consensus protocol is executed in rounds, which monotonically increase per epoch.
    round: Round,
    /// The identifier (hash) of the block.
    id: HashValue,
    /// The accumulator root hash after executing this block.
    executed_state_id: HashValue,
    /// The version of the latest transaction after executing this block.
    version: Version,
    /// The timestamp this block was proposed by a proposer.
    timestamp_usecs: u64,
    /// An optional field containing the next epoch info
    next_epoch_state: Option<EpochState>,
}
```

**File:** types/src/block_info.rs (L196-204)
```rust
    pub fn match_ordered_only(&self, executed_block_info: &BlockInfo) -> bool {
        self.epoch == executed_block_info.epoch
            && self.round == executed_block_info.round
            && self.id == executed_block_info.id
            && (self.timestamp_usecs == executed_block_info.timestamp_usecs
            // executed block info has changed its timestamp because it's a reconfiguration suffix
                || (self.timestamp_usecs > executed_block_info.timestamp_usecs
                    && executed_block_info.has_reconfiguration()))
    }
```

**File:** consensus/src/consensus_observer/observer/ordered_blocks.rs (L127-142)
```rust
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

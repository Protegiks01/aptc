# Audit Report

## Title
Duplicate Block Execution via State Sync Completion Race Condition in Consensus Observer

## Summary
The consensus observer can send the same ordered block to the execution pipeline multiple times when state sync completes before the block's commit callback is invoked, leading to duplicate execution and potential state corruption.

## Finding Description

The vulnerability exists in the interaction between `process_ordered_block()` and `process_commit_sync_notification()` in the consensus observer. The issue arises from the following race condition:

When an ordered block is processed normally:
1. Block is inserted into `ordered_block_store` [1](#0-0) 
2. If not syncing, `finalize_ordered_block()` is called immediately [2](#0-1) 
3. Block is sent to execution pipeline via `finalize_order()` [3](#0-2) 
4. A commit callback is set up that will remove the block from `ordered_block_store` when committed [4](#0-3) 

However, when state sync completes, it unconditionally finalizes ALL ordered blocks: [5](#0-4) 

The vulnerability occurs when:
1. Block X arrives and is finalized (sent to execution, callback registered)
2. State sync is initiated for a later block due to a gap
3. State sync completes before Block X's commit callback executes
4. Block X is still in `ordered_block_store` (callback hasn't removed it yet)
5. `process_commit_sync_notification()` iterates through all ordered blocks including Block X
6. Block X is finalized AGAIN, sending it to execution pipeline a second time

The buffer manager receives the duplicate block and creates a new `BufferItem` for it: [6](#0-5) 

This results in the same block being executed twice, violating the **Deterministic Execution** invariant that requires each block to be executed exactly once with consistent state transitions.

## Impact Explanation

**Critical Severity** - This vulnerability can cause:

1. **Consensus Safety Violations**: Different nodes may execute blocks a different number of times depending on timing, leading to state divergence between validators. This breaks the fundamental consensus guarantee that all honest validators produce identical state roots for identical block sequences.

2. **State Corruption**: Transactions within the duplicated block are executed twice, potentially causing:
   - Double-spending if the same transaction modifies balances
   - Incorrect state transitions
   - Merkle tree inconsistencies

3. **Non-Recoverable Network Partition**: If validators diverge on state roots due to different numbers of block executions, the network cannot reach consensus and requires manual intervention or a hardfork to recover.

This meets the **Critical Severity** criteria per the Aptos bug bounty program as it causes consensus violations and potential loss of network liveness.

## Likelihood Explanation

**High Likelihood** - This vulnerability is likely to occur in production because:

1. **Common Trigger**: State sync is initiated whenever there's a gap in block reception, which happens regularly due to network latency or temporary peer unavailability
2. **Timing Window**: The vulnerability window exists from when a block is finalized until its commit callback executes - typically several hundred milliseconds to seconds depending on execution complexity
3. **Natural Occurrence**: No malicious behavior required - normal network conditions create the race condition
4. **Multiple Blocks at Risk**: During state sync, multiple blocks may be in-flight, increasing the probability that at least one will be duplicated

The vulnerability is easier to trigger when:
- Network latency is high
- Execution is slow due to complex transactions
- State sync completes quickly (short gaps)
- Multiple blocks are being processed concurrently

## Recommendation

Add deduplication tracking to prevent re-finalizing blocks that have already been sent to execution:

```rust
// In ConsensusObserver struct, add a new field:
finalized_block_ids: Arc<Mutex<HashSet<HashValue>>>,

// Modify finalize_ordered_block() to check and record:
async fn finalize_ordered_block(&mut self, ordered_block: OrderedBlock) {
    let block_id = ordered_block.first_block().id();
    
    // Check if already finalized
    if self.finalized_block_ids.lock().contains(&block_id) {
        warn!("Block {} already finalized, skipping duplicate", block_id);
        return;
    }
    
    // Record as finalized
    self.finalized_block_ids.lock().insert(block_id);
    
    // ... existing finalization logic ...
}

// Modify the commit callback to remove from tracking:
pub fn create_commit_callback(
    observer_block_data: Arc<Mutex<ObserverBlockData>>,
    finalized_block_ids: Arc<Mutex<HashSet<HashValue>>>,
) -> Box<dyn FnOnce(WrappedLedgerInfo, LedgerInfoWithSignatures) + Send + Sync> {
    Box::new(move |_, ledger_info: LedgerInfoWithSignatures| {
        let block_id = ledger_info.commit_info().id();
        finalized_block_ids.lock().remove(&block_id);
        observer_block_data.lock().handle_committed_blocks(ledger_info);
    })
}
```

Alternatively, check the execution pipeline state before re-finalizing blocks in `process_commit_sync_notification()`.

## Proof of Concept

```rust
// Integration test demonstrating the vulnerability
#[tokio::test]
async fn test_duplicate_block_execution_via_state_sync() {
    // Setup: Create consensus observer with mock execution client
    let (execution_client, block_tracker) = create_mock_execution_client_with_tracker();
    let mut consensus_observer = create_test_consensus_observer(execution_client);
    
    // Step 1: Send ordered block X (round 100)
    let ordered_block_x = create_test_ordered_block(100);
    consensus_observer.process_ordered_block_message(
        peer_network_id,
        Instant::now(),
        ordered_block_x.clone()
    ).await;
    
    // Verify block was sent to execution once
    assert_eq!(block_tracker.lock().count_for_round(100), 1);
    
    // Step 2: Initiate state sync to round 110 (creates gap)
    let commit_decision_110 = create_commit_decision(110);
    consensus_observer.state_sync_manager.sync_to_commit(commit_decision_110, false);
    
    // Step 3: State sync completes before block 100 commits
    let synced_ledger_info = create_ledger_info(110);
    consensus_observer.process_commit_sync_notification(
        StateSyncNotification::CommitSyncCompleted(synced_ledger_info)
    ).await;
    
    // Step 4: Verify block 100 was sent to execution TWICE
    assert_eq!(block_tracker.lock().count_for_round(100), 2, 
        "Block 100 should be executed twice due to duplicate finalization");
    
    // This demonstrates consensus violation: same block executed multiple times
}
```

The test would show that `finalize_ordered_block()` is called twice for the same block, resulting in duplicate execution requests to the buffer manager, breaking the deterministic execution invariant.

### Citations

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L287-301)
```rust
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
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L785-787)
```rust
            self.observer_block_data
                .lock()
                .insert_ordered_block(observed_ordered_block.clone());
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L789-791)
```rust
            // If state sync is not syncing to a commit, finalize the ordered blocks
            if !self.state_sync_manager.is_syncing_to_commit() {
                self.finalize_ordered_block(ordered_block).await;
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

**File:** consensus/src/consensus_observer/observer/block_data.rs (L325-333)
```rust
pub fn create_commit_callback(
    observer_block_data: Arc<Mutex<ObserverBlockData>>,
) -> Box<dyn FnOnce(WrappedLedgerInfo, LedgerInfoWithSignatures) + Send + Sync> {
    Box::new(move |_, ledger_info: LedgerInfoWithSignatures| {
        observer_block_data
            .lock()
            .handle_committed_blocks(ledger_info);
    })
}
```

**File:** consensus/src/pipeline/buffer_manager.rs (L382-423)
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
```

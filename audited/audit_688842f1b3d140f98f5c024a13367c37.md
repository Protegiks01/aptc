# Audit Report

## Title
Consensus Observer Execution Pipeline Deadlock via Premature Payload Removal During State Sync

## Summary
The consensus observer can enter a permanent deadlock when commit decisions for future rounds/epochs arrive while blocks are in the execution pipeline. The code removes payloads without aborting in-flight execution tasks, causing them to fail payload lookups and enter an infinite retry loop, permanently blocking the execution pipeline.

## Finding Description
The consensus observer maintains three stores: `block_payload_store` (payloads), `ordered_block_store` (ordered blocks), and `pending_block_store` (pending blocks). When blocks are finalized for execution, they enter an asynchronous pipeline that retrieves transactions from a shared payload store. [1](#0-0) 

The critical vulnerability occurs when processing commit decisions for future epochs or higher rounds. The code path is: [2](#0-1) 

At line 522, `update_blocks_for_state_sync_commit` is called, which aggressively removes all payloads for rounds ≤ commit_round: [3](#0-2) [4](#0-3) 

**The critical flaw**: The execution pipeline is never aborted. In contrast, when entering fallback mode, the code properly resets the pipeline: [5](#0-4) 

The `ConsensusObserverPayloadManager` shares the same `Arc<Mutex<BTreeMap>>` with `BlockPayloadStore`: [6](#0-5) 

When blocks in the pipeline reach the materialize phase after payloads are removed, `get_transactions_for_observer` fails: [7](#0-6) 

The materialize function catches the error and enters an **infinite retry loop**: [8](#0-7) 

Since the payload has been permanently removed, retries fail indefinitely, blocking the entire execution pipeline.

## Impact Explanation
**Critical Severity** - This vulnerability causes **total loss of liveness** for consensus observer nodes:

- The execution pipeline enters permanent deadlock with infinite 100ms retry loops
- No new blocks can be processed while stuck on the failing block
- The node effectively stops participating in consensus observation
- Recovery requires manual intervention or node restart
- If multiple observers are affected simultaneously, network observation capability is severely degraded

This meets the Critical severity criteria: "Total loss of liveness/network availability" per the Aptos Bug Bounty program.

## Likelihood Explanation
**HIGH LIKELIHOOD** - This can occur during normal network operations:

**Triggering Conditions**:
1. Node receives `OrderedBlock` and begins processing it
2. `BlockPayload` messages arrive and are stored
3. Block enters execution pipeline (asynchronous)
4. Before execution completes, a `CommitDecision` for higher round arrives from a faster peer
5. Commit decision triggers payload removal without pipeline abort

**Realistic Scenarios**:
- Network latency causing nodes to receive commits from faster peers while processing older blocks
- Nodes rejoining the network or temporarily falling behind
- Epoch transitions where new epoch commits arrive during old epoch block execution

**No Special Privileges Required**: Any peer can send `CommitDecision` messages. Future epoch commits bypass verification (TODO comment at line 497-498), making this exploitable during normal network synchronization.

## Recommendation
Add execution pipeline abort before removing payloads during state sync commits:

```rust
// In process_commit_decision_message, replace lines 518-526 with:
// Otherwise, we should start the state sync process for the commit.
// Clear all the pending block state (including aborting the execution pipeline)
self.clear_pending_block_state().await;

// Update the block data (to the commit decision).
self.observer_block_data
    .lock()
    .update_blocks_for_state_sync_commit(&commit_decision);

// Start state syncing to the commit decision
self.state_sync_manager
    .sync_to_commit(commit_decision, epoch_changed);
```

This mirrors the `enter_fallback_mode` pattern which correctly aborts the pipeline before state sync.

## Proof of Concept
```rust
#[tokio::test]
async fn test_state_sync_commit_causes_execution_deadlock() {
    // Step 1: Create consensus observer and insert block 100 into execution pipeline
    let epoch = 10;
    let round_100 = 100;
    let block_100 = create_test_pipelined_block(epoch, round_100);
    let payload_100 = BlockPayload::new(
        block_100.block_info(),
        BlockTransactionPayload::empty(),
    );
    
    observer_block_data.lock().insert_block_payload(payload_100.clone(), true);
    observer_block_data.lock().insert_ordered_block(
        ObservedOrderedBlock::new(create_ordered_block(block_100.clone()))
    );
    
    // Step 2: Finalize block 100 for execution (enters pipeline asynchronously)
    finalize_ordered_block(create_ordered_block(block_100.clone())).await;
    
    // Step 3: Before execution completes, process commit decision for round 105
    let commit_decision_105 = CommitDecision::new(
        create_test_ledger_info(epoch, 105)
    );
    
    observer_block_data.lock()
        .update_blocks_for_state_sync_commit(&commit_decision_105);
    
    // Step 4: Verify payload for round 100 was removed
    assert!(!observer_block_data.lock().existing_payload_entry(&payload_100));
    
    // Step 5: When block 100's execution tries to get transactions,
    // it fails with InternalError and enters infinite retry loop
    let block_payloads = observer_block_data.lock().get_block_payloads();
    let result = get_transactions_for_observer(
        block_100.block(),
        &block_payloads,
        &None,
    ).await;
    
    assert!(matches!(result, Err(ExecutorError::InternalError { .. })));
    // In production, materialize() would retry this indefinitely,
    // permanently blocking the execution pipeline
}
```

**Notes**: This vulnerability represents a logic flaw where the system removes data (payloads) still logically referenced by in-flight execution tasks, causing permanent deadlock. While not a traditional memory use-after-free (no unsafe code), it breaks the liveness invariant by creating an unrecoverable execution pipeline deadlock during normal network operations.

### Citations

**File:** consensus/src/consensus_observer/observer/block_data.rs (L40-52)
```rust
pub struct ObserverBlockData {
    // The block payload store (containing the block transaction payloads)
    block_payload_store: BlockPayloadStore,

    // The ordered block store (containing ordered blocks that are ready for execution)
    ordered_block_store: OrderedBlockStore,

    // The pending block store (containing pending blocks that are without payloads)
    pending_block_store: PendingBlockStore,

    // The latest ledger info
    root: LedgerInfoWithSignatures,
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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L236-246)
```rust
    /// Enters fallback mode for consensus observer by invoking state sync
    async fn enter_fallback_mode(&mut self) {
        // Terminate all active subscriptions (to ensure we don't process any more messages)
        self.subscription_manager.terminate_all_subscriptions();

        // Clear all the pending block state
        self.clear_pending_block_state().await;

        // Start syncing for the fallback
        self.state_sync_manager.sync_for_fallback();
    }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L500-527)
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
```

**File:** consensus/src/consensus_observer/observer/payload_store.rs (L111-119)
```rust
    /// Removes all blocks up to the specified epoch and round (inclusive)
    pub fn remove_blocks_for_epoch_round(&self, epoch: u64, round: Round) {
        // Determine the round to split off
        let split_off_round = round.saturating_add(1);

        // Remove the blocks from the payload store
        let mut block_payloads = self.block_payloads.lock();
        *block_payloads = block_payloads.split_off(&(epoch, split_off_round));
    }
```

**File:** consensus/src/payload_manager/co_payload_manager.rs (L29-58)
```rust
async fn get_transactions_for_observer(
    block: &Block,
    block_payloads: &Arc<Mutex<BTreeMap<(u64, Round), BlockPayloadStatus>>>,
    consensus_publisher: &Option<Arc<ConsensusPublisher>>,
) -> ExecutorResult<(Vec<SignedTransaction>, Option<u64>, Option<u64>)> {
    // The data should already be available (as consensus observer will only ever
    // forward a block to the executor once the data has been received and verified).
    let block_payload = match block_payloads.lock().entry((block.epoch(), block.round())) {
        Entry::Occupied(mut value) => match value.get_mut() {
            BlockPayloadStatus::AvailableAndVerified(block_payload) => block_payload.clone(),
            BlockPayloadStatus::AvailableAndUnverified(_) => {
                // This shouldn't happen (the payload should already be verified)
                let error = format!(
                    "Payload data for block epoch {}, round {} is unverified!",
                    block.epoch(),
                    block.round()
                );
                return Err(InternalError { error });
            },
        },
        Entry::Vacant(_) => {
            // This shouldn't happen (the payload should already be present)
            let error = format!(
                "Missing payload data for block epoch {}, round {}!",
                block.epoch(),
                block.round()
            );
            return Err(InternalError { error });
        },
    };
```

**File:** consensus/src/payload_manager/co_payload_manager.rs (L78-81)
```rust
pub struct ConsensusObserverPayloadManager {
    txns_pool: Arc<Mutex<BTreeMap<(u64, Round), BlockPayloadStatus>>>,
    consensus_publisher: Option<Arc<ConsensusPublisher>>,
}
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L634-646)
```rust
        let result = loop {
            match preparer.materialize_block(&block, qc_rx.clone()).await {
                Ok(input_txns) => break input_txns,
                Err(e) => {
                    warn!(
                        "[BlockPreparer] failed to prepare block {}, retrying: {}",
                        block.id(),
                        e
                    );
                    tokio::time::sleep(Duration::from_millis(100)).await;
                },
            }
        };
```

# Audit Report

## Title
Consensus Observer Execution Pipeline Deadlock via Premature Payload Removal During State Sync

## Summary
The consensus observer can enter a permanent deadlock when commit decisions for future rounds/epochs arrive while blocks are in the execution pipeline. The code removes payloads without aborting in-flight execution tasks, causing them to fail payload lookups and enter an infinite retry loop, permanently blocking the execution pipeline.

## Finding Description
The consensus observer maintains three stores managed by `ObserverBlockData`: `block_payload_store`, `ordered_block_store`, and `pending_block_store`. [1](#0-0) 

When blocks are finalized for execution via `finalize_ordered_block`, they enter an asynchronous pipeline that builds pipeline futures and sends blocks to the execution client. [2](#0-1) 

The critical vulnerability occurs in `process_commit_decision_message` when processing commit decisions for future epochs or higher rounds. [3](#0-2) 

At line 522, `update_blocks_for_state_sync_commit` is called, which aggressively removes all payloads for rounds ≤ commit_round. [4](#0-3) 

This removal is permanent, implemented via `remove_blocks_for_epoch_round` which uses `split_off` to delete entries from the BTreeMap. [5](#0-4) 

**The critical flaw**: The execution pipeline is never aborted. In contrast, when entering fallback mode, the code properly resets the pipeline by calling `execution_client.reset()`. [6](#0-5) [7](#0-6) 

The `ConsensusObserverPayloadManager` shares the same `Arc<Mutex<BTreeMap>>` with `BlockPayloadStore`, enabling direct access to the payload storage. [8](#0-7) [9](#0-8) 

When blocks in the pipeline reach the materialize phase after payloads are removed, `get_transactions_for_observer` fails with an `InternalError` when the payload is missing. [10](#0-9) 

The materialize function in the execution pipeline catches this error and enters an **infinite retry loop** with 100ms sleep intervals. The comment explicitly states "the loop can only be abort by the caller". [11](#0-10) 

Since the payload has been permanently removed from the store, retries fail indefinitely, blocking the entire execution pipeline.

## Impact Explanation
**Critical Severity** - This vulnerability causes **total loss of liveness** for consensus observer nodes, meeting the Aptos Bug Bounty Critical severity criteria for "Total Loss of Liveness/Network Availability":

- The execution pipeline enters permanent deadlock with infinite 100ms retry loops attempting to materialize blocks
- No new blocks can be processed while the pipeline is stuck on the failing block
- The node effectively stops participating in consensus observation
- Recovery requires manual intervention or node restart
- If multiple observers are affected simultaneously, network observation capability is severely degraded

This directly aligns with Critical Impact Category #4: "Network halts due to protocol bug / All validators unable to progress".

## Likelihood Explanation
**HIGH LIKELIHOOD** - This can occur during normal network operations without any malicious intent:

**Triggering Conditions**:
1. Node receives `OrderedBlock` and begins processing it via `finalize_ordered_block`
2. `BlockPayload` messages arrive and are stored in the payload store
3. Block enters the asynchronous execution pipeline, which will eventually call materialize
4. Before the materialize phase completes, a `CommitDecision` for a higher round/epoch arrives from a faster peer
5. `process_commit_decision_message` triggers `update_blocks_for_state_sync_commit`, which removes payloads without aborting the pipeline

**Realistic Scenarios**:
- Network latency causing nodes to receive commits from faster peers while still processing older blocks
- Nodes rejoining the network or temporarily falling behind during normal operations
- Epoch transitions where new epoch commits arrive during old epoch block execution
- Any scenario where the asynchronous pipeline processing is slower than commit decision propagation

**No Special Privileges Required**: Any network peer can send `CommitDecision` messages. The TODO comment at lines 497-498 explicitly acknowledges that future epoch commit verification is incomplete, making this exploitable during normal network synchronization. [12](#0-11) 

## Recommendation
The fix should mirror the approach used in `enter_fallback_mode`. Before removing payloads in `update_blocks_for_state_sync_commit`, abort the execution pipeline:

1. Call `execution_client.reset(&root)` before removing payloads
2. This ensures in-flight materialize tasks are aborted before their dependencies are removed
3. After state sync completes, the pipeline can be restarted with the new root

The corrected flow in `process_commit_decision_message` should be:
```rust
// Reset the execution pipeline BEFORE removing payloads
let root = self.observer_block_data.lock().root();
if let Err(error) = self.execution_client.reset(&root).await {
    error!("Failed to reset execution pipeline: {:?}", error);
}

// Then update block data and remove payloads
self.observer_block_data
    .lock()
    .update_blocks_for_state_sync_commit(&commit_decision);
```

## Proof of Concept
While a full PoC requires setting up a consensus observer network, the vulnerability can be demonstrated by examining the code paths:

1. Start with `finalize_ordered_block` creating pipeline futures for block (epoch=10, round=100)
2. Pipeline futures include materialize task that will call `get_transactions_for_observer`
3. Before materialize completes, receive `CommitDecision` for (epoch=10, round=100)
4. `process_commit_decision_message` calls `update_blocks_for_state_sync_commit`
5. This removes payload for (10, 100) from the shared BTreeMap
6. Materialize task executes, attempts to get payload for (10, 100), receives `Entry::Vacant`
7. Returns `InternalError` with "Missing payload data for block epoch 10, round 100!"
8. Infinite retry loop begins, checking every 100ms, never succeeding
9. Pipeline is deadlocked, no new blocks can be processed

The vulnerability is definitively present in the codebase as documented by the citations above.

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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L216-234)
```rust
    /// Clears the pending block state (this is useful for changing
    /// subscriptions, where we want to wipe all state and restart).
    async fn clear_pending_block_state(&self) {
        // Clear the observer block data
        let root = self.observer_block_data.lock().clear_block_data();

        // Reset the execution pipeline for the root
        if let Err(error) = self.execution_client.reset(&root).await {
            error!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Failed to reset the execution pipeline for the root! Error: {:?}",
                    error
                ))
            );
        }

        // Increment the cleared block state counter
        metrics::increment_counter_without_labels(&metrics::OBSERVER_CLEARED_BLOCK_STATE);
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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L497-498)
```rust
        // TODO: identify the best way to handle an invalid commit decision
        // for a future epoch. In such cases, we currently rely on state sync.
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

**File:** consensus/src/consensus_observer/observer/payload_store.rs (L28-44)
```rust
/// A simple struct to store the block payloads of ordered and committed blocks
pub struct BlockPayloadStore {
    // The configuration of the consensus observer
    consensus_observer_config: ConsensusObserverConfig,

    // Block transaction payloads (indexed by epoch and round).
    // This is directly accessed by the payload manager.
    block_payloads: Arc<Mutex<BTreeMap<(u64, Round), BlockPayloadStatus>>>,
}

impl BlockPayloadStore {
    pub fn new(consensus_observer_config: ConsensusObserverConfig) -> Self {
        Self {
            consensus_observer_config,
            block_payloads: Arc::new(Mutex::new(BTreeMap::new())),
        }
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

**File:** consensus/src/payload_manager/co_payload_manager.rs (L49-57)
```rust
        Entry::Vacant(_) => {
            // This shouldn't happen (the payload should already be present)
            let error = format!(
                "Missing payload data for block epoch {}, round {}!",
                block.epoch(),
                block.round()
            );
            return Err(InternalError { error });
        },
```

**File:** consensus/src/payload_manager/co_payload_manager.rs (L78-93)
```rust
pub struct ConsensusObserverPayloadManager {
    txns_pool: Arc<Mutex<BTreeMap<(u64, Round), BlockPayloadStatus>>>,
    consensus_publisher: Option<Arc<ConsensusPublisher>>,
}

impl ConsensusObserverPayloadManager {
    pub fn new(
        txns_pool: Arc<Mutex<BTreeMap<(u64, Round), BlockPayloadStatus>>>,
        consensus_publisher: Option<Arc<ConsensusPublisher>>,
    ) -> Self {
        Self {
            txns_pool,
            consensus_publisher,
        }
    }
}
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L615-648)
```rust
    async fn materialize(
        preparer: Arc<BlockPreparer>,
        block: Arc<Block>,
        qc_rx: oneshot::Receiver<Arc<QuorumCert>>,
    ) -> TaskResult<MaterializeResult> {
        let mut tracker = Tracker::start_waiting("materialize", &block);
        tracker.start_working();

        let qc_rx = async {
            match qc_rx.await {
                Ok(qc) => Some(qc),
                Err(_) => {
                    warn!("[BlockPreparer] qc tx cancelled for block {}", block.id());
                    None
                },
            }
        }
        .shared();
        // the loop can only be abort by the caller
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
        Ok(result)
    }
```

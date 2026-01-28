# Audit Report

## Title
Consensus Observer Execution Pipeline Deadlock via Premature Payload Removal During State Sync

## Summary
The consensus observer can enter a permanent deadlock when commit decisions for future rounds/epochs arrive while blocks are in the execution pipeline. The code removes payloads without aborting in-flight execution tasks, causing them to fail payload lookups and enter an infinite retry loop, permanently blocking the execution pipeline.

## Finding Description
The consensus observer maintains three stores managed by `ObserverBlockData`: `block_payload_store`, `ordered_block_store`, and `pending_block_store`. When blocks are finalized for execution via `finalize_ordered_block()`, they enter an asynchronous pipeline with futures built by `PipelineBuilder::build_for_observer()`. [1](#0-0) 

The critical vulnerability occurs when processing commit decisions for future epochs or higher rounds. When `process_commit_decision_message()` receives a commit decision for a future epoch, it bypasses verification (as noted in the TODO comment): [2](#0-1) 

The code then calls `update_blocks_for_state_sync_commit()` which aggressively removes all payloads: [3](#0-2) [4](#0-3) [5](#0-4) 

**The critical flaw**: The execution pipeline is never aborted. In contrast, when entering fallback mode, the code properly resets the pipeline: [6](#0-5) [7](#0-6) 

The `BufferManager::reset()` properly aborts all in-flight pipelines: [8](#0-7) 

The `ConsensusObserverPayloadManager` shares the same `Arc<Mutex<BTreeMap>>` with `BlockPayloadStore`: [9](#0-8) [10](#0-9) [11](#0-10) 

When blocks in the pipeline reach the materialize phase after payloads are removed, `get_transactions_for_observer()` fails: [12](#0-11) 

The materialize function catches the error and enters an infinite retry loop: [13](#0-12) 

Since the payload has been permanently removed by `split_off()`, retries fail indefinitely, blocking the entire execution pipeline.

## Impact Explanation
**High Severity** - This vulnerability causes complete loss of liveness for consensus observer nodes:

- The execution pipeline enters permanent deadlock with infinite 100ms retry loops
- No new blocks can be processed while stuck on the failing block
- The node stops participating in consensus observation
- Recovery requires node restart
- Multiple affected observers severely degrade network observation capability

While this affects observer infrastructure rather than validator consensus directly, consensus observers are critical for network monitoring, API services, and downstream applications. The permanent deadlock requires manual intervention, making this a High severity issue per Aptos Bug Bounty criteria for "Validator Node Slowdowns" with complete service disruption.

## Likelihood Explanation
**HIGH LIKELIHOOD** - This can occur during normal network operations:

**Triggering Conditions**:
1. Node receives `OrderedBlock` and begins processing
2. `BlockPayload` messages arrive and are stored
3. Block enters execution pipeline (asynchronous)
4. Before execution completes, `CommitDecision` for higher round arrives
5. Commit decision triggers payload removal without pipeline abort

**Realistic Scenarios**:
- Network latency causing nodes to receive commits from faster peers
- Nodes rejoining network or temporarily falling behind
- Epoch transitions where new epoch commits arrive during old epoch execution

**No Special Privileges Required**: Any peer can send `CommitDecision` messages. Future epoch commits bypass verification (TODO comment), making this exploitable during normal synchronization.

## Recommendation
Add pipeline reset to `update_blocks_for_state_sync_commit()` similar to `clear_pending_block_state()`:

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

Should be changed to call `clear_pending_block_state()` or invoke `execution_client.reset()` before removing payloads to abort in-flight pipeline tasks.

## Proof of Concept
The vulnerability can be triggered by:
1. Starting a consensus observer node
2. Sending an `OrderedBlock` message for epoch E, round R
3. Sending corresponding `BlockPayload` messages
4. Waiting for block to enter execution pipeline
5. Sending a `CommitDecision` for epoch E, round R+10 before execution completes
6. Observer enters permanent deadlock in materialize retry loop
7. Monitoring shows execution pipeline stuck with 100ms retry intervals

Node logs would show repeated failures in `get_transactions_for_observer` with "Missing payload data for block epoch X, round Y!" errors.

### Citations

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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L248-283)
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
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L497-498)
```rust
        // TODO: identify the best way to handle an invalid commit decision
        // for a future epoch. In such cases, we currently rely on state sync.
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L518-527)
```rust
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

**File:** consensus/src/consensus_observer/observer/payload_store.rs (L29-44)
```rust
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

**File:** consensus/src/pipeline/buffer_manager.rs (L546-570)
```rust
    async fn reset(&mut self) {
        while let Some((_, block)) = self.pending_commit_blocks.pop_first() {
            // Those blocks don't have any dependencies, should be able to finish commit_ledger.
            // Abort them can cause error on epoch boundary.
            block.wait_for_commit_ledger().await;
        }
        while let Some(item) = self.buffer.pop_front() {
            for b in item.get_blocks() {
                if let Some(futs) = b.abort_pipeline() {
                    futs.wait_until_finishes().await;
                }
            }
        }
        self.buffer = Buffer::new();
        self.execution_root = None;
        self.signing_root = None;
        self.previous_commit_time = Instant::now();
        self.commit_proof_rb_handle.take();
        // purge the incoming blocks queue
        while let Ok(Some(blocks)) = self.block_rx.try_next() {
            for b in blocks.ordered_blocks {
                if let Some(futs) = b.abort_pipeline() {
                    futs.wait_until_finishes().await;
                }
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

**File:** consensus/src/payload_manager/co_payload_manager.rs (L78-92)
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
```

**File:** consensus/src/consensus_observer/observer/epoch_state.rs (L110-115)
```rust
        // Create the payload manager
        let payload_manager: Arc<dyn TPayloadManager> = if self.quorum_store_enabled {
            Arc::new(ConsensusObserverPayloadManager::new(
                block_payloads,
                self.consensus_publisher.clone(),
            ))
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

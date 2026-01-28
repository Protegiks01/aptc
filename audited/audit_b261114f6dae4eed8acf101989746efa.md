# Audit Report

## Title
Consensus Observer Execution Pipeline Deadlock via Premature Payload Removal During State Sync

## Summary
The consensus observer can enter a permanent deadlock when commit decisions for future rounds/epochs arrive while blocks are in the execution pipeline. The code removes payloads without aborting in-flight execution tasks, causing them to fail payload lookups and enter an infinite retry loop, permanently blocking the execution pipeline.

## Finding Description
The consensus observer maintains block payloads in a shared store that is accessed by both the consensus observer and the execution pipeline. When blocks are finalized for execution, they enter an asynchronous pipeline that materializes transactions from this shared payload store. [1](#0-0) 

The critical vulnerability occurs when processing commit decisions for future epochs or higher rounds. When such a commit decision arrives, the code calls `update_blocks_for_state_sync_commit` which removes all payloads up to the committed round: [2](#0-1) 

This function aggressively removes payloads without any pipeline coordination: [3](#0-2) 

**The critical flaw**: The execution pipeline is never aborted or notified. In stark contrast, when entering fallback mode, the code properly resets the execution pipeline: [4](#0-3) 

The `ConsensusObserverPayloadManager` shares the same `Arc<Mutex<BTreeMap>>` with `BlockPayloadStore`, meaning payload removals are immediately visible to the execution pipeline: [5](#0-4) 

When blocks in the pipeline reach the materialize phase after payloads are removed, `get_transactions_for_observer` fails with an error: [6](#0-5) 

The materialize function catches this error and enters an **infinite retry loop** with 100ms sleeps: [7](#0-6) 

Since the payload has been permanently removed from the shared store, retries fail indefinitely, blocking the entire execution pipeline and preventing any new blocks from being processed.

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
3. Block enters execution pipeline asynchronously via `finalize_order`
4. Before materialize phase completes, a `CommitDecision` for higher round arrives from a faster peer
5. Commit decision triggers payload removal without pipeline abort

**Realistic Scenarios**:
- Network latency causing nodes to receive commits from faster peers while processing older blocks
- Nodes rejoining the network or temporarily falling behind
- Epoch transitions where new epoch commits arrive during old epoch block execution

**No Special Privileges Required**: Any peer can send `CommitDecision` messages. Future epoch commits bypass verification (TODO comment acknowledges this): [8](#0-7) 

The race condition between asynchronous pipeline execution and commit decision processing makes this readily exploitable during normal network synchronization.

## Recommendation
The fix should mirror the fallback mode behavior by resetting the execution pipeline before removing payloads. Modify the state sync commit path to call `execution_client.reset()`:

```rust
// In process_commit_decision_message, before updating blocks:
self.observer_block_data
    .lock()
    .update_blocks_for_state_sync_commit(&commit_decision);

// Add pipeline reset:
let root = self.observer_block_data.lock().root();
if let Err(error) = self.execution_client.reset(&root).await {
    error!("Failed to reset execution pipeline for state sync commit");
}

// Then proceed with state sync:
self.state_sync_manager
    .sync_to_commit(commit_decision, epoch_changed);
```

Alternatively, the execution pipeline should be made aware of payload removals and abort ongoing tasks gracefully.

## Proof of Concept
The vulnerability can be reproduced by simulating the race condition:

1. Start a consensus observer node
2. Send an `OrderedBlock` message with blocks at round N
3. Send corresponding `BlockPayload` messages
4. While the materialize phase is executing (before `get_transactions` completes), send a `CommitDecision` for round N+10 from another peer
5. Observe the execution pipeline entering infinite retry loops in logs: `"failed to prepare block, retrying: Missing payload data for block epoch X, round Y"`
6. Verify no new blocks are processed and the node is deadlocked

The infinite retry loop is confirmed by the code comment "the loop can only be abort by the caller" and the absence of any abort mechanism in the state sync commit path.

### Citations

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L218-234)
```rust
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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L275-302)
```rust
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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L520-527)
```rust
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

**File:** consensus/src/payload_manager/co_payload_manager.rs (L29-76)
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

    // If the payload is valid, publish it to any downstream observers
    let transaction_payload = block_payload.transaction_payload();
    if let Some(consensus_publisher) = consensus_publisher {
        let message = ConsensusObserverMessage::new_block_payload_message(
            block.gen_block_info(HashValue::zero(), 0, None),
            transaction_payload.clone(),
        );
        consensus_publisher.publish_message(message);
    }

    // Return the transactions and the transaction limit
    Ok((
        transaction_payload.transactions(),
        transaction_payload.transaction_limit(),
        transaction_payload.gas_limit(),
    ))
}
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

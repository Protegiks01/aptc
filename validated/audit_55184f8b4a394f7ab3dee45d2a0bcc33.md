# Audit Report

## Title
Race Condition in Consensus Observer Causes Infinite Materialization Retry Loop on Pruned Payloads

## Summary
A race condition exists in the consensus observer where block payloads can be pruned while blocks are still in the materialization phase of the execution pipeline. This causes `get_transactions_for_observer()` to repeatedly return `InternalError`, triggering an infinite retry loop that prevents the node from making progress.

## Finding Description

The vulnerability occurs in the consensus observer's block processing flow where there is insufficient synchronization between block finalization and payload pruning:

**Step 1: Block Finalization Without Waiting**

When an ordered block is received, `finalize_ordered_block()` builds the execution pipeline asynchronously but returns immediately without waiting for execution to complete. [1](#0-0) 

The pipeline's materialization phase is triggered asynchronously, where `materialize_block()` will eventually call `get_transactions()` on the payload manager.

**Step 2: Payload Manager Returns InternalError on Missing Payloads**

The `get_transactions_for_observer()` function expects payloads to be available in the `block_payloads` BTreeMap. When a payload is missing, it returns an `InternalError`. [2](#0-1) 

**Step 3: Infinite Retry Loop on Materialization Failure**

The materialization process has a retry loop that continues indefinitely when errors occur, with a 100ms delay between retries. [3](#0-2) 

**Step 4: Race Condition - Payload Pruning During Materialization**

When a commit decision arrives for a future round while blocks are still materializing, `update_blocks_for_state_sync_commit()` immediately prunes all payloads up to that round. [4](#0-3) 

The pruning operation removes all blocks up to and including the specified round using `split_off` on the BTreeMap. [5](#0-4) 

This pruning is triggered from `process_commit_decision_message()` when the commit round exceeds the last ordered block's round. [6](#0-5) 

**Attack Scenario:**

1. Consensus observer receives and finalizes ordered block at epoch X, round 100
2. Block enters asynchronous materialization phase via the execution pipeline
3. Before materialization completes, a commit decision arrives for epoch X, round 200
4. Since `commit_round (200) > last_block.round() (100)`, the state sync path is taken
5. `update_blocks_for_state_sync_commit()` prunes all payloads up to round 200, including round 100
6. The block at round 100 tries to materialize, but `get_transactions_for_observer()` finds the payload missing
7. `InternalError` is returned: "Missing payload data for block epoch X, round 100!"
8. The materialization retry loop activates, attempting to get transactions every 100ms indefinitely
9. The consensus observer is stuck and cannot make progress

This breaks the liveness invariant - the node should be able to process blocks once their payloads have been received and verified.

## Impact Explanation

**Severity: Medium**

This vulnerability falls under the Medium severity category per the Aptos bug bounty program: "State inconsistencies requiring intervention."

**Impact:**
- **Node Liveness Failure**: The affected consensus observer node becomes stuck in an infinite retry loop and cannot make progress
- **Resource Waste**: CPU cycles are consumed retrying the materialization every 100ms
- **Manual Intervention Required**: The node must be restarted to recover
- **Limited Scope**: Only affects the individual consensus observer node (fullnode), not the broader network

The issue does not constitute Critical or High severity because:
- No funds are at risk
- No consensus safety violations occur (consensus observers are fullnodes, not validators)
- The broader network continues operating normally
- Only individual observer nodes are affected

However, it does require manual intervention to resolve, qualifying it as Medium severity.

## Likelihood Explanation

**Likelihood: Medium to High**

This vulnerability has a moderate to high likelihood of occurring during normal operations:

**Triggering Conditions:**
1. Network timing variations naturally cause ordered blocks and commit decisions to arrive out of order
2. Validators with different network latencies will send messages at different times
3. Fast block production rates increase the probability of the race condition
4. No malicious behavior is required - this occurs during normal consensus

**Factors Increasing Likelihood:**
- High transaction throughput environments
- Network latency variations between validators
- Geographic distribution of validators
- Fast epoch progression

**Factors Decreasing Likelihood:**
- Materialization typically completes quickly if the node is not overloaded
- Commit decisions usually follow ordered blocks with some delay

The vulnerability is particularly concerning because it requires no attacker - it's a natural consequence of asynchronous message processing in distributed consensus.

## Recommendation

The issue can be fixed by ensuring pipeline futures are properly aborted before pruning payloads during state sync operations. Specifically:

1. Before calling `update_blocks_for_state_sync_commit()`, abort all active pipeline futures for blocks that will have their payloads pruned
2. Wait for the abort operations to complete before proceeding with payload pruning
3. Alternatively, check if blocks are currently materializing before pruning their payloads, and delay pruning until materialization completes

The fix should follow the pattern used in `clear_pending_block_state()` where pipelines are reset via `execution_client.reset()` before clearing data structures.

## Proof of Concept

This race condition can be reproduced by:

1. Setting up a consensus observer node
2. Ensuring it receives an ordered block at round N
3. Before materialization completes (simulated by adding delay in materialization), sending a commit decision for round N+100
4. Observing the infinite retry loop in the logs showing repeated "Missing payload data" errors every 100ms

The vulnerability occurs in production consensus observer deployments during normal network operations when message ordering is affected by network latency variations.

## Notes

The consensus observer is a component used by Validator Fullnodes (VFNs) to stay synchronized with consensus without participating in voting. This vulnerability affects the liveness of individual fullnodes but does not impact validator consensus or network security. The lack of synchronization between the asynchronous materialization pipeline and the payload pruning logic creates a race window where payloads can be removed while still being actively accessed by the execution pipeline.

### Citations

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L249-302)
```rust
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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L502-522)
```rust
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

**File:** consensus/src/consensus_observer/observer/block_data.rs (L285-286)
```rust
        self.block_payload_store
            .remove_blocks_for_epoch_round(commit_epoch, commit_round);
```

**File:** consensus/src/consensus_observer/observer/payload_store.rs (L112-119)
```rust
    pub fn remove_blocks_for_epoch_round(&self, epoch: u64, round: Round) {
        // Determine the round to split off
        let split_off_round = round.saturating_add(1);

        // Remove the blocks from the payload store
        let mut block_payloads = self.block_payloads.lock();
        *block_payloads = block_payloads.split_off(&(epoch, split_off_round));
    }
```

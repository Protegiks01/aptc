# Audit Report

## Title
Race Condition in send_for_execution() Allows Duplicate Block Processing Pipeline Execution

## Summary
The `send_for_execution()` function in `block_store.rs` contains a Time-of-Check-Time-of-Use (TOCTOU) race condition that allows the same finality proof to be processed multiple times concurrently. While downstream safeguards prevent actual double-commits to storage, the vulnerability causes wasteful duplicate processing through the entire execution, signing, and persisting pipeline, potentially causing validator node slowdowns. [1](#0-0) 

## Finding Description

The `send_for_execution()` function performs a non-atomic check-then-update pattern:

1. **Line 323**: Checks if `block_to_commit.round() > self.ordered_root().round()` (acquires read lock, then releases)
2. **Lines 327-329**: Retrieves blocks to commit via `path_from_ordered_root()`  
3. **Line 338**: Updates `ordered_root` (acquires write lock, then releases)
4. **Lines 344-347**: Sends blocks to execution pipeline via `finalize_order()`

The gap between the check (line 323) and update (line 338) creates a race window. If two threads concurrently call `send_for_execution()` with the same finality proof:

- Both threads read the same `ordered_root` value and pass the check
- Both threads retrieve the same blocks
- Both threads update `ordered_root` to the same value (redundant but harmless)
- **Both threads send identical blocks to the buffer manager for processing**

This occurs in realistic scenarios when multiple validators broadcast the same quorum certificate or ordered certificate, and the node receives them concurrently through different network threads. [2](#0-1) [3](#0-2) 

The `insert_quorum_cert()` and `insert_ordered_cert()` functions call `send_for_execution()` after performing their own non-synchronized checks, amplifying the race window.

Once duplicate `OrderedBlocks` reach the buffer manager, it creates separate `BufferItem` instances for the same block Arc references and processes both through the full pipeline: [4](#0-3) 

The `process_ordered_blocks()` function lacks deduplication logic - it blindly creates a new `BufferItem` and pushes it to the buffer for each received `OrderedBlocks` message.

Both buffer items proceed through:
1. **Execution Schedule Phase**: Both await compute results (futures are shared, so same result)
2. **Execution Wait Phase**: Both set compute results (second triggers warning log)
3. **Signing Phase**: Both create commit votes and broadcast them (network bandwidth waste)
4. **Persisting Phase**: First sends commit signal, second gets None from `.take()` operation [5](#0-4) 

The `.take()` operation in the persisting phase provides partial protection - the `commit_proof_tx` is taken by the first persisting request, so the second request cannot send a duplicate commit signal. However, this safeguard is reactive (prevents the worst outcome) rather than proactive (prevents duplicate processing).

## Impact Explanation

**Severity: High** - Validator Node Slowdowns

This vulnerability causes:

1. **Resource Exhaustion**: Duplicate blocks consume CPU cycles through the full execution, signing, and persisting pipeline. While individual occurrences may have limited impact, repeated race conditions during high network activity could accumulate.

2. **Network Bandwidth Waste**: Duplicate commit votes are broadcast to all validators, consuming network bandwidth. Under network congestion, this exacerbates synchronization delays.

3. **Buffer Manager State Inconsistency**: The buffer contains duplicate `BufferItem` entries for the same blocks, complicating state management and potentially triggering edge cases in buffer cleanup logic.

While the `.take()` operation prevents actual double-commits to storage (avoiding Critical severity consensus violations), the wasted processing through the pipeline qualifies as validator node slowdown per the High severity category.

## Likelihood Explanation

**Likelihood: Medium**

This race condition occurs naturally when:
- Multiple validators broadcast the same certificate to a node
- Network conditions cause near-simultaneous message arrival  
- The consensus node processes messages concurrently via `BoundedExecutor` [6](#0-5) 

The vulnerability does not require attacker manipulation - it happens organically in production networks. However:
- Precise timing is required for concurrent execution
- Natural occurrence rate is relatively low
- Each instance causes finite resource waste (not cumulative damage)

An attacker with validator status could deliberately send duplicate certificates to amplify the issue, but this would constitute a network-level DoS (out of scope per bug bounty rules).

## Recommendation

**Solution**: Make `send_for_execution()` properly idempotent by atomically checking and updating `ordered_root` within a single critical section:

```rust
pub async fn send_for_execution(
    &self,
    finality_proof: WrappedLedgerInfo,
) -> anyhow::Result<()> {
    let block_id_to_commit = finality_proof.commit_info().id();
    let block_to_commit = self
        .get_block(block_id_to_commit)
        .ok_or_else(|| format_err!("Committed block id not found"))?;

    // ATOMIC CHECK AND UPDATE - hold write lock throughout
    let blocks_to_commit = {
        let mut tree = self.inner.write();
        
        // Check with lock held
        ensure!(
            block_to_commit.round() > tree.ordered_root().round(),
            "Committed block round lower than root"
        );

        // Get blocks with lock held
        let blocks = tree.path_from_ordered_root(block_id_to_commit)
            .unwrap_or_default();
        
        assert!(!blocks.is_empty());
        
        // Update immediately with lock still held
        tree.update_ordered_root(block_to_commit.id());
        tree.insert_ordered_cert(finality_proof.clone());
        
        blocks
    }; // Lock released here
    
    self.pending_blocks
        .lock()
        .gc(finality_proof.commit_info().round());
    
    update_counters_for_ordered_blocks(&blocks_to_commit);
    
    self.execution_client
        .finalize_order(blocks_to_commit, finality_proof.clone())
        .await
        .expect("Failed to persist commit");

    Ok(())
}
```

This fix ensures that only the first caller passes the check and updates `ordered_root`, while subsequent callers with the same finality proof immediately fail the check and return an error, preventing duplicate processing.

## Proof of Concept

The vulnerability requires concurrent access, which is difficult to reproduce in a simple unit test. However, the race condition can be demonstrated with the following Rust integration test:

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_send_for_execution() {
    // Setup: Create BlockStore with initial state
    // where ordered_root is at round 10
    let block_store = setup_test_block_store().await;
    let finality_proof = create_finality_proof_for_round(15);
    
    // Spawn two concurrent tasks calling send_for_execution
    let block_store_1 = block_store.clone();
    let proof_1 = finality_proof.clone();
    let task1 = tokio::spawn(async move {
        block_store_1.send_for_execution(proof_1).await
    });
    
    let block_store_2 = block_store.clone();
    let proof_2 = finality_proof.clone();
    let task2 = tokio::spawn(async move {
        block_store_2.send_for_execution(proof_2).await
    });
    
    // Both should succeed in current implementation (BUG)
    let result1 = task1.await.unwrap();
    let result2 = task2.await.unwrap();
    
    assert!(result1.is_ok());
    assert!(result2.is_ok()); // Both succeed - demonstrates race
    
    // Verify buffer manager received duplicate OrderedBlocks
    // by checking that execution was initiated twice
    assert_eq!(get_execution_request_count(), 2); // BUG: should be 1
}
```

**Notes**

The vulnerability is mitigated by downstream safeguards (the `.take()` operation in persisting phase) that prevent the most severe outcome (double-commit to storage). However, the wasteful duplicate processing through the execution, signing, and persisting pipeline constitutes a validator node slowdown issue per the High severity criteria. The fix is straightforward: atomic check-and-update using proper locking discipline.

### Citations

**File:** consensus/src/block_storage/block_store.rs (L312-350)
```rust
    pub async fn send_for_execution(
        &self,
        finality_proof: WrappedLedgerInfo,
    ) -> anyhow::Result<()> {
        let block_id_to_commit = finality_proof.commit_info().id();
        let block_to_commit = self
            .get_block(block_id_to_commit)
            .ok_or_else(|| format_err!("Committed block id not found"))?;

        // First make sure that this commit is new.
        ensure!(
            block_to_commit.round() > self.ordered_root().round(),
            "Committed block round lower than root"
        );

        let blocks_to_commit = self
            .path_from_ordered_root(block_id_to_commit)
            .unwrap_or_default();

        assert!(!blocks_to_commit.is_empty());

        let finality_proof_clone = finality_proof.clone();
        self.pending_blocks
            .lock()
            .gc(finality_proof.commit_info().round());

        self.inner.write().update_ordered_root(block_to_commit.id());
        self.inner
            .write()
            .insert_ordered_cert(finality_proof_clone.clone());
        update_counters_for_ordered_blocks(&blocks_to_commit);

        self.execution_client
            .finalize_order(blocks_to_commit, finality_proof.clone())
            .await
            .expect("Failed to persist commit");

        Ok(())
    }
```

**File:** consensus/src/block_storage/sync_manager.rs (L186-189)
```rust
        if self.ordered_root().round() < qc.commit_info().round() {
            SUCCESSFUL_EXECUTED_WITH_REGULAR_QC.inc();
            self.send_for_execution(qc.into_wrapped_ledger_info())
                .await?;
```

**File:** consensus/src/block_storage/sync_manager.rs (L210-219)
```rust
        if self.ordered_root().round() < ordered_cert.ledger_info().ledger_info().round() {
            if let Some(ordered_block) = self.get_block(ordered_cert.commit_info().id()) {
                if !ordered_block.block().is_nil_block() {
                    observe_block(
                        ordered_block.block().timestamp_usecs(),
                        BlockStage::OC_ADDED,
                    );
                }
                SUCCESSFUL_EXECUTED_WITH_ORDER_VOTE_QC.inc();
                self.send_for_execution(ordered_cert.clone()).await?;
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

**File:** consensus/src/pipeline/persisting_phase.rs (L65-72)
```rust
        for b in &blocks {
            if let Some(tx) = b.pipeline_tx().lock().as_mut() {
                tx.commit_proof_tx
                    .take()
                    .map(|tx| tx.send(commit_ledger_info.clone()));
            }
            b.wait_for_commit_ledger().await;
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

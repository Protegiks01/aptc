# Audit Report

## Title
Task Cancellation in Persisting Phase Breaks Batch Commit Atomicity

## Summary
The `process()` function in the persisting phase iterates over a batch of blocks to send commit proofs, but lacks atomicity guarantees. If the async task is cancelled mid-execution, some blocks receive commit proofs while others remain stuck, violating the batch commit atomicity invariant and potentially causing validator liveness failures.

## Finding Description

The persisting phase processes commit requests for batches of blocks that should commit atomically. However, the implementation is not cancellation-safe. [1](#0-0) 

The function iterates over blocks, sending commit proofs one by one. Each iteration involves:
1. Locking the mutex to access `pipeline_tx`
2. Taking and sending `commit_proof_tx`  
3. Awaiting on `wait_for_commit_ledger()`

If the async task is cancelled at any `.await` point during this loop, execution stops immediately, leaving the system in a partially-processed state. Specifically:

**Cancellation Scenario**: The persisting phase task is spawned via `tokio::spawn`: [2](#0-1) 

If this task is cancelled (e.g., during epoch transitions, runtime shutdown, or system panics), the `process()` loop is interrupted wherever it's currently awaiting. This means:

- Blocks 1 through N have received `commit_proof_tx` and can proceed to commit
- Blocks N+1 through M never receive `commit_proof_tx` and wait indefinitely
- The persisting phase returns without completing
- The buffer manager doesn't receive a success response [3](#0-2) 

**Why This Is a Problem**:

The commit proof signals to each block's pipeline that it should commit: [4](#0-3) 

Blocks that receive the commit proof will commit to storage. Blocks that don't receive it will either wait indefinitely or fail when their futures are eventually aborted. This breaks the atomic batch commit invariant - all blocks in a commit batch should succeed or fail together.

**Resource Cleanup Analysis**:

While Rust's `MutexGuard` ensures locks are released on drop, the channel state is NOT properly cleaned up: [5](#0-4) 

If cancellation occurs after `take()` but before `send()` completes, the sender is dropped and the receiver fails: [6](#0-5) 

The receiver will get a "commit proof tx cancelled" error, causing the commit phase to fail for that block.

## Impact Explanation

This vulnerability falls under **High Severity** per Aptos bug bounty criteria:

- **Validator Node Slowdowns/Hangs**: Validators with cancelled persisting tasks will have blocks stuck waiting for commit proofs that never arrive. During reset attempts, the system waits for these blocks: [7](#0-6) 

If blocks never receive commit proofs, the reset hangs indefinitely, requiring validator restart.

- **State Inconsistencies**: Partial batch commits violate the atomicity invariant for state transitions. Different validators may have different commit states if cancellation timing varies, though the consensus protocol should eventually reconcile this.

- **Epoch Transition Failures**: If cancellation occurs before sending the epoch change notification: [8](#0-7) 

Validators may fail to properly transition to the next epoch, causing network-wide coordination failures.

## Likelihood Explanation

**Medium Likelihood**. While external attackers cannot directly cancel tokio tasks, several realistic scenarios can trigger this:

1. **Epoch Boundary Race Conditions**: During epoch transitions, the buffer manager calls `reset()` which could race with in-progress persisting operations [9](#0-8) 

2. **System Resource Exhaustion**: Under heavy load, the tokio runtime may drop tasks or the validator may panic/crash mid-processing

3. **Runtime Shutdown**: Validator restarts or upgrades that don't gracefully wait for in-flight operations

The lack of explicit transaction boundaries or rollback mechanisms makes this issue inherent to the current design.

## Recommendation

Make the batch processing atomic by wrapping it in a cancellation-safe structure:

```rust
async fn process(&self, req: PersistingRequest) -> PersistingResponse {
    let PersistingRequest {
        blocks,
        commit_ledger_info,
    } = req;

    // Collect all operations first without side effects
    let mut commit_txs = Vec::new();
    for b in &blocks {
        if let Some(mut tx_guard) = b.pipeline_tx().lock().as_mut() {
            if let Some(tx) = tx_guard.commit_proof_tx.take() {
                commit_txs.push((b.clone(), tx));
            }
        }
    }
    
    // Atomically send to all blocks - if cancelled here, no sends occurred
    for (block, tx) in commit_txs {
        let _ = tx.send(commit_ledger_info.clone());
    }
    
    // Wait for all blocks to commit
    for b in &blocks {
        b.wait_for_commit_ledger().await;
    }

    let response = Ok(blocks.last().expect("Blocks can't be empty").round());
    if commit_ledger_info.ledger_info().ends_epoch() {
        self.commit_msg_tx
            .send_epoch_change(EpochChangeProof::new(vec![commit_ledger_info], false))
            .await;
    }
    response
}
```

Alternatively, wrap the entire operation in a `tokio::select!` with explicit cancellation handling or use `CancellationToken` to detect and rollback partial operations.

## Proof of Concept

```rust
#[tokio::test]
async fn test_persisting_phase_cancellation_leaves_inconsistent_state() {
    // Setup: Create persisting phase and mock blocks
    let (commit_msg_tx, _rx) = tokio::sync::mpsc::channel(10);
    let persisting_phase = PersistingPhase::new(Arc::new(commit_msg_tx));
    
    // Create 5 blocks with pipeline_tx channels
    let blocks: Vec<Arc<PipelinedBlock>> = (0..5)
        .map(|i| {
            let block = create_test_block(i);
            let (tx, rx) = create_pipeline_channels();
            block.set_pipeline_tx(tx);
            Arc::new(block)
        })
        .collect();
    
    let request = PersistingRequest {
        blocks: blocks.clone(),
        commit_ledger_info: create_test_commit_proof(),
    };
    
    // Spawn the persisting task
    let handle = tokio::spawn(persisting_phase.process(request));
    
    // Simulate cancellation after 2nd block by aborting the task
    tokio::time::sleep(Duration::from_millis(10)).await;
    handle.abort();
    
    // Verify inconsistent state:
    // - Blocks 0-1 received commit proof
    // - Blocks 2-4 did not receive commit proof
    assert!(blocks[0].pipeline_tx().lock().as_ref().unwrap().commit_proof_tx.is_none());
    assert!(blocks[1].pipeline_tx().lock().as_ref().unwrap().commit_proof_tx.is_none());
    assert!(blocks[2].pipeline_tx().lock().as_ref().unwrap().commit_proof_tx.is_some());
    assert!(blocks[3].pipeline_tx().lock().as_ref().unwrap().commit_proof_tx.is_some());
    assert!(blocks[4].pipeline_tx().lock().as_ref().unwrap().commit_proof_tx.is_some());
    
    // Blocks 2-4 will timeout waiting for commit proof
    // This violates batch atomicity invariant
}
```

## Notes

While Rust's `MutexGuard` automatically releases locks on drop (preventing lock-related deadlocks), the channel state and batch processing atomicity are NOT protected by this mechanism. The vulnerability lies in the gap between taking side effects (sending commit proofs) and completing the entire batch operation. Recovery mechanisms like `abort_pipeline()` and `reset()` exist but may hang if blocks are left waiting for commit proofs that were never sent.

### Citations

**File:** consensus/src/pipeline/persisting_phase.rs (L59-81)
```rust
    async fn process(&self, req: PersistingRequest) -> PersistingResponse {
        let PersistingRequest {
            blocks,
            commit_ledger_info,
        } = req;

        for b in &blocks {
            if let Some(tx) = b.pipeline_tx().lock().as_mut() {
                tx.commit_proof_tx
                    .take()
                    .map(|tx| tx.send(commit_ledger_info.clone()));
            }
            b.wait_for_commit_ledger().await;
        }

        let response = Ok(blocks.last().expect("Blocks can't be empty").round());
        if commit_ledger_info.ledger_info().ends_epoch() {
            self.commit_msg_tx
                .send_epoch_change(EpochChangeProof::new(vec![commit_ledger_info], false))
                .await;
        }
        response
    }
```

**File:** consensus/src/pipeline/execution_client.rs (L515-515)
```rust
        tokio::spawn(persisting_phase.start());
```

**File:** consensus/src/pipeline/buffer_manager.rs (L530-534)
```rust
                if commit_proof.ledger_info().ends_epoch() {
                    // the epoch ends, reset to avoid executing more blocks, execute after
                    // this persisting request will result in BlockNotFound
                    self.reset().await;
                }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L546-551)
```rust
    async fn reset(&mut self) {
        while let Some((_, block)) = self.pending_commit_blocks.pop_first() {
            // Those blocks don't have any dependencies, should be able to finish commit_ledger.
            // Abort them can cause error on epoch boundary.
            block.wait_for_commit_ledger().await;
        }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L968-973)
```rust
                Some(Ok(round)) = self.persisting_phase_rx.next() => {
                    // see where `need_backpressure()` is called.
                    self.pending_commit_votes = self.pending_commit_votes.split_off(&(round + 1));
                    self.highest_committed_round = round;
                    self.pending_commit_blocks = self.pending_commit_blocks.split_off(&(round + 1));
                },
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L306-313)
```rust
        let commit_proof_fut = spawn_shared_fut(
            async move {
                commit_proof_fut
                    .await
                    .map_err(|_| TaskError::from(anyhow!("commit proof tx cancelled")))
            },
            Some(abort_handles),
        );
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L1079-1106)
```rust
    async fn commit_ledger(
        pre_commit_fut: TaskFuture<PreCommitResult>,
        commit_proof_fut: TaskFuture<LedgerInfoWithSignatures>,
        parent_block_commit_fut: TaskFuture<CommitLedgerResult>,
        executor: Arc<dyn BlockExecutorTrait>,
        block: Arc<Block>,
    ) -> TaskResult<CommitLedgerResult> {
        let mut tracker = Tracker::start_waiting("commit_ledger", &block);
        parent_block_commit_fut.await?;
        pre_commit_fut.await?;
        let ledger_info_with_sigs = commit_proof_fut.await?;

        // it's committed as prefix
        if ledger_info_with_sigs.commit_info().id() != block.id() {
            return Ok(None);
        }

        tracker.start_working();
        let ledger_info_with_sigs_clone = ledger_info_with_sigs.clone();
        tokio::task::spawn_blocking(move || {
            executor
                .commit_ledger(ledger_info_with_sigs_clone)
                .map_err(anyhow::Error::from)
        })
        .await
        .expect("spawn blocking failed")?;
        Ok(Some(ledger_info_with_sigs))
    }
```

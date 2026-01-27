# Audit Report

## Title
Critical Consensus Safety Violation: Silent Commit Failures in Persisting Phase Allow False Commitment Tracking

## Summary
The persisting phase unconditionally reports success even when individual block commits fail, causing the buffer manager to incorrectly update `highest_committed_round` for blocks that were never actually persisted to storage. This breaks consensus safety by creating state divergence between the node's belief about committed blocks and the actual ledger state.

## Finding Description

The vulnerability exists in the interaction between three components:

**1. Persisting Phase Error Suppression** [1](#0-0) 

The `PersistingPhase::process()` method iterates through blocks, waits for each to commit, but always returns `Ok(blocks.last().round())` regardless of individual commit failures.

**2. Silent Error Handling** [2](#0-1) 

The `wait_for_commit_ledger()` method ignores all commit results via `let _ = fut.commit_ledger_fut.await`, including errors from database failures, block-not-found errors, or pruning failures.

**3. Unchecked Round Advancement** [3](#0-2) 

The buffer manager blindly trusts the persisting phase response and updates `highest_committed_round` without verifying that blocks were actually persisted.

**Attack Scenario:**

1. Consensus sends blocks [B1, B2, B3] to persisting phase
2. B1 commits successfully 
3. B2's `commit_ledger_fut` encounters a database write failure or block tree inconsistency [4](#0-3) 

4. The `commit_ledger` method returns `ExecutorError` (e.g., from `BlockNotFound` at line 381 or DB write failure at line 390)
5. This error propagates up as `TaskError::InternalError` through the pipeline [5](#0-4) 

6. `wait_for_commit_ledger()` ignores this error completely
7. Persisting phase continues with B3, which also fails
8. Persisting phase returns `Ok(B3.round())` 
9. Buffer manager sets `highest_committed_round = B3.round()`
10. **Node believes B2 and B3 are committed, but they are not in the ledger**

This breaks **Invariant #2 (Consensus Safety)** and **Invariant #4 (State Consistency)**: The node advertises a higher committed round than what exists in storage, causing state divergence across validators.

## Impact Explanation

**Severity: Critical** (up to $1,000,000)

This is a **Consensus Safety Violation**:

- **State Divergence**: Nodes have inconsistent views of committed state
- **Data Loss**: Blocks marked committed but not persisted are lost on restart
- **Chain Split Risk**: Different validators may commit different histories
- **Client Impact**: Queries return non-existent "committed" blocks
- **Recovery Impossible**: Requires manual intervention or hard fork

The vulnerability affects core consensus correctness. A node with this bug can:
- Report false commitment to clients
- Prune blocks other nodes still need
- Participate in quorum formation with invalid state
- Cause permanent network partition if multiple validators hit this condition

## Likelihood Explanation

**Likelihood: Medium-High**

The vulnerability triggers when:
- Database write failures occur (disk full, I/O errors, corruption)
- Block tree inconsistencies arise from race conditions
- Epoch boundaries create timing issues with block pruning
- State sync interrupts commit operations

These are realistic operational scenarios, especially:
- During high load or resource exhaustion
- Hardware failures or network partitions
- Rapid epoch transitions
- Concurrent state sync and commit operations

The code path is automatically triggered during normal consensus operation, requiring no attacker action.

## Recommendation

**Fix: Propagate and check commit errors**

```rust
// In consensus/src/pipeline/persisting_phase.rs
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
        // FIX: Check commit result instead of ignoring
        if let Err(e) = b.check_commit_ledger_result().await {
            error!("Block {} commit failed: {}", b.id(), e);
            return Err(ExecutorError::InternalError {
                error: format!("Commit failed for block {}: {}", b.id(), e),
            });
        }
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

**Add new method in pipelined_block.rs:**
```rust
pub async fn check_commit_ledger_result(&self) -> ExecutorResult<()> {
    if let Some(fut) = self.pipeline_futs() {
        match fut.commit_ledger_fut.await {
            Ok(_) => Ok(()),
            Err(e) => Err(ExecutorError::InternalError {
                error: format!("Commit ledger failed: {}", e),
            }),
        }
    } else {
        Err(ExecutorError::InternalError {
            error: "Pipeline aborted".to_string(),
        })
    }
}
```

## Proof of Concept

```rust
// Test in consensus/src/pipeline/tests/persisting_phase_test.rs
#[tokio::test]
async fn test_persisting_phase_commit_failure_propagation() {
    // Setup: Create blocks with mocked executor that fails on second commit
    let mock_executor = MockExecutor::new_with_failure_at(1); // Fail at block index 1
    
    // Create persisting request with 3 blocks
    let blocks = vec![
        create_test_block(1),
        create_test_block(2), // This will fail to commit
        create_test_block(3),
    ];
    
    let persisting_phase = PersistingPhase::new(/* ... */);
    
    // Execute persisting request
    let result = persisting_phase.process(PersistingRequest {
        blocks,
        commit_ledger_info: create_test_ledger_info(),
    }).await;
    
    // EXPECTED: Should return error, not Ok(round 3)
    // ACTUAL (BUG): Returns Ok(3) even though block 2 failed
    assert!(result.is_err(), "Persisting should fail when individual commit fails");
    assert_eq!(
        highest_committed_round, 
        1, // Only block 1 should be committed
        "highest_committed_round should not advance past failed commits"
    );
}
```

**Reproduction steps:**
1. Configure node with limited disk space or inject fail point at `executor::commit_blocks` [6](#0-5) 

2. Submit transactions to fill blocks
3. Trigger consensus to commit multiple blocks in a batch
4. Observe persisting phase returns success while `commit_ledger` fails internally
5. Check `highest_committed_round` advances beyond actual ledger state
6. Restart node - committed blocks are missing, causing `BlockNotFound` errors

## Notes

The vulnerability is exacerbated by the fact that `commit_ledger_fut` is spawned without an abort handle (passed `None`), making it non-cancellable but still failable through internal errors. The design assumption that commit should always succeed after pre-commit is violated by operational realities like database failures and resource exhaustion.

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

**File:** consensus/consensus-types/src/pipelined_block.rs (L562-568)
```rust
    pub async fn wait_for_commit_ledger(&self) {
        // may be aborted (e.g. by reset)
        if let Some(fut) = self.pipeline_futs() {
            // this may be cancelled
            let _ = fut.commit_ledger_fut.await;
        }
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

**File:** execution/executor/src/block_executor/mod.rs (L362-395)
```rust
    fn commit_ledger(&self, ledger_info_with_sigs: LedgerInfoWithSignatures) -> ExecutorResult<()> {
        let _timer = OTHER_TIMERS.timer_with(&["commit_ledger"]);

        let block_id = ledger_info_with_sigs.ledger_info().consensus_block_id();
        info!(
            LogSchema::new(LogEntry::BlockExecutor).block_id(block_id),
            "commit_ledger"
        );

        // Check for any potential retries
        // TODO: do we still have such retries?
        let committed_block = self.block_tree.root_block();
        if committed_block.num_persisted_transactions()?
            == ledger_info_with_sigs.ledger_info().version() + 1
        {
            return Ok(());
        }

        // Confirm the block to be committed is tracked in the tree.
        self.block_tree.get_block(block_id)?;

        fail_point!("executor::commit_blocks", |_| {
            Err(anyhow::anyhow!("Injected error in commit_blocks.").into())
        });

        let target_version = ledger_info_with_sigs.ledger_info().version();
        self.db
            .writer
            .commit_ledger(target_version, Some(&ledger_info_with_sigs), None)?;

        self.block_tree.prune(ledger_info_with_sigs.ledger_info())?;

        Ok(())
    }
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

# Audit Report

## Title
Consensus Persisting Phase Fails to Validate Commit Success, Causing State Inconsistency and Potential Liveness Failure

## Summary
The `PersistingPhase::process()` function unconditionally returns success even when block commits fail, causing the buffer manager to incorrectly update `highest_committed_round` and creating state divergence between consensus layer tracking and actual storage state that can lead to individual validator liveness failure.

## Finding Description

The persisting phase is responsible for waiting for block commit operations to complete. However, it contains a critical flaw in error handling that allows commit failures to be silently ignored.

The vulnerability exists in the `wait_for_commit_ledger()` method, which discards the Result returned by `commit_ledger_fut` with `let _`: [1](#0-0) 

The `commit_ledger_fut` future resolves to a `TaskResult<CommitLedgerResult>` (which is `Result<Option<LedgerInfoWithSignatures>, TaskError>`), meaning errors can occur and are being silently discarded.

The commit_ledger pipeline stage can indeed fail. The executor's implementation shows multiple error paths including database writes and failpoint injection: [2](#0-1) 

The database writer's commit_ledger can fail with I/O errors, storage errors, and validation failures during actual persistence: [3](#0-2) 

The pipeline correctly propagates errors through dependency chains using the `?` operator: [4](#0-3) 

However, despite these error propagation mechanisms, the persisting phase never checks whether commits actually succeeded. It unconditionally returns `Ok(last_block.round())` regardless of commit outcomes: [5](#0-4) 

When the buffer manager receives this response, it unconditionally updates `highest_committed_round` and clears `pending_commit_blocks`: [6](#0-5) 

Note that there is no error handling branch for `Some(Err(_))` cases from the persisting phase.

**Exploitation Path:**

1. Buffer manager sends batch of blocks [A, B, C] at rounds [10, 11, 12] to persisting phase
2. Block A commits successfully to storage (version 110)
3. Block B's commit fails (database error, disk full, corruption, etc.) at the executor level
4. Due to pipeline dependencies, Block C's commit also fails when awaiting parent
5. Persisting phase still returns `Ok(12)` - claiming success
6. Buffer manager updates `highest_committed_round = 12` and cleans up `pending_commit_blocks`
7. System state is now inconsistent:
   - Storage layer: committed up to version 110 (round 10)
   - Consensus layer: believes committed up to round 12

When subsequent blocks arrive, they depend on rounds 11-12 which failed to commit, creating a cascade of failures that halts consensus progress for this validator.

## Impact Explanation

**Severity: Medium**

This violates the **State Consistency** invariant. The consensus layer believes blocks are committed when they are not, breaking the fundamental assumption that committed rounds are durably persisted.

**Impact:**
- **Individual Validator Liveness Failure**: The affected validator cannot make progress. All subsequent commit attempts will fail due to missing parent blocks in storage, but the buffer manager believes those parents are committed and won't retry.
- **State Divergence**: Consensus metadata becomes inconsistent with storage reality, requiring node restart to recover.
- **Manual Intervention Required**: Operator must restart the validator node to recover.

This aligns with **MEDIUM severity** in the Aptos bug bounty program: "state inconsistencies requiring manual intervention" and "temporary liveness issues" affecting individual validators. The report correctly notes that this:
- Only affects individual validators (not network-wide)
- Is recoverable through node restart
- Does not result in fund loss or permanent network partition

## Likelihood Explanation

**Likelihood: Medium to High**

While this requires commit failures (database errors, disk full, I/O failures, corruption), these are realistic operational scenarios:
- High transaction throughput causing disk I/O saturation
- Storage resource exhaustion
- Database corruption from power failures
- Concurrent write conflicts in edge cases

The bug manifests automatically once a commit failure occurs—no attacker action is needed. Given the scale of Aptos validator operations, commit failures will eventually occur during normal operations.

The failpoint injection at the executor level confirms this is a testable and realistic failure mode: [7](#0-6) 

**Mitigation Factor**: The issue self-corrects on node restart as the buffer manager re-initializes from storage state. However, this requires manual intervention and causes service disruption.

## Recommendation

The `wait_for_commit_ledger()` method should propagate errors instead of discarding them, and the `PersistingPhase::process()` function should check commit results and return appropriate errors.

**Recommended Fix:**

1. Change `wait_for_commit_ledger()` to return the Result:
```rust
pub async fn wait_for_commit_ledger(&self) -> TaskResult<()> {
    if let Some(fut) = self.pipeline_futs() {
        fut.commit_ledger_fut.await?;
    }
    Ok(())
}
```

2. Update `PersistingPhase::process()` to check commit results:
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
        // Propagate errors from commit_ledger
        b.wait_for_commit_ledger().await?;
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

3. Add error handling in buffer manager's event loop to handle `Some(Err(_))` from persisting phase and trigger appropriate recovery logic.

## Proof of Concept

The failpoint injection mechanism provides a built-in test capability:

```rust
// In executor::commit_ledger
fail_point!("executor::commit_blocks", |_| {
    Err(anyhow::anyhow!("Injected error in commit_blocks.").into())
});
```

A test case can inject this failure to demonstrate that:
1. The commit_ledger operation fails at the executor level
2. The error is silently discarded in wait_for_commit_ledger()
3. The persisting phase returns Ok(round) despite the failure
4. The buffer manager updates highest_committed_round incorrectly
5. Subsequent operations fail due to missing parent blocks in storage

This can be verified by checking that `highest_committed_round` in the buffer manager differs from the actual committed version in storage after the failure is injected.

## Notes

The vulnerability is valid and demonstrates a genuine state consistency issue in the consensus pipeline. However, the severity classification should be **MEDIUM** rather than HIGH, as it:
- Affects only individual validators, not the network as a whole
- Is recoverable through node restart without data loss
- Does not enable fund theft or permanent network damage
- Matches the bug bounty framework's MEDIUM category: "state inconsistencies requiring manual intervention and temporary liveness issues"

### Citations

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

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L78-112)
```rust
    fn commit_ledger(
        &self,
        version: Version,
        ledger_info_with_sigs: Option<&LedgerInfoWithSignatures>,
        chunk_opt: Option<ChunkToCommit>,
    ) -> Result<()> {
        gauged_api("commit_ledger", || {
            // Pre-committing and committing in concurrency is allowed but not pre-committing at the
            // same time from multiple threads, the same for committing.
            // Consensus and state sync must hand over to each other after all pending execution and
            // committing complete.
            let _lock = self
                .commit_lock
                .try_lock()
                .expect("Concurrent committing detected.");
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["commit_ledger"]);

            let old_committed_ver = self.get_and_check_commit_range(version)?;

            let mut ledger_batch = SchemaBatch::new();
            // Write down LedgerInfo if provided.
            if let Some(li) = ledger_info_with_sigs {
                self.check_and_put_ledger_info(version, li, &mut ledger_batch)?;
            }
            // Write down commit progress
            ledger_batch.put::<DbMetadataSchema>(
                &DbMetadataKey::OverallCommitProgress,
                &DbMetadataValue::Version(version),
            )?;
            self.ledger_db.metadata_db().write_schemas(ledger_batch)?;

            // Notify the pruners, invoke the indexer, and update in-memory ledger info.
            self.post_commit(old_committed_ver, version, ledger_info_with_sigs, chunk_opt)
        })
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

**File:** consensus/src/pipeline/buffer_manager.rs (L968-973)
```rust
                Some(Ok(round)) = self.persisting_phase_rx.next() => {
                    // see where `need_backpressure()` is called.
                    self.pending_commit_votes = self.pending_commit_votes.split_off(&(round + 1));
                    self.highest_committed_round = round;
                    self.pending_commit_blocks = self.pending_commit_blocks.split_off(&(round + 1));
                },
```

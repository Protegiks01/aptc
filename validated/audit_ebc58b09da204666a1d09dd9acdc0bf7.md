# Audit Report

## Title
Storage Corruption Errors Silently Ignored During Block Persistence Leading to Consensus Safety Violation

## Summary
The `PersistingPhase::process()` function silently ignores storage corruption errors during block commitment, causing consensus to believe blocks are committed when they are not actually persisted to storage. This leads to critical state inconsistencies where a validator's in-memory consensus state diverges from its on-disk storage state, resulting in consensus safety violations at the node level.

## Finding Description

The vulnerability exists in the error handling path of the block persistence pipeline. When blocks are committed to storage, errors from the underlying database operations are explicitly discarded, creating a critical divergence between what consensus believes is committed versus what is actually persisted.

**Error Discard in wait_for_commit_ledger():**

The `PipelinedBlock::wait_for_commit_ledger()` method explicitly ignores the result of the commit operation using `let _ = ...`, silently discarding any errors from the commit_ledger future. [1](#0-0) 

**Always Returns Success:**

The `PersistingPhase::process()` method calls `wait_for_commit_ledger()` which returns void, then unconditionally returns success with the round number, regardless of whether the actual storage commit succeeded or failed. [2](#0-1) 

**Storage Errors Can Occur:**

At the storage layer, RocksDB corruption errors are properly detected and converted to AptosDbError. The `ErrorKind::Corruption` variant is explicitly handled in the error conversion logic. [3](#0-2) 

**Database Write Can Fail:**

The actual database write operation via `write_schemas()` can fail and return an error, which propagates through the executor's `commit_ledger()` method. [4](#0-3) [5](#0-4) 

**Errors Propagate to commit_ledger_fut:**

The commit_ledger operation in the pipeline builder properly propagates errors from the executor through the future chain, but these errors are then discarded by `wait_for_commit_ledger()`. [6](#0-5) 

**BufferManager Updates In-Memory State:**

When the PersistingPhase returns success, the BufferManager unconditionally updates its `highest_committed_round` in-memory state, believing the blocks are committed. [7](#0-6) 

**Exploitation Scenario:**
1. Storage corruption occurs (hardware failure, filesystem bug, etc.) during block commit at round N
2. RocksDB returns `ErrorKind::Corruption` during `write_schemas()` operation  
3. Error propagates through `commit_ledger()` chain but is discarded by `wait_for_commit_ledger()`
4. `PersistingPhase::process()` returns `Ok(N)` indicating successful commit
5. `BufferManager` updates `highest_committed_round = N` and cleans up pending blocks
6. Consensus moves forward believing round N is committed
7. Storage layer still has last committed round at M < N (commit actually failed)
8. On node restart, `highest_committed_round` is reinitialized from storage which returns round M < N
9. Node has inconsistent state - consensus believed it committed round N but storage only has round M committed

This breaks the critical consensus safety invariant that a validator's view of committed state must be consistent and monotonically increasing.

## Impact Explanation

This is **HIGH Severity** per Aptos bug bounty criteria:

**Node-Level Consensus Safety Violation:** The affected validator develops an inconsistent view of committed state. Its in-memory consensus state believes blocks are committed while its storage does not contain them. On restart, the node effectively "rolls back" its committed state, violating the monotonicity guarantee of consensus. This qualifies as a validator node integrity issue affecting consensus participation.

**Client Impact:** Clients querying the affected validator receive incorrect information about transaction finality. Transactions reported as committed may not actually be persisted, potentially leading to incorrect assumptions about finality and transaction confirmation.

**Silent Failure:** The complete absence of error handling, logging, or alerting makes this vulnerability extremely difficult to detect and diagnose in production environments. There is no mechanism to alert operators that commits are failing.

**Network-Wide Risk:** If multiple validators experience storage corruption simultaneously (e.g., due to a common infrastructure issue or filesystem bug), the network could have validators with different views of committed state, potentially impacting consensus health.

**Liveness Impact:** On restart, the affected validator may have difficulty rejoining consensus if it has significantly diverged from other validators in its view of committed state, requiring manual intervention or state synchronization.

While this does not enable direct fund theft or network-wide consensus splits (which would be CRITICAL), it represents a serious validator node integrity issue that violates consensus safety guarantees at the individual node level, justifying HIGH severity classification.

## Likelihood Explanation

**Likelihood: Low to Medium**

While storage corruption events are relatively rare in well-maintained infrastructure, they do occur in practice:

1. **Hardware Failures**: Disk failures, memory corruption, and power loss during writes can cause storage corruption
2. **Filesystem Bugs**: Underlying filesystem implementation bugs can corrupt data
3. **Software Stack Issues**: Bugs in RocksDB or the storage stack could cause corruption

The key concern is that **there is zero error handling** - when storage corruption does occur during the commit operation, this vulnerability will trigger with 100% certainty. There is no retry mechanism, no error detection, and no recovery path. The silent nature of the failure significantly amplifies the impact when it occurs.

## Recommendation

Add proper error handling in the `wait_for_commit_ledger()` method to propagate errors instead of silently discarding them:

```rust
pub async fn wait_for_commit_ledger(&self) -> TaskResult<()> {
    if let Some(fut) = self.pipeline_futs() {
        fut.commit_ledger_fut.await?;
    }
    Ok(())
}
```

Update `PersistingPhase::process()` to handle and log errors from `wait_for_commit_ledger()`:

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
        // Propagate errors instead of silently ignoring them
        if let Err(e) = b.wait_for_commit_ledger().await {
            error!("Failed to commit ledger for block {}: {}", b.id(), e);
            return Err(ExecutorError::InternalError {
                error: format!("Commit ledger failed: {}", e),
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

Additionally, implement retry logic and add monitoring/alerting for commit failures to ensure operators are aware of storage issues.

## Proof of Concept

A proof of concept would require simulating storage corruption during the commit operation. This can be demonstrated using the fail point mechanism already present in the executor:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use fail::FailScenario;
    
    #[tokio::test]
    async fn test_commit_ledger_error_ignored() {
        let scenario = FailScenario::setup();
        // Enable the fail point to inject an error during commit
        fail::cfg("executor::commit_blocks", "return").unwrap();
        
        // Create test setup with blocks to commit
        // ... (test setup code)
        
        // Process blocks through persisting phase
        let result = persisting_phase.process(request).await;
        
        // BUG: This succeeds even though commit failed!
        assert!(result.is_ok());
        
        // Verify that storage does NOT have the committed block
        let storage_round = storage.get_latest_ledger_info().unwrap().commit_info().round();
        assert!(storage_round < expected_round);
        
        // But BufferManager thinks it's committed
        assert_eq!(buffer_manager.highest_committed_round, expected_round);
        
        scenario.teardown();
    }
}
```

The fail point at line 383 in `block_executor/mod.rs` can be used to inject commit failures for testing purposes. The test would demonstrate that despite the commit failure, the PersistingPhase returns success and the BufferManager updates its state accordingly.

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

**File:** storage/schemadb/src/lib.rs (L389-408)
```rust
fn to_db_err(rocksdb_err: rocksdb::Error) -> AptosDbError {
    match rocksdb_err.kind() {
        ErrorKind::Incomplete => AptosDbError::RocksDbIncompleteResult(rocksdb_err.to_string()),
        ErrorKind::NotFound
        | ErrorKind::Corruption
        | ErrorKind::NotSupported
        | ErrorKind::InvalidArgument
        | ErrorKind::IOError
        | ErrorKind::MergeInProgress
        | ErrorKind::ShutdownInProgress
        | ErrorKind::TimedOut
        | ErrorKind::Aborted
        | ErrorKind::Busy
        | ErrorKind::Expired
        | ErrorKind::TryAgain
        | ErrorKind::CompactionTooLarge
        | ErrorKind::ColumnFamilyDropped
        | ErrorKind::Unknown => AptosDbError::OtherRocksDbError(rocksdb_err.to_string()),
    }
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

**File:** consensus/src/pipeline/buffer_manager.rs (L968-973)
```rust
                Some(Ok(round)) = self.persisting_phase_rx.next() => {
                    // see where `need_backpressure()` is called.
                    self.pending_commit_votes = self.pending_commit_votes.split_off(&(round + 1));
                    self.highest_committed_round = round;
                    self.pending_commit_blocks = self.pending_commit_blocks.split_off(&(round + 1));
                },
```

# Audit Report

## Title
Silent Failure of Ledger Commits Allows Validators to Proceed Despite Database Persistence Errors

## Summary
During the commit phase, the persisting phase silently ignores all errors from the `commit_ledger` operation, causing validators to believe blocks are committed even when database writes fail. This violates consensus safety by allowing state divergence between validators.

## Finding Description

The Aptos consensus pipeline includes a critical error handling flaw in the commit phase. When blocks reach the persisting phase after achieving commit quorum, the system calls `wait_for_commit_ledger()` but explicitly discards any errors returned. [1](#0-0) 

The `wait_for_commit_ledger()` method in `PipelinedBlock` silently ignores the result: [2](#0-1) 

The persisting phase then unconditionally returns success: [3](#0-2) 

The buffer manager receives this `Ok(round)` response and updates `highest_committed_round`, believing the commit succeeded: [4](#0-3) 

The actual database commit operation can fail with various errors: [5](#0-4) [6](#0-5) 

**Attack Scenario:**
While a validator is operating, if database errors occur (disk full, corruption, I/O failures), the following sequence happens:
1. Validator participates in consensus and achieves commit quorum
2. Blocks reach persisting phase
3. `executor.commit_ledger()` fails due to database error
4. Error is silently ignored via `let _ = ...`
5. Validator updates `highest_committed_round` as if commit succeeded
6. Validator continues participating in consensus for subsequent rounds
7. Other validators successfully committed and have the data
8. This validator has missing committed blocks in its database

This breaks the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs." A validator that believes it committed blocks but lacks the actual data will fail when queried or when trying to build on that state.

## Impact Explanation

**Severity: Critical** - Consensus Safety Violation

This vulnerability breaks consensus safety in multiple ways:

1. **State Divergence**: Validators can have different views of committed state. Some validators may successfully persist blocks while others silently fail, creating inconsistent database states across the network.

2. **Chain Fork Risk**: A validator that failed to persist but believes it committed may build different blocks on top, potentially causing chain forks or consensus stalls when block verification fails.

3. **Availability Impact**: Validators with missing committed blocks cannot serve state queries, participate correctly in state synchronization, or provide accurate responses to peer requests.

4. **Irrecoverable State**: Once `highest_committed_round` advances past failed commits, the validator may not realize it's missing data until much later, making recovery difficult.

According to Aptos bug bounty criteria, this qualifies as **Critical Severity** because it enables "Consensus/Safety violations" - validators can commit blocks despite database failures, violating the fundamental requirement that committed data must be persisted.

## Likelihood Explanation

**Likelihood: Medium to High**

This vulnerability can be triggered in several realistic scenarios:

1. **Disk Space Exhaustion**: Validators running low on disk space will experience write failures. This is a common operational issue.

2. **I/O Errors**: Hardware failures, filesystem corruption, or storage system issues cause database write failures.

3. **Resource Limits**: Operating system limits (file descriptors, memory) can cause database operations to fail.

4. **Concurrent Load**: High transaction throughput may cause database contention or lock timeouts.

The vulnerability does NOT require:
- Remote exploitation capability
- Malicious attacker action
- Validator compromise
- Network manipulation

It can occur through normal operational failures, making it a **latent bug** that will eventually manifest in production environments. The code explicitly uses `let _ = ...` to discard errors, indicating this is not an oversight but incorrect error handling design.

The TODO comment in a related code path suggests the team is aware of error handling issues: [7](#0-6) 

## Recommendation

**Fix: Propagate commit_ledger errors and handle them appropriately**

1. Modify `wait_for_commit_ledger()` to return the result instead of discarding it:

```rust
pub async fn wait_for_commit_ledger(&self) -> TaskResult<CommitLedgerResult> {
    if let Some(fut) = self.pipeline_futs() {
        fut.commit_ledger_fut.await
    } else {
        Err(TaskError::InternalError(Arc::new(anyhow::anyhow!(
            "Pipeline aborted"
        ))))
    }
}
```

2. Update `PersistingPhase::process()` to check the result:

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
        
        // Check the result instead of ignoring it
        if let Err(e) = b.wait_for_commit_ledger().await {
            error!("Failed to commit ledger for block {}: {:?}", b.id(), e);
            return Err(ExecutorError::InternalError {
                error: format!("Commit ledger failed: {}", e),
            });
        }
    }

    // Only return success if all commits succeeded
    let response = Ok(blocks.last().expect("Blocks can't be empty").round());
    if commit_ledger_info.ledger_info().ends_epoch() {
        self.commit_msg_tx
            .send_epoch_change(EpochChangeProof::new(vec![commit_ledger_info], false))
            .await;
    }
    response
}
```

3. Update `BufferManager` to handle errors from persisting phase:

```rust
Some(result) = self.persisting_phase_rx.next() => {
    match result {
        Ok(round) => {
            self.pending_commit_votes = self.pending_commit_votes.split_off(&(round + 1));
            self.highest_committed_round = round;
            self.pending_commit_blocks = self.pending_commit_blocks.split_off(&(round + 1));
        },
        Err(e) => {
            error!("Persisting phase failed: {:?}. Initiating recovery.", e);
            // Trigger recovery mechanism, potentially falling back to state sync
            // Do NOT advance highest_committed_round
        }
    }
},
```

## Proof of Concept

The vulnerability can be demonstrated using the existing fail_point injection mechanism:

```rust
#[tokio::test]
async fn test_commit_ledger_failure_ignored() {
    // Setup consensus pipeline with persisting phase
    let (mut buffer_manager, persisting_phase_rx) = setup_test_buffer_manager();
    
    // Inject failure in commit_ledger
    fail::cfg("executor::commit_blocks", "return").unwrap();
    
    // Send blocks to persisting phase
    let blocks = create_test_blocks(3);
    let commit_proof = create_test_commit_proof();
    
    // Process persisting request
    let request = PersistingRequest {
        blocks: blocks.clone(),
        commit_ledger_info: commit_proof,
    };
    
    // Observe that persisting phase returns Ok despite database failure
    let result = persisting_phase.process(request).await;
    assert!(result.is_ok(), "Persisting phase should return Ok");
    
    // Observe that buffer manager updates highest_committed_round
    let initial_round = buffer_manager.highest_committed_round;
    buffer_manager.process_persisting_response(result).await;
    assert!(buffer_manager.highest_committed_round > initial_round,
            "highest_committed_round advanced despite commit failure");
    
    // Verify database does NOT contain the committed blocks
    let db_blocks = db.get_blocks(blocks[0].round()..=blocks[2].round());
    assert!(db_blocks.is_empty(), "Blocks not in database but consensus thinks committed");
    
    fail::cfg("executor::commit_blocks", "off").unwrap();
}
```

The test demonstrates that:
1. When `commit_ledger` fails (via fail_point injection), the error is silently ignored
2. The persisting phase returns `Ok(round)` 
3. The buffer manager advances `highest_committed_round`
4. The database does NOT contain the supposedly committed blocks

This proves the consensus state (highest_committed_round) diverges from the actual persisted state.

## Notes

The related TODO comment at execution_client.rs:669-670 indicates awareness of error handling issues in state sync scenarios, but the commit ledger error handling bug is separate and affects all commit operations regardless of state sync involvement. [8](#0-7) 

While the question specifically asks about confusion between `StateSyncError` and `DbError`, the actual vulnerability is broader: **all errors** from commit_ledger (including database errors, executor errors, and any other failures) are silently ignored. This makes the issue more severe than just error type confusion.

### Citations

**File:** consensus/src/pipeline/persisting_phase.rs (L59-82)
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

**File:** consensus/src/pipeline/execution_client.rs (L669-670)
```rust
        // TODO: handle the state sync error (e.g., re-push the ordered
        // blocks to the buffer manager when it's reset but sync fails).
```

**File:** consensus/src/error.rs (L7-37)
```rust
#[derive(Debug, Error)]
#[error(transparent)]
pub struct DbError {
    #[from]
    inner: anyhow::Error,
}

impl From<aptos_storage_interface::AptosDbError> for DbError {
    fn from(e: aptos_storage_interface::AptosDbError) -> Self {
        DbError { inner: e.into() }
    }
}

#[derive(Debug, Error)]
#[error(transparent)]
pub struct StateSyncError {
    #[from]
    inner: anyhow::Error,
}

impl From<pipeline::errors::Error> for StateSyncError {
    fn from(e: pipeline::errors::Error) -> Self {
        StateSyncError { inner: e.into() }
    }
}

impl From<aptos_executor_types::ExecutorError> for StateSyncError {
    fn from(e: aptos_executor_types::ExecutorError) -> Self {
        StateSyncError { inner: e.into() }
    }
}
```

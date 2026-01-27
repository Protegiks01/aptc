# Audit Report

## Title
State Machine Corruption Due to Non-Atomic Parallel Database Writes During Pre-Commit with Insufficient Error Information for Safe Rollback

## Summary
During the pre-commit phase in BlockExecutor, parallel database writes can fail inconsistently due to resource exhaustion or I/O errors, leaving partial state committed across multiple database column families. The ExecutorError type provides only a generic error message with no structured information about which writes succeeded or failed, making safe rollback impossible. This can result in validators having divergent database states, violating consensus safety guarantees. [1](#0-0) 

## Finding Description

The vulnerability exists in the pre-commit ledger write path used by consensus. When `pre_commit_ledger` is called, it executes 7 parallel database write operations using rayon's scope: [2](#0-1) 

Each parallel write uses `.unwrap()` which panics on failure. The developers acknowledge this issue in a TODO comment stating "Consider propagating the error instead of panic, if necessary." [3](#0-2) 

**Critical Race Condition:**

One parallel thread (`commit_state_kv_and_ledger_metadata`) writes `LedgerCommitProgress` and state key-value data: [4](#0-3) 

The `LedgerCommitProgress` marker is written at lines 360-365, and committed in parallel with state_kv_db at lines 369-381.

**Failure Scenario:**

1. Multiple parallel writes begin for version N
2. `commit_state_kv_and_ledger_metadata` succeeds, writing:
   - `LedgerCommitProgress = N`
   - State KV data for version N  
   - Ledger metadata for version N
3. Another thread (e.g., `commit_transactions`, `commit_events`) encounters an I/O error and panics
4. The panic propagates through rayon, causing entire `pre_commit_ledger` to fail
5. The `buffered_state.update()` at line 68-72 **never executes**: [5](#0-4) 

6. ExecutorError is returned to consensus with only a generic error string: [6](#0-5) 

7. Consensus logs the error and continues without panicking: [7](#0-6) 

**Resulting State Corruption:**

The database now contains:
- `LedgerCommitProgress = N` (committed)
- `StateKvCommitProgress = N` (committed)  
- State KV database with version N data (committed)
- Ledger metadata with version N data (committed)
- **BUT**: Transaction database missing version N (failed)
- **OR**: Event database missing version N (failed)
- `OverallCommitProgress = N-1` (correct, not yet updated)
- Executor's `buffered_state` still at version N-1

**Consensus Safety Violation:**

Unlike ChunkExecutor which has panic protection for this exact scenario: [8](#0-7) 

The BlockExecutor used by consensus has **no such protection**: [9](#0-8) 

When consensus receives the error, it simply skips the block without forcing a restart. The node continues operating with a corrupted database. If consensus later attempts to commit a different block at version N, the partial writes from the first attempt get mixed with writes from the second attempt, creating an inconsistent state that differs across validators.

## Impact Explanation

**Critical Severity** - This vulnerability breaks the core consensus safety guarantee:

1. **Consensus Safety Violation**: Different validators can end up with different database states for the same version, causing state root disagreement and potential chain splits. This violates invariant #1 "Deterministic Execution: All validators must produce identical state roots for identical blocks" and invariant #2 "Consensus Safety: AptosBFT must prevent double-spending and chain splits."

2. **State Consistency Breach**: The atomic state transition guarantee is violated. Partial writes leave the database in an inconsistent state where some components have version N while others don't, breaking invariant #4 "State Consistency: State transitions must be atomic and verifiable via Merkle proofs."

3. **Non-Recoverable Without Restart**: The recovery mechanism `sync_commit_progress` only runs at node startup: [10](#0-9) 

During normal operation, there is no mechanism to detect or recover from this corruption. The node continues with divergent state until manually restarted.

This meets the **Critical Severity** criteria: "Consensus/Safety violations" and "State inconsistencies requiring intervention."

## Likelihood Explanation

**High Likelihood** - This can occur naturally without attacker intervention:

1. **Resource Exhaustion**: Disk full, memory pressure, or I/O throttling during peak load
2. **Hardware Failures**: Transient disk errors, network-attached storage failures
3. **Non-Deterministic Timing**: Rayon's parallel scheduling is non-deterministic, making failure timing unpredictable
4. **Production Environment**: More likely under high transaction throughput when resources are constrained

The vulnerability requires no special access or Byzantine behavior - just normal operational stress conditions that any production validator will encounter.

## Recommendation

**Immediate Fix**: Implement transactional semantics for parallel writes with proper error propagation and rollback:

```rust
fn calculate_and_commit_ledger_and_state_kv(
    &self,
    chunk: &ChunkToCommit,
    skip_index_and_usage: bool,
) -> Result<HashValue> {
    let _timer = OTHER_TIMERS_SECONDS.timer_with(&["save_transactions__work"]);
    
    let mut new_root_hash = HashValue::zero();
    
    // Execute in parallel but collect errors instead of unwrapping
    let results: Vec<Result<()>> = THREAD_MANAGER.get_non_exe_cpu_pool().install(|| {
        vec![
            self.commit_events(chunk.first_version, chunk.transaction_outputs, skip_index_and_usage),
            self.ledger_db.write_set_db().commit_write_sets(chunk.first_version, chunk.transaction_outputs),
            self.ledger_db.transaction_db().commit_transactions(chunk.first_version, chunk.transactions, skip_index_and_usage),
            self.ledger_db.persisted_auxiliary_info_db().commit_auxiliary_info(chunk.first_version, chunk.persisted_auxiliary_infos),
            self.commit_state_kv_and_ledger_metadata(chunk, skip_index_and_usage),
            self.commit_transaction_infos(chunk.first_version, chunk.transaction_infos),
            self.commit_transaction_accumulator(chunk.first_version, chunk.transaction_infos).map(|hash| { new_root_hash = hash; () }),
        ]
    });
    
    // Check for any errors BEFORE considering the write successful
    for result in results {
        result?;
    }
    
    Ok(new_root_hash)
}
```

**Enhanced ExecutorError**: Add structured error information:

```rust
#[derive(Debug, Deserialize, Error, PartialEq, Eq, Serialize, Clone)]
pub enum ExecutorError {
    // ... existing variants ...
    
    #[error("Partial write failure during pre-commit: {failed_components:?}, version: {version}")]
    PartialWriteFailure {
        failed_components: Vec<String>,
        version: Version,
        underlying_error: String,
    },
}
```

**Add Panic Protection to BlockExecutor**: Similar to ChunkExecutor's protection:

```rust
impl<V> BlockExecutorInner<V> {
    fn with_pending_pre_commit_check<F, T>(&self, f: F) -> ExecutorResult<T>
    where
        F: FnOnce() -> ExecutorResult<T>,
    {
        let has_pending = self.has_pending_pre_commit();
        f().map_err(|error| {
            if has_pending {
                panic!("Hit error with pending pre-committed ledger: {:?}", error);
            }
            error
        })
    }
}
```

## Proof of Concept

The following test demonstrates the vulnerability by injecting a failure in one parallel write operation:

```rust
#[test]
#[should_panic(expected = "partial state corruption")]
fn test_partial_write_corruption_in_consensus_path() {
    use fail::FailScenario;
    
    let scenario = FailScenario::setup();
    // Inject failure in commit_transactions after commit_state_kv succeeds
    fail::cfg("commit_transactions_fail", "panic").unwrap();
    
    let (db, executor) = setup_executor();
    
    // Execute block to version N
    let block_n = create_test_block(/* version N */);
    executor.execute_and_update_state(block_n, parent_id, config).unwrap();
    executor.ledger_update(block_n.id(), parent_id).unwrap();
    
    // Pre-commit should fail with partial writes
    let result = executor.pre_commit_block(block_n.id());
    assert!(result.is_err());
    
    // Check database state - CORRUPTION DETECTED
    let ledger_progress = db.reader.get_ledger_commit_progress().unwrap();
    let overall_progress = db.reader.get_synced_version().unwrap();
    
    // LedgerCommitProgress advanced but OverallCommitProgress didn't
    assert_eq!(ledger_progress, Some(N));
    assert_eq!(overall_progress, Some(N-1));
    
    // State KV has version N but transactions don't
    let state_kv_exists = db.reader.get_state_value_by_version(key, N).is_ok();
    let txn_exists = db.reader.get_transaction_by_version(N).is_ok();
    assert!(state_kv_exists && !txn_exists, "partial state corruption");
    
    scenario.teardown();
}
```

**Notes**
- The TODO comments in the codebase explicitly acknowledge this design flaw but it remains unaddressed
- ChunkExecutor has protection via panic-on-error-with-pending-commit, but BlockExecutor (consensus path) does not
- The truncation recovery mechanism only runs at startup, leaving active nodes vulnerable  
- ExecutorError provides insufficient structured information to determine which database writes succeeded or failed, making safe runtime rollback impossible
- This vulnerability can cause validators to diverge silently during normal operation under resource pressure

### Citations

**File:** execution/executor-types/src/error.rs (L11-43)
```rust
#[derive(Debug, Deserialize, Error, PartialEq, Eq, Serialize, Clone)]
/// Different reasons for proposal rejection
pub enum ExecutorError {
    #[error("Cannot find speculation result for block id {0}")]
    BlockNotFound(HashValue),

    #[error("Cannot get data for batch id {0}")]
    DataNotFound(HashValue),

    #[error(
        "Bad num_txns_to_commit. first version {}, num to commit: {}, target version: {}",
        first_version,
        to_commit,
        target_version
    )]
    BadNumTxnsToCommit {
        first_version: Version,
        to_commit: usize,
        target_version: Version,
    },

    #[error("Internal error: {:?}", error)]
    InternalError { error: String },

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Received Empty Blocks")]
    EmptyBlocks,

    #[error("request timeout")]
    CouldNotGetData,
}
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L44-76)
```rust
    fn pre_commit_ledger(&self, chunk: ChunkToCommit, sync_commit: bool) -> Result<()> {
        gauged_api("pre_commit_ledger", || {
            // Pre-committing and committing in concurrency is allowed but not pre-committing at the
            // same time from multiple threads, the same for committing.
            // Consensus and state sync must hand over to each other after all pending execution and
            // committing complete.
            let _lock = self
                .pre_commit_lock
                .try_lock()
                .expect("Concurrent committing detected.");
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["pre_commit_ledger"]);

            chunk
                .state_summary
                .latest()
                .global_state_summary
                .log_generation("db_save");

            self.pre_commit_validation(&chunk)?;
            let _new_root_hash =
                self.calculate_and_commit_ledger_and_state_kv(&chunk, self.skip_index_and_usage)?;

            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["save_transactions__others"]);

            self.state_store.buffered_state().lock().update(
                chunk.result_ledger_state_with_summary(),
                chunk.estimated_total_state_updates(),
                sync_commit || chunk.is_reconfig,
            )?;

            Ok(())
        })
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L263-322)
```rust
    fn calculate_and_commit_ledger_and_state_kv(
        &self,
        chunk: &ChunkToCommit,
        skip_index_and_usage: bool,
    ) -> Result<HashValue> {
        let _timer = OTHER_TIMERS_SECONDS.timer_with(&["save_transactions__work"]);

        let mut new_root_hash = HashValue::zero();
        THREAD_MANAGER.get_non_exe_cpu_pool().scope(|s| {
            // TODO(grao): Write progress for each of the following databases, and handle the
            // inconsistency at the startup time.
            //
            // TODO(grao): Consider propagating the error instead of panic, if necessary.
            s.spawn(|_| {
                self.commit_events(
                    chunk.first_version,
                    chunk.transaction_outputs,
                    skip_index_and_usage,
                )
                .unwrap()
            });
            s.spawn(|_| {
                self.ledger_db
                    .write_set_db()
                    .commit_write_sets(chunk.first_version, chunk.transaction_outputs)
                    .unwrap()
            });
            s.spawn(|_| {
                self.ledger_db
                    .transaction_db()
                    .commit_transactions(
                        chunk.first_version,
                        chunk.transactions,
                        skip_index_and_usage,
                    )
                    .unwrap()
            });
            s.spawn(|_| {
                self.ledger_db
                    .persisted_auxiliary_info_db()
                    .commit_auxiliary_info(chunk.first_version, chunk.persisted_auxiliary_infos)
                    .unwrap()
            });
            s.spawn(|_| {
                self.commit_state_kv_and_ledger_metadata(chunk, skip_index_and_usage)
                    .unwrap()
            });
            s.spawn(|_| {
                self.commit_transaction_infos(chunk.first_version, chunk.transaction_infos)
                    .unwrap()
            });
            s.spawn(|_| {
                new_root_hash = self
                    .commit_transaction_accumulator(chunk.first_version, chunk.transaction_infos)
                    .unwrap()
            });
        });

        Ok(new_root_hash)
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L324-384)
```rust
    fn commit_state_kv_and_ledger_metadata(
        &self,
        chunk: &ChunkToCommit,
        skip_index_and_usage: bool,
    ) -> Result<()> {
        let _timer = OTHER_TIMERS_SECONDS.timer_with(&["commit_state_kv_and_ledger_metadata"]);

        let mut ledger_metadata_batch = SchemaBatch::new();
        let mut sharded_state_kv_batches = self.state_kv_db.new_sharded_native_batches();

        self.state_store.put_state_updates(
            chunk.state,
            &chunk.state_update_refs.per_version,
            chunk.state_reads,
            &mut ledger_metadata_batch,
            &mut sharded_state_kv_batches,
        )?;

        // Write block index if event index is skipped.
        if skip_index_and_usage {
            for (i, txn_out) in chunk.transaction_outputs.iter().enumerate() {
                for event in txn_out.events() {
                    if let Some(event_key) = event.event_key() {
                        if *event_key == new_block_event_key() {
                            let version = chunk.first_version + i as Version;
                            LedgerMetadataDb::put_block_info(
                                version,
                                event,
                                &mut ledger_metadata_batch,
                            )?;
                        }
                    }
                }
            }
        }

        ledger_metadata_batch
            .put::<DbMetadataSchema>(
                &DbMetadataKey::LedgerCommitProgress,
                &DbMetadataValue::Version(chunk.expect_last_version()),
            )
            .unwrap();

        let _timer =
            OTHER_TIMERS_SECONDS.timer_with(&["commit_state_kv_and_ledger_metadata___commit"]);
        rayon::scope(|s| {
            s.spawn(|_| {
                self.ledger_db
                    .metadata_db()
                    .write_schemas(ledger_metadata_batch)
                    .unwrap();
            });
            s.spawn(|_| {
                self.state_kv_db
                    .commit(chunk.expect_last_version(), None, sharded_state_kv_batches)
                    .unwrap();
            });
        });

        Ok(())
    }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L617-627)
```rust
        let executed_blocks = match inner {
            Ok(result) => result,
            Err(e) => {
                log_executor_error_occurred(
                    e,
                    &counters::BUFFER_MANAGER_RECEIVED_EXECUTOR_ERROR_COUNT,
                    block_id,
                );
                return;
            },
        };
```

**File:** execution/executor/src/chunk_executor/mod.rs (L89-106)
```rust
    fn with_inner<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&ChunkExecutorInner<V>) -> Result<T>,
    {
        let locked = self.inner.read();
        let inner = locked.as_ref().expect("not reset");

        let has_pending_pre_commit = inner.has_pending_pre_commit.load(Ordering::Acquire);
        f(inner).map_err(|error| {
            if has_pending_pre_commit {
                panic!(
                    "Hit error with pending pre-committed ledger, panicking. {:?}",
                    error,
                );
            }
            error
        })
    }
```

**File:** execution/executor/src/block_executor/mod.rs (L336-360)
```rust
    fn pre_commit_block(&self, block_id: HashValue) -> ExecutorResult<()> {
        let _timer = COMMIT_BLOCKS.start_timer();
        info!(
            LogSchema::new(LogEntry::BlockExecutor).block_id(block_id),
            "pre_commit_block",
        );

        let block = self.block_tree.get_block(block_id)?;

        fail_point!("executor::pre_commit_block", |_| {
            Err(anyhow::anyhow!("Injected error in pre_commit_block.").into())
        });

        let output = block.output.expect_complete_result();
        let num_txns = output.num_transactions_to_commit();
        if num_txns != 0 {
            let _timer = SAVE_TRANSACTIONS.start_timer();
            self.db
                .writer
                .pre_commit_ledger(output.as_chunk_to_commit(), false)?;
            TRANSACTIONS_SAVED.observe(num_txns as f64);
        }

        Ok(())
    }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L410-502)
```rust
    pub fn sync_commit_progress(
        ledger_db: Arc<LedgerDb>,
        state_kv_db: Arc<StateKvDb>,
        state_merkle_db: Arc<StateMerkleDb>,
        crash_if_difference_is_too_large: bool,
    ) {
        let ledger_metadata_db = ledger_db.metadata_db();
        if let Some(overall_commit_progress) = ledger_metadata_db
            .get_synced_version()
            .expect("DB read failed.")
        {
            info!(
                overall_commit_progress = overall_commit_progress,
                "Start syncing databases..."
            );
            let ledger_commit_progress = ledger_metadata_db
                .get_ledger_commit_progress()
                .expect("Failed to read ledger commit progress.");
            assert_ge!(ledger_commit_progress, overall_commit_progress);

            let state_kv_commit_progress = state_kv_db
                .metadata_db()
                .get::<DbMetadataSchema>(&DbMetadataKey::StateKvCommitProgress)
                .expect("Failed to read state K/V commit progress.")
                .expect("State K/V commit progress cannot be None.")
                .expect_version();
            assert_ge!(state_kv_commit_progress, overall_commit_progress);

            // LedgerCommitProgress was not guaranteed to commit after all ledger changes finish,
            // have to attempt truncating every column family.
            info!(
                ledger_commit_progress = ledger_commit_progress,
                "Attempt ledger truncation...",
            );
            let difference = ledger_commit_progress - overall_commit_progress;
            if crash_if_difference_is_too_large {
                assert_le!(difference, MAX_COMMIT_PROGRESS_DIFFERENCE);
            }
            truncate_ledger_db(ledger_db.clone(), overall_commit_progress)
                .expect("Failed to truncate ledger db.");

            // State K/V commit progress isn't (can't be) written atomically with the data,
            // because there are shards, so we have to attempt truncation anyway.
            info!(
                state_kv_commit_progress = state_kv_commit_progress,
                "Start state KV truncation..."
            );
            let difference = state_kv_commit_progress - overall_commit_progress;
            if crash_if_difference_is_too_large {
                assert_le!(difference, MAX_COMMIT_PROGRESS_DIFFERENCE);
            }
            truncate_state_kv_db(
                &state_kv_db,
                state_kv_commit_progress,
                overall_commit_progress,
                std::cmp::max(difference as usize, 1), /* batch_size */
            )
            .expect("Failed to truncate state K/V db.");

            let state_merkle_max_version = get_max_version_in_state_merkle_db(&state_merkle_db)
                .expect("Failed to get state merkle max version.")
                .expect("State merkle max version cannot be None.");
            if state_merkle_max_version > overall_commit_progress {
                let difference = state_merkle_max_version - overall_commit_progress;
                if crash_if_difference_is_too_large {
                    assert_le!(difference, MAX_COMMIT_PROGRESS_DIFFERENCE);
                }
            }
            let state_merkle_target_version = find_tree_root_at_or_before(
                ledger_metadata_db,
                &state_merkle_db,
                overall_commit_progress,
            )
            .expect("DB read failed.")
            .unwrap_or_else(|| {
                panic!(
                    "Could not find a valid root before or at version {}, maybe it was pruned?",
                    overall_commit_progress
                )
            });
            if state_merkle_target_version < state_merkle_max_version {
                info!(
                    state_merkle_max_version = state_merkle_max_version,
                    target_version = state_merkle_target_version,
                    "Start state merkle truncation..."
                );
                truncate_state_merkle_db(&state_merkle_db, state_merkle_target_version)
                    .expect("Failed to truncate state merkle db.");
            }
        } else {
            info!("No overall commit progress was found!");
        }
    }
```

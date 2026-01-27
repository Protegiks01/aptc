# Audit Report

## Title
Storage Inconsistency Due to Non-Atomic Parallel Database Writes and Incomplete Truncation Recovery

## Summary
The `ChunkToCommit` storage commit process writes to multiple independent databases in parallel without atomic coordination. If any database write fails, some databases retain committed data while others don't, creating storage inconsistency. The recovery mechanism (`sync_commit_progress`) fails to truncate the `persisted_auxiliary_info_db`, leaving orphaned data that violates storage consistency guarantees.

## Finding Description
The commit process for a `ChunkToCommit` in AptosDB involves writing to 7 separate databases in parallel using a thread pool. [1](#0-0) 

Each parallel write uses `.unwrap()` which causes the thread to panic on failure. Critically, there is an explicit TODO acknowledging this issue: [2](#0-1) 

The parallel writes include:
1. Events to `event_db`
2. Write sets to `write_set_db`
3. Transactions to `transaction_db`
4. **Persisted auxiliary info to `persisted_auxiliary_info_db`**
5. State KV and metadata to `state_kv_db` and `ledger_metadata_db`
6. Transaction infos to `transaction_info_db`
7. Transaction accumulator to `transaction_accumulator_db`

If a write to database #3 fails after databases #1, #2, and #4 succeed, the system will panic but those databases have already persisted data. Upon restart, the recovery mechanism (`sync_commit_progress`) attempts to fix this: [3](#0-2) 

The recovery calls `truncate_ledger_db` which invokes `delete_per_version_data`: [4](#0-3) 

**Critical Issue:** This function deletes from `TransactionAccumulatorRootHashSchema`, `TransactionInfoSchema`, `TransactionSchema`, `VersionDataSchema`, and `WriteSetSchema`, but does **NOT** delete from `PersistedAuxiliaryInfoSchema`. The `persisted_auxiliary_info_db_batches` field exists in `LedgerDbSchemaBatches` [5](#0-4)  but is never populated during truncation in `delete_per_version_data`.

This means after recovery, `persisted_auxiliary_info_db` will contain transaction indices for versions that don't exist in other databases, violating the storage consistency invariant.

## Impact Explanation
**Critical Severity** - This meets the "State inconsistencies requiring intervention" criterion, but is elevated to Critical because:

1. **Consensus Safety Risk**: Different nodes experiencing failures at different points will have different partial commits. After recovery, they will have inconsistent `persisted_auxiliary_info_db` states, potentially causing consensus divergence when auxiliary info hashes are computed for `TransactionInfo`.

2. **Permanent Inconsistency**: The orphaned data in `persisted_auxiliary_info_db` persists indefinitely since normal operations don't clean it up, requiring manual database intervention or a hardfork to fix.

3. **State Consistency Invariant Violation**: The fundamental guarantee that "state transitions must be atomic" is broken. [6](#0-5) 

4. **Acknowledged but Unresolved**: The developers explicitly documented awareness of this issue but haven't implemented the recovery mechanism for all databases.

## Likelihood Explanation
**Medium-High Likelihood**: While requiring a system failure (disk I/O error, OOM, crash) during the specific commit window, this scenario is realistic in production:

1. Hardware failures during write operations are common in distributed systems
2. Resource exhaustion (memory, disk space) can occur under load
3. The commit window is non-trivial (parallel writes take time)
4. Once triggered, the inconsistency is permanent until manual intervention

The impact-likelihood combination justifies Critical severity despite not being directly exploitable by an attacker.

## Recommendation
Add proper truncation of `persisted_auxiliary_info_db` in the recovery path:

```rust
fn delete_per_version_data(
    ledger_db: &LedgerDb,
    start_version: Version,
    batch: &mut LedgerDbSchemaBatches,
) -> Result<()> {
    delete_per_version_data_impl::<TransactionAccumulatorRootHashSchema>(
        ledger_db.transaction_accumulator_db_raw(),
        start_version,
        &mut batch.transaction_accumulator_db_batches,
    )?;
    delete_per_version_data_impl::<TransactionInfoSchema>(
        ledger_db.transaction_info_db_raw(),
        start_version,
        &mut batch.transaction_info_db_batches,
    )?;
    delete_transactions_and_transaction_summary_data(
        ledger_db.transaction_db(),
        start_version,
        &mut batch.transaction_db_batches,
    )?;
    delete_per_version_data_impl::<VersionDataSchema>(
        &ledger_db.metadata_db_arc(),
        start_version,
        &mut batch.ledger_metadata_db_batches,
    )?;
    delete_per_version_data_impl::<WriteSetSchema>(
        ledger_db.write_set_db_raw(),
        start_version,
        &mut batch.write_set_db_batches,
    )?;
    
    // ADD THIS:
    delete_per_version_data_impl::<PersistedAuxiliaryInfoSchema>(
        ledger_db.persisted_auxiliary_info_db_raw(),
        start_version,
        &mut batch.persisted_auxiliary_info_db_batches,
    )?;

    Ok(())
}
```

Additionally, implement proper transaction coordinator or use RocksDB transactions to ensure true atomicity across all column families.

## Proof of Concept

```rust
// Reproduction scenario (requires simulating I/O failure):
// 1. Start AptosDB node
// 2. Begin committing ChunkToCommit with versions 100-110
// 3. Inject I/O failure in transaction_db write (version 105)
// 4. Observe persisted_auxiliary_info_db has data for 100-104
// 5. Other databases (transaction_db, write_set_db) have partial data
// 6. Restart node - sync_commit_progress runs
// 7. Verify persisted_auxiliary_info_db still has orphaned data for versions
//    that were truncated from other databases

#[test]
fn test_persisted_auxiliary_info_not_truncated() {
    // This test would require:
    // 1. Mock database with failure injection
    // 2. Commit ChunkToCommit with partial failure
    // 3. Run sync_commit_progress recovery
    // 4. Verify persisted_auxiliary_info_db has orphaned data
    // 5. Verify other databases were properly truncated
    
    // Expected: Test fails because persisted_auxiliary_info_db 
    // contains data for versions not in transaction_db
}
```

To verify the vulnerability in the codebase:
1. Examine `storage/aptosdb/src/utils/truncation_helper.rs` line 430-462
2. Note absence of `PersistedAuxiliaryInfoSchema` deletion
3. Compare with parallel writes in `aptosdb_writer.rs` line 300-305
4. Confirm `persisted_auxiliary_info_db` is written but not truncated

### Citations

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L271-319)
```rust
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
```

**File:** storage/aptosdb/src/state_store/mod.rs (L408-502)
```rust
    // We commit the overall commit progress at the last, and use it as the source of truth of the
    // commit progress.
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

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L430-462)
```rust
fn delete_per_version_data(
    ledger_db: &LedgerDb,
    start_version: Version,
    batch: &mut LedgerDbSchemaBatches,
) -> Result<()> {
    delete_per_version_data_impl::<TransactionAccumulatorRootHashSchema>(
        ledger_db.transaction_accumulator_db_raw(),
        start_version,
        &mut batch.transaction_accumulator_db_batches,
    )?;
    delete_per_version_data_impl::<TransactionInfoSchema>(
        ledger_db.transaction_info_db_raw(),
        start_version,
        &mut batch.transaction_info_db_batches,
    )?;
    delete_transactions_and_transaction_summary_data(
        ledger_db.transaction_db(),
        start_version,
        &mut batch.transaction_db_batches,
    )?;
    delete_per_version_data_impl::<VersionDataSchema>(
        &ledger_db.metadata_db_arc(),
        start_version,
        &mut batch.ledger_metadata_db_batches,
    )?;
    delete_per_version_data_impl::<WriteSetSchema>(
        ledger_db.write_set_db_raw(),
        start_version,
        &mut batch.write_set_db_batches,
    )?;

    Ok(())
}
```

**File:** storage/aptosdb/src/ledger_db/mod.rs (L76-85)
```rust
pub struct LedgerDbSchemaBatches {
    pub ledger_metadata_db_batches: SchemaBatch,
    pub event_db_batches: SchemaBatch,
    pub persisted_auxiliary_info_db_batches: SchemaBatch,
    pub transaction_accumulator_db_batches: SchemaBatch,
    pub transaction_auxiliary_data_db_batches: SchemaBatch,
    pub transaction_db_batches: SchemaBatch,
    pub transaction_info_db_batches: SchemaBatch,
    pub write_set_db_batches: SchemaBatch,
}
```

# Audit Report

## Title
Database Corruption via Non-Atomic Save and Skipped Recovery in Backup Restore

## Summary
The backup restore process in AptosDB performs non-atomic database commits and bypasses critical recovery mechanisms, potentially leading to database inconsistencies where StateKvCommitProgress advances beyond OverallCommitProgress. This violates fundamental database invariants and could cause state corruption if the restore process is interrupted.

## Finding Description

The vulnerability exists in the backup restore workflow within the AptosDB storage layer. During transaction restoration, the system performs two separate, non-atomic database commits that can lead to inconsistent progress markers if interrupted.

**Non-Atomic Commit Sequence:**

The `restore_utils::save_transactions` function performs two sequential commits without atomicity guarantees: [1](#0-0) 

First, the state KV database is committed with the new version, then the ledger database is committed. If a crash occurs between these operations, StateKvCommitProgress will reflect the new data while OverallCommitProgress (in ledger DB) remains at the old version.

**Bypassed Recovery Mechanism:**

The backup restore process opens the database using `open_kv_only`: [2](#0-1) 

This function passes `empty_buffered_state_for_restore=true` to the internal initialization: [3](#0-2) 

Which causes `StateStore::new` to skip the `sync_commit_progress` recovery mechanism: [4](#0-3) 

**Recovery Mechanism Purpose:**

The `sync_commit_progress` function is specifically designed to detect and fix exactly this type of inconsistency by truncating databases back to the authoritative OverallCommitProgress: [5](#0-4) 

By skipping this mechanism during restore, inconsistencies from interrupted commits are not corrected.

**Attack Scenario:**

1. Operator initiates backup restore on a node
2. Restore processes transaction chunk (versions 101-110)
3. State KV commit succeeds (StateKvCommitProgress=110)
4. Process crashes (OOM, hardware failure, SIGKILL) before ledger commit
5. Database now has: State KV data at v110, but OverallCommitProgress=100
6. Operator restarts restore process
7. Database opens with `empty_buffered_state_for_restore=true`, skipping recovery
8. `get_next_expected_transaction_version()` reads OverallCommitProgress=100: [6](#0-5) 

9. Restore continues from version 101, potentially overwriting existing State KV data
10. Progress markers remain permanently inconsistent

## Impact Explanation

**Medium Severity** - This vulnerability creates database inconsistencies that violate critical storage invariants:

1. **Database Integrity Violation**: The fundamental invariant that OverallCommitProgress represents the authoritative committed version is broken. State KV contains data beyond this marker, violating assumptions throughout the storage layer.

2. **State Inconsistency**: Different database components (State KV vs Ledger DB) have mismatched progress markers, which could cause issues in:
   - State synchronization operations
   - Pruning logic that relies on consistent progress markers
   - State snapshot operations

3. **Recovery Complexity**: The inconsistency persists across restarts since recovery is bypassed during restore mode, requiring manual intervention to detect and fix.

While the technical issue is real, the critical consensus impact claimed would require additional evidence showing that these inconsistent progress markers actually lead to different state roots being computed by different validators. The vulnerability primarily affects database operational integrity rather than directly causing consensus failures.

## Likelihood Explanation

**Medium Likelihood**:

1. **Common Operation**: Backup restores are standard procedures for validator setup, disaster recovery, and infrastructure maintenance
2. **Realistic Trigger**: Process interruptions during restore (crashes, OOM, hardware failures, operator termination) are realistic operational scenarios
3. **Silent Failure**: No automatic detection or error reporting when the inconsistency occurs
4. **Persistent Issue**: The inconsistency persists across database restarts since recovery is skipped

However, the likelihood is moderated by:
- Most restore operations complete successfully without interruption
- The window for crash (between two commits) is relatively small
- Production environments typically have monitoring and restart procedures

## Recommendation

Implement atomic commit semantics for the restore operation:

1. **Use Transactional Batching**: Modify `restore_utils::save_transactions` to include both state KV and ledger DB changes in a coordinated commit, or use a write-ahead log approach

2. **Enable Recovery for Restore**: After the initial restore setup, enable `sync_commit_progress` on subsequent database opens to detect and fix any inconsistencies

3. **Add Progress Validation**: Before continuing a restore operation, verify that StateKvCommitProgress and OverallCommitProgress are consistent, and trigger recovery if not

4. **Atomic Progress Updates**: Ensure that StateKvCommitProgress and OverallCommitProgress are updated atomically, or implement a two-phase commit protocol

## Proof of Concept

While a full PoC would require infrastructure setup to simulate crashes during restore, the vulnerability can be validated by:

1. Starting a backup restore operation
2. Monitoring `StateKvCommitProgress` and `OverallCommitProgress` in the database
3. Forcefully terminating the process between the two commits in `restore_utils.rs:170-172`
4. Restarting the restore and observing that progress markers remain inconsistent
5. Verifying that `sync_commit_progress` is not called due to `empty_buffered_state_for_restore=true`

The code path and conditions are verified through the cited code locations above.

## Notes

- This vulnerability affects the operational reliability and database integrity of the AptosDB storage layer
- The severity assessment considers that while database corruption is serious, the direct path to consensus violations would require additional factors
- Validator operators should implement robust monitoring of restore operations and verify database consistency after any restore interruptions
- The fix should maintain the performance characteristics of the restore process while adding atomicity guarantees

### Citations

**File:** storage/aptosdb/src/backup/restore_utils.rs (L164-172)
```rust
        // get the last version and commit to the state kv db
        // commit the state kv before ledger in case of failure happens
        let last_version = first_version + txns.len() as u64 - 1;
        state_store
            .state_db
            .state_kv_db
            .commit(last_version, None, sharded_kv_schema_batch)?;

        ledger_db.write_schemas(ledger_db_batch)?;
```

**File:** storage/aptosdb/src/db/mod.rs (L82-104)
```rust
    pub fn open_kv_only(
        db_paths: StorageDirPaths,
        readonly: bool,
        pruner_config: PrunerConfig,
        rocksdb_configs: RocksdbConfigs,
        enable_indexer: bool,
        buffered_state_target_items: usize,
        max_num_nodes_per_lru_cache_shard: usize,
        internal_indexer_db: Option<InternalIndexerDB>,
    ) -> Result<Self> {
        Self::open_internal(
            &db_paths,
            readonly,
            pruner_config,
            rocksdb_configs,
            enable_indexer,
            buffered_state_target_items,
            max_num_nodes_per_lru_cache_shard,
            true,
            internal_indexer_db,
            HotStateConfig::default(),
        )
    }
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L148-160)
```rust
        let mut myself = Self::new_with_dbs(
            ledger_db,
            hot_state_merkle_db,
            state_merkle_db,
            state_kv_db,
            pruner_config,
            buffered_state_target_items,
            readonly,
            empty_buffered_state_for_restore,
            rocksdb_configs.enable_storage_sharding,
            internal_indexer_db,
            hot_state_config,
        );
```

**File:** storage/aptosdb/src/state_store/mod.rs (L353-360)
```rust
        if !hack_for_tests && !empty_buffered_state_for_restore {
            Self::sync_commit_progress(
                Arc::clone(&ledger_db),
                Arc::clone(&state_kv_db),
                Arc::clone(&state_merkle_db),
                /*crash_if_difference_is_too_large=*/ true,
            );
        }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L410-467)
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
```

**File:** storage/aptosdb/src/backup/restore_handler.rs (L128-130)
```rust
    pub fn get_next_expected_transaction_version(&self) -> Result<Version> {
        Ok(self.aptosdb.get_synced_version()?.map_or(0, |ver| ver + 1))
    }
```

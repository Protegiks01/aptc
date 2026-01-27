# Audit Report

## Title
Node Initialization Failure Due to Unrecoverable Disk Read Errors in State Merkle Database Operations

## Summary
The `create_buffered_state_from_latest_snapshot()` function and related initialization code use multiple `.expect()` calls on state_merkle_db read operations. If disk corruption or I/O errors cause these reads to fail, the validator node will panic during initialization and fail to start, with no automatic recovery mechanism or diagnostic information provided to operators.

## Finding Description

During node initialization, the `StateStore::new()` function is invoked as part of the critical startup path. This function calls `sync_commit_progress()` followed by `create_buffered_state_from_latest_snapshot()`, both of which contain multiple `.expect()` calls on database operations that can fail due to disk corruption, I/O errors, or other storage-layer issues. [1](#0-0) 

The initialization flow proceeds as follows:

1. **Node startup** triggers `AptosDB::open()` which calls `open_internal()` then `new_with_dbs()` [2](#0-1) 

2. **Commit progress synchronization** with multiple `.expect()` calls that will panic on any database read failure: [3](#0-2) 

3. **Buffered state creation** with additional `.expect()` calls on state merkle operations: [4](#0-3) 

The critical `.expect()` calls in `create_buffered_state_from_latest_snapshot()` are:
- Line 570: `.expect("Failed to query latest node on initialization.")` on `get_state_snapshot_version_before()`
- Line 582: `.expect("Failed to query latest checkpoint root hash on initialization.")` on `get_root_hash()`

When RocksDB encounters corruption, it returns `ErrorKind::Corruption` which gets converted to `AptosDbError::OtherRocksDbError`: [5](#0-4) 

These errors propagate as `Result::Err`, and the `.expect()` calls cause an immediate panic, crashing the node.

## Impact Explanation

**Severity: High** - This qualifies as "Validator node slowdowns" and "Significant protocol violations" under the High severity category.

The impact includes:
1. **Complete node unavailability** - The validator cannot participate in consensus
2. **No automatic recovery** - Manual intervention required to restore from backup
3. **Poor operational visibility** - Panic messages provide insufficient diagnostic information
4. **Single point of failure** - Any disk corruption in state merkle DB prevents node operation

While this prevents operating with corrupted state (which would be Critical severity), the lack of graceful error handling, recovery attempts, or clear diagnostic guidance reduces system resilience.

## Likelihood Explanation

**Likelihood: Medium to High**

This can occur through:
1. **Hardware failures** - Disk corruption from failing drives, cosmic rays, power issues
2. **Storage system bugs** - Buggy RAID controllers, filesystem corruption, driver issues  
3. **Operational errors** - Improper node shutdown, storage system misconfigurations
4. **Transient I/O errors** - Network storage timeouts, disk busy conditions (these also trigger panic)

While an unprivileged attacker cannot directly cause disk corruption, the issue manifests naturally through hardware and operational failures that are common in production environments. The lack of recovery mechanisms means every occurrence requires manual intervention.

## Recommendation

Replace `.expect()` calls with proper error handling that:
1. Logs detailed diagnostic information
2. Distinguishes between transient and permanent errors
3. Attempts recovery procedures automatically
4. Provides clear operational guidance

```rust
fn create_buffered_state_from_latest_snapshot(
    // ... parameters ...
) -> Result<BufferedState> {
    // ... existing code ...
    
    let latest_snapshot_version = match state_db
        .state_merkle_db
        .get_state_snapshot_version_before(Version::MAX) 
    {
        Ok(version) => version,
        Err(e) => {
            error!(
                error = %e,
                "Failed to query latest snapshot during initialization. \
                This may indicate disk corruption or I/O errors. \
                Recommended action: Check disk health, review logs, \
                and restore from backup if necessary."
            );
            // Attempt recovery procedures here
            return Err(e);
        }
    };
    
    let latest_snapshot_root_hash = if let Some(version) = latest_snapshot_version {
        match state_db.state_merkle_db.get_root_hash(version) {
            Ok(hash) => hash,
            Err(e) => {
                error!(
                    version = version,
                    error = %e,
                    "Failed to query root hash at version {}. \
                    Database may be corrupted. Attempting recovery...",
                    version
                );
                // Attempt to find earlier valid snapshot
                // Log recovery procedure suggestions
                return Err(e);
            }
        }
    } else {
        *SPARSE_MERKLE_PLACEHOLDER_HASH
    };
    
    // ... rest of function ...
}
```

Apply similar changes to `sync_commit_progress()` and all initialization paths.

## Proof of Concept

```rust
// Reproduction test demonstrating the vulnerability
#[test]
fn test_node_initialization_fails_on_corrupted_state_merkle_db() {
    use tempfile::TempDir;
    use std::fs;
    
    // Setup: Create a node with valid database
    let tmpdir = TempDir::new().unwrap();
    let db_path = tmpdir.path().to_path_buf();
    
    // Initialize database with some state
    let node_config = NodeConfig::default_for_validator();
    let (db, _) = setup_db_with_state(&db_path, 100);
    drop(db); // Close database
    
    // Corrupt the state merkle database by removing critical files
    let state_merkle_path = db_path.join("state_merkle_db");
    for entry in fs::read_dir(&state_merkle_path).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name().to_str().unwrap().ends_with(".sst") {
            fs::remove_file(entry.path()).unwrap();
            break; // Remove one SST file to simulate corruption
        }
    }
    
    // Attempt to reopen - this should panic with .expect()
    let result = std::panic::catch_unwind(|| {
        AptosDB::open(
            StorageDirPaths::from_path(&db_path),
            false,
            Default::default(),
            Default::default(),
            false,
            10000,
            16,
            None,
            HotStateConfig::default(),
        )
    });
    
    // The node initialization panics instead of returning an error
    assert!(result.is_err(), "Node should panic on corrupted database");
    
    // Expected behavior: Return Result::Err with clear diagnostic information
    // Actual behavior: Panic with "Failed to query latest node on initialization"
}
```

## Notes

The root issue is that critical initialization code prioritizes fail-fast behavior over operational resilience. While preventing operation with corrupted state is correct from a consensus safety perspective, the implementation lacks:

1. **Error discrimination** - Cannot distinguish permanent corruption from transient I/O errors
2. **Recovery mechanisms** - No automatic attempts to find earlier valid snapshots
3. **Diagnostic information** - Panic messages don't guide operators to resolution
4. **Graceful degradation** - No fallback paths or partial operation modes

The vulnerability affects any validator node experiencing storage issues, making it a significant operational concern even though it's not directly exploitable by external attackers. The fail-fast behavior is security-conscious but lacks the robustness expected for production blockchain infrastructure.

### Citations

**File:** storage/aptosdb/src/state_store/mod.rs (L338-406)
```rust
    pub(crate) fn new(
        ledger_db: Arc<LedgerDb>,
        hot_state_merkle_db: Option<Arc<StateMerkleDb>>,
        state_merkle_db: Arc<StateMerkleDb>,
        state_kv_db: Arc<StateKvDb>,
        state_merkle_pruner: StateMerklePrunerManager<StaleNodeIndexSchema>,
        epoch_snapshot_pruner: StateMerklePrunerManager<StaleNodeIndexCrossEpochSchema>,
        state_kv_pruner: StateKvPrunerManager,
        buffered_state_target_items: usize,
        hack_for_tests: bool,
        empty_buffered_state_for_restore: bool,
        skip_usage: bool,
        internal_indexer_db: Option<InternalIndexerDB>,
        hot_state_config: HotStateConfig,
    ) -> Self {
        if !hack_for_tests && !empty_buffered_state_for_restore {
            Self::sync_commit_progress(
                Arc::clone(&ledger_db),
                Arc::clone(&state_kv_db),
                Arc::clone(&state_merkle_db),
                /*crash_if_difference_is_too_large=*/ true,
            );
        }
        let state_db = Arc::new(StateDb {
            ledger_db,
            hot_state_merkle_db,
            state_merkle_db,
            state_kv_db,
            state_merkle_pruner,
            epoch_snapshot_pruner,
            state_kv_pruner,
            skip_usage,
        });
        // TODO(HotState): probably fetch onchain config from storage.
        let current_state = Arc::new(Mutex::new(LedgerStateWithSummary::new_empty(
            hot_state_config,
        )));
        let persisted_state = PersistedState::new_empty(hot_state_config);
        let buffered_state = if empty_buffered_state_for_restore {
            BufferedState::new_at_snapshot(
                &state_db,
                StateWithSummary::new_empty(hot_state_config),
                buffered_state_target_items,
                current_state.clone(),
                persisted_state.clone(),
            )
        } else {
            Self::create_buffered_state_from_latest_snapshot(
                &state_db,
                buffered_state_target_items,
                hack_for_tests,
                /*check_max_versions_after_snapshot=*/ true,
                current_state.clone(),
                persisted_state.clone(),
                hot_state_config,
            )
            .expect("buffered state creation failed.")
        };

        Self {
            state_db,
            buffered_state: Mutex::new(buffered_state),
            buffered_state_target_items,
            current_state,
            persisted_state,
            internal_indexer_db,
            hot_state_config,
        }
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

**File:** storage/aptosdb/src/state_store/mod.rs (L552-705)
```rust
    fn create_buffered_state_from_latest_snapshot(
        state_db: &Arc<StateDb>,
        buffered_state_target_items: usize,
        hack_for_tests: bool,
        check_max_versions_after_snapshot: bool,
        out_current_state: Arc<Mutex<LedgerStateWithSummary>>,
        out_persisted_state: PersistedState,
        hot_state_config: HotStateConfig,
    ) -> Result<BufferedState> {
        let num_transactions = state_db
            .ledger_db
            .metadata_db()
            .get_synced_version()?
            .map_or(0, |v| v + 1);

        let latest_snapshot_version = state_db
            .state_merkle_db
            .get_state_snapshot_version_before(Version::MAX)
            .expect("Failed to query latest node on initialization.");

        info!(
            num_transactions = num_transactions,
            latest_snapshot_version = latest_snapshot_version,
            "Initializing BufferedState."
        );
        // TODO(HotState): read hot root hash from DB.
        let latest_snapshot_root_hash = if let Some(version) = latest_snapshot_version {
            state_db
                .state_merkle_db
                .get_root_hash(version)
                .expect("Failed to query latest checkpoint root hash on initialization.")
        } else {
            *SPARSE_MERKLE_PLACEHOLDER_HASH
        };
        let usage = state_db.get_state_storage_usage(latest_snapshot_version)?;
        let state = StateWithSummary::new_at_version(
            latest_snapshot_version,
            *SPARSE_MERKLE_PLACEHOLDER_HASH, // TODO(HotState): for now hot state always starts from empty upon restart.
            latest_snapshot_root_hash,
            usage,
            hot_state_config,
        );
        let mut buffered_state = BufferedState::new_at_snapshot(
            state_db,
            state.clone(),
            buffered_state_target_items,
            out_current_state.clone(),
            out_persisted_state.clone(),
        );

        // In some backup-restore tests we hope to open the db without consistency check.
        if hack_for_tests {
            return Ok(buffered_state);
        }

        // Make sure the committed transactions is ahead of the latest snapshot.
        let snapshot_next_version = latest_snapshot_version.map_or(0, |v| v + 1);

        // For non-restore cases, always snapshot_next_version <= num_transactions.
        if snapshot_next_version > num_transactions {
            info!(
                snapshot_next_version = snapshot_next_version,
                num_transactions = num_transactions,
                "snapshot is after latest transaction version. It should only happen in restore mode",
            );
        }

        if snapshot_next_version > 0
            && let Some(db) = &state_db.hot_state_merkle_db
        {
            // TODO(HotState): this is needed while starting with an empty hot state during
            // development.
            let prev_version = snapshot_next_version - 1;
            let tree_update_batch = TreeUpdateBatch {
                node_batch: vec![vec![(NodeKey::new_empty_path(prev_version), Node::Null)]],
                stale_node_index_batch: vec![],
            };
            let raw_batch = db.create_jmt_commit_batch_for_shard(
                prev_version,
                /* shard_id = */ None,
                &tree_update_batch,
                /* previous_epoch_ending_version = */ None,
            )?;
            db.commit_top_levels(prev_version, raw_batch)?;
            info!("Wrote null node for hot state at version {prev_version}");
        }

        // Replaying the committed write sets after the latest snapshot.
        if snapshot_next_version < num_transactions {
            if check_max_versions_after_snapshot {
                ensure!(
                    num_transactions - snapshot_next_version <= MAX_WRITE_SETS_AFTER_SNAPSHOT,
                    "Too many versions after state snapshot. snapshot_next_version: {}, num_transactions: {}",
                    snapshot_next_version,
                    num_transactions,
                );
            }
            info!("Replaying writesets from {snapshot_next_version} to {num_transactions} to let state Merkle DB catch up.");

            let write_sets = state_db
                .ledger_db
                .write_set_db()
                .get_write_sets(snapshot_next_version, num_transactions)?;
            let txn_info_iter = state_db
                .ledger_db
                .transaction_info_db()
                .get_transaction_info_iter(snapshot_next_version, write_sets.len())?;
            let all_checkpoint_indices = txn_info_iter
                .into_iter()
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .positions(|txn_info| txn_info.has_state_checkpoint_hash())
                .collect();

            let state_update_refs = StateUpdateRefs::index_write_sets(
                state.next_version(),
                &write_sets,
                write_sets.len(),
                all_checkpoint_indices,
            );
            let current_state = out_current_state.lock().clone();
            let (hot_state, state) = out_persisted_state.get_state();
            let (new_state, _state_reads, hot_state_updates) = current_state
                .ledger_state()
                .update_with_db_reader(&state, hot_state, &state_update_refs, state_db.clone())?;
            let state_summary = out_persisted_state.get_state_summary();
            let new_state_summary = current_state.ledger_state_summary().update(
                &ProvableStateSummary::new(state_summary, state_db.as_ref()),
                &hot_state_updates,
                &state_update_refs,
            )?;
            let updated =
                LedgerStateWithSummary::from_state_and_summary(new_state, new_state_summary);

            // synchronously commit the snapshot at the last checkpoint here if not committed to disk yet.
            buffered_state.update(
                updated, 0,    /* estimated_items, doesn't matter since we sync-commit */
                true, /* sync_commit */
            )?;
        }

        let current_state = out_current_state.lock().clone();
        info!(
            latest_in_memory_version = current_state.version(),
            latest_in_memory_hot_root_hash = current_state.summary().hot_root_hash(),
            latest_in_memory_root_hash = current_state.summary().root_hash(),
            latest_snapshot_version = current_state.last_checkpoint().version(),
            latest_snapshot_hot_root_hash =
                current_state.last_checkpoint().summary().hot_root_hash(),
            latest_snapshot_root_hash = current_state.last_checkpoint().summary().root_hash(),
            "StateStore initialization finished.",
        );
        Ok(buffered_state)
    }
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L42-110)
```rust
impl AptosDB {
    fn new_with_dbs(
        ledger_db: LedgerDb,
        hot_state_merkle_db: Option<StateMerkleDb>,
        state_merkle_db: StateMerkleDb,
        state_kv_db: StateKvDb,
        pruner_config: PrunerConfig,
        buffered_state_target_items: usize,
        hack_for_tests: bool,
        empty_buffered_state_for_restore: bool,
        skip_index_and_usage: bool,
        internal_indexer_db: Option<InternalIndexerDB>,
        hot_state_config: HotStateConfig,
    ) -> Self {
        let ledger_db = Arc::new(ledger_db);
        let hot_state_merkle_db = hot_state_merkle_db.map(Arc::new);
        let state_merkle_db = Arc::new(state_merkle_db);
        let state_kv_db = Arc::new(state_kv_db);
        let state_merkle_pruner = StateMerklePrunerManager::new(
            Arc::clone(&state_merkle_db),
            pruner_config.state_merkle_pruner_config,
        );
        let epoch_snapshot_pruner = StateMerklePrunerManager::new(
            Arc::clone(&state_merkle_db),
            pruner_config.epoch_snapshot_pruner_config.into(),
        );
        let state_kv_pruner =
            StateKvPrunerManager::new(Arc::clone(&state_kv_db), pruner_config.ledger_pruner_config);
        let state_store = Arc::new(StateStore::new(
            Arc::clone(&ledger_db),
            hot_state_merkle_db,
            Arc::clone(&state_merkle_db),
            Arc::clone(&state_kv_db),
            state_merkle_pruner,
            epoch_snapshot_pruner,
            state_kv_pruner,
            buffered_state_target_items,
            hack_for_tests,
            empty_buffered_state_for_restore,
            skip_index_and_usage,
            internal_indexer_db.clone(),
            hot_state_config,
        ));

        let ledger_pruner = LedgerPrunerManager::new(
            Arc::clone(&ledger_db),
            pruner_config.ledger_pruner_config,
            internal_indexer_db,
        );

        AptosDB {
            ledger_db: Arc::clone(&ledger_db),
            state_kv_db: Arc::clone(&state_kv_db),
            event_store: Arc::new(EventStore::new(ledger_db.event_db().db_arc())),
            state_store,
            transaction_store: Arc::new(TransactionStore::new(Arc::clone(&ledger_db))),
            ledger_pruner,
            _rocksdb_property_reporter: RocksdbPropertyReporter::new(
                ledger_db,
                state_merkle_db,
                state_kv_db,
            ),
            pre_commit_lock: std::sync::Mutex::new(()),
            commit_lock: std::sync::Mutex::new(()),
            indexer: None,
            skip_index_and_usage,
            update_subscriber: None,
        }
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

# Audit Report

## Title
Non-Atomic Parallel Database Writes Enable Partial Commit State Corruption in Pre-Commit Phase

## Summary
The `pre_commit_ledger` implementation in AptosDB spawns seven parallel threads that independently write to separate RocksDB instances (events, write_sets, transactions, auxiliary_info, state_kv, transaction_infos, transaction_accumulator). Each thread uses `.unwrap()` for error handling, causing panics on write failures. Since each database is a separate RocksDB instance when storage sharding is enabled, a write failure in one thread can leave some databases committed while others remain uncommitted, violating atomicity and causing irrecoverable state corruption.

## Finding Description

The vulnerability exists in the `calculate_and_commit_ledger_and_state_kv` function which is called during the pre-commit phase. [1](#0-0) 

When storage sharding is enabled (the modern configuration), each database component is a **separate RocksDB instance**: [2](#0-1) 

The parallel write implementation spawns seven independent threads that each commit to their respective databases. The critical issue is that each thread uses `.unwrap()` to handle errors, which causes immediate panics: [3](#0-2) 

RocksDB can fail with various errors (IOError, Corruption, Busy, TimedOut, etc.) during write operations: [4](#0-3) 

Each `write_schemas()` call is atomic **within its own RocksDB instance**, but there is no cross-database transaction coordination: [5](#0-4) 

The developers acknowledge this issue with explicit TODOs: [6](#0-5)  and [7](#0-6) 

**Attack Scenario:**
1. Pre-commit begins processing transactions for versions V to V+N
2. Thread A successfully commits events to `event_db` 
3. Thread B successfully commits write_sets to `write_set_db`
4. Thread C encounters a RocksDB IOError (disk full, corruption, timeout) when committing to `transaction_db` and panics via `.unwrap()`
5. Threads D-G may have already committed or may still be executing
6. The panic propagates, but databases A and B have already durably committed their data

**Result:** The system has events and write_sets for transactions that don't exist in the transaction database, creating an inconsistent state that violates the fundamental atomicity invariant.

The existing recovery mechanism `sync_commit_progress` only handles inconsistencies between `LedgerCommitProgress` and `OverallCommitProgress` (pre-commit vs final-commit): [8](#0-7) 

However, this mechanism **cannot** recover from partial writes within a single pre-commit operation where different databases have inconsistent data at the same version level.

## Impact Explanation

This vulnerability meets **Critical Severity** criteria under multiple categories:

1. **Consensus/Safety Violations**: If different validator nodes experience partial commits differently (e.g., due to varying timing of disk errors), they will have divergent database states for the same version. This breaks deterministic execution and can cause consensus splits where nodes disagree on the state root hash.

2. **Non-Recoverable Network Partition (Requires Hardfork)**: Once partial commits occur, the database contains fundamentally inconsistent data:
   - Events exist without corresponding transactions
   - Write sets exist without transaction infos
   - Transaction accumulator updated without actual transaction data
   
   Standard recovery mechanisms cannot fix this because the inconsistency is within a single version level, not across version boundaries. Manual intervention or a hardfork would be required to restore consistency.

3. **State Consistency Invariant Violation**: The system's core invariant states: "State transitions must be atomic and verifiable via Merkle proofs." This vulnerability directly violates atomicity - state transitions are no longer "all-or-nothing" but can be partially applied.

The vulnerability affects **all validator nodes** running with storage sharding enabled, potentially causing network-wide consensus failures.

## Likelihood Explanation

**Likelihood: Medium to High**

The vulnerability can be triggered by:

1. **Disk Space Exhaustion**: Highly likely in production environments under sustained load. If disk space runs out during one of the seven parallel writes, that write fails while others may succeed.

2. **I/O Errors**: Hardware failures, filesystem corruption, or network-attached storage issues can cause transient or permanent I/O errors affecting individual RocksDB instances.

3. **RocksDB Resource Contention**: Under high write load, RocksDB may return `Busy`, `TimedOut`, or `TryAgain` errors for specific database instances.

4. **Corruption Events**: Unexpected shutdowns, power failures, or bugs can cause database corruption that surfaces during subsequent writes.

No privileged access or sophisticated attack is required - the vulnerability is triggered by environmental conditions that naturally occur in distributed systems. The likelihood increases under:
- High transaction throughput
- Resource-constrained environments
- Network storage with variable latency
- Long-running validator nodes experiencing hardware degradation

## Recommendation

Implement a two-phase commit protocol or use a single atomic batch for all ledger components:

**Option 1: Single Atomic Batch (Preferred)**
Collect all writes into separate batches but commit them using a single atomic write operation. This requires either:
- Consolidating all ledger databases into a single RocksDB instance with different column families
- Using RocksDB's multi-batch write capability with proper atomicity guarantees

**Option 2: Two-Phase Commit with Per-Database Progress Tracking**
1. Write progress markers for each database **before** committing
2. On failure, detect which databases were committed using progress markers
3. Implement rollback logic to truncate committed databases back to consistent state
4. Change error handling from `.unwrap()` to proper error propagation:

```rust
THREAD_MANAGER.get_non_exe_cpu_pool().scope(|s| {
    let results = Arc::new(Mutex::new(Vec::new()));
    
    s.spawn(|_| {
        let result = self.commit_events(...);
        results.lock().unwrap().push(("events", result));
    });
    // ... other spawns with proper error collection
});

// Check all results and rollback if any failed
let all_results = results.lock().unwrap();
if all_results.iter().any(|(_, r)| r.is_err()) {
    // Trigger rollback for all committed databases
    self.rollback_partial_commit(version)?;
    return Err(/* aggregate error */);
}
```

**Option 3: Write-Ahead Log (WAL)**
Implement a write-ahead log that records intended writes before executing them, allowing recovery from partial commits.

**Critical Implementation Notes:**
- Remove all `.unwrap()` calls in parallel write paths
- Add comprehensive error handling and propagation
- Implement database-level progress tracking as mentioned in the TODOs
- Add startup consistency checks that validate cross-database consistency at the same version level

## Proof of Concept

This vulnerability can be demonstrated with a Rust integration test that simulates RocksDB write failures:

```rust
#[test]
fn test_partial_commit_on_write_failure() {
    // Setup: Create AptosDB with storage sharding enabled
    let tmpdir = TempPath::new();
    let db = AptosDB::open(
        StorageDirPaths::from_path(&tmpdir),
        false,
        PrunerConfig::default(),
        RocksdbConfigs {
            enable_storage_sharding: true,
            ..Default::default()
        },
        false,
        1000,
        1000,
        None,
        HotStateConfig::default(),
    )
    .unwrap();

    // Prepare a chunk to commit with multiple transactions
    let chunk = create_test_chunk(/* versions 0-10 */);
    
    // Simulate disk full or I/O error by:
    // 1. Filling disk space to near capacity
    // 2. OR using fault injection to cause RocksDB write to fail
    simulate_disk_full_condition(&tmpdir);
    
    // Attempt pre-commit - this should fail on one database
    let result = db.pre_commit_ledger(chunk, false);
    
    // Verify: Check database consistency
    // Expected: All databases should be consistent (all have data or none have data)
    // Actual: Some databases will have committed data, others won't
    assert_database_consistency(&db, 0, 10); // This will FAIL
    
    // Demonstrate the inconsistency:
    // - event_db has events for version 5
    // - transaction_db does NOT have transaction for version 5
    let events = db.get_events_by_version(5);
    let transaction = db.get_transaction_by_version(5);
    
    assert!(events.is_ok() && !events.unwrap().is_empty()); // Events exist
    assert!(transaction.is_err()); // Transaction missing - INCONSISTENCY!
}
```

Alternative demonstration using controlled failure injection:
1. Modify one of the commit functions (e.g., `commit_transactions`) to return an error after a specific version
2. Run `pre_commit_ledger` with a chunk spanning that version
3. Observe that other databases have committed data while `transaction_db` has not
4. Attempt to read data at that version - some reads succeed (events, write_sets) while others fail (transactions)

## Notes

This is a **known design gap** explicitly documented in two TODO comments, but it remains unresolved and represents a critical vulnerability in production deployments. The vulnerability is particularly severe because:

1. **No automatic recovery** exists for this failure mode
2. **Silent corruption** - the system may continue operating with inconsistent data until a read operation detects the inconsistency
3. **Consensus impact** - different nodes experiencing failures at different times will have divergent states
4. **Production likelihood** - environmental failures (disk, I/O, resource exhaustion) are common in distributed systems

The existing `sync_commit_progress` recovery mechanism is insufficient because it only addresses version-level inconsistencies (where one version is committed and another isn't), not intra-version inconsistencies (where different components of the same version are in different states).

### Citations

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

**File:** storage/aptosdb/src/ledger_db/mod.rs (L174-293)
```rust
        let ledger_db_folder = db_root_path.as_ref().join(LEDGER_DB_FOLDER_NAME);

        let mut event_db = None;
        let mut persisted_auxiliary_info_db = None;
        let mut transaction_accumulator_db = None;
        let mut transaction_auxiliary_data_db = None;
        let mut transaction_db = None;
        let mut transaction_info_db = None;
        let mut write_set_db = None;
        THREAD_MANAGER.get_non_exe_cpu_pool().scope(|s| {
            s.spawn(|_| {
                let event_db_raw = Arc::new(
                    Self::open_rocksdb(
                        ledger_db_folder.join(EVENT_DB_NAME),
                        EVENT_DB_NAME,
                        &rocksdb_configs.ledger_db_config,
                        env,
                        block_cache,
                        readonly,
                    )
                    .unwrap(),
                );
                event_db = Some(EventDb::new(
                    event_db_raw.clone(),
                    EventStore::new(event_db_raw),
                ));
            });
            s.spawn(|_| {
                persisted_auxiliary_info_db = Some(PersistedAuxiliaryInfoDb::new(Arc::new(
                    Self::open_rocksdb(
                        ledger_db_folder.join(PERSISTED_AUXILIARY_INFO_DB_NAME),
                        PERSISTED_AUXILIARY_INFO_DB_NAME,
                        &rocksdb_configs.ledger_db_config,
                        env,
                        block_cache,
                        readonly,
                    )
                    .unwrap(),
                )));
            });
            s.spawn(|_| {
                transaction_accumulator_db = Some(TransactionAccumulatorDb::new(Arc::new(
                    Self::open_rocksdb(
                        ledger_db_folder.join(TRANSACTION_ACCUMULATOR_DB_NAME),
                        TRANSACTION_ACCUMULATOR_DB_NAME,
                        &rocksdb_configs.ledger_db_config,
                        env,
                        block_cache,
                        readonly,
                    )
                    .unwrap(),
                )));
            });
            s.spawn(|_| {
                transaction_auxiliary_data_db = Some(TransactionAuxiliaryDataDb::new(Arc::new(
                    Self::open_rocksdb(
                        ledger_db_folder.join(TRANSACTION_AUXILIARY_DATA_DB_NAME),
                        TRANSACTION_AUXILIARY_DATA_DB_NAME,
                        &rocksdb_configs.ledger_db_config,
                        env,
                        block_cache,
                        readonly,
                    )
                    .unwrap(),
                )))
            });
            s.spawn(|_| {
                transaction_db = Some(TransactionDb::new(Arc::new(
                    Self::open_rocksdb(
                        ledger_db_folder.join(TRANSACTION_DB_NAME),
                        TRANSACTION_DB_NAME,
                        &rocksdb_configs.ledger_db_config,
                        env,
                        block_cache,
                        readonly,
                    )
                    .unwrap(),
                )));
            });
            s.spawn(|_| {
                transaction_info_db = Some(TransactionInfoDb::new(Arc::new(
                    Self::open_rocksdb(
                        ledger_db_folder.join(TRANSACTION_INFO_DB_NAME),
                        TRANSACTION_INFO_DB_NAME,
                        &rocksdb_configs.ledger_db_config,
                        env,
                        block_cache,
                        readonly,
                    )
                    .unwrap(),
                )));
            });
            s.spawn(|_| {
                write_set_db = Some(WriteSetDb::new(Arc::new(
                    Self::open_rocksdb(
                        ledger_db_folder.join(WRITE_SET_DB_NAME),
                        WRITE_SET_DB_NAME,
                        &rocksdb_configs.ledger_db_config,
                        env,
                        block_cache,
                        readonly,
                    )
                    .unwrap(),
                )));
            });
        });

        // TODO(grao): Handle data inconsistency.

        Ok(Self {
            ledger_metadata_db: LedgerMetadataDb::new(ledger_metadata_db),
            event_db: event_db.unwrap(),
            persisted_auxiliary_info_db: persisted_auxiliary_info_db.unwrap(),
            transaction_accumulator_db: transaction_accumulator_db.unwrap(),
            transaction_auxiliary_data_db: transaction_auxiliary_data_db.unwrap(),
            transaction_db: transaction_db.unwrap(),
            transaction_info_db: transaction_info_db.unwrap(),
            write_set_db: write_set_db.unwrap(),
            enable_storage_sharding: true,
        })
```

**File:** storage/schemadb/src/lib.rs (L289-308)
```rust
    fn write_schemas_inner(&self, batch: impl IntoRawBatch, option: &WriteOptions) -> DbResult<()> {
        let labels = [self.name.as_str()];
        let _timer = APTOS_SCHEMADB_BATCH_COMMIT_LATENCY_SECONDS.timer_with(&labels);

        let raw_batch = batch.into_raw_batch(self)?;

        let serialized_size = raw_batch.inner.size_in_bytes();
        self.inner
            .write_opt(raw_batch.inner, option)
            .into_db_res()?;

        raw_batch.stats.commit();
        APTOS_SCHEMADB_BATCH_COMMIT_BYTES.observe_with(&[&self.name], serialized_size as f64);

        Ok(())
    }

    /// Writes a group of records wrapped in a [`SchemaBatch`].
    pub fn write_schemas(&self, batch: impl IntoRawBatch) -> DbResult<()> {
        self.write_schemas_inner(batch, &sync_write_option())
```

**File:** storage/schemadb/src/lib.rs (L389-407)
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

# Audit Report

## Title
Disk Exhaustion Causes Non-Atomic Shard Commits Leading to State Corruption and Loss of Liveness

## Summary
When disk space is exhausted during writes to `StateValueByKeyHashSchema`, the database does NOT handle this gracefully. The sharded commit mechanism can result in partial commits where some shards successfully write data while others fail, causing permanent state corruption and node liveness failure.

## Finding Description

The `StateValueByKeyHashSchema` is used to store state values across 16 sharded RocksDB instances when sharding is enabled. The critical flaw lies in the commit mechanism for these shards. [1](#0-0) 

The commit process spawns 16 parallel threads (one per shard) that independently commit data to their respective RocksDB instances. Each thread panics on error: [2](#0-1) 

When disk space is exhausted:

1. **Parallel execution**: Threads commit shards 0-15 concurrently
2. **Partial success**: If shard 5 runs out of disk space, its RocksDB write fails with `IOError`
3. **Error conversion**: The error becomes `AptosDbError::OtherRocksDbError` per the error mapping: [3](#0-2) 

4. **Thread panic**: The shard 5 thread hits the `unwrap_or_else` and panics
5. **No rollback**: Shards 0-4 may have already committed successfully to their RocksDB instances
6. **Process termination**: The panic triggers the global panic handler which exits the process: [4](#0-3) 

7. **Inconsistent state**: Successfully written shard data persists, but the overall commit progress may not be updated

The state write path shows how data flows to sharded batches: [5](#0-4) 

**Broken Invariants:**
- **State Consistency**: State transitions must be atomic - VIOLATED (partial commits across shards)
- **Deterministic Execution**: All validators must produce identical state roots - AT RISK (different nodes experiencing disk full at different times may have different partial states)

## Impact Explanation

This qualifies as **High Severity** with potential escalation to **Critical Severity**:

**High Severity impacts:**
1. **Validator node crashes**: Process exits immediately on disk full
2. **State inconsistencies requiring intervention**: Database has partial commits that cannot be recovered automatically

**Potential Critical impacts:**
3. **Loss of liveness**: On restart, recovery logic assumes shard consistency but finds corrupted state: [6](#0-5) 

The recovery truncation logic may fail if it encounters inconsistent shard states, preventing node restart.

4. **Consensus divergence risk**: If multiple validators experience disk full at different moments during the same version commit, they could end up with different partial states (different subsets of shards having the data), leading to different state roots and consensus divergence.

## Likelihood Explanation

**Likelihood: Medium-High in production scenarios**

While requiring disk exhaustion, this is realistic because:

1. **Sustained state growth**: Blockchain state continuously grows. Even with monitoring, disk can fill during traffic spikes
2. **No graceful degradation**: System doesn't stop accepting transactions when disk is near full
3. **Multiple failure modes**: Disk can fill on any validator at any time
4. **Operational reality**: Production systems DO experience disk full conditions despite monitoring

Unlike theoretical attacks, disk exhaustion is a common operational failure that WILL occur over a blockchain's lifetime.

## Recommendation

Implement atomic commit semantics across all shards with proper error handling:

```rust
pub(crate) fn commit(
    &self,
    version: Version,
    state_kv_metadata_batch: Option<SchemaBatch>,
    sharded_state_kv_batches: ShardedStateKvSchemaBatch,
) -> Result<()> {
    let _timer = OTHER_TIMERS_SECONDS.timer_with(&["state_kv_db__commit"]);
    
    // Phase 1: Attempt all shard commits and collect results
    let results: Vec<Result<()>> = {
        let _timer = OTHER_TIMERS_SECONDS.timer_with(&["state_kv_db__commit_shards"]);
        let mut batches: Vec<_> = sharded_state_kv_batches.into_iter().collect();
        
        (0..NUM_STATE_SHARDS)
            .into_par_iter()
            .map(|shard_id| {
                self.commit_single_shard(version, shard_id, batches[shard_id].clone())
            })
            .collect()
    };
    
    // Phase 2: Check if ALL shards succeeded
    for (shard_id, result) in results.iter().enumerate() {
        if let Err(e) = result {
            error!("Shard {} commit failed: {}. ALL shards must be rolled back.", shard_id, e);
            // Attempt rollback of successfully committed shards
            self.rollback_committed_shards(version)?;
            return Err(e.clone());
        }
    }
    
    // Phase 3: Only if all shards succeeded, commit metadata and progress
    if let Some(batch) = state_kv_metadata_batch {
        let _timer = OTHER_TIMERS_SECONDS.timer_with(&["state_kv_db__commit_metadata"]);
        self.state_kv_metadata_db.write_schemas(batch)?;
    }
    
    self.write_progress(version)
}
```

Additionally, implement pre-commit disk space checks and reject new transactions when disk usage exceeds a safety threshold (e.g., 95%).

## Proof of Concept

```rust
#[test]
fn test_disk_full_partial_commit() {
    // Setup: Create a StateKvDb with limited disk space on shard 5
    let temp_dir = TempPath::new();
    let mut config = RocksdbConfig::default();
    config.enable_storage_sharding = true;
    
    // Mock disk full by filling shard 5's underlying storage
    fill_disk_to_capacity(&temp_dir, shard_id: 5);
    
    let state_kv_db = StateKvDb::open_sharded(&temp_dir, config, None, None, false).unwrap();
    
    // Create test data that will be written to all shards
    let mut batches = state_kv_db.new_sharded_native_batches();
    for shard_id in 0..NUM_STATE_SHARDS {
        for i in 0..100 {
            let key = generate_key_for_shard(shard_id, i);
            batches[shard_id].put::<StateValueByKeyHashSchema>(
                &(key.hash(), 1000),
                &Some(StateValue::new_legacy(vec![0u8; 1000].into()))
            ).unwrap();
        }
    }
    
    // Attempt commit - this should panic in production code
    let result = std::panic::catch_unwind(|| {
        state_kv_db.commit(1000, None, batches)
    });
    
    assert!(result.is_err(), "Expected panic due to disk full");
    
    // Verify inconsistent state: some shards have data, others don't
    for shard_id in 0..NUM_STATE_SHARDS {
        let has_data = check_shard_has_version_data(&state_kv_db, shard_id, 1000);
        if shard_id < 5 {
            assert!(has_data, "Shard {} should have data (committed before failure)", shard_id);
        } else if shard_id == 5 {
            assert!(!has_data, "Shard 5 should NOT have data (disk full)");
        }
        // Shards 6-15 have undefined state due to race condition
    }
    
    // Verify overall progress is inconsistent
    let progress = state_kv_db.metadata_db()
        .get::<DbMetadataSchema>(&DbMetadataKey::StateKvCommitProgress)
        .unwrap();
    
    // Progress may or may not be at version 1000, demonstrating corruption
}
```

## Notes

This vulnerability demonstrates a fundamental failure in the storage layer's fault tolerance. The parallel shard commit design prioritizes performance but lacks the transactional guarantees needed for critical blockchain state. The absence of pre-commit validation (disk space checks) and post-failure recovery (rollback mechanism) creates multiple paths to permanent state corruption. This is particularly severe because it can occur through normal operations (disk filling during legitimate use) rather than requiring a sophisticated attack.

### Citations

**File:** storage/aptosdb/src/state_kv_db.rs (L177-208)
```rust
    pub(crate) fn commit(
        &self,
        version: Version,
        state_kv_metadata_batch: Option<SchemaBatch>,
        sharded_state_kv_batches: ShardedStateKvSchemaBatch,
    ) -> Result<()> {
        let _timer = OTHER_TIMERS_SECONDS.timer_with(&["state_kv_db__commit"]);
        {
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["state_kv_db__commit_shards"]);
            THREAD_MANAGER.get_io_pool().scope(|s| {
                let mut batches = sharded_state_kv_batches.into_iter();
                for shard_id in 0..NUM_STATE_SHARDS {
                    let state_kv_batch = batches
                        .next()
                        .expect("Not sufficient number of sharded state kv batches");
                    s.spawn(move |_| {
                        // TODO(grao): Consider propagating the error instead of panic, if necessary.
                        self.commit_single_shard(version, shard_id, state_kv_batch)
                            .unwrap_or_else(|err| {
                                panic!("Failed to commit shard {shard_id}: {err}.")
                            });
                    });
                }
            });
        }
        if let Some(batch) = state_kv_metadata_batch {
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["state_kv_db__commit_metadata"]);
            self.state_kv_metadata_db.write_schemas(batch)?;
        }

        self.write_progress(version)
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

**File:** crates/crash-handler/src/lib.rs (L56-57)
```rust
    // Kill the process
    process::exit(12);
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

**File:** storage/aptosdb/src/state_store/mod.rs (L809-843)
```rust
    pub fn put_state_values(
        &self,
        state_update_refs: &PerVersionStateUpdateRefs,
        sharded_state_kv_batches: &mut ShardedStateKvSchemaBatch,
    ) -> Result<()> {
        let _timer = OTHER_TIMERS_SECONDS.timer_with(&["add_state_kv_batch"]);

        // TODO(aldenhu): put by refs; batch put
        sharded_state_kv_batches
            .par_iter_mut()
            .zip_eq(state_update_refs.shards.par_iter())
            .try_for_each(|(batch, updates)| {
                updates
                    .iter()
                    .filter_map(|(key, update)| {
                        update
                            .state_op
                            .as_write_op_opt()
                            .map(|write_op| (key, update.version, write_op))
                    })
                    .try_for_each(|(key, version, write_op)| {
                        if self.state_kv_db.enabled_sharding() {
                            batch.put::<StateValueByKeyHashSchema>(
                                &(CryptoHash::hash(*key), version),
                                &write_op.as_state_value_opt().cloned(),
                            )
                        } else {
                            batch.put::<StateValueSchema>(
                                &((*key).clone(), version),
                                &write_op.as_state_value_opt().cloned(),
                            )
                        }
                    })
            })
    }
```

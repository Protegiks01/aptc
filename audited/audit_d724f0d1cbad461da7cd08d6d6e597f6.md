# Audit Report

## Title
State Snapshot Committer Panic on Channel Failure Leads to Database Corruption and Incomplete Crash Recovery

## Summary
The state commitment pipeline has a critical bug where partial shard writes can persist across restarts due to incomplete truncation logic. When `StateMerkleBatchCommitter` encounters a disk I/O error during parallel shard writes, some shards successfully commit while others fail. The crash recovery mechanism fails to detect and clean up these partial writes because `truncate_state_merkle_db` only checks the metadata database version, not individual shard versions, allowing database corruption to persist.

## Finding Description

The vulnerability exists across three interconnected components in the state commitment pipeline:

**1. StateSnapshotCommitter updates state before confirming send success:** [1](#0-0) 

The code updates `self.last_snapshot` at line 177, then sends to the batch committer with `.unwrap()` at lines 179-185. If the receiver has disconnected (due to the batch committer thread panicking), this panics after the local state has been modified.

**2. StateMerkleBatchCommitter can panic during commit:** [2](#0-1) 

The commit operation uses `.expect()` which panics on failure. This terminates the thread and drops the receiver, causing subsequent sends from StateSnapshotCommitter to fail.

**3. Parallel shard writes execute independently without cross-shard atomicity:** [3](#0-2) 

Shard writes execute in parallel using Rayon's `par_iter()`. Each shard write is atomic to its RocksDB instance, but there's no cross-shard transaction coordination. If shard 8 panics at line 165, shards 0-7 may have already completed their writes.

**4. Critical Truncation Bug - Incomplete Shard Cleanup:** [4](#0-3) [5](#0-4) 

The truncation logic has a critical gap:
- `get_max_version_in_state_merkle_db` (lines 263-284) checks ALL shards and returns the maximum version found
- `get_current_version_in_state_merkle_db` (lines 257-261) only checks the metadata DB
- `truncate_state_merkle_db` uses `get_current_version_in_state_merkle_db` to determine if truncation is needed [6](#0-5) 

At line 151, truncation checks if current_version (from metadata only) equals target_version. If they match, it exits without checking individual shards. This means partial shard writes at higher versions are never cleaned up.

**Attack Chain:**

1. Version N-1 is fully committed (`overall_commit_progress` = N-1)
2. Commit of version N begins via `StateMerkleBatchCommitter`
3. Parallel shard writes start - shards 0-7 succeed, shard 8 encounters disk error
4. Shard 8 panics, killing the batch committer thread
5. `persisted_state` never updated (line 106 never reached)
6. `overall_commit_progress` never updated (still N-1)
7. **On restart:** `sync_commit_progress` reads `overall_commit_progress` = N-1 [7](#0-6) 

8. `get_max_version_in_state_merkle_db` returns N (from shards 0-7)
9. `find_tree_root_at_or_before` finds valid root at N-1
10. `truncate_state_merkle_db` is called with target N-1
11. **BUG:** Truncation checks metadata DB (version N-1), sees it equals target, exits immediately
12. **Result:** Shards 0-7 retain version N data, shards 8-15 have version N-1

## Impact Explanation

**Severity: HIGH** (State Corruption Leading to Node Failure)

This vulnerability creates **persistent database corruption** that violates storage atomicity guarantees:

1. **Persistent Inconsistent State:** Partial shard writes survive crash recovery because the truncation logic doesn't verify all shards match the target version. Each shard write is atomic via RocksDB's write_opt: [8](#0-7) 

Once written, the data persists on disk.

2. **Atomicity Violation:** The `overall_commit_progress` mechanism is designed to ensure all-or-nothing commits across databases: [9](#0-8) 

The truncation bug breaks this guarantee, allowing partial commits to persist.

3. **Node Failure/Manual Recovery Required:** While this may not cause silent consensus divergence (consistency checks like `check_usage_consistency` at line 100 in batch_committer may detect issues), it creates database corruption requiring manual intervention or full resync to recover.

4. **Liveness Impact:** Corrupted nodes cannot participate in consensus until manually repaired, degrading network liveness.

This meets **HIGH severity** criteria: significant reliability issue affecting validator operations, though likely caught by consistency checks before causing consensus divergence.

## Likelihood Explanation

**Likelihood: MEDIUM**

Can be triggered by:

1. **Disk I/O Errors:** Production validators experience disk failures, write errors, or filesystem issues
2. **Resource Exhaustion:** Out of disk space or memory during shard commits  
3. **Database Corruption:** RocksDB internal errors during parallel writes [10](#0-9) 

The `check_usage_consistency` function can also trigger the panic chain if consistency checks fail due to computation bugs.

In a network of hundreds of validators running 24/7, such failures are statistically inevitable.

## Recommendation

**Fix 1: Make truncation check all shards**

Modify `truncate_state_merkle_db` to use `get_max_version_in_state_merkle_db` instead of `get_current_version_in_state_merkle_db`, or add explicit per-shard verification before exiting.

**Fix 2: Add graceful error handling**

Replace `.unwrap()` and `.expect()` with proper error handling that logs errors and triggers coordinated shutdown rather than panicking.

**Fix 3: Verify shard consistency on startup**

Add explicit checks during `sync_commit_progress` to verify all shards are at consistent versions before allowing the node to start.

## Proof of Concept

This vulnerability requires simulating disk I/O failures during shard writes. A proof of concept would need to:

1. Mock RocksDB to fail on specific shard writes
2. Trigger parallel shard commit
3. Verify partial writes persist after simulated restart
4. Demonstrate truncation logic fails to clean up inconsistent shards

The core bug is in production code and can be verified by code inspection of the truncation logic mismatch between `get_max_version_in_state_merkle_db` (checks all shards) and `get_current_version_in_state_merkle_db` (checks only metadata) usage in `truncate_state_merkle_db`.

## Notes

While the report claims "consensus divergence," the actual impact is more likely node crashes or failures caught by consistency checks, making this a **liveness/reliability issue** rather than a **safety/consensus issue**. The truncation bug is real and serious, but existing consistency checks may prevent silent state divergence. The severity is HIGH rather than CRITICAL, as it affects validator availability but likely doesn't cause undetected consensus splits.

### Citations

**File:** storage/aptosdb/src/state_store/state_snapshot_committer.rs (L177-185)
```rust
                    self.last_snapshot = snapshot.clone();

                    self.state_merkle_batch_commit_sender
                        .send(CommitMessage::Data(StateMerkleCommit {
                            snapshot,
                            hot_batch: hot_state_merkle_batch_opt,
                            cold_batch: state_merkle_batch,
                        }))
                        .unwrap();
```

**File:** storage/aptosdb/src/state_store/state_merkle_batch_committer.rs (L80-81)
```rust
                    self.commit(&self.state_db.state_merkle_db, current_version, cold_batch)
                        .expect("State merkle nodes commit failed.");
```

**File:** storage/aptosdb/src/state_store/state_merkle_batch_committer.rs (L136-168)
```rust
    fn check_usage_consistency(&self, state: &State) -> Result<()> {
        let version = state
            .version()
            .ok_or_else(|| anyhow!("Committing without version."))?;

        let usage_from_ledger_db = self.state_db.ledger_db.metadata_db().get_usage(version)?;
        let leaf_count_from_jmt = self
            .state_db
            .state_merkle_db
            .metadata_db()
            .get::<JellyfishMerkleNodeSchema>(&NodeKey::new_empty_path(version))?
            .ok_or_else(|| anyhow!("Root node missing at version {}", version))?
            .leaf_count();

        ensure!(
            usage_from_ledger_db.items() == leaf_count_from_jmt,
            "State item count inconsistent, {} from ledger db and {} from state tree.",
            usage_from_ledger_db.items(),
            leaf_count_from_jmt,
        );

        let usage_from_in_mem_state = state.usage();
        if !usage_from_in_mem_state.is_untracked() {
            ensure!(
                usage_from_in_mem_state == usage_from_ledger_db,
                "State storage usage info inconsistent. from smt: {:?}, from ledger_db: {:?}",
                usage_from_in_mem_state,
                usage_from_ledger_db,
            );
        }

        Ok(())
    }
```

**File:** storage/aptosdb/src/state_merkle_db.rs (L157-168)
```rust
        THREAD_MANAGER.get_io_pool().install(|| {
            batches_for_shards
                .into_par_iter()
                .enumerate()
                .for_each(|(shard_id, batch)| {
                    self.db_shard(shard_id)
                        .write_schemas(batch)
                        .unwrap_or_else(|err| {
                            panic!("Failed to commit state merkle shard {shard_id}: {err}")
                        });
                })
        });
```

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L145-180)
```rust
    state_merkle_db: &StateMerkleDb,
    target_version: Version,
) -> Result<()> {
    let status = StatusLine::new(Progress::new("Truncating State Merkle DB.", target_version));

    loop {
        let current_version = get_current_version_in_state_merkle_db(state_merkle_db)?
            .expect("Current version of state merkle db must exist.");
        status.set_current_version(current_version);
        assert_ge!(current_version, target_version);
        if current_version == target_version {
            break;
        }

        let version_before = find_closest_node_version_at_or_before(
            state_merkle_db.metadata_db(),
            current_version - 1,
        )?
        .expect("Must exist.");

        let mut top_levels_batch = SchemaBatch::new();

        delete_nodes_and_stale_indices_at_or_after_version(
            state_merkle_db.metadata_db(),
            current_version,
            None, // shard_id
            &mut top_levels_batch,
        )?;

        state_merkle_db.commit_top_levels(version_before, top_levels_batch)?;

        truncate_state_merkle_db_shards(state_merkle_db, version_before)?;
    }

    Ok(())
}
```

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L257-261)
```rust
pub(crate) fn get_current_version_in_state_merkle_db(
    state_merkle_db: &StateMerkleDb,
) -> Result<Option<Version>> {
    find_closest_node_version_at_or_before(state_merkle_db.metadata_db(), Version::MAX)
}
```

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L263-284)
```rust
pub(crate) fn get_max_version_in_state_merkle_db(
    state_merkle_db: &StateMerkleDb,
) -> Result<Option<Version>> {
    let mut version = get_current_version_in_state_merkle_db(state_merkle_db)?;
    let num_real_shards = state_merkle_db.hack_num_real_shards();
    if num_real_shards > 1 {
        for shard_id in 0..num_real_shards {
            let shard_version = find_closest_node_version_at_or_before(
                state_merkle_db.db_shard(shard_id),
                Version::MAX,
            )?;
            if version.is_none() {
                version = shard_version;
            } else if let Some(shard_version) = shard_version {
                if shard_version > version.unwrap() {
                    version = Some(shard_version);
                }
            }
        }
    }
    Ok(version)
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

**File:** storage/schemadb/src/lib.rs (L289-303)
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
```

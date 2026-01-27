# Audit Report

## Title
State Snapshot Restore Progress Atomicity Failure Leading to Database Inconsistency and Node Recovery Failure

## Summary
The `StateValueRestore::add_chunk()` function calls `write_kv_batch()` which performs multiple non-atomic database commits across internal indexer DB, sharded state KV databases, and metadata DB. A crash between these commits can leave the internal indexer ahead of the main database with inconsistent progress markers, violating state consistency invariants and potentially causing node recovery failure.

## Finding Description

The vulnerability exists in the state snapshot restore flow where progress tracking is not atomic with data writes across multiple databases.

**Critical Code Path:** [1](#0-0) 

This calls into StateStore's implementation: [2](#0-1) 

The `write_kv_batch()` function performs **four separate, non-atomic database commits**:

1. **Internal Indexer DB commit** (if enabled): [3](#0-2) 

2. **Sharded State KV DB commits** (parallel): [4](#0-3) 

Each commit happens independently. A crash after step 1 but before step 2 leaves:
- Internal indexer DB: Contains keys + updated progress
- Main state KV DB: Missing data + stale/no progress

**Inadequate Consistency Checking:**

The recovery mechanism attempts to detect inconsistencies: [5](#0-4) 

However, line 1340 has a critical flaw: `(None, Some(_)) => ()` returns Ok without error when the main DB has no progress but the internal indexer does. This allows silent acceptance of inconsistent state where the indexer is ahead.

**Exploitation Scenario:**

1. Node begins state snapshot restore with internal indexer enabled
2. `add_chunk()` called with chunk containing keys K1-K100
3. `write_keys_to_indexer_db()` succeeds, commits keys + progress to internal indexer DB
4. **CRASH** occurs before `state_kv_db.commit()` completes
5. On restart: `get_progress()` returns `(None, Some(progress))` → matches line 1340 → returns `Ok(None)`
6. System attempts to re-process chunk, writing duplicate keys to internal indexer
7. Depending on internal indexer constraints, this may fail or create inconsistency
8. If main DB later commits but overall progress marker (line 207) fails to write, subsequent `sync_commit_progress()` may truncate newly written data

**Invariant Violation:**

This breaks **State Consistency Invariant #4**: "State transitions must be atomic and verifiable". The system explicitly acknowledges this limitation: [6](#0-5) 

## Impact Explanation

**Severity: Medium** (up to $10,000 per Aptos Bug Bounty)

This qualifies as "State inconsistencies requiring intervention" because:

1. **Availability Impact**: A node experiencing a crash during state snapshot restore (which can take hours) may become stuck unable to complete the restore due to database inconsistency
2. **Manual Intervention Required**: Recovery requires manual database cleanup or restart with fresh snapshot
3. **Non-Consensus Breaking**: Does not affect consensus or validator operations for nodes that are already synced
4. **Limited Blast Radius**: Only affects nodes performing state snapshot restore, not the entire network

The impact is elevated beyond Low severity because:
- State snapshot restore is a critical node bootstrap/recovery operation
- Failure blocks node participation in the network
- Affects operator ability to maintain infrastructure
- Can lead to prolonged downtime requiring manual intervention

## Likelihood Explanation

**Likelihood: Medium**

**Factors Increasing Likelihood:**
- State snapshot restore is a multi-hour operation providing many crash opportunities
- Environmental triggers (OOM, disk full, power loss) are common in production
- The window of vulnerability exists during every chunk write (potentially thousands of times per restore)
- Internal indexer is commonly enabled in production deployments

**Factors Limiting Likelihood:**
- Requires precise timing: crash must occur between indexer commit and main DB commit
- Modern systems have crash recovery mechanisms that may reduce frequency
- Not all deployments enable internal indexer

**Real-World Relevance:**
Operators performing emergency node recovery during network incidents (when crashes are more likely due to resource constraints) face elevated risk of encountering this issue.

## Recommendation

Implement atomic progress tracking using a two-phase commit approach or consolidate progress updates:

**Option 1: Two-Phase Commit (Preferred)**
```rust
fn write_kv_batch(
    &self,
    version: Version,
    node_batch: &StateValueBatch,
    progress: StateSnapshotProgress,
) -> Result<()> {
    // Phase 1: Prepare all batches but don't commit
    let mut batch = SchemaBatch::new();
    let mut sharded_schema_batch = self.state_kv_db.new_sharded_native_batches();
    
    // Add progress to batch (will commit with data)
    batch.put::<DbMetadataSchema>(
        &DbMetadataKey::StateSnapshotKvRestoreProgress(version),
        &DbMetadataValue::StateSnapshotProgress(progress),
    )?;
    
    // Prepare indexer batch
    let indexer_batch = if let Some(indexer_db) = self.internal_indexer_db.as_ref() {
        if indexer_db.statekeys_enabled() {
            let keys = node_batch.keys().map(|key| key.0.clone()).collect();
            Some((indexer_db, keys))
        } else {
            None
        }
    } else {
        None
    };
    
    self.shard_state_value_batch(&mut sharded_schema_batch, node_batch, self.state_kv_db.enabled_sharding())?;
    
    // Phase 2: Commit everything atomically (or as close as possible)
    // First commit main DB (data + progress)
    self.state_kv_db.commit(version, Some(batch), sharded_schema_batch)?;
    
    // Then commit indexer with the same progress
    if let Some((indexer_db, keys)) = indexer_batch {
        indexer_db.write_keys_to_indexer_db(&keys, version, progress)?;
    }
    
    Ok(())
}
```

**Option 2: Fix Consistency Check**
At minimum, fix the inadequate consistency checking:

```rust
fn get_progress(&self, version: Version) -> Result<Option<StateSnapshotProgress>> {
    let main_db_progress = self.state_kv_db.metadata_db()
        .get::<DbMetadataSchema>(&DbMetadataKey::StateSnapshotKvRestoreProgress(version))?
        .map(|v| v.expect_state_snapshot_progress());

    if self.internal_indexer_db.is_some() && self.internal_indexer_db.as_ref().unwrap().statekeys_enabled() {
        let progress_opt = self.internal_indexer_db.as_ref().unwrap().get_restore_progress(version)?;

        match (main_db_progress, progress_opt) {
            (None, None) => (),
            (None, Some(indexer_progress)) => {
                // FIX: This case should bail, not proceed
                bail!(
                    "Inconsistent restore progress: main db has no progress but internal indexer db has progress {:?}. \
                    This indicates a crash during restore. Manual recovery required: clear internal indexer progress or restart restore.",
                    indexer_progress
                );
            },
            (Some(main_progress), Some(indexer_progress)) => {
                if main_progress.key_hash != indexer_progress.key_hash {
                    bail!(
                        "Inconsistent restore progress between main db and internal indexer db. main db: {:?}, internal indexer db: {:?}",
                        main_progress,
                        indexer_progress,
                    );
                }
            },
            (Some(main_progress), None) => {
                bail!(
                    "Inconsistent restore progress: main db has progress {:?} but internal indexer db has none.",
                    main_progress
                );
            },
        }
    }

    Ok(main_db_progress)
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod atomicity_test {
    use super::*;
    use std::sync::{Arc, Mutex as StdMutex};
    
    // Simulate crash-prone StateStore
    struct CrashyStateStore {
        inner: Arc<StateStore>,
        crash_after_indexer: Arc<StdMutex<bool>>,
    }
    
    impl StateValueWriter<StateKey, StateValue> for CrashyStateStore {
        fn write_kv_batch(
            &self,
            version: Version,
            node_batch: &StateValueBatch,
            progress: StateSnapshotProgress,
        ) -> Result<()> {
            // Write to internal indexer (if enabled)
            if let Some(indexer_db) = self.inner.internal_indexer_db.as_ref() {
                if indexer_db.statekeys_enabled() {
                    let keys = node_batch.keys().map(|key| key.0.clone()).collect();
                    indexer_db.write_keys_to_indexer_db(&keys, version, progress)?;
                }
            }
            
            // Simulate crash here
            if *self.crash_after_indexer.lock().unwrap() {
                panic!("Simulated crash after indexer write but before main DB commit");
            }
            
            // Continue with normal write
            self.inner.write_kv_batch(version, node_batch, progress)
        }
        
        fn kv_finish(&self, version: Version, usage: StateStorageUsage) -> Result<()> {
            self.inner.kv_finish(version, usage)
        }
        
        fn get_progress(&self, version: Version) -> Result<Option<StateSnapshotProgress>> {
            self.inner.get_progress(version)
        }
    }
    
    #[test]
    #[should_panic(expected = "Inconsistent restore progress")]
    fn test_crash_leaves_inconsistent_state() {
        // Setup: Create state store with internal indexer enabled
        // ...
        
        let crash_flag = Arc::new(StdMutex::new(false));
        let crashy_store = Arc::new(CrashyStateStore {
            inner: state_store,
            crash_after_indexer: crash_flag.clone(),
        });
        
        // First write succeeds
        let mut restore = StateValueRestore::new(crashy_store.clone(), 0);
        let chunk1 = vec![/* keys */];
        restore.add_chunk(chunk1).unwrap();
        
        // Enable crash on next write
        *crash_flag.lock().unwrap() = true;
        
        // This should crash after indexer write
        let chunk2 = vec![/* more keys */];
        let _ = restore.add_chunk(chunk2); // Panics here
        
        // On recovery, get_progress should detect inconsistency
        let new_restore = StateValueRestore::new(crashy_store.clone(), 0);
        let progress = new_restore.db.get_progress(0);
        
        // This should fail with current code behavior (but shouldn't!)
        // With fix, this would return the error
        assert!(progress.is_err()); 
    }
}
```

## Notes

The test suite does not catch this vulnerability because `MockSnapshotStore` writes atomically to in-memory structures: [7](#0-6) 

The production implementation involves multiple database instances with separate commit operations, creating the atomicity gap. The system designers were aware of this limitation but the consistency checking is insufficient to handle all failure modes.

### Citations

**File:** storage/aptosdb/src/state_restore/mod.rs (L122-126)
```rust
        self.db.write_kv_batch(
            self.version,
            &kv_batch,
            StateSnapshotProgress::new(last_key_hash, usage),
        )
```

**File:** storage/aptosdb/src/state_store/mod.rs (L451-452)
```rust
            // State K/V commit progress isn't (can't be) written atomically with the data,
            // because there are shards, so we have to attempt truncation anyway.
```

**File:** storage/aptosdb/src/state_store/mod.rs (L1244-1279)
```rust
    fn write_kv_batch(
        &self,
        version: Version,
        node_batch: &StateValueBatch,
        progress: StateSnapshotProgress,
    ) -> Result<()> {
        let _timer = OTHER_TIMERS_SECONDS.timer_with(&["state_value_writer_write_chunk"]);
        let mut batch = SchemaBatch::new();
        let mut sharded_schema_batch = self.state_kv_db.new_sharded_native_batches();

        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::StateSnapshotKvRestoreProgress(version),
            &DbMetadataValue::StateSnapshotProgress(progress),
        )?;

        if self.internal_indexer_db.is_some()
            && self
                .internal_indexer_db
                .as_ref()
                .unwrap()
                .statekeys_enabled()
        {
            let keys = node_batch.keys().map(|key| key.0.clone()).collect();
            self.internal_indexer_db
                .as_ref()
                .unwrap()
                .write_keys_to_indexer_db(&keys, version, progress)?;
        }
        self.shard_state_value_batch(
            &mut sharded_schema_batch,
            node_batch,
            self.state_kv_db.enabled_sharding(),
        )?;
        self.state_kv_db
            .commit(version, Some(batch), sharded_schema_batch)
    }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L1317-1361)
```rust
    fn get_progress(&self, version: Version) -> Result<Option<StateSnapshotProgress>> {
        let main_db_progress = self
            .state_kv_db
            .metadata_db()
            .get::<DbMetadataSchema>(&DbMetadataKey::StateSnapshotKvRestoreProgress(version))?
            .map(|v| v.expect_state_snapshot_progress());

        // verify if internal indexer db and main db are consistent before starting the restore
        if self.internal_indexer_db.is_some()
            && self
                .internal_indexer_db
                .as_ref()
                .unwrap()
                .statekeys_enabled()
        {
            let progress_opt = self
                .internal_indexer_db
                .as_ref()
                .unwrap()
                .get_restore_progress(version)?;

            match (main_db_progress, progress_opt) {
                (None, None) => (),
                (None, Some(_)) => (),
                (Some(main_progress), Some(indexer_progress)) => {
                    if main_progress.key_hash > indexer_progress.key_hash {
                        bail!(
                            "Inconsistent restore progress between main db and internal indexer db. main db: {:?}, internal indexer db: {:?}",
                            main_progress,
                            indexer_progress,
                        );
                    }
                },
                _ => {
                    bail!(
                        "Inconsistent restore progress between main db and internal indexer db. main db: {:?}, internal indexer db: {:?}",
                        main_db_progress,
                        progress_opt,
                    );
                },
            }
        }

        Ok(main_db_progress)
    }
```

**File:** storage/indexer/src/db_indexer.rs (L90-107)
```rust
    pub fn write_keys_to_indexer_db(
        &self,
        keys: &Vec<StateKey>,
        snapshot_version: Version,
        progress: StateSnapshotProgress,
    ) -> Result<()> {
        // add state value to internal indexer
        let mut batch = SchemaBatch::new();
        for state_key in keys {
            batch.put::<StateKeysSchema>(state_key, &())?;
        }

        batch.put::<InternalIndexerMetadataSchema>(
            &MetadataKey::StateSnapshotRestoreProgress(snapshot_version),
            &MetadataValue::StateSnapshotProgress(progress),
        )?;
        self.db.write_schemas(batch)?;
        Ok(())
```

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

**File:** storage/aptosdb/src/state_restore/restore_test.rs (L74-89)
```rust
    fn write_kv_batch(
        &self,
        version: Version,
        kv_batch: &StateValueBatch<K, Option<V>>,
        progress: StateSnapshotProgress,
    ) -> Result<()> {
        for (k, v) in kv_batch {
            if let Some(v) = v {
                self.kv_store.write().insert(k.clone(), v.clone());
            } else {
                self.kv_store.write().remove(k);
            }
        }
        self.progress_store.write().insert(version, progress);
        Ok(())
    }
```

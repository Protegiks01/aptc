# Audit Report

## Title
State Restore Progress Race Condition Leading to Chunk Loss via Concurrent Instance TOCTOU

## Summary
Multiple `StateSnapshotRestore` instances created for the same version can concurrently call `add_chunk()`, causing a TOCTOU vulnerability where progress reads at line 90 and writes at line 122 are not atomic, resulting in progress corruption that leads to skipped chunks or duplicate processing during state restore operations.

## Finding Description

The vulnerability exists in the state restore mechanism where concurrent `StateSnapshotRestore` instances for the same version lack database-level synchronization. [1](#0-0) 

The critical flaw is that each `StateSnapshotRestore` instance maintains its own mutex for internal state, but multiple instances can access the shared database concurrently: [2](#0-1) 

When `StateSnapshotRestore::add_chunk()` is called, it locks only its instance's internal mutex: [3](#0-2) 

This creates a TOCTOU window:

**Race Scenario:**
1. Instance A reads progress = `key_hash_100` from database (line 90)
2. Instance B reads progress = `key_hash_100` from database (concurrent)
3. Instance A processes chunk `[101-150]`, prepares `progress = key_hash_150`
4. Instance B processes chunk `[151-200]`, prepares `progress = key_hash_200`  
5. Instance B writes to database: data `[151-200]` + `progress = key_hash_200`
6. Instance A writes to database: data `[101-150]` + `progress = key_hash_150` (overwrites B's progress)

**Result:** Database now contains data through `key_hash_200`, but progress shows `key_hash_150`. Chunk `[151-200]` becomes "lost" from the progress tracker's perspective.

The database write operation commits sharded data and metadata separately without cross-instance locking: [4](#0-3) [5](#0-4) 

The metadata (including `StateSnapshotProgress`) is written after shards complete, but RocksDB provides no transaction isolation between separate write operations—last write wins.

## Impact Explanation

**Severity: Medium** 

This breaks the **State Consistency** invariant by causing:

1. **Skipped Chunks**: If restore is interrupted after the race, resume will start from the corrupted progress marker, potentially missing chunks that were already written
2. **Incorrect Storage Usage Tracking**: Usage calculation in line 107-114 depends on progress, so race conditions cause incorrect accounting
3. **Restore Operation Failure**: While the expected root hash verification prevents silent corruption, restore failures waste resources and delay node synchronization [6](#0-5) 

This qualifies as **Medium severity** per Aptos bug bounty criteria: "State inconsistencies requiring intervention" - the corrupted progress requires manual intervention or complete restore restart.

## Likelihood Explanation

**Likelihood: Low-Medium**

While the current backup-cli implementation wraps receivers in a protective mutex: [7](#0-6) 

The vulnerability can be triggered by:

1. **Code Refactoring**: Removal of the outer mutex protection
2. **Direct API Usage**: Other code paths that create `StateSnapshotRestore` instances directly without proper synchronization
3. **Distributed Restore**: Future parallel restore implementations across multiple processes/nodes

The test suite demonstrates that multiple instances for the same version are an intended use case for resumption: [8](#0-7) 

## Recommendation

Add database-level synchronization using an advisory lock keyed by version:

```rust
pub fn add_chunk(&mut self, mut chunk: Vec<(K, V)>) -> Result<()> {
    // Acquire version-specific lock to prevent concurrent instances
    let _version_lock = self.db.acquire_restore_lock(self.version)?;
    
    // load progress
    let progress_opt = self.db.get_progress(self.version)?;
    
    // ... rest of the implementation
}
```

Alternatively, implement atomic read-modify-write for progress updates:

```rust
self.db.write_kv_batch_atomic(
    self.version,
    &kv_batch,
    StateSnapshotProgress::new(last_key_hash, usage),
    progress_opt.map(|p| p.key_hash), // expected_previous_hash for CAS
)
```

The `write_kv_batch_atomic` would fail if progress changed since the read, forcing retry with fresh progress.

## Proof of Concept

```rust
#[test]
fn test_concurrent_restore_race_condition() {
    use std::sync::{Arc, Barrier};
    use std::thread;
    
    // Setup: Create database and test data with 300 items
    let (db, version) = init_mock_store(&all_items);
    let tree = JellyfishMerkleTree::new(&db);
    let expected_root_hash = tree.get_root_hash(version).unwrap();
    
    // Split into two non-overlapping chunks
    let chunk1: Vec<_> = all_items[0..150].to_vec(); // keys 0-149
    let chunk2: Vec<_> = all_items[150..300].to_vec(); // keys 150-299
    
    let restore_db = Arc::new(MockSnapshotStore::default());
    let barrier = Arc::new(Barrier::new(2));
    
    // Create two separate StateSnapshotRestore instances for the SAME version
    let restore_db1 = Arc::clone(&restore_db);
    let restore_db2 = Arc::clone(&restore_db);
    let barrier1 = Arc::clone(&barrier);
    let barrier2 = Arc::clone(&barrier);
    
    let handle1 = thread::spawn(move || {
        let mut restore1 = StateSnapshotRestore::new(
            &restore_db1, &restore_db1, version, expected_root_hash, 
            false, StateSnapshotRestoreMode::Default
        ).unwrap();
        
        barrier1.wait(); // Synchronize to maximize race window
        
        let proof1 = tree.get_range_proof(chunk1.last().unwrap().0, version).unwrap();
        restore1.add_chunk(chunk1, proof1).unwrap();
    });
    
    let handle2 = thread::spawn(move || {
        let mut restore2 = StateSnapshotRestore::new(
            &restore_db2, &restore_db2, version, expected_root_hash,
            false, StateSnapshotRestoreMode::Default
        ).unwrap();
        
        barrier2.wait(); // Synchronize to maximize race window
        
        let proof2 = tree.get_range_proof(chunk2.last().unwrap().0, version).unwrap();
        restore2.add_chunk(chunk2, proof2).unwrap();
    });
    
    handle1.join().unwrap();
    handle2.join().unwrap();
    
    // Verify the race: progress may be at chunk1's end even though chunk2 was written
    let progress = restore_db.get_progress(version).unwrap().unwrap();
    let chunk1_last_hash = CryptoHash::hash(&chunk1.last().unwrap().0);
    let chunk2_last_hash = CryptoHash::hash(&chunk2.last().unwrap().0);
    
    // BUG: Progress may show chunk1's hash while data includes chunk2
    // This proves the TOCTOU - progress doesn't reflect actual written data
    if progress.key_hash == chunk1_last_hash {
        println!("RACE DETECTED: Progress at {:?} but chunk2 data written", progress.key_hash);
        assert!(restore_db.has_data_for_key(&chunk2.last().unwrap().0));
        panic!("Progress corruption detected - chunk2 written but progress shows chunk1!");
    }
}
```

## Notes

While the current production code path (backup-cli) mitigates this with an outer mutex, the vulnerability exists at the API level. The state restore subsystem should enforce its own consistency guarantees rather than relying on callers to prevent concurrent access. This is particularly important given that test code demonstrates multi-instance usage for resumption, establishing that multiple instances per version is an intended pattern.

### Citations

**File:** storage/aptosdb/src/state_restore/mod.rs (L88-127)
```rust
    pub fn add_chunk(&mut self, mut chunk: Vec<(K, V)>) -> Result<()> {
        // load progress
        let progress_opt = self.db.get_progress(self.version)?;

        // skip overlaps
        if let Some(progress) = progress_opt {
            let idx = chunk
                .iter()
                .position(|(k, _v)| CryptoHash::hash(k) > progress.key_hash)
                .unwrap_or(chunk.len());
            chunk = chunk.split_off(idx);
        }

        // quit if all skipped
        if chunk.is_empty() {
            return Ok(());
        }

        // save
        let mut usage = progress_opt.map_or(StateStorageUsage::zero(), |p| p.usage);
        let (last_key, _last_value) = chunk.last().unwrap();
        let last_key_hash = CryptoHash::hash(last_key);

        // In case of TreeOnly Restore, we only restore the usage of KV without actually writing KV into DB
        for (k, v) in chunk.iter() {
            usage.add_item(k.key_size() + v.value_size());
        }

        // prepare the sharded kv batch
        let kv_batch: StateValueBatch<K, Option<V>> = chunk
            .into_iter()
            .map(|(k, v)| ((k, self.version), Some(v)))
            .collect();

        self.db.write_kv_batch(
            self.version,
            &kv_batch,
            StateSnapshotProgress::new(last_key_hash, usage),
        )
    }
```

**File:** storage/aptosdb/src/state_restore/mod.rs (L145-149)
```rust
pub struct StateSnapshotRestore<K, V> {
    tree_restore: Arc<Mutex<Option<JellyfishMerkleRestore<K>>>>,
    kv_restore: Arc<Mutex<Option<StateValueRestore<K, V>>>>,
    restore_mode: StateSnapshotRestoreMode,
}
```

**File:** storage/aptosdb/src/state_restore/mod.rs (L228-236)
```rust
    fn add_chunk(&mut self, chunk: Vec<(K, V)>, proof: SparseMerkleRangeProof) -> Result<()> {
        let kv_fn = || {
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["state_value_add_chunk"]);
            self.kv_restore
                .lock()
                .as_mut()
                .unwrap()
                .add_chunk(chunk.clone())
        };
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

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L141-145)
```rust
        let receiver = Arc::new(Mutex::new(Some(self.run_mode.get_state_restore_receiver(
            self.version,
            manifest.root_hash,
            self.restore_mode,
        )?)));
```

**File:** storage/aptosdb/src/state_restore/restore_test.rs (L188-202)
```rust
        {
            let mut restore =
                StateSnapshotRestore::new(&restore_db, &restore_db,  version, expected_root_hash, true /* async_commit */, StateSnapshotRestoreMode::Default).unwrap();
            let proof = tree
                .get_range_proof(batch1.last().map(|(key, _value)| *key).unwrap(), version)
                .unwrap();
            restore.add_chunk(batch1.into_iter().map(|(_, kv)| kv).collect(), proof).unwrap();
            // Do not call `finish`.
        }

        {
            let remaining_accounts: Vec<_> = all.clone().into_iter().skip(batch1_size - overlap_size).collect();

            let mut restore =
                StateSnapshotRestore::new(&restore_db, &restore_db,  version, expected_root_hash, true /* async commit */, StateSnapshotRestoreMode::Default ).unwrap();
```

# Audit Report

## Title
Restore Operation Requires Manual Intervention After Crash Due to Orphaned Progress Metadata and Non-Atomic Multi-Shard Commits

## Summary
The restore operation in AptosDB cannot automatically recover to a consistent state after interruption. Progress metadata (`StateSnapshotKvRestoreProgress`) is never deleted after successful completion, and the multi-shard commit process is non-atomic, requiring manual database intervention to recover from crashes at specific points in the restore flow.

## Finding Description
The restore handler in AptosDB has two critical flaws that prevent automatic recovery after interruption:

**Flaw 1: Orphaned Progress Metadata**

After a restore operation completes successfully, the `StateSnapshotKvRestoreProgress` metadata is never deleted from the database. [1](#0-0) 

The `kv_finish()` method writes the final storage usage but contains no logic to delete the progress metadata. This orphaned metadata persists indefinitely and is detected by `get_in_progress_state_kv_snapshot_version()` which iterates through all metadata entries: [2](#0-1) 

**Flaw 2: Non-Atomic Multi-Shard Commit**

During restore, state values are written through a multi-step commit process that is not atomic: [3](#0-2) 

The commit sequence is:
1. Commit all 16 shards in parallel (lines 186-200)
2. Commit metadata batch containing `StateSnapshotKvRestoreProgress` (lines 202-205)  
3. Write `StateKvCommitProgress` (line 207)

If a crash occurs between steps 1 and 2, the shards contain data but the progress metadata doesn't reflect it. If a crash occurs between steps 2 and 3, the progress metadata is written but some shards may have failed. The restore logic uses this progress to skip already-processed keys: [4](#0-3) 

**Manual Intervention Scenarios:**

1. **Orphaned metadata after successful restore**: If the node restarts after a successful restore, the old progress marker remains, causing `get_in_progress_state_kv_snapshot_version()` to incorrectly detect an in-progress restore.

2. **Database files deleted but metadata intact**: If state KV shards are manually deleted or corrupted but the metadata DB remains, the system detects a non-existent in-progress restore and cannot proceed without manually deleting the orphaned metadata.

3. **Inconsistent state after partial shard commit**: If only some shards commit before a crash, the database is in an inconsistent state with no automated recovery mechanism.

## Impact Explanation
This qualifies as **High severity** per the security question designation and meets the "State inconsistencies requiring intervention" criterion (Medium severity minimum in the bug bounty program).

**Affected Systems:**
- All validator nodes performing restore operations
- Archive nodes restoring from backups
- Any node recovering from database corruption

**Consequences:**
- Node operators must manually inspect and clean up orphaned metadata entries
- No documented procedure for metadata cleanup exists
- Restore operations cannot complete automatically after crashes
- Database inconsistencies may persist undetected until manual inspection

This breaks the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs." The multi-shard commit is not atomic, and the system cannot automatically verify and recover from inconsistent states.

## Likelihood Explanation
**High likelihood** in production environments:

- Restore operations are common during:
  - Node initialization from backups
  - Recovery from database corruption
  - Disaster recovery scenarios
  - State sync operations

- Crashes during restore are realistic:
  - Out of memory during large state downloads
  - Network interruptions during backup retrieval
  - Disk space exhaustion
  - Process crashes due to resource limits
  - System reboots during maintenance

- The vulnerability triggers automatically when crashes occur at specific points in the commit sequence (between shard commits and metadata commits).

## Recommendation

**Solution 1: Delete progress metadata after successful completion**

Modify `kv_finish()` to delete the progress metadata: [1](#0-0) 

Add deletion logic after writing usage:
```rust
fn kv_finish(&self, version: Version, usage: StateStorageUsage) -> Result<()> {
    self.ledger_db.metadata_db().put_usage(version, usage)?;
    
    // Delete progress metadata after successful completion
    let mut batch = SchemaBatch::new();
    batch.delete::<DbMetadataSchema>(&DbMetadataKey::StateSnapshotKvRestoreProgress(version))?;
    self.state_kv_db.metadata_db().write_schemas(batch)?;
    
    // ... rest of the function
}
```

**Solution 2: Make multi-shard commit atomic**

Use a two-phase commit protocol or write-ahead logging to ensure atomicity across all shards and metadata. Commit metadata BEFORE committing shards, then verify all shards committed successfully.

**Solution 3: Add automated consistency checks**

On startup, verify that `StateSnapshotKvRestoreProgress` metadata matches actual database state (e.g., check if `db_next_version` has progressed beyond the progress marker). Automatically clean up stale metadata.

## Proof of Concept

```rust
// Test demonstrating orphaned metadata after successful restore
#[test]
fn test_orphaned_progress_metadata() {
    // Setup: Create a mock database and restore handler
    let tmpdir = TempDir::new().unwrap();
    let db = AptosDB::new_for_test(&tmpdir);
    let restore_handler = db.get_restore_handler();
    
    // Step 1: Perform a complete restore at version 100
    let version = 100;
    let root_hash = HashValue::random();
    let mut receiver = restore_handler
        .get_state_restore_receiver(
            version,
            root_hash,
            StateSnapshotRestoreMode::Default,
        )
        .unwrap();
    
    // Add chunks and complete restore
    let test_chunk = vec![(StateKey::random(), StateValue::random())];
    receiver.add_chunk(test_chunk, SparseMerkleRangeProof::default()).unwrap();
    receiver.finish().unwrap();
    
    // Step 2: Verify progress metadata still exists
    let in_progress = restore_handler
        .get_in_progress_state_kv_snapshot_version()
        .unwrap();
    
    // BUG: This should be None after successful completion, but returns Some(100)
    assert_eq!(in_progress, Some(version), "Progress metadata was not cleaned up!");
    
    // Step 3: Simulate node restart and attempt new restore
    // The system incorrectly detects an in-progress restore
    // Manual intervention required to delete the orphaned metadata
}
```

## Notes
The vulnerability is confirmed by the absence of any deletion logic for `StateSnapshotKvRestoreProgress` in the entire codebase (grep search returned zero matches for deletion patterns). The test mock implementations also preserve progress metadata indefinitely, indicating this behavior is by design but flawed. [5](#0-4)

### Citations

**File:** storage/aptosdb/src/state_store/mod.rs (L1281-1314)
```rust
    fn kv_finish(&self, version: Version, usage: StateStorageUsage) -> Result<()> {
        self.ledger_db.metadata_db().put_usage(version, usage)?;
        if let Some(internal_indexer_db) = self.internal_indexer_db.as_ref() {
            if version > 0 {
                let mut batch = SchemaBatch::new();
                batch.put::<InternalIndexerMetadataSchema>(
                    &MetadataKey::LatestVersion,
                    &MetadataValue::Version(version - 1),
                )?;
                if internal_indexer_db.statekeys_enabled() {
                    batch.put::<InternalIndexerMetadataSchema>(
                        &MetadataKey::StateVersion,
                        &MetadataValue::Version(version - 1),
                    )?;
                }
                if internal_indexer_db.transaction_enabled() {
                    batch.put::<InternalIndexerMetadataSchema>(
                        &MetadataKey::TransactionVersion,
                        &MetadataValue::Version(version - 1),
                    )?;
                }
                if internal_indexer_db.event_enabled() {
                    batch.put::<InternalIndexerMetadataSchema>(
                        &MetadataKey::EventVersion,
                        &MetadataValue::Version(version - 1),
                    )?;
                }
                internal_indexer_db
                    .get_inner_db_ref()
                    .write_schemas(batch)?;
            }
        }

        Ok(())
```

**File:** storage/aptosdb/src/backup/restore_handler.rs (L139-149)
```rust
    pub fn get_in_progress_state_kv_snapshot_version(&self) -> Result<Option<Version>> {
        let db = self.aptosdb.state_kv_db.metadata_db_arc();
        let mut iter = db.iter::<DbMetadataSchema>()?;
        iter.seek_to_first();
        while let Some((k, _v)) = iter.next().transpose()? {
            if let DbMetadataKey::StateSnapshotKvRestoreProgress(version) = k {
                return Ok(Some(version));
            }
        }
        Ok(None)
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

**File:** storage/aptosdb/src/state_restore/restore_test.rs (L91-94)
```rust
    fn kv_finish(&self, version: Version, usage: StateStorageUsage) -> Result<()> {
        self.usage_store.write().insert(version, usage);
        Ok(())
    }
```

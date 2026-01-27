# Audit Report

## Title
Cross-Column Family Deletion Bug in Quorum Store Epoch Garbage Collection

## Summary
The `gc_previous_epoch_batches_from_db_v2()` function in `batch_store.rs` incorrectly deletes batches from the `batch` CF instead of the `batch_v2` CF during epoch transitions, causing cross-CF data corruption and preventing proper cleanup of V2 batches from previous epochs.

## Finding Description
During epoch transitions, the `BatchStore::new()` function spawns garbage collection tasks to clean up batches from previous epochs. The system maintains two separate column families: `batch` CF for V1 batches (BatchInfo) and `batch_v2` CF for V2 batches (BatchInfoExt). [1](#0-0) 

The critical bug occurs in the V2 garbage collection function: [2](#0-1) 

At line 241, the function calls `db.delete_batches(expired_keys)` instead of `db.delete_batches_v2(expired_keys)`. This causes it to delete from the wrong column family.

The distinction between these methods is clear in the database implementation: [3](#0-2) 

`delete_batches()` operates on `BatchSchema` (the `batch` CF), while `delete_batches_v2()` operates on `BatchV2Schema` (the `batch_v2` CF).

**Breaking the State Consistency Invariant:**

This bug violates the State Consistency invariant by causing validators to have different persistent storage states. When epoch N+1 begins:

1. All validators execute `gc_previous_epoch_batches_from_db_v2()`
2. This reads expired V2 batch digests from `batch_v2` CF
3. But deletes those digests from `batch` CF instead
4. Result: V2 batches from epoch N-1 remain in `batch_v2` CF indefinitely
5. If any V1 batches share the same digest, they are incorrectly deleted from `batch` CF

The same issue exists in the expiration cleanup path: [4](#0-3) 

The `db_cache` contains `PersistedValue<BatchInfoExt>` entries (which can be either V1 or V2), but `update_certified_timestamp()` only calls `delete_batches()`, not `delete_batches_v2()`.

## Impact Explanation
This qualifies as **Medium Severity** under the bug bounty criteria ("State inconsistencies requiring intervention") because:

1. **Storage Exhaustion**: V2 batches accumulate indefinitely across epochs, never being garbage collected, leading to unbounded storage growth
2. **Cross-CF Data Corruption**: V1 batches can be incorrectly deleted if they share digests with expired V2 batches
3. **Validator State Divergence**: Different validators may have different storage states depending on their batch history, breaking deterministic execution guarantees
4. **No Network Partition**: While it causes state inconsistencies, it does not create irrecoverable network partitions

The bug does not reach Critical severity because it does not directly enable fund theft, consensus safety violations, or network-wide liveness failures. However, it does require manual intervention to clean up accumulated V2 batches.

## Likelihood Explanation
**High Likelihood** - This bug triggers automatically on every epoch transition when V2 batches are enabled:

1. **Automatic Trigger**: No attacker action required - happens during normal epoch transitions
2. **Current Deployment**: If `enable_batch_v2` configuration is enabled in production, this bug is actively occurring
3. **Compounding Effect**: Storage bloat accumulates with each epoch transition
4. **Migration Risk**: During V1→V2 migration periods, cross-CF deletion is most likely [5](#0-4) 

## Recommendation
Fix both garbage collection functions to delete from the correct column family:

**Fix for `gc_previous_epoch_batches_from_db_v2`:**
```rust
fn gc_previous_epoch_batches_from_db_v2(db: Arc<dyn QuorumStoreStorage>, current_epoch: u64) {
    let db_content = db
        .get_all_batches_v2()
        .expect("failed to read data from db");
    // ... collection logic ...
    
    // FIXED: Use delete_batches_v2 instead of delete_batches
    db.delete_batches_v2(expired_keys)
        .expect("Deletion of expired keys should not fail");
}
```

**Fix for `update_certified_timestamp`:**
```rust
pub fn update_certified_timestamp(&self, certified_time: u64) {
    trace!("QS: batch reader updating time {:?}", certified_time);
    self.last_certified_time
        .fetch_max(certified_time, Ordering::SeqCst);

    let expired_keys = self.clear_expired_payload(certified_time);
    
    // FIXED: Delete from both CFs based on batch version
    // Option 1: Track which CF each digest belongs to
    // Option 2: Attempt deletion from both CFs (ignore not-found errors)
    if let Err(e) = self.db.delete_batches_v2(expired_keys.clone()) {
        debug!("Error deleting V2 batches: {:?}", e)
    }
    if let Err(e) = self.db.delete_batches(expired_keys) {
        debug!("Error deleting V1 batches: {:?}", e)
    }
}
```

## Proof of Concept

```rust
#[tokio::test]
async fn test_cross_cf_deletion_bug() {
    use aptos_crypto::HashValue;
    use consensus::quorum_store::{
        batch_store::BatchStore,
        quorum_store_db::QuorumStoreDB,
        types::PersistedValue,
    };
    use aptos_consensus_types::proof_of_store::BatchInfoExt;
    use std::sync::Arc;
    use tempfile::TempDir;

    // Setup
    let tmp_dir = TempDir::new().unwrap();
    let db = Arc::new(QuorumStoreDB::new(tmp_dir.path()));
    
    // Create and store a V2 batch in epoch 1
    let batch_v2 = BatchInfoExt::new_v2(
        PeerId::random(),
        BatchId::new_for_test(1),
        1, // epoch 1
        1000,
        HashValue::random(),
        10,
        1000,
        0,
        BatchKind::Normal,
    );
    let persisted_v2 = PersistedValue::new(batch_v2.clone(), Some(vec![]));
    db.save_batch_v2(persisted_v2).unwrap();
    
    // Verify V2 batch exists
    assert!(db.get_batch_v2(batch_v2.digest()).unwrap().is_some());
    
    // Trigger epoch transition to epoch 2 (this runs gc_previous_epoch_batches_from_db_v2)
    let batch_store = BatchStore::new(
        2, // epoch 2
        true, // is_new_epoch = true triggers gc
        2000,
        db.clone(),
        1000000,
        1000000,
        1000,
        validator_signer,
        60_000_000,
    );
    
    // Wait for async gc to complete
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // BUG: V2 batch should be deleted but still exists
    // because gc_previous_epoch_batches_from_db_v2 called delete_batches 
    // instead of delete_batches_v2
    assert!(db.get_batch_v2(batch_v2.digest()).unwrap().is_some(), 
            "V2 batch from epoch 1 should have been deleted but still exists");
}
```

## Notes
While the security question asked about "cross-CF race conditions", the actual issue discovered is a **cross-CF logic error** rather than a race condition. RocksDB column families provide proper isolation for concurrent reads and writes. However, the bug causes cross-CF data corruption by deleting from the wrong column family, which can lead to validator state inconsistencies during epoch transitions.

The bug requires the `enable_batch_v2` configuration to be active and affects all validators uniformly during epoch transitions. It is not directly exploitable by malicious actors but represents a systematic implementation error that violates state consistency guarantees.

### Citations

**File:** consensus/src/quorum_store/schema.rs (L14-16)
```rust
pub(crate) const BATCH_CF_NAME: ColumnFamilyName = "batch";
pub(crate) const BATCH_ID_CF_NAME: ColumnFamilyName = "batch_ID";
pub(crate) const BATCH_V2_CF_NAME: ColumnFamilyName = "batch_v2";
```

**File:** consensus/src/quorum_store/batch_store.rs (L156-160)
```rust
        if is_new_epoch {
            tokio::task::spawn_blocking(move || {
                Self::gc_previous_epoch_batches_from_db_v1(db_clone.clone(), epoch);
                Self::gc_previous_epoch_batches_from_db_v2(db_clone, epoch);
            });
```

**File:** consensus/src/quorum_store/batch_store.rs (L212-243)
```rust
    fn gc_previous_epoch_batches_from_db_v2(db: Arc<dyn QuorumStoreStorage>, current_epoch: u64) {
        let db_content = db
            .get_all_batches_v2()
            .expect("failed to read data from db");
        info!(
            epoch = current_epoch,
            "QS: Read batches from storage. Len: {}",
            db_content.len(),
        );

        let mut expired_keys = Vec::new();
        for (digest, value) in db_content {
            let epoch = value.epoch();

            trace!(
                "QS: Batchreader recovery content epoch {:?}, digest {}",
                epoch,
                digest
            );

            if epoch < current_epoch {
                expired_keys.push(digest);
            }
        }

        info!(
            "QS: Batch store bootstrap expired keys len {}",
            expired_keys.len()
        );
        db.delete_batches(expired_keys)
            .expect("Deletion of expired keys should not fail");
    }
```

**File:** consensus/src/quorum_store/batch_store.rs (L530-539)
```rust
    pub fn update_certified_timestamp(&self, certified_time: u64) {
        trace!("QS: batch reader updating time {:?}", certified_time);
        self.last_certified_time
            .fetch_max(certified_time, Ordering::SeqCst);

        let expired_keys = self.clear_expired_payload(certified_time);
        if let Err(e) = self.db.delete_batches(expired_keys) {
            debug!("Error deleting batches: {:?}", e)
        }
    }
```

**File:** consensus/src/quorum_store/quorum_store_db.rs (L93-131)
```rust
    fn delete_batches(&self, digests: Vec<HashValue>) -> Result<(), DbError> {
        let mut batch = SchemaBatch::new();
        for digest in digests.iter() {
            trace!("QS: db delete digest {}", digest);
            batch.delete::<BatchSchema>(digest)?;
        }
        self.db.write_schemas_relaxed(batch)?;
        Ok(())
    }

    fn get_all_batches(&self) -> Result<HashMap<HashValue, PersistedValue<BatchInfo>>> {
        let mut iter = self.db.iter::<BatchSchema>()?;
        iter.seek_to_first();
        iter.map(|res| res.map_err(Into::into))
            .collect::<Result<HashMap<HashValue, PersistedValue<BatchInfo>>>>()
    }

    fn save_batch(&self, batch: PersistedValue<BatchInfo>) -> Result<(), DbError> {
        trace!(
            "QS: db persists digest {} expiration {:?}",
            batch.digest(),
            batch.expiration()
        );
        self.put::<BatchSchema>(batch.digest(), &batch)
    }

    fn get_batch(&self, digest: &HashValue) -> Result<Option<PersistedValue<BatchInfo>>, DbError> {
        Ok(self.db.get::<BatchSchema>(digest)?)
    }

    fn delete_batches_v2(&self, digests: Vec<HashValue>) -> Result<(), DbError> {
        let mut batch = SchemaBatch::new();
        for digest in digests.iter() {
            trace!("QS: db delete digest {}", digest);
            batch.delete::<BatchV2Schema>(digest)?;
        }
        self.db.write_schemas_relaxed(batch)?;
        Ok(())
    }
```

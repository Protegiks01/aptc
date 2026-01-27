# Audit Report

## Title
V2 Batch Garbage Collection Bypass Leading to Storage Exhaustion and Validator Node Failure

## Summary
The `gc_previous_epoch_batches_from_db_v2()` function incorrectly calls `delete_batches()` instead of `delete_batches_v2()`, causing v2 batches to never be deleted from the database during epoch-based cleanup. This results in indefinite accumulation of v2 batches, eventually leading to storage exhaustion and validator node failures. [1](#0-0) 

## Finding Description
The Aptos quorum store maintains two separate storage schemas for batches: `BatchSchema` (v1) stored in the "batch" column family and `BatchV2Schema` (v2) stored in the "batch_v2" column family. [2](#0-1) 

The storage interface provides separate deletion methods: `delete_batches()` for v1 batches and `delete_batches_v2()` for v2 batches. [3](#0-2) 

During epoch transitions, when `is_new_epoch` is true, the system spawns garbage collection tasks for both v1 and v2 batches. [4](#0-3) 

The critical bug exists in `gc_previous_epoch_batches_from_db_v2()`: it correctly reads v2 batches from the "batch_v2" column family but then attempts to delete them from the "batch" column family by calling the wrong deletion method. This causes v2 batches to survive epoch-based cleanup entirely.

Additionally, time-based expiration via `update_certified_timestamp()` also fails to properly clean up v2 batches from persistent storage. [5](#0-4) 

**Attack Scenario:**
1. Network operators enable v2 batch support via the `enable_batch_v2` configuration flag
2. Validators create v2 batches during normal consensus operations [6](#0-5) 
3. When epoch N transitions to epoch N+1, `gc_previous_epoch_batches_from_db_v2()` executes
4. The function reads all v2 batches from epoch N but fails to delete them (deletes from wrong column family)
5. V2 batches from epoch N remain in the "batch_v2" column family indefinitely
6. Process repeats for epochs N+1, N+2, N+3, etc., accumulating undeletable batches
7. Eventually, disk storage fills up, causing validator node crashes or failure to restart

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

## Impact Explanation
This vulnerability qualifies as **HIGH severity** under the Aptos bug bounty program criteria:

- **Validator node slowdowns**: As storage fills, I/O performance degrades, slowing down block processing
- **Significant protocol violations**: Epoch-based garbage collection is a critical resource management protocol that is fundamentally broken for v2 batches
- **Network availability impact**: Multiple validators experiencing storage exhaustion simultaneously could severely impact network liveness, approaching the "Total loss of liveness/network availability" threshold for Critical severity

The impact is gradual but inevitable:
- **Immediate**: No visible impact (batches accumulate slowly)
- **Short-term (days-weeks)**: Increased disk usage, slower I/O operations
- **Medium-term (weeks-months)**: Disk space exhaustion, validator nodes fail to restart
- **Long-term**: Potential network disruption if multiple validators are affected simultaneously

## Likelihood Explanation
**Likelihood: HIGH** - This bug triggers automatically under normal operating conditions:

1. **No attacker action required**: The bug manifests during routine epoch transitions when v2 batches are enabled
2. **Configuration-dependent**: Only affects networks/validators that have enabled the `enable_batch_v2` feature flag
3. **Guaranteed accumulation**: Every epoch with v2 batches creates permanent database entries that never get cleaned up
4. **Cumulative damage**: Impact compounds over time, making long-running validators particularly vulnerable

The only requirement is that v2 batches are enabled, which is likely in production environments as it represents a protocol upgrade. There is no randomness or race condition—the bug occurs deterministically.

## Recommendation
**Immediate Fix**: Change line 241 in `batch_store.rs` to call the correct deletion method:

```rust
// BEFORE (BUGGY):
db.delete_batches(expired_keys)
    .expect("Deletion of expired keys should not fail");

// AFTER (FIXED):
db.delete_batches_v2(expired_keys)
    .expect("Deletion of expired keys should not fail");
```

**Additional Fix**: Update `update_certified_timestamp()` to separately track and delete v2 batches:

```rust
pub fn update_certified_timestamp(&self, certified_time: u64) {
    trace!("QS: batch reader updating time {:?}", certified_time);
    self.last_certified_time
        .fetch_max(certified_time, Ordering::SeqCst);

    let expired_keys = self.clear_expired_payload(certified_time);
    
    // Separate expired batches by version
    let (v1_keys, v2_keys): (Vec<_>, Vec<_>) = expired_keys
        .into_iter()
        .partition(|digest| {
            if let Some(value) = self.db_cache.get(digest) {
                !value.batch_info().is_v2()
            } else {
                true // Default to v1 for safety
            }
        });
    
    if let Err(e) = self.db.delete_batches(v1_keys) {
        debug!("Error deleting v1 batches: {:?}", e)
    }
    if let Err(e) = self.db.delete_batches_v2(v2_keys) {
        debug!("Error deleting v2 batches: {:?}", e)
    }
}
```

**Cleanup of Existing Corrupted State**: Deploy a migration script to clean up accumulated v2 batches from previous epochs during the next protocol upgrade.

## Proof of Concept

```rust
#[cfg(test)]
mod test_v2_batch_gc_bug {
    use super::*;
    use aptos_consensus_types::proof_of_store::BatchKind;
    use aptos_crypto::hash::HashValue;
    use aptos_types::{PeerId, transaction::SignedTransaction};
    
    #[test]
    fn test_v2_batches_survive_epoch_gc() {
        // Setup: Create a test database
        let db = Arc::new(QuorumStoreDB::new(tempfile::tempdir().unwrap().path()));
        
        // Create and persist a v2 batch in epoch 1
        let batch_info_v2 = BatchInfoExt::new_v2(
            PeerId::random(),
            BatchId::new_for_test(1),
            1, // epoch
            1000, // expiration
            HashValue::random(),
            10, // num_txns
            1000, // num_bytes
            0, // gas_bucket_start
            BatchKind::Normal,
        );
        let persisted_v2 = PersistedValue::new(batch_info_v2, Some(vec![]));
        db.save_batch_v2(persisted_v2.clone()).unwrap();
        
        // Verify batch is in database
        let all_v2_before = db.get_all_batches_v2().unwrap();
        assert_eq!(all_v2_before.len(), 1);
        
        // Trigger epoch GC (epoch 1 -> epoch 2)
        BatchStore::gc_previous_epoch_batches_from_db_v2(db.clone(), 2);
        
        // BUG: V2 batch should be deleted but still exists!
        let all_v2_after = db.get_all_batches_v2().unwrap();
        assert_eq!(all_v2_after.len(), 1, 
            "BUG CONFIRMED: V2 batch from epoch 1 survived GC during epoch 2 transition!");
        
        // V1 batches from same epoch (if any) would be correctly deleted
        let all_v1_after = db.get_all_batches().unwrap();
        assert_eq!(all_v1_after.len(), 0);
    }
}
```

## Notes

The vulnerability has two manifestation paths:
1. **Epoch-based GC** (primary bug): Occurs during epoch transitions when `gc_previous_epoch_batches_from_db_v2()` is called
2. **Time-based GC** (secondary issue): Time-based expiration via `update_certified_timestamp()` also fails to clean v2 batches from persistent storage

The `populate_cache_and_gc_expired_batches_v2()` function correctly uses `delete_batches_v2()`, but this only runs when `!is_new_epoch`, providing partial mitigation but not preventing the fundamental epoch-based accumulation. [7](#0-6)

### Citations

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

**File:** consensus/src/quorum_store/batch_store.rs (L292-336)
```rust
    fn populate_cache_and_gc_expired_batches_v2(
        db: Arc<dyn QuorumStoreStorage>,
        current_epoch: u64,
        last_certified_time: u64,
        expiration_buffer_usecs: u64,
        batch_store: &BatchStore,
    ) {
        let db_content = db
            .get_all_batches_v2()
            .expect("failed to read v1 data from db");
        info!(
            epoch = current_epoch,
            "QS: Read v1 batches from storage. Len: {}, Last Cerified Time: {}",
            db_content.len(),
            last_certified_time
        );

        let mut expired_keys = Vec::new();
        let gc_timestamp = last_certified_time.saturating_sub(expiration_buffer_usecs);
        for (digest, value) in db_content {
            let expiration = value.expiration();
            trace!(
                "QS: Batchreader recovery content exp {:?}, digest {}",
                expiration,
                digest
            );

            if expiration < gc_timestamp {
                expired_keys.push(digest);
            } else {
                batch_store
                    .insert_to_cache(&value)
                    .expect("Storage limit exceeded upon BatchReader construction");
            }
        }

        info!(
            "QS: Batch store bootstrap expired keys len {}",
            expired_keys.len()
        );
        tokio::task::spawn_blocking(move || {
            db.delete_batches_v2(expired_keys)
                .expect("Deletion of expired keys should not fail");
        });
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

**File:** consensus/src/quorum_store/schema.rs (L14-56)
```rust
pub(crate) const BATCH_CF_NAME: ColumnFamilyName = "batch";
pub(crate) const BATCH_ID_CF_NAME: ColumnFamilyName = "batch_ID";
pub(crate) const BATCH_V2_CF_NAME: ColumnFamilyName = "batch_v2";

#[derive(Debug)]
pub(crate) struct BatchSchema;

impl Schema for BatchSchema {
    type Key = HashValue;
    type Value = PersistedValue<BatchInfo>;

    const COLUMN_FAMILY_NAME: aptos_schemadb::ColumnFamilyName = BATCH_CF_NAME;
}

impl KeyCodec<BatchSchema> for HashValue {
    fn encode_key(&self) -> Result<Vec<u8>> {
        Ok(self.to_vec())
    }

    fn decode_key(data: &[u8]) -> Result<Self> {
        Ok(HashValue::from_slice(data)?)
    }
}

impl ValueCodec<BatchSchema> for PersistedValue<BatchInfo> {
    fn encode_value(&self) -> Result<Vec<u8>> {
        Ok(bcs::to_bytes(&self)?)
    }

    fn decode_value(data: &[u8]) -> Result<Self> {
        Ok(bcs::from_bytes(data)?)
    }
}

#[derive(Debug)]
pub(crate) struct BatchV2Schema;

impl Schema for BatchV2Schema {
    type Key = HashValue;
    type Value = PersistedValue<BatchInfoExt>;

    const COLUMN_FAMILY_NAME: aptos_schemadb::ColumnFamilyName = BATCH_V2_CF_NAME;
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

**File:** consensus/src/quorum_store/batch_generator.rs (L190-211)
```rust
        if self.config.enable_batch_v2 {
            // TODO(ibalajiarun): Specify accurate batch kind
            let batch_kind = BatchKind::Normal;
            Batch::new_v2(
                batch_id,
                txns,
                self.epoch,
                expiry_time,
                self.my_peer_id,
                bucket_start,
                batch_kind,
            )
        } else {
            Batch::new_v1(
                batch_id,
                txns,
                self.epoch,
                expiry_time,
                self.my_peer_id,
                bucket_start,
            )
        }
```

# Audit Report

## Title
V2 Batch Storage Leak: Unbounded Database Growth from Missing Schema-Specific Deletion

## Summary
The QuorumStore batch cleanup logic fails to distinguish between V1 and V2 batch schemas when performing deletions, causing all V2 batches to remain permanently in the database. This results in unbounded storage growth that can lead to validator node failures.

## Finding Description

The collision domains ARE properly separated - `BatchSchema` and `BatchV2Schema` use distinct column families (`"batch"` and `"batch_v2"` respectively), preventing key collisions at the storage layer. [1](#0-0) [2](#0-1) 

However, the cleanup implementation contains critical bugs that cause cross-schema deletion attempts:

**Bug #1 - Wrong Schema Deletion in Epoch GC:**
The `gc_previous_epoch_batches_from_db_v2` function reads V2 batches but attempts to delete them from the V1 schema: [3](#0-2) 

Line 214 reads from V2 schema, but line 241 calls `delete_batches()` which only deletes from V1 schema (`BatchSchema`). This should call `delete_batches_v2()`.

**Bug #2 - V2 Batches Never Deleted During Normal Operation:**
The `update_certified_timestamp` function, responsible for removing expired batches during consensus, only deletes from the V1 schema: [4](#0-3) 

The `expired_keys` come from a unified cache containing both V1 and V2 batches: [5](#0-4) 

But only `delete_batches()` is called, which targets `BatchSchema` only: [6](#0-5) 

V2 batches are never deleted because `delete_batches_v2()` is never invoked during normal expiration cleanup. It's only called once during initialization: [7](#0-6) 

**Root Cause:**
The system uses a unified in-memory cache for both versions but split database schemas. The deletion logic doesn't track which schema each digest belongs to, defaulting to V1 deletion only.

## Impact Explanation

**Severity: HIGH** (up to $50,000)

This vulnerability causes **validator node slowdowns** through unbounded storage growth, meeting the High severity criteria. Specifically:

1. **Storage Exhaustion**: V2 batches accumulate indefinitely in QuorumStoreDB, growing without bound
2. **Performance Degradation**: Large database sizes slow down RocksDB operations (reads, writes, compaction)
3. **Node Failures**: Eventually, disk space exhaustion can crash validator nodes
4. **Network Impact**: If multiple validators run V2, consensus could be disrupted when nodes fail

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

While not immediately catastrophic like consensus safety violations, the impact escalates over time and affects network availability when validators using V2 batches experience storage-related failures.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability triggers automatically whenever V2 batches are enabled: [8](#0-7) 

1. **No special attack needed**: Simply operating with `enable_batch_v2 = true` causes the leak
2. **Continuous accumulation**: Every V2 batch created persists forever
3. **No cleanup path**: There is no code path that correctly deletes V2 batches during normal operation
4. **Deterministic outcome**: Storage exhaustion is inevitable given enough time

The only reason this might not manifest immediately is if V2 batches haven't been widely deployed yet. However, once enabled, the leak is guaranteed.

## Recommendation

Fix both deletion bugs to ensure schema-specific cleanup:

**Fix for Bug #1** (line 241 in `batch_store.rs`):
```rust
fn gc_previous_epoch_batches_from_db_v2(db: Arc<dyn QuorumStoreStorage>, current_epoch: u64) {
    // ... existing code ...
    
    // CHANGE: Use delete_batches_v2 instead of delete_batches
    db.delete_batches_v2(expired_keys)  // Fixed!
        .expect("Deletion of expired keys should not fail");
}
```

**Fix for Bug #2** (line 530-539 in `batch_store.rs`):
```rust
pub fn update_certified_timestamp(&self, certified_time: u64) {
    trace!("QS: batch reader updating time {:?}", certified_time);
    self.last_certified_time
        .fetch_max(certified_time, Ordering::SeqCst);

    let expired_keys = self.clear_expired_payload(certified_time);
    
    // CHANGE: Separate V1 and V2 keys for schema-specific deletion
    let mut v1_keys = Vec::new();
    let mut v2_keys = Vec::new();
    
    for digest in expired_keys {
        // Check cache to determine schema version
        if let Some(value) = self.db_cache.get(&digest) {
            if value.batch_info().is_v2() {
                v2_keys.push(digest);
            } else {
                v1_keys.push(digest);
            }
        }
    }
    
    if let Err(e) = self.db.delete_batches(v1_keys) {
        debug!("Error deleting V1 batches: {:?}", e)
    }
    if let Err(e) = self.db.delete_batches_v2(v2_keys) {
        debug!("Error deleting V2 batches: {:?}", e)
    }
}
```

Alternatively, modify `clear_expired_payload` to return schema-tagged digests directly.

## Proof of Concept

```rust
// Rust test demonstrating V2 batch leak
#[tokio::test]
async fn test_v2_batch_storage_leak() {
    // Setup: Create QuorumStoreDB and BatchStore with V2 enabled
    let db = Arc::new(QuorumStoreDB::new(test_path));
    let config = QuorumStoreConfig {
        enable_batch_v2: true,
        ..Default::default()
    };
    
    let batch_store = BatchStore::new(
        epoch,
        true,
        0,
        db.clone(),
        memory_quota,
        db_quota,
        batch_quota,
        validator_signer,
        expiration_buffer,
    );
    
    // Create and persist V2 batch
    let batch_info = BatchInfoExt::new_v2(
        author,
        batch_id,
        epoch,
        expiration,
        digest,
        num_txns,
        num_bytes,
        gas_bucket_start,
        BatchKind::Normal,
    );
    
    let persisted_value = PersistedValue::new(batch_info, Some(payload));
    batch_store.persist(vec![persisted_value.clone()]);
    
    // Verify batch is in V2 schema
    let from_db = db.get_batch_v2(&digest).unwrap();
    assert!(from_db.is_some());
    
    // Simulate time passing and batch expiring
    let certified_time = expiration + 1;
    batch_store.update_certified_timestamp(certified_time);
    
    // BUG: V2 batch still exists in database!
    let still_there = db.get_batch_v2(&digest).unwrap();
    assert!(still_there.is_some(), "V2 batch was not deleted - LEAK CONFIRMED");
    
    // V1 schema correctly empty
    let v1_check = db.get_batch(&digest).unwrap();
    assert!(v1_check.is_none());
}
```

**Expected behavior**: After expiration, the V2 batch should be deleted from the database.

**Actual behavior**: The V2 batch remains in `batch_v2` column family indefinitely, causing storage leak.

### Citations

**File:** consensus/src/quorum_store/schema.rs (L14-26)
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
```

**File:** consensus/src/quorum_store/schema.rs (L48-56)
```rust
#[derive(Debug)]
pub(crate) struct BatchV2Schema;

impl Schema for BatchV2Schema {
    type Key = HashValue;
    type Value = PersistedValue<BatchInfoExt>;

    const COLUMN_FAMILY_NAME: aptos_schemadb::ColumnFamilyName = BATCH_V2_CF_NAME;
}
```

**File:** consensus/src/quorum_store/batch_store.rs (L113-119)
```rust
pub struct BatchStore {
    epoch: OnceCell<u64>,
    last_certified_time: AtomicU64,
    db_cache: DashMap<HashValue, PersistedValue<BatchInfoExt>>,
    peer_quota: DashMap<PeerId, QuotaManager>,
    expirations: Mutex<TimeExpirations<HashValue>>,
    db: Arc<dyn QuorumStoreStorage>,
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

**File:** consensus/src/quorum_store/batch_store.rs (L332-335)
```rust
        tokio::task::spawn_blocking(move || {
            db.delete_batches_v2(expired_keys)
                .expect("Deletion of expired keys should not fail");
        });
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

**File:** consensus/src/quorum_store/quorum_store_db.rs (L93-101)
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

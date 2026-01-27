# Audit Report

## Title
V2 Batches Not Deleted from Database During Expiration Leading to Unbounded Database Growth and State Inconsistency

## Summary
The quorum store batch expiration mechanism fails to delete V2 batches from persistent storage during normal operation. While V2 batches are correctly removed from the in-memory cache, they remain in the database indefinitely, causing unbounded database growth and state inconsistency between cache and persistent storage.

## Finding Description

The Aptos consensus quorum store manages transaction batches using two storage schemas: `BatchSchema` (V1) and `BatchV2Schema` (V2). The in-memory cache (`db_cache`) stores both V1 and V2 batches as `PersistedValue<BatchInfoExt>`. [1](#0-0) 

When batches are persisted to disk, the system correctly routes them based on version: [2](#0-1) 

However, the batch expiration mechanism in `update_certified_timestamp()` has a critical flaw: [3](#0-2) 

The `clear_expired_payload()` method removes **both V1 and V2** batches from the cache, but `delete_batches()` only deletes from `BatchSchema` (V1): [4](#0-3) 

V2 batches use a different schema and column family: [5](#0-4) 

Additionally, there is a similar bug in epoch-based garbage collection where `gc_previous_epoch_batches_from_db_v2()` reads V2 batches but attempts to delete them using the V1 method: [6](#0-5) 

**Attack Propagation:**
1. Validator node receives and processes transaction batches using V2 format
2. Batches are stored in both cache and `batch_v2` database column family
3. As time progresses, batches expire based on certified timestamp
4. `clear_expired_payload()` removes V2 batches from cache
5. `delete_batches()` is called, but only touches `batch` column family (V1)
6. V2 batches remain permanently in `batch_v2` column family
7. Database grows unbounded as more V2 batches accumulate
8. On node restart, expired V2 batches are reloaded into cache

This breaks the **State Consistency** invariant: state transitions between cache and persistent storage are not atomic, and the system maintains inconsistent views of what batches exist.

## Impact Explanation

**High Severity** - This vulnerability meets multiple criteria:

1. **Validator Node Slowdowns**: As the database grows with undeleted V2 batches, disk I/O operations slow down, impacting node performance and consensus participation.

2. **Significant Protocol Violations**: The quorum store protocol expects expired batches to be garbage collected. This bug violates that fundamental assumption, potentially causing different nodes to have different persistence states based on their restart history.

3. **Resource Exhaustion**: Unbounded database growth will eventually exhaust disk space on validator nodes, causing node failures and reducing network capacity.

4. **State Inconsistency**: The cache and database maintain different views of batch availability. On restart, expired batches reappear, potentially causing confusion in batch availability checks and consensus processing.

This qualifies as **High Severity** under Aptos bug bounty criteria: "Validator node slowdowns" and "Significant protocol violations."

## Likelihood Explanation

**Very High Likelihood**:

1. **Automatic Trigger**: The bug triggers automatically during normal consensus operation whenever V2 batches expire. No attacker action required.

2. **No Special Privileges**: Any transaction sender contributes to batch creation. The bug affects all V2 batches regardless of origin.

3. **Production Impact**: If V2 batches are enabled in production (based on `enable_batch_v2` flag), this bug affects all nodes immediately and continuously.

4. **Cumulative Effect**: The impact worsens over time as more V2 batches accumulate, making this a time-bomb that will eventually cause node failures.

## Recommendation

Fix the batch expiration mechanism to handle both V1 and V2 batches correctly:

**For `update_certified_timestamp()`**: Separate expired batches by version and call the appropriate deletion method:

```rust
pub fn update_certified_timestamp(&self, certified_time: u64) {
    trace!("QS: batch reader updating time {:?}", certified_time);
    self.last_certified_time
        .fetch_max(certified_time, Ordering::SeqCst);

    let expired_keys = self.clear_expired_payload(certified_time);
    
    // Separate V1 and V2 batches for proper deletion
    let mut v1_keys = Vec::new();
    let mut v2_keys = Vec::new();
    
    for key in expired_keys {
        // Check if batch is V2 by trying to read from V2 schema first
        if let Ok(Some(_)) = self.db.get_batch_v2(&key) {
            v2_keys.push(key);
        } else {
            v1_keys.push(key);
        }
    }
    
    if !v1_keys.is_empty() {
        if let Err(e) = self.db.delete_batches(v1_keys) {
            debug!("Error deleting V1 batches: {:?}", e)
        }
    }
    
    if !v2_keys.is_empty() {
        if let Err(e) = self.db.delete_batches_v2(v2_keys) {
            debug!("Error deleting V2 batches: {:?}", e)
        }
    }
}
```

**For `gc_previous_epoch_batches_from_db_v2()`**: Change the deletion call to use the correct V2 method:

```rust
fn gc_previous_epoch_batches_from_db_v2(db: Arc<dyn QuorumStoreStorage>, current_epoch: u64) {
    let db_content = db
        .get_all_batches_v2()
        .expect("failed to read data from db");
    
    let mut expired_keys = Vec::new();
    for (digest, value) in db_content {
        if value.epoch() < current_epoch {
            expired_keys.push(digest);
        }
    }
    
    // Fixed: Use delete_batches_v2 instead of delete_batches
    db.delete_batches_v2(expired_keys)
        .expect("Deletion of expired keys should not fail");
}
```

Additionally, consider tracking batch version in the cache to avoid the need for database lookups during expiration.

## Proof of Concept

```rust
// Test demonstrating the vulnerability
#[tokio::test]
async fn test_v2_batch_not_deleted_on_expiration() {
    use aptos_crypto::HashValue;
    use aptos_consensus_types::proof_of_store::BatchInfoExt;
    use crate::quorum_store::{
        quorum_store_db::{QuorumStoreDB, QuorumStoreStorage},
        types::PersistedValue,
    };
    use tempfile::TempDir;
    
    // Setup test database
    let tmpdir = TempDir::new().unwrap();
    let db = Arc::new(QuorumStoreDB::new(tmpdir.path()));
    
    // Create and persist a V2 batch
    let batch_info = BatchInfoExt::new_v2(
        /* author */ PeerId::random(),
        /* batch_id */ BatchId::new_for_test(1),
        /* epoch */ 1,
        /* expiration */ 100,
        /* digest */ HashValue::random(),
        /* num_txns */ 10,
        /* num_bytes */ 1000,
        /* gas_bucket_start */ 0,
        /* kind */ BatchKind::Normal,
    );
    
    let persisted = PersistedValue::new(batch_info.clone(), 100, 1000);
    let digest = *persisted.digest();
    
    // Save V2 batch to database
    db.save_batch_v2(persisted.clone()).unwrap();
    
    // Verify it exists in V2 schema
    assert!(db.get_batch_v2(&digest).unwrap().is_some());
    
    // Simulate expiration: call delete_batches (V1 method) as the bug does
    db.delete_batches(vec![digest]).unwrap();
    
    // BUG: V2 batch still exists in database because wrong method was called
    assert!(db.get_batch_v2(&digest).unwrap().is_some());
    println!("BUG CONFIRMED: V2 batch not deleted by delete_batches()");
    
    // Fix: Use delete_batches_v2
    db.delete_batches_v2(vec![digest]).unwrap();
    
    // Now it's properly deleted
    assert!(db.get_batch_v2(&digest).unwrap().is_none());
    println!("FIXED: V2 batch properly deleted by delete_batches_v2()");
}
```

This proof of concept demonstrates that calling `delete_batches()` on a V2 batch leaves it in the database, while `delete_batches_v2()` properly removes it.

## Notes

Regarding the specific question about "partial deletion failures within `delete_batches_v2()` itself": The function uses RocksDB's atomic WriteBatch mechanism, so partial deletions within a single call cannot occur. [7](#0-6) 

The underlying write uses RocksDB's atomic batch commit: [8](#0-7) 

However, the **system-level vulnerability** is that `delete_batches_v2()` is not being called at all in critical code paths, leading to V2 batches never being deleted from the database during normal expiration cycles. This creates an inconsistent state where batches exist in persistent storage but not in cache, violating the system's consistency guarantees.

### Citations

**File:** consensus/src/quorum_store/batch_store.rs (L116-116)
```rust
    db_cache: DashMap<HashValue, PersistedValue<BatchInfoExt>>,
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

**File:** consensus/src/quorum_store/batch_store.rs (L500-513)
```rust
                if needs_db {
                    if !batch_info.is_v2() {
                        let persist_request =
                            persist_request.try_into().expect("Must be a V1 batch");
                        #[allow(clippy::unwrap_in_result)]
                        self.db
                            .save_batch(persist_request)
                            .expect("Could not write to DB");
                    } else {
                        #[allow(clippy::unwrap_in_result)]
                        self.db
                            .save_batch_v2(persist_request)
                            .expect("Could not write to DB")
                    }
```

**File:** consensus/src/quorum_store/batch_store.rs (L530-538)
```rust
    pub fn update_certified_timestamp(&self, certified_time: u64) {
        trace!("QS: batch reader updating time {:?}", certified_time);
        self.last_certified_time
            .fetch_max(certified_time, Ordering::SeqCst);

        let expired_keys = self.clear_expired_payload(certified_time);
        if let Err(e) = self.db.delete_batches(expired_keys) {
            debug!("Error deleting batches: {:?}", e)
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

**File:** consensus/src/quorum_store/quorum_store_db.rs (L123-131)
```rust
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

**File:** storage/schemadb/src/lib.rs (L289-304)
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
```

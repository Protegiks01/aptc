# Audit Report

## Title
Incomplete V2 Batch Deletion During Schema Migration Leads to Validator Node Storage Exhaustion

## Summary
During the V1 to V2 quorum store batch schema migration, two critical bugs prevent proper deletion of V2 batches from persistent storage. The `gc_previous_epoch_batches_from_db_v2()` function incorrectly calls `delete_batches()` instead of `delete_batches_v2()`, and `update_certified_timestamp()` only deletes V1 batches while ignoring V2 batches. This causes unbounded accumulation of V2 batch data in the `batch_v2` column family, leading to disk space exhaustion and validator node degradation.

## Finding Description

The Aptos quorum store maintains two separate database schemas for batches with distinct column families: [1](#0-0) [2](#0-1) 

During migration from V1 to V2, controlled by the `enable_batch_v2` configuration flag, nodes begin creating V2 batches: [3](#0-2) [4](#0-3) 

**Bug #1 - Epoch Garbage Collection Failure:**

The `gc_previous_epoch_batches_from_db_v2()` function reads V2 batches from storage but incorrectly calls `delete_batches()` (which only deletes from V1 schema) instead of `delete_batches_v2()`: [5](#0-4) 

The function reads from V2 storage at line 214 using `get_all_batches_v2()`, identifies expired V2 batches, but then calls `delete_batches()` at line 241. The database layer confirms these methods target different column families: [6](#0-5) [7](#0-6) 

**Bug #2 - Expiration Cleanup Failure:**

The `update_certified_timestamp()` function only deletes expired batches from V1 storage, completely ignoring V2 batches: [8](#0-7) 

The `expired_keys` returned from `clear_expired_payload()` can contain both V1 and V2 batch digests since the cache stores `PersistedValue<BatchInfoExt>` which encompasses both types: [9](#0-8) 

The cache population confirms both V1 and V2 batches are stored together: [10](#0-9) [11](#0-10) 

When batches are persisted, the system correctly distinguishes between V1 and V2 using `is_v2()`: [12](#0-11) 

However, the deletion logic in `update_certified_timestamp()` fails to make this distinction, calling only `delete_batches()` for all expired keys.

**Exploitation Path:**

1. Validators initially run with `enable_batch_v2 = false`, creating V1 batches
2. Migration begins: `enable_batch_v2` is set to `true` 
3. New V2 batches are created and stored in "batch_v2" column family
4. When epochs change, `gc_previous_epoch_batches_from_db_v2()` attempts cleanup but fails (Bug #1)
5. During normal operation, expired V2 batches are removed from cache but not from disk (Bug #2)
6. Over time, the "batch_v2" column family grows unbounded
7. Disk space exhaustion eventually causes validator node failures

This breaks resource management invariants critical for validator operation.

## Impact Explanation

**HIGH Severity** per Aptos bug bounty criteria - "Validator node slowdowns" (up to $50,000):

1. **Progressive Storage Degradation**: V2 batches accumulate at a rate proportional to consensus throughput. With high transaction volumes, this could be hundreds of MB to GB per day per validator.

2. **Disk I/O Performance Impact**: As the database grows, RocksDB compaction overhead increases, slowing down all consensus operations that require storage access.

3. **Eventual Node Failure**: When disk space is exhausted, validators cannot persist new batches or blocks, causing consensus participation to halt. This affects network liveness.

4. **Network-Wide Impact**: Since all validators running V2 batches are affected, this could degrade the entire network's consensus performance simultaneously after migration.

The impact is not immediate but progressively worsens over time, making it particularly insidious as it may not be detected until significant damage has occurred.

## Likelihood Explanation

**Likelihood: VERY HIGH (Certain to occur)**

This vulnerability will trigger automatically during normal operation after V2 migration with zero attacker intervention required:

1. **No Attacker Action Needed**: The bugs trigger during standard epoch transitions and batch expiration cleanup.

2. **Affects All Validators**: Every validator node that enables V2 batches will experience this issue.

3. **Time-Based Certainty**: The longer the network runs with V2 batches enabled, the worse the storage bloat becomes. Given Aptos's high transaction throughput, this will manifest within days to weeks.

4. **No Privileges Required**: This is not an attack but a protocol-level bug affecting all participants equally.

## Recommendation

**Fix for Bug #1**: In `gc_previous_epoch_batches_from_db_v2()`, change line 241 to call `delete_batches_v2()`:

```rust
db.delete_batches_v2(expired_keys)  // Changed from delete_batches()
    .expect("Deletion of expired keys should not fail");
```

**Fix for Bug #2**: In `update_certified_timestamp()`, separate expired keys by batch version and call the appropriate deletion method:

```rust
let expired_keys = self.clear_expired_payload(certified_time);
let (v1_keys, v2_keys): (Vec<_>, Vec<_>) = expired_keys.into_iter()
    .partition(|digest| {
        // Check if batch is V1 or V2 based on which storage it exists in
        self.db.get_batch(digest).ok().flatten().is_some()
    });

if let Err(e) = self.db.delete_batches(v1_keys) {
    debug!("Error deleting V1 batches: {:?}", e)
}
if let Err(e) = self.db.delete_batches_v2(v2_keys) {
    debug!("Error deleting V2 batches: {:?}", e)
}
```

## Proof of Concept

The bugs are directly observable in the codebase without requiring a separate PoC:

1. Inspect `gc_previous_epoch_batches_from_db_v2()` at line 212-243 of `batch_store.rs` - it reads V2 but deletes V1
2. Inspect `update_certified_timestamp()` at line 530-539 of `batch_store.rs` - it only deletes V1 batches
3. Enable `enable_batch_v2 = true` in validator configuration
4. Run validator for multiple epochs with transaction processing
5. Monitor disk usage - the `batch_v2` column family will grow unbounded
6. Query the database directly to confirm V2 batches are accumulating without deletion

The logic errors are evident from code inspection and will manifest in any production environment that enables V2 batch migration.

## Notes

This vulnerability is particularly severe because it affects a critical migration path. When Aptos moves from V1 to V2 batch schema, all validators will be impacted simultaneously. The gradual nature of the storage exhaustion means it may not be detected immediately, allowing significant damage to accumulate before the issue is identified. This requires urgent remediation before any V2 migration is attempted in production.

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

**File:** config/src/config/quorum_store_config.rs (L102-103)
```rust
    pub enable_batch_v2: bool,
}
```

**File:** config/src/config/quorum_store_config.rs (L144-144)
```rust
            enable_batch_v2: false,
```

**File:** consensus/src/quorum_store/batch_store.rs (L113-126)
```rust
pub struct BatchStore {
    epoch: OnceCell<u64>,
    last_certified_time: AtomicU64,
    db_cache: DashMap<HashValue, PersistedValue<BatchInfoExt>>,
    peer_quota: DashMap<PeerId, QuotaManager>,
    expirations: Mutex<TimeExpirations<HashValue>>,
    db: Arc<dyn QuorumStoreStorage>,
    memory_quota: usize,
    db_quota: usize,
    batch_quota: usize,
    validator_signer: ValidatorSigner,
    persist_subscribers: DashMap<HashValue, Vec<oneshot::Sender<PersistedValue<BatchInfoExt>>>>,
    expiration_buffer_usecs: u64,
}
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

**File:** consensus/src/quorum_store/batch_store.rs (L245-290)
```rust
    fn populate_cache_and_gc_expired_batches_v1(
        db: Arc<dyn QuorumStoreStorage>,
        current_epoch: u64,
        last_certified_time: u64,
        expiration_buffer_usecs: u64,
        batch_store: &BatchStore,
    ) {
        let db_content = db
            .get_all_batches()
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
                    .insert_to_cache(&value.into())
                    .expect("Storage limit exceeded upon BatchReader construction");
            }
        }

        info!(
            "QS: Batch store bootstrap expired keys len {}",
            expired_keys.len()
        );
        tokio::task::spawn_blocking(move || {
            db.delete_batches(expired_keys)
                .expect("Deletion of expired keys should not fail");
        });
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

**File:** consensus/src/quorum_store/batch_store.rs (L488-528)
```rust
    fn persist_inner(
        &self,
        batch_info: BatchInfoExt,
        persist_request: PersistedValue<BatchInfoExt>,
    ) -> Option<SignedBatchInfo<BatchInfoExt>> {
        assert!(
            &batch_info == persist_request.batch_info(),
            "Provided batch info doesn't match persist request batch info"
        );
        match self.save(&persist_request) {
            Ok(needs_db) => {
                trace!("QS: sign digest {}", persist_request.digest());
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
                }
                if !batch_info.is_v2() {
                    self.generate_signed_batch_info(batch_info.info().clone())
                        .ok()
                        .map(|inner| inner.into())
                } else {
                    self.generate_signed_batch_info(batch_info).ok()
                }
            },
            Err(e) => {
                debug!("QS: failed to store to cache {:?}", e);
                None
            },
        }
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

# Audit Report

## Title
V2 Batch Garbage Collection Failure Due to Wrong Delete Method Call Causes Unbounded Storage Growth

## Summary
The `gc_previous_epoch_batches_from_db_v2()` function contains a critical bug where it reads V2 batches from the "batch_v2" column family but attempts to delete them using the V1 deletion method that targets the "batch" column family. This causes V2 batches from old epochs to never be cleaned up, resulting in unbounded storage growth that can exhaust disk space and cause validator node failures.

## Finding Description

The quorum store maintains two separate column families for batch storage: "batch" (V1) and "batch_v2" (V2), as defined in the schema. [1](#0-0) 

The `delete_batches()` function operates exclusively on the V1 "batch" column family using `BatchSchema`: [2](#0-1) 

In contrast, `delete_batches_v2()` correctly operates on the V2 "batch_v2" column family using `BatchV2Schema`: [3](#0-2) 

The critical bug exists in `gc_previous_epoch_batches_from_db_v2()`. This function reads V2 batches from the "batch_v2" column family using `get_all_batches_v2()` at line 214, but then incorrectly calls `delete_batches()` instead of `delete_batches_v2()` at line 241: [4](#0-3) 

The consequence is that the function attempts to delete V2 batch digests from the V1 "batch" column family where they don't exist. The underlying RocksDB delete operation is idempotent, so deleting a non-existent key is a silent no-op. The V2 batches remain in the "batch_v2" column family indefinitely.

To confirm this is a bug and not intended behavior, the parallel function `populate_cache_and_gc_expired_batches_v2()` correctly uses `delete_batches_v2()` for V2 batches: [5](#0-4) 

The garbage collection function is invoked at every epoch transition when `is_new_epoch` is true: [6](#0-5) 

V2 batches are actively created and persisted to the database when the `is_v2()` check returns true: [7](#0-6) 

The `BatchInfoExt` enum supports both V1 and V2 variants with the `is_v2()` method distinguishing between them: [8](#0-7) 

**Attack Path:**
1. An attacker sends a high volume of transactions to the network
2. The quorum store creates many V2 batches to handle these transactions
3. At each epoch transition, old V2 batches should be deleted but aren't due to the bug
4. Over many epochs, V2 batches accumulate in the "batch_v2" column family
5. Eventually, disk space is exhausted causing validator nodes to crash or become unable to sync
6. The attacker can accelerate this by maintaining sustained high transaction volume

**Broken Invariant:** The code violates the **State Consistency** invariant - the database state becomes inconsistent with the intended cleanup logic, with old batches persisting when they should be purged.

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty criteria for the following reasons:

1. **State Inconsistencies Requiring Intervention**: Old V2 batches accumulate indefinitely in the database, creating a divergence between intended state (clean database after GC) and actual state (growing collection of stale batches). Manual intervention is required to clean the database.

2. **Resource Exhaustion Leading to Availability Issues**: Over time, the accumulated batches will:
   - Consume increasing disk space until exhaustion
   - Degrade database performance due to larger data sets
   - Cause validator nodes to crash when disk space runs out
   - Prevent nodes from syncing if disk space is insufficient

3. **Exploitable by Unprivileged Attackers**: Any user can submit transactions to create batches, and by maintaining high transaction volume, can accelerate the accumulation of stale V2 batches.

Per the Aptos bug bounty Medium severity category: "State inconsistencies requiring manual intervention" - this issue clearly fits as the database state diverges from the intended state, requiring manual cleanup to resolve.

While this doesn't directly cause consensus safety violations or immediate fund loss, it creates a path to validator node unavailability through resource exhaustion.

## Likelihood Explanation

This issue has **HIGH likelihood** of occurrence:

1. **Guaranteed Trigger**: The bug triggers automatically at every epoch transition when V2 batches exist in the database
2. **Active Feature**: V2 batches are actively created when the `enable_batch_v2` configuration is enabled
3. **Cumulative Effect**: The impact compounds over time - each epoch adds more undeletable batches
4. **No Self-Healing**: There is no automatic mechanism to clean up the accumulated batches
5. **Attacker Acceleration**: An attacker can trivially increase the rate of batch creation by sending more transactions

The only variable is how long it takes to exhaust disk space, which depends on:
- Transaction volume (higher volume = faster accumulation)
- Disk capacity (smaller disks fill faster)  
- Epoch duration (more frequent epochs = more accumulated batches)

## Recommendation

Change line 241 in `consensus/src/quorum_store/batch_store.rs` from:
```rust
db.delete_batches(expired_keys)
```

To:
```rust
db.delete_batches_v2(expired_keys)
```

This ensures that V2 batches are deleted from the correct "batch_v2" column family, matching the pattern used in the `populate_cache_and_gc_expired_batches_v2()` function.

## Proof of Concept

While a full runtime PoC would require a test environment with epoch transitions and V2 batch creation enabled, the bug is evident from static code analysis:

1. The schema defines separate column families for V1 and V2 batches
2. The `gc_previous_epoch_batches_from_db_v2()` function reads from "batch_v2" but deletes from "batch"
3. The parallel function `populate_cache_and_gc_expired_batches_v2()` correctly uses `delete_batches_v2()`
4. This is clearly a copy-paste error where the V1 deletion method was not updated to V2

The bug can be confirmed by:
1. Enabling V2 batches in configuration
2. Running the node through multiple epoch transitions
3. Observing that V2 batches accumulate in the "batch_v2" column family without being deleted
4. Monitoring disk space consumption over time

## Notes

This vulnerability represents a clear logic bug in the garbage collection implementation where the wrong deletion method is called for V2 batches. The evidence is strong:

1. **Code pattern inconsistency**: The companion function `populate_cache_and_gc_expired_batches_v2()` correctly uses `delete_batches_v2()`, while `gc_previous_epoch_batches_from_db_v2()` incorrectly uses `delete_batches()`

2. **Type system violation**: Reading V2 batches (`get_all_batches_v2()`) but deleting through V1 method (`delete_batches()`) breaks the intended separation of the two storage schemas

3. **State consistency breach**: Old batches that should be purged remain in the database indefinitely, violating the intended cleanup invariant

The fix is trivial (one line change), but the impact is significant as it leads to unbounded storage growth that can eventually cause validator node failures.

### Citations

**File:** consensus/src/quorum_store/schema.rs (L14-16)
```rust
pub(crate) const BATCH_CF_NAME: ColumnFamilyName = "batch";
pub(crate) const BATCH_ID_CF_NAME: ColumnFamilyName = "batch_ID";
pub(crate) const BATCH_V2_CF_NAME: ColumnFamilyName = "batch_v2";
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

**File:** consensus/src/quorum_store/batch_store.rs (L501-513)
```rust
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

**File:** consensus/consensus-types/src/proof_of_store.rs (L195-265)
```rust
pub enum BatchInfoExt {
    V1 {
        info: BatchInfo,
    },
    V2 {
        info: BatchInfo,
        extra: ExtraBatchInfo,
    },
}

impl BatchInfoExt {
    pub fn new_v1(
        author: PeerId,
        batch_id: BatchId,
        epoch: u64,
        expiration: u64,
        digest: HashValue,
        num_txns: u64,
        num_bytes: u64,
        gas_bucket_start: u64,
    ) -> Self {
        Self::V1 {
            info: BatchInfo::new(
                author,
                batch_id,
                epoch,
                expiration,
                digest,
                num_txns,
                num_bytes,
                gas_bucket_start,
            ),
        }
    }

    pub fn new_v2(
        author: PeerId,
        batch_id: BatchId,
        epoch: u64,
        expiration: u64,
        digest: HashValue,
        num_txns: u64,
        num_bytes: u64,
        gas_bucket_start: u64,
        kind: BatchKind,
    ) -> Self {
        Self::V2 {
            info: BatchInfo::new(
                author,
                batch_id,
                epoch,
                expiration,
                digest,
                num_txns,
                num_bytes,
                gas_bucket_start,
            ),
            extra: ExtraBatchInfo { batch_kind: kind },
        }
    }

    pub fn info(&self) -> &BatchInfo {
        match self {
            BatchInfoExt::V1 { info } => info,
            BatchInfoExt::V2 { info, .. } => info,
        }
    }

    pub fn is_v2(&self) -> bool {
        matches!(self, Self::V2 { .. })
    }
```

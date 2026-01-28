# Audit Report

## Title
Database Resource Leak: V2 Batches Never Deleted from Disk in Quorum Store

## Summary
The quorum store batch cleanup mechanism fails to delete V2 batches from the database, causing unbounded disk growth on validators running with `enable_batch_v2: true`. Two critical code paths incorrectly use V1 deletion methods when cleaning up V2 batches.

## Finding Description

The Aptos quorum store maintains two separate database column families for batch storage:
- `"batch"` (V1 format) using `BatchSchema` [1](#0-0) 
- `"batch_v2"` (V2 format) using `BatchV2Schema` [2](#0-1) 

When `enable_batch_v2: true` is configured [3](#0-2) , batches are saved to the V2 column family via `save_batch_v2()` [4](#0-3) .

However, the cleanup mechanisms contain two critical bugs:

**Bug 1: Epoch Cleanup**

The function `gc_previous_epoch_batches_from_db_v2()` reads batches from the V2 column family [5](#0-4)  but attempts to delete them using the V1 deletion method [6](#0-5) . This is inconsistent with the V1 cleanup function which correctly reads and deletes from the same column family [7](#0-6) .

The correct V2 deletion method exists and is properly used elsewhere in the codebase [8](#0-7) .

**Bug 2: Expiration Cleanup**

The function `update_certified_timestamp()` cleans up expired batches from the cache and attempts to delete them from disk [9](#0-8) , but only calls the V1 deletion method regardless of batch version. The cache stores `PersistedValue<BatchInfoExt>` [10](#0-9)  which can contain both V1 and V2 batches [11](#0-10) .

The database operations clearly distinguish between V1 and V2:
- `delete_batches()` deletes from `BatchSchema` (V1) [12](#0-11) 
- `delete_batches_v2()` deletes from `BatchV2Schema` (V2) [13](#0-12) 

## Impact Explanation

**Severity: Medium** (per Aptos bug bounty criteria: "State inconsistencies requiring manual intervention")

**Impact:**
- Unbounded database growth on validators with `enable_batch_v2: true`
- Progressive disk space exhaustion over time
- Eventually causes validator node failure when disk is full
- Requires manual intervention (database cleanup or node replacement)
- Does not immediately affect consensus safety but degrades network health over time

This breaks the resource limits invariant. The database grows without bound, violating storage limits and eventually causing validator failure.

**Affected Nodes:**
- Any validator running with `enable_batch_v2: true` in their quorum store configuration
- Default configuration has this flag set to `false` [14](#0-13) , limiting immediate impact

## Likelihood Explanation

**Likelihood: High** (for nodes with `enable_batch_v2: true`)

The vulnerability triggers automatically without attacker intervention:
1. Validator sets `enable_batch_v2: true` in configuration
2. Batches are created and saved via the V2 path during normal operation
3. When batches expire or epochs change, cleanup functions execute [15](#0-14) 
4. V2 batches remain in database indefinitely due to the bugs
5. Database grows continuously during consensus operation

The vulnerability requires no special privileges - just a configuration change that may be deployed during protocol upgrades when the V2 format becomes standard.

## Recommendation

Fix both cleanup paths to use the correct deletion method based on batch version:

**Bug 1 Fix:** In `gc_previous_epoch_batches_from_db_v2()`, change line 241 from:
```rust
db.delete_batches(expired_keys)
```
to:
```rust
db.delete_batches_v2(expired_keys)
```

**Bug 2 Fix:** In `update_certified_timestamp()`, check batch version before deletion. Replace the single deletion call with logic that separates V1 and V2 batches from the expired keys and calls the appropriate deletion method for each type.

## Proof of Concept

The bug can be demonstrated by:
1. Configuring a validator node with `enable_batch_v2: true`
2. Running the validator for multiple epochs
3. Monitoring the database size of the `batch_v2` column family
4. Observing that batches from previous epochs are never deleted despite cleanup functions executing

The code evidence clearly shows the mismatch between read and delete operations, making this vulnerability exploitable through normal consensus operation without requiring a malicious actor.

## Notes

This is a logic vulnerability in the resource cleanup mechanism. The bug is evident from code inspection: V2 batches are written to the `batch_v2` column family but cleanup attempts to delete them from the `batch` column family, causing them to persist indefinitely. The correct V2 deletion method exists in the codebase but is not consistently used across all cleanup paths.

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

**File:** consensus/src/quorum_store/schema.rs (L49-56)
```rust
pub(crate) struct BatchV2Schema;

impl Schema for BatchV2Schema {
    type Key = HashValue;
    type Value = PersistedValue<BatchInfoExt>;

    const COLUMN_FAMILY_NAME: aptos_schemadb::ColumnFamilyName = BATCH_V2_CF_NAME;
}
```

**File:** config/src/config/quorum_store_config.rs (L102-102)
```rust
    pub enable_batch_v2: bool,
```

**File:** config/src/config/quorum_store_config.rs (L144-144)
```rust
            enable_batch_v2: false,
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

**File:** consensus/src/quorum_store/quorum_store_db.rs (L140-147)
```rust
    fn save_batch_v2(&self, batch: PersistedValue<BatchInfoExt>) -> Result<(), DbError> {
        trace!(
            "QS: db persists digest {} expiration {:?}",
            batch.digest(),
            batch.expiration()
        );
        self.put::<BatchV2Schema>(batch.digest(), &batch)
    }
```

**File:** consensus/src/quorum_store/batch_store.rs (L116-116)
```rust
    db_cache: DashMap<HashValue, PersistedValue<BatchInfoExt>>,
```

**File:** consensus/src/quorum_store/batch_store.rs (L156-160)
```rust
        if is_new_epoch {
            tokio::task::spawn_blocking(move || {
                Self::gc_previous_epoch_batches_from_db_v1(db_clone.clone(), epoch);
                Self::gc_previous_epoch_batches_from_db_v2(db_clone, epoch);
            });
```

**File:** consensus/src/quorum_store/batch_store.rs (L182-209)
```rust
        let db_content = db.get_all_batches().expect("failed to read data from db");
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
```

**File:** consensus/src/quorum_store/batch_store.rs (L213-215)
```rust
        let db_content = db
            .get_all_batches_v2()
            .expect("failed to read data from db");
```

**File:** consensus/src/quorum_store/batch_store.rs (L241-242)
```rust
        db.delete_batches(expired_keys)
            .expect("Deletion of expired keys should not fail");
```

**File:** consensus/src/quorum_store/batch_store.rs (L332-335)
```rust
        tokio::task::spawn_blocking(move || {
            db.delete_batches_v2(expired_keys)
                .expect("Deletion of expired keys should not fail");
        });
```

**File:** consensus/src/quorum_store/batch_store.rs (L535-538)
```rust
        let expired_keys = self.clear_expired_payload(certified_time);
        if let Err(e) = self.db.delete_batches(expired_keys) {
            debug!("Error deleting batches: {:?}", e)
        }
```

**File:** consensus/consensus-types/src/proof_of_store.rs (L263-265)
```rust
    pub fn is_v2(&self) -> bool {
        matches!(self, Self::V2 { .. })
    }
```

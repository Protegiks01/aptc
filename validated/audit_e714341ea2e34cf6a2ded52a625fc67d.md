# Audit Report

## Title
V2 Batch Schema Data Leak: Unbounded Database Growth Due to Missing V2 Batch Deletion Logic

## Summary
The quorum store batch deletion logic contains two critical bugs that prevent V2 batches from being deleted from the database. When the `enable_batch_v2` configuration flag is enabled, V2 batches accumulate indefinitely in the database, leading to unbounded storage growth, disk exhaustion, and eventual validator node failure.

## Finding Description

The Aptos consensus quorum store maintains batches in two separate database column families: `BATCH_CF_NAME` ("batch") for V1 batches and `BATCH_V2_CF_NAME` ("batch_v2") for V2 batches. [1](#0-0) 

When V2 batches are enabled via the `enable_batch_v2` configuration flag [2](#0-1) , new batches are created as V2 format and stored using the `save_batch_v2()` method which persists to the V2 column family. [3](#0-2) 

However, the deletion logic contains two critical bugs:

**Bug #1**: In the `gc_previous_epoch_batches_from_db_v2()` function, after reading V2 batches from the database via `get_all_batches_v2()`, the code incorrectly calls `db.delete_batches(expired_keys)` instead of `db.delete_batches_v2(expired_keys)`. [4](#0-3)  This attempts to delete V2 batches from the V1 column family, leaving V2 batches in the database.

The `delete_batches()` method only operates on `BatchSchema` (V1), not `BatchV2Schema` (V2). [5](#0-4)  The correct method `delete_batches_v2()` exists and operates on `BatchV2Schema`. [6](#0-5) 

For comparison, the function `populate_cache_and_gc_expired_batches_v2()` correctly uses `delete_batches_v2()` for V2 batch deletion. [7](#0-6) 

**Bug #2**: In the `update_certified_timestamp()` function, which handles deletion of expired batches during normal operation, the code only calls `db.delete_batches(expired_keys)`. [8](#0-7)  

The `clear_expired_payload()` method removes expired entries from the in-memory cache (`db_cache`) which stores both V1 and V2 batches as `PersistedValue<BatchInfoExt>`. [9](#0-8) [10](#0-9)  However, the subsequent deletion only affects the V1 column family, leaving V2 batches permanently in the database.

**Exploitation Path:**
1. Validator operator enables `enable_batch_v2` configuration flag (defaults to false but intended for deployment) [11](#0-10) 
2. New batches are created as V2 and persisted to the `BATCH_V2_CF_NAME` column family
3. V2 batches are cached in memory and participate in consensus
4. When batches expire (due to time progression or epoch change), they are removed from the in-memory cache
5. The deletion attempts only affect the V1 column family - V2 batches persist permanently in the database
6. Over time, the database grows unboundedly with expired V2 batches
7. Disk space exhaustion occurs, causing node crashes
8. If multiple validators enable this feature, network liveness is affected

## Impact Explanation

**Severity: Critical** - This vulnerability could qualify for Critical severity under the Aptos Bug Bounty program category "Total loss of liveness/network availability" if deployed network-wide. At minimum, it represents High severity as "Validator Node Slowdowns" leading to crashes.

**Impact Details:**
- **Disk Exhaustion**: V2 batches accumulate indefinitely, consuming all available disk space on validator nodes
- **Node Crashes**: When disk space is exhausted, database operations fail, causing validator nodes to crash
- **Network Risk**: If multiple validators enable V2 batches simultaneously (as would happen in a coordinated feature rollout), multiple nodes could crash, potentially affecting network liveness
- **Operational Impact**: Emergency interventions require manual database cleanup or disabling the feature

The vulnerability affects all validator nodes that enable the V2 batch feature. The severity depends on deployment scope - individual validator failures (High) versus coordinated network-wide deployment (Critical).

## Likelihood Explanation

**Likelihood: High to Certain**

This bug will manifest with certainty once the `enable_batch_v2` configuration flag is enabled. The conditions are:
1. The configuration flag is enabled (operational requirement for V2 feature deployment)
2. Sufficient time passes for batches to expire and accumulate (days to weeks depending on transaction volume)
3. No manual intervention occurs to clean the database

The vulnerability requires no attacker action - it is an automatic consequence of normal system operation with the V2 batch feature enabled. The bugs are deterministic: the wrong deletion methods are called, and V2 batches will never be deleted from persistent storage.

## Recommendation

**Fix for Bug #1**: In `gc_previous_epoch_batches_from_db_v2()`, change line 241 to call the correct deletion method:
```rust
db.delete_batches_v2(expired_keys)  // Instead of delete_batches()
```

**Fix for Bug #2**: In `update_certified_timestamp()`, the function needs to track which batches are V1 vs V2 and call the appropriate deletion methods. The `clear_expired_payload()` method should return information about batch versions, or separate deletion calls should be made for each schema:
```rust
let expired_keys = self.clear_expired_payload(certified_time);
// Separate V1 and V2 keys, or track version info
// Then call both:
if let Err(e) = self.db.delete_batches(expired_v1_keys) {
    debug!("Error deleting V1 batches: {:?}", e)
}
if let Err(e) = self.db.delete_batches_v2(expired_v2_keys) {
    debug!("Error deleting V2 batches: {:?}", e)
}
```

Alternatively, the system could track batch versions in the expiration data structure to enable proper deletion routing.

## Proof of Concept

The bugs are evident from code inspection. A PoC would involve:
1. Enabling `enable_batch_v2` in the configuration
2. Running a validator node with transaction processing
3. Monitoring the database size over time
4. Observing that V2 batches accumulate in the `batch_v2` column family
5. Verifying that expired V2 batches remain in the database despite being removed from the in-memory cache

The deterministic nature of these bugs (wrong method calls in the deletion logic) means they will manifest whenever the V2 feature is enabled.

## Notes

This vulnerability demonstrates a schema migration issue where the deletion logic was not properly updated to handle both V1 and V2 batch formats. The existence of `delete_batches_v2()` and its correct usage in `populate_cache_and_gc_expired_batches_v2()` confirms that the infrastructure for proper V2 deletion exists but is not being called in the critical deletion paths.

The impact severity depends heavily on deployment context. If this feature is enabled individually by validators, it represents a High severity operational issue. If enabled network-wide as part of a coordinated upgrade (which is the typical deployment pattern for feature flags), it could escalate to Critical severity due to potential network liveness impact.

### Citations

**File:** consensus/src/quorum_store/schema.rs (L14-16)
```rust
pub(crate) const BATCH_CF_NAME: ColumnFamilyName = "batch";
pub(crate) const BATCH_ID_CF_NAME: ColumnFamilyName = "batch_ID";
pub(crate) const BATCH_V2_CF_NAME: ColumnFamilyName = "batch_v2";
```

**File:** config/src/config/quorum_store_config.rs (L102-102)
```rust
    pub enable_batch_v2: bool,
```

**File:** config/src/config/quorum_store_config.rs (L144-144)
```rust
            enable_batch_v2: false,
```

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

**File:** consensus/src/quorum_store/batch_store.rs (L332-335)
```rust
        tokio::task::spawn_blocking(move || {
            db.delete_batches_v2(expired_keys)
                .expect("Deletion of expired keys should not fail");
        });
```

**File:** consensus/src/quorum_store/batch_store.rs (L443-472)
```rust
    pub(crate) fn clear_expired_payload(&self, certified_time: u64) -> Vec<HashValue> {
        // To help slow nodes catch up via execution without going to state sync we keep the blocks for 60 extra seconds
        // after the expiration time. This will help remote peers fetch batches that just expired but are within their
        // execution window.
        let expiration_time = certified_time.saturating_sub(self.expiration_buffer_usecs);
        let expired_digests = self.expirations.lock().expire(expiration_time);
        let mut ret = Vec::new();
        for h in expired_digests {
            let removed_value = match self.db_cache.entry(h) {
                Occupied(entry) => {
                    // We need to check up-to-date expiration again because receiving the same
                    // digest with a higher expiration would update the persisted value and
                    // effectively extend the expiration.
                    if entry.get().expiration() <= expiration_time {
                        self.persist_subscribers.remove(entry.get().digest());
                        Some(entry.remove())
                    } else {
                        None
                    }
                },
                Vacant(_) => unreachable!("Expired entry not in cache"),
            };
            // No longer holding the lock on db_cache entry.
            if let Some(value) = removed_value {
                self.free_quota(value);
                ret.push(h);
            }
        }
        ret
    }
```

**File:** consensus/src/quorum_store/batch_store.rs (L508-513)
```rust
                    } else {
                        #[allow(clippy::unwrap_in_result)]
                        self.db
                            .save_batch_v2(persist_request)
                            .expect("Could not write to DB")
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

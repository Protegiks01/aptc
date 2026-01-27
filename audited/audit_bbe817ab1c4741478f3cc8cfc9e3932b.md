# Audit Report

## Title
V2 Batch Schema Data Leak: Unbounded Database Growth Due to Missing V2 Batch Deletion Logic

## Summary
The quorum store batch deletion logic contains two critical bugs that prevent V2 batches from being deleted from the database. When the `enable_batch_v2` configuration flag is enabled, V2 batches accumulate indefinitely in the database, leading to unbounded storage growth, disk exhaustion, and eventual validator node failure causing total network liveness loss.

## Finding Description

The Aptos consensus quorum store maintains batches in two separate database column families: `BATCH_CF_NAME` for V1 batches and `BATCH_V2_CF_NAME` for V2 batches. [1](#0-0) 

When V2 batches are enabled via the `enable_batch_v2` configuration flag, new batches are created as `BatchInfoExt::V2` and stored in the V2 column family. [2](#0-1) 

However, the deletion logic contains two critical bugs:

**Bug #1**: In the `gc_previous_epoch_batches_from_db_v2()` function, after reading and identifying expired V2 batches from previous epochs, the code incorrectly calls `db.delete_batches(expired_keys)` instead of `db.delete_batches_v2(expired_keys)`. [3](#0-2) 

This attempts to delete V2 batches from the V1 column family instead of the V2 column family, so the V2 batches remain in the database.

**Bug #2**: In the `update_certified_timestamp()` function, which handles deletion of expired batches during normal operation, the code only calls `db.delete_batches(expired_keys)` which exclusively deletes from the V1 schema. [4](#0-3) 

The `clear_expired_payload()` method returns digests for both V1 and V2 batches that have expired from the in-memory cache, but the deletion only affects V1 batches. [5](#0-4) 

**Exploitation Path:**
1. Validator operator enables `enable_batch_v2` configuration flag
2. New batches are created as V2 and persisted to the `BATCH_V2_CF_NAME` column family
3. V2 batches are cached in memory and participate in consensus
4. When batches expire (due to time progression or epoch change), they are removed from the in-memory cache
5. The deletion attempts only affect the V1 column family - V2 batches persist permanently in the database
6. Over time, the database grows unboundedly with expired V2 batches
7. Disk space exhaustion occurs, causing node crashes
8. Network loses validators, leading to liveness failures

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The system fails to enforce storage limits on the persistent database layer.

## Impact Explanation

**Severity: Critical** - This vulnerability qualifies for Critical severity under the Aptos Bug Bounty program category: "Total loss of liveness/network availability."

**Impact Details:**
- **Disk Exhaustion**: V2 batches accumulate indefinitely, consuming all available disk space on validator nodes
- **Node Crashes**: When disk space is exhausted, the validator node database operations fail, causing the node to crash
- **Network Partition**: If multiple validators enable V2 batches simultaneously, multiple nodes will crash, potentially causing a non-recoverable network partition
- **Data Integrity Risk**: Emergency interventions to recover disk space may require manual database manipulation, risking data corruption
- **Consensus Safety**: Loss of sufficient validators can break consensus quorum requirements

The vulnerability affects all validator nodes that enable the V2 batch feature, making it a systemic risk rather than an isolated node issue.

## Likelihood Explanation

**Likelihood: High to Certain**

This bug will manifest with certainty once the following conditions are met:
1. The `enable_batch_v2` configuration flag is enabled (operational requirement for V2 feature deployment)
2. Sufficient time passes for batches to expire and accumulate (days to weeks depending on transaction volume)
3. No manual intervention occurs to clean the database

The vulnerability requires no attacker action - it is an automatic consequence of normal system operation under V2 batch mode. The likelihood increases as the Aptos network moves toward adopting V2 batches as the standard format.

**Time to Exploitation:**
- With typical validator transaction throughput, disk exhaustion could occur within weeks to months
- High-volume validators may experience issues sooner
- The problem compounds over time as more batches accumulate

## Recommendation

**Fix for Bug #1** - Correct the deletion method in `gc_previous_epoch_batches_from_db_v2`:

Change line 241 in `consensus/src/quorum_store/batch_store.rs` from:
```rust
db.delete_batches(expired_keys)
```
to:
```rust
db.delete_batches_v2(expired_keys)
```

**Fix for Bug #2** - Handle both V1 and V2 batch deletion in `update_certified_timestamp`:

The `clear_expired_payload()` method should be modified to track which version each expired batch belongs to, then call the appropriate deletion method. Alternatively, modify the deletion logic to:

```rust
pub fn update_certified_timestamp(&self, certified_time: u64) {
    trace!("QS: batch reader updating time {:?}", certified_time);
    self.last_certified_time
        .fetch_max(certified_time, Ordering::SeqCst);

    let expired_keys = self.clear_expired_payload(certified_time);
    
    // Separate V1 and V2 batches based on what's in cache before deletion
    let mut v1_keys = Vec::new();
    let mut v2_keys = Vec::new();
    
    for key in expired_keys {
        // Check if we need to delete from V1 or V2 schema
        // Since batch may already be removed from cache, we need to try both
        v1_keys.push(key);
        v2_keys.push(key);
    }
    
    // Delete from both schemas (harmless if key doesn't exist)
    if let Err(e) = self.db.delete_batches(v1_keys) {
        debug!("Error deleting V1 batches: {:?}", e)
    }
    if let Err(e) = self.db.delete_batches_v2(v2_keys) {
        debug!("Error deleting V2 batches: {:?}", e)
    }
}
```

**Better approach**: Modify `clear_expired_payload` to return version information alongside digests, enabling precise deletion.

**Immediate Mitigation**: 
- Add monitoring for database size on validator nodes
- Implement alerts for unexpected database growth
- Create manual cleanup scripts for V2 batches as a temporary workaround

## Proof of Concept

```rust
#[cfg(test)]
mod v2_batch_deletion_bug_test {
    use super::*;
    use aptos_consensus_types::proof_of_store::BatchKind;
    use aptos_temppath::TempPath;
    use aptos_types::validator_signer::ValidatorSigner;
    
    #[tokio::test]
    async fn test_v2_batches_not_deleted() {
        // Create a temporary database
        let tmp_dir = TempPath::new();
        let db = Arc::new(QuorumStoreDB::new(tmp_dir.path()));
        
        // Create a V2 batch
        let validator_signer = ValidatorSigner::random([0u8; 32]);
        let batch_info_v2 = BatchInfoExt::new_v2(
            validator_signer.author(),
            BatchId::new_for_test(1),
            1, // epoch
            1000, // expiration in the past
            HashValue::random(),
            10, // num_txns
            1024, // num_bytes
            0, // gas_bucket_start
            BatchKind::Normal,
        );
        
        // Persist the V2 batch
        let persisted_v2 = PersistedValue::new(batch_info_v2.clone(), None);
        db.save_batch_v2(persisted_v2).unwrap();
        
        // Verify it exists in V2 schema
        let retrieved = db.get_batch_v2(batch_info_v2.digest()).unwrap();
        assert!(retrieved.is_some());
        
        // Create batch store and trigger garbage collection for new epoch
        let batch_store = BatchStore::new(
            2, // new epoch
            true, // is_new_epoch
            2000, // current time (after batch expiration)
            db.clone(),
            1024 * 1024, // memory_quota
            10 * 1024 * 1024, // db_quota
            1000, // batch_quota
            validator_signer,
            60_000_000, // expiration_buffer_usecs
        );
        
        // Wait for gc to complete
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // BUG: The V2 batch should be deleted but it's still there
        // because gc_previous_epoch_batches_from_db_v2 calls delete_batches
        // instead of delete_batches_v2
        let still_exists = db.get_batch_v2(batch_info_v2.digest()).unwrap();
        assert!(still_exists.is_some(), "BUG: V2 batch was not deleted!");
        
        // Now test the second bug: update_certified_timestamp only deletes V1 batches
        let batch_info_v2_new = BatchInfoExt::new_v2(
            validator_signer.author(),
            BatchId::new_for_test(2),
            2, // current epoch
            3000, // expiration
            HashValue::random(),
            10,
            1024,
            0,
            BatchKind::Normal,
        );
        
        let persisted_v2_new = PersistedValue::new(batch_info_v2_new.clone(), Some(vec![]));
        batch_store.save(&persisted_v2_new).unwrap();
        
        // Advance time past expiration
        batch_store.update_certified_timestamp(4000);
        
        // BUG: V2 batch should be deleted but still exists
        let still_exists_2 = db.get_batch_v2(batch_info_v2_new.digest()).unwrap();
        assert!(still_exists_2.is_some(), "BUG: Expired V2 batch was not deleted!");
    }
}
```

**Notes:**
- The original security question asked about data becoming "inaccessible" during V1 to V2 migration. The actual vulnerability is the inverse: V2 data becomes impossible to remove, not impossible to access.
- V1 batches remain accessible when V2 is deployed since both schemas coexist. The code reads from both. [6](#0-5) 
- V1 batches are correctly converted to V2 format in memory via the `From` trait implementation. [7](#0-6) 
- The vulnerability is more severe than simple data loss - it's a resource exhaustion DoS that affects network availability.

### Citations

**File:** consensus/src/quorum_store/schema.rs (L14-16)
```rust
pub(crate) const BATCH_CF_NAME: ColumnFamilyName = "batch";
pub(crate) const BATCH_ID_CF_NAME: ColumnFamilyName = "batch_ID";
pub(crate) const BATCH_V2_CF_NAME: ColumnFamilyName = "batch_v2";
```

**File:** consensus/src/quorum_store/batch_store.rs (L156-176)
```rust
        if is_new_epoch {
            tokio::task::spawn_blocking(move || {
                Self::gc_previous_epoch_batches_from_db_v1(db_clone.clone(), epoch);
                Self::gc_previous_epoch_batches_from_db_v2(db_clone, epoch);
            });
        } else {
            Self::populate_cache_and_gc_expired_batches_v1(
                db_clone.clone(),
                epoch,
                last_certified_time,
                expiration_buffer_usecs,
                &batch_store,
            );
            Self::populate_cache_and_gc_expired_batches_v2(
                db_clone,
                epoch,
                last_certified_time,
                expiration_buffer_usecs,
                &batch_store,
            );
        }
```

**File:** consensus/src/quorum_store/batch_store.rs (L237-242)
```rust
        info!(
            "QS: Batch store bootstrap expired keys len {}",
            expired_keys.len()
        );
        db.delete_batches(expired_keys)
            .expect("Deletion of expired keys should not fail");
```

**File:** consensus/src/quorum_store/batch_store.rs (L443-471)
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

**File:** consensus/src/quorum_store/types.rs (L112-117)
```rust
impl From<PersistedValue<BatchInfo>> for PersistedValue<BatchInfoExt> {
    fn from(value: PersistedValue<BatchInfo>) -> Self {
        let (batch_info, payload) = value.unpack();
        PersistedValue::new(batch_info.into(), payload)
    }
}
```

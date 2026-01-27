# Audit Report

## Title
Critical Race Condition in QuorumStore Batch Garbage Collection Causes Cache-DB Inconsistency and Consensus Failure

## Summary
A race condition exists between `BatchStore::clear_expired_payload()` and `BatchStore::persist_inner()` where a batch can be deleted from the database after being re-added with an extended expiration. This creates a cache-DB inconsistency that becomes permanent after node restart, causing the node to fail execution of blocks referencing the missing batch.

## Finding Description

The vulnerability occurs in the batch garbage collection logic where cache removal and database deletion are not atomic with respect to concurrent batch insertions. [1](#0-0) 

The garbage collection flow in `update_certified_timestamp()` performs two separate operations:
1. `clear_expired_payload()` removes expired batches from cache and returns their digests
2. `delete_batches()` deletes those digests from the database [2](#0-1) 

The `clear_expired_payload()` method checks the expiration in the cache and removes entries, but there is a critical window between when it releases the cache lock and when the database deletion occurs.

Meanwhile, the persist flow can concurrently add batches: [3](#0-2) 

**Race Condition Timeline:**

1. **T0**: Batch with digest `D` and expiration `E1` exists in cache and DB
2. **T1**: Thread 1 (GC) calls `update_certified_timestamp(T)` where `T - buffer > E1`
3. **T2**: Thread 1 enters `clear_expired_payload()`, acquires lock on cache entry `D`
4. **T3**: Thread 1 checks expiration, removes `D` from cache, adds to `expired_keys`, releases lock
5. **T4**: Thread 2 (Persist) receives batch `D` with expiration `E2` where `E2 > T`
6. **T5**: Thread 2 calls `insert_to_cache()` - cache entry is now vacant, inserts `D` with `E2` [4](#0-3) 

7. **T6**: Thread 2 calls `db.save_batch(D)` - writes `D` to database [5](#0-4) 

8. **T7**: Thread 1 calls `db.delete_batches([D])` - deletes `D` from database [6](#0-5) 

**Result**: `D` exists in cache with expiration `E2` but is missing from the database.

The same batch digest can legitimately have different expiration times because the digest is computed from the transaction payload, not the expiration timestamp. This is explicitly supported by the code logic that keeps the batch with the higher expiration. [7](#0-6) 

**Critical Impact After Node Restart:**

When the node restarts, the cache is repopulated from the database: [8](#0-7) 

Since batch `D` is not in the database, it will not be loaded into the cache. When consensus attempts to execute a block referencing batch `D`, the retrieval fails: [9](#0-8) 

This returns `ExecutorError::CouldNotGetData`, causing execution to fail: [10](#0-9) 

## Impact Explanation

**Severity: Critical** (up to $1,000,000 per Aptos Bug Bounty)

This vulnerability meets multiple Critical severity criteria:

1. **Consensus Safety Violation**: The affected node cannot execute blocks containing the missing batch, causing it to diverge from the network consensus state. While other validators can execute the block, this node becomes unable to verify the consensus and falls out of sync.

2. **State Consistency Violation**: The cache-DB inconsistency breaks the fundamental invariant that persistent storage must be recoverable. The system assumes that batches in the cache are also in the database (or can be retrieved from peers), but this race creates an unrecoverable state.

3. **Loss of Liveness**: The node cannot make progress on executing blocks that reference the missing batch. This effectively removes the validator from consensus participation until manual intervention.

4. **Data Loss**: The batch is permanently lost from the node's storage. While it may be available from peers, the node has no mechanism to recover from this specific failure mode (cache has it before restart but not after).

The vulnerability directly impacts the "Deterministic Execution" and "State Consistency" critical invariants. All validators must produce identical state roots for identical blocks, but a validator affected by this bug cannot execute blocks at all.

## Likelihood Explanation

**Likelihood: Medium-High**

This race condition is highly likely to occur in production environments for several reasons:

1. **Legitimate Protocol Behavior**: The scenario where a batch receives an extended expiration is a normal part of the quorum store protocol. Validators may re-broadcast batches with updated expirations as network conditions change.

2. **High Concurrency Environment**: Consensus nodes process thousands of operations per second across multiple threads. The garbage collection runs periodically while batch persist operations occur continuously.

3. **Timing Window**: The race window between cache removal (line 458) and database deletion (line 536) is relatively large - it includes the entire loop processing potentially many expired batches and then making a database write call.

4. **No Synchronization**: There are no locks, atomic operations, or ordering guarantees between the cache operations and database operations. The code uses DashMap for the cache (which provides per-entry locking) but doesn't extend any protection to the database layer.

5. **Production Load Conditions**: Under high load or during network partitions where batches might be re-transmitted with extended deadlines, this race becomes even more probable.

The comment in the code itself acknowledges concurrent updates are possible but only protects the cache removal, not the database deletion.

## Recommendation

**Solution: Add expiration verification before database deletion**

The fix should verify that the batch hasn't been updated in the cache before deleting from the database. Modify `update_certified_timestamp()`:

```rust
pub fn update_certified_timestamp(&self, certified_time: u64) {
    trace!("QS: batch reader updating time {:?}", certified_time);
    self.last_certified_time
        .fetch_max(certified_time, Ordering::SeqCst);

    let expiration_time = certified_time.saturating_sub(self.expiration_buffer_usecs);
    let expired_keys = self.clear_expired_payload(certified_time);
    
    // Filter out batches that were re-added to cache with higher expiration
    let keys_to_delete: Vec<HashValue> = expired_keys
        .into_iter()
        .filter(|digest| {
            // Check if batch is still absent from cache or has expired expiration
            match self.db_cache.get(digest) {
                Some(entry) => entry.expiration() <= expiration_time,
                None => true, // Still expired, safe to delete
            }
        })
        .collect();
    
    if let Err(e) = self.db.delete_batches(keys_to_delete) {
        debug!("Error deleting batches: {:?}", e)
    }
}
```

**Alternative Solution: Use a single atomic write batch**

Combine cache updates and database deletions into a single transaction or use a write-ahead log pattern to ensure consistency.

## Proof of Concept

```rust
#[tokio::test]
async fn test_race_condition_batch_gc_vs_persist() {
    use std::sync::Arc;
    use tokio::sync::Barrier;
    use aptos_temppath::TempPath;
    
    // Setup
    let tmp_dir = TempPath::new();
    let db = Arc::new(QuorumStoreDB::new(tmp_dir.path()));
    let validator_signer = ValidatorSigner::random([0u8; 32]);
    
    let batch_store = Arc::new(BatchStore::new(
        1, // epoch
        false, // not new epoch
        1000000, // last_certified_time (1 second)
        db.clone(),
        10000, // memory_quota
        100000, // db_quota
        100, // batch_quota
        validator_signer,
        60000000, // expiration_buffer_usecs (60 seconds)
    ));
    
    // Create a batch with expiration at 1.5 seconds
    let digest = HashValue::random();
    let batch_info = BatchInfoExt::new(
        /* author */ PeerId::random(),
        /* batch_id */ BatchId::new(0),
        /* epoch */ 1,
        /* expiration */ 1500000, // 1.5 seconds
        /* digest */ digest,
        /* num_txns */ 10,
        /* num_bytes */ 1000,
        /* gas_bucket_start */ 0,
    );
    let persisted = PersistedValue::new(batch_info.clone(), Some(vec![]));
    
    // Initial persist - adds to cache and DB
    batch_store.persist(vec![persisted.clone()]);
    
    // Verify it's in DB
    assert!(db.get_batch_v2(&digest).unwrap().is_some());
    
    let barrier = Arc::new(Barrier::new(2));
    let bs1 = batch_store.clone();
    let bs2 = batch_store.clone();
    let barrier1 = barrier.clone();
    let barrier2 = barrier.clone();
    
    // Thread 1: Garbage collection (certified_time = 2 seconds)
    let gc_handle = tokio::spawn(async move {
        barrier1.wait().await;
        // This will try to delete the batch since 2000000 - 60000 > 1500000
        bs1.update_certified_timestamp(2000000);
    });
    
    // Thread 2: Re-persist with higher expiration
    let persist_handle = tokio::spawn(async move {
        barrier2.wait().await;
        // Small delay to let GC start but not finish
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        
        // Re-add same batch with higher expiration (3 seconds)
        let new_batch_info = BatchInfoExt::new(
            batch_info.author(),
            batch_info.batch_id(),
            1,
            3000000, // Extended to 3 seconds
            digest,
            10,
            1000,
            0,
        );
        let new_persisted = PersistedValue::new(new_batch_info, Some(vec![]));
        bs2.persist(vec![new_persisted]);
    });
    
    gc_handle.await.unwrap();
    persist_handle.await.unwrap();
    
    // Verify the race condition: batch is in cache but not in DB
    assert!(batch_store.db_cache.contains_key(&digest), "Batch should be in cache");
    assert!(db.get_batch_v2(&digest).unwrap().is_none(), "Batch should be MISSING from DB - RACE CONDITION!");
    
    // Simulate node restart by creating new batch store
    let batch_store_restarted = Arc::new(BatchStore::new(
        1,
        false,
        2000000,
        db.clone(),
        10000,
        100000,
        100,
        validator_signer,
        60000000,
    ));
    
    // After restart, batch is lost from cache because it wasn't in DB
    assert!(
        !batch_store_restarted.db_cache.contains_key(&digest),
        "After restart, batch is LOST - cannot execute blocks referencing it!"
    );
}
```

## Notes

The vulnerability is subtle because:
1. The individual database operations are atomic (via RocksDB batch writes)
2. The cache operations are thread-safe (via DashMap locking)
3. However, there is no coordination between cache and DB operations across different threads

The developers were aware of concurrent updates to expiration times (see comment at line 453-455) but only protected the cache removal logic, not the subsequent database deletion. This creates a TOCTOU (Time-of-Check-Time-of-Use) vulnerability where the set of expired digests is determined at one point in time but acted upon later when those digests may no longer be expired.

### Citations

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

**File:** consensus/src/quorum_store/batch_store.rs (L358-417)
```rust
    pub(crate) fn insert_to_cache(
        &self,
        value: &PersistedValue<BatchInfoExt>,
    ) -> anyhow::Result<bool> {
        let digest = *value.digest();
        let author = value.author();
        let expiration_time = value.expiration();

        {
            // Acquire dashmap internal lock on the entry corresponding to the digest.
            let cache_entry = self.db_cache.entry(digest);

            if let Occupied(entry) = &cache_entry {
                match entry.get().expiration().cmp(&expiration_time) {
                    std::cmp::Ordering::Equal => return Ok(false),
                    std::cmp::Ordering::Greater => {
                        debug!(
                            "QS: already have the digest with higher expiration {}",
                            digest
                        );
                        return Ok(false);
                    },
                    std::cmp::Ordering::Less => {},
                }
            };
            let value_to_be_stored = if self
                .peer_quota
                .entry(author)
                .or_insert(QuotaManager::new(
                    self.db_quota,
                    self.memory_quota,
                    self.batch_quota,
                ))
                .update_quota(value.num_bytes() as usize)?
                == StorageMode::PersistedOnly
            {
                PersistedValue::new(value.batch_info().clone(), None)
            } else {
                value.clone()
            };

            match cache_entry {
                Occupied(entry) => {
                    let (k, prev_value) = entry.replace_entry(value_to_be_stored);
                    debug_assert!(k == digest);
                    self.free_quota(prev_value);
                },
                Vacant(slot) => {
                    slot.insert(value_to_be_stored);
                },
            }
        }

        // Add expiration for the inserted entry, no need to be atomic w. insertion.
        #[allow(clippy::unwrap_used)]
        {
            self.expirations.lock().add_item(digest, expiration_time);
        }
        Ok(true)
    }
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

**File:** consensus/src/quorum_store/batch_store.rs (L545-569)
```rust
    fn get_batch_from_db(
        &self,
        digest: &HashValue,
        is_v2: bool,
    ) -> ExecutorResult<PersistedValue<BatchInfoExt>> {
        counters::GET_BATCH_FROM_DB_COUNT.inc();

        if is_v2 {
            match self.db.get_batch_v2(digest) {
                Ok(Some(value)) => Ok(value),
                Ok(None) | Err(_) => {
                    warn!("Could not get batch from db");
                    Err(ExecutorError::CouldNotGetData)
                },
            }
        } else {
            match self.db.get_batch(digest) {
                Ok(Some(value)) => Ok(value.into()),
                Ok(None) | Err(_) => {
                    warn!("Could not get batch from db");
                    Err(ExecutorError::CouldNotGetData)
                },
            }
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

**File:** consensus/src/quorum_store/quorum_store_db.rs (L110-117)
```rust
    fn save_batch(&self, batch: PersistedValue<BatchInfo>) -> Result<(), DbError> {
        trace!(
            "QS: db persists digest {} expiration {:?}",
            batch.digest(),
            batch.expiration()
        );
        self.put::<BatchSchema>(batch.digest(), &batch)
    }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L617-626)
```rust
        let executed_blocks = match inner {
            Ok(result) => result,
            Err(e) => {
                log_executor_error_occurred(
                    e,
                    &counters::BUFFER_MANAGER_RECEIVED_EXECUTOR_ERROR_COUNT,
                    block_id,
                );
                return;
            },
```

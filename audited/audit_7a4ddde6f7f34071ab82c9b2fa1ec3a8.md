# Audit Report

## Title
Cache-Database Inconsistency in Batch Store Leading to False Negative Existence Checks

## Summary
The `exists()` function in `BatchReaderImpl` performs a cache-only check for batch existence, returning `None` for batches that exist in the database but not in the cache. This can occur when database deletion operations fail during batch expiration cleanup, creating a cache-database inconsistency that causes unnecessary batch refetches and incorrect consensus behavior.

## Finding Description

The vulnerability stems from a state inconsistency between the in-memory cache and persistent database in the quorum store batch management system.

**Root Cause Flow:**

1. When `update_certified_timestamp()` is invoked to clean up expired batches, it calls `clear_expired_payload()` which removes batches from the in-memory `db_cache` and returns their digests. [1](#0-0) 

2. The function then attempts to delete these batches from the persistent database. However, if the database deletion fails (due to disk I/O errors, filesystem issues, corruption, or resource exhaustion), the error is only logged and execution continues. [2](#0-1) 

3. This creates an inconsistent state where batches are removed from cache but remain in the database. The database write operation uses `write_schemas_relaxed()` which can fail for various operational reasons. [3](#0-2) 

4. When `exists()` is subsequently called for such a batch, it delegates to `get_batch_from_local()` which only checks the in-memory cache. [4](#0-3) 

5. Since the batch is not in cache, `get_batch_from_local()` returns `Err(ExecutorError::CouldNotGetData)`, which `exists()` converts to `None`, producing a false negative. [5](#0-4) 

**Consensus Impact:**

The false negative propagates to critical consensus components:

1. **Payload Manager**: When verifying OptQuorumStore payloads, batches are incorrectly marked as missing, causing the validator to record the batch author as unavailable. [6](#0-5) [7](#0-6) 

2. **Proof Coordinator**: Signed batch information is rejected with a `NotFound` error even though the batch exists in the database, requiring unnecessary refetch operations. [8](#0-7) 

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty program's "State inconsistencies requiring intervention" category.

**Concrete Impacts:**

1. **State Inconsistency**: Violates the cache-database synchronization invariant that the system relies upon for correct batch availability determination.

2. **Network Resource Waste**: Triggers unnecessary batch refetch requests across the network for batches that already exist locally in the database, consuming bandwidth and CPU resources.

3. **Consensus Delays**: When multiple batches are affected, the repeated refetch operations can slow down block proposal verification and consensus progress.

4. **Incorrect Metrics**: Batch availability metrics become unreliable, reporting batches as missing when they are actually available. [9](#0-8) 

5. **Validator Reputation Impact**: Authors are incorrectly marked as having missing batches, potentially affecting validator performance tracking.

While this does not directly cause fund loss or consensus safety violations, it creates persistent state inconsistencies that degrade system performance and reliability until manual intervention (node restart) occurs.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability manifests under realistic operational conditions:

1. **Database I/O Failures**: Can occur during high system load, disk failures, filesystem corruption, or resource exhaustion (disk space, file descriptors).

2. **Persistence**: Once the inconsistency occurs, it persists until the affected batches naturally expire from the database or the node restarts, potentially affecting multiple consensus rounds.

3. **Cascade Effect**: If multiple batches experience failed deletions simultaneously (e.g., during sustained I/O issues), the impact compounds across the consensus process.

4. **Relaxed Writes**: The use of `write_schemas_relaxed()` instead of synchronous writes may have different failure characteristics under stress.

The issue does not require attacker action but occurs naturally under adverse operational conditions that validators commonly encounter in production environments.

## Recommendation

**Fix Option 1: Add Database Fallback to exists()**

Modify `get_batch_from_local()` to check the database when a batch is not found in cache:

```rust
pub(crate) fn get_batch_from_local(
    &self,
    digest: &HashValue,
) -> ExecutorResult<PersistedValue<BatchInfoExt>> {
    if let Some(value) = self.db_cache.get(digest) {
        if value.payload_storage_mode() == StorageMode::PersistedOnly {
            self.get_batch_from_db(digest, value.batch_info().is_v2())
        } else {
            Ok(value.clone())
        }
    } else {
        // Fallback: check database for batches that may exist but aren't cached
        // This handles the case where cache-database sync failed
        self.get_batch_from_db(digest, false)
            .or_else(|_| self.get_batch_from_db(digest, true))
    }
}
```

**Fix Option 2: Handle Database Deletion Failures Properly**

Make the cache and database operations atomic or handle deletion failures:

```rust
pub fn update_certified_timestamp(&self, certified_time: u64) {
    trace!("QS: batch reader updating time {:?}", certified_time);
    self.last_certified_time
        .fetch_max(certified_time, Ordering::SeqCst);

    let expired_keys = self.clear_expired_payload(certified_time);
    if let Err(e) = self.db.delete_batches(expired_keys.clone()) {
        error!("Critical: Error deleting batches from DB: {:?}", e);
        // Re-insert batches into cache since DB deletion failed
        for digest in expired_keys {
            if let Ok(value) = self.db.get_batch(&digest).or_else(|_| self.db.get_batch_v2(&digest)) {
                let _ = self.insert_to_cache(&value);
            }
        }
        counters::BATCH_DELETE_FAILURE_COUNT.inc();
    }
}
```

**Recommended Approach**: Implement Option 1 as it provides defense-in-depth and handles the inconsistency gracefully without adding complexity to the cleanup path.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use aptos_crypto::HashValue;
    use std::sync::Arc;

    // Mock QuorumStoreStorage that fails deletions
    struct FailingDeleteDB {
        inner: Arc<MockQuorumStoreDB>,
        should_fail: Arc<AtomicBool>,
    }

    impl QuorumStoreStorage for FailingDeleteDB {
        fn delete_batches(&self, _: Vec<HashValue>) -> Result<(), DbError> {
            if self.should_fail.load(Ordering::Relaxed) {
                Err(DbError::Other("Simulated I/O error".to_string()))
            } else {
                Ok(())
            }
        }
        
        // Implement other required methods by delegating to inner...
        fn get_batch(&self, digest: &HashValue) -> Result<Option<PersistedValue<BatchInfo>>, DbError> {
            self.inner.get_batch(digest)
        }
        // ... (other methods)
    }

    #[test]
    fn test_cache_db_inconsistency_on_failed_deletion() {
        // Setup batch store with failing delete DB
        let failing_db = Arc::new(FailingDeleteDB {
            inner: Arc::new(MockQuorumStoreDB::new()),
            should_fail: Arc::new(AtomicBool::new(false)),
        });
        
        let batch_store = BatchStore::new(
            1, false, 1000, failing_db.clone(), 
            1024 * 1024, 10 * 1024 * 1024, 100,
            ValidatorSigner::random(None), 60_000_000
        );
        
        // Create and persist a batch
        let batch_info = create_test_batch_info();
        let persist_value = PersistedValue::new(batch_info.clone(), Some(vec![]));
        batch_store.save(&persist_value).unwrap();
        
        let digest = *batch_info.digest();
        
        // Verify batch exists before expiration
        let reader = BatchReaderImpl::new(Arc::new(batch_store), mock_batch_requester());
        assert!(reader.exists(&digest).is_some(), "Batch should exist in cache");
        
        // Enable deletion failure
        failing_db.should_fail.store(true, Ordering::Relaxed);
        
        // Trigger expiration cleanup - cache will be cleared but DB deletion fails
        reader.batch_store.update_certified_timestamp(batch_info.expiration() + 120_000_000);
        
        // BUG: exists() now returns None even though batch is still in database
        assert!(reader.exists(&digest).is_none(), 
            "FALSE NEGATIVE: exists() returns None despite batch being in database");
        
        // Verify batch is still in database
        assert!(failing_db.get_batch(&digest).unwrap().is_some(),
            "Batch still exists in database");
    }
}
```

## Notes

This vulnerability represents a classic cache-database synchronization problem where partial failure handling leads to state inconsistency. While the immediate impact is performance degradation rather than consensus safety violation, the persistent nature of the inconsistency and its effect on batch availability determination warrant attention. The fix should prioritize correctness over performance optimization, as the cache-only check optimization breaks down under the failure scenario documented here.

### Citations

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

**File:** consensus/src/quorum_store/batch_store.rs (L571-585)
```rust
    pub(crate) fn get_batch_from_local(
        &self,
        digest: &HashValue,
    ) -> ExecutorResult<PersistedValue<BatchInfoExt>> {
        if let Some(value) = self.db_cache.get(digest) {
            if value.payload_storage_mode() == StorageMode::PersistedOnly {
                self.get_batch_from_db(digest, value.batch_info().is_v2())
            } else {
                // Available in memory.
                Ok(value.clone())
            }
        } else {
            Err(ExecutorError::CouldNotGetData)
        }
    }
```

**File:** consensus/src/quorum_store/batch_store.rs (L727-732)
```rust
    fn exists(&self, digest: &HashValue) -> Option<PeerId> {
        self.batch_store
            .get_batch_from_local(digest)
            .map(|v| v.author())
            .ok()
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

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L368-376)
```rust
                        let (available_count, missing_count) = chunk
                            .map(|info| batch_reader.exists(info.digest()))
                            .fold((0, 0), |(available_count, missing_count), item| {
                                if item.is_some() {
                                    (available_count + 1, missing_count)
                                } else {
                                    (available_count, missing_count + 1)
                                }
                            });
```

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L412-418)
```rust
                    if self.batch_reader.exists(batch.digest()).is_none() {
                        let index = *self
                            .address_to_validator_index
                            .get(&batch.author())
                            .expect("Payload author should have been verified");
                        missing_authors.set(index as u16);
                    }
```

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L429-435)
```rust
                    if self.batch_reader.exists(batch.digest()).is_none() {
                        let index = *self
                            .address_to_validator_index
                            .get(&batch.author())
                            .expect("Payload author should have been verified");
                        missing_authors.set(index as u16);
                    }
```

**File:** consensus/src/quorum_store/proof_coordinator.rs (L277-283)
```rust
        let batch_author = self
            .batch_reader
            .exists(signed_batch_info.digest())
            .ok_or(SignedBatchInfoError::NotFound)?;
        if batch_author != signed_batch_info.author() {
            return Err(SignedBatchInfoError::WrongAuthor);
        }
```

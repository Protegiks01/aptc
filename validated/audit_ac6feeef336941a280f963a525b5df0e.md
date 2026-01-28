# Audit Report

## Title
Database Schema Mismatch Causes Incomplete Deletion of V2 Batches Leading to Unbounded Database Growth

## Summary
The `update_certified_timestamp` method in QuorumStore's `batch_store.rs` only deletes expired batches from the V1 database schema (`BatchSchema`), failing to delete V2 batches from the separate V2 column family (`BatchV2Schema`). When `enable_batch_v2` is enabled, this causes permanent accumulation of expired V2 batches, leading to unbounded storage growth and validator node performance degradation.

## Finding Description
The Aptos consensus layer uses QuorumStore to manage transaction batches with two separate database schemas stored in distinct column families: V1 using `BatchSchema` in the "batch" column family, and V2 using `BatchV2Schema` in the "batch_v2" column family. [1](#0-0) [2](#0-1) 

These schemas store different batch formats: `PersistedValue<BatchInfo>` for V1 and `PersistedValue<BatchInfoExt>` for V2, persisted through separate database methods. [3](#0-2) 

When V2 batches are enabled via the `enable_batch_v2` configuration flag, batches are created using the V2 format and saved to the "batch_v2" column family: [4](#0-3) [5](#0-4) 

During normal consensus operation, the `update_certified_timestamp` method is called on every block commit to clean up expired batches: [6](#0-5) 

**The Critical Bug:** While `update_certified_timestamp` correctly clears expired batches from the in-memory cache, it only deletes them from the V1 database schema: [7](#0-6) 

The `delete_batches` method operates exclusively on the `BatchSchema` (V1) column family: [8](#0-7) 

However, a separate `delete_batches_v2` method exists for deleting V2 batches from the "batch_v2" column family: [9](#0-8) 

This method is never invoked in `update_certified_timestamp`, causing V2 batches to accumulate permanently in the database without cleanup.

**Additional Bug:** The same issue exists in `gc_previous_epoch_batches_from_db_v2`, which reads V2 batches but incorrectly attempts to delete them using the V1 deletion method: [10](#0-9) 

**Execution Flow:**
1. Block is committed → `notify_commit` invoked
2. `update_certified_timestamp` called with block timestamp
3. `clear_expired_payload` removes expired batches from in-memory cache (both V1 and V2)
4. `delete_batches` called, but only deletes from "batch" column family
5. V2 batches remain permanently in "batch_v2" column family
6. Process repeats on every block commit, accumulating storage without bound

**Invariant Violations:**
- **Resource Management**: Database storage quota should be bounded and properly reclaimed
- **State Consistency**: Expired batches should be completely removed from all storage layers
- **Cache Coherence**: In-memory cache and persistent storage should maintain consistency

## Impact Explanation
This vulnerability qualifies as **High Severity** under the "Validator Node Slowdowns" category:

**Resource Exhaustion**: Once `enable_batch_v2` is enabled, expired V2 batches accumulate continuously in the database:
- Multiple blocks per second means rapid accumulation of undeletable batches
- Database grows without bound over time
- Increased disk I/O overhead during database operations
- Longer node restart times as initialization attempts to load accumulated batches

**Performance Degradation**: The `populate_cache_and_gc_expired_batches_v2` method loads all V2 batches from the database during node restart: [11](#0-10) 

Accumulated expired V2 batches within the expiration buffer window will be reloaded into memory, potentially causing:
- Memory exhaustion from loading thousands of expired batches
- Quota management inconsistencies
- Degraded consensus participation performance
- Potential cascade failures affecting validator operations

While this doesn't directly cause consensus violations, significant validator slowdowns can indirectly affect network health and consensus participation.

## Likelihood Explanation
**Likelihood: High (Conditional on Feature Enablement)**

When `enable_batch_v2` is enabled:
- Triggers automatically on every block commit (several times per second)
- No attacker action required - normal consensus operation causes accumulation
- 100% reproduction rate when V2 batches are in use
- Accumulation rate is proportional to block production frequency

**Current Mitigation**: The `enable_batch_v2` flag is disabled by default: [12](#0-11) 

This significantly reduces immediate impact, as no validators are currently affected unless they explicitly enabled this feature. However, this remains a valid vulnerability because:
1. The feature exists in production code as a supported configuration option
2. Enabling it is legitimate validator operator behavior (not malicious)
3. Once enabled, the bug manifests automatically and deterministically
4. Future activation of this feature would expose all participating validators

## Recommendation
Fix both bugs by calling the correct deletion methods for each schema version:

**Fix 1: Update `update_certified_timestamp`**
```rust
pub fn update_certified_timestamp(&self, certified_time: u64) {
    trace!("QS: batch reader updating time {:?}", certified_time);
    self.last_certified_time
        .fetch_max(certified_time, Ordering::SeqCst);

    let expired_keys = self.clear_expired_payload(certified_time);
    
    // Delete from both V1 and V2 schemas
    if let Err(e) = self.db.delete_batches(expired_keys.clone()) {
        debug!("Error deleting V1 batches: {:?}", e)
    }
    if let Err(e) = self.db.delete_batches_v2(expired_keys) {
        debug!("Error deleting V2 batches: {:?}", e)
    }
}
```

**Fix 2: Update `gc_previous_epoch_batches_from_db_v2`**
Change line 241 from `db.delete_batches(expired_keys)` to `db.delete_batches_v2(expired_keys)`.

Alternatively, maintain separate tracking of V1 and V2 batch digests in the cache to avoid redundant deletion attempts.

## Proof of Concept
```rust
#[cfg(test)]
mod test_v2_batch_deletion_bug {
    use super::*;
    use aptos_types::validator_signer::ValidatorSigner;
    use aptos_config::config::QuorumStoreConfig;
    
    #[test]
    fn test_v2_batches_not_deleted() {
        // Create batch store with V2 enabled
        let mut config = QuorumStoreConfig::default();
        config.enable_batch_v2 = true;
        
        let db = Arc::new(QuorumStoreDB::new_for_test());
        let batch_store = BatchStore::new(
            1, // epoch
            true,
            0, // last_certified_time
            db.clone(),
            100000, // memory_quota
            200000, // db_quota
            1000, // batch_quota
            ValidatorSigner::random(None),
            Duration::from_secs(60).as_micros() as u64,
        );
        
        // Create and persist V2 batch
        let txns = vec![create_test_transaction()];
        let expiration = 100_000;
        let batch = Batch::new_v2(
            BatchId::new(1),
            txns,
            1, // epoch
            expiration,
            PeerId::random(),
            0, // bucket_start
            BatchKind::Normal,
        );
        
        batch_store.persist(vec![batch.into_persisted_value()]);
        
        // Verify V2 batch is in database
        let all_v2 = db.get_all_batches_v2().unwrap();
        assert_eq!(all_v2.len(), 1);
        
        // Update certified timestamp past expiration
        batch_store.update_certified_timestamp(expiration + 10_000);
        
        // BUG: V2 batch should be deleted but remains in database
        let all_v2_after = db.get_all_batches_v2().unwrap();
        assert_eq!(all_v2_after.len(), 1, "V2 batch was NOT deleted - BUG!");
        
        // V1 batches would be correctly deleted (if any existed)
        let all_v1_after = db.get_all_batches().unwrap();
        assert_eq!(all_v1_after.len(), 0, "V1 batches correctly deleted");
    }
}
```

## Notes
This vulnerability demonstrates a critical schema version mismatch in the deletion logic. While the feature is currently disabled by default, this is a legitimate bug in production consensus code that would affect any validator enabling V2 batch support. The bug's validity is not negated by the feature being disabled - it represents a defect in supported functionality that should be fixed before wider deployment.

The fix is straightforward: ensure both schema versions are properly cleaned up during garbage collection operations. The existence of separate V2 methods (`delete_batches_v2`, `populate_cache_and_gc_expired_batches_v2`, etc.) indicates the codebase was designed to support both versions, but the cleanup logic was incompletely updated.

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

**File:** consensus/src/quorum_store/quorum_store_db.rs (L26-44)
```rust
pub trait QuorumStoreStorage: Sync + Send {
    fn delete_batches(&self, digests: Vec<HashValue>) -> Result<(), DbError>;

    fn get_all_batches(&self) -> Result<HashMap<HashValue, PersistedValue<BatchInfo>>>;

    fn save_batch(&self, batch: PersistedValue<BatchInfo>) -> Result<(), DbError>;

    fn get_batch(&self, digest: &HashValue) -> Result<Option<PersistedValue<BatchInfo>>, DbError>;

    fn delete_batches_v2(&self, digests: Vec<HashValue>) -> Result<(), DbError>;

    fn get_all_batches_v2(&self) -> Result<HashMap<HashValue, PersistedValue<BatchInfoExt>>>;

    fn save_batch_v2(&self, batch: PersistedValue<BatchInfoExt>) -> Result<(), DbError>;

    fn get_batch_v2(
        &self,
        digest: &HashValue,
    ) -> Result<Option<PersistedValue<BatchInfoExt>>, DbError>;
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

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L168-170)
```rust
    fn notify_commit(&self, block_timestamp: u64, payloads: Vec<Payload>) {
        self.batch_reader
            .update_certified_timestamp(block_timestamp);
```

**File:** config/src/config/quorum_store_config.rs (L102-144)
```rust
    pub enable_batch_v2: bool,
}

impl Default for QuorumStoreConfig {
    fn default() -> QuorumStoreConfig {
        QuorumStoreConfig {
            channel_size: 1000,
            proof_timeout_ms: 10000,
            batch_generation_poll_interval_ms: 25,
            batch_generation_min_non_empty_interval_ms: 50,
            batch_generation_max_interval_ms: 250,
            sender_max_batch_txns: DEFEAULT_MAX_BATCH_TXNS,
            // TODO: on next release, remove BATCH_PADDING_BYTES
            sender_max_batch_bytes: 1024 * 1024 - BATCH_PADDING_BYTES,
            sender_max_num_batches: DEFAULT_MAX_NUM_BATCHES,
            sender_max_total_txns: 1500,
            // TODO: on next release, remove DEFAULT_MAX_NUM_BATCHES * BATCH_PADDING_BYTES
            sender_max_total_bytes: 4 * 1024 * 1024 - DEFAULT_MAX_NUM_BATCHES * BATCH_PADDING_BYTES,
            receiver_max_batch_txns: 100,
            receiver_max_batch_bytes: 1024 * 1024 + BATCH_PADDING_BYTES,
            receiver_max_num_batches: 20,
            receiver_max_total_txns: 2000,
            receiver_max_total_bytes: 4 * 1024 * 1024
                + DEFAULT_MAX_NUM_BATCHES
                + BATCH_PADDING_BYTES,
            batch_request_num_peers: 5,
            batch_request_retry_limit: 10,
            batch_request_retry_interval_ms: 500,
            batch_request_rpc_timeout_ms: 5000,
            batch_expiry_gap_when_init_usecs: Duration::from_secs(60).as_micros() as u64,
            remote_batch_expiry_gap_when_init_usecs: Duration::from_millis(500).as_micros() as u64,
            memory_quota: 120_000_000,
            db_quota: 300_000_000,
            batch_quota: 300_000,
            back_pressure: QuorumStoreBackPressureConfig::default(),
            // number of batch coordinators to handle QS batch messages, should be >= 1
            num_workers_for_remote_batches: 10,
            batch_buckets: DEFAULT_BUCKETS.to_vec(),
            allow_batches_without_pos_in_proposal: true,
            enable_opt_quorum_store: true,
            opt_qs_minimum_batch_age_usecs: Duration::from_millis(50).as_micros() as u64,
            enable_payload_v2: false,
            enable_batch_v2: false,
```

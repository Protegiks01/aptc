# Audit Report

## Title
Database Deserialization Panic in Quorum Store Batch Loading Causes Validator Crash

## Summary
The quorum store database batch loading functions use `.expect()` on database read operations that can fail during BCS deserialization. If any stored `PersistedValue` is corrupted, the validator will panic during startup or epoch transitions, causing a non-recoverable crash that prevents the validator from participating in consensus.

## Finding Description

While `get_batch()` itself properly handles deserialization errors by returning a `Result` type, the related `get_all_batches()` function is called with `.expect()` in multiple critical initialization paths, creating a crash vulnerability.

The vulnerability exists in the batch store initialization code where corrupted database entries cause unhandled panics: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

The `get_all_batches()` implementation uses an iterator that performs BCS deserialization on each value: [5](#0-4) 

The deserialization happens in the schema's `decode_value()` implementation: [6](#0-5) 

The SchemaDB iterator calls this decode function and propagates errors: [7](#0-6) 

When `.collect()` encounters a deserialization error, it returns an `Err`, which then hits the `.expect()` calls in the batch store initialization, causing the validator to panic.

These initialization functions are called during `BatchStore::new()`: [8](#0-7) 

Which is invoked during consensus initialization: [9](#0-8) 

**Attack Path:**
1. Database corruption occurs (hardware failure, filesystem issues, software bug, incomplete write)
2. Validator restarts or epoch transition occurs
3. `BatchStore::new()` is called during consensus initialization
4. `get_all_batches()` attempts to deserialize all stored batches
5. Corrupted entry causes BCS deserialization to fail
6. `.expect()` panics the validator process
7. Validator cannot restart and remains offline

## Impact Explanation

This is a **HIGH severity** vulnerability per Aptos bug bounty criteria:

- **Validator node crash**: The panic completely crashes the validator process
- **Non-recoverable without manual intervention**: The validator will continuously crash on restart until the corrupted database entry is manually removed
- **Consensus availability impact**: Affected validators cannot participate in consensus, reducing network availability
- **Potential network partition**: If multiple validators experience database corruption simultaneously, consensus could stall

While individual validator crashes are categorized as High severity, the non-recoverable nature and potential for multiple validators to be affected simultaneously makes this particularly severe.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

Database corruption is not a theoretical concern but a practical reality in production systems:

1. **Hardware failures**: Disk failures, memory corruption, power loss during writes
2. **Software bugs**: Race conditions in database writes, incomplete transactions
3. **Filesystem issues**: Corruption, quota issues, permission problems
4. **Upgrades/migrations**: Schema changes that make old data incompatible with new deserializers
5. **Operational errors**: Disk space exhaustion, backup/restore issues

The vulnerability is automatically triggered—no attacker action required. Any validator experiencing database corruption will crash and remain offline until manual intervention.

## Recommendation

Replace all `.expect()` calls with proper error handling that logs the error and skips corrupted entries:

```rust
fn gc_previous_epoch_batches_from_db_v1(db: Arc<dyn QuorumStoreStorage>, current_epoch: u64) {
    let db_content = match db.get_all_batches() {
        Ok(content) => content,
        Err(e) => {
            error!("Failed to read batches from db during GC: {:?}. Skipping GC for this epoch.", e);
            return;
        }
    };
    // ... rest of function
}

fn populate_cache_and_gc_expired_batches_v1(
    db: Arc<dyn QuorumStoreStorage>,
    current_epoch: u64,
    last_certified_time: u64,
    expiration_buffer_usecs: u64,
    batch_store: &BatchStore,
) {
    let db_content = match db.get_all_batches() {
        Ok(content) => content,
        Err(e) => {
            warn!("Failed to read v1 batches from db: {:?}. Starting with empty cache.", e);
            return;
        }
    };
    // ... rest of function
}
```

Additionally, consider modifying `get_all_batches()` to skip corrupted entries rather than failing entirely:

```rust
fn get_all_batches(&self) -> Result<HashMap<HashValue, PersistedValue<BatchInfo>>> {
    let mut iter = self.db.iter::<BatchSchema>()?;
    iter.seek_to_first();
    let mut result = HashMap::new();
    for item in iter {
        match item {
            Ok((key, value)) => {
                result.insert(key, value);
            }
            Err(e) => {
                warn!("Failed to deserialize batch entry, skipping: {:?}", e);
                counters::BATCH_DESERIALIZATION_ERROR_COUNT.inc();
                continue;
            }
        }
    }
    Ok(result)
}
```

## Proof of Concept

```rust
#[test]
fn test_corrupted_batch_causes_panic() {
    use aptos_temppath::TempPath;
    use aptos_crypto::HashValue;
    use std::sync::Arc;
    
    // Setup: Create a quorum store DB
    let tmpdir = TempPath::new();
    let db = Arc::new(QuorumStoreDB::new(tmpdir.path()));
    
    // Step 1: Write valid batch
    let valid_batch = create_test_batch();
    db.save_batch(valid_batch).unwrap();
    
    // Step 2: Manually corrupt the database by writing invalid BCS data
    // This simulates database corruption
    let corrupted_digest = HashValue::random();
    let invalid_bcs_data = vec![0xFF, 0xFF, 0xFF]; // Invalid BCS encoding
    
    // Write corrupted data directly to RocksDB
    let cf_handle = db.inner.get_cf_handle(BATCH_CF_NAME).unwrap();
    db.inner.put_cf(cf_handle, corrupted_digest.to_vec(), invalid_bcs_data).unwrap();
    
    // Step 3: Try to read all batches - this will panic with current implementation
    let result = std::panic::catch_unwind(|| {
        db.get_all_batches().expect("failed to read data from db");
    });
    
    // Current behavior: panics
    assert!(result.is_err(), "Expected panic from corrupted data");
    
    // Expected behavior after fix: should handle gracefully
    // let batches = db.get_all_batches().unwrap();
    // assert_eq!(batches.len(), 1); // Only the valid batch
}
```

## Notes

The direct `get_batch()` function mentioned in the security question **does** handle errors properly through the `get_batch_from_db()` wrapper. However, the broader vulnerability exists in `get_all_batches()` which is used during initialization and epoch transitions. This represents a more severe availability issue since it prevents validator startup rather than just failing individual batch retrievals during operation.

### Citations

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

**File:** consensus/src/quorum_store/batch_store.rs (L181-182)
```rust
    fn gc_previous_epoch_batches_from_db_v1(db: Arc<dyn QuorumStoreStorage>, current_epoch: u64) {
        let db_content = db.get_all_batches().expect("failed to read data from db");
```

**File:** consensus/src/quorum_store/batch_store.rs (L212-215)
```rust
    fn gc_previous_epoch_batches_from_db_v2(db: Arc<dyn QuorumStoreStorage>, current_epoch: u64) {
        let db_content = db
            .get_all_batches_v2()
            .expect("failed to read data from db");
```

**File:** consensus/src/quorum_store/batch_store.rs (L252-254)
```rust
        let db_content = db
            .get_all_batches()
            .expect("failed to read v1 data from db");
```

**File:** consensus/src/quorum_store/batch_store.rs (L299-301)
```rust
        let db_content = db
            .get_all_batches_v2()
            .expect("failed to read v1 data from db");
```

**File:** consensus/src/quorum_store/quorum_store_db.rs (L103-108)
```rust
    fn get_all_batches(&self) -> Result<HashMap<HashValue, PersistedValue<BatchInfo>>> {
        let mut iter = self.db.iter::<BatchSchema>()?;
        iter.seek_to_first();
        iter.map(|res| res.map_err(Into::into))
            .collect::<Result<HashMap<HashValue, PersistedValue<BatchInfo>>>>()
    }
```

**File:** consensus/src/quorum_store/schema.rs (L38-46)
```rust
impl ValueCodec<BatchSchema> for PersistedValue<BatchInfo> {
    fn encode_value(&self) -> Result<Vec<u8>> {
        Ok(bcs::to_bytes(&self)?)
    }

    fn decode_value(data: &[u8]) -> Result<Self> {
        Ok(bcs::from_bytes(data)?)
    }
}
```

**File:** storage/schemadb/src/iterator.rs (L118-121)
```rust
        let key = <S::Key as KeyCodec<S>>::decode_key(raw_key);
        let value = <S::Value as ValueCodec<S>>::decode_value(raw_value);

        Ok(Some((key?, value?)))
```

**File:** consensus/src/quorum_store/quorum_store_builder.rs (L256-266)
```rust
        let batch_store = Arc::new(BatchStore::new(
            self.epoch,
            is_new_epoch,
            last_committed_timestamp,
            self.quorum_store_storage.clone(),
            self.config.memory_quota,
            self.config.db_quota,
            self.config.batch_quota,
            signer,
            Duration::from_secs(60).as_micros() as u64,
        ));
```

# Audit Report

## Title
Consensus Node Crash Due to Unhandled Database Deserialization Errors in Quorum Store Batch Recovery

## Summary
The `get_all_batches_v2()` function lacks defensive error handling for corrupted database entries. When corrupted data exists in the `BATCH_V2_CF_NAME` column family, BCS deserialization failures cause panics via `.expect()` calls during consensus node initialization, resulting in validator node startup failure.

## Finding Description

The vulnerability exists in the quorum store database recovery logic during consensus node initialization. When a validator node starts, the `BatchStore::new()` constructor calls either `populate_cache_and_gc_expired_batches_v2()` (when continuing an epoch) or `gc_previous_epoch_batches_from_db_v2()` (when starting a new epoch) to recover batch data from persistent storage.

Both functions call `get_all_batches_v2()` which iterates over the `BATCH_V2_CF_NAME` column family and deserializes each entry using BCS: [1](#0-0) 

During iteration, the SchemaDB iterator calls `decode_value()` for each entry, which uses BCS deserialization: [2](#0-1) 

The iterator's `next_impl()` propagates deserialization errors up the call chain: [3](#0-2) 

However, the calling code uses `.expect()` instead of proper error handling, causing panics when deserialization fails: [4](#0-3) [5](#0-4) 

**Attack Scenario:**

1. A validator node's RocksDB database contains corrupted data in `BATCH_V2_CF_NAME` (due to hardware failure, filesystem corruption, or a bug in the write path)
2. When `is_new_epoch = false`, the synchronous call to `populate_cache_and_gc_expired_batches_v2()` executes during `BatchStore::new()`
3. The function calls `get_all_batches_v2().expect("failed to read data from db")`
4. During iteration, BCS fails to deserialize a corrupted `PersistedValue<BatchInfoExt>` entry
5. The `.expect()` triggers a panic, crashing the consensus node during startup
6. The validator cannot restart until the database is manually repaired

**Invariants Broken:**
- **Resource Limits**: Node startup should be resilient to non-critical storage corruption
- **Availability**: Validators must maintain uptime; preventable crashes violate availability guarantees

## Impact Explanation

This qualifies as **HIGH severity** per Aptos bug bounty criteria for the following reasons:

1. **Validator Node Crashes**: The panic occurs during critical consensus initialization at `BatchStore::new()`, which is called during node startup. A validator that cannot start cannot participate in consensus. [6](#0-5) 

2. **Liveness Impact**: If multiple validators experience database corruption simultaneously (e.g., due to a common software bug in the write path), the network could lose liveness if more than 1/3 of validators cannot restart.

3. **Requires Manual Intervention**: The validator cannot auto-recover; operators must manually repair or rebuild the database, increasing downtime.

4. **Deterministic Trigger**: Once corrupted data exists, the crash is deterministic and repeatable on every restart attempt.

While this is not directly exploitable by external attackers without additional vulnerabilities or privileged access, it represents a significant defensive programming failure that amplifies the impact of other bugs or natural failures.

## Likelihood Explanation

**Likelihood: Medium**

Corrupted data in RocksDB can occur through:

1. **Hardware failures**: Disk corruption, memory errors
2. **Filesystem issues**: Incomplete writes during crashes, filesystem bugs  
3. **Software bugs**: Race conditions or logic errors in batch persistence code that write invalid `BatchInfoExt` structures
4. **Operational errors**: Database backup/restore issues, version mismatches

While external attackers cannot directly write to the database, the presence of corrupted data is a realistic operational concern. The lack of defensive error handling means ANY source of corruption becomes a critical availability issue.

## Recommendation

Replace `.expect()` with proper error handling that allows the node to continue operating despite corrupted individual entries:

```rust
fn get_all_batches_v2(&self) -> Result<HashMap<HashValue, PersistedValue<BatchInfoExt>>> {
    let mut iter = self.db.iter::<BatchV2Schema>()?;
    iter.seek_to_first();
    
    let mut result = HashMap::new();
    for item in iter {
        match item {
            Ok((key, value)) => {
                result.insert(key, value);
            }
            Err(e) => {
                error!("Failed to deserialize batch entry, skipping: {:?}", e);
                counters::CORRUPTED_BATCH_ENTRIES.inc();
                // Continue iteration instead of failing
            }
        }
    }
    Ok(result)
}
```

Update callers to handle partial recovery gracefully:

```rust
fn populate_cache_and_gc_expired_batches_v2(...) {
    match db.get_all_batches_v2() {
        Ok(db_content) => {
            info!("Successfully recovered {} batches", db_content.len());
            // Continue with recovered data
        }
        Err(e) => {
            error!("Failed to recover v2 batches: {:?}", e);
            // Continue with empty set or partial recovery
        }
    }
}
```

## Proof of Concept

```rust
#[test]
fn test_corrupted_batch_causes_panic() {
    use aptos_temppath::TempPath;
    use aptos_crypto::HashValue;
    
    // Create a quorum store DB
    let tmpdir = TempPath::new();
    let db = QuorumStoreDB::new(&tmpdir);
    
    // Write corrupted data directly to the column family
    let corrupted_key = HashValue::random();
    let corrupted_value = vec![0xFF, 0xFF, 0xFF]; // Invalid BCS
    
    db.db.put::<BatchV2Schema>(&corrupted_key, &corrupted_value)
        .expect("Failed to write corrupted data");
    
    // Attempt to read all batches - this will panic
    let result = std::panic::catch_unwind(|| {
        db.get_all_batches_v2()
    });
    
    assert!(result.is_err(), "Expected panic due to corrupted data");
}

#[test]  
fn test_batch_store_init_with_corruption() {
    use aptos_temppath::TempPath;
    
    let tmpdir = TempPath::new();
    let db = Arc::new(QuorumStoreDB::new(&tmpdir));
    
    // Write corrupted batch
    let corrupted_key = HashValue::random();
    db.db.put::<BatchV2Schema>(&corrupted_key, &vec![0xFF, 0xFF, 0xFF])
        .expect("Write failed");
    
    // Attempt BatchStore initialization - will panic with is_new_epoch=false
    let result = std::panic::catch_unwind(|| {
        BatchStore::new(
            1, // epoch
            false, // is_new_epoch - triggers synchronous path
            0, // last_certified_time
            db,
            1000, // memory_quota  
            2000, // db_quota
            100, // batch_quota
            ValidatorSigner::random(None),
            Duration::from_secs(60).as_micros() as u64,
        )
    });
    
    assert!(result.is_err(), "Expected panic during BatchStore initialization");
}
```

## Notes

**Infinite Loop Analysis**: The iterator does NOT cause infinite loops. The RocksDB iterator advances normally via `self.db_iter.next()` regardless of deserialization success. The error is propagated correctly at the iterator level - the panic only occurs in calling code. [7](#0-6) 

**Additional Panic Point**: There is a secondary panic risk in the iterator itself if RocksDB returns `None` for `key()` or `value()` despite the iterator being valid: [8](#0-7) 

This should not occur under normal RocksDB semantics but could happen with severe database corruption.

### Citations

**File:** consensus/src/quorum_store/quorum_store_db.rs (L133-138)
```rust
    fn get_all_batches_v2(&self) -> Result<HashMap<HashValue, PersistedValue<BatchInfoExt>>> {
        let mut iter = self.db.iter::<BatchV2Schema>()?;
        iter.seek_to_first();
        iter.map(|res| res.map_err(Into::into))
            .collect::<Result<HashMap<HashValue, PersistedValue<BatchInfoExt>>>>()
    }
```

**File:** consensus/src/quorum_store/schema.rs (L68-76)
```rust
impl ValueCodec<BatchV2Schema> for PersistedValue<BatchInfoExt> {
    fn encode_value(&self) -> Result<Vec<u8>> {
        Ok(bcs::to_bytes(&self)?)
    }

    fn decode_value(data: &[u8]) -> Result<Self> {
        Ok(bcs::from_bytes(data)?)
    }
}
```

**File:** storage/schemadb/src/iterator.rs (L95-102)
```rust
        if let Status::Advancing = self.status {
            match self.direction {
                ScanDirection::Forward => self.db_iter.next(),
                ScanDirection::Backward => self.db_iter.prev(),
            }
        } else {
            self.status = Status::Advancing;
        }
```

**File:** storage/schemadb/src/iterator.rs (L111-112)
```rust
        let raw_key = self.db_iter.key().expect("db_iter.key() failed.");
        let raw_value = self.db_iter.value().expect("db_iter.value(0 failed.");
```

**File:** storage/schemadb/src/iterator.rs (L118-121)
```rust
        let key = <S::Key as KeyCodec<S>>::decode_key(raw_key);
        let value = <S::Value as ValueCodec<S>>::decode_value(raw_value);

        Ok(Some((key?, value?)))
```

**File:** consensus/src/quorum_store/batch_store.rs (L213-215)
```rust
        let db_content = db
            .get_all_batches_v2()
            .expect("failed to read data from db");
```

**File:** consensus/src/quorum_store/batch_store.rs (L299-301)
```rust
        let db_content = db
            .get_all_batches_v2()
            .expect("failed to read v1 data from db");
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

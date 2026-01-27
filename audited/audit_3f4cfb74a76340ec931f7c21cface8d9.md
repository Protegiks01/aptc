# Audit Report

## Title
Missing Post-Deserialization Integrity Validation for Persisted Batch Data Leading to Silent Corruption Propagation

## Summary
The `BatchSchema::decode_value()` implementation relies solely on BCS structural deserialization without validating the semantic correctness of loaded batch data. When RocksDB storage corruption occurs in a way that produces structurally-valid but semantically-incorrect BCS data, corrupted `PersistedValue<BatchInfo>` entries can be silently loaded into consensus, potentially causing divergent validator states and consensus failures.

## Finding Description

The quorum store persistence layer stores batch metadata and payloads using BCS serialization in RocksDB. The critical vulnerability lies in the deserialization path where no integrity validation occurs after loading data from disk. [1](#0-0) 

The `decode_value()` method uses only BCS deserialization, which validates structural integrity but not semantic correctness. BCS will successfully deserialize any byte sequence that matches the expected type structure, even if field values are corrupted.

When batch data is loaded from the database: [2](#0-1) [3](#0-2) 

The loaded `PersistedValue` is converted to `Batch` without validation: [4](#0-3) 

No verification occurs that the `BatchInfo.digest` matches the actual payload hash, or that `num_txns`/`num_bytes` match the actual transaction data. The corrupted batch then enters consensus through two critical paths:

1. **Batch retrieval serving** (responding to peer requests): [5](#0-4) 

2. **Inline block creation** (proposing blocks): [6](#0-5) 

RocksDB's corruption detection operates at the block level with checksums, but corruption affecting individual key-value pairs may not trigger these checks: [7](#0-6) 

**Breaking Invariants:**
- **Deterministic Execution**: Validators with corrupted vs. uncorrupted data will process different batch contents
- **Consensus Safety**: Node-specific corruption can cause validators to produce divergent blocks for the same proposal

## Impact Explanation

This qualifies as **Medium Severity** per the bug bounty criteria:
- **State inconsistencies requiring intervention**: Corrupted batch data causes validators to diverge, requiring manual intervention to identify and repair the corrupted node
- **Consensus disruption**: Affected validators will produce invalid blocks that get rejected by honest nodes, causing liveness degradation

The impact is limited because:
- Requires underlying storage corruption (hardware/software fault)
- RocksDB's block-level checksums catch most corruption patterns
- Only affects nodes experiencing corruption, not network-wide

However, the lack of application-level validation means corruption that bypasses RocksDB checksums will propagate silently into consensus logic rather than failing fast at the database layer.

## Likelihood Explanation

**Likelihood: Low to Medium**

While disk corruption is relatively rare on modern hardware with ECC memory and redundant storage, the complete absence of post-deserialization validation means that when corruption does occur:
- It will not be detected until consensus failure symptoms appear
- Debugging is significantly harder without clear error messages
- Node operators may not realize the root cause is storage corruption

Factors increasing likelihood:
- Long-running validators accumulate more exposure to bit-flip probabilities
- Power failures during writes can create partially-written data
- Some corruption patterns produce valid BCS but incorrect values (e.g., single-bit flips in numeric fields)

## Recommendation

Add integrity validation after deserializing `PersistedValue` from disk. Implement a verification step that computes the payload hash and compares it to the stored `BatchInfo.digest`:

```rust
// In consensus/src/quorum_store/quorum_store_db.rs
impl QuorumStoreStorage for QuorumStoreDB {
    fn get_batch(&self, digest: &HashValue) -> Result<Option<PersistedValue<BatchInfo>>, DbError> {
        let value = self.db.get::<BatchSchema>(digest)?;
        
        if let Some(ref persisted_value) = value {
            // Validate integrity if payload is present
            if let Some(payload) = persisted_value.payload() {
                let computed_hash = BatchPayload::new(
                    persisted_value.author(),
                    payload.clone()
                ).hash();
                
                if computed_hash != *persisted_value.digest() {
                    error!(
                        "Storage corruption detected: digest mismatch for batch {}. \
                         Expected: {}, Computed: {}",
                        digest,
                        persisted_value.digest(),
                        computed_hash
                    );
                    return Err(DbError::from(anyhow::anyhow!(
                        "Batch integrity validation failed: corrupted data detected"
                    )));
                }
            }
        }
        
        Ok(value)
    }
}
```

Apply similar validation to `get_batch_v2()` and during batch iteration in `get_all_batches()`.

## Proof of Concept

```rust
#[cfg(test)]
mod corruption_detection_test {
    use super::*;
    use aptos_crypto::HashValue;
    use aptos_types::transaction::SignedTransaction;
    
    #[test]
    fn test_corrupted_batch_detected() {
        // Setup: Create a valid PersistedValue
        let valid_batch_info = create_test_batch_info();
        let valid_payload = create_test_transactions();
        let valid_value = PersistedValue::new(
            valid_batch_info.clone(),
            Some(valid_payload.clone())
        );
        
        // Simulate corruption: Change the digest in BatchInfo without changing payload
        let mut corrupted_batch_info = valid_batch_info.clone();
        corrupted_batch_info.digest = HashValue::random(); // Simulated corruption
        let corrupted_value = PersistedValue::new(
            corrupted_batch_info,
            Some(valid_payload.clone())
        );
        
        // Current behavior: Corrupted value is accepted silently
        // This should fail but currently doesn't:
        let batch_result = Batch::try_from(corrupted_value.clone());
        assert!(batch_result.is_ok()); // Currently passes - BUG!
        
        // With fix: Should detect mismatch and fail
        // verify_persisted_value(&corrupted_value).unwrap_err();
    }
}
```

**Notes**

The vulnerability stems from architectural assumption that RocksDB's block-level checksums provide sufficient corruption detection. However, application-layer semantic validation is necessary as defense-in-depth, especially for consensus-critical data where silent corruption can cause Byzantine-like behavior from otherwise-honest validators. The fix adds minimal overhead (one hash computation per batch load) while providing strong corruption detection guarantees.

### Citations

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

**File:** consensus/src/quorum_store/quorum_store_db.rs (L119-121)
```rust
    fn get_batch(&self, digest: &HashValue) -> Result<Option<PersistedValue<BatchInfo>>, DbError> {
        Ok(self.db.get::<BatchSchema>(digest)?)
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

**File:** consensus/src/quorum_store/types.rs (L95-110)
```rust
impl<T: TBatchInfo> TryFrom<PersistedValue<T>> for Batch<T> {
    type Error = anyhow::Error;

    fn try_from(value: PersistedValue<T>) -> Result<Self, Self::Error> {
        let author = value.author();
        Ok(Batch {
            batch_info: value.info,
            payload: BatchPayload::new(
                author,
                value
                    .maybe_payload
                    .ok_or_else(|| anyhow::anyhow!("Payload not exist"))?,
            ),
        })
    }
}
```

**File:** consensus/src/quorum_store/quorum_store_builder.rs (L408-415)
```rust
                let response = if let Ok(value) =
                    batch_store.get_batch_from_local(&rpc_request.req.digest())
                {
                    let batch: Batch<BatchInfoExt> = value.try_into().unwrap();
                    let batch: Batch<BatchInfo> = batch
                        .try_into()
                        .expect("Batch retieval requests must be for V1 batch");
                    BatchResponse::Batch(batch)
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L540-543)
```rust
            if let Ok(mut persisted_value) = self.batch_store.get_batch_from_local(batch.digest()) {
                if let Some(txns) = persisted_value.take_payload() {
                    result.push((batch, txns));
                }
```

**File:** storage/schemadb/src/lib.rs (L389-407)
```rust
fn to_db_err(rocksdb_err: rocksdb::Error) -> AptosDbError {
    match rocksdb_err.kind() {
        ErrorKind::Incomplete => AptosDbError::RocksDbIncompleteResult(rocksdb_err.to_string()),
        ErrorKind::NotFound
        | ErrorKind::Corruption
        | ErrorKind::NotSupported
        | ErrorKind::InvalidArgument
        | ErrorKind::IOError
        | ErrorKind::MergeInProgress
        | ErrorKind::ShutdownInProgress
        | ErrorKind::TimedOut
        | ErrorKind::Aborted
        | ErrorKind::Busy
        | ErrorKind::Expired
        | ErrorKind::TryAgain
        | ErrorKind::CompactionTooLarge
        | ErrorKind::ColumnFamilyDropped
        | ErrorKind::Unknown => AptosDbError::OtherRocksDbError(rocksdb_err.to_string()),
    }
```

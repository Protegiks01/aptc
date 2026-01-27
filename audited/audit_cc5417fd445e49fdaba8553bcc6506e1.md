# Audit Report

## Title
Race Condition in LocalFileStoreOperator Allows Concurrent Read of Partially Written Transaction Files

## Summary
The `LocalFileStoreOperator` implementation uses non-atomic file write operations (`tokio::fs::write`) without synchronization mechanisms, allowing concurrent reads via `get_transactions()` to access partially written data during `upload_transaction_batch()` execution. This causes deserialization failures and API crashes in the indexer data service.

## Finding Description

The vulnerability exists in the local filesystem implementation of the file store operator. The race condition occurs between two unsynchronized operations:

**Write Path:** [1](#0-0) 

The upload operation spawns concurrent tasks that use `tokio::fs::write()` to write transaction files. This operation is not atomic—it writes data sequentially to the file.

**Read Path:** [2](#0-1) 

The read operation uses `tokio::fs::read()` to fetch transaction files without any synchronization or locking mechanism.

**Concurrent Access Pattern:**

The file store processor creates multiple cloned operator instances for parallel uploads: [3](#0-2) 

Simultaneously, the data service creates independent operator instances for each request: [4](#0-3) 

**No Synchronization:** A comprehensive grep search confirms there are no Mutex, RwLock, or file locking mechanisms protecting these operations in the file store operator implementations.

**Failure Mode:**

When partial data is read, the deserialization fails with panics: [5](#0-4) 

For JSON format: [6](#0-5) 

**Attack Scenario:**
1. File store processor begins uploading transaction batch for version 1000-1999
2. During write execution, data service receives client request for version 1000  
3. Data service reads the file while write is in-progress
4. Partial/corrupted bytes are returned
5. Decompression or deserialization fails with panic/error
6. API request crashes, returning error to client

## Impact Explanation

This qualifies as **High Severity** per the Aptos bug bounty criteria under "API crashes." The vulnerability can cause the indexer data service API to crash when serving requests for transaction data that is currently being written to the file store. 

While this does not affect the blockchain consensus layer, validator operations, or on-chain state, it degrades the availability and reliability of the indexer infrastructure that serves historical transaction data to ecosystem applications and users.

## Likelihood Explanation

**High Likelihood** - The race condition will occur whenever:
- The file store processor is actively uploading recent transactions (continuous operation)
- A client requests transaction data that was recently evicted from cache but is currently being written to file store
- The local filesystem implementation is used (not GCS, which has atomic object creation)

This is a realistic scenario in normal operations, especially during periods of cache pressure or when serving historical data requests.

## Recommendation

Implement atomic file writes using the write-then-rename pattern:

```rust
async fn upload_transaction_batch(
    &mut self,
    chain_id: u64,
    transactions: Vec<Transaction>,
) -> anyhow::Result<(u64, u64)> {
    // ... existing validation code ...
    
    for i in transactions.chunks(FILE_ENTRY_TRANSACTION_COUNT as usize) {
        let current_batch = i.iter().cloned().collect_vec();
        let starting_version = current_batch.first().unwrap().version;
        let file_entry = FileEntry::from_transactions(current_batch, self.storage_format);
        let file_entry_key = FileEntry::build_key(starting_version, self.storage_format).to_string();
        
        // Write to temporary file first
        let temp_path = self.path.join(format!("{}.tmp", file_entry_key));
        let final_path = self.path.join(file_entry_key.as_str());
        
        let task = tokio::spawn(async move {
            // Write to temp file
            tokio::fs::write(&temp_path, file_entry.into_inner()).await?;
            // Atomically rename to final location
            tokio::fs::rename(&temp_path, &final_path).await?;
            Ok(())
        });
        tasks.push(task);
    }
    // ... rest of implementation ...
}
```

The `rename()` operation is atomic on POSIX filesystems, ensuring readers either see the complete file or no file at all.

## Proof of Concept

```rust
use tokio;
use std::sync::Arc;
use std::path::PathBuf;

#[tokio::test]
async fn test_concurrent_write_read_race() {
    let temp_dir = tempfile::tempdir().unwrap();
    let operator = Arc::new(LocalFileStoreOperator::new(
        PathBuf::from(temp_dir.path()),
        true, // enable compression
    ));
    
    // Create test transactions
    let transactions: Vec<Transaction> = (0..1000).map(|i| {
        Transaction {
            version: i,
            // ... populate other fields ...
        }
    }).collect();
    
    let write_operator = operator.clone();
    let read_operator = operator.clone();
    
    // Spawn writer
    let writer = tokio::spawn(async move {
        write_operator.upload_transaction_batch(1, transactions).await
    });
    
    // Spawn concurrent reader attempting to read the same version
    let reader = tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
        read_operator.get_transactions(0, 3).await
    });
    
    let (write_result, read_result) = tokio::join!(writer, reader);
    
    // Race condition manifests as read error due to partial data
    if read_result.is_err() {
        println!("Race condition triggered: {:?}", read_result.unwrap_err());
    }
}
```

## Notes

**Important Context:** This vulnerability affects the indexer-grpc infrastructure, which is auxiliary to the core blockchain protocol. It does not impact consensus safety, validator operations, or on-chain state. The GCS implementation is not affected as `Object::create()` provides atomic object creation guarantees. [7](#0-6)

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator/local.rs (L58-73)
```rust
    async fn get_raw_file(&self, version: u64) -> anyhow::Result<Vec<u8>> {
        let file_entry_key = FileEntry::build_key(version, self.storage_format).to_string();
        let file_path = self.path.join(file_entry_key);
        match tokio::fs::read(file_path).await {
            Ok(file) => Ok(file),
            Err(err) => {
                if err.kind() == std::io::ErrorKind::NotFound {
                    anyhow::bail!("[Indexer File] Transactions file not found. Gap might happen between cache and file store. {}", err)
                } else {
                    anyhow::bail!(
                        "[Indexer File] Error happens when transaction file. {}",
                        err
                    );
                }
            },
        }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator/local.rs (L184-189)
```rust
            let task = tokio::spawn(async move {
                match tokio::fs::write(txns_path, file_entry.into_inner()).await {
                    Ok(_) => Ok(()),
                    Err(err) => Err(anyhow::Error::from(err)),
                }
            });
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store/src/processor.rs (L157-203)
```rust
            for start_version in batches {
                let mut cache_operator_clone = self.cache_operator.clone();
                let mut file_store_operator_clone = self.file_store_operator.clone_box();
                let task = tokio::spawn(async move {
                    let fetch_start_time = std::time::Instant::now();
                    let transactions = cache_operator_clone
                        .get_transactions(start_version, FILE_ENTRY_TRANSACTION_COUNT)
                        .await
                        .unwrap();
                    let last_transaction = transactions.last().unwrap().clone();
                    log_grpc_step(
                        SERVICE_TYPE,
                        IndexerGrpcStep::FilestoreFetchTxns,
                        Some(start_version as i64),
                        Some((start_version + FILE_ENTRY_TRANSACTION_COUNT - 1) as i64),
                        None,
                        None,
                        Some(fetch_start_time.elapsed().as_secs_f64()),
                        None,
                        Some(FILE_ENTRY_TRANSACTION_COUNT as i64),
                        None,
                    );
                    for (i, txn) in transactions.iter().enumerate() {
                        assert_eq!(txn.version, start_version + i as u64);
                    }
                    let upload_start_time = std::time::Instant::now();
                    let (start, end) = file_store_operator_clone
                        .upload_transaction_batch(chain_id, transactions)
                        .await
                        .unwrap();
                    log_grpc_step(
                        SERVICE_TYPE,
                        IndexerGrpcStep::FilestoreUploadTxns,
                        Some(start_version as i64),
                        Some((start_version + FILE_ENTRY_TRANSACTION_COUNT - 1) as i64),
                        None,
                        None,
                        Some(upload_start_time.elapsed().as_secs_f64()),
                        None,
                        Some(FILE_ENTRY_TRANSACTION_COUNT as i64),
                        None,
                    );

                    (start, end, last_transaction)
                });
                tasks.push(task);
            }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/service.rs (L170-171)
```rust
        let file_store_operator: Box<dyn FileStoreOperator> = self.file_store_config.create();
        let file_store_operator = Arc::new(file_store_operator);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/compression_util.rs (L264-272)
```rust
            FileEntry::Lz4CompressionProto(bytes) => {
                let mut decompressor = Decoder::new(&bytes[..]).expect("Lz4 decompression failed.");
                let mut decompressed = Vec::new();
                decompressor
                    .read_to_end(&mut decompressed)
                    .expect("Lz4 decompression failed.");
                TransactionsInStorage::decode(decompressed.as_slice())
                    .expect("proto deserialization failed.")
            },
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/compression_util.rs (L273-276)
```rust
            FileEntry::JsonBase64UncompressedProto(bytes) => {
                let file: TransactionsLegacyFile =
                    serde_json::from_slice(bytes.as_slice()).expect("json deserialization failed.");
                let transactions = file
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator/gcs.rs (L239-245)
```rust
        Object::create(
            bucket_name.clone().as_str(),
            file_entry.into_inner(),
            file_entry_key_path.as_str(),
            JSON_FILE_TYPE,
        )
        .await?;
```

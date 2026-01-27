# Audit Report

## Title
Non-Atomic State Updates in FileStoreOperatorV2 Causing Non-Recoverable State and Indexer Downtime

## Summary
The `dump_transactions_to_file()` function in `FileStoreOperatorV2` performs non-atomic state mutations before a potentially failing channel send operation. When the send fails (e.g., due to upload task crash), the operator enters an unrecoverable corrupted state with lost transactions and invalid metadata, forcing a process crash that causes prolonged indexer downtime.

## Finding Description

The `FileStoreOperatorV2::dump_transactions_to_file()` function violates atomicity by performing irreversible state mutations before executing an operation that can fail: [1](#0-0) 

The critical issue is the ordering of operations:

1. **Line 71**: Buffer is permanently emptied via `std::mem::take(&mut self.buffer)`
2. **Lines 73-77**: `FileMetadata` is added to `buffer_batch_metadata.files`  
3. **Line 78**: `buffer_size_in_bytes` is reset to 0
4. **Lines 80-82**: Channel send operation occurs (**CAN FAIL**)

If the channel send fails, the transactions are lost because the buffer was already emptied, and the batch metadata is corrupted with an entry for a non-existent upload. The operator cannot continue from this corrupted state.

The failure scenario is triggered when the upload task crashes. In the file store uploader, the upload task uses `.unwrap()` on the upload result: [2](#0-1) 

When `do_upload()` fails (e.g., network timeout to Google Cloud Storage), the upload task panics at line 143, dropping the channel receiver. Subsequent send attempts in `dump_transactions_to_file()` fail with "receiver dropped" error.

The main processing loop also uses `.unwrap()`: [3](#0-2) 

This causes the entire indexer task to crash when dump fails, requiring manual restart.

**Additional Data Loss Risk**: The cache immediately increments its `file_store_version` when transactions are fetched, even before they're successfully uploaded: [4](#0-3) 

Combined with the cache garbage collection that removes transactions up to `file_store_version`: [5](#0-4) 

If the cache GCs the failed transactions before recovery, those transactions become permanently unrecoverable, causing a **permanent liveness failure** where the indexer cannot progress past the gap.

## Impact Explanation

This vulnerability qualifies as **High Severity** per Aptos bug bounty criteria:

1. **Indexer Downtime**: When upload fails, the entire file store uploader task crashes and requires manual restart, causing service disruption.

2. **API Unavailability**: The indexer-grpc service becomes unavailable during downtime, affecting all downstream consumers (explorers, wallets, analytics platforms).

3. **Potential Permanent Liveness Failure**: In the worst case where cache GC occurs before recovery, the indexer becomes permanently stuck at a version gap, requiring manual intervention or database manipulation to recover.

The impact maps to the "API crashes" and "Significant protocol violations" categories under High Severity ($50,000 tier), as the indexer is a critical infrastructure component for the Aptos ecosystem.

## Likelihood Explanation

**High Likelihood** - This vulnerability is triggered by common operational failures:

1. **Network Timeouts**: Cloud storage operations (GCS) commonly experience transient failures, especially under load or during infrastructure issues.

2. **Disk Space Exhaustion**: File store writes can fail if storage quota is exceeded.

3. **Permission Errors**: Misconfigured cloud storage permissions cause write failures.

4. **Service Degradation**: During GCS service degradation, multiple consecutive failures can occur, increasing crash frequency.

These are routine operational issues in production environments, not requiring attacker interaction. The mandatory `.unwrap()` error handling guarantees that any such failure immediately crashes the indexer.

## Recommendation

Implement transactional state updates with rollback capability:

```rust
async fn dump_transactions_to_file(
    &mut self,
    end_batch: bool,
    tx: Sender<(Vec<Transaction>, BatchMetadata, bool)>,
) -> Result<()> {
    // Take transactions but keep a reference for potential rollback
    let transactions = std::mem::take(&mut self.buffer);
    let first_version = transactions.first().unwrap().version;
    let file_metadata = FileMetadata {
        first_version,
        last_version: first_version + transactions.len() as u64,
        size_bytes: self.buffer_size_in_bytes,
    };
    
    // Clone metadata before mutation
    let mut updated_batch_metadata = self.buffer_batch_metadata.clone();
    updated_batch_metadata.files.push(file_metadata);
    
    // Try to send - if this fails, we can still rollback
    match tx.send((transactions.clone(), updated_batch_metadata.clone(), end_batch)).await {
        Ok(_) => {
            // Success - commit state changes
            self.buffer_batch_metadata = updated_batch_metadata;
            self.buffer_size_in_bytes = 0;
            
            if end_batch {
                self.buffer_batch_metadata = BatchMetadata::default();
            }
            Ok(())
        }
        Err(e) => {
            // Failure - rollback by restoring transactions to buffer
            self.buffer = transactions;
            Err(anyhow::Error::msg(e))
        }
    }
}
```

Additionally, replace `.unwrap()` with proper error handling and retry logic:

```rust
// In file_store_uploader.rs main loop
for transaction in transactions {
    // Add retry logic with exponential backoff
    let mut retries = 0;
    loop {
        match file_store_operator
            .buffer_and_maybe_dump_transactions_to_file(transaction.clone(), tx.clone())
            .await 
        {
            Ok(_) => break,
            Err(e) if retries < MAX_RETRIES => {
                warn!("Failed to dump transaction, retrying: {}", e);
                tokio::time::sleep(Duration::from_secs(2u64.pow(retries))).await;
                retries += 1;
            }
            Err(e) => {
                error!("Failed to dump transaction after {} retries: {}", MAX_RETRIES, e);
                // Implement graceful shutdown instead of panic
                return Err(e);
            }
        }
    }
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use tokio::sync::mpsc::channel;
    use aptos_protos::transaction::v1::Transaction;

    #[tokio::test]
    async fn test_dump_failure_leaves_corrupted_state() {
        // Create operator with initial state
        let mut operator = FileStoreOperatorV2::new(
            1000,  // max_size_per_file
            100,   // num_txns_per_folder
            0,     // starting version
            BatchMetadata::default(),
        );
        
        // Create channel and immediately drop receiver to simulate crash
        let (tx, rx) = channel(5);
        drop(rx); // Receiver dropped - simulates upload task crash
        
        // Add transaction to buffer
        let mut transaction = Transaction::default();
        transaction.version = 0;
        operator.buffer.push(transaction);
        operator.buffer_size_in_bytes = 100;
        
        // Verify buffer has data
        assert_eq!(operator.buffer.len(), 1);
        assert_eq!(operator.buffer_size_in_bytes, 100);
        
        // Attempt dump - should fail due to dropped receiver
        let result = operator.dump_transactions_to_file(false, tx).await;
        assert!(result.is_err());
        
        // VULNERABILITY: Buffer is empty even though upload failed
        assert_eq!(operator.buffer.len(), 0);
        
        // VULNERABILITY: Buffer size was reset even though upload failed  
        assert_eq!(operator.buffer_size_in_bytes, 0);
        
        // VULNERABILITY: Batch metadata was corrupted with invalid entry
        assert_eq!(operator.buffer_batch_metadata.files.len(), 1);
        
        // Operator is now in unrecoverable state:
        // - Lost the transaction from buffer
        // - Has invalid metadata entry
        // - Cannot determine which transactions were actually uploaded
        
        println!("VULNERABILITY CONFIRMED: Operator in corrupted state after failed dump");
        println!("Buffer emptied: {}", operator.buffer.is_empty());
        println!("Invalid metadata entries: {}", operator.buffer_batch_metadata.files.len());
        println!("Transactions lost: 1");
    }
}
```

## Notes

This vulnerability exists in both the main file store uploader and the backfiller component, which uses identical error handling patterns: [6](#0-5) 

The issue is systemic across all FileStoreOperatorV2 usage patterns in the codebase. A complete fix requires both the atomic state update changes in the operator itself and proper error handling in all call sites.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator_v2/file_store_operator.rs (L66-89)
```rust
    async fn dump_transactions_to_file(
        &mut self,
        end_batch: bool,
        tx: Sender<(Vec<Transaction>, BatchMetadata, bool)>,
    ) -> Result<()> {
        let transactions = std::mem::take(&mut self.buffer);
        let first_version = transactions.first().unwrap().version;
        self.buffer_batch_metadata.files.push(FileMetadata {
            first_version,
            last_version: first_version + transactions.len() as u64,
            size_bytes: self.buffer_size_in_bytes,
        });
        self.buffer_size_in_bytes = 0;

        tx.send((transactions, self.buffer_batch_metadata.clone(), end_batch))
            .await
            .map_err(anyhow::Error::msg)?;

        if end_batch {
            self.buffer_batch_metadata = BatchMetadata::default();
        }

        Ok(())
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/file_store_uploader.rs (L138-146)
```rust
            s.spawn(async move {
                while let Some((transactions, batch_metadata, end_batch)) = rx.recv().await {
                    let bytes_to_upload = batch_metadata.files.last().unwrap().size_bytes as u64;
                    self.do_upload(transactions, batch_metadata, end_batch)
                        .await
                        .unwrap();
                    FILE_STORE_UPLOADED_BYTES.inc_by(bytes_to_upload);
                }
            });
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/file_store_uploader.rs (L167-171)
```rust
                        file_store_operator
                            .buffer_and_maybe_dump_transactions_to_file(transaction, tx.clone())
                            .await
                            .unwrap();
                    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L63-80)
```rust
    fn maybe_gc(&mut self) -> bool {
        if self.cache_size <= self.max_cache_size {
            return true;
        }

        while self.start_version < self.file_store_version.load(Ordering::SeqCst)
            && self.cache_size > self.target_cache_size
        {
            let transaction = self.transactions.pop_front().unwrap();
            self.cache_size -= transaction.encoded_len();
            self.start_version += 1;
        }

        CACHE_SIZE.set(self.cache_size as i64);
        CACHE_START_VERSION.set(self.start_version as i64);

        self.cache_size <= self.max_cache_size
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L127-135)
```rust
        if update_file_store_version {
            if !transactions.is_empty() {
                let old_version = self
                    .file_store_version
                    .fetch_add(transactions.len() as u64, Ordering::SeqCst);
                let new_version = old_version + transactions.len() as u64;
                FILE_STORE_VERSION_IN_CACHE.set(new_version as i64);
                info!("Updated file_store_version in cache to {new_version}.");
            }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-v2-file-store-backfiller/src/processor.rs (L181-188)
```rust
                                                file_store_operator
                                                    .buffer_and_maybe_dump_transactions_to_file(
                                                        transaction,
                                                        tx.clone(),
                                                    )
                                                    .await
                                                    .unwrap();
                                            }
```

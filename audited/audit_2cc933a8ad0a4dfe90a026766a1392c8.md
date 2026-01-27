# Audit Report

## Title
Race Condition in FileStoreUploader Causes Premature Cache Garbage Collection Leading to Transaction Data Loss

## Summary
A race condition exists between the `file_store_uploader` and `data_manager` tasks where the file store version counter is optimistically incremented in cache before transactions are actually persisted to storage. This allows cache garbage collection to prematurely remove transactions that have been "claimed" for upload but not yet written to disk. If the process crashes during this window, those transactions are permanently lost.

## Finding Description

The vulnerability exists in the coordination between transaction caching and file store persistence in the indexer-grpc-manager component.

**The Critical Race Condition:**

When the `file_store_uploader` task requests transactions from the cache, it sets `update_file_store_version=true`: [1](#0-0) 

This causes the cache to immediately increment its `file_store_version` counter **before** the transactions are actually persisted: [2](#0-1) 

The transactions are then sent through an asynchronous channel (with capacity 5) for upload: [3](#0-2) 

Meanwhile, the cache garbage collection logic uses `file_store_version` to determine which data can be safely removed: [4](#0-3) 

**The Vulnerability Window:**

1. FileStoreUploader requests transactions with `update_file_store_version=true`
2. Cache immediately increments `file_store_version` (e.g., from 1000 to 1100)
3. Transactions are queued in channel for async upload
4. Cache fills up (due to slow network/storage or high transaction rate)
5. `maybe_gc()` runs and removes transactions up to version 1100 (believing they're persisted)
6. **Process crashes before `do_upload()` completes**
7. Transactions 1000-1100 are lost: not in cache, never written to file store

This breaks the data durability invariant that the indexer service must maintain.

## Impact Explanation

**Severity: High**

This vulnerability causes **data loss** in the Aptos indexer infrastructure:

- **Transaction Data Loss**: Indexed transaction data can be permanently lost, breaking data availability guarantees for dApps and indexing services that depend on this infrastructure
- **Service Reliability Impact**: The indexer-grpc-manager is a critical component for the Aptos ecosystem; data loss requires reprocessing from fullnodes and causes service disruptions
- **Silent Failure**: The data loss occurs silently during crashes without explicit error indication, making it difficult to detect and recover from

According to the Aptos Bug Bounty criteria, this qualifies as **High Severity** because it causes:
- Significant protocol violations (data persistence guarantees)
- API crashes and service disruptions
- State inconsistencies requiring manual intervention

While this doesn't directly affect consensus or validator operations, the indexer service is critical infrastructure for the ecosystem.

## Likelihood Explanation

**Likelihood: Medium-High**

This vulnerability is likely to occur in production environments because:

1. **Normal Operating Conditions**: The race window exists during standard operation whenever the cache fills up and needs garbage collection
2. **Large Window**: With a channel capacity of 5 and potential network/storage delays, the window can be several seconds
3. **Default Cache Sizes**: The default cache is 5GB max / 4GB target, which can fill quickly under load
4. **Common Triggers**: Any of these can trigger the vulnerability:
   - Slow cloud storage (S3, GCS) during high load
   - Network connectivity issues
   - Process crashes (OOM, segfaults, hardware failures)
   - Deployment restarts during active upload

The default configuration makes this exploitable without any attacker action: [5](#0-4) 

## Recommendation

**Fix: Defer file_store_version increment until after successful persistence**

The `file_store_version` should only be incremented after transactions are successfully written to the file store, not when they're retrieved from cache.

**Recommended changes:**

1. **Remove optimistic version update** from `get_transactions_from_cache()`:
   - Remove the `update_file_store_version` parameter
   - Never increment `file_store_version` during cache read operations

2. **Update version only after successful upload** in `do_upload()`:
   - After `save_raw_file()` completes successfully, update the cache's `file_store_version`
   - This requires passing the DataManager reference to the upload task or using a callback mechanism

3. **Alternative: Add write-ahead logging**:
   - Mark transactions as "claimed but not persisted" in a separate tracking structure
   - Only allow GC of transactions that are fully persisted
   - On recovery, reprocess any claimed-but-not-persisted transactions

The fix ensures that `file_store_version` acts as a true lower bound for what's safely persisted, preventing premature garbage collection.

## Proof of Concept

```rust
// Reproduction scenario (pseudocode for test):
// 
// 1. Start indexer-grpc-manager with small cache (e.g., 100MB)
// 2. Configure slow file store (add artificial delays)
// 3. Send high transaction volume to fill cache
// 4. Monitor file_store_version vs actual persisted version
// 5. Crash process during upload window
// 6. Restart and verify data loss
//
// Expected: Transactions marked as "persisted" (by file_store_version)
//           but not actually in file store are lost

#[tokio::test]
async fn test_race_condition_data_loss() {
    // Setup with small cache and slow storage
    let cache_config = CacheConfig {
        max_cache_size: 100 * (1 << 20), // 100MB
        target_cache_size: 80 * (1 << 20), // 80MB
    };
    
    // Create mock file store with artificial delay
    let slow_file_store = MockSlowFileStore::new(Duration::from_secs(5));
    
    // Start data manager and file store uploader
    let data_manager = DataManager::new(/* ... with cache_config ... */);
    let file_store_uploader = FileStoreUploader::new(/* ... with slow_file_store ... */);
    
    // Spawn tasks
    tokio::spawn(data_manager.start(true, rx));
    tokio::spawn(file_store_uploader.start(data_manager.clone(), tx));
    
    // Fill cache with transactions until GC triggers
    while data_manager.cache_size() < cache_config.max_cache_size {
        // Add transactions...
    }
    
    // Record file_store_version from cache
    let version_in_cache = data_manager.get_cache_file_store_version();
    
    // Record actual persisted version
    let version_in_storage = file_store_uploader.get_actual_persisted_version();
    
    // Assert there's a gap (race window exists)
    assert!(version_in_cache > version_in_storage);
    
    // Simulate crash
    drop(data_manager);
    drop(file_store_uploader);
    
    // Restart and verify data loss
    let recovered_data_manager = DataManager::new(/* ... */);
    let recovered_version = recovered_data_manager.get_file_store_version().await;
    
    // Data loss: cache version was ahead, but data was never persisted
    assert_eq!(recovered_version, version_in_storage);
    assert!(recovered_version < version_in_cache);
    
    // Transactions in range [version_in_storage, version_in_cache) are lost
}
```

**Notes:**

1. **Component Context**: This vulnerability is in the indexer-grpc infrastructure, not the core consensus/execution layer. However, it affects critical ecosystem infrastructure that dApps and services depend on.

2. **Master Node Only**: The vulnerability only affects the master indexer-grpc-manager node (where `is_master=true`), as only the master runs the file store uploader: [6](#0-5) 

3. **Channel Buffering Amplifies Risk**: The channel capacity of 5 means up to 5 batches of transactions can be "in flight" between cache removal and actual persistence, significantly increasing the data loss window.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/file_store_uploader.rs (L137-146)
```rust
            let (tx, mut rx) = channel::<(_, BatchMetadata, _)>(5);
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

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/file_store_uploader.rs (L157-163)
```rust
                        data_manager
                            .get_transactions_from_cache(
                                next_version,
                                MAX_SIZE_PER_FILE,
                                /*update_file_store_version=*/ true,
                            )
                            .await
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L62-74)
```rust
    // NOTE: This will only gc data up to the file store version.
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
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L127-134)
```rust
        if update_file_store_version {
            if !transactions.is_empty() {
                let old_version = self
                    .file_store_version
                    .fetch_add(transactions.len() as u64, Ordering::SeqCst);
                let new_version = old_version + transactions.len() as u64;
                FILE_STORE_VERSION_IN_CACHE.set(new_version as i64);
                info!("Updated file_store_version in cache to {new_version}.");
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/config.rs (L44-49)
```rust
const fn default_cache_config() -> CacheConfig {
    CacheConfig {
        max_cache_size: 5 * (1 << 30),
        target_cache_size: 4 * (1 << 30),
    }
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/grpc_manager.rs (L112-121)
```rust
            if self.is_master {
                s.spawn(async move {
                    self.file_store_uploader
                        .lock()
                        .await
                        .start(self.data_manager.clone(), tx)
                        .await
                        .unwrap();
                });
            }
```

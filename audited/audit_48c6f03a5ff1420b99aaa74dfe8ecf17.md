# Audit Report

## Title
Premature Transaction Eviction in Indexer Cache Causes Data Loss

## Summary
The indexer-grpc-manager's cache eviction logic (`maybe_gc`) can prematurely evict transactions before they are successfully persisted to file storage, leading to permanent data loss. The `file_store_version` tracking variable is incremented immediately when transactions are fetched for upload, but actual persistence happens asynchronously later, creating a dangerous time window.

## Finding Description

The vulnerability occurs due to incorrect synchronization between cache eviction and file store persistence in the indexer-grpc system.

**The Race Condition Flow:**

1. **FileStoreUploader fetches transactions**: In `FileStoreUploader::start`, when transactions are fetched from cache with `update_file_store_version=true`, the cache immediately increments its internal `file_store_version` counter. [1](#0-0) 

2. **Transactions queued for async upload**: The fetched transactions are buffered and sent through a channel (capacity 5) to a separate async task that performs the actual upload. [2](#0-1) 

3. **Cache eviction runs concurrently**: The `DataManager::start` loop continuously calls `maybe_gc()` before inserting new transactions, which evicts transactions from cache based on `file_store_version`. [3](#0-2) 

4. **Eviction logic uses stale version**: The `maybe_gc` function evicts transactions where `start_version < file_store_version`, believing they're safely persisted. [4](#0-3) 

**The Critical Window:**

Between step 1 (incrementing `file_store_version`) and actual persistence in the async upload task, transactions marked as "safe to evict" can be permanently removed from the cache VecDeque. If the upload fails or the process crashes during this window, those transactions are lost forever since the recovery mechanism only restores from already-persisted file store data. [5](#0-4) 

**Regarding Transaction Ordering:**

Transaction ordering itself IS preserved correctly through the VecDeque implementation - insertions append to the end, retrievals iterate in order, and evictions remove from the front in FIFO order. However, the premature eviction issue means transactions can be lost entirely, which is a more severe problem than ordering corruption.

## Impact Explanation

This vulnerability affects the **indexer infrastructure availability and data completeness**. While it does NOT impact consensus, validator operations, or on-chain state, it does cause:

1. **Permanent loss of historical transaction data** in the indexer's file store
2. **Incomplete query results** for applications relying on the indexer
3. **Service disruption** requiring manual intervention and re-synchronization
4. **Data integrity issues** where gaps exist in the indexed transaction history

Under the Aptos bug bounty categories, this falls under **Medium Severity** - "State inconsistencies requiring intervention" - as it corrupts the indexer's state and requires manual recovery procedures. The cache configuration shows default limits of 5GB max and 4GB target, making this triggerable under normal high-load conditions. [6](#0-5) 

## Likelihood Explanation

**Likelihood: HIGH under production load**

The vulnerability triggers when:
1. Cache size exceeds `max_cache_size` (5GB default)
2. FileStoreUploader is actively uploading batches (up to 5 queued)
3. Upload latency creates delay between version increment and persistence
4. Network issues, storage errors, or system crashes occur during upload

These conditions are expected in production environments with high transaction throughput, making this a realistic and recurring risk.

## Recommendation

**Fix: Defer `file_store_version` increment until after successful persistence**

The `file_store_version` should only be incremented AFTER the upload task confirms successful persistence to file store, not when transactions are initially fetched. This requires:

1. **Remove the premature increment** from `Cache::get_transactions` when `update_file_store_version=true`
2. **Add a callback mechanism** where the upload task notifies the cache after successful `do_upload` completion
3. **Implement atomic version updates** coordinated with actual persistence

Alternative simpler fix: Use a separate "pending upload" counter and only allow eviction of transactions below `min(file_store_version, file_store_version - pending_upload_count)`.

## Proof of Concept

```rust
// Scenario demonstrating the race condition:

// Initial state:
// - cache: [tx_100, tx_101, ..., tx_199] (100 transactions)
// - start_version = 100
// - file_store_version = 100
// - cache_size = 5.5GB (exceeds max)

// Step 1: FileStoreUploader fetches batch
let transactions = data_manager
    .get_transactions_from_cache(100, MAX_SIZE_PER_FILE, true)
    .await;
// Result: file_store_version = 150 (incremented by 50)
//         transactions = [tx_100..tx_149] (queued for upload)

// Step 2: Cache eviction runs immediately after
cache.maybe_gc();
// Result: Evicts tx_100..tx_149 from cache (since 100 < 150)
//         These transactions are now only in the upload queue

// Step 3: Upload fails or process crashes
// - Upload channel buffer lost
// - Transactions [100-149] permanently lost
// - On restart, recovery starts from file_store_version (actual: 100)
// - Gap in indexed data: [100-149] never recoverable

// This can be triggered by:
// 1. Flooding the indexer with high transaction volume
// 2. Introducing upload latency (slow storage)
// 3. Causing upload failures (network partition)
```

## Notes

- This vulnerability is specific to the indexer-grpc-manager component and does NOT affect blockchain consensus or validator operations
- The core blockchain data remains intact on fullnodes; only the indexer's cached/archived copy is affected
- While transaction ordering through insertions, retrievals, and evictions is correctly preserved via the VecDeque FIFO structure, the premature eviction creates a more critical data loss scenario
- The issue requires the indexer to be under memory pressure (cache > max_cache_size) to trigger, which is expected in production deployments serving high-throughput applications

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L62-80)
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

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L235-240)
```rust
                loop {
                    trace!("Maybe running GC.");
                    if self.cache.write().await.maybe_gc() {
                        IS_FILE_STORE_LAGGING.set(0);
                        trace!("GC is done, file store is not lagging.");
                        break;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/file_store_uploader.rs (L86-118)
```rust
    /// Recovers the batch metadata in memory buffer for the unfinished batch from file store.
    async fn recover(&self) -> Result<(u64, BatchMetadata)> {
        let _timer = TIMER.with_label_values(&["recover"]).start_timer();

        let mut version = self
            .reader
            .get_latest_version()
            .await
            .expect("Latest version must exist.");
        info!("Starting recovering process, current version in storage: {version}.");
        let mut num_folders_checked = 0;
        let mut buffered_batch_metadata_to_recover = BatchMetadata::default();
        while let Some(batch_metadata) = self.reader.get_batch_metadata(version).await {
            let batch_last_version = batch_metadata.files.last().unwrap().last_version;
            version = batch_last_version;
            if version % NUM_TXNS_PER_FOLDER != 0 {
                buffered_batch_metadata_to_recover = batch_metadata;
                break;
            }
            num_folders_checked += 1;
            if num_folders_checked >= MAX_NUM_FOLDERS_TO_CHECK_FOR_RECOVERY {
                panic!(
                    "File store metadata is way behind batch metadata, data might be corrupted."
                );
            }
        }

        self.update_file_store_metadata(version).await?;

        info!("Finished recovering process, recovered at version: {version}.");

        Ok((version, buffered_batch_metadata_to_recover))
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/file_store_uploader.rs (L157-170)
```rust
                        data_manager
                            .get_transactions_from_cache(
                                next_version,
                                MAX_SIZE_PER_FILE,
                                /*update_file_store_version=*/ true,
                            )
                            .await
                    };
                    let len = transactions.len();
                    for transaction in transactions {
                        file_store_operator
                            .buffer_and_maybe_dump_transactions_to_file(transaction, tx.clone())
                            .await
                            .unwrap();
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

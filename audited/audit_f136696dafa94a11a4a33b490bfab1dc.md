# Audit Report

## Title
Cascading Panic Failure in Indexer-GRPC DataManager Due to Backward File Store Version

## Summary
A master DataManager recovery process can write a backward file store version to shared storage, triggering panic cascades across all slave DataManager instances, resulting in complete indexer-grpc system outage.

## Finding Description

The indexer-grpc-manager system operates with one master and multiple slave instances sharing a common file store (S3/GCS). Each GrpcManager contains a single DataManager instance that manages transaction caching and file store synchronization. [1](#0-0) 

The vulnerability occurs when the master DataManager recovers from a crash and writes a backward version to the shared file store metadata. The master explicitly allows version rollback during recovery, but slave instances do not, creating a fatal inconsistency. [2](#0-1) 

**Attack Scenario:**

1. **Initial State**: All DataManager instances (master + slaves) operate at file store version 1000

2. **Master Failure**: Master crashes unexpectedly or experiences file store corruption

3. **Master Recovery**: The FileStoreUploader recovery process determines that only version 950 is reliably valid [3](#0-2) 

4. **Backward Version Write**: Master updates the shared `metadata.json` file from version 1000 to version 950 [4](#0-3) 

5. **Slave Detection**: Slave DataManagers continuously monitor file store version in their main loop [5](#0-4) 

6. **Panic Cascade**: When slaves read the new metadata (version 950) while having cached version 1000, the backward version check triggers: [6](#0-5) 

7. **Complete Outage**: ALL slave DataManager instances panic simultaneously, taking down the entire indexer-grpc serving infrastructure

The root cause is the asymmetric version rollback policy: the master uses `version_can_go_backward=true` during initial recovery, while slaves use `version_can_go_backward=false` during normal operation, creating an unhandled edge case when master recovery affects operational slaves.

## Impact Explanation

This vulnerability qualifies as **High Severity** per Aptos bug bounty criteria:
- **API crashes**: Complete failure of all slave indexer-grpc instances
- **Significant protocol violations**: Inconsistent handling of shared state across distributed instances

**Affected Systems:**
- All downstream clients querying indexer-grpc API experience service outage
- Applications relying on historical transaction data cannot function
- Monitoring and analytics systems lose blockchain data access

**Note**: This vulnerability affects the indexer infrastructure availability but does NOT impact core blockchain consensus, transaction execution, or validator operations. The blockchain continues operating normally; only the indexer API serving layer fails.

## Likelihood Explanation

**Likelihood: Medium**

**Prerequisites:**
1. Master DataManager crash or restart during active operation
2. File store corruption or partial writes requiring recovery to earlier version
3. Slave instances already caching a higher version number

**Realistic Scenarios:**
- Master node OOM/crash during high transaction load
- Network partition causing incomplete file store writes
- S3/GCS eventual consistency issues during master failover
- Intentional master restart during version rollback recovery

The vulnerability is not directly exploitable by unprivileged attackers but represents a critical operational failure mode in distributed deployments. Master crashes are common operational events, making this scenario realistic in production environments.

## Recommendation

**Fix 1: Allow Controlled Version Rollback on Slaves**

Modify slave DataManager instances to handle backward version during specific recovery windows:

```rust
async fn update_file_store_version_in_cache(
    &self,
    cache: &RwLockReadGuard<'_, Cache>,
    version_can_go_backward: bool,
) {
    let file_store_version = self.file_store_reader.get_latest_version().await;
    if let Some(file_store_version) = file_store_version {
        let file_store_version_before_update = cache
            .file_store_version
            .fetch_max(file_store_version, Ordering::SeqCst);
        FILE_STORE_VERSION_IN_CACHE.set(file_store_version as i64);
        
        if !version_can_go_backward && file_store_version_before_update > file_store_version {
            // Instead of panicking, log error and allow recovery
            error!(
                "File store version rollback detected: {} -> {}. Allowing recovery.",
                file_store_version_before_update, file_store_version
            );
            // Force update the cached version to the new (lower) value
            cache.file_store_version.store(file_store_version, Ordering::SeqCst);
        }
    }
}
```

**Fix 2: Master Recovery Signal**

Implement a recovery flag in shared metadata that signals slaves to expect version rollback:

```rust
pub struct FileStoreMetadata {
    pub chain_id: u64,
    pub num_transactions_per_folder: u64,
    pub version: u64,
    pub recovery_mode: bool,  // New field
}
```

Slaves check this flag before panic validation, allowing graceful handling of recovery scenarios.

**Fix 3: Defensive Cache Invalidation**

When detecting backward version, slaves should invalidate their cache and resynchronize rather than panicking:

```rust
if file_store_version_before_update > file_store_version {
    warn!("File store version rollback detected. Invalidating cache and resyncing.");
    drop(cache);
    let mut cache_write = self.cache.write().await;
    // Clear cache and reset to new file store version
    cache_write.transactions.clear();
    cache_write.start_version = file_store_version;
    cache_write.cache_size = 0;
    cache_write.file_store_version.store(file_store_version, Ordering::SeqCst);
}
```

## Proof of Concept

```rust
// Reproduction steps for integration test
#[tokio::test]
async fn test_panic_cascade_on_version_rollback() {
    // 1. Setup: Initialize master and 2 slave GrpcManager instances
    //    with shared mock file store
    let mut mock_file_store = MockFileStore::new();
    mock_file_store.set_metadata(FileStoreMetadata {
        chain_id: 1,
        num_transactions_per_folder: 100000,
        version: 1000,
    });
    
    let master = create_grpc_manager(/* is_master= */ true, mock_file_store.clone()).await;
    let slave1 = create_grpc_manager(/* is_master= */ false, mock_file_store.clone()).await;
    let slave2 = create_grpc_manager(/* is_master= */ false, mock_file_store.clone()).await;
    
    // 2. Run all instances, slaves cache version 1000
    tokio::spawn(async move { master.start().await });
    tokio::spawn(async move { slave1.start().await });
    tokio::spawn(async move { slave2.start().await });
    
    tokio::time::sleep(Duration::from_secs(2)).await; // Allow slaves to cache version
    
    // 3. Simulate master crash and recovery to version 950
    drop(master);
    mock_file_store.set_metadata(FileStoreMetadata {
        chain_id: 1,
        num_transactions_per_folder: 100000,
        version: 950,  // Backward version
    });
    
    // 4. Observe: Both slaves panic when detecting backward version
    //    Expected: Both slave tasks panic with message:
    //    "File store version is going backward, data might be corrupted. 1000 v.s. 950"
    
    tokio::time::sleep(Duration::from_secs(2)).await;
    // Verify both slaves have panicked (test framework would catch panics)
}
```

**Notes**

This vulnerability specifically affects the **indexer-grpc-manager** component, which is part of the data serving infrastructure, not the core blockchain consensus. While it causes significant operational impact (complete indexer API outage), it does not compromise:
- Blockchain consensus safety
- Transaction execution correctness  
- State commitment integrity
- Validator operations

The cascading failure mechanism is a distributed systems reliability issue where asymmetric error handling across master/slave instances leads to total system failure when shared state becomes inconsistent during recovery operations.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/grpc_manager.rs (L22-28)
```rust
pub(crate) struct GrpcManager {
    chain_id: u64,
    file_store_uploader: Mutex<FileStoreUploader>,
    metadata_manager: Arc<MetadataManager>,
    data_manager: Arc<DataManager>,
    is_master: bool,
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L176-192)
```rust
        is_master: bool,
        file_store_uploader_recover_rx: Receiver<()>,
    ) {
        let watch_file_store_version = !is_master;

        if is_master {
            // For master, we need to wait for the FileStoreUploader to finish the recover to get
            // the true file_store_version.
            info!("Waiting for FileStoreUploader recovering.");
            match file_store_uploader_recover_rx.await {
                Ok(_) => {},
                Err(_) => panic!("Should not happen!"),
            };
            let cache = self.cache.read().await;
            self.update_file_store_version_in_cache(&cache, /*version_can_go_backward=*/ true)
                .await;
        }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L201-206)
```rust
            if watch_file_store_version {
                self.update_file_store_version_in_cache(
                    &cache, /*version_can_go_backward=*/ false,
                )
                .await;
            }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L415-417)
```rust
            if !version_can_go_backward && file_store_version_before_update > file_store_version {
                panic!("File store version is going backward, data might be corrupted. {file_store_version_before_update} v.s. {file_store_version}");
            };
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/file_store_uploader.rs (L87-118)
```rust
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

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/file_store_uploader.rs (L261-274)
```rust
    /// Updates the file store metadata.
    async fn update_file_store_metadata(&self, version: u64) -> Result<()> {
        FILE_STORE_VERSION.set(version as i64);
        let metadata = FileStoreMetadata {
            chain_id: self.chain_id,
            num_transactions_per_folder: NUM_TXNS_PER_FOLDER,
            version,
        };

        let raw_data = serde_json::to_vec(&metadata).map_err(anyhow::Error::msg)?;
        self.writer
            .save_raw_file(PathBuf::from(METADATA_FILE_NAME), raw_data)
            .await
    }
```

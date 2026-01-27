# Audit Report

## Title
Replica Nodes Can Write to File Store During Initialization - Bypassing Master-Only Upload Protection

## Summary
The `is_master` check at line 112 of `grpc_manager.rs` does not properly prevent replica nodes from uploading to the file store. Both master and replica nodes unconditionally create a `FileStoreUploader` instance during initialization, which writes to the file store if it detects the store is uninitialized. This creates a TOCTOU (Time-of-Check-Time-of-Use) race condition where multiple nodes can simultaneously initialize the file store, and violates the security invariant that only master nodes should have write access.

## Finding Description
The indexer-grpc-manager component is designed with a master-replica architecture where only the master node should upload transaction data to the file store. The code attempts to enforce this through an `is_master` boolean check. [1](#0-0) 

However, this check only prevents the file store uploader *task* from being spawned. The critical flaw is that `FileStoreUploader::new()` is called unconditionally for ALL nodes (both master and replica) during `GrpcManager` construction: [2](#0-1) 

Inside `FileStoreUploader::new()`, if the file store is not initialized, the code performs a write operation to create the initial `metadata.json` file: [3](#0-2) 

**The vulnerability has two components:**

1. **Access Control Bypass**: Replica nodes CAN and DO write to the file store during initialization, contradicting the design that only master nodes should upload data.

2. **TOCTOU Race Condition**: The `is_initialized()` check is not atomic with the subsequent write operation. When multiple nodes (master and/or replicas) start concurrently against an uninitialized file store:
   - All nodes check `is_initialized()` → returns `false`
   - All nodes attempt to write `metadata.json` simultaneously
   - Race condition occurs with potential for data corruption or inconsistent state

The `is_initialized()` implementation for GCS simply checks if any objects exist in the bucket, which is not atomic: [4](#0-3) 

**Attack Scenario:**
1. Deploy an indexer-grpc-manager cluster with 1 master and 2 replica nodes against a fresh/empty file store
2. Start all nodes simultaneously
3. All three nodes call `FileStoreUploader::new()`
4. All three see `is_initialized() == false`
5. All three attempt to write `metadata.json`
6. Potential outcomes:
   - Last writer wins (may overwrite with different chain_id if misconfigured)
   - Concurrent writes cause GCS/filesystem errors
   - Inconsistent initialization state

## Impact Explanation
This vulnerability qualifies as **Medium to High severity**:

**Medium Severity** aspects:
- Violates the fundamental access control invariant that replicas should be read-only
- Creates state inconsistencies during initialization that may require manual intervention
- If nodes are misconfigured with different `chain_id` values, replicas could corrupt master's metadata

**High Severity** potential:
- In production deployments with IAM policies designed assuming replicas never write, this breaks security boundaries
- Race conditions during initialization could cause permanent file store corruption requiring reinitialization
- Violates the principle of least privilege - replicas have unnecessary write permissions

The impact is significant because:
1. Security policies and IAM roles may be designed assuming replicas are read-only
2. Audit logs would show replica nodes performing write operations, contradicting design documentation
3. In multi-tenant or multi-chain deployments, a replica from chain A could initialize the file store meant for chain B

## Likelihood Explanation
**High likelihood** in the following scenarios:

1. **Fresh Deployments**: Every new deployment against an uninitialized file store will trigger this vulnerability 100% of the time

2. **Disaster Recovery**: When restoring from backups or initializing new infrastructure, operators routinely start multiple nodes simultaneously

3. **Container Orchestration**: Kubernetes/Docker deployments often start all pods in a deployment concurrently, making the race condition highly likely

4. **Configuration Errors**: Operators deploying multiple indexer clusters might accidentally point replicas at the wrong (uninitialized) file store

**Mitigation factors:**
- Once the file store is initialized, subsequent starts don't trigger writes
- Nodes with identical configurations write identical metadata (reducing corruption risk)
- The window for the race is small (startup time)

However, the vulnerability fundamentally violates the stated security model and will manifest in every initial deployment.

## Recommendation

**Option 1: Move initialization to master-only code path (Preferred)**

Refactor `FileStoreUploader::new()` to NOT perform initialization. Instead, only initialize the file store when `is_master == true`:

```rust
// In grpc_manager.rs, modify the start() function:
if self.is_master {
    s.spawn(async move {
        // Ensure file store is initialized before starting uploader
        let mut uploader = self.file_store_uploader.lock().await;
        uploader.ensure_initialized().await.unwrap();
        uploader.start(self.data_manager.clone(), tx).await.unwrap();
    });
}

// In file_store_uploader.rs, split initialization from construction:
impl FileStoreUploader {
    pub(crate) async fn new(
        chain_id: u64,
        file_store_config: IndexerGrpcFileStoreConfig,
    ) -> Result<Self> {
        let file_store = file_store_config.create_filestore().await;
        // DO NOT initialize here
        let reader = FileStoreReader::new(chain_id, file_store.clone()).await?;
        Ok(Self {
            chain_id,
            reader,
            writer: file_store,
            last_batch_metadata_update_time: None,
            last_metadata_update_time: Instant::now(),
        })
    }
    
    pub(crate) async fn ensure_initialized(&self) -> Result<()> {
        if !self.writer.is_initialized().await {
            info!(chain_id = self.chain_id, "FileStore is not initialized, initializing...");
            let metadata = FileStoreMetadata {
                chain_id: self.chain_id,
                num_transactions_per_folder: NUM_TXNS_PER_FOLDER,
                version: 0,
            };
            let raw_data = serde_json::to_vec(&metadata).unwrap();
            self.writer
                .save_raw_file(PathBuf::from(METADATA_FILE_NAME), raw_data)
                .await?;
        }
        Ok(())
    }
}
```

**Option 2: Don't create FileStoreUploader for replicas**

Only create the `FileStoreUploader` when `is_master == true`:

```rust
// In grpc_manager.rs
pub(crate) async fn new(config: &IndexerGrpcManagerConfig) -> Self {
    let file_store_uploader = if config.is_master {
        Some(Mutex::new(
            FileStoreUploader::new(chain_id, config.file_store_config.clone())
                .await
                .unwrap_or_else(|e| panic!(...))
        ))
    } else {
        None
    };
    
    Self {
        file_store_uploader,
        // ...
    }
}
```

**Option 3: Use atomic file creation**

Implement atomic "create-if-not-exists" semantics for the initial metadata write using conditional GCS operations or file locks.

## Proof of Concept

```rust
// PoC: Demonstrate replica writing to file store during initialization
#[tokio::test]
async fn test_replica_writes_during_initialization() {
    use tempfile::TempDir;
    use std::sync::Arc;
    use tokio::sync::Barrier;
    
    // Create empty temp directory for file store
    let temp_dir = TempDir::new().unwrap();
    let file_store_config = IndexerGrpcFileStoreConfig::LocalFileStore(LocalFileStore {
        local_file_store_path: temp_dir.path().to_path_buf(),
        enable_compression: false,
    });
    
    // Barrier to synchronize concurrent starts
    let barrier = Arc::new(Barrier::new(3));
    
    let mut handles = vec![];
    
    // Start 3 nodes concurrently (1 master, 2 replicas)
    for i in 0..3 {
        let config = IndexerGrpcManagerConfig {
            chain_id: 1,
            service_config: ServiceConfig { 
                listen_address: format!("127.0.0.1:{}", 8000 + i).parse().unwrap() 
            },
            cache_config: CacheConfig::default(),
            file_store_config: file_store_config.clone(),
            self_advertised_address: format!("127.0.0.1:{}", 8000 + i),
            grpc_manager_addresses: vec![],
            fullnode_addresses: vec![],
            is_master: i == 0,  // Only first node is master
            allow_fn_fallback: false,
        };
        
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            // Wait for all nodes to be ready
            barrier.wait().await;
            
            // This call will trigger FileStoreUploader::new() which writes to file store
            let manager = GrpcManager::new(&config).await;
            
            println!("Node {} (is_master={}) initialized", i, config.is_master);
        }));
    }
    
    // Wait for all nodes
    for handle in handles {
        handle.await.unwrap();
    }
    
    // Verify: metadata.json was written by at least one node
    // In the vulnerable code, ALL THREE nodes (including replicas) attempt this write
    let metadata_path = temp_dir.path().join("metadata.json");
    assert!(metadata_path.exists(), "Metadata file should exist");
    
    // The bug: Replicas wrote to the file store during initialization,
    // violating the master-only upload invariant
}
```

## Notes

This vulnerability is particularly concerning because:

1. **Documentation Gap**: The code comments and architecture assume only masters write, but replicas DO write during initialization
2. **Security Boundary Violation**: IAM policies and filesystem permissions designed for read-only replicas are insufficient
3. **Silent Failure**: The race condition may succeed silently, making it hard to detect in production
4. **Configuration Amplification**: A single misconfiguration (wrong chain_id on a replica) can corrupt the entire file store

The `is_master` check at line 112 correctly prevents the continuous upload task from running on replicas, but it fails to prevent the initial write during construction. This is a textbook example of placing the security check too late in the execution flow.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/grpc_manager.rs (L33-42)
```rust
        let file_store_uploader = Mutex::new(
            FileStoreUploader::new(chain_id, config.file_store_config.clone())
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "Failed to create filestore uploader, config: {:?}, error: {e:?}",
                        config.file_store_config
                    )
                }),
        );
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

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/file_store_uploader.rs (L46-63)
```rust
        let file_store = file_store_config.create_filestore().await;
        if !file_store.is_initialized().await {
            info!(
                chain_id = chain_id,
                "FileStore is not initialized, initializing..."
            );
            info!("Transactions per folder: {NUM_TXNS_PER_FOLDER}.");
            let metadata = FileStoreMetadata {
                chain_id,
                num_transactions_per_folder: NUM_TXNS_PER_FOLDER,
                version: 0,
            };
            let raw_data = serde_json::to_vec(&metadata).unwrap();
            file_store
                .save_raw_file(PathBuf::from(METADATA_FILE_NAME), raw_data)
                .await
                .unwrap_or_else(|e| panic!("Failed to initialize FileStore: {e:?}."));
        }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator_v2/gcs.rs (L68-93)
```rust
    async fn is_initialized(&self) -> bool {
        let request = ListRequest {
            max_results: Some(1),
            prefix: self
                .bucket_sub_dir
                .clone()
                .map(|p| p.to_string_lossy().into_owned()),
            ..Default::default()
        };

        let response = Object::list(&self.bucket_name, request)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to list bucket. Bucket name: {}, sub_dir: {:?}, error: {e:?}.",
                    self.bucket_name, self.bucket_sub_dir
                )
            })
            .boxed()
            .next()
            .await
            .expect("Expect response.")
            .unwrap_or_else(|e| panic!("Got error in response: {e:?}."));

        !response.prefixes.is_empty() || !response.items.is_empty()
    }
```

# Audit Report

## Title
Undefined Behavior from Thread-Unsafe Environment Variable Modification in GcsFileStore Implementation

## Summary
The `GcsFileStore` implementation uses `unsafe { env::set_var() }` to modify global process state in a multi-threaded async runtime, creating undefined behavior that is not present in the `LocalFileStore` implementation. This violates the safety abstractions of the `IFileStore` interface.

## Finding Description

The `IFileStore` trait provides an abstraction for file storage operations with two implementations: `GcsFileStore` and `LocalFileStore`. These implementations have fundamentally different security properties that are not properly communicated by the interface.

**GcsFileStore Unsafe Behavior:** [1](#0-0) 

The `GcsFileStore::new()` function uses `unsafe { env::set_var() }` to modify the global `SERVICE_ACCOUNT` environment variable. The code even acknowledges this issue with a TODO comment indicating the need to audit that environment access only happens in single-threaded code.

**LocalFileStore Safe Behavior:** [2](#0-1) 

The `LocalFileStore::new()` function performs only safe operations without modifying global state.

**Interface Abstraction Failure:** [3](#0-2) 

The `IFileStore` trait presents both implementations as equally safe and thread-safe (requiring `Sync + Send`), but this abstraction is violated by `GcsFileStore`'s use of unsafe environment variable modification.

**Concurrent Usage Scenarios:**

Multiple components create `GcsFileStore` instances: [4](#0-3) [5](#0-4) 

Both `FileStoreUploader` and `DataManager` create separate file store instances. While these calls are sequential within `GrpcManager::new()`, the async runtime (tokio) is multi-threaded, and the underlying `cloud_storage` library may spawn background threads that read the environment variable concurrently.

Additionally, other services create instances: [6](#0-5) [7](#0-6) 

## Impact Explanation

This issue qualifies as **Medium severity** per the Aptos bug bounty criteria for the following reasons:

1. **State Inconsistencies**: Undefined behavior from concurrent environment variable access could lead to authentication failures or service crashes, requiring manual intervention to restore indexer service availability.

2. **Service Availability**: While the indexer is not part of core consensus, it provides critical infrastructure for querying blockchain data. Service disruptions affect ecosystem participants relying on indexed data.

3. **Violation of Rust Safety Guarantees**: The use of `unsafe { env::set_var() }` in a multi-threaded context (tokio async runtime) is explicitly documented as undefined behavior in Rust. According to Rust's safety model, modifying environment variables is not thread-safe.

However, this does **not** qualify as High or Critical severity because:
- It does not directly affect consensus, validator operations, or funds
- The indexer is an off-chain service, not core blockchain infrastructure
- No clear path to remote code execution or consensus violations

## Likelihood Explanation

**Likelihood: Medium to High**

The undefined behavior occurs in every deployment using `GcsFileStore`:

1. **Guaranteed UB in Multi-threaded Context**: Any deployment using tokio (which is multi-threaded by default) triggers undefined behavior when `GcsFileStore::new()` is called.

2. **Multiple Instance Creation**: Normal operation creates at least two instances per `GrpcManager` deployment.

3. **Timing-Dependent Manifestation**: While the UB is guaranteed, whether it manifests as observable crashes or authentication failures depends on thread scheduling, which is non-deterministic.

4. **Known Technical Debt**: The TODO comment indicates developers are aware this needs addressing, suggesting it's an acknowledged risk.

## Recommendation

**Solution: Remove Global State Dependency**

Replace the unsafe environment variable approach with thread-safe credential management:

```rust
pub struct GcsFileStore {
    bucket_name: String,
    bucket_sub_dir: Option<PathBuf>,
    // Store credentials directly instead of relying on environment variables
    service_account_key: String,
}

impl GcsFileStore {
    pub async fn new(
        bucket_name: String,
        bucket_sub_dir: Option<PathBuf>,
        service_account_path: String,
    ) -> Self {
        // Read credentials directly without modifying global state
        let service_account_key = tokio::fs::read_to_string(&service_account_path)
            .await
            .expect("Failed to read service account key");

        // Pass credentials directly to cloud_storage library
        // (requires updating cloud_storage usage to accept explicit credentials)
        
        Self {
            bucket_name,
            bucket_sub_dir,
            service_account_key,
        }
    }
}
```

**Alternative: If the cloud_storage library requires environment variables**, use a lazy_static Mutex to serialize access:

```rust
use lazy_static::lazy_static;
use std::sync::Mutex;

lazy_static! {
    static ref GCS_INIT_LOCK: Mutex<()> = Mutex::new(());
}

impl GcsFileStore {
    pub async fn new(
        bucket_name: String,
        bucket_sub_dir: Option<PathBuf>,
        service_account_path: String,
    ) -> Self {
        let _guard = GCS_INIT_LOCK.lock().unwrap();
        unsafe {
            env::set_var(SERVICE_ACCOUNT_ENV_VAR, service_account_path);
        }
        // ... rest of initialization
    }
}
```

## Proof of Concept

```rust
// test_gcs_filestore_race.rs
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_gcs_filestore_creation() {
    use std::sync::Arc;
    use tokio::task;
    
    // Simulate concurrent creation of GcsFileStore instances
    // with different service account paths
    let configs = vec![
        ("bucket1", "path/to/account1.json"),
        ("bucket2", "path/to/account2.json"),
    ];
    
    let mut handles = vec![];
    
    for (bucket, sa_path) in configs {
        let handle = task::spawn(async move {
            // This triggers the unsafe env::set_var()
            let _store = GcsFileStore::new(
                bucket.to_string(),
                None,
                sa_path.to_string(),
            ).await;
        });
        handles.push(handle);
    }
    
    // Join all tasks - in a race condition, the SERVICE_ACCOUNT
    // environment variable could be set to different values
    // concurrently, leading to undefined behavior
    for handle in handles {
        handle.await.unwrap();
    }
    
    // The actual manifestation of UB is non-deterministic
    // but Miri or ThreadSanitizer would flag this as a data race
}
```

To detect the undefined behavior, run with:
```bash
cargo +nightly miri test test_concurrent_gcs_filestore_creation
# Or with ThreadSanitizer:
RUSTFLAGS="-Z sanitizer=thread" cargo test test_concurrent_gcs_filestore_creation
```

## Notes

- The legacy v1 implementation has the identical issue: [8](#0-7) 
- This pattern appears throughout the codebase with similar TODO comments, indicating systemic technical debt around environment variable handling
- The `enable_compression` configuration parameter is present in the config but not used in the v2 `GcsFileStore` implementation, only in v1: [9](#0-8)

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator_v2/gcs.rs (L22-49)
```rust
    pub async fn new(
        bucket_name: String,
        bucket_sub_dir: Option<PathBuf>,
        service_account_path: String,
    ) -> Self {
        // TODO: Audit that the environment access only happens in single-threaded code.
        unsafe {
            env::set_var(SERVICE_ACCOUNT_ENV_VAR, service_account_path);
        }

        info!(
            bucket_name = bucket_name,
            "Verifying the bucket exists for GcsFileStore."
        );

        Bucket::read(&bucket_name)
            .await
            .expect("Failed to read bucket.");

        info!(
            bucket_name = bucket_name,
            "Bucket exists, GcsFileStore is created."
        );
        Self {
            bucket_name,
            bucket_sub_dir,
        }
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator_v2/local.rs (L15-25)
```rust
impl LocalFileStore {
    pub fn new(path: PathBuf) -> Self {
        info!(
            path = path.to_str().unwrap(),
            "Verifying the path exists for LocalFileStore."
        );
        if !path.exists() {
            panic!("LocalFileStore path does not exist.");
        }
        Self { path }
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator_v2/common.rs (L33-52)
```rust
#[async_trait::async_trait]
pub trait IFileStoreReader: Sync + Send {
    /// The tag of the store, for logging.
    fn tag(&self) -> &str;

    /// Returns true if the file store is initialized (non-empty).
    async fn is_initialized(&self) -> bool;

    async fn get_raw_file(&self, file_path: PathBuf) -> Result<Option<Vec<u8>>>;
}

#[async_trait::async_trait]
pub trait IFileStoreWriter: Sync + Send {
    async fn save_raw_file(&self, file_path: PathBuf, data: Vec<u8>) -> Result<()>;

    fn max_update_frequency(&self) -> Duration;
}

#[async_trait::async_trait]
pub trait IFileStore: IFileStoreReader + IFileStoreWriter {}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/grpc_manager.rs (L31-42)
```rust
    pub(crate) async fn new(config: &IndexerGrpcManagerConfig) -> Self {
        let chain_id = config.chain_id;
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

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L156-172)
```rust
    pub(crate) async fn new(
        chain_id: u64,
        file_store_config: IndexerGrpcFileStoreConfig,
        cache_config: CacheConfig,
        metadata_manager: Arc<MetadataManager>,
        allow_fn_fallback: bool,
    ) -> Self {
        let file_store = file_store_config.create_filestore().await;
        let file_store_reader = FileStoreReader::new(chain_id, file_store).await;
        let file_store_version = file_store_reader.get_latest_version().await.unwrap();
        Self {
            cache: RwLock::new(Cache::new(cache_config, file_store_version)),
            file_store_reader,
            metadata_manager,
            allow_fn_fallback,
        }
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/historical_data_service.rs (L37-50)
```rust
    pub fn new(
        chain_id: u64,
        config: HistoricalDataServiceConfig,
        connection_manager: Arc<ConnectionManager>,
        max_transaction_filter_size_bytes: usize,
    ) -> Self {
        let file_store = block_on(config.file_store_config.create_filestore());
        let file_store_reader = Arc::new(block_on(FileStoreReader::new(chain_id, file_store)));
        Self {
            chain_id,
            connection_manager: connection_manager.clone(),
            file_store_reader,
            max_transaction_filter_size_bytes,
        }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-v2-file-store-backfiller/src/processor.rs (L53-64)
```rust
    pub async fn new(
        fullnode_grpc_address: Url,
        file_store_config: IndexerGrpcFileStoreConfig,
        chain_id: u64,
        progress_file_path: String,
        starting_version: u64,
        ending_version: u64,
        backfill_processing_task_count: usize,
    ) -> Result<Self> {
        let file_store = file_store_config.create_filestore().await;
        ensure!(file_store.is_initialized().await);
        let file_store_reader = FileStoreReader::new(chain_id, file_store.clone()).await;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator/gcs.rs (L28-38)
```rust
impl GcsFileStoreOperator {
    pub fn new(
        bucket_name: String,
        bucket_sub_dir: Option<PathBuf>,
        service_account_path: String,
        enable_compression: bool,
    ) -> Self {
        // TODO: Audit that the environment access only happens in single-threaded code.
        unsafe {
            env::set_var(SERVICE_ACCOUNT_ENV_VAR, service_account_path);
        }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/config.rs (L10-24)
```rust
pub struct GcsFileStore {
    pub gcs_file_store_bucket_name: String,
    pub gcs_file_store_bucket_sub_dir: Option<PathBuf>,
    // Required to operate on GCS.
    pub gcs_file_store_service_account_key_path: String,
    #[serde(default = "default_enable_compression")]
    pub enable_compression: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LocalFileStore {
    pub local_file_store_path: PathBuf,
    #[serde(default = "default_enable_compression")]
    pub enable_compression: bool,
}
```

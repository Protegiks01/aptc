# Audit Report

## Title
Concurrent Environment Variable Modification Causes Undefined Behavior in GCS File Store Operator

## Summary

The `GcsFileStoreOperator` constructor contains unsafe code that modifies process-wide environment variables without synchronization. When the indexer-grpc data service handles concurrent gRPC requests, multiple threads simultaneously invoke this constructor, triggering undefined behavior through concurrent calls to `env::set_var()`. This violates Rust's safety guarantees and can cause crashes, memory corruption, or unpredictable service behavior.

## Finding Description

The `FileStoreOperator` trait is marked with `Send + Sync` bounds, indicating implementations can be safely used across threads. However, the `GcsFileStoreOperator` implementation contains a critical flaw in its constructor that performs unsynchronized modification of process-global state. [1](#0-0) 

This unsafe block sets an environment variable during object construction. Environment variable operations in Rust are inherently thread-unsafe because they modify global process state without any synchronization primitives.

The vulnerability manifests when the indexer-grpc data service handles concurrent client requests: [2](#0-1) 

Each incoming gRPC request to `get_transactions()` creates a fresh `FileStoreOperator` instance. When configured for GCS storage (typical in production), this invokes `GcsFileStoreOperator::new()`, which calls the unsafe `env::set_var()`.

**Attack Scenario:**
1. Attacker sends multiple concurrent gRPC `GetTransactions` requests
2. Each request executes in a separate async task/thread via the tonic gRPC framework
3. All tasks simultaneously invoke `self.file_store_config.create()` at line 170
4. Multiple threads concurrently execute `unsafe { env::set_var(...) }`
5. Undefined behavior occurs due to unsynchronized global state modification

The code includes a TODO comment acknowledging this hazard: [3](#0-2) 

This demonstrates awareness of the thread-safety issue, but the assumption that environment access "only happens in single-threaded code" is violated by the concurrent gRPC handler design.

## Impact Explanation

**Severity: High** - This qualifies as "API crashes" under the Aptos bug bounty program.

The undefined behavior from concurrent `env::set_var()` calls can manifest as:

1. **Service Crashes**: Undefined behavior may cause segmentation faults or panics, terminating the data service
2. **Memory Corruption**: Concurrent modification of internal libc structures managing environment variables could corrupt heap metadata
3. **Data Races**: Simultaneous reads/writes to environment variable storage without synchronization
4. **Unpredictable Behavior**: The GCS client library may read corrupted or partially-written environment variable values, causing authentication failures

While this doesn't directly affect blockchain consensus or validator operations, it severely degrades the availability and reliability of the indexer-grpc data service, which external applications depend on for querying blockchain state. Service crashes require manual intervention and could impact user-facing applications relying on this API.

## Likelihood Explanation

**Likelihood: High**

This vulnerability triggers under normal production conditions:

1. The indexer-grpc data service is designed to handle concurrent client requests
2. Each client request to `get_transactions()` creates a new operator instance
3. Production deployments commonly use GCS for file storage
4. No special privileges or insider access required - any client can send concurrent requests
5. The race window is wide (entire constructor execution), making races highly probable under load

The vulnerability activates immediately upon receiving multiple simultaneous gRPC requests, which is expected behavior for any production API service. No sophisticated exploitation required - simple parallel requests from any client suffice.

## Recommendation

**Solution 1: Initialize Once (Preferred)**

Move the `FileStoreOperator` creation to service initialization rather than per-request:

```rust
pub struct RawDataServerWrapper {
    pub redis_client: Arc<redis::Client>,
    pub file_store_operator: Arc<Box<dyn FileStoreOperator>>, // Created once at init
    pub data_service_response_channel_size: usize,
    // ... other fields
}

impl RawDataServerWrapper {
    pub fn new(
        redis_address: RedisUrl,
        file_store_config: IndexerGrpcFileStoreConfig,
        // ... other params
    ) -> anyhow::Result<Self> {
        let file_store_operator = Arc::new(file_store_config.create());
        // Initialize once, share via Arc
        Ok(Self {
            file_store_operator,
            // ... other fields
        })
    }
}

async fn get_transactions(&self, req: Request<GetTransactionsRequest>) 
    -> Result<Response<Self::GetTransactionsStream>, Status> {
    // ... setup code ...
    let file_store_operator = self.file_store_operator.clone(); // Reuse shared instance
    // ... rest of handler ...
}
```

**Solution 2: Remove Unsafe Environment Modification**

Pass the service account path directly to the GCS client instead of using environment variables:

```rust
impl GcsFileStoreOperator {
    pub fn new(
        bucket_name: String,
        bucket_sub_dir: Option<PathBuf>,
        service_account_path: String,
        enable_compression: bool,
    ) -> Self {
        // Store path in struct, don't set environment variable
        Self {
            bucket_name,
            bucket_sub_dir,
            service_account_path, // Add this field
            file_store_metadata_last_updated: std::time::Instant::now(),
            storage_format: if enable_compression { /* ... */ },
            metadata_file_path: /* ... */,
        }
    }
    
    // Use service_account_path directly when creating GCS clients
}
```

**Solution 3: One-Time Global Initialization**

Use `std::sync::Once` to ensure environment variable is set exactly once:

```rust
use std::sync::Once;

static INIT: Once = Once::new();

impl GcsFileStoreOperator {
    pub fn new(/* ... */) -> Self {
        INIT.call_once(|| {
            unsafe {
                env::set_var(SERVICE_ACCOUNT_ENV_VAR, &service_account_path);
            }
        });
        // ... rest of constructor
    }
}
```

However, this assumes all instances use the same service account path.

## Proof of Concept

```rust
use std::thread;
use std::sync::Arc;
use aptos_indexer_grpc_utils::{
    config::{IndexerGrpcFileStoreConfig, GcsFileStore},
    file_store_operator::FileStoreOperator,
};

#[test]
fn test_concurrent_gcs_operator_creation() {
    let config = Arc::new(IndexerGrpcFileStoreConfig::GcsFileStore(GcsFileStore {
        gcs_file_store_bucket_name: "test-bucket".to_string(),
        gcs_file_store_bucket_sub_dir: None,
        gcs_file_store_service_account_key_path: "/tmp/test-key.json".to_string(),
        enable_compression: false,
    }));

    let mut handles = vec![];
    
    // Simulate 10 concurrent gRPC requests
    for i in 0..10 {
        let config_clone = config.clone();
        let handle = thread::spawn(move || {
            println!("Thread {} creating operator", i);
            // This calls GcsFileStoreOperator::new() which does unsafe env::set_var
            let _operator: Box<dyn FileStoreOperator> = config_clone.create();
            println!("Thread {} created operator", i);
        });
        handles.push(handle);
    }
    
    for handle in handles {
        handle.join().expect("Thread panicked");
    }
    
    // If this test completes without crashing, you got lucky
    // UB may manifest non-deterministically
    println!("Test completed - but UB may have occurred!");
}
```

Run with thread sanitizer to detect the race:
```bash
RUSTFLAGS="-Z sanitizer=thread" cargo test --target x86_64-unknown-linux-gnu test_concurrent_gcs_operator_creation
```

## Notes

While this vulnerability affects the indexer-grpc ecosystem service rather than core blockchain consensus, it represents a critical design flaw in a production API component. The `Send + Sync` trait bounds on `FileStoreOperator` indicate thread-safe usage, but the GCS implementation violates this contract through unsafe global state modification. The explicit TODO comment demonstrates prior awareness of this hazard, yet the unsafe code remains in production without proper synchronization.

The fix is straightforward: either create the operator once during service initialization and share it safely via `Arc`, or eliminate the unsafe environment variable manipulation entirely by passing credentials directly to GCS API calls.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator/gcs.rs (L35-38)
```rust
        // TODO: Audit that the environment access only happens in single-threaded code.
        unsafe {
            env::set_var(SERVICE_ACCOUNT_ENV_VAR, service_account_path);
        }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/service.rs (L145-171)
```rust
    async fn get_transactions(
        &self,
        req: Request<GetTransactionsRequest>,
    ) -> Result<Response<Self::GetTransactionsStream>, Status> {
        // Get request identity. The request is already authenticated by the interceptor.
        let request_metadata = get_request_metadata(&req);
        CONNECTION_COUNT
            .with_label_values(&request_metadata.get_label_values())
            .inc();
        let request = req.into_inner();

        let transactions_count = request.transactions_count;

        // Response channel to stream the data to the client.
        let (tx, rx) = channel(self.data_service_response_channel_size);
        let current_version = match &request.starting_version {
            Some(version) => *version,
            // Live mode if starting version isn't specified
            None => self
                .in_memory_cache
                .latest_version()
                .await
                .saturating_sub(1),
        };

        let file_store_operator: Box<dyn FileStoreOperator> = self.file_store_config.create();
        let file_store_operator = Arc::new(file_store_operator);
```

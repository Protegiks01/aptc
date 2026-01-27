# Audit Report

## Title
Unhandled GCS Initialization Failure Causes Indexer Service Crash

## Summary
The `create_filestore()` function in the indexer-grpc configuration contains an unhandled panic point during GCS bucket verification. When `Bucket::read()` fails due to network errors, timeouts, or GCS service issues, the `.expect()` call causes the entire indexer service to crash during initialization, resulting in API unavailability. [1](#0-0) 

## Finding Description
The vulnerability exists in the GCS file store initialization flow. When `create_filestore()` is called with a GCS configuration, it awaits `GcsFileStore::new()` which performs bucket verification: [2](#0-1) 

The `Bucket::read()` operation can fail for multiple realistic reasons:
- Transient network timeouts or connection failures
- GCS service outages or degraded performance
- GCS rate limiting (429 errors)
- Invalid or expired service account credentials
- Insufficient permissions on the bucket
- Bucket doesn't exist or was deleted

When any of these failures occur, the `.expect()` immediately panics, crashing the indexer process. This happens during service initialization in multiple critical components:

**Data Manager initialization** (synchronous blocking): [3](#0-2) 

**File Store Uploader initialization** (async context): [4](#0-3) 

The codebase demonstrates awareness of GCS reliability issues in other components. The backup/restore system implements retry logic with exponential backoff for GCS operations, and the NFT metadata crawler uses similar patterns. However, this critical initialization path lacks any retry mechanism or graceful error handling.

## Impact Explanation
This qualifies as **High Severity** per the Aptos bug bounty criteria which explicitly lists "API crashes" as a High severity impact. 

The indexer-grpc service provides critical API functionality for:
- Historical transaction queries
- Event streaming to dApps
- Data analytics and monitoring
- Block explorer services
- Third-party integrations

When the panic occurs during initialization, the entire API service becomes unavailable. Unlike transient errors during normal operation, initialization failures prevent the service from starting at all, requiring manual intervention to resolve.

This breaks service availability guarantees and affects the broader Aptos ecosystem's ability to query historical blockchain data, even though the core blockchain consensus and execution continue unaffected.

## Likelihood Explanation
**Likelihood: Medium to High**

This is likely to occur in production environments due to:

1. **GCS service reliability**: While GCS has high uptime SLAs, transient network issues, regional outages, and rate limiting are documented occurrences
2. **Rate limiting**: GCS enforces per-object write limits (1 write/second) and other quotas that can trigger errors during initialization
3. **Configuration errors**: Incorrect service account paths, expired credentials, or permission misconfigurations are common during deployment
4. **Cold start scenarios**: Services starting in new regions or after extended downtime may encounter GCS connectivity issues

The lack of retry logic means even brief, recoverable network glitches during the exact moment of initialization cause crashes.

## Recommendation
Implement retry logic with exponential backoff for GCS bucket verification, following patterns already used elsewhere in the codebase:

```rust
use tokio::time::{sleep, Duration};

pub async fn new(
    bucket_name: String,
    bucket_sub_dir: Option<PathBuf>,
    service_account_path: String,
) -> Result<Self, anyhow::Error> {
    unsafe {
        env::set_var(SERVICE_ACCOUNT_ENV_VAR, service_account_path);
    }

    info!(
        bucket_name = bucket_name,
        "Verifying the bucket exists for GcsFileStore."
    );

    // Retry with exponential backoff
    let mut retry_delay = Duration::from_millis(100);
    let max_retries = 5;
    let mut last_error = None;

    for attempt in 0..max_retries {
        match Bucket::read(&bucket_name).await {
            Ok(_) => {
                info!(
                    bucket_name = bucket_name,
                    "Bucket exists, GcsFileStore is created."
                );
                return Ok(Self {
                    bucket_name,
                    bucket_sub_dir,
                });
            },
            Err(e) => {
                last_error = Some(e);
                if attempt < max_retries - 1 {
                    info!(
                        "Failed to read bucket (attempt {}/{}), retrying in {:?}",
                        attempt + 1, max_retries, retry_delay
                    );
                    sleep(retry_delay).await;
                    retry_delay *= 2;
                }
            }
        }
    }

    Err(anyhow::anyhow!(
        "Failed to verify GCS bucket '{}' after {} attempts: {:?}",
        bucket_name,
        max_retries,
        last_error
    ))
}
```

Update the call site in `config.rs` to handle the Result:

```rust
pub async fn create_filestore(
    self,
) -> Result<Arc<dyn crate::file_store_operator_v2::common::IFileStore>, anyhow::Error> {
    match self {
        IndexerGrpcFileStoreConfig::GcsFileStore(gcs_file_store) => {
            let store = crate::file_store_operator_v2::gcs::GcsFileStore::new(
                gcs_file_store.gcs_file_store_bucket_name,
                gcs_file_store.gcs_file_store_bucket_sub_dir,
                gcs_file_store.gcs_file_store_service_account_key_path.clone(),
            )
            .await?;
            Ok(Arc::new(store))
        },
        IndexerGrpcFileStoreConfig::LocalFileStore(local_file_store) => {
            Ok(Arc::new(crate::file_store_operator_v2::local::LocalFileStore::new(
                local_file_store.local_file_store_path,
            )))
        },
    }
}
```

## Proof of Concept

To reproduce this vulnerability, simulate a GCS initialization failure:

```rust
#[tokio::test]
async fn test_gcs_initialization_panic() {
    // Set invalid or non-existent bucket configuration
    let config = IndexerGrpcFileStoreConfig::GcsFileStore(GcsFileStore {
        gcs_file_store_bucket_name: "non-existent-bucket-12345".to_string(),
        gcs_file_store_bucket_sub_dir: None,
        gcs_file_store_service_account_key_path: "/invalid/path/key.json".to_string(),
        enable_compression: false,
    });

    // This will panic with "Failed to read bucket."
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(config.create_filestore())
    }));

    assert!(result.is_err(), "Expected panic but got successful result");
}
```

Alternatively, simulate a network timeout by temporarily disconnecting from the network or using a network chaos tool during indexer startup. The service will crash immediately during initialization with the error message "Failed to read bucket."

## Notes

This issue also affects the older v1 file store operator at a similar location: [5](#0-4) 

The same fix should be applied to both implementations for consistency. The codebase already demonstrates proper patterns for handling GCS errors with retry logic in other components, making this an inconsistency in error handling strategy.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/config.rs (L47-67)
```rust
    pub async fn create_filestore(
        self,
    ) -> Arc<dyn crate::file_store_operator_v2::common::IFileStore> {
        match self {
            IndexerGrpcFileStoreConfig::GcsFileStore(gcs_file_store) => Arc::new(
                crate::file_store_operator_v2::gcs::GcsFileStore::new(
                    gcs_file_store.gcs_file_store_bucket_name,
                    gcs_file_store.gcs_file_store_bucket_sub_dir,
                    gcs_file_store
                        .gcs_file_store_service_account_key_path
                        .clone(),
                )
                .await,
            ),
            IndexerGrpcFileStoreConfig::LocalFileStore(local_file_store) => {
                Arc::new(crate::file_store_operator_v2::local::LocalFileStore::new(
                    local_file_store.local_file_store_path,
                ))
            },
        }
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator_v2/gcs.rs (L37-39)
```rust
        Bucket::read(&bucket_name)
            .await
            .expect("Failed to read bucket.");
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/historical_data_service.rs (L43-43)
```rust
        let file_store = block_on(config.file_store_config.create_filestore());
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/file_store_uploader.rs (L46-46)
```rust
        let file_store = file_store_config.create_filestore().await;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator/gcs.rs (L90-92)
```rust
        Bucket::read(&self.bucket_name)
            .await
            .expect("Failed to read bucket.");
```

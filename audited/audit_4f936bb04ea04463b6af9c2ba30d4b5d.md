# Audit Report

## Title
Storage Format Mismatch Causes Indexer Data Service Panic and Service Unavailability

## Summary
The indexer-grpc data service uses a configurable storage format parameter that is independent of the actual format stored in files. When there is a mismatch between the configured format and the actual file format (e.g., reading old `JsonBase64UncompressedProto` files with an operator configured for `Lz4CompressedProto`), the service panics during deserialization, causing immediate service crashes and denial of service for clients requesting historical transaction data.

## Finding Description

The vulnerability exists in how the file store operator determines which deserialization method to use when reading transaction files. The storage format is determined at operator initialization time based on the `enable_compression` configuration flag, but this configured format may not match the actual format of files stored in the file store. [1](#0-0) 

When the data service reads transactions, it uses the operator's configured storage format rather than checking the metadata file's `storage_format` field: [2](#0-1) 

The deserialization logic contains `expect()` calls that panic on format mismatch: [3](#0-2) 

**Attack Scenario:**

1. A file store contains historical transaction files in `JsonBase64UncompressedProto` format (e.g., `files/0.json`, `files/1000.json`, etc.)
2. The metadata file either lacks the `storage_format` field (defaulting to `JsonBase64UncompressedProto` via serde default) or explicitly specifies it
3. An operator deploys a new data service instance with `enable_compression: true` in the configuration
4. The data service creates a file store operator with `storage_format = Lz4CompressedProto`
5. A client requests historical transactions (e.g., starting from version 0)
6. The service downloads `files/0.json` containing JSON data
7. The service attempts to decompress this JSON data as LZ4 compressed bytes
8. LZ4 decompression fails with panic: `"Lz4 decompression failed."`
9. The service thread panics, causing connection failures for clients

The metadata validation only occurs during write operations, not read operations: [4](#0-3) 

Read-only consumers like the data service never validate that their configured format matches the metadata: [5](#0-4) 

## Impact Explanation

This is a **High Severity** vulnerability according to the Aptos bug bounty criteria, specifically falling under "API crashes." The indexer-grpc data service is a critical API component that provides transaction data to external clients, indexers, and applications.

**Impact:**
- **Service Unavailability**: The data service panics and crashes when serving requests for historical data with mismatched formats
- **Denial of Service**: Any client requesting old transaction versions can trigger the crash
- **Operational Disruption**: Requires service restart with corrected configuration
- **Data Access Loss**: Applications dependent on the indexer API lose access to historical blockchain data

While this does not affect consensus, validators, or core blockchain operations, it severely impacts the availability of the indexer API, which is essential for the Aptos ecosystem's data infrastructure.

## Likelihood Explanation

**Likelihood: Medium to High**

This vulnerability is highly likely to occur in the following realistic scenarios:

1. **Configuration Migration**: When upgrading from an older deployment without compression to a newer one with `enable_compression: true`, operators may not realize the configuration must match the existing file format

2. **Shared Storage**: When multiple services share the same file store bucket with different compression settings

3. **Configuration Drift**: When configuration files are updated without considering backward compatibility with existing stored data

4. **Rollback Scenarios**: After enabling compression, rolling back to an older configuration may cause the reverse mismatch

The vulnerability requires only a configuration mismatch—no special privileges or complex exploitation steps. Any client requesting historical data will immediately trigger the panic.

## Recommendation

**Solution 1: Read Format from Metadata (Preferred)**

Modify the file store operator to read the actual storage format from the metadata file and use it for decoding, rather than relying on the configured format:

1. When reading transactions, first check the metadata file to determine the actual storage format
2. Use the metadata's `storage_format` field for decoding
3. Only use the configured format for write operations

**Solution 2: Startup Validation**

Add validation during data service initialization to verify that the configured storage format matches the metadata:

Add validation in the data service startup:
- Read the file store metadata during initialization
- Compare `metadata.storage_format` with the operator's configured format
- Fail fast with a clear error message if they don't match
- Require explicit configuration to handle format migration

**Solution 3: Graceful Format Detection**

Implement format detection that attempts to determine the actual format before deserialization:
- Try to detect JSON vs binary format from file headers
- Fall back to configured format if detection is ambiguous
- Log warnings when format detection differs from configuration

## Proof of Concept

**Setup:**

1. Deploy a file store with `enable_compression: false` and write some transaction batches (versions 0-999)

2. Create a configuration file for the data service with mismatched compression:

```yaml
file_store_config:
  file_store_type: "GcsFileStore"
  gcs_file_store_bucket_name: "test-bucket"
  gcs_file_store_service_account_key_path: "/path/to/key.json"
  enable_compression: true  # Mismatch: true when files are uncompressed

redis_read_replica_address: "redis://localhost:6379"
enable_cache_compression: false
```

3. Start the data service with this configuration

4. Send a gRPC request for historical transactions:

```rust
use aptos_protos::indexer::v1::{GetTransactionsRequest, raw_data_client::RawDataClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = RawDataClient::connect("http://localhost:50051").await?;
    
    let request = GetTransactionsRequest {
        starting_version: Some(0),  // Request old transactions
        transactions_count: Some(100),
    };
    
    // This will trigger the panic in the data service
    let response = client.get_transactions(request).await;
    
    println!("Response: {:?}", response);  // Will receive error due to server panic
    Ok(())
}
```

**Expected Result:**
The data service will panic with:
```
thread 'tokio-runtime-worker' panicked at 'Lz4 decompression failed.':
ecosystem/indexer-grpc/indexer-grpc-utils/src/compression_util.rs:265
```

The client will receive a connection error or internal server error, and the data service will need to be restarted.

## Notes

This vulnerability specifically affects the backward compatibility mechanism where `JsonBase64UncompressedProto` is the default format. The issue arises because the system allows configuration-driven format selection for reading, but doesn't validate that the configuration matches the actual stored data format. This breaks the service availability guarantee for the indexer API, which is critical infrastructure for the Aptos ecosystem even though it doesn't affect consensus or validator operations.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/lib.rs (L29-33)
```rust
/// The default file storage format is JsonBase64UncompressedProto.
/// This is only used in file store metadata for backward compatibility.
pub fn default_file_storage_format() -> compression_util::StorageFormat {
    compression_util::StorageFormat::JsonBase64UncompressedProto
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator/mod.rs (L59-75)
```rust
    async fn get_transactions_with_durations(
        &self,
        version: u64,
        retries: u8,
    ) -> Result<(Vec<Transaction>, f64, f64)> {
        let io_start_time = std::time::Instant::now();
        let bytes = self.get_raw_file_with_retries(version, retries).await?;
        let io_duration = io_start_time.elapsed().as_secs_f64();
        let decoding_start_time = std::time::Instant::now();
        let storage_format = self.storage_format();

        let transactions_in_storage = tokio::task::spawn_blocking(move || {
            FileEntry::new(bytes, storage_format).into_transactions_in_storage()
        })
        .await
        .context("Converting storage bytes to FileEntry transactions thread panicked")?;

```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/compression_util.rs (L262-292)
```rust
    pub fn into_transactions_in_storage(self) -> TransactionsInStorage {
        match self {
            FileEntry::Lz4CompressionProto(bytes) => {
                let mut decompressor = Decoder::new(&bytes[..]).expect("Lz4 decompression failed.");
                let mut decompressed = Vec::new();
                decompressor
                    .read_to_end(&mut decompressed)
                    .expect("Lz4 decompression failed.");
                TransactionsInStorage::decode(decompressed.as_slice())
                    .expect("proto deserialization failed.")
            },
            FileEntry::JsonBase64UncompressedProto(bytes) => {
                let file: TransactionsLegacyFile =
                    serde_json::from_slice(bytes.as_slice()).expect("json deserialization failed.");
                let transactions = file
                    .transactions_in_base64
                    .into_iter()
                    .map(|base64| {
                        let bytes: Vec<u8> =
                            base64::decode(base64).expect("base64 decoding failed.");
                        Transaction::decode(bytes.as_slice())
                            .expect("proto deserialization failed.")
                    })
                    .collect::<Vec<Transaction>>();
                TransactionsInStorage {
                    starting_version: Some(file.starting_version),
                    transactions,
                }
            },
        }
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator/gcs.rs (L162-182)
```rust
    async fn update_file_store_metadata_with_timeout(
        &mut self,
        expected_chain_id: u64,
        version: u64,
    ) -> anyhow::Result<()> {
        if let Some(metadata) = self.get_file_store_metadata().await {
            assert_eq!(metadata.chain_id, expected_chain_id, "Chain ID mismatch.");
            assert_eq!(
                metadata.storage_format, self.storage_format,
                "Storage format mismatch."
            );
        }
        if self.file_store_metadata_last_updated.elapsed().as_millis()
            < FILE_STORE_METADATA_TIMEOUT_MILLIS
        {
            bail!("File store metadata is updated too frequently.")
        }
        self.update_file_store_metadata_internal(expected_chain_id, version)
            .await?;
        Ok(())
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/service.rs (L170-171)
```rust
        let file_store_operator: Box<dyn FileStoreOperator> = self.file_store_config.create();
        let file_store_operator = Arc::new(file_store_operator);
```

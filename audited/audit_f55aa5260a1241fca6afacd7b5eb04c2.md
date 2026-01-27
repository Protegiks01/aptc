# Audit Report

## Title
Insecure File Permissions in LocalFileStore Expose Indexer Transaction Data to Local Attackers

## Summary
The `LocalFileStore` implementation in the indexer-grpc component creates files and directories with default system permissions, resulting in world-readable transaction data files. This allows any local user on the system to access sensitive blockchain transaction data stored by the indexer without authorization.

## Finding Description
The `LocalFileStore` struct creates transaction data files and metadata files without explicitly setting secure permissions. When files are created using `tokio::fs::write()` [1](#0-0)  and directories are created using `tokio::fs::create_dir_all()` [2](#0-1) , they inherit default system permissions.

On Unix systems, this typically results in:
- Files: 0644 (rw-r--r--) - world-readable
- Directories: 0755 (rwxr-xr-x) - world-readable and executable

The same vulnerability exists in both file store implementations:
- `file_store_operator_v2/local.rs` [3](#0-2) 
- `file_store_operator/local.rs` for transaction files [4](#0-3)  and metadata files [5](#0-4) 

The stored data includes complete blockchain transactions with user addresses, signatures, transaction payloads, and state changes [6](#0-5) , which are serialized as protobuf messages containing sensitive information [7](#0-6) .

The Aptos codebase already establishes secure patterns for handling confidential files using mode 0o600 [8](#0-7)  and provides utility functions for user-only file creation [9](#0-8) , but these patterns are not applied to the indexer file storage.

## Impact Explanation
This vulnerability allows unauthorized local users to read blockchain transaction data stored by the indexer, including:
- User wallet addresses and transaction patterns
- Transaction payloads and parameters
- State changes and event data
- Historical transaction metadata

In multi-tenant environments (shared servers, Kubernetes clusters, cloud instances), this enables:
- **Privacy violations**: Transaction analysis and user profiling
- **Reconnaissance**: Planning targeted attacks on specific accounts
- **Compliance violations**: Exposure of data that should be access-controlled

This qualifies as **Medium severity** per the Aptos bug bounty program, as it represents an information disclosure vulnerability affecting the confidentiality of indexer data in production environments where proper isolation is expected.

## Likelihood Explanation
**High likelihood** in common deployment scenarios:
- Multi-tenant Kubernetes clusters where pods share nodes
- Shared development/staging servers
- Cloud instances with multiple services
- Any environment where the indexer service is compromised or runs alongside untrusted code

The vulnerability is **triggered automatically** - every file created by the indexer is world-readable by default without any special attacker action required beyond local system access.

## Recommendation
Apply explicit secure file permissions when creating files and directories in `LocalFileStore`. Use Rust's `std::fs::Permissions` with mode 0o600 for files and 0o700 for directories:

```rust
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;

// For file_store_operator_v2/local.rs
async fn save_raw_file(&self, file_path: PathBuf, data: Vec<u8>) -> Result<()> {
    let file_path = self.path.join(file_path);
    if let Some(parent) = file_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
        #[cfg(unix)]
        tokio::fs::set_permissions(parent, Permissions::from_mode(0o700)).await?;
    }
    tokio::fs::write(&file_path, data).await?;
    #[cfg(unix)]
    tokio::fs::set_permissions(&file_path, Permissions::from_mode(0o600)).await?;
    Ok(())
}
```

Apply similar changes to `file_store_operator/local.rs` for both transaction file uploads and metadata file writes.

## Proof of Concept
```rust
use std::path::PathBuf;
use std::fs;
use std::os::unix::fs::PermissionsExt;

#[tokio::test]
async fn test_insecure_file_permissions() {
    // Setup test directory
    let test_dir = PathBuf::from("/tmp/aptos_indexer_test");
    fs::create_dir_all(&test_dir).unwrap();
    
    // Create LocalFileStore and write a file
    let store = LocalFileStore::new(test_dir.clone());
    let test_data = vec![1, 2, 3, 4, 5];
    store.save_raw_file(PathBuf::from("test.bin"), test_data).await.unwrap();
    
    // Check file permissions
    let file_path = test_dir.join("test.bin");
    let metadata = fs::metadata(&file_path).unwrap();
    let permissions = metadata.permissions();
    let mode = permissions.mode() & 0o777;
    
    // Vulnerability: file is world-readable (0o644)
    assert_eq!(mode, 0o644, "File has insecure world-readable permissions");
    
    // Expected secure permissions would be 0o600
    println!("VULNERABILITY: File created with mode {:o}, should be 0o600", mode);
    
    // Cleanup
    fs::remove_dir_all(test_dir).unwrap();
}
```

This test demonstrates that files created by `LocalFileStore` have world-readable permissions (0o644), allowing any local user to access sensitive indexer transaction data.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator_v2/local.rs (L61-69)
```rust
    async fn save_raw_file(&self, file_path: PathBuf, data: Vec<u8>) -> Result<()> {
        let file_path = self.path.join(file_path);
        if let Some(parent) = file_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(file_path, data)
            .await
            .map_err(anyhow::Error::msg)
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator/local.rs (L139-139)
```rust
        match tokio::fs::write(metadata_path, serde_json::to_vec(&metadata).unwrap()).await {
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator/local.rs (L173-189)
```rust
            let txns_path = self.path.join(file_entry_key.as_str());
            let parent_dir = txns_path.parent().unwrap();
            if !parent_dir.exists() {
                tracing::debug!("Creating parent dir: {parent_dir:?}.");
                tokio::fs::create_dir_all(parent_dir).await?;
            }

            tracing::debug!(
                "Uploading transactions to {:?}",
                txns_path.to_str().unwrap()
            );
            let task = tokio::spawn(async move {
                match tokio::fs::write(txns_path, file_entry.into_inner()).await {
                    Ok(_) => Ok(()),
                    Err(err) => Err(anyhow::Error::from(err)),
                }
            });
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/compression_util.rs (L191-237)
```rust
    pub fn from_transactions(
        transactions: Vec<Transaction>,
        storage_format: StorageFormat,
    ) -> Self {
        let mut bytes = Vec::new();
        let starting_version = transactions
            .first()
            .expect("Cannot build empty file")
            .version;
        match storage_format {
            StorageFormat::Lz4CompressedProto => {
                let t = TransactionsInStorage {
                    starting_version: Some(transactions.first().unwrap().version),
                    transactions,
                };
                t.encode(&mut bytes).expect("proto serialization failed.");
                let mut compressed = EncoderBuilder::new()
                    .level(0)
                    .build(Vec::new())
                    .expect("Lz4 compression failed.");
                compressed
                    .write_all(&bytes)
                    .expect("Lz4 compression failed.");
                FileEntry::Lz4CompressionProto(compressed.finish().0)
            },
            StorageFormat::Base64UncompressedProto => {
                panic!("Base64UncompressedProto is not supported.")
            },
            StorageFormat::JsonBase64UncompressedProto => {
                let transactions_in_base64 = transactions
                    .into_iter()
                    .map(|transaction| {
                        let mut bytes = Vec::new();
                        transaction
                            .encode(&mut bytes)
                            .expect("proto serialization failed.");
                        base64::encode(bytes)
                    })
                    .collect::<Vec<String>>();
                let file = TransactionsLegacyFile {
                    starting_version,
                    transactions_in_base64,
                };
                let json = serde_json::to_vec(&file).expect("json serialization failed.");
                FileEntry::JsonBase64UncompressedProto(json)
            },
        }
```

**File:** protos/proto/aptos/transaction/v1/transaction.proto (L156-194)
```text
message UserTransaction {
  UserTransactionRequest request = 1;
  repeated Event events = 2;
}

message Event {
  EventKey key = 1;
  uint64 sequence_number = 2 [jstype = JS_STRING];
  MoveType type = 3;
  string type_str = 5;
  string data = 4;
}

message TransactionInfo {
  bytes hash = 1;
  bytes state_change_hash = 2;
  bytes event_root_hash = 3;
  optional bytes state_checkpoint_hash = 4;
  uint64 gas_used = 5 [jstype = JS_STRING];
  bool success = 6;
  string vm_status = 7;
  bytes accumulator_root_hash = 8;
  repeated WriteSetChange changes = 9;
}

message EventKey {
  uint64 creation_number = 1 [jstype = JS_STRING];
  string account_address = 2;
}

message UserTransactionRequest {
  string sender = 1;
  uint64 sequence_number = 2 [jstype = JS_STRING];
  uint64 max_gas_amount = 3 [jstype = JS_STRING];
  uint64 gas_unit_price = 4 [jstype = JS_STRING];
  aptos.util.timestamp.Timestamp expiration_timestamp_secs = 5;
  TransactionPayload payload = 6;
  Signature signature = 7;
}
```

**File:** crates/aptos/src/common/types.rs (L1083-1089)
```rust
    /// Save to the `output_file` with restricted permissions (mode 0600)
    pub fn save_to_file_confidential(&self, name: &str, bytes: &[u8]) -> CliTypedResult<()> {
        let mut opts = OpenOptions::new();
        #[cfg(unix)]
        opts.mode(0o600);
        write_to_file_with_opts(self.output_file.as_path(), name, bytes, &mut opts)
    }
```

**File:** crates/aptos/src/common/utils.rs (L223-229)
```rust
/// Write a User only read / write file
pub fn write_to_user_only_file(path: &Path, name: &str, bytes: &[u8]) -> CliTypedResult<()> {
    let mut opts = OpenOptions::new();
    #[cfg(unix)]
    opts.mode(0o600);
    write_to_file_with_opts(path, name, bytes, &mut opts)
}
```

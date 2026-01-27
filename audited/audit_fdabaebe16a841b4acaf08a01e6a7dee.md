# Audit Report

## Title
Indexer-GRPC LocalFileStore Filesystem Permission Vulnerability Leading to Service Denial and Data Corruption

## Summary
The `LocalFileStore` implementation in the indexer-grpc subsystem does not enforce restrictive filesystem permissions when creating directories and files, and uses panic-on-error handling for all deserialization operations. If the local file store path has insecure filesystem permissions, unauthorized local processes can corrupt transaction data files, causing the indexer service to crash.

## Finding Description

The LocalFileStore implementation has two critical security weaknesses:

**1. No Explicit Permission Management**

The `LocalFileStore` creates directories and writes files without setting explicit filesystem permissions: [1](#0-0) 

The code relies entirely on the system's umask to determine file permissions. If the process runs with a permissive umask (e.g., `0000`) or if the directory is manually configured with world-writable permissions, files will be created with insecure permissions (potentially `0666` for files, `0777` for directories).

**2. Panic-on-Error Deserialization**

All file deserialization operations use `.expect()`, causing the service to panic when reading corrupted data: [2](#0-1) [3](#0-2) 

**Attack Scenario:**

1. The indexer-grpc-file-store service is deployed with a permissive umask or manually configured world-writable permissions on `local_file_store_path`
2. An attacker with local filesystem access (different user/process on the same machine) modifies transaction data files or the `metadata.json` file
3. When the service attempts to read the corrupted file, deserialization fails
4. The `.expect()` calls trigger a panic, crashing the entire indexer service

This affects both the file store processor and data service components that read from the local file store.

## Impact Explanation

This vulnerability qualifies as **High Severity** under Aptos Bug Bounty criteria ("API crashes"):

- **Availability Impact**: Complete denial of service for the indexer-grpc infrastructure. The service crashes and cannot recover until corrupted files are manually removed.
- **Data Integrity Impact**: Malicious corruption of indexed blockchain data can cause incorrect data to be served to clients before the service crashes.
- **Operational Impact**: Requires manual intervention to identify and repair corrupted files.

While the indexed transaction data is public blockchain information (confidentiality impact is minimal), the service availability and data integrity impacts are significant for applications relying on the indexer-grpc API.

## Likelihood Explanation

**Likelihood: Medium**

This vulnerability requires:
- Local filesystem access to the machine running the indexer service
- Misconfigured filesystem permissions (permissive umask or manual misconfiguration)
- Knowledge of file structure and location

However, in multi-tenant environments or shared infrastructure deployments, these conditions are realistic. The lack of defensive security measures (explicit permission setting, graceful error handling) makes this exploitable in common deployment scenarios.

## Recommendation

**1. Enforce Restrictive Filesystem Permissions**

Set explicit permissions when creating directories and files:

```rust
use std::os::unix::fs::PermissionsExt;

#[async_trait::async_trait]
impl IFileStoreWriter for LocalFileStore {
    async fn save_raw_file(&self, file_path: PathBuf, data: Vec<u8>) -> Result<()> {
        let file_path = self.path.join(file_path);
        if let Some(parent) = file_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
            // Set directory permissions to 0700 (owner only)
            let metadata = tokio::fs::metadata(parent).await?;
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o700);
            tokio::fs::set_permissions(parent, permissions).await?;
        }
        
        tokio::fs::write(&file_path, data).await?;
        
        // Set file permissions to 0600 (owner read/write only)
        let metadata = tokio::fs::metadata(&file_path).await?;
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o600);
        tokio::fs::set_permissions(&file_path, permissions).await?;
        
        Ok(())
    }
}
```

**2. Implement Graceful Error Handling**

Replace `.expect()` calls with proper error propagation:

```rust
pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
    serde_json::from_slice(bytes.as_slice())
        .context("FileStoreMetadata json deserialization failed")
}

pub fn into_transactions_in_storage(self) -> Result<TransactionsInStorage> {
    match self {
        FileEntry::Lz4CompressionProto(bytes) => {
            let mut decompressor = Decoder::new(&bytes[..])
                .context("Lz4 decompression failed")?;
            let mut decompressed = Vec::new();
            decompressor.read_to_end(&mut decompressed)
                .context("Lz4 decompression read failed")?;
            TransactionsInStorage::decode(decompressed.as_slice())
                .context("proto deserialization failed")
        },
        // ... handle other variants
    }
}
```

## Proof of Concept

```rust
// PoC: Corrupt a metadata file to crash the indexer service

use std::fs;
use std::path::PathBuf;

#[tokio::test]
async fn test_corrupted_metadata_causes_panic() {
    // Setup: Create a local file store directory
    let temp_dir = tempfile::tempdir().unwrap();
    let store_path = temp_dir.path().to_path_buf();
    
    // Write a corrupted metadata.json file
    let metadata_path = store_path.join("metadata.json");
    fs::write(&metadata_path, b"invalid json {{{").unwrap();
    
    // Make the file world-readable/writable (simulating misconfiguration)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&metadata_path).unwrap().permissions();
        perms.set_mode(0o666);
        fs::set_permissions(&metadata_path, perms).unwrap();
    }
    
    // Attempt to read metadata - this will panic
    use aptos_indexer_grpc_utils::compression_util::FileStoreMetadata;
    
    let result = std::panic::catch_unwind(|| {
        let bytes = fs::read(&metadata_path).unwrap();
        FileStoreMetadata::from_bytes(bytes) // This panics!
    });
    
    assert!(result.is_err(), "Service should panic on corrupted metadata");
}
```

## Notes

While the transaction data stored is public blockchain information, the lack of explicit permission management violates defense-in-depth principles. Combined with panic-on-error handling, this creates a reliable DoS vector against the indexer-grpc infrastructure. The fix should implement both restrictive permissions and graceful error handling to ensure service resilience.

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

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/compression_util.rs (L58-61)
```rust
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        serde_json::from_slice(bytes.as_slice())
            .expect("FileStoreMetadata json deserialization failed.")
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/compression_util.rs (L262-272)
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
```

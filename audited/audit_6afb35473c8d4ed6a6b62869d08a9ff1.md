# Audit Report

## Title
Metadata Deletion Causes Permanent Indexer Crash Loop via Dual Unwrap Panics

## Summary
The indexer-grpc file store processor contains two unwrap() calls that cause cascading failures when the metadata file is deleted. The processor crashes immediately on metadata retrieval, then enters a permanent crash loop after restart due to incorrect state reconstruction and cache eviction.

## Finding Description

The vulnerability exists in the file store processor's metadata handling logic across two critical points:

**Primary Crash Point:** [1](#0-0) 

The `run()` function unconditionally unwraps the metadata retrieval result without error handling. When `get_file_store_metadata()` returns `None` (which occurs when the metadata file doesn't exist), the unwrap() panics and crashes the processor.

**Metadata Implementations:**
Both file store implementations return `None` when metadata is not found: [2](#0-1) [3](#0-2) 

**Cascade Failure on Restart:**

When the processor restarts, the `new()` function attempts recovery: [4](#0-3) 

The recovery logic creates new metadata with version 0, which is incorrect if the file store already contains indexed data. When `run()` executes with this corrupted state, it attempts to fetch transactions from version 0.

**Secondary Crash Point:** [5](#0-4) 

The cache eviction policy retains only approximately 250,000 recent transactions: [6](#0-5) 

If the file store had processed beyond version 250,000 before metadata deletion, attempting to fetch version 0 from cache will fail. The `get_transactions()` method enforces that all requested transactions must be returned: [7](#0-6) 

This unwrap() at line 165 causes a second panic, creating a permanent crash loop.

**Attack Scenario:**
1. File store has indexed transactions up to version 1,000,000
2. Attacker with file store access (compromised GCS credentials, misconfigured permissions, insider) deletes `metadata.json`
3. Processor crashes immediately on line 120 (unwrap on None)
4. Container orchestration restarts the processor
5. Initialization recreates metadata with version 0 (incorrect state)
6. Processor attempts to fetch transactions from version 0 from cache
7. Cache only contains versions ~750,000-1,000,000 (evicted older entries)
8. `get_transactions()` fails, line 165 unwrap panics
9. Processor enters permanent crash loop until manual intervention

## Impact Explanation

**Severity: High**

This qualifies as **High Severity** under the Aptos Bug Bounty program category "API crashes" for the following reasons:

1. **Service Availability Impact:** The indexer-grpc file store is critical infrastructure that serves historical transaction data to dApps, wallets, block explorers, and analytics platforms. Complete failure prevents all downstream consumers from accessing indexed data.

2. **Permanent Denial of Service:** Unlike temporary crashes, this creates a permanent crash loop. The processor cannot self-recover and requires manual intervention to either:
   - Restore the correct metadata file with accurate version information
   - Clear and rebuild the entire file store from scratch
   - Manually reconstruct the correct metadata version

3. **State Corruption:** The automatic recovery mechanism creates incorrect state (version 0) that doesn't match the actual file store contents, preventing normal operation even after restart.

4. **No Authentication Required for Exploitation:** The attack only requires file store access (cloud storage bucket permissions), not validator node access or protocol-level privileges.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability is moderately likely to be exploited due to:

**Attack Vectors:**
- **Compromised Cloud Credentials:** GCS service account key compromise
- **Misconfigured IAM Permissions:** Overly permissive bucket access policies
- **Insider Threat:** Cloud infrastructure administrator with malicious intent
- **Automated Cleanup Scripts:** Misconfigured retention policies that delete metadata
- **Human Error:** Accidental deletion during maintenance operations

**Realistic Scenarios:**
- Cloud storage credentials exposed in public repositories
- Shared infrastructure with multiple teams having bucket access
- Automated cleanup scripts targeting old files without excluding metadata
- Supply chain attacks targeting cloud service accounts

**Mitigation Factors:**
- Requires file store access (not publicly accessible)
- Most production environments have proper IAM controls
- Cloud storage typically has audit logging to detect unauthorized access

## Recommendation

Replace all unwrap() calls with proper error handling and recovery mechanisms:

**Fix for processor.rs line 120:**
```rust
pub async fn run(&mut self) -> Result<()> {
    let chain_id = self.chain_id;

    // Attempt metadata retrieval with retry logic
    let metadata = match self.file_store_operator.get_file_store_metadata().await {
        Some(metadata) => metadata,
        None => {
            tracing::error!("Metadata file not found. Attempting recovery...");
            // Attempt to determine correct version from file store contents
            let latest_version = self.recover_latest_version_from_files().await?;
            tracing::info!(version = latest_version, "Recovered version from file store");
            
            // Recreate metadata with correct version
            self.file_store_operator
                .update_file_store_metadata_with_timeout(chain_id, latest_version)
                .await?;
            
            self.file_store_operator
                .get_file_store_metadata()
                .await
                .context("Failed to retrieve metadata after recovery")?
        }
    };
    
    ensure!(metadata.chain_id == chain_id, "Chain ID mismatch.");
    // ... rest of function
}
```

**Fix for processor.rs line 165:**
```rust
// Inside spawned task
let transactions = match cache_operator_clone
    .get_transactions(start_version, FILE_ENTRY_TRANSACTION_COUNT)
    .await
{
    Ok(txns) => txns,
    Err(err) => {
        tracing::error!(
            start_version = start_version,
            error = ?err,
            "Failed to fetch transactions from cache. Data may be evicted."
        );
        // Fall back to rebuilding from fullnode or fail gracefully
        return Err(anyhow::anyhow!(
            "Transactions at version {} not available in cache", 
            start_version
        ));
    }
};
```

**Additional Recommendations:**
1. Implement metadata file versioning and backup
2. Add metadata integrity verification on startup
3. Implement recovery logic to scan file store and determine correct version
4. Add monitoring/alerting for metadata file deletion
5. Use cloud storage bucket versioning to prevent permanent deletion
6. Implement periodic metadata checksum validation

## Proof of Concept

**Reproduction Steps:**

1. **Setup:** Deploy indexer-grpc file store processor with GCS or local file store
2. **Index Data:** Allow processor to index at least 300,000 transactions
3. **Delete Metadata:** Remove the metadata.json file from the storage bucket:
   ```bash
   # For GCS
   gsutil rm gs://your-bucket/metadata.json
   
   # For local file store
   rm /path/to/filestore/metadata.json
   ```
4. **Observe Primary Crash:** Monitor processor logs for panic:
   ```
   thread 'tokio-runtime-worker' panicked at 'called `Option::unwrap()` on a `None` value',
   ecosystem/indexer-grpc/indexer-grpc-file-store/src/processor.rs:120:14
   ```

5. **Observe Restart:** Container orchestration (Kubernetes/Docker) restarts the pod

6. **Observe Secondary Crash:** Monitor logs for cache fetch failure:
   ```
   thread 'tokio-runtime-worker' panicked at 'called `Result::unwrap()` on an `Err` value',
   ecosystem/indexer-grpc/indexer-grpc-file-store/src/processor.rs:165:14
   ```

7. **Verify Permanent Failure:** Confirm processor continues crashing on every restart attempt

**Recovery Verification:**
Manual recovery requires either:
- Restoring correct metadata: `{"chain_id": 1, "version": 300000, "storage_format": "Lz4CompressedProto"}`
- Clearing file store and cache to reindex from genesis
- Manually calculating correct version from file store contents

## Notes

This vulnerability affects the indexer infrastructure layer rather than core consensus, but meets the High severity criteria for "API crashes" as the indexer GRPC service is critical infrastructure for the Aptos ecosystem. The dual-failure mechanism (immediate crash + crash loop on restart) makes this particularly severe as it prevents automatic recovery and requires manual intervention to restore service.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store/src/processor.rs (L63-82)
```rust
        let file_store_metadata: Option<FileStoreMetadata> =
            file_store_operator.get_file_store_metadata().await;
        if file_store_metadata.is_none() {
            // If metadata doesn't exist, create and upload it and init file store latest version in cache.
            while file_store_operator
                .update_file_store_metadata_with_timeout(chain_id, 0)
                .await
                .is_err()
            {
                tracing::error!(
                    batch_start_version = 0,
                    service_type = SERVICE_TYPE,
                    "[File worker] Failed to update file store metadata. Retrying."
                );
                std::thread::sleep(std::time::Duration::from_millis(500));
                METADATA_UPLOAD_FAILURE_COUNT.inc();
            }
        }
        // Metadata is guaranteed to exist now
        let metadata = file_store_operator.get_file_store_metadata().await.unwrap();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store/src/processor.rs (L116-120)
```rust
        let metadata = self
            .file_store_operator
            .get_file_store_metadata()
            .await
            .unwrap();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store/src/processor.rs (L162-166)
```rust
                    let transactions = cache_operator_clone
                        .get_transactions(start_version, FILE_ENTRY_TRANSACTION_COUNT)
                        .await
                        .unwrap();
                    let last_transaction = transactions.last().unwrap().clone();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator/gcs.rs (L127-159)
```rust
    async fn get_file_store_metadata(&self) -> Option<FileStoreMetadata> {
        match Object::download(
            &self.bucket_name,
            self.metadata_file_path
                .to_str()
                .expect("Expected metadata file path to be valid."),
        )
        .await
        {
            Ok(metadata) => {
                let metadata: FileStoreMetadata =
                    serde_json::from_slice(&metadata).expect("Expected metadata to be valid JSON.");
                Some(metadata)
            },
            Err(cloud_storage::Error::Other(err)) => {
                if err.contains("No such object: ") {
                    // Metadata is not found.
                    None
                } else {
                    panic!(
                        "[Indexer File] Error happens when accessing metadata file. {}",
                        err
                    );
                }
            },
            Err(e) => {
                panic!(
                    "[Indexer File] Error happens when accessing metadata file. {}",
                    e
                );
            },
        }
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator/local.rs (L76-92)
```rust
    async fn get_file_store_metadata(&self) -> Option<FileStoreMetadata> {
        let metadata_path = self.path.join(METADATA_FILE_NAME);
        match tokio::fs::read(metadata_path).await {
            Ok(metadata) => Some(FileStoreMetadata::from_bytes(metadata)),
            Err(err) => {
                if err.kind() == std::io::ErrorKind::NotFound {
                    // Metadata is not found.
                    None
                } else {
                    panic!(
                        "[Indexer File] Error happens when accessing metadata file. {}",
                        err
                    );
                }
            },
        }
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/cache_operator.rs (L14-23)
```rust
pub const CACHE_SIZE_ESTIMATION: u64 = 250_000_u64;

pub const MAX_CACHE_FETCH_SIZE: u64 = 1000_u64;

// Hard limit for cache lower bound. Only used for active eviction.
// Cache worker actively evicts the cache entries if the cache entry version is
// lower than the latest version - CACHE_SIZE_EVICTION_LOWER_BOUND.
// The gap between CACHE_SIZE_ESTIMATION and this is to give buffer since
// reading latest version and actual data not atomic(two operations).
const CACHE_SIZE_EVICTION_LOWER_BOUND: u64 = 300_000_u64;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/cache_operator.rs (L367-395)
```rust
    pub async fn get_transactions_with_durations(
        &mut self,
        start_version: u64,
        transaction_count: u64,
    ) -> anyhow::Result<(Vec<Transaction>, f64, f64)> {
        let start_time = std::time::Instant::now();
        let versions = (start_version..start_version + transaction_count)
            .map(|e| CacheEntry::build_key(e, self.storage_format))
            .collect::<Vec<String>>();
        let encoded_transactions: Vec<Vec<u8>> = self
            .conn
            .mget(versions)
            .await
            .context("Failed to mget from Redis")?;
        let io_duration = start_time.elapsed().as_secs_f64();
        let start_time = std::time::Instant::now();
        let mut transactions = vec![];
        for encoded_transaction in encoded_transactions {
            let cache_entry: CacheEntry = CacheEntry::new(encoded_transaction, self.storage_format);
            let transaction = cache_entry.into_transaction();
            transactions.push(transaction);
        }
        ensure!(
            transactions.len() == transaction_count as usize,
            "Failed to get all transactions from cache."
        );
        let decoding_duration = start_time.elapsed().as_secs_f64();
        Ok((transactions, io_duration, decoding_duration))
    }
```

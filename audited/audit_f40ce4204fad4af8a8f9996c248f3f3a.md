# Audit Report

## Title
Indexer File Store Metadata Update Inconsistency Leading to Crash Recovery Failure

## Summary
The `LocalFileStoreOperator::update_file_store_metadata_with_timeout()` function ignores its `version` parameter, violating the trait contract and causing metadata staleness. This creates a window where processor crashes can result in metadata not reflecting the actual file store state, potentially causing cache worker synchronization failures and requiring manual intervention.

## Finding Description

The `FileStoreOperator` trait defines `update_file_store_metadata_with_timeout(expected_chain_id: u64, version: u64)` which should update the file store metadata with the provided version. However, the `LocalFileStoreOperator` implementation completely ignores the `version` parameter. [1](#0-0) 

In contrast, the `GcsFileStoreOperator` correctly uses the version parameter to update metadata: [2](#0-1) 

The file store processor relies on this function to update metadata after uploading transaction batches: [3](#0-2) 

**Attack Scenario:**
1. Processor successfully uploads transaction files for versions 1000-4999 to local file store
2. Processor calls `update_file_store_metadata_with_timeout(chain_id, 5000)` to update metadata
3. Local implementation does nothing (just validates chain_id), metadata remains at stale version (e.g., 1000)
4. Processor crashes before the periodic timeout-based metadata update in `upload_transaction_batch` occurs (5 second window)
5. On restart, processor reads stale metadata showing version 1000
6. Cache worker attempts to synchronize but encounters version mismatch, failing its validation: [4](#0-3) 

7. Indexer system requires manual intervention to recover

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty program: "State inconsistencies requiring intervention."

While this bug affects an off-chain indexing service (not core consensus), it can cause:
- **Operational disruption**: Cache worker fails to start after processor crashes
- **Data service unavailability**: Indexer API cannot serve queries until manual recovery
- **State inconsistency**: File store contains data up to version X but metadata claims version Y (Y < X)

The issue does NOT affect blockchain consensus, transaction execution, or fund security, limiting it to Medium severity.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability manifests whenever:
1. LocalFileStoreOperator is used (common in development/testing environments)
2. Processor crashes or is restarted between batch upload and timeout-based metadata update
3. The crash occurs within the 5-second window defined by `FILE_STORE_UPDATE_FREQUENCY_SECS` [5](#0-4) 

While the periodic update in `upload_transaction_batch` provides partial mitigation, the window exists and crashes during high-throughput periods increase likelihood.

## Recommendation

Fix `LocalFileStoreOperator::update_file_store_metadata_with_timeout()` to match the GCS implementation behavior:

```rust
async fn update_file_store_metadata_with_timeout(
    &mut self,
    expected_chain_id: u64,
    version: u64,  // Remove underscore prefix
) -> anyhow::Result<()> {
    let metadata_path = self.path.join(METADATA_FILE_NAME);
    match tokio::fs::read(metadata_path).await {
        Ok(metadata) => {
            let metadata: FileStoreMetadata =
                serde_json::from_slice(&metadata).expect("Expected metadata to be valid JSON.");
            anyhow::ensure!(metadata.chain_id == expected_chain_id, "Chain ID mismatch.");
            // Add version update logic:
            self.update_file_store_metadata_internal(expected_chain_id, version)
                .await?;
            Ok(())
        },
        Err(err) => {
            if err.kind() == std::io::ErrorKind::NotFound {
                info!("File store is empty. Creating metadata file.");
                self.update_file_store_metadata_internal(expected_chain_id, version)
                    .await
                    .expect("[Indexer File] Update metadata failed.");
                Ok(())
            } else {
                Err(anyhow::Error::msg(format!(
                    "Metadata not found or file store operator is not in write mode. {}",
                    err
                )))
            }
        },
    }
}
```

## Proof of Concept

Reproduction steps:

1. Configure indexer to use LocalFileStoreOperator
2. Start processor and let it upload several batches (e.g., versions 0-4999)
3. Before the 5-second timeout expires, forcefully kill the processor (SIGKILL)
4. Check metadata.json - it will show an outdated version
5. Restart processor - observe it attempts to re-process from stale version
6. Start cache worker - observe synchronization failure with version mismatch error

Expected behavior: Metadata should reflect version 5000 after step 2.
Actual behavior: Metadata shows stale version (e.g., 1000 or 0), causing recovery issues.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator/local.rs (L94-124)
```rust
    async fn update_file_store_metadata_with_timeout(
        &mut self,
        expected_chain_id: u64,
        _version: u64,
    ) -> anyhow::Result<()> {
        let metadata_path = self.path.join(METADATA_FILE_NAME);
        match tokio::fs::read(metadata_path).await {
            Ok(metadata) => {
                let metadata: FileStoreMetadata =
                    serde_json::from_slice(&metadata).expect("Expected metadata to be valid JSON.");
                anyhow::ensure!(metadata.chain_id == expected_chain_id, "Chain ID mismatch.");
                Ok(())
            },
            Err(err) => {
                if err.kind() == std::io::ErrorKind::NotFound {
                    // If the metadata is not found, it means the file store is empty.
                    info!("File store is empty. Creating metadata file.");
                    self.update_file_store_metadata_internal(expected_chain_id, 0)
                        .await
                        .expect("[Indexer File] Update metadata failed.");
                    Ok(())
                } else {
                    // If not in write mode, the metadata must exist.
                    Err(anyhow::Error::msg(format!(
                        "Metadata not found or file store operator is not in write mode. {}",
                        err
                    )))
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

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store/src/processor.rs (L261-273)
```rust
            while self
                .file_store_operator
                .update_file_store_metadata_with_timeout(chain_id, batch_start_version)
                .await
                .is_err()
            {
                tracing::error!(
                    batch_start_version = batch_start_version,
                    "Failed to update file store metadata. Retrying."
                );
                std::thread::sleep(std::time::Duration::from_millis(500));
                METADATA_UPLOAD_FAILURE_COUNT.inc();
            }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L316-319)
```rust
    // It's required to start the worker with the same version as file store.
    if file_store_metadata.version != starting_version {
        bail!("[Indexer Cache] Starting version mismatch between filestore metadata and fullnode init signal.");
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator/mod.rs (L17-17)
```rust
const FILE_STORE_UPDATE_FREQUENCY_SECS: u64 = 5;
```

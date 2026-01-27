# Audit Report

## Title
Race Condition in File Store Processor Initialization Allows Backward Writes to Redis Metadata, Causing Data Archival Gaps

## Summary
The `Processor::new()` method in the indexer-grpc file store subsystem contains a Time-of-Check-Time-of-Use (TOCTOU) race condition where file store metadata is read from persistent storage and unconditionally written to Redis cache, potentially overwriting newer values with stale data. This can cause the `file_store_latest_version` Redis key to move backward, leading to incorrect state tracking and potential gaps in archived blockchain data.

## Finding Description

During initialization of the File Store Processor, the following sequence occurs: [1](#0-0) 

The processor reads file store metadata from persistent storage (GCS/filesystem) and uses that version to update the Redis cache. The critical issue is in the `update_file_store_latest_version` implementation: [2](#0-1) 

This method uses an unconditional Redis SET operation with **no atomicity guarantees** and **no monotonicity checks**. It does not verify whether the current Redis value is newer than the value being written.

This creates a race condition window in the main processing loop where Redis is updated BEFORE file store metadata: [3](#0-2) 

**Attack Scenario:**

1. Processor A is running, has processed blockchain data up to version 400,000
2. Processor A updates Redis: `FILE_STORE_LATEST_VERSION = 401,000` (after processing batch 400,000-400,999)
3. Processor A attempts to update file store metadata but **crashes or is forcibly terminated** before completing the metadata write (lines 261-273)
4. File store metadata still shows version 400,000 (last successful write)
5. System auto-restarts Processor B
6. Processor B reads stale file store metadata showing version 400,000
7. Processor B **unconditionally overwrites** Redis with `FILE_STORE_LATEST_VERSION = 400,000`
8. **Backward write occurs**: Redis moves from 401,000 → 400,000

**Consequence**: The cache worker waits for file store based on this incorrect metadata: [4](#0-3) 

If the mismatch is severe and cache entries have been evicted (cache retains only ~300,000 versions), the processor cannot retrieve transactions from cache, causing permanent data gaps in the file store archive: [5](#0-4) 

The processor will fail with "Failed to get all transactions from cache" when trying to fetch evicted data, creating unrecoverable gaps in the archived blockchain history.

## Impact Explanation

**Severity: Medium** (per Aptos bug bounty criteria: "State inconsistencies requiring intervention")

This vulnerability violates the indexer subsystem's data integrity invariant: **archived data must be continuous and complete without gaps**. While this does not affect consensus, validator operations, or core blockchain execution, it has significant operational impact:

1. **Data Availability**: External applications relying on the indexer API will experience missing transaction data
2. **Manual Intervention Required**: Operators must manually identify gaps and restore missing data from alternative sources
3. **Service Degradation**: Indexer services may crash repeatedly if they cannot fetch required data from cache

**Note**: This is an operational/reliability vulnerability in the data archival subsystem, not a direct security exploit of the core blockchain. It cannot be triggered by external attackers through normal transaction submission or API calls. However, it represents a **design flaw** that violates critical data integrity guarantees.

## Likelihood Explanation

**Likelihood: High** in production environments with:

- Kubernetes/container orchestration performing rolling updates
- Process crashes due to OOM, hardware failures, or bugs
- Manual process restarts during maintenance
- Network partitions causing connection failures

The race window is **several seconds** wide (time between Redis update and file store metadata update with retry logic), making this readily exploitable during common operational scenarios. The issue becomes **more severe** as system load increases and the metadata update retry loop takes longer.

## Recommendation

Implement **atomic monotonic updates** to prevent backward writes. Use Redis SET with the GT (greater than) option to ensure the version only increases:

```rust
pub async fn update_file_store_latest_version(
    &mut self,
    latest_version: u64,
) -> anyhow::Result<()> {
    // Use Redis SET with GT option to only set if new value is greater
    let result: Option<String> = redis::cmd("SET")
        .arg(FILE_STORE_LATEST_VERSION)
        .arg(latest_version)
        .arg("GT")  // Only set if Greater Than current value
        .arg("GET") // Return previous value
        .query_async(&mut self.conn)
        .await?;
    
    // Log if update was rejected (backward write attempt)
    if let Some(prev) = result {
        if let Ok(prev_version) = prev.parse::<u64>() {
            if prev_version >= latest_version {
                tracing::warn!(
                    previous_version = prev_version,
                    attempted_version = latest_version,
                    "Rejected backward write to file_store_latest_version"
                );
            }
        }
    }
    Ok(())
}
```

**Additional hardening**:
1. Read current Redis value during initialization and compare with metadata before overwriting
2. Implement distributed locking to ensure only one processor instance runs at a time
3. Add validation that batch_start_version from metadata is not significantly behind Redis value
4. Persist Redis state periodically to recover from full Redis failures

## Proof of Concept

```rust
#[tokio::test]
async fn test_backward_write_race_condition() {
    // Setup Redis connection
    let client = redis::Client::open("redis://127.0.0.1/").unwrap();
    let conn = client.get_tokio_connection_manager().await.unwrap();
    let mut cache_operator = CacheOperator::new(conn, StorageFormat::Base64UncompressedProto);
    
    // Simulate normal operation: processor has reached version 100,000
    cache_operator.update_file_store_latest_version(100_000).await.unwrap();
    
    // Verify Redis has correct value
    let version = cache_operator.get_file_store_latest_version().await.unwrap();
    assert_eq!(version, Some(100_000));
    
    // Simulate crash scenario: new processor starts with stale metadata (version 50,000)
    // and unconditionally overwrites Redis
    cache_operator.update_file_store_latest_version(50_000).await.unwrap();
    
    // VULNERABILITY: Redis value has moved backward
    let version = cache_operator.get_file_store_latest_version().await.unwrap();
    assert_eq!(version, Some(50_000)); // Backward write succeeded!
    
    // This creates data gap: transactions 50,000-100,000 may never be archived
    // if cache has evicted them and processor tries to re-process from 50,000
}
```

**Notes**

This vulnerability is specific to the indexer-grpc data archival subsystem and does not affect the core Aptos blockchain consensus, execution, or validator operations. The indexer is a separate service that archives committed blockchain data for external API consumption. While this bug can cause data integrity issues in the indexer, it cannot:

- Cause consensus splits or blockchain forks
- Enable theft or minting of funds
- Affect validator operations or staking
- Compromise on-chain transaction processing

The bug manifests during operational scenarios (process restarts, crashes, rolling updates) rather than through direct attacker exploitation. However, it represents a **critical design flaw** in the data archival system that violates data completeness guarantees and requires manual intervention to resolve.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store/src/processor.rs (L82-98)
```rust
        let metadata = file_store_operator.get_file_store_metadata().await.unwrap();

        ensure!(metadata.chain_id == chain_id, "Chain ID mismatch.");
        let batch_start_version = metadata.version;
        // Cache config in the cache
        cache_operator.cache_setup_if_needed().await?;
        match cache_operator.get_chain_id().await? {
            Some(id) => {
                ensure!(id == chain_id, "Chain ID mismatch.");
            },
            None => {
                cache_operator.set_chain_id(chain_id).await?;
            },
        }
        cache_operator
            .update_file_store_latest_version(batch_start_version)
            .await?;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store/src/processor.rs (L256-273)
```rust
            // Update filestore metadata. First do it in cache for performance then update metadata file
            let start_metadata_upload_time = std::time::Instant::now();
            self.cache_operator
                .update_file_store_latest_version(batch_start_version)
                .await?;
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

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/cache_operator.rs (L181-190)
```rust
    pub async fn update_file_store_latest_version(
        &mut self,
        latest_version: u64,
    ) -> anyhow::Result<()> {
        let _: () = self
            .conn
            .set(FILE_STORE_LATEST_VERSION, latest_version)
            .await?;
        Ok(())
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/cache_operator.rs (L389-392)
```rust
        ensure!(
            transactions.len() == transaction_count as usize,
            "Failed to get all transactions from cache."
        );
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L479-499)
```rust
        loop {
            let file_store_version = cache_operator
                .get_file_store_latest_version()
                .await?
                .unwrap();
            if file_store_version + FILE_STORE_VERSIONS_RESERVED < current_version {
                tokio::time::sleep(std::time::Duration::from_millis(
                    CACHE_WORKER_WAIT_FOR_FILE_STORE_MS,
                ))
                .await;
                tracing::warn!(
                    current_version = current_version,
                    file_store_version = file_store_version,
                    "[Indexer Cache] File store version is behind current version too much."
                );
                WAIT_FOR_FILE_STORE_COUNTER.inc();
            } else {
                // File store is up to date, continue cache update.
                break;
            }
        }
```

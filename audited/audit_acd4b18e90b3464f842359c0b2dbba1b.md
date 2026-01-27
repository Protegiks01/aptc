# Audit Report

## Title
Cache Worker Panic Due to Missing File Store Version in Redis During Stream Processing

## Summary

The indexer-grpc cache worker contains a critical unwrap operation at line 483 that can cause a panic when the Redis key `FILE_STORE_LATEST_VERSION` is missing or not yet initialized. This occurs during active stream processing, causing immediate service termination and disruption to the Aptos blockchain data indexing infrastructure. [1](#0-0) 

## Finding Description

The vulnerability exists in the `process_streaming_response()` function where the cache worker checks if the file store version is keeping pace with the cache. The code unconditionally unwraps the result of `get_file_store_latest_version()`, which returns `Result<Option<u64>>`. [2](#0-1) 

The `get_config_by_key()` method returns `Ok(None)` when the Redis key is empty or missing: [3](#0-2) 

**Attack/Failure Scenarios:**

1. **Service Startup Race Condition**: The documented startup sequence shows the cache worker starts first and waits for file store metadata to exist in storage. However, the cache worker never verifies that the `FILE_STORE_LATEST_VERSION` Redis key has been initialized by the file store processor. [4](#0-3) 

The cache worker waits only for file store metadata from storage, not the Redis key: [5](#0-4) 

Meanwhile, the file store processor sets the Redis key during its initialization: [6](#0-5) 

**Exploitation Path:**
- Cache worker starts and waits for file store metadata (from GCS/filesystem)
- File store processor creates/verifies metadata and writes to storage
- Cache worker detects metadata exists and proceeds to start streaming
- Cache worker begins processing transactions in `process_streaming_response()`
- File store processor hasn't yet completed initialization to line 97 (Redis key set)
- Cache worker reaches line 483 in the processing loop
- `get_file_store_latest_version()` returns `Ok(None)` because Redis key not set
- `.unwrap()` panics, crashing the cache worker mid-stream

2. **Redis Data Loss**: If Redis restarts without persistence, or if data is flushed (as documented in the cleanup procedure), the `FILE_STORE_LATEST_VERSION` key disappears while the cache worker is running. [7](#0-6) 

3. **Operational Error**: An operator or automation script accidentally deletes the Redis key during maintenance.

## Impact Explanation

This qualifies as **High Severity** per Aptos bug bounty criteria: **"API crashes"**.

The indexer-grpc system is critical infrastructure that serves blockchain transaction data to downstream applications, indexers, and analytics platforms. When the cache worker panics:

- Immediate service termination (panic causes process crash)
- Complete loss of real-time transaction streaming to cache
- Downstream data services lose access to recent transaction data
- Requires manual operator intervention to restart services
- Data indexing lag accumulates during downtime
- Potential data consistency issues if restart occurs mid-batch

The panic occurs in the main processing loop during active transaction streaming, not during controlled shutdown or error recovery paths. This breaks the availability/liveness invariant for the indexer infrastructure.

## Likelihood Explanation

**High Likelihood** - This vulnerability can be triggered through multiple realistic scenarios:

1. **Service Deployment**: Every time the indexer-grpc services are deployed or restarted according to the documented startup sequence, there is a race condition window. The README explicitly notes the cache worker may exit and need restart, indicating this is a known operational pattern.

2. **Redis Maintenance**: Standard Redis operations (restart, failover, data migration) will trigger this issue if the cache worker is running during the operation.

3. **Resource Constraints**: If the file store processor starts slowly due to resource constraints (network latency to GCS, CPU contention), the race window increases.

The issue is deterministic once the conditions are met (missing Redis key + cache worker reaches line 483), making it reliably reproducible.

## Recommendation

Replace the unwrap with proper error handling that waits for the Redis key to be initialized, similar to how the cache worker already waits for file store metadata:

```rust
// Check if the file store isn't too far away
loop {
    let file_store_version = loop {
        match cache_operator.get_file_store_latest_version().await? {
            Some(version) => break version,
            None => {
                tracing::warn!(
                    "[Indexer Cache] File store latest version not found in Redis. Waiting for {} ms.",
                    CACHE_WORKER_WAIT_FOR_FILE_STORE_MS
                );
                tokio::time::sleep(std::time::Duration::from_millis(
                    CACHE_WORKER_WAIT_FOR_FILE_STORE_MS,
                ))
                .await;
            }
        }
    };
    
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

Additionally, consider adding a startup synchronization check to verify the Redis key exists before entering the main processing loop.

## Proof of Concept

**Reproduction Steps:**

1. Start Redis server
2. Create local file store directory and initialize metadata file manually (simulating file store processor partial initialization)
3. Start cache worker with configuration pointing to local file store
4. Observe cache worker proceeds past metadata check
5. Do NOT start file store processor (so Redis key is never set)
6. Cache worker will panic when reaching line 483

**Integration Test Scenario:**

```rust
#[tokio::test]
async fn test_cache_worker_panic_on_missing_file_store_version() {
    // Setup: Start Redis and create file store metadata
    let redis_client = redis::Client::open("redis://127.0.0.1:6379/").unwrap();
    let mut conn = redis_client.get_tokio_connection_manager().await.unwrap();
    
    // Create file store metadata file (simulates file store processor partial init)
    let metadata = FileStoreMetadata {
        chain_id: 1,
        version: 0,
    };
    // Write metadata to local file store...
    
    // Start cache worker WITHOUT initializing FILE_STORE_LATEST_VERSION in Redis
    // Expected: Cache worker should panic at line 483 when processing stream
    
    // Setup cache operator
    let mut cache_operator = CacheOperator::new(conn.clone(), StorageFormat::Base64UncompressedProto);
    cache_operator.set_chain_id(1).await.unwrap();
    
    // Verify FILE_STORE_LATEST_VERSION is not set
    assert!(cache_operator.get_file_store_latest_version().await.unwrap().is_none());
    
    // This will panic with "called `Option::unwrap()` on a `None` value"
    let _ = cache_operator.get_file_store_latest_version().await.unwrap().unwrap();
}
```

**Notes**

- This vulnerability is specific to the indexer-grpc infrastructure, not the core consensus or Move VM components
- The issue affects data availability for applications relying on the indexer, but does not directly impact validator consensus or on-chain state
- The severity is appropriately classified as High (API crashes) rather than Critical, as it does not involve fund loss or consensus violations
- The recommended fix follows the same pattern already used in the codebase for waiting on file store metadata availability

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L119-139)
```rust
            // 1. Fetch metadata.
            let file_store_operator: Box<dyn FileStoreOperator> = self.file_store.create();
            // TODO: move chain id check somewhere around here
            // This ensures that metadata is created before we start the cache worker
            let mut starting_version = file_store_operator.get_latest_version().await;
            while starting_version.is_none() {
                starting_version = file_store_operator.get_latest_version().await;
                tracing::warn!(
                    "[Indexer Cache] File store metadata not found. Waiting for {} ms.",
                    FILE_STORE_METADATA_WAIT_MS
                );
                tokio::time::sleep(std::time::Duration::from_millis(
                    FILE_STORE_METADATA_WAIT_MS,
                ))
                .await;
            }

            // There's a guarantee at this point that starting_version is not null
            let starting_version = starting_version.unwrap();

            let file_store_metadata = file_store_operator.get_file_store_metadata().await.unwrap();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L480-483)
```rust
            let file_store_version = cache_operator
                .get_file_store_latest_version()
                .await?
                .unwrap();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/cache_operator.rs (L164-166)
```rust
    pub async fn get_file_store_latest_version(&mut self) -> anyhow::Result<Option<u64>> {
        self.get_config_by_key(FILE_STORE_LATEST_VERSION).await
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/cache_operator.rs (L169-179)
```rust
    async fn get_config_by_key(&mut self, key: &str) -> anyhow::Result<Option<u64>> {
        let result = self.conn.get::<&str, Vec<u8>>(key).await?;
        if result.is_empty() {
            Ok(None)
        } else {
            let result_string = String::from_utf8(result).unwrap();
            Ok(Some(result_string.parse::<u64>().with_context(|| {
                format!("Redis key {} is not a number.", key)
            })?))
        }
    }
```

**File:** ecosystem/indexer-grpc/README.md (L17-23)
```markdown
### General Startup

The implementation is up to the operator, but in general:
* Start the full node and cache worker (for more information, refer to `indexer-grpc-cache-worker`)
  * Note: : the cache worker will exit after 1 minute since the file store is not ready. Please restart it.
* Start the file store worker (for more information, refer to `indexer-grpc-file-store`).
* Start the data service (for more information, refer to `indexer-grpc-data-service`).
```

**File:** ecosystem/indexer-grpc/README.md (L93-96)
```markdown
#### Clean up

Clean up all the persistence layers:
* Remove redis data: `redis-cli -p 6379 flushall`
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store/src/processor.rs (L96-98)
```rust
        cache_operator
            .update_file_store_latest_version(batch_start_version)
            .await?;
```

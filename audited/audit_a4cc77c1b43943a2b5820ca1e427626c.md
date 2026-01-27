# Audit Report

## Title
Partial Redis Initialization Causes Indexer System Deadlock on Transient Connection Failures

## Summary
A transient Redis connection failure during file store processor initialization can leave the system in a partially initialized state where critical Redis keys (`chain_id` and `file_store_latest_version`) are missing, causing the cache worker to panic on startup with unwrap errors, resulting in complete indexer service unavailability.

## Finding Description

The vulnerability exists in the initialization sequence of the file store processor. When `Processor::new()` establishes a Redis connection and begins initialization, it performs several Redis operations in sequence: [1](#0-0) 

The initialization flow is:
1. File store metadata is created/uploaded (lines 67-80) with version 0
2. `cache_setup_if_needed()` sets Redis key `latest_version` = "0" (line 87)
3. `get_chain_id()` and conditionally `set_chain_id()` (lines 88-94)
4. `update_file_store_latest_version()` sets Redis key `file_store_latest_version` (lines 96-98)

If Redis connection fails after line 87 but before line 98 completes, the system enters an inconsistent state:
- File store metadata: ✓ exists (version 0)
- Redis `latest_version`: ✓ set to "0"
- Redis `chain_id`: ✗ **NOT SET**
- Redis `file_store_latest_version`: ✗ **NOT SET**

The cache worker depends on these Redis keys being present and uses `.unwrap()` without checking: [2](#0-1) [3](#0-2) 

When the cache worker attempts to start after a partial initialization, it will panic with "called `Option::unwrap()` on a `None` value" when these Redis keys are missing. The comment at line 310 states "Guaranteed that chain id is here at this point because we already ensure that fileworker did the set up" - **but this guarantee is violated** when the file worker fails mid-initialization.

The processor initialization uses `.expect()` which causes immediate crash on failure: [4](#0-3) 

## Impact Explanation

This qualifies as **Medium severity** per Aptos bug bounty criteria: "State inconsistencies requiring intervention."

**Impact:**
- Complete indexer service unavailability - neither file store processor nor cache worker can operate
- Requires manual operator intervention to recover (either restart services in correct order after Redis recovery, or manually set missing Redis keys)
- Affects all users and applications depending on the indexer-grpc service for blockchain data access
- Creates operational burden and extended downtime during transient Redis failures

While this doesn't affect core blockchain consensus or validator operations, it breaks the indexer service's availability guarantees and creates a deadlock requiring human intervention.

## Likelihood Explanation

**Likelihood: Medium-High**

This can occur during:
- Transient Redis network failures or timeouts during initialization
- Redis server restarts or maintenance windows
- Network partitions between the processor and Redis
- Resource exhaustion on Redis server causing connection drops
- Container orchestration scenarios where services start/restart in unpredictable orders

The window for this race condition is small (between lines 87-98), but Redis operations over network are inherently susceptible to transient failures. Production systems commonly experience such transient failures, making this a realistic operational scenario.

## Recommendation

**Solution 1: Make initialization atomic and idempotent**

Wrap all Redis initialization operations in a transaction or retry loop to ensure atomic completion:

```rust
pub async fn new(
    redis_main_instance_address: RedisUrl,
    file_store_config: IndexerGrpcFileStoreConfig,
    chain_id: u64,
    enable_cache_compression: bool,
) -> Result<Self> {
    // ... existing code up to line 85 ...
    
    // Atomically initialize all Redis keys with retry logic
    let mut retry_count = 0;
    const MAX_RETRIES: u32 = 5;
    loop {
        match initialize_cache_atomically(
            &mut cache_operator, 
            chain_id, 
            batch_start_version
        ).await {
            Ok(_) => break,
            Err(e) if retry_count < MAX_RETRIES => {
                retry_count += 1;
                tracing::warn!(
                    retry_count = retry_count,
                    error = ?e,
                    "Redis initialization failed, retrying..."
                );
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => return Err(e),
        }
    }
    
    Ok(Self { cache_operator, file_store_operator, chain_id })
}

async fn initialize_cache_atomically(
    cache_operator: &mut CacheOperator<redis::aio::ConnectionManager>,
    chain_id: u64,
    batch_start_version: u64,
) -> Result<()> {
    cache_operator.cache_setup_if_needed().await?;
    match cache_operator.get_chain_id().await? {
        Some(id) => ensure!(id == chain_id, "Chain ID mismatch."),
        None => cache_operator.set_chain_id(chain_id).await?,
    }
    cache_operator.update_file_store_latest_version(batch_start_version).await?;
    Ok(())
}
```

**Solution 2: Fix cache worker to handle missing keys gracefully**

Replace `.unwrap()` calls with proper error handling:

```rust
// In worker.rs line 311:
let chain_id = match cache_operator.get_chain_id().await? {
    Some(id) => id,
    None => {
        bail!("[Indexer Cache] Chain ID not found in cache. File worker may not have completed initialization.");
    }
};

// In worker.rs line 480-483:
let file_store_version = match cache_operator.get_file_store_latest_version().await? {
    Some(v) => v,
    None => {
        bail!("[Indexer Cache] File store version not found in cache. File worker may not have completed initialization.");
    }
};
```

**Recommended approach:** Implement both solutions for defense in depth.

## Proof of Concept

```rust
// Reproduction steps (pseudo-code for testing):

#[tokio::test]
async fn test_partial_redis_initialization() {
    // 1. Start mock Redis server
    let redis = start_test_redis().await;
    
    // 2. Create file store processor
    let config = create_test_config();
    
    // 3. Inject Redis connection failure after cache_setup_if_needed()
    // This simulates network failure at line 88
    let mock_redis = MockRedisConnection::new_with_failure_after_n_ops(1);
    
    // 4. Attempt initialization - should fail after partial setup
    let result = Processor::new(
        redis_url.clone(),
        config.clone(),
        1, // chain_id
        false
    ).await;
    
    assert!(result.is_err(), "Initialization should fail");
    
    // 5. Verify partial state
    let mut cache_op = CacheOperator::new(new_connection, StorageFormat::Base64UncompressedProto);
    assert_eq!(cache_op.get_latest_version().await.unwrap(), Some(0)); // Set
    assert_eq!(cache_op.get_chain_id().await.unwrap(), None); // NOT set
    assert_eq!(cache_op.get_file_store_latest_version().await.unwrap(), None); // NOT set
    
    // 6. Attempt to start cache worker - should panic
    let worker_result = std::panic::catch_unwind(|| {
        let mut worker = Worker::new(/* ... */).await.unwrap();
        worker.run().await
    });
    
    assert!(worker_result.is_err(), "Cache worker should panic on unwrap");
}
```

**Notes:**
- This is a state management vulnerability in the indexer-grpc subsystem
- While not affecting core blockchain consensus, it breaks indexer service availability
- The vulnerability violates the assumption that file worker initialization is atomic
- Requires operator intervention to recover from partial initialization state

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store/src/processor.rs (L87-98)
```rust
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

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L310-311)
```rust
    // Guaranteed that chain id is here at this point because we already ensure that fileworker did the set up
    let chain_id = cache_operator.get_chain_id().await?.unwrap();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L480-483)
```rust
            let file_store_version = cache_operator
                .get_file_store_latest_version()
                .await?
                .unwrap();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store/src/lib.rs (L49-56)
```rust
        let mut processor = Processor::new(
            self.redis_main_instance_address.clone(),
            self.file_store_config.clone(),
            self.chain_id,
            self.enable_cache_compression,
        )
        .await
        .expect("Failed to create file store processor");
```

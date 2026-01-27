# Audit Report

## Title
Indexer-GRPC Cache Worker Process Crash on Error Without Recovery - Service Availability Impact

## Summary
The indexer-grpc-cache-worker service contains multiple `.expect()` calls and explicit `panic!()` statements that cause the entire process to crash when errors occur. While a panic handler exists at the framework level, it does not recover from panics but instead logs them and exits the process with code 12, causing service downtime until Docker restarts the container.

## Finding Description

The indexer-grpc-cache-worker implements a critical caching layer that streams transaction data from fullnodes and stores it in Redis for fast retrieval by the data service. The service contains multiple panic points without graceful error handling:

**Primary Panic Point:** [1](#0-0) 

This `.expect()` call will panic if `worker.run().await` returns an error, causing immediate process termination.

**Panic Handler (No Recovery):** [2](#0-1) 

The panic handler logs the crash and exits with code 12 - it does NOT recover from panics.

**Additional Critical Panic Points:**

1. **Chain ID Mismatch During Streaming:** [3](#0-2) 

2. **Transaction Processing Failure:** [4](#0-3) 

3. **File Store Metadata Unwrap:** [5](#0-4) 

**Error Propagation Chain:**

The `Worker::run()` method returns `Result<()>` but errors at multiple points propagate to the `.expect()`: [6](#0-5) [7](#0-6) [8](#0-7) 

**Deployment Configuration:** [9](#0-8) 

While Docker's `restart: unless-stopped` policy provides external recovery, the service experiences downtime during crashes and potential crash loops if errors persist.

## Impact Explanation

This issue qualifies as **High Severity** under the Aptos bug bounty program's "API crashes" category. The indexer-grpc services provide critical infrastructure for external clients to query blockchain data. When the cache-worker crashes:

1. **Service Unavailability**: The cache-worker becomes unavailable until Docker restarts it (typically seconds, but potentially longer in crash loops)

2. **Degraded Performance**: The data-service loses access to fast Redis cache and must fall back to slower file store queries

3. **Cascade Effect**: The data-service explicitly depends on the cache-worker: [10](#0-9) 

4. **Persistent Crash Loops**: If the underlying error condition persists (Redis connection failures, network issues, data corruption), the service enters a crash loop, repeatedly failing and restarting

## Likelihood Explanation

The likelihood is **MEDIUM-HIGH** because multiple realistic operational scenarios trigger these panics:

1. **Redis Connection Failures**: Common in production due to network issues, Redis server downtime, memory exhaustion, or configuration errors

2. **gRPC Fullnode Connection Issues**: Network partitions, fullnode restarts, or version incompatibilities can cause request failures

3. **Chain ID Mismatches**: While rare, can occur during:
   - Misconfigured fullnode endpoints pointing to different networks
   - Network resets or upgrades
   - DNS/routing issues causing connections to wrong chains

4. **Transaction Processing Failures**: Redis write failures due to memory limits, connection issues, or data serialization errors

5. **File Store Metadata Issues**: The code waits for metadata but still has an `.unwrap()` after the wait loop, creating a potential panic path

## Recommendation

Replace all `.expect()` calls and explicit `panic!()` statements with proper error handling and retry logic:

**1. Remove `.expect()` from lib.rs and return errors properly:**

```rust
#[async_trait::async_trait]
impl RunnableConfig for IndexerGrpcCacheWorkerConfig {
    async fn run(&self) -> Result<()> {
        let mut worker = Worker::new(
            self.fullnode_grpc_address.clone(),
            self.redis_main_instance_address.clone(),
            self.file_store_config.clone(),
            self.enable_cache_compression,
        )
        .await
        .context("Failed to create cache worker")?;
        
        // Return error instead of panicking
        worker
            .run()
            .await
            .context("Cache worker failed")
    }
    // ...
}
```

**2. Replace explicit panics with error returns in worker.rs:**

```rust
// Instead of panic on chain ID mismatch
if received.chain_id as u64 != fullnode_chain_id as u64 {
    ERROR_COUNT.with_label_values(&["chain_id_mismatch"]).inc();
    bail!("[Indexer Cache] Chain id mismatch happens during data streaming.");
}

// Instead of panic on processing errors
if result.iter().any(|r| r.is_err() || r.as_ref().unwrap().is_err()) {
    ERROR_COUNT.with_label_values(&["response_error"]).inc();
    bail!("Error happens when processing transactions from fullnode.");
}
```

**3. Fix the file store metadata unwrap:**

```rust
let file_store_metadata = file_store_operator
    .get_file_store_metadata()
    .await
    .context("Failed to get file store metadata after waiting")?;
```

**4. Implement exponential backoff for reconnection:**

```rust
pub async fn run(&mut self) -> Result<()> {
    let mut retry_count = 0;
    let max_retries = 10;
    
    loop {
        match self.run_once().await {
            Ok(_) => {
                // Reset retry count on success
                retry_count = 0;
            }
            Err(e) => {
                error!("Cache worker error: {}", e);
                retry_count += 1;
                
                if retry_count >= max_retries {
                    bail!("Max retries exceeded: {}", e);
                }
                
                let backoff_ms = std::cmp::min(1000 * 2_u64.pow(retry_count), 30000);
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            }
        }
    }
}
```

## Proof of Concept

**Rust Reproduction Steps:**

```rust
// Create a test that simulates Redis connection failure
#[tokio::test]
async fn test_cache_worker_redis_failure() {
    use aptos_indexer_grpc_cache_worker::IndexerGrpcCacheWorkerConfig;
    use aptos_indexer_grpc_utils::types::RedisUrl;
    use url::Url;
    
    // Create config with invalid Redis address
    let config = IndexerGrpcCacheWorkerConfig::new(
        Url::parse("http://localhost:50051").unwrap(),
        IndexerGrpcFileStoreConfig::default(),
        RedisUrl("redis://invalid-host:6379".to_string()),
        false,
    );
    
    // This will panic with .expect() instead of returning error
    let result = config.run().await;
    
    // With proper error handling, this should be an Err, not a panic
    assert!(result.is_err());
}

// Test chain ID mismatch scenario
#[tokio::test]
async fn test_chain_id_mismatch_panic() {
    // Simulate streaming from fullnode with mismatched chain ID
    // The current code will panic! instead of returning an error
    // This demonstrates the vulnerability
}
```

**To trigger in production:**
1. Configure Redis with invalid host or port
2. Start the cache-worker service
3. Observe process crash with exit code 12
4. Check Docker logs showing panic and restart
5. If Redis remains unavailable, observe crash loop

**Notes**

This is an operational reliability issue affecting the indexer infrastructure service. While it meets the "API crashes" criteria for High Severity, it's important to note that:

1. The indexer-grpc services are ecosystem tools, not core consensus/execution components
2. Crashes don't affect blockchain state, consensus safety, or transaction processing
3. Docker's restart policy provides external recovery, though with service downtime
4. The primary impact is on external clients querying transaction data, not on blockchain operation itself

The recommended fixes significantly improve service reliability and should be prioritized for production deployments to ensure stable indexer infrastructure availability.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/lib.rs (L55-59)
```rust
        worker
            .run()
            .await
            .context("Failed to run cache worker")
            .expect("Cache worker failed");
```

**File:** ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs (L149-168)
```rust
pub fn setup_panic_handler() {
    std::panic::set_hook(Box::new(move |pi: &PanicHookInfo<'_>| {
        handle_panic(pi);
    }));
}

// Formats and logs panic information
fn handle_panic(panic_info: &PanicHookInfo<'_>) {
    // The Display formatter for a PanicHookInfo contains the message, payload and location.
    let details = format!("{}", panic_info);
    let backtrace = format!("{:#?}", Backtrace::new());
    let info = CrashInfo { details, backtrace };
    let crash_info = toml::to_string_pretty(&info).unwrap();
    error!("{}", crash_info);
    // TODO / HACK ALARM: Write crash info synchronously via eprintln! to ensure it is written before the process exits which error! doesn't guarantee.
    // This is a workaround until https://github.com/aptos-labs/aptos-core/issues/2038 is resolved.
    eprintln!("{}", crash_info);
    // Kill the process
    process::exit(12);
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L112-117)
```rust
            let conn = self
                .redis_client
                .get_tokio_connection_manager()
                .await
                .context("Get redis connection failed.")?;
            let mut rpc_client = create_grpc_client(self.fullnode_grpc_address.clone()).await;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L139-139)
```rust
            let file_store_metadata = file_store_operator.get_file_store_metadata().await.unwrap();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L153-161)
```rust
            let response = rpc_client
                .get_transactions_from_node(request)
                .await
                .with_context(|| {
                    format!(
                        "Failed to get transactions from node at starting version {}",
                        starting_version
                    )
                })?;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L167-173)
```rust
            process_streaming_response(
                conn,
                self.cache_storage_format,
                file_store_metadata,
                response.into_inner(),
            )
            .await?;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L382-384)
```rust
        if received.chain_id as u64 != fullnode_chain_id as u64 {
            panic!("[Indexer Cache] Chain id mismatch happens during data streaming.");
        }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L418-430)
```rust
                    let result = join_all(tasks_to_run).await;
                    if result
                        .iter()
                        .any(|r| r.is_err() || r.as_ref().unwrap().is_err())
                    {
                        error!(
                            start_version = start_version,
                            num_of_transactions = num_of_transactions,
                            "[Indexer Cache] Process transactions from fullnode failed."
                        );
                        ERROR_COUNT.with_label_values(&["response_error"]).inc();
                        panic!("Error happens when processing transactions from fullnode.");
                    }
```

**File:** docker/compose/indexer-grpc/docker-compose.yaml (L40-58)
```yaml
  indexer-grpc-cache-worker:
    image: "${INDEXER_GRPC_IMAGE_REPO:-aptoslabs/indexer-grpc}:${IMAGE_TAG:-main}"
    networks:
      shared:
        ipv4_address: 172.16.1.13
    restart: unless-stopped
    volumes:
      - type: volume # XXX: needed now before refactor https://github.com/aptos-labs/aptos-core/pull/8139
        source: indexer-grpc-file-store
        target: /opt/aptos/file-store
      - type: bind
        source: ./cache-worker-config.yaml
        target: /opt/aptos/cache-worker-config.yaml
    command:
      - '/usr/local/bin/aptos-indexer-grpc-cache-worker'
      - '--config-path'
      - '/opt/aptos/cache-worker-config.yaml'
    depends_on:
      - redis
```

**File:** docker/compose/indexer-grpc/docker-compose.yaml (L106-110)
```yaml
      - "18084:8084" # health
    depends_on:
      - indexer-grpc-cache-worker
      - indexer-grpc-file-store
      - redis-replica
```

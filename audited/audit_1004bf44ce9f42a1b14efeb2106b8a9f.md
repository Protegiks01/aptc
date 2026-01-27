# Audit Report

## Title
Missing Cache Configuration Validation in IndexerGrpcManagerConfig Leads to Service Unavailability

## Summary
The `IndexerGrpcManagerConfig` struct lacks validation for its `cache_config` fields (`max_cache_size` and `target_cache_size`), relying on the default `RunnableConfig::validate()` that returns `Ok(())`. [1](#0-0)  This allows invalid configurations where `target_cache_size >= max_cache_size`, causing the garbage collection logic in `Cache::maybe_gc()` to fail repeatedly, resulting in denial of service for the indexer-grpc-manager.

## Finding Description

The `IndexerGrpcManagerConfig` struct implements the `RunnableConfig` trait without overriding the `validate()` method. [2](#0-1)  The default implementation simply returns `Ok(())`. [3](#0-2) 

The `CacheConfig` contains two critical fields that control the cache garbage collection behavior. [4](#0-3)  These values are used in the `Cache::maybe_gc()` function which implements the following logic:

1. If `cache_size <= max_cache_size`, return true (no GC needed)
2. Otherwise, evict transactions until `cache_size <= target_cache_size`
3. Return whether `cache_size <= max_cache_size` [5](#0-4) 

**Attack Scenario:**

An operator deploys the indexer-grpc-manager with a misconfigured YAML file:
```yaml
cache_config:
  max_cache_size: 4294967296  # 4GB
  target_cache_size: 5368709120  # 5GB (INVALID: larger than max)
```

When this configuration is loaded:
1. The service starts successfully (no validation error)
2. The `DataManager` begins caching transactions
3. When `cache_size` exceeds `max_cache_size` (e.g., reaches 4.5GB), `maybe_gc()` is called
4. Line 64 fails: `4.5GB > 4GB`, so it doesn't return early
5. The GC loop condition `cache_size > target_cache_size` evaluates to `4.5GB > 5GB` = false
6. No transactions are evicted
7. Line 79 returns `4.5GB <= 4GB` = false
8. The `start()` function enters an infinite loop [6](#0-5) , continuously logging warnings and sleeping
9. The service stops accepting new transactions from fullnodes
10. All gRPC clients experience timeouts and data unavailability

This breaks the service availability guarantee for the indexer infrastructure.

## Impact Explanation

This vulnerability causes **denial of service** for the indexer-grpc-manager, which is a critical component of the Aptos indexer infrastructure. According to the Aptos bug bounty program, this falls under **High Severity: API crashes** (up to $50,000).

While this does not affect consensus or validator nodes directly, it impacts:
- All indexer clients relying on this service for transaction data
- Third-party applications and analytics tools
- Explorers and wallets that query historical data
- The overall ecosystem's data availability

The misconfiguration can occur through:
- Human error during deployment
- Corrupted configuration files
- Automated configuration management systems with bugs

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability requires operator error to trigger, but:
- Configuration mistakes are common in production deployments
- No validation feedback is provided at startup
- The default configuration is correct, but operators may customize cache sizes based on available memory
- The failure mode is not immediately obvious (service appears to start successfully)
- Similar validation patterns exist in related components (e.g., `InMemoryCacheSizeConfig`), suggesting this was an oversight

The impact is immediate and severe once triggered, making this a significant operational risk.

## Recommendation

Implement validation logic for `IndexerGrpcManagerConfig` following the pattern used in `InMemoryCacheSizeConfig`: [7](#0-6) 

Add validation to the `RunnableConfig` implementation:

```rust
#[async_trait::async_trait]
impl RunnableConfig for IndexerGrpcManagerConfig {
    fn validate(&self) -> Result<()> {
        // Validate cache configuration
        if self.cache_config.max_cache_size == 0 {
            bail!("max_cache_size must be greater than 0");
        }
        if self.cache_config.target_cache_size == 0 {
            bail!("target_cache_size must be greater than 0");
        }
        if self.cache_config.target_cache_size >= self.cache_config.max_cache_size {
            bail!("target_cache_size must be less than max_cache_size");
        }
        
        // Validate file store config if it has validation
        self.file_store_config.validate()?;
        
        Ok(())
    }

    async fn run(&self) -> Result<()> {
        // ... existing implementation
    }
    
    // ... rest of implementation
}
```

This validation will be called by `ServerArgs::run()` before the service starts: [8](#0-7) 

## Proof of Concept

Create a test configuration file `invalid_config.yaml`:
```yaml
health_check_port: 8080
server_config:
  chain_id: 1
  service_config:
    listen_address: "127.0.0.1:50051"
  cache_config:
    max_cache_size: 1073741824      # 1GB
    target_cache_size: 2147483648   # 2GB (INVALID)
  file_store_config:
    file_store_type: "LocalFileStore"
    local_file_store_path: "/tmp/filestore"
  self_advertised_address: "127.0.0.1:50051"
  grpc_manager_addresses: []
  fullnode_addresses: ["127.0.0.1:50052"]
  is_master: false
  allow_fn_fallback: false
```

Run the indexer-grpc-manager:
```bash
cargo run --bin aptos-indexer-grpc-manager -- --config-path invalid_config.yaml
```

**Expected behavior (current):** Service starts successfully, then enters infinite GC loop when cache fills up

**Expected behavior (with fix):** Service fails to start with validation error: "target_cache_size must be less than max_cache_size"

---

**Notes:**
- The default configuration values satisfy the invariant: `max_cache_size = 5GB`, `target_cache_size = 4GB` [9](#0-8) 
- Other indexer services like `IndexerGrpcDataServiceConfig` properly validate their cache configurations [10](#0-9) 
- This issue only affects the indexer-grpc-manager component, not core consensus or validator nodes

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/config.rs (L23-27)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct CacheConfig {
    pub(crate) max_cache_size: usize,
    pub(crate) target_cache_size: usize,
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/config.rs (L29-42)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IndexerGrpcManagerConfig {
    pub(crate) chain_id: u64,
    pub(crate) service_config: ServiceConfig,
    #[serde(default = "default_cache_config")]
    pub(crate) cache_config: CacheConfig,
    pub(crate) file_store_config: IndexerGrpcFileStoreConfig,
    pub(crate) self_advertised_address: GrpcAddress,
    pub(crate) grpc_manager_addresses: Vec<GrpcAddress>,
    pub(crate) fullnode_addresses: Vec<GrpcAddress>,
    pub(crate) is_master: bool,
    pub(crate) allow_fn_fallback: bool,
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/config.rs (L44-49)
```rust
const fn default_cache_config() -> CacheConfig {
    CacheConfig {
        max_cache_size: 5 * (1 << 30),
        target_cache_size: 4 * (1 << 30),
    }
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/config.rs (L51-67)
```rust
#[async_trait::async_trait]
impl RunnableConfig for IndexerGrpcManagerConfig {
    async fn run(&self) -> Result<()> {
        GRPC_MANAGER
            .get_or_init(|| async { GrpcManager::new(self).await })
            .await
            .start(&self.service_config)
    }

    fn get_server_name(&self) -> String {
        "grpc_manager".to_string()
    }

    async fn status_page(&self) -> Result<Response, Rejection> {
        crate::status_page::status_page().await
    }
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs (L39-41)
```rust
        config
            .validate()
            .context("Config did not pass validation")?;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs (L114-116)
```rust
    fn validate(&self) -> Result<()> {
        Ok(())
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L63-80)
```rust
    fn maybe_gc(&mut self) -> bool {
        if self.cache_size <= self.max_cache_size {
            return true;
        }

        while self.start_version < self.file_store_version.load(Ordering::SeqCst)
            && self.cache_size > self.target_cache_size
        {
            let transaction = self.transactions.pop_front().unwrap();
            self.cache_size -= transaction.encoded_len();
            self.start_version += 1;
        }

        CACHE_SIZE.set(self.cache_size as i64);
        CACHE_START_VERSION.set(self.start_version as i64);

        self.cache_size <= self.max_cache_size
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L235-256)
```rust
                loop {
                    trace!("Maybe running GC.");
                    if self.cache.write().await.maybe_gc() {
                        IS_FILE_STORE_LAGGING.set(0);
                        trace!("GC is done, file store is not lagging.");
                        break;
                    }
                    IS_FILE_STORE_LAGGING.set(1);
                    // If file store is lagging, we are not inserting more data.
                    let cache = self.cache.read().await;
                    warn!("Filestore is lagging behind, cache is full [{}, {}), known_latest_version ({}).",
                          cache.start_version,
                          cache.start_version + cache.transactions.len() as u64,
                          self.metadata_manager.get_known_latest_version());
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    if watch_file_store_version {
                        self.update_file_store_version_in_cache(
                            &cache, /*version_can_go_backward=*/ false,
                        )
                        .await;
                    }
                }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/in_memory_cache.rs (L48-64)
```rust
impl InMemoryCacheSizeConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.cache_target_size_bytes == 0 {
            return Err(anyhow::anyhow!("Cache target size must be greater than 0"));
        }
        if self.cache_eviction_trigger_size_bytes == 0 {
            return Err(anyhow::anyhow!(
                "Cache eviction trigger size must be greater than 0"
            ));
        }
        if self.cache_eviction_trigger_size_bytes < self.cache_target_size_bytes {
            return Err(anyhow::anyhow!(
                "Cache eviction trigger size must be greater than cache target size"
            ));
        }
        Ok(())
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/config.rs (L130-138)
```rust
    fn validate(&self) -> Result<()> {
        if self.data_service_grpc_non_tls_config.is_none()
            && self.data_service_grpc_tls_config.is_none()
        {
            bail!("At least one of data_service_grpc_non_tls_config and data_service_grpc_tls_config must be set");
        }
        self.in_memory_cache_config.validate()?;
        Ok(())
    }
```

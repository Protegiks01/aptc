# Audit Report

## Title
Indexer gRPC Configuration Sanitizer Fails to Validate Critical Dependency Chain Leading to Runtime Panic

## Summary
The configuration sanitizer for the indexer gRPC service contains a critical validation gap that allows nodes to start with invalid configurations, resulting in runtime panics when clients connect to the service. The sanitizer incorrectly accepts the legacy `storage.enable_indexer` flag as sufficient, but this flag does not create the `IndexerReader` interface that the indexer gRPC service requires at runtime, causing immediate denial of service.

## Finding Description

The vulnerability exists in the incomplete dependency validation logic of the indexer gRPC configuration sanitizer. [1](#0-0) 

The sanitizer validates that when `indexer_grpc.enabled = true`, either `storage.enable_indexer` OR `indexer_table_info.table_info_service_mode.is_enabled()` must be true. However, this validation is insufficient because:

**1. Legacy Indexer Confusion**: The `storage.enable_indexer` flag only initializes a deprecated legacy `Indexer` struct in AptosDB, as documented in the code comments: [2](#0-1) 

This legacy indexer is opened within AptosDB but does NOT create the `IndexerReader` interface required by the indexer gRPC service: [3](#0-2) 

**2. Actual Dependency Chain**: The indexer gRPC service requires an `IndexerReader` which is only created when at least one of the following bootstrap functions returns a valid reader:

- `bootstrap_indexer_table_info` (requires `table_info_service_mode.is_enabled()` to return non-None): [4](#0-3) 

- `bootstrap_internal_indexer_db` (requires `indexer_db_config.is_internal_indexer_db_enabled()` AND `internal_indexer_db.is_some()` to return non-None): [5](#0-4) 

The `IndexerReaders::new()` function returns `None` when both readers are absent: [6](#0-5) 

**3. Missing Validation**: The sanitizer does NOT validate that `indexer_db_config.is_internal_indexer_db_enabled()` is true, creating a validation gap where configurations can pass sanitization but fail at runtime.

**4. Runtime Panic**: When the indexer gRPC service starts with `indexer_reader = None`, it panics during request processing. The panic occurs when clients connect and the service attempts to set the highest known version: [7](#0-6) 

The execution path that triggers this panic is:
1. Client connects to indexer gRPC service via `get_transactions_from_node()`
2. `IndexerStreamCoordinator::new()` is created with context containing `indexer_reader: None`
3. `process_next_batch()` → `fetch_transactions_from_storage()` → `get_batches()` → `ensure_highest_known_version()`: [8](#0-7) 

4. `set_highest_known_version()` executes `.expect("Table info reader not set")` on `None`, causing immediate panic [9](#0-8) 

**Attack Scenario**: An operator configures a fullnode with:
- `indexer_grpc.enabled = true`
- `storage.enable_indexer = true` (legacy flag, satisfies sanitizer)
- `indexer_table_info.table_info_service_mode = Disabled`
- `indexer_db_config` features all disabled

This configuration passes sanitization but results in `IndexerReaders::new()` returning `None`. When any client connects to the indexer gRPC endpoint, the service immediately panics, causing complete denial of service.

## Impact Explanation

This vulnerability qualifies as **High Severity** under Aptos bug bounty criteria for **API Crashes**. The impact includes:

1. **Complete Service Unavailability**: Every client request to the indexer gRPC service triggers a panic, making the service completely non-functional
2. **Configuration Validation Bypass**: The sanitizer security control fails to prevent invalid runtime states, violating the invariant that validated configurations should not cause runtime failures
3. **Operational Disruption**: Nodes with this misconfiguration cannot serve indexer gRPC clients, requiring manual intervention to detect and fix the configuration error

While this does not affect consensus, validator operations, or cause fund loss, it represents a significant availability issue where a security control (configuration sanitization) fails to prevent a predictable runtime failure. The indexer gRPC service is a critical API component for applications that need to stream blockchain data, and its complete unavailability constitutes an API crash scenario.

The vulnerability breaks the security guarantee that configuration sanitizers must validate all critical dependencies before allowing a service to start.

## Likelihood Explanation

**Likelihood: Medium-High**

This vulnerability is likely to manifest in production environments because:

1. **Configuration Complexity**: The distinction between `storage.enable_indexer` (legacy AptosDB indexer) and the new indexer system (`indexer_table_info` + `indexer_db_config`) is subtle and easily confused
2. **Migration Path**: Operators upgrading from older versions or following outdated documentation may enable `storage.enable_indexer` expecting it to satisfy indexer gRPC dependencies
3. **Silent Failure**: The configuration passes all startup validation checks; the error only manifests when a client connects
4. **Immediate Trigger**: Any client attempting to use the indexer gRPC service immediately triggers the panic
5. **No Attacker Required**: This is a natural configuration mistake that requires no malicious intent

The vulnerability can be triggered through normal operational procedures without requiring any specialized knowledge or attack sophistication.

## Recommendation

Fix the sanitizer to validate that at least one actual `IndexerReader` source will be created:

```rust
impl ConfigSanitizer for IndexerGrpcConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        _chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();

        if !node_config.indexer_grpc.enabled {
            return Ok(());
        }

        // Check that at least one IndexerReader source will be created
        let has_table_info_reader = node_config
            .indexer_table_info
            .table_info_service_mode
            .is_enabled();
        
        let has_internal_indexer = node_config
            .indexer_db_config
            .is_internal_indexer_db_enabled();

        if !has_table_info_reader && !has_internal_indexer {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "indexer_grpc.enabled requires either indexer_table_info.table_info_service_mode to be enabled OR indexer_db_config to have internal indexer DB enabled".to_string(),
            ));
        }
        
        Ok(())
    }
}
```

Additionally, consider deprecating or removing the confusing `storage.enable_indexer` flag from the sanitizer check entirely, as it creates false expectations about indexer gRPC dependencies.

## Proof of Concept

The vulnerability can be reproduced with the following configuration:

```yaml
indexer_grpc:
  enabled: true
  
storage:
  enable_indexer: true  # Legacy flag - passes sanitizer but doesn't create IndexerReader

indexer_table_info:
  table_info_service_mode: Disabled  # No IndexerAsyncV2 created

indexer_db_config:
  # All features disabled - no DBIndexer created
  enable_transaction: false
  enable_event: false
  enable_statekeys: false
```

Steps to reproduce:
1. Start a fullnode with the above configuration
2. Node starts successfully (sanitizer passes)
3. Connect a client to the indexer gRPC service endpoint
4. Client connection triggers `get_transactions_from_node()` → `IndexerStreamCoordinator::new()` → `process_next_batch()` → `ensure_highest_known_version()` → `set_highest_known_version()`
5. Service panics with: `thread 'tokio-runtime-worker' panicked at 'Table info reader not set'`

The panic occurs because `indexer_reader` is `None` in the context, but the code expects it to always be `Some(...)` when the service is enabled.

### Citations

**File:** config/src/config/indexer_grpc_config.rs (L115-125)
```rust
        if !node_config.storage.enable_indexer
            && !node_config
                .indexer_table_info
                .table_info_service_mode
                .is_enabled()
        {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "storage.enable_indexer must be true or indexer_table_info.table_info_service_mode must be IndexingOnly if indexer_grpc.enabled is true".to_string(),
            ));
        }
```

**File:** storage/indexer/src/lib.rs (L4-4)
```rust
/// TODO(jill): deprecate Indexer once Indexer Async V2 is ready
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L184-189)
```rust
        if !readonly && enable_indexer {
            myself.open_indexer(
                db_paths.default_root_path(),
                rocksdb_configs.index_db_config,
            )?;
        }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/runtime.rs (L29-31)
```rust
    if !config.indexer_db_config.is_internal_indexer_db_enabled() || internal_indexer_db.is_none() {
        return None;
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/runtime.rs (L57-63)
```rust
    if !config
        .indexer_table_info
        .table_info_service_mode
        .is_enabled()
    {
        return None;
    }
```

**File:** storage/indexer/src/indexer_reader.rs (L27-39)
```rust
    pub fn new(
        table_info_reader: Option<Arc<IndexerAsyncV2>>,
        db_indexer_reader: Option<Arc<DBIndexer>>,
    ) -> Option<Self> {
        if table_info_reader.is_none() && db_indexer_reader.is_none() {
            None
        } else {
            Some(Self {
                table_info_reader,
                db_indexer_reader,
            })
        }
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L293-296)
```rust
    async fn get_batches(&mut self) -> Vec<TransactionBatchInfo> {
        if !self.ensure_highest_known_version().await {
            return vec![];
        }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L534-540)
```rust
        let latest_table_info_version = self
            .context
            .indexer_reader
            .as_ref()
            .expect("Table info reader not set")
            .get_latest_table_info_ledger_version()?
            .expect("Table info ledger version not set");
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L562-562)
```rust
            if let Err(err) = self.set_highest_known_version() {
```

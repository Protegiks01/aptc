# Audit Report

## Title
API Crashes Due to Missing Indexer Reader Validation When Storage Sharding is Enabled

## Summary
When storage sharding is enabled by default but both indexer services are disabled by default, the API Context is initialized with `indexer_reader = None`. Critical API endpoints fail with "Indexer reader doesn't exist" errors, returning 500 Internal Server Errors and rendering these endpoints non-functional with default node configuration.

## Finding Description

The vulnerability exists in the initialization and usage pattern of the indexer reader across multiple components:

**1. Bootstrap Phase:** The `bootstrap()` function returns `None` when the table info service is disabled. [1](#0-0) 

Similarly, `bootstrap_internal_indexer_db()` returns `None` when the internal indexer DB is disabled. [2](#0-1) 

**2. IndexerReaders Construction:** When both indexers are disabled, `IndexerReaders::new()` returns `None`. [3](#0-2) 

**3. API Context Creation:** The Context is created with `indexer_reader = None` when `IndexerReaders::new()` returns `None`. [4](#0-3) 

**4. Runtime Failure:** When storage sharding is enabled (checked via `db_sharding_enabled()`), [5](#0-4)  the code assumes `indexer_reader` must be available and attempts to use it without proper None handling:

- In `get_state_values()`: [6](#0-5) 

- In `get_resources_by_pagination()`: [7](#0-6) 

- In `get_modules_by_pagination()`: [8](#0-7) 

- In `get_account_ordered_transactions()`: [9](#0-8) 

**5. Configuration Defaults:** The problematic state occurs with default configuration:

- Storage sharding is enabled by default: [10](#0-9) 

- Table info service is disabled by default: [11](#0-10) 

- Internal indexer DB is disabled by default: [12](#0-11) 

**6. Missing Validation:** The configuration sanitizer only validates that internal indexer shouldn't be enabled if sharding is off. [13](#0-12)  There is no validation enforcing that if storage sharding is enabled, at least one indexer must be enabled.

## Impact Explanation

This is a **HIGH severity** vulnerability per Aptos bug bounty criteria under "API Crashes (High)":

- **Critical API Endpoints Non-Functional**: Endpoints querying account resources (`GET /accounts/:address/resources`), modules (`GET /accounts/:address/modules`), and transactions (`GET /accounts/:address/transactions`) return 500 Internal Server Errors with "Indexer reader doesn't exist" messages.

- **Default Configuration Affected**: The issue manifests with default node configuration without any misconfiguration by operators. Any node deployed with default settings will have these non-functional API endpoints.

- **Silent Failure**: The node starts successfully without warnings, making the issue difficult to detect until runtime when APIs are actually called by users or applications.

- **Network Participation Impact**: Nodes with broken API endpoints cannot properly serve API clients, affecting network participation and ecosystem functionality.

This meets the HIGH severity criteria of "REST API crashes affecting network participation" as specified in the bug bounty program.

## Likelihood Explanation

**Likelihood: HIGH**

This issue is highly likely to occur because:

1. **Default Configuration**: The vulnerable state exists with default settings (`enable_storage_sharding = true`, indexers disabled).

2. **No Startup Validation**: No configuration validation prevents this invalid state at startup.

3. **Silent Failure Mode**: The node starts successfully without errors or warnings, giving operators no indication of the problem until API calls fail.

4. **Common Deployment Pattern**: Many nodes may be deployed with default configurations, especially fullnodes that don't need specialized indexing features.

5. **Fundamental API Endpoints**: The affected endpoints are fundamental operations that will be called by most API clients and applications.

## Recommendation

Implement configuration validation to enforce that if storage sharding is enabled, at least one indexer must be enabled. This can be added to the `ConfigSanitizer` implementation:

```rust
// In config/src/config/internal_indexer_db_config.rs or similar
fn sanitize(...) {
    // Existing check...
    
    // Add new check:
    if node_config.storage.rocksdb_configs.enable_storage_sharding 
        && !config.is_internal_indexer_db_enabled()
        && !node_config.indexer_table_info.table_info_service_mode.is_enabled() 
    {
        return Err(Error::ConfigSanitizerFailed(
            sanitizer_name,
            "Storage sharding requires at least one indexer to be enabled (internal indexer DB or table info service)".into(),
        ));
    }
}
```

Alternatively, provide graceful fallback handling in the API layer when `indexer_reader` is `None` and sharding is enabled, returning a more descriptive error or falling back to alternative query methods.

## Proof of Concept

1. Deploy an Aptos node with default configuration (no explicit indexer configuration)
2. Wait for node to sync and start API server
3. Execute API request: `curl http://localhost:8080/v1/accounts/0x1/resources`
4. Observe 500 Internal Server Error with message "Indexer reader doesn't exist"

The same failure occurs for:
- `GET /v1/accounts/{address}/modules`
- `GET /v1/accounts/{address}/transactions`
- Any other endpoint that queries account state when sharding is enabled

## Notes

This vulnerability represents a critical gap between configuration defaults and runtime requirements. The system allows an invalid configuration state (sharding enabled, no indexers available) to exist, which causes runtime failures rather than startup failures. This is particularly problematic because it affects default deployments without any operator misconfiguration, making it a systemic issue rather than a deployment error.

### Citations

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

**File:** aptos-node/src/services.rs (L92-98)
```rust
    let indexer_readers = IndexerReaders::new(indexer_async_v2, txn_event_reader);

    // Create the API runtime
    let indexer_reader: Option<Arc<dyn IndexerReader>> = indexer_readers.map(|readers| {
        let trait_object: Arc<dyn IndexerReader> = Arc::new(readers);
        trait_object
    });
```

**File:** api/src/context.rs (L453-458)
```rust
        } else {
            self.indexer_reader
                .as_ref()
                .ok_or_else(|| format_err!("Indexer reader doesn't exist"))?
                .get_prefixed_state_value_iterator(&StateKeyPrefix::from(address), None, version)?
        };
```

**File:** api/src/context.rs (L487-496)
```rust
        } else {
            self.indexer_reader
                .as_ref()
                .ok_or_else(|| format_err!("Indexer reader doesn't exist"))?
                .get_prefixed_state_value_iterator(
                    &StateKeyPrefix::from(address),
                    prev_state_key,
                    version,
                )?
        };
```

**File:** api/src/context.rs (L578-587)
```rust
        } else {
            self.indexer_reader
                .as_ref()
                .ok_or_else(|| format_err!("Indexer reader doesn't exist"))?
                .get_prefixed_state_value_iterator(
                    &StateKeyPrefix::from(address),
                    prev_state_key,
                    version,
                )?
        };
```

**File:** api/src/context.rs (L908-923)
```rust
        } else {
            self.indexer_reader
                .as_ref()
                .ok_or_else(|| anyhow!("Indexer reader is None"))
                .map_err(|err| {
                    E::internal_with_code(err, AptosErrorCode::InternalError, ledger_info)
                })?
                .get_account_ordered_transactions(
                    address,
                    start_seq_number,
                    limit as u64,
                    true,
                    ledger_version,
                )
                .map_err(|e| AptosDbError::Other(e.to_string()))
        };
```

**File:** api/src/context.rs (L1771-1773)
```rust
fn db_sharding_enabled(node_config: &NodeConfig) -> bool {
    node_config.storage.rocksdb_configs.enable_storage_sharding
}
```

**File:** config/src/config/storage_config.rs (L219-239)
```rust
impl Default for RocksdbConfigs {
    fn default() -> Self {
        Self {
            ledger_db_config: RocksdbConfig::default(),
            state_merkle_db_config: RocksdbConfig::default(),
            state_kv_db_config: RocksdbConfig {
                bloom_filter_bits: Some(10.0),
                bloom_before_level: Some(2),
                ..Default::default()
            },
            index_db_config: RocksdbConfig {
                max_open_files: 1000,
                ..Default::default()
            },
            enable_storage_sharding: true,
            high_priority_background_threads: 4,
            low_priority_background_threads: 2,
            shared_block_cache_size: Self::DEFAULT_BLOCK_CACHE_SIZE,
        }
    }
}
```

**File:** config/src/config/indexer_table_info_config.rs (L41-49)
```rust
impl Default for IndexerTableInfoConfig {
    fn default() -> Self {
        Self {
            parser_task_count: DEFAULT_PARSER_TASK_COUNT,
            parser_batch_size: DEFAULT_PARSER_BATCH_SIZE,
            table_info_service_mode: TableInfoServiceMode::Disabled,
        }
    }
}
```

**File:** config/src/config/internal_indexer_db_config.rs (L69-80)
```rust
impl Default for InternalIndexerDBConfig {
    fn default() -> Self {
        Self {
            enable_transaction: false,
            enable_event: false,
            enable_event_v2_translation: false,
            event_v2_translation_ignores_below_version: 0,
            enable_statekeys: false,
            batch_size: 10_000,
        }
    }
}
```

**File:** config/src/config/internal_indexer_db_config.rs (L92-99)
```rust
        if !node_config.storage.rocksdb_configs.enable_storage_sharding
            && config.is_internal_indexer_db_enabled()
        {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "Don't turn on internal indexer db if DB sharding is off".into(),
            ));
        }
```

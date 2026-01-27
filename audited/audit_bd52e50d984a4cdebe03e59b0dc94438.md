# Audit Report

## Title
Silent API Failure Due to Storage Sharding Enabled Without Internal Indexer Configuration

## Summary
A configuration mismatch between default values causes nodes to start successfully but fail account-based API queries silently. Storage sharding defaults to enabled, but all internal indexer features default to disabled, creating a non-functional state that is not detected at startup.

## Finding Description

The Aptos node configuration has a dangerous default value mismatch that causes silent API failures:

**Default Configuration Mismatch:**

Storage sharding is enabled by default: [1](#0-0) 

However, all internal indexer features are disabled by default: [2](#0-1) 

**Incomplete Validation:**

The configuration sanitizer only validates one direction - that the indexer cannot be enabled without sharding: [3](#0-2) 

This validation does NOT check the reverse: when sharding is enabled, it does not verify that the indexer has at least some features enabled.

**Silent Failure Mechanism:**

When all indexer features are disabled, the internal indexer DB is not created: [4](#0-3) 

This results in `indexer_reader` being `None` in the API context, but the node starts successfully without any warnings.

**API Query Failures:**

When storage sharding is enabled, the API layer routes account-based queries through the indexer reader: [5](#0-4) 

With `indexer_reader` set to `None`, these queries fail with internal errors: [6](#0-5) 

Similar failures occur for resource and module queries: [7](#0-6) [8](#0-7) 

And event queries: [9](#0-8) 

**Affected API Endpoints:**
- `GET /accounts/{address}/transactions` 
- `GET /accounts/{address}/events/*`
- `GET /accounts/{address}/resources`
- `GET /accounts/{address}/modules`

## Impact Explanation

This issue represents a **Medium severity** configuration validation gap. While it does not cause consensus violations or fund loss, it creates a significant operational problem:

1. **Silent Degradation**: Nodes appear healthy (consensus works, transactions process) but critical API functionality is broken
2. **User Experience Impact**: DApps and services relying on account queries receive cryptic "Internal Error" responses
3. **Diagnostic Difficulty**: The root cause is not immediately obvious since the node starts without warnings
4. **Default Configuration Trap**: New node operators using recommended default configurations will encounter this issue

The impact falls under the "API crashes" category of High severity, though technically these are error responses rather than crashes. Given the ambiguity, Medium severity is more appropriate.

## Likelihood Explanation

**Likelihood: High**

This issue will occur in the following scenarios:

1. **New Node Deployments**: Any operator starting a node with default configuration values
2. **Configuration Updates**: Operators who enable storage sharding without updating indexer settings
3. **Infrastructure-as-Code**: Terraform templates and Helm charts that use storage sharding defaults

The default values are explicitly set to trigger this condition, making it highly likely to occur in production environments unless operators are aware of the interdependency.

## Recommendation

Add bidirectional validation in the configuration sanitizer to ensure storage sharding and internal indexer are configured consistently:

```rust
impl ConfigSanitizer for InternalIndexerDBConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        _chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let config = node_config.indexer_db_config;

        // Shouldn't turn on internal indexer for db without sharding
        if !node_config.storage.rocksdb_configs.enable_storage_sharding
            && config.is_internal_indexer_db_enabled()
        {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "Don't turn on internal indexer db if DB sharding is off".into(),
            ));
        }

        // NEW: Shouldn't enable sharding without configuring the indexer
        if node_config.storage.rocksdb_configs.enable_storage_sharding
            && !config.is_internal_indexer_db_enabled()
        {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "Storage sharding is enabled but internal indexer features are all disabled. \
                 Enable at least one of: enable_transaction, enable_event, or enable_statekeys".into(),
            ));
        }

        Ok(())
    }
}
```

Alternatively, update the default values to be consistent, either by:
- Setting storage sharding to `false` by default, OR
- Enabling at least one indexer feature by default (e.g., `enable_transaction: true`)

## Proof of Concept

```rust
// Test case demonstrating the configuration mismatch
#[test]
fn test_default_config_creates_invalid_state() {
    let mut node_config = NodeConfig::default();
    
    // Default storage sharding is enabled
    assert!(node_config.storage.rocksdb_configs.enable_storage_sharding);
    
    // Default indexer features are all disabled
    assert!(!node_config.indexer_db_config.enable_transaction);
    assert!(!node_config.indexer_db_config.enable_event);
    assert!(!node_config.indexer_db_config.enable_statekeys);
    assert!(!node_config.indexer_db_config.is_internal_indexer_db_enabled());
    
    // This configuration would pass sanitization (no error thrown)
    let result = InternalIndexerDBConfig::sanitize(
        &node_config,
        NodeType::Validator,
        None,
    );
    assert!(result.is_ok()); // Bug: Should fail but doesn't
    
    // At runtime, indexer_reader would be None
    let indexer_db = InternalIndexerDBService::get_indexer_db(&node_config);
    assert!(indexer_db.is_none()); // No indexer created
    
    // API calls to account endpoints would fail with:
    // "Indexer reader is None" or "Indexer reader doesn't exist"
}
```

To reproduce in a live environment:
1. Start a node with default `NodeConfig`
2. Observe node starts successfully with no warnings
3. Attempt `GET /accounts/{address}/transactions`
4. Observe `500 Internal Server Error` with message "Indexer reader is None"

### Citations

**File:** config/src/config/storage_config.rs (L233-233)
```rust
            enable_storage_sharding: true,
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

**File:** config/src/config/internal_indexer_db_config.rs (L82-103)
```rust
impl ConfigSanitizer for InternalIndexerDBConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        _chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let config = node_config.indexer_db_config;

        // Shouldn't turn on internal indexer for db without sharding
        if !node_config.storage.rocksdb_configs.enable_storage_sharding
            && config.is_internal_indexer_db_enabled()
        {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "Don't turn on internal indexer db if DB sharding is off".into(),
            ));
        }

        Ok(())
    }
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/internal_indexer_db_service.rs (L59-65)
```rust
    pub fn get_indexer_db(node_config: &NodeConfig) -> Option<InternalIndexerDB> {
        if !node_config
            .indexer_db_config
            .is_internal_indexer_db_enabled()
        {
            return None;
        }
```

**File:** api/src/context.rs (L454-458)
```rust
            self.indexer_reader
                .as_ref()
                .ok_or_else(|| format_err!("Indexer reader doesn't exist"))?
                .get_prefixed_state_value_iterator(&StateKeyPrefix::from(address), None, version)?
        };
```

**File:** api/src/context.rs (L579-587)
```rust
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

**File:** api/src/context.rs (L900-923)
```rust
        let txns_res = if !db_sharding_enabled(&self.node_config) {
            self.db.get_account_ordered_transactions(
                address,
                start_seq_number,
                limit as u64,
                true,
                ledger_version,
            )
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

**File:** api/src/context.rs (L1096-1104)
```rust
        let mut res = if !db_sharding_enabled(&self.node_config) {
            self.db
                .get_events(event_key, start, order, limit as u64, ledger_version)?
        } else {
            self.indexer_reader
                .as_ref()
                .ok_or_else(|| anyhow!("Internal indexer reader doesn't exist"))?
                .get_events(event_key, start, order, limit as u64, ledger_version)?
        };
```

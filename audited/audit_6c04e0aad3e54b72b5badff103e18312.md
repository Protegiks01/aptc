# Audit Report

## Title
Configuration Validation Gap: Storage Sharding Enabled Without Internal Indexer Breaks Account-Based APIs

## Summary
The configuration sanitizer validates that the internal indexer requires storage sharding, but fails to validate the reverse dependency: when storage sharding is enabled, the internal indexer must also be enabled. This allows nodes to start with an invalid configuration where sharded storage exists but the indexer is not initialized, causing all account-based REST APIs to fail at runtime with "Indexer reader doesn't exist" errors.

## Finding Description

The internal indexer database configuration sanitizer only enforces a unidirectional dependency check. [1](#0-0) 

This check ensures internal indexer cannot be enabled without storage sharding, but does NOT validate the reverse: that storage sharding requires the internal indexer to be enabled.

When storage sharding is enabled, the API layer routes account-based queries through the `indexer_reader` instead of direct database access: [2](#0-1) 

Similar routing occurs for account resources, modules, and transactions: [3](#0-2) [4](#0-3) 

However, if `is_internal_indexer_db_enabled()` returns false, the `bootstrap_internal_indexer_db` function returns None: [5](#0-4) 

When both indexer components are None, `IndexerReaders::new()` returns None: [6](#0-5) 

This results in `indexer_reader` being None in the API Context, causing runtime failures when `db_sharding_enabled()` returns true but no indexer reader exists.

The storage README explicitly documents that the internal indexer is required for account-based APIs after DB sharding: [7](#0-6) 

**Exploitation Path:**
1. Node operator configures: `storage.rocksdb_configs.enable_storage_sharding = true` (required for mainnet/testnet per line 664-668)
2. Node operator leaves default indexer config: all flags false (default per line 69-80)
3. `is_internal_indexer_db_enabled()` returns false [8](#0-7) 
4. Configuration passes sanitization (no error thrown)
5. Node starts successfully
6. At runtime, `indexer_reader` is None in API Context [9](#0-8) 
7. All requests to `/accounts/{address}/events/*`, `/accounts/{address}/transactions`, `/accounts/{address}/resources`, `/accounts/{address}/modules` fail

## Impact Explanation

This qualifies as **High Severity** per the bug bounty program's "API crashes" category. The vulnerability causes complete failure of critical REST API endpoints:

- `/accounts/{address}/events/*` - event queries by account
- `/accounts/{address}/transactions` - transaction history by account  
- `/accounts/{address}/resources` - resource queries by account
- `/accounts/{address}/modules` - module queries by account

These are fundamental APIs required for wallets, explorers, and dApps to function. The impact is particularly severe because:

1. **Mainnet/testnet nodes are forced into this configuration**: Storage sharding is mandatory [10](#0-9)  but internal indexer enablement is not enforced
2. **Silent failure**: The node starts successfully with no warning that APIs will be broken
3. **No early detection**: The sanitizer fails to catch this invalid configuration
4. **Runtime errors only**: Operators discover the issue only when APIs are called and fail

## Likelihood Explanation

**High Likelihood** - This will occur on any mainnet or testnet node where the operator:
- Follows the migration guide to enable storage sharding (mandatory)
- Does not explicitly enable internal indexer flags (which default to false)

The default configuration creates this exact scenario: [11](#0-10) 

Combined with mandatory sharding enablement for mainnet/testnet, this makes the vulnerable configuration highly likely in production deployments.

## Recommendation

Add bidirectional validation in the configuration sanitizer:

```rust
impl ConfigSanitizer for InternalIndexerDBConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        _chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let config = node_config.indexer_db_config;
        let sharding_enabled = node_config.storage.rocksdb_configs.enable_storage_sharding;

        // Existing check: internal indexer requires sharding
        if !sharding_enabled && config.is_internal_indexer_db_enabled() {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "Don't turn on internal indexer db if DB sharding is off".into(),
            ));
        }

        // NEW CHECK: sharding requires internal indexer for statekeys
        if sharding_enabled && !config.enable_statekeys {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "Storage sharding requires internal indexer with enable_statekeys=true for account-based APIs. Set indexer_db_config.enable_statekeys=true".into(),
            ));
        }

        Ok(())
    }
}
```

At minimum, `enable_statekeys` must be true when sharding is enabled, as it's required for resource and module APIs. Optionally also enforce `enable_transaction` and `enable_event` for complete API functionality.

## Proof of Concept

**Configuration file that passes sanitization but breaks at runtime:**

```yaml
# node_config.yaml
storage:
  rocksdb_configs:
    enable_storage_sharding: true  # Required for mainnet/testnet

indexer_db_config:
  enable_transaction: false  # Default
  enable_event: false        # Default  
  enable_statekeys: false    # Default - causes the issue
  batch_size: 10000
```

**Steps to reproduce:**

1. Start an Aptos node with the above configuration
2. Node starts successfully (no sanitizer error)
3. Attempt to query account resources: `curl http://localhost:8080/v1/accounts/0x1/resources`
4. Observe error: "Indexer reader doesn't exist"
5. All account-based API endpoints return errors while node operates normally otherwise

**Expected behavior:** Configuration sanitizer should reject this configuration with clear error message requiring indexer enablement when sharding is enabled.

**Actual behavior:** Configuration passes validation, node starts, APIs fail at runtime.

### Citations

**File:** config/src/config/internal_indexer_db_config.rs (L60-62)
```rust
    pub fn is_internal_indexer_db_enabled(&self) -> bool {
        self.enable_transaction || self.enable_event || self.enable_statekeys
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

**File:** config/src/config/internal_indexer_db_config.rs (L91-99)
```rust
        // Shouldn't turn on internal indexer for db without sharding
        if !node_config.storage.rocksdb_configs.enable_storage_sharding
            && config.is_internal_indexer_db_enabled()
        {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "Don't turn on internal indexer db if DB sharding is off".into(),
            ));
        }
```

**File:** api/src/context.rs (L443-458)
```rust
        let mut iter = if !db_sharding_enabled(&self.node_config) {
            Box::new(
                self.db
                    .get_prefixed_state_value_iterator(
                        &StateKeyPrefix::from(address),
                        None,
                        version,
                    )?
                    .map(|item| item.map_err(|err| anyhow!(err.to_string()))),
            )
        } else {
            self.indexer_reader
                .as_ref()
                .ok_or_else(|| format_err!("Indexer reader doesn't exist"))?
                .get_prefixed_state_value_iterator(&StateKeyPrefix::from(address), None, version)?
        };
```

**File:** api/src/context.rs (L477-490)
```rust
        let account_iter = if !db_sharding_enabled(&self.node_config) {
            Box::new(
                self.db
                    .get_prefixed_state_value_iterator(
                        &StateKeyPrefix::from(address),
                        prev_state_key,
                        version,
                    )?
                    .map(|item| item.map_err(|err| anyhow!(err.to_string()))),
            )
        } else {
            self.indexer_reader
                .as_ref()
                .ok_or_else(|| format_err!("Indexer reader doesn't exist"))?
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

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/runtime.rs (L29-31)
```rust
    if !config.indexer_db_config.is_internal_indexer_db_enabled() || internal_indexer_db.is_none() {
        return None;
    }
```

**File:** storage/indexer/src/indexer_reader.rs (L31-32)
```rust
        if table_info_reader.is_none() && db_indexer_reader.is_none() {
            None
```

**File:** storage/README.md (L153-176)
```markdown
## Internal Indexer

Internal indexer is used to provide data for the following node APIs after DB sharding.

Account based event APIs
* /accounts/{address}/events/{event_handle}/{field_name}
* /accounts/{address}/events/{creation_number}

Account based transaction API
* /accounts/{address}/transactions

Account based resource APIs
* /accounts/{address}/modules
* /accounts/{address}/resources

The internal indexer is configured as below.
The batch size is used to chunk the transactions to smaller batches before writting to internal indexer DB.
```
indexer_db_config:
    enable_transaction: true // this is required for account based transaction API
    enable_event: true // this is required for account based event APIs
    enable_statekeys: true // this is required for account based resource APIs
    batch_size: 10000
```
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

**File:** config/src/config/storage_config.rs (L664-668)
```rust
            if (chain_id.is_testnet() || chain_id.is_mainnet())
                && config_yaml["rocksdb_configs"]["enable_storage_sharding"].as_bool() != Some(true)
            {
                panic!("Storage sharding (AIP-97) is not enabled in node config. Please follow the guide to migration your node, and set storage.rocksdb_configs.enable_storage_sharding to true explicitly in your node config. https://aptoslabs.notion.site/DB-Sharding-Migration-Public-Full-Nodes-1978b846eb7280b29f17ceee7d480730");
            }
```

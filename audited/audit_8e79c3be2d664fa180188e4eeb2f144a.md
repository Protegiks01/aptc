# Audit Report

## Title
Missing Configuration Validation: Storage Sharding Enabled Without IndexerReader Causes Critical API Endpoint Failures

## Summary
When a node is configured with storage sharding enabled (`enable_storage_sharding=true`) but both internal indexer DB and table info service are disabled, the `indexer_reader` passed to `bootstrap()` becomes `None`. This causes critical API endpoints to fail with "Indexer reader doesn't exist" errors, breaking core API functionality for account resources, modules, and transaction queries.

## Finding Description

The configuration validation in the Aptos node has a critical gap that allows an invalid operational state. The `ConfigSanitizer` in [1](#0-0)  validates one direction: it prevents enabling internal indexer when storage sharding is OFF. However, it does NOT validate the reverse: preventing storage sharding from being enabled when BOTH indexer components are disabled.

**Vulnerable Configuration Flow:**

1. Node configured with `enable_storage_sharding=true` [2](#0-1) 

2. Both indexer components disabled:
   - `bootstrap_indexer_table_info()` returns `None` [3](#0-2) 
   - `bootstrap_internal_indexer_db()` returns `None` [4](#0-3) 

3. `IndexerReaders::new()` creates `None` when both are disabled [5](#0-4) 

4. API bootstrap receives `indexer_reader=None` [6](#0-5) 

**Affected API Endpoints:**

When `db_sharding_enabled()` returns true but `indexer_reader` is `None`, these endpoints fail:

- **GET /v1/accounts/:address/resources** - Uses `get_resources_by_pagination()` [7](#0-6) 

- **GET /v1/accounts/:address/modules** - Uses `get_modules_by_pagination()` [8](#0-7) 

- **GET /v1/accounts/:address/transactions** - Uses `get_account_ordered_transactions()` [9](#0-8) 

All three functions check for sharding and attempt to use the indexer reader [10](#0-9) , causing immediate failure with "Indexer reader doesn't exist" error when `None`.

## Impact Explanation

**Severity: High** (API crashes per Aptos bug bounty criteria)

This misconfiguration renders critical API endpoints non-functional:
- Users cannot query account resources (balances, tokens, NFTs)
- Smart contract developers cannot fetch account modules
- Transaction history queries fail completely
- Any dApp or indexer relying on these endpoints experiences complete service failure

While this doesn't affect consensus or cause fund loss, it represents a **critical availability failure** of essential node services. Nodes in this state appear operational but cannot serve basic read queries, violating the operational integrity requirement for public API nodes.

## Likelihood Explanation

**Likelihood: Medium**

This requires a specific misconfiguration by node operators, but it's realistic because:

1. Storage sharding is recommended for performance in production environments
2. Indexer components are optional features that operators might disable to reduce resource usage
3. No validation prevents this invalid combination during node startup
4. The node starts successfully and runs consensus, masking the API failure until queried

An operator following performance optimization guides might enable sharding while disabling "optional" indexer features, inadvertently triggering this failure.

## Recommendation

Add bidirectional validation in the `ConfigSanitizer` implementation: [11](#0-10) 

Add this validation after line 99:

```rust
// Must enable at least one indexer component when DB sharding is on
if node_config.storage.rocksdb_configs.enable_storage_sharding
    && !config.is_internal_indexer_db_enabled()
    && !node_config.indexer_table_info.table_info_service_mode.is_enabled()
{
    return Err(Error::ConfigSanitizerFailed(
        sanitizer_name,
        "Must enable internal indexer DB or table info service when storage sharding is enabled. These components are required for API endpoints to function with sharded storage.".into(),
    ));
}
```

Additionally, add runtime validation in `bootstrap()` [12](#0-11)  to fail fast if this condition is detected.

## Proof of Concept

**Configuration File (node_config.yaml):**
```yaml
storage:
  rocksdb_configs:
    enable_storage_sharding: true

indexer_db_config:
  enable_transaction: false
  enable_event: false
  enable_statekeys: false

indexer_table_info:
  table_info_service_mode: Disabled

api:
  enabled: true
```

**Expected Behavior:**
1. Start node with above configuration
2. Node starts successfully and runs consensus
3. Query `GET /v1/accounts/0x1/resources`
4. API returns 500 Internal Server Error with "Indexer reader doesn't exist"

**Reproduction Steps:**
```bash
# Set up test node with config above
cargo run --bin aptos-node -- --config-path node_config.yaml

# In another terminal, wait for node to start, then:
curl http://localhost:8080/v1/accounts/0x1/resources

# Expected output: Error 500 with "Indexer reader doesn't exist"
```

The vulnerability lies in the missing validation at startup that would prevent this invalid configuration combination from being deployed.

### Citations

**File:** config/src/config/internal_indexer_db_config.rs (L82-102)
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
```

**File:** api/src/context.rs (L454-457)
```rust
            self.indexer_reader
                .as_ref()
                .ok_or_else(|| format_err!("Indexer reader doesn't exist"))?
                .get_prefixed_state_value_iterator(&StateKeyPrefix::from(address), None, version)?
```

**File:** api/src/context.rs (L477-496)
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
                .get_prefixed_state_value_iterator(
                    &StateKeyPrefix::from(address),
                    prev_state_key,
                    version,
                )?
        };
```

**File:** api/src/context.rs (L568-587)
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

**File:** api/src/context.rs (L1771-1773)
```rust
fn db_sharding_enabled(node_config: &NodeConfig) -> bool {
    node_config.storage.rocksdb_configs.enable_storage_sharding
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

**File:** aptos-node/src/services.rs (L92-98)
```rust
    let indexer_readers = IndexerReaders::new(indexer_async_v2, txn_event_reader);

    // Create the API runtime
    let indexer_reader: Option<Arc<dyn IndexerReader>> = indexer_readers.map(|readers| {
        let trait_object: Arc<dyn IndexerReader> = Arc::new(readers);
        trait_object
    });
```

**File:** api/src/runtime.rs (L42-53)
```rust
pub fn bootstrap(
    config: &NodeConfig,
    chain_id: ChainId,
    db: Arc<dyn DbReader>,
    mp_sender: MempoolClientSender,
    indexer_reader: Option<Arc<dyn IndexerReader>>,
    port_tx: Option<oneshot::Sender<u16>>,
) -> anyhow::Result<Runtime> {
    let max_runtime_workers = get_max_runtime_workers(&config.api);
    let runtime = aptos_runtimes::spawn_named_runtime("api".into(), Some(max_runtime_workers));

    let context = Context::new(chain_id, db, mp_sender, config.clone(), indexer_reader);
```

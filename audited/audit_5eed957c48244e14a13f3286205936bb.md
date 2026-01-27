# Audit Report

## Title
Indexer-gRPC Service Panic Due to Uninitialized IndexerReader in ServiceContext

## Summary
The indexer-gRPC fullnode service can be started with a `Context` that has `indexer_reader` set to `None`. When a client requests transaction streaming, the service panics with "Table info reader not set", causing a denial of service for the indexer API. This occurs because `IndexerStreamCoordinator::set_highest_known_version()` unconditionally expects the `indexer_reader` to be present, violating the `Option<Arc<dyn IndexerReader>>` type semantics.

## Finding Description

The `ServiceContext` struct contains an `Arc<Context>`, where `Context` has an `indexer_reader: Option<Arc<dyn IndexerReader>>` field. [1](#0-0) 

During node initialization, if both the internal indexer DB and table info service are disabled, `IndexerReaders::new()` returns `None`: [2](#0-1) 

This `None` value is then passed to `bootstrap_indexer_grpc`, which creates a `Context` with `indexer_reader = None` and wraps it in `ServiceContext`: [3](#0-2) 

When a client sends a `GetTransactionsFromNode` request via `FullnodeDataService`, the request handling creates an `IndexerStreamCoordinator` and calls `process_next_batch()`. This triggers the following call chain:
1. `process_next_batch()` → `fetch_transactions_from_storage()` 
2. → `get_batches()` → `ensure_highest_known_version()`
3. → `set_highest_known_version()`

The vulnerable code is in `set_highest_known_version()`: [4](#0-3) 

At line 537-538, the code calls `.expect("Table info reader not set")` on `indexer_reader.as_ref()`, which panics when `indexer_reader` is `None`. This is a violation of Rust's `Option` semantics - the code should handle the `None` case gracefully instead of panicking.

The same vulnerability affects `LocalnetDataService`, which uses the same `IndexerStreamCoordinator`: [5](#0-4) 

## Impact Explanation

This is a **High Severity** issue under the Aptos Bug Bounty criteria: "API crashes" (up to $50,000).

**Impact:**
- Complete denial of service for the indexer-gRPC API
- Any client attempting to stream transactions triggers an immediate panic
- The indexer-grpc runtime crashes and must be restarted
- External applications depending on the indexer API (block explorers, analytics platforms, wallets) cannot retrieve transaction data

**Scope limitation:**
- This does NOT affect consensus, validators, or the core blockchain operation
- This is isolated to the indexer-gRPC data service component
- No funds are at risk, no state corruption occurs

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

This vulnerability has a realistic likelihood of occurrence:

1. **Valid Configuration Scenario**: The configuration that triggers this bug is valid and might be intentionally used by node operators who want to run the indexer-gRPC service for basic transaction streaming without the overhead of running full indexer components (table info service and internal indexer DB).

2. **Configuration Path**: The issue occurs when:
   - `config.indexer_grpc.enabled = true`
   - `config.indexer_table_info.table_info_service_mode.is_enabled() = false`
   - `config.indexer_db_config.is_internal_indexer_db_enabled() = false` OR `internal_indexer_db = None`

3. **Triggering the Bug**: Once the service is running with this configuration, any legitimate client request for transaction streaming immediately triggers the panic. No malicious intent is required.

4. **Operator Error**: Node operators might mistakenly enable indexer-grpc without understanding the dependency on indexer components, leading to production outages.

## Recommendation

**Fix 1: Add validation at bootstrap time** - Prevent starting indexer-grpc without a valid indexer_reader: [6](#0-5) 

Add validation after line 46:
```rust
if indexer_reader.is_none() {
    aptos_logger::warn!("Indexer-gRPC requires indexer_reader but it is None. Service will not start.");
    return None;
}
```

**Fix 2: Handle None case gracefully in set_highest_known_version()** - Use fallback logic: [4](#0-3) 

Replace the method with:
```rust
pub fn set_highest_known_version(&mut self) -> anyhow::Result<()> {
    let info = self.context.get_latest_ledger_info_wrapped()?;
    
    // If indexer_reader is available, use table info version as constraint
    let highest_version = if let Some(indexer_reader) = self.context.indexer_reader.as_ref() {
        if let Ok(Some(table_info_version)) = indexer_reader.get_latest_table_info_ledger_version() {
            std::cmp::min(info.ledger_version.0, table_info_version)
        } else {
            info.ledger_version.0
        }
    } else {
        // Fallback: use ledger version directly if no indexer_reader
        info.ledger_version.0
    };

    self.highest_known_version = highest_version;
    Ok(())
}
```

**Recommended approach**: Implement **both** fixes - validation at bootstrap prevents the service from starting in an invalid state, and graceful handling provides defense in depth.

## Proof of Concept

**Rust Reproduction Steps:**

1. Configure a node with:
```toml
[indexer_grpc]
enabled = true
address = "0.0.0.0:50051"

[indexer_table_info]
# Disabled - this causes indexer_reader to be None
mode = "Disabled"

[indexer_db_config]
# Disabled - this causes indexer_reader to be None
enable_transaction = false
enable_event = false
enable_statekeys = false
```

2. Start the node - the indexer-grpc service will start successfully

3. Send a gRPC request:
```rust
use aptos_protos::internal::fullnode::v1::fullnode_data_client::FullnodeDataClient;
use aptos_protos::internal::fullnode::v1::GetTransactionsFromNodeRequest;

#[tokio::main]
async fn main() {
    let mut client = FullnodeDataClient::connect("http://127.0.0.1:50051")
        .await
        .unwrap();
    
    let request = GetTransactionsFromNodeRequest {
        starting_version: Some(0),
        transactions_count: Some(100),
    };
    
    // This will cause the server to panic
    let response = client.get_transactions_from_node(request).await;
    println!("{:?}", response); // Will see connection error due to server panic
}
```

4. Observe server logs:
```
thread 'tokio-runtime-worker' panicked at 'Table info reader not set'
```

The panic occurs at: [7](#0-6) 

## Notes

This vulnerability specifically affects the indexer-gRPC API service, not the core consensus or validator operations. While the severity classification is "High" due to API crashes, this does not represent a consensus-level or funds-at-risk vulnerability. The issue stems from incorrect assumptions about `Option<T>` handling - the code uses `.expect()` where it should gracefully handle the `None` case or validate requirements at initialization time.

### Citations

**File:** api/src/context.rs (L83-83)
```rust
    pub indexer_reader: Option<Arc<dyn IndexerReader>>,
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

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/runtime.rs (L36-46)
```rust
pub fn bootstrap(
    config: &NodeConfig,
    chain_id: ChainId,
    db: Arc<dyn DbReader>,
    mp_sender: MempoolClientSender,
    indexer_reader: Option<Arc<dyn IndexerReader>>,
    port_tx: Option<oneshot::Sender<u16>>,
) -> Option<Runtime> {
    if !config.indexer_grpc.enabled {
        return None;
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/runtime.rs (L65-79)
```rust
        let context = Arc::new(Context::new(
            chain_id,
            db,
            mp_sender,
            node_config,
            indexer_reader,
        ));
        let service_context = ServiceContext {
            context: context.clone(),
            processor_task_count,
            processor_batch_size,
            output_batch_size,
            transaction_channel_size,
            max_transaction_filter_size_bytes,
        };
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L532-546)
```rust
    pub fn set_highest_known_version(&mut self) -> anyhow::Result<()> {
        let info = self.context.get_latest_ledger_info_wrapped()?;
        let latest_table_info_version = self
            .context
            .indexer_reader
            .as_ref()
            .expect("Table info reader not set")
            .get_latest_table_info_ledger_version()?
            .expect("Table info ledger version not set");

        self.highest_known_version =
            std::cmp::min(info.ledger_version.0, latest_table_info_version);

        Ok(())
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/localnet_data_service.rs (L79-89)
```rust
            let mut coordinator = IndexerStreamCoordinator::new(
                context,
                starting_version,
                ending_version,
                processor_task_count,
                processor_batch_size,
                output_batch_size,
                tx.clone(),
                filter,
                None,
            );
```

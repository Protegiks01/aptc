# Audit Report

## Title
Configuration Validation Bypass Allows Indexer GRPC Service Crash via Zero-Value Batch Size Parameters

## Summary
The `IndexerGrpcConfig::sanitize()` method fails to validate numeric configuration parameters, allowing zero values for `processor_batch_size` and `output_batch_size` to pass validation. When these invalid configurations are used at runtime, they cause deterministic panics that crash the indexer GRPC service, resulting in loss of availability for indexer-dependent applications and services.

## Finding Description

The test `test_sanitize_enable_indexer` only validates boolean flag dependencies (whether `storage.enable_indexer` or `table_info_service_mode` is enabled when indexer is enabled), but completely misses validation of numeric configuration parameters. [1](#0-0) 

The sanitize method only checks the `enabled` boolean flag and dependency relationships, but never validates that `processor_batch_size`, `output_batch_size`, or `processor_task_count` have valid non-zero values. [2](#0-1) 

These unvalidated u16 fields are then used directly in the runtime without any bounds checking: [3](#0-2) 

**Crash Path 1: processor_batch_size = 0**

When `processor_batch_size` is set to 0, the `get_batches()` method creates transaction batches with `num_transactions_to_fetch = 0`: [4](#0-3) 

These zero-transaction batches are then fetched from storage: [5](#0-4) 

The `context.get_transactions()` call with `limit = 0` returns an empty `TransactionOutputListWithProof` where `first_transaction_output_version` is `None`. This causes a panic at the unwrap: [6](#0-5) 

**Crash Path 2: output_batch_size = 0**

When `output_batch_size` is set to 0, the transaction processing attempts to chunk protobuf transactions into batches of size 0, which causes Rust's `chunks()` method to panic (chunk size must be non-zero): [7](#0-6) 

## Impact Explanation

**Severity: High** - per Aptos bug bounty criteria "API crashes"

This vulnerability causes complete loss of availability for the indexer GRPC service, which is a critical API component for:
- Blockchain explorers querying transaction data
- Analytics platforms tracking on-chain activity  
- Applications relying on historical transaction streaming
- Monitoring and observability systems

The crash is deterministic and immediate upon service startup with invalid configuration. While this requires configuration file access, it can occur through:
1. **Human error**: Node operators accidentally setting zero values during configuration
2. **Supply chain attacks**: Malicious configuration templates or documentation examples
3. **Automated deployment**: CI/CD pipelines using invalid config templates
4. **Config generation tools**: Bugs in config generators producing zero values

The indexer service is essential infrastructure - its unavailability degrades the entire ecosystem's observability and user experience.

## Likelihood Explanation

**Likelihood: Medium to High**

While this requires configuration file modification (typically operator-controlled), several realistic scenarios make this likely:

1. **Typo/Human Error**: Operators manually editing YAML configs could accidentally set `processor_batch_size: 0` or omit the field causing it to default incorrectly
2. **Config Template Issues**: Many operators copy configuration templates from documentation or examples - a malicious or incorrect template would affect multiple deployments
3. **Infrastructure-as-Code**: Automated deployment tools might generate invalid configs due to bugs in templating logic
4. **Testing/Development Configs**: Development configurations with test values (including 0) might accidentally be promoted to production

The lack of validation in the sanitize method means there's no safety net to catch these errors before runtime.

## Recommendation

Add comprehensive numeric validation to the `ConfigSanitizer::sanitize()` method for `IndexerGrpcConfig`:

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

        // Existing validation
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

        // NEW: Validate numeric parameters
        if node_config.indexer_grpc.processor_batch_size == 0 {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "indexer_grpc.processor_batch_size must be greater than 0".to_string(),
            ));
        }

        if node_config.indexer_grpc.output_batch_size == 0 {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "indexer_grpc.output_batch_size must be greater than 0".to_string(),
            ));
        }

        let processor_task_count = node_config
            .indexer_grpc
            .processor_task_count
            .unwrap_or_else(|| get_default_processor_task_count(node_config.indexer_grpc.use_data_service_interface));
        
        if processor_task_count == 0 {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "indexer_grpc.processor_task_count must be greater than 0".to_string(),
            ));
        }

        Ok(())
    }
}
```

Additionally, add test coverage for these edge cases in the test suite.

## Proof of Concept

Add this test to `config/src/config/indexer_grpc_config.rs`:

```rust
#[test]
fn test_sanitize_zero_batch_sizes() {
    // Test zero processor_batch_size
    let mut node_config = NodeConfig {
        storage: StorageConfig {
            enable_indexer: true,
            ..Default::default()
        },
        indexer_grpc: IndexerGrpcConfig {
            enabled: true,
            processor_batch_size: 0,
            ..Default::default()
        },
        ..Default::default()
    };

    let error = IndexerGrpcConfig::sanitize(
        &node_config,
        NodeType::Validator,
        Some(ChainId::mainnet()),
    )
    .unwrap_err();
    assert!(matches!(error, Error::ConfigSanitizerFailed(_, _)));

    // Test zero output_batch_size
    node_config.indexer_grpc.processor_batch_size = 1000;
    node_config.indexer_grpc.output_batch_size = 0;

    let error = IndexerGrpcConfig::sanitize(
        &node_config,
        NodeType::Validator,
        Some(ChainId::mainnet()),
    )
    .unwrap_err();
    assert!(matches!(error, Error::ConfigSanitizerFailed(_, _)));

    // Test zero processor_task_count
    node_config.indexer_grpc.output_batch_size = 100;
    node_config.indexer_grpc.processor_task_count = Some(0);

    let error = IndexerGrpcConfig::sanitize(
        &node_config,
        NodeType::Validator,
        Some(ChainId::mainnet()),
    )
    .unwrap_err();
    assert!(matches!(error, Error::ConfigSanitizerFailed(_, _)));
}
```

To reproduce the crash, create a node config YAML with:
```yaml
indexer_grpc:
  enabled: true
  processor_batch_size: 0
storage:
  enable_indexer: true
```

Start the node - the indexer GRPC service will panic with "no start version from database" when it attempts to process the first batch.

## Notes

The test coverage gap identified in the security question is directly tied to a production vulnerability. The `test_sanitize_enable_indexer` test validates only boolean dependencies, missing critical numeric validation that would prevent zero-value configurations from reaching runtime where they cause deterministic crashes. This demonstrates how insufficient test coverage of edge cases (zero values, boundary conditions) can mask serious operational vulnerabilities in production code.

### Citations

**File:** config/src/config/indexer_grpc_config.rs (L33-59)
```rust
pub struct IndexerGrpcConfig {
    pub enabled: bool,

    /// If true, the GRPC stream interface exposed by the data service will be used
    /// instead of the standard fullnode GRPC stream interface. In other words, with
    /// this enabled, you can use an indexer fullnode like it is an instance of the
    /// indexer-grpc data service (aka the Transaction Stream Service API).
    pub use_data_service_interface: bool,

    /// The address that the grpc server will listen on.
    pub address: SocketAddr,

    /// Number of processor tasks to fan out
    pub processor_task_count: Option<u16>,

    /// Number of transactions each processor will process
    pub processor_batch_size: u16,

    /// Number of transactions returned in a single stream response
    pub output_batch_size: u16,

    /// Size of the transaction channel buffer for streaming.
    pub transaction_channel_size: usize,

    /// Maximum size in bytes for transaction filters.
    pub max_transaction_filter_size_bytes: usize,
}
```

**File:** config/src/config/indexer_grpc_config.rs (L104-128)
```rust
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        _chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();

        if !node_config.indexer_grpc.enabled {
            return Ok(());
        }

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
        Ok(())
    }
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/runtime.rs (L54-62)
```rust
    let processor_task_count = node_config
        .indexer_grpc
        .processor_task_count
        .unwrap_or_else(|| get_default_processor_task_count(use_data_service_interface));
    let processor_batch_size = node_config.indexer_grpc.processor_batch_size;
    let output_batch_size = node_config.indexer_grpc.output_batch_size;
    let transaction_channel_size = node_config.indexer_grpc.transaction_channel_size;
    let max_transaction_filter_size_bytes =
        node_config.indexer_grpc.max_transaction_filter_size_bytes;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L183-186)
```rust
                let mut responses = vec![];
                // Wrap in stream response object and send to channel
                for chunk in pb_txns.chunks(output_batch_size as usize) {
                    for chunk in chunk_transactions(chunk.to_vec(), MESSAGE_SIZE_LIMIT) {
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L293-318)
```rust
    async fn get_batches(&mut self) -> Vec<TransactionBatchInfo> {
        if !self.ensure_highest_known_version().await {
            return vec![];
        }

        let mut starting_version = self.current_version;
        let mut num_fetches = 0;
        let mut batches = vec![];
        let end_version = std::cmp::min(self.end_version, self.highest_known_version + 1);

        while num_fetches < self.processor_task_count && starting_version < end_version {
            let num_transactions_to_fetch = std::cmp::min(
                self.processor_batch_size as u64,
                end_version - starting_version,
            ) as u16;

            batches.push(TransactionBatchInfo {
                start_version: starting_version,
                head_version: self.highest_known_version,
                num_transactions_to_fetch,
            });
            starting_version += num_transactions_to_fetch as u64;
            num_fetches += 1;
        }
        batches
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L320-360)
```rust
    pub async fn fetch_raw_txns_with_retries(
        context: Arc<Context>,
        ledger_version: u64,
        batch: TransactionBatchInfo,
    ) -> Vec<TransactionOnChainData> {
        let mut retries = 0;
        loop {
            match context.get_transactions(
                batch.start_version,
                batch.num_transactions_to_fetch,
                ledger_version,
            ) {
                Ok(raw_txns) => return raw_txns,
                Err(err) => {
                    UNABLE_TO_FETCH_TRANSACTION.inc();
                    retries += 1;

                    if retries >= DEFAULT_NUM_RETRIES {
                        error!(
                            starting_version = batch.start_version,
                            num_transactions = batch.num_transactions_to_fetch,
                            error = format!("{:?}", err),
                            "Could not fetch transactions: retries exhausted",
                        );
                        panic!(
                            "Could not fetch {} transactions after {} retries, starting at {}: {:?}",
                            batch.num_transactions_to_fetch, retries, batch.start_version, err
                        );
                    } else {
                        error!(
                            starting_version = batch.start_version,
                            num_transactions = batch.num_transactions_to_fetch,
                            error = format!("{:?}", err),
                            "Could not fetch transactions: will retry",
                        );
                    }
                    tokio::time::sleep(Duration::from_millis(300)).await;
                },
            }
        }
    }
```

**File:** api/src/context.rs (L831-850)
```rust
    pub fn get_transactions(
        &self,
        start_version: u64,
        limit: u16,
        ledger_version: u64,
    ) -> Result<Vec<TransactionOnChainData>> {
        let data = self
            .db
            .get_transaction_outputs(start_version, limit as u64, ledger_version)?
            .consume_output_list_with_proof();

        let txn_start_version = data
            .get_first_output_version()
            .ok_or_else(|| format_err!("no start version from database"))?;
        ensure!(
            txn_start_version == start_version,
            "invalid start version from database: {} != {}",
            txn_start_version,
            start_version
        );
```

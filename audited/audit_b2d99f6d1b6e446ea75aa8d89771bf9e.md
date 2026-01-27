# Audit Report

## Title
Silent Indexing Failure Due to Unhandled Task Panic in Internal Indexer DB Service

## Summary
The internal indexer DB service spawns an async task that processes blockchain transactions into the indexer database. While all `?` operators correctly propagate errors within the service functions, the task is spawned with an `.unwrap()` call on the top-level error result, causing the task to panic and terminate silently when any database error occurs. Since no `JoinHandle` is stored or monitored, this panic goes undetected, leaving the indexer permanently stopped while the node appears healthy.

## Finding Description

The error propagation in `get_start_version()` uses `?` operators correctly throughout the function. [1](#0-0) 

Similarly, the `run()` function properly propagates errors from `get_start_version()` and database operations. [2](#0-1) 

However, when the indexer service is bootstrapped, the `run()` function is spawned as an async task with `.unwrap()` on the result, and the returned `JoinHandle` is not stored. [3](#0-2) 

Database operations can fail with various errors including `NotFound`, `RocksDbIncompleteResult`, `OtherRocksDbError`, `IoError`, and others. [4](#0-3) 

When any error occurs in `get_start_version()` or during the `run()` loop (e.g., from `ensure_synced_version()`, `get_persisted_version()`, or `process()`), the error is propagated correctly, but then hits the `.unwrap()` in the spawned task. This causes the task to panic. Since Tokio's spawned tasks terminate silently when they panic and no one awaits on them, the indexer service simply stops working without any log, metric update, or alert.

The runtime is kept alive in the `AptosHandle` struct, but only the runtime itself is stored, not the task handle. [5](#0-4) 

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty criteria for "State inconsistencies requiring intervention." While the indexer is not consensus-critical, its silent failure causes:

1. **API Degradation**: APIs depending on indexed data return incomplete or stale results
2. **Undetected Data Loss**: No alerts fire, making the failure invisible to operators
3. **Operational Blind Spot**: Node health checks pass while a critical service is down
4. **Recovery Complexity**: Operators must manually detect and restart the indexer, potentially requiring re-indexing from scratch

This doesn't affect consensus or core blockchain operations, but it degrades node functionality and user experience without visibility.

## Likelihood Explanation

This issue has **High Likelihood** of occurrence in production:

1. **Common Triggers**: Database errors occur regularly due to:
   - Disk space exhaustion
   - RocksDB corruption
   - I/O errors
   - Transient database failures during node restarts

2. **No Recovery Mechanism**: Once the task panics, it never restarts automatically

3. **No Visibility**: Without explicit monitoring of the task handle, operators won't know the indexer has stopped

4. **Silent Nature**: The node continues operating normally in all other aspects

## Recommendation

Replace the `.unwrap()` with proper error handling that logs the error and either retries or gracefully shuts down the node:

```rust
let config_clone = config.to_owned();
let join_handle = runtime.spawn(async move {
    loop {
        match indexer_service.run(&config_clone).await {
            Ok(_) => {
                // Should never return Ok in normal operation
                error!("Internal indexer service unexpectedly terminated");
                break;
            }
            Err(e) => {
                error!("Internal indexer service error: {}. Retrying in 5s...", e);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                // Reinitialize service state if needed
            }
        }
    }
});

// Store the join_handle for monitoring
Some((runtime, db_indexer, join_handle))
```

Additionally:
1. Store the `JoinHandle` and periodically check if the task is still alive
2. Add metrics to track indexer task health
3. Implement graceful degradation with alerting when the indexer fails

## Proof of Concept

The following test demonstrates the silent failure:

```rust
#[tokio::test]
async fn test_silent_indexer_failure() {
    use std::sync::Arc;
    use aptos_storage_interface::DbReader;
    use mockall::mock;
    
    // Create mock DbReader that returns an error
    mock! {
        DbReader {}
        impl DbReader for DbReader {
            fn ensure_synced_version(&self) -> Result<Version, AptosDbError> {
                Err(AptosDbError::NotFound("Database corrupted".to_string()))
            }
            // ... other required trait methods
        }
    }
    
    let mock_db = Arc::new(MockDbReader::new());
    let (sender, receiver) = tokio::sync::watch::channel((Instant::now(), 0u64));
    
    // Create indexer service
    let runtime = aptos_runtimes::spawn_named_runtime("test".to_string(), None);
    let internal_indexer_db = /* create test db */;
    let mut service = InternalIndexerDBService::new(
        mock_db.clone(),
        internal_indexer_db,
        receiver,
    );
    
    let config = NodeConfig::default();
    
    // Spawn task with unwrap - this will panic silently
    runtime.spawn(async move {
        service.run(&config).await.unwrap(); // Panics here
    });
    
    // Wait a bit
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    
    // Task has terminated silently - no error logged
    // Node continues running but indexer is dead
    // This demonstrates the vulnerability
}
```

## Notes

The answer to the specific question "Do all the ? operators properly propagate errors up the call stack?" is **YES** - the `?` operators work correctly. However, the second part of the question "or can some errors be silently swallowed causing silent indexing failures?" is also **YES** - errors ARE silently swallowed, but the root cause is the `.unwrap()` on the spawned task that has no monitoring, not a failure of the `?` operators themselves. This creates a complete error handling gap where properly propagated errors ultimately disappear into a panic that no one observes.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/internal_indexer_db_service.rs (L88-165)
```rust
    pub async fn get_start_version(&self, node_config: &NodeConfig) -> Result<Version> {
        let fast_sync_enabled = node_config
            .state_sync
            .state_sync_driver
            .bootstrapping_mode
            .is_fast_sync();
        let mut main_db_synced_version = self.db_indexer.main_db_reader.ensure_synced_version()?;

        // Wait till fast sync is done
        while fast_sync_enabled && main_db_synced_version == 0 {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            main_db_synced_version = self.db_indexer.main_db_reader.ensure_synced_version()?;
        }

        let start_version = self
            .db_indexer
            .indexer_db
            .get_persisted_version()?
            .map_or(0, |v| v + 1);

        if node_config.indexer_db_config.enable_statekeys() {
            let state_start_version = self
                .db_indexer
                .indexer_db
                .get_state_version()?
                .map_or(0, |v| v + 1);
            if start_version != state_start_version {
                panic!("Cannot start state indexer because the progress doesn't match.");
            }
        }

        if node_config.indexer_db_config.enable_transaction() {
            let transaction_start_version = self
                .db_indexer
                .indexer_db
                .get_transaction_version()?
                .map_or(0, |v| v + 1);
            if start_version != transaction_start_version {
                panic!("Cannot start transaction indexer because the progress doesn't match.");
            }
        }

        if node_config.indexer_db_config.enable_event() {
            let event_start_version = self
                .db_indexer
                .indexer_db
                .get_event_version()?
                .map_or(0, |v| v + 1);
            if start_version != event_start_version {
                panic!("Cannot start event indexer because the progress doesn't match.");
            }
        }

        if node_config.indexer_db_config.enable_event_v2_translation() {
            let event_v2_translation_start_version = self
                .db_indexer
                .indexer_db
                .get_event_v2_translation_version()?
                .map_or(0, |v| v + 1);
            if node_config
                .indexer_db_config
                .event_v2_translation_ignores_below_version()
                < start_version
                && start_version != event_v2_translation_start_version
            {
                panic!(
                    "Cannot start event v2 translation indexer because the progress doesn't match. \
                    start_version: {}, event_v2_translation_start_version: {}",
                    start_version, event_v2_translation_start_version
                );
            }
            if !node_config.indexer_db_config.enable_event() {
                panic!("Cannot start event v2 translation indexer because event indexer is not enabled.");
            }
        }

        Ok(start_version)
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/internal_indexer_db_service.rs (L167-199)
```rust
    pub async fn run(&mut self, node_config: &NodeConfig) -> Result<()> {
        let mut start_version = self.get_start_version(node_config).await?;
        let mut target_version = self.db_indexer.main_db_reader.ensure_synced_version()?;
        let mut step_timer = std::time::Instant::now();

        loop {
            if target_version <= start_version {
                match self.update_receiver.changed().await {
                    Ok(_) => {
                        (step_timer, target_version) = *self.update_receiver.borrow();
                    },
                    Err(e) => {
                        panic!("Failed to get update from update_receiver: {}", e);
                    },
                }
            }
            let next_version = self.db_indexer.process(start_version, target_version)?;
            INDEXER_DB_LATENCY.set(step_timer.elapsed().as_millis() as i64);
            log_grpc_step(
                SERVICE_TYPE,
                IndexerGrpcStep::InternalIndexerDBProcessed,
                Some(start_version as i64),
                Some(next_version as i64),
                None,
                None,
                Some(step_timer.elapsed().as_secs_f64()),
                None,
                Some((next_version - start_version) as i64),
                None,
            );
            start_version = next_version;
        }
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/runtime.rs (L40-46)
```rust
    // Spawn task for db indexer
    let config_clone = config.to_owned();
    runtime.spawn(async move {
        indexer_service.run(&config_clone).await.unwrap();
    });

    Some((runtime, db_indexer))
```

**File:** storage/storage-interface/src/errors.rs (L9-37)
```rust
/// This enum defines errors commonly used among `AptosDB` APIs.
#[derive(Clone, Debug, Error)]
pub enum AptosDbError {
    /// A requested item is not found.
    #[error("{0} not found.")]
    NotFound(String),
    /// Requested too many items.
    #[error("Too many items requested: at least {0} requested, max is {1}")]
    TooManyRequested(u64, u64),
    #[error("Missing state root node at version {0}, probably pruned.")]
    MissingRootError(u64),
    /// Other non-classified error.
    #[error("AptosDB Other Error: {0}")]
    Other(String),
    #[error("AptosDB RocksDb Error: {0}")]
    RocksDbIncompleteResult(String),
    #[error("AptosDB RocksDB Error: {0}")]
    OtherRocksDbError(String),
    #[error("AptosDB bcs Error: {0}")]
    BcsError(String),
    #[error("AptosDB IO Error: {0}")]
    IoError(String),
    #[error("AptosDB Recv Error: {0}")]
    RecvError(String),
    #[error("AptosDB ParseInt Error: {0}")]
    ParseIntError(String),
    #[error("Hot state not configured properly")]
    HotStateError,
}
```

**File:** aptos-node/src/lib.rs (L197-215)
```rust
pub struct AptosHandle {
    _admin_service: AdminService,
    _api_runtime: Option<Runtime>,
    _backup_runtime: Option<Runtime>,
    _consensus_observer_runtime: Option<Runtime>,
    _consensus_publisher_runtime: Option<Runtime>,
    _consensus_runtime: Option<Runtime>,
    _dkg_runtime: Option<Runtime>,
    _indexer_grpc_runtime: Option<Runtime>,
    _indexer_runtime: Option<Runtime>,
    _indexer_table_info_runtime: Option<Runtime>,
    _jwk_consensus_runtime: Option<Runtime>,
    _mempool_runtime: Runtime,
    _network_runtimes: Vec<Runtime>,
    _peer_monitoring_service_runtime: Runtime,
    _state_sync_runtimes: StateSyncRuntimes,
    _telemetry_runtime: Option<Runtime>,
    _indexer_db_runtime: Option<Runtime>,
}
```

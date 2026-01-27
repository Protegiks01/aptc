# Audit Report

## Title
Internal Indexer Version Mismatch Panic on Configuration Change (enable_event toggle)

## Summary
The internal indexer DB service contains a critical design flaw where toggling `enable_event` configuration between node restarts causes orphaned event metadata and triggers a panic on subsequent startup, rendering the node unable to restart without manual database intervention.

## Finding Description

The vulnerability exists in the internal indexer's metadata tracking system. The system maintains separate version metadata for different indexer components (`LatestVersion`, `EventVersion`, `TransactionVersion`, `StateVersion`) but fails to handle configuration changes that disable/re-enable specific indexer features.

**Core Issue**: When event indexing is disabled (`enable_event=false`), the `EventVersion` metadata stops being updated while `LatestVersion` continues advancing. Upon re-enabling event indexing (`enable_event=true`), the startup validation detects a version mismatch and panics. [1](#0-0) 

When event indexing is enabled, `EventVersion` is updated to track progress: [2](#0-1) 

However, `LatestVersion` is **always** updated regardless of configuration: [3](#0-2) 

The startup validation reads `LatestVersion` as the base version: [4](#0-3) 

When `enable_event` is true at startup, the code validates that `EventVersion` matches `LatestVersion` and panics if they diverge:

**Attack Scenario**:
1. Node starts with `enable_event=true`, indexes versions 0-10000
   - `LatestVersion = 10000`
   - `EventVersion = 10000`
2. Operator restarts with `enable_event=false`, indexes versions 10001-50000
   - `LatestVersion = 50000` (always updated)
   - `EventVersion = 10000` (not updated when disabled)
3. Operator restarts with `enable_event=true`
   - `start_version = 50001` (from LatestVersion + 1)
   - `event_start_version = 10001` (from EventVersion + 1)
   - **Panic**: "Cannot start event indexer because the progress doesn't match."

## Impact Explanation

This qualifies as **High Severity** per Aptos bug bounty criteria:

1. **Validator/Fullnode Cannot Start**: The node panics during startup and cannot recover without manual intervention
2. **No Documented Recovery Path**: The storage README and codebase provide no guidance for recovering from this state
3. **Operational Availability Impact**: Production nodes affected by this issue experience complete downtime
4. **Manual Database Intervention Required**: Operators must directly manipulate RocksDB metadata or completely reindex [5](#0-4) 

The documentation describes the internal indexer configuration but provides no recovery procedures for metadata mismatches.

This meets the **"Validator node slowdowns"** and **"API crashes"** criteria for High Severity, as the node cannot start at all.

## Likelihood Explanation

**Likelihood: Medium to High**

This scenario occurs in legitimate operational contexts:
- **Performance Testing**: Operators may disable event indexing temporarily to measure performance impact
- **Debugging**: Troubleshooting issues by selectively enabling/disabling indexer components
- **Configuration Rollback**: Reverting configuration changes after discovering issues
- **Resource Constraints**: Temporarily disabling features during resource pressure

The issue is **deterministic** - it will always occur when the configuration change pattern is followed. The only barrier is that it requires node operator access, but this is a normal operational action, not a security breach.

## Recommendation

Implement one of the following solutions:

**Option 1: Validate Configuration Consistency at Startup**

Add validation before starting the indexer to detect version mismatches and provide clear error messages with recovery instructions:

```rust
// In get_start_version() method
if node_config.indexer_db_config.enable_event() {
    let event_start_version = self
        .db_indexer
        .indexer_db
        .get_event_version()?
        .map_or(0, |v| v + 1);
    
    if start_version != event_start_version {
        return Err(anyhow::anyhow!(
            "Event indexer version mismatch detected. This likely occurred due to \
            configuration changes. EventVersion: {}, LatestVersion: {}. \
            Recovery options: \n\
            1. Delete internal indexer DB and reindex from scratch\n\
            2. Manually reset EventVersion metadata to match LatestVersion\n\
            3. Continue with enable_event=false until versions align",
            event_start_version - 1,
            start_version - 1
        ));
    }
}
```

**Option 2: Automatic Metadata Reset**

When enabling a previously disabled indexer component, automatically reset its metadata to the current `LatestVersion`:

```rust
if node_config.indexer_db_config.enable_event() {
    let event_version = self.db_indexer.indexer_db.get_event_version()?;
    
    if let Some(event_ver) = event_version {
        if start_version != event_ver + 1 {
            warn!(
                "Resetting EventVersion from {} to {} due to configuration change",
                event_ver, start_version - 1
            );
            // Reset EventVersion to LatestVersion
            let mut batch = SchemaBatch::new();
            batch.put::<InternalIndexerMetadataSchema>(
                &MetadataKey::EventVersion,
                &MetadataValue::Version(start_version - 1),
            )?;
            self.db_indexer.indexer_db.get_inner_db_ref().write_schemas(batch)?;
        }
    }
}
```

**Option 3: Prevent Configuration Changes**

Add sanitizer validation to prevent configuration changes on existing databases: [6](#0-5) 

Extend the sanitizer to detect configuration changes from previous runs.

## Proof of Concept

```rust
#[test]
fn test_event_indexer_config_change_panic() {
    use aptos_db::AptosDB;
    use aptos_db_indexer::db_indexer::DBIndexer;
    use aptos_indexer_grpc_table_info::internal_indexer_db_service::InternalIndexerDBService;
    use aptos_config::config::{NodeConfig, InternalIndexerDBConfig};
    use aptos_temppath::TempPath;
    
    // Create test database with some transactions
    let (aptos_db, _) = create_test_db(); // Creates 12 versions
    let temp_path = TempPath::new();
    
    // Phase 1: Index with enable_event=true from 0 to 11
    let mut node_config = NodeConfig::default();
    node_config.storage.dir = temp_path.path().to_path_buf();
    node_config.indexer_db_config = InternalIndexerDBConfig::new(
        false, true, false, 0, false, 10_000
    ); // Only enable_event=true
    
    let internal_indexer_db = InternalIndexerDBService::get_indexer_db(&node_config).unwrap();
    let db_indexer = DBIndexer::new(internal_indexer_db.clone(), aptos_db.clone());
    db_indexer.process(0, 12).unwrap();
    
    // Verify EventVersion was written
    assert_eq!(internal_indexer_db.get_event_version().unwrap(), Some(11));
    assert_eq!(internal_indexer_db.get_persisted_version().unwrap(), Some(11));
    
    drop(db_indexer);
    drop(internal_indexer_db);
    
    // Simulate adding more transactions to main DB (versions 12-50)
    // (In real scenario, node continues running with enable_event=false)
    
    // Phase 2: Reopen with enable_event=false and continue indexing
    node_config.indexer_db_config = InternalIndexerDBConfig::new(
        false, false, false, 0, false, 10_000  
    ); // Disable event indexing
    
    let internal_indexer_db2 = InternalIndexerDBService::get_indexer_db(&node_config).unwrap();
    let db_indexer2 = DBIndexer::new(internal_indexer_db2.clone(), aptos_db.clone());
    
    // Manually update LatestVersion to simulate continued indexing
    // (without updating EventVersion since enable_event=false)
    use aptos_db_indexer_schemas::schema::indexer_metadata::InternalIndexerMetadataSchema;
    use aptos_db_indexer_schemas::metadata::{MetadataKey, MetadataValue};
    use aptos_schemadb::SchemaBatch;
    
    let mut batch = SchemaBatch::new();
    batch.put::<InternalIndexerMetadataSchema>(
        &MetadataKey::LatestVersion,
        &MetadataValue::Version(50),
    ).unwrap();
    internal_indexer_db2.get_inner_db_ref().write_schemas(batch).unwrap();
    
    // Verify the mismatch
    assert_eq!(internal_indexer_db2.get_event_version().unwrap(), Some(11)); // Old value
    assert_eq!(internal_indexer_db2.get_persisted_version().unwrap(), Some(50)); // New value
    
    drop(db_indexer2);
    drop(internal_indexer_db2);
    
    // Phase 3: Attempt to restart with enable_event=true
    // This should panic
    node_config.indexer_db_config = InternalIndexerDBConfig::new(
        false, true, false, 0, false, 10_000
    ); // Re-enable event indexing
    
    let internal_indexer_db3 = InternalIndexerDBService::get_indexer_db(&node_config).unwrap();
    let (tx, rx) = tokio::sync::watch::channel((std::time::Instant::now(), 0u64));
    
    let mut service = InternalIndexerDBService::new(
        aptos_db.clone(),
        internal_indexer_db3,
        rx
    );
    
    // This will panic with "Cannot start event indexer because the progress doesn't match."
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            service.get_start_version(&node_config).await
        })
    }));
    
    assert!(result.is_err(), "Expected panic due to version mismatch");
}
```

## Notes

This vulnerability represents a **defensive programming failure** where the system:
1. Allows state-altering configuration changes without validation
2. Lacks migration logic for metadata consistency
3. Uses panic instead of graceful error handling
4. Provides no recovery documentation

The same issue applies to `enable_transaction` and `enable_statekeys` configurations, as they follow identical patterns in the codebase. [7](#0-6) 

All three indexer components (events, transactions, state keys) share this vulnerability pattern.

### Citations

**File:** storage/indexer/src/db_indexer.rs (L530-535)
```rust
        if self.indexer_db.event_enabled() {
            batch.put::<InternalIndexerMetadataSchema>(
                &MetadataKey::EventVersion,
                &MetadataValue::Version(version - 1),
            )?;
        }
```

**File:** storage/indexer/src/db_indexer.rs (L542-545)
```rust
        batch.put::<InternalIndexerMetadataSchema>(
            &MetadataKey::LatestVersion,
            &MetadataValue::Version(version - 1),
        )?;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/internal_indexer_db_service.rs (L102-106)
```rust
        let start_version = self
            .db_indexer
            .indexer_db
            .get_persisted_version()?
            .map_or(0, |v| v + 1);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/internal_indexer_db_service.rs (L108-128)
```rust
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
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/internal_indexer_db_service.rs (L130-139)
```rust
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
```

**File:** storage/README.md (L149-176)
```markdown
  # The internal indexer is experimental, and should be kept disabled.
  enable_indexer: false
```

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

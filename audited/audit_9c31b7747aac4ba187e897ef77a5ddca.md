# Audit Report

## Title
TOCTOU Race Condition in Internal Indexer Service Version Consistency Checks

## Summary
The `get_start_version()` function in `InternalIndexerDBService` performs multiple non-atomic database reads to verify version consistency across different indexer types (state, transaction, event). These separate reads create a TOCTOU race condition where concurrent writers (`StateStore::kv_finish()` during state restore or `DBIndexer::process_a_batch()`) can update all version metadata between reads, causing the service to panic and crash with "Cannot start X indexer because the progress doesn't match."

## Finding Description

The vulnerability exists in the `get_start_version()` function which performs version consistency validation through multiple separate database queries: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

Each version query is a separate, non-atomic database read: [5](#0-4) 

Meanwhile, concurrent writers update all version metadata atomically in a single batch. The `StateStore::kv_finish()` method (called during state restore/fast sync) writes all versions together: [6](#0-5) 

Similarly, `DBIndexer::process_a_batch()` updates all versions atomically: [7](#0-6) 

**The Race Condition:**

1. Thread A (service initialization): Reads `start_version` (LatestVersion) = N
2. Thread B (state restore/indexer): Writes atomic batch updating all versions to N+1
3. Thread A: Reads `state_start_version` (StateVersion) = N+1
4. Thread A: Panics because N ≠ N+1, crashing the service

This violates the **State Consistency** invariant that expects atomic version reads, and breaks **availability** by causing service crashes.

## Impact Explanation

**Severity: High**

This qualifies as **High Severity** per Aptos bug bounty criteria:
- **API crashes**: The internal indexer service crashes with a panic
- **Service unavailability**: The indexing subsystem becomes unavailable until restart
- **Critical infrastructure impact**: Internal indexer is essential for state queries and blockchain data access

The impact is:
1. **Denial of Service**: The internal indexer service terminates unexpectedly
2. **Cascading failures**: Services depending on the indexer lose functionality
3. **Operational disruption**: Requires manual intervention to restart the service
4. **Repeated failures**: Can occur repeatedly during fast sync periods

While this doesn't directly affect consensus or cause fund loss, it significantly degrades node availability and API functionality, meeting the "API crashes" criterion for High Severity.

## Likelihood Explanation

**Likelihood: High**

This race condition is highly likely to occur because:

1. **Common trigger conditions**: 
   - Fast sync operations (explicitly waited for in the code)
   - State restore operations
   - Service initialization during active indexing

2. **Timing window**: The race window exists between ANY two consecutive version reads (microseconds to milliseconds), during which database writes can occur

3. **Concurrent writers**: Multiple sources can write versions:
   - `StateStore::kv_finish()` during state snapshots
   - `DBIndexer::process_a_batch()` during normal indexing
   - Both run in separate threads from the service initialization

4. **No synchronization**: No locks, transactions, or atomic read operations protect the multi-read sequence

5. **Real-world scenario**: During node bootstrap with fast sync enabled, the code explicitly waits for sync completion while simultaneously performing version checks, creating the perfect race condition scenario: [8](#0-7) 

## Recommendation

**Solution: Use a database transaction or snapshot to ensure atomic reads**

Wrap all version reads in a single database transaction or snapshot read to guarantee consistency:

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

    // Use a snapshot read or single batch read for all versions
    let versions = self.db_indexer.indexer_db.get_all_versions_atomic()?;
    
    let start_version = versions.latest_version.map_or(0, |v| v + 1);

    if node_config.indexer_db_config.enable_statekeys() {
        let state_start_version = versions.state_version.map_or(0, |v| v + 1);
        if start_version != state_start_version {
            panic!("Cannot start state indexer because the progress doesn't match.");
        }
    }

    if node_config.indexer_db_config.enable_transaction() {
        let transaction_start_version = versions.transaction_version.map_or(0, |v| v + 1);
        if start_version != transaction_start_version {
            panic!("Cannot start transaction indexer because the progress doesn't match.");
        }
    }

    if node_config.indexer_db_config.enable_event() {
        let event_start_version = versions.event_version.map_or(0, |v| v + 1);
        if start_version != event_start_version {
            panic!("Cannot start event indexer because the progress doesn't match.");
        }
    }

    if node_config.indexer_db_config.enable_event_v2_translation() {
        let event_v2_translation_start_version = versions.event_v2_translation_version.map_or(0, |v| v + 1);
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

Add a new method to `InternalIndexerDB`:

```rust
struct IndexerVersions {
    latest_version: Option<Version>,
    state_version: Option<Version>,
    transaction_version: Option<Version>,
    event_version: Option<Version>,
    event_v2_translation_version: Option<Version>,
}

impl InternalIndexerDB {
    pub fn get_all_versions_atomic(&self) -> Result<IndexerVersions> {
        // Use RocksDB snapshot for atomic multi-key read
        let snapshot = self.db.get_snapshot();
        Ok(IndexerVersions {
            latest_version: self.get_version_from_snapshot(&snapshot, &MetadataKey::LatestVersion)?,
            state_version: self.get_version_from_snapshot(&snapshot, &MetadataKey::StateVersion)?,
            transaction_version: self.get_version_from_snapshot(&snapshot, &MetadataKey::TransactionVersion)?,
            event_version: self.get_version_from_snapshot(&snapshot, &MetadataKey::EventVersion)?,
            event_v2_translation_version: self.get_version_from_snapshot(&snapshot, &MetadataKey::EventV2TranslationVersion)?,
        })
    }
}
```

## Proof of Concept

```rust
#[tokio::test]
async fn test_toctou_race_condition() {
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;
    
    // Setup: Create InternalIndexerDB and service
    let db = create_test_db();
    let indexer_db = InternalIndexerDB::new(Arc::new(db), default_config());
    let db_reader = create_mock_db_reader();
    let (tx, rx) = tokio::sync::watch::channel((Instant::now(), 0u64));
    let mut service = InternalIndexerDBService::new(db_reader, indexer_db.clone(), rx);
    
    // Initialize with version 100 for all indexer types
    initialize_versions(&indexer_db, 100);
    
    // Spawn concurrent writer that updates versions
    let indexer_db_clone = indexer_db.clone();
    let writer_handle = thread::spawn(move || {
        loop {
            // Simulate StateStore::kv_finish() or DBIndexer::process_a_batch()
            update_all_versions_atomically(&indexer_db_clone, 101);
            thread::sleep(Duration::from_micros(10));
        }
    });
    
    // Attempt to call get_start_version multiple times
    let mut panic_count = 0;
    for _ in 0..100 {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // This should panic due to version mismatch
            futures::executor::block_on(service.get_start_version(&default_node_config()))
        }));
        
        if result.is_err() {
            panic_count += 1;
        }
        
        // Reset versions for next iteration
        initialize_versions(&indexer_db, 100);
        thread::sleep(Duration::from_micros(100));
    }
    
    // The race condition should trigger at least some panics
    assert!(panic_count > 0, "TOCTOU race condition reproduced: {} panics out of 100 attempts", panic_count);
}
```

**Notes**

The vulnerability is a classic TOCTOU race condition where the "check" (reading multiple version values) and "use" (comparing them for consistency) are not atomic, allowing concurrent "writers" to modify the underlying data between operations. This is particularly problematic during fast sync and state restore operations when version updates are frequent. The fix requires using database snapshots or transactions to ensure all version reads see a consistent view of the data.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/internal_indexer_db_service.rs (L89-100)
```rust
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
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/internal_indexer_db_service.rs (L102-106)
```rust
        let start_version = self
            .db_indexer
            .indexer_db
            .get_persisted_version()?
            .map_or(0, |v| v + 1);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/internal_indexer_db_service.rs (L109-116)
```rust
            let state_start_version = self
                .db_indexer
                .indexer_db
                .get_state_version()?
                .map_or(0, |v| v + 1);
            if start_version != state_start_version {
                panic!("Cannot start state indexer because the progress doesn't match.");
            }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/internal_indexer_db_service.rs (L120-127)
```rust
            let transaction_start_version = self
                .db_indexer
                .indexer_db
                .get_transaction_version()?
                .map_or(0, |v| v + 1);
            if start_version != transaction_start_version {
                panic!("Cannot start transaction indexer because the progress doesn't match.");
            }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/internal_indexer_db_service.rs (L131-138)
```rust
            let event_start_version = self
                .db_indexer
                .indexer_db
                .get_event_version()?
                .map_or(0, |v| v + 1);
            if start_version != event_start_version {
                panic!("Cannot start event indexer because the progress doesn't match.");
            }
```

**File:** storage/indexer/src/db_indexer.rs (L287-292)
```rust
    fn get_version(&self, key: &MetadataKey) -> Result<Option<Version>> {
        Ok(self
            .db
            .get::<InternalIndexerMetadataSchema>(key)?
            .map(|v| v.expect_version()))
    }
```

**File:** storage/indexer/src/db_indexer.rs (L524-545)
```rust
        if self.indexer_db.transaction_enabled() {
            batch.put::<InternalIndexerMetadataSchema>(
                &MetadataKey::TransactionVersion,
                &MetadataValue::Version(version - 1),
            )?;
        }
        if self.indexer_db.event_enabled() {
            batch.put::<InternalIndexerMetadataSchema>(
                &MetadataKey::EventVersion,
                &MetadataValue::Version(version - 1),
            )?;
        }
        if self.indexer_db.statekeys_enabled() {
            batch.put::<InternalIndexerMetadataSchema>(
                &MetadataKey::StateVersion,
                &MetadataValue::Version(version - 1),
            )?;
        }
        batch.put::<InternalIndexerMetadataSchema>(
            &MetadataKey::LatestVersion,
            &MetadataValue::Version(version - 1),
        )?;
```

**File:** storage/aptosdb/src/state_store/mod.rs (L1283-1311)
```rust
        if let Some(internal_indexer_db) = self.internal_indexer_db.as_ref() {
            if version > 0 {
                let mut batch = SchemaBatch::new();
                batch.put::<InternalIndexerMetadataSchema>(
                    &MetadataKey::LatestVersion,
                    &MetadataValue::Version(version - 1),
                )?;
                if internal_indexer_db.statekeys_enabled() {
                    batch.put::<InternalIndexerMetadataSchema>(
                        &MetadataKey::StateVersion,
                        &MetadataValue::Version(version - 1),
                    )?;
                }
                if internal_indexer_db.transaction_enabled() {
                    batch.put::<InternalIndexerMetadataSchema>(
                        &MetadataKey::TransactionVersion,
                        &MetadataValue::Version(version - 1),
                    )?;
                }
                if internal_indexer_db.event_enabled() {
                    batch.put::<InternalIndexerMetadataSchema>(
                        &MetadataKey::EventVersion,
                        &MetadataValue::Version(version - 1),
                    )?;
                }
                internal_indexer_db
                    .get_inner_db_ref()
                    .write_schemas(batch)?;
            }
```

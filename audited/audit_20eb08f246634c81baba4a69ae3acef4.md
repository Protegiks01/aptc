# Audit Report

## Title
EventByVersionSchema Orphaned Index Vulnerability During Pruning with Disabled Internal Indexer Event Support

## Summary
When the internal indexer database is enabled but event indexing is disabled (`enable_event=false`), the event pruning process creates orphaned index entries in `EventByVersionSchema` and `EventByKeySchema` that point to non-existent event data, causing query failures and API crashes.

## Finding Description

The vulnerability exists in the event pruning logic when a specific configuration is used. The Aptos storage system maintains event indices in both the main event database and optionally in a separate internal indexer database. The indices (`EventByVersionSchema` and `EventByKeySchema`) map event lookups to actual event data stored in `EventSchema`. [1](#0-0) 

The event database contains both the indices and the actual event data. When the internal indexer database is enabled for other purposes (e.g., transaction indexing with `enable_transaction=true`) but event indexing is explicitly disabled (`enable_event=false`), the pruning logic exhibits a critical flaw. [2](#0-1) 

In this configuration, `indices_batch` is set to `None` because `indexer_db.event_enabled()` returns `false`, but `indexer_batch` is not initialized. This causes the index deletion logic to be skipped entirely: [3](#0-2) 

When `indices_batch` is `None`, the condition at line 206 fails, and the index deletions (lines 209-214) are never executed. However, the actual event data deletion still proceeds: [4](#0-3) [5](#0-4) 

This creates orphaned indices pointing to pruned events. When queries are executed, they successfully find index entries but fail when attempting to retrieve the actual event data: [6](#0-5) 

Public-facing APIs are directly affected: [7](#0-6) [8](#0-7) 

## Impact Explanation

This vulnerability qualifies as **High Severity** ($50,000 category) based on the Aptos bug bounty criteria:

1. **API Crashes**: The REST API endpoints `/accounts/{address}/events/{creation_number}` and `/accounts/{address}/events/{event_handle}/{field_name}` return `AptosDbError::NotFound` errors for events that should exist according to the indices, breaking client applications that rely on event queries.

2. **Significant Protocol Violations**: This violates the **State Consistency** invariant - the storage layer returns inconsistent results where indices indicate data exists but the data itself is missing. This breaks the assumption that indices accurately reflect data availability.

3. **Node Reliability**: Critical internal APIs like `get_first_viable_block()` fail, potentially affecting state sync, pruning calculations, and other node operations that depend on event data.

4. **Data Integrity**: The database enters an inconsistent state with orphaned indices, requiring manual intervention or database rebuild to restore full functionality.

While this does not directly affect consensus safety or cause fund loss, it significantly degrades node reliability and API availability, meeting the High Severity criteria for "API crashes" and "Significant protocol violations."

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability requires a specific but valid configuration:
- Internal indexer database must be enabled
- Event indexing must be explicitly disabled (`enable_event=false`)
- Another indexer feature must be enabled (e.g., `enable_transaction=true` or `enable_statekeys=true`) [9](#0-8) 

This configuration is valid and could be intentionally chosen by node operators who want transaction indexing but not event indexing for performance reasons. Once configured this way and pruning executes (which happens automatically based on pruner configuration), the vulnerability manifests immediately and persistently.

## Recommendation

Fix the pruning logic to ensure indices in the event database are deleted regardless of internal indexer configuration. The `indices_batch` should always point to a valid batch when pruning the event database:

```rust
// In event_store_pruner.rs, modify the prune() method:
let mut batch = SchemaBatch::new();
let mut indexer_batch = None;

// Always use the main batch for event DB indices unless overridden
let indices_batch = if let Some(indexer_db) = self.indexer_db() {
    if indexer_db.event_enabled() {
        indexer_batch = Some(SchemaBatch::new());
        indexer_batch.as_mut()
    } else {
        // If internal indexer exists but event indexing disabled,
        // still prune indices from the main event DB
        Some(&mut batch)
    }
} else {
    Some(&mut batch)
};
```

This ensures that when `event_enabled()` is false, the indices are still deleted from the event database alongside the event data, maintaining consistency.

Additionally, add validation during startup to detect and warn about orphaned indices, and provide a database repair tool to rebuild or clean up inconsistent indices.

## Proof of Concept

```rust
// Test demonstrating orphaned index creation
// File: storage/aptosdb/src/pruner/ledger_pruner/event_store_pruner_test.rs

#[test]
fn test_orphaned_indices_with_disabled_internal_indexer_events() {
    // Setup: Create AptosDB with internal indexer enabled but events disabled
    let tmpdir = TempPath::new();
    let mut config = RocksdbConfigs::default();
    config.enable_storage_sharding = true;
    
    let mut indexer_config = InternalIndexerDBConfig::default();
    indexer_config.enable_transaction = true;  // Enable indexer
    indexer_config.enable_event = false;       // But disable event indexing
    
    let db = AptosDB::new_for_test_with_indexer(&tmpdir, indexer_config);
    
    // Write some events
    let events = vec![ContractEvent::V1(/* create test event */)];
    db.save_transactions(/* transactions with events */, /* ... */);
    
    // Verify indices exist in event DB
    let event_key = /* extract event key */;
    let indices = db.event_store.lookup_events_by_key(&event_key, 0, 10, 100).unwrap();
    assert!(!indices.is_empty());
    
    // Run pruning
    let pruner = EventStorePruner::new(/* ... */);
    pruner.prune(0, 50).unwrap();
    
    // BUG: Indices still exist in event DB
    let indices_after = db.event_store.lookup_events_by_key(&event_key, 0, 10, 100).unwrap();
    assert!(!indices_after.is_empty()); // Indices NOT pruned
    
    // But event data is gone
    let (version, index) = indices_after[0].1, indices_after[0].2;
    let result = db.event_store.get_event_by_version_and_index(version, index);
    assert!(result.is_err()); // NotFound error - orphaned index!
}
```

### Citations

**File:** storage/aptosdb/src/db_options.rs (L42-51)
```rust
pub(super) fn event_db_column_families() -> Vec<ColumnFamilyName> {
    vec![
        /* empty cf */ DEFAULT_COLUMN_FAMILY_NAME,
        DB_METADATA_CF_NAME,
        EVENT_ACCUMULATOR_CF_NAME,
        EVENT_BY_KEY_CF_NAME,
        EVENT_BY_VERSION_CF_NAME,
        EVENT_CF_NAME,
    ]
}
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/event_store_pruner.rs (L47-54)
```rust
        let indices_batch = if let Some(indexer_db) = self.indexer_db() {
            if indexer_db.event_enabled() {
                indexer_batch = Some(SchemaBatch::new());
            }
            indexer_batch.as_mut()
        } else {
            Some(&mut batch)
        };
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/event_store_pruner.rs (L60-65)
```rust
        self.ledger_db.event_db().prune_events(
            num_events_per_version,
            current_progress,
            target_version,
            &mut batch,
        )?;
```

**File:** storage/aptosdb/src/ledger_db/event_db.rs (L192-222)
```rust
    pub(crate) fn prune_event_indices(
        &self,
        start: Version,
        end: Version,
        mut indices_batch: Option<&mut SchemaBatch>,
    ) -> Result<Vec<usize>> {
        let mut ret = Vec::new();

        let mut current_version = start;

        for events in self.get_events_by_version_iter(start, (end - start) as usize)? {
            let events = events?;
            ret.push(events.len());

            if let Some(ref mut batch) = indices_batch {
                for event in events {
                    if let ContractEvent::V1(v1) = event {
                        batch.delete::<EventByKeySchema>(&(*v1.key(), v1.sequence_number()))?;
                        batch.delete::<EventByVersionSchema>(&(
                            *v1.key(),
                            current_version,
                            v1.sequence_number(),
                        ))?;
                    }
                }
            }
            current_version += 1;
        }

        Ok(ret)
    }
```

**File:** storage/aptosdb/src/ledger_db/event_db.rs (L225-243)
```rust
    pub(crate) fn prune_events(
        &self,
        num_events_per_version: Vec<usize>,
        start: Version,
        end: Version,
        db_batch: &mut SchemaBatch,
    ) -> Result<()> {
        let mut current_version = start;

        for num_events in num_events_per_version {
            for idx in 0..num_events {
                db_batch.delete::<EventSchema>(&(current_version, idx as u64))?;
            }
            current_version += 1;
        }
        self.event_store
            .prune_event_accumulator(start, end, db_batch)?;
        Ok(())
    }
```

**File:** storage/aptosdb/src/event_store/mod.rs (L42-50)
```rust
    pub fn get_event_by_version_and_index(
        &self,
        version: Version,
        index: u64,
    ) -> Result<ContractEvent> {
        self.event_db
            .get::<EventSchema>(&(version, index))?
            .ok_or_else(|| AptosDbError::NotFound(format!("Event {} of Txn {}", index, version)))
    }
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L335-352)
```rust
    /// Get the first block version / height that will likely not be pruned soon.
    fn get_first_viable_block(&self) -> Result<(Version, BlockHeight)> {
        gauged_api("get_first_viable_block", || {
            let min_version = self.ledger_pruner.get_min_viable_version();
            if !self.skip_index_and_usage {
                let (block_version, index, _seq_num) = self
                    .event_store
                    .lookup_event_at_or_after_version(&new_block_event_key(), min_version)?
                    .ok_or_else(|| {
                        AptosDbError::NotFound(format!(
                            "NewBlockEvent at or after version {}",
                            min_version
                        ))
                    })?;
                let event = self
                    .event_store
                    .get_event_by_version_and_index(block_version, index)?;
                return Ok((block_version, event.expect_new_block_event()?.height()));
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L1153-1169)
```rust
        let mut events_with_version = event_indices
            .into_iter()
            .map(|(seq, ver, idx)| {
                let event = self.event_store.get_event_by_version_and_index(ver, idx)?;
                let v0 = match &event {
                    ContractEvent::V1(event) => event,
                    ContractEvent::V2(_) => bail!("Unexpected module event"),
                };
                ensure!(
                    seq == v0.sequence_number(),
                    "Index broken, expected seq:{}, actual:{}",
                    seq,
                    v0.sequence_number()
                );
                Ok(EventWithVersion::new(ver, event))
            })
            .collect::<Result<Vec<_>>>()?;
```

**File:** config/src/config/internal_indexer_db_config.rs (L60-62)
```rust
    pub fn is_internal_indexer_db_enabled(&self) -> bool {
        self.enable_transaction || self.enable_event || self.enable_statekeys
    }
```

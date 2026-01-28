# Audit Report

## Title
Incorrect LedgerPrunerProgress Initialization Causes Unintended Data Deletion During Sub-Pruner Catch-Up

## Summary
When `LedgerPrunerProgress` metadata is missing from the database, the fallback initialization logic incorrectly sets it to the first available `VersionData` checkpoint version. Since `VersionData` entries below the actual pruning progress have already been deleted, this results in an artificially inflated progress value. Sub-pruners then "catch up" to this incorrect value by deleting legitimate ledger data that was never intended to be pruned.

## Finding Description

The vulnerability manifests during node initialization when the `LedgerPrunerProgress` metadata key is absent from the database. This can occur during database migration from older versions, selective backup/restore operations, metadata corruption, or manual database maintenance.

The fallback initialization logic in `LedgerMetadataPruner::new()` seeks to the first entry in `VersionDataSchema` to initialize the progress counter: [1](#0-0) 

The developer comment explicitly acknowledges uncertainty about this scenario, stating "I **think** all db should have the LedgerPrunerProgress."

The critical issue is that `VersionData` is only written at checkpoint boundaries, not for every version. This is evident in the state store implementation where usage statistics are selectively written: [2](#0-1) 

After previous pruning operations, `VersionData` entries below the actual pruning progress are deleted: [3](#0-2) 

When `LedgerPruner` initializes, it retrieves this incorrectly high `metadata_progress` and passes it to all sub-pruners: [4](#0-3) 

Each sub-pruner (EventStorePruner, TransactionPruner, WriteSetPruner, etc.) then executes a "catch up" operation. For example, EventStorePruner initializes with: [5](#0-4) 

The sub-pruner retrieves its correctly stored progress (e.g., 9,500,000) but receives the incorrectly inflated metadata_progress (e.g., 9,550,000 from the first checkpoint). Line 106 then calls `prune(progress, metadata_progress)`, which deletes events from versions 9,500,000 to 9,549,999 - data that was never meant to be pruned.

**Exploitation Scenario:**
1. Database previously pruned to version 9,500,000
2. All sub-pruner progress keys correctly stored at 9,500,000
3. `LedgerPrunerProgress` lost due to migration/restore/corruption
4. Previous pruning deleted all VersionData below 9,500,000
5. First remaining VersionData checkpoint at 9,550,000
6. On restart: LedgerMetadataPruner initializes to 9,550,000
7. Each sub-pruner "catches up" by deleting versions 9,500,000-9,549,999
8. Result: Permanent data loss for 50,000 versions

## Impact Explanation

**Severity: MEDIUM**

This qualifies as **"State inconsistencies requiring manual intervention"** under the Aptos bug bounty program's Medium severity category:

- **Permanent Data Loss**: Critical ledger data (transactions, events, transaction info, write sets) is irreversibly deleted from the affected node for potentially tens of thousands of versions
- **Historical Query Failures**: The node cannot serve API queries for the deleted version range, breaking historical query guarantees
- **Node-Level Inconsistency**: Creates data gaps on the affected node, though does not impact network-wide consensus
- **Recovery Requirement**: Affected nodes must re-sync from genesis or restore from backup, requiring manual operator intervention
- **No Consensus Impact**: Does not affect agreement on new blocks or network liveness

The gap between checkpoint boundaries can range from thousands to hundreds of thousands of versions depending on checkpoint frequency configuration, making the data loss substantial.

## Likelihood Explanation

**Likelihood: MEDIUM**

This vulnerability can be triggered through legitimate operational scenarios:

1. **Database Migration**: Migrating from database versions that predate the `LedgerPrunerProgress` feature
2. **Selective Backup/Restore**: Backup procedures that don't consistently preserve all metadata keys
3. **Fast Sync Edge Cases**: Scenarios where `finalize_state_snapshot` doesn't properly initialize pruner progress via `save_min_readable_version`: [6](#0-5) 
4. **Metadata Corruption**: Database corruption specifically affecting the metadata column family
5. **Manual Operations**: Operators performing database maintenance may inadvertently affect metadata keys

The developer's explicit comment acknowledging uncertainty confirms this is a recognized edge case without confident validation of prevention mechanisms.

## Recommendation

1. **Validate Initialization Source**: Instead of blindly using the first `VersionDataSchema` entry, validate it against sub-pruner progress keys. The metadata progress should be the minimum of all sub-pruner progress values:

```rust
pub(in crate::pruner) fn new(ledger_metadata_db: Arc<DB>) -> Result<Self> {
    if let Some(v) = ledger_metadata_db.get::<DbMetadataSchema>(&DbMetadataKey::LedgerPrunerProgress)? {
        v.expect_version();
    } else {
        // Query all sub-pruner progress keys
        let event_progress = ledger_metadata_db.get::<DbMetadataSchema>(&DbMetadataKey::EventPrunerProgress)?
            .map(|v| v.expect_version());
        let transaction_progress = ledger_metadata_db.get::<DbMetadataSchema>(&DbMetadataKey::TransactionPrunerProgress)?
            .map(|v| v.expect_version());
        // ... check all sub-pruner progress keys
        
        // Use minimum of all found progress values, or fallback to VersionDataSchema
        let min_subpruner_progress = [event_progress, transaction_progress, /* ... */]
            .iter()
            .filter_map(|&p| p)
            .min();
            
        let version = if let Some(min_progress) = min_subpruner_progress {
            min_progress
        } else {
            // Only use VersionDataSchema as last resort when no sub-pruner progress exists
            let mut iter = ledger_metadata_db.iter::<VersionDataSchema>()?;
            iter.seek_to_first();
            match iter.next().transpose()? {
                Some((version, _)) => version,
                None => 0,
            }
        };
        
        ledger_metadata_db.put::<DbMetadataSchema>(
            &DbMetadataKey::LedgerPrunerProgress,
            &DbMetadataValue::Version(version),
        )?;
    }
    
    Ok(LedgerMetadataPruner { ledger_metadata_db })
}
```

2. **Add Safety Check in Sub-Pruners**: Prevent sub-pruners from pruning ahead of their stored progress when catching up.

3. **Strengthen Fast Sync**: Ensure `finalize_state_snapshot` always writes `LedgerPrunerProgress` atomically with sub-pruner progress.

4. **Add Validation Logging**: Log warnings when fallback initialization is triggered to alert operators.

## Proof of Concept

```rust
#[test]
fn test_incorrect_ledger_pruner_progress_initialization() {
    use tempfile::TempDir;
    
    // Setup: Create database with pruned state
    let tmpdir = TempDir::new().unwrap();
    let db = Arc::new(DB::open(
        tmpdir.path(),
        "test_db",
        &DbOptions::default(),
        &[DbColumnFamilyName::Default]
    ).unwrap());
    
    // Simulate previous pruning state:
    // - Actual pruning stopped at version 9,500,000
    // - Sub-pruner progress correctly at 9,500,000
    // - VersionData only exists at checkpoints (every 50,000 versions)
    // - First remaining VersionData at 9,550,000 (checkpoint after pruning)
    
    db.put::<DbMetadataSchema>(
        &DbMetadataKey::EventPrunerProgress,
        &DbMetadataValue::Version(9_500_000)
    ).unwrap();
    
    db.put::<VersionDataSchema>(
        &9_550_000,
        &StateStorageUsage::new(1000, 500000)
    ).unwrap();
    
    // Simulate LedgerPrunerProgress missing (migration/corruption scenario)
    // Don't write LedgerPrunerProgress
    
    // Trigger vulnerability: Initialize LedgerMetadataPruner
    let pruner = LedgerMetadataPruner::new(db.clone()).unwrap();
    let metadata_progress = pruner.progress().unwrap();
    
    // BUG: metadata_progress is 9,550,000 (from checkpoint)
    // but should be 9,500,000 (actual pruning progress)
    assert_eq!(metadata_progress, 9_550_000);
    
    // Now sub-pruner would "catch up" by deleting 50,000 versions
    // that were never meant to be pruned
    let event_progress = db.get::<DbMetadataSchema>(&DbMetadataKey::EventPrunerProgress)
        .unwrap()
        .unwrap()
        .expect_version();
    assert_eq!(event_progress, 9_500_000);
    
    // Gap of 50,000 versions would be incorrectly deleted
    let gap = metadata_progress - event_progress;
    assert_eq!(gap, 50_000);
    
    println!("Vulnerability confirmed: {} versions would be incorrectly deleted", gap);
}
```

## Notes

This vulnerability represents a genuine data integrity issue in the Aptos storage layer. While it does not compromise network consensus or enable fund theft, it creates operational risks through unintended data deletion requiring manual intervention. The developer comment acknowledging uncertainty about `LedgerPrunerProgress` presence confirms this is a known edge case without robust handling. The fix should prioritize using existing sub-pruner progress values as the source of truth rather than relying on checkpoint boundaries which may not accurately reflect actual pruning state.

### Citations

**File:** storage/aptosdb/src/pruner/ledger_pruner/ledger_metadata_pruner.rs (L24-36)
```rust
        } else {
            // NOTE: I **think** all db should have the LedgerPrunerProgress. Have a fallback path
            // here in case the database was super old before we introducing this progress counter.
            let mut iter = ledger_metadata_db.iter::<VersionDataSchema>()?;
            iter.seek_to_first();
            let version = match iter.next().transpose()? {
                Some((version, _)) => version,
                None => 0,
            };
            ledger_metadata_db.put::<DbMetadataSchema>(
                &DbMetadataKey::LedgerPrunerProgress,
                &DbMetadataValue::Version(version),
            )?;
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/ledger_metadata_pruner.rs (L42-56)
```rust
    pub(in crate::pruner) fn prune(
        &self,
        current_progress: Version,
        target_version: Version,
    ) -> Result<()> {
        let mut batch = SchemaBatch::new();
        for version in current_progress..target_version {
            batch.delete::<VersionDataSchema>(&version)?;
        }
        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::LedgerPrunerProgress,
            &DbMetadataValue::Version(target_version),
        )?;
        self.ledger_metadata_db.write_schemas(batch)
    }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L881-888)
```rust
            if latest_state.last_checkpoint().next_version() > current_state.next_version() {
                // has a checkpoint in the chunk
                Self::put_usage(latest_state.last_checkpoint(), batch)?;
            }
            if !latest_state.is_checkpoint() {
                // latest state isn't a checkpoint
                Self::put_usage(latest_state, batch)?;
            }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/mod.rs (L124-142)
```rust
        let ledger_metadata_pruner = Box::new(
            LedgerMetadataPruner::new(ledger_db.metadata_db_arc())
                .expect("Failed to initialize ledger_metadata_pruner."),
        );

        let metadata_progress = ledger_metadata_pruner.progress()?;

        info!(
            metadata_progress = metadata_progress,
            "Created ledger metadata pruner, start catching up all sub pruners."
        );

        let transaction_store = Arc::new(TransactionStore::new(Arc::clone(&ledger_db)));

        let event_store_pruner = Box::new(EventStorePruner::new(
            Arc::clone(&ledger_db),
            metadata_progress,
            internal_indexer_db.clone(),
        )?);
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/event_store_pruner.rs (L85-109)
```rust
    pub(in crate::pruner) fn new(
        ledger_db: Arc<LedgerDb>,
        metadata_progress: Version,
        internal_indexer_db: Option<InternalIndexerDB>,
    ) -> Result<Self> {
        let progress = get_or_initialize_subpruner_progress(
            ledger_db.event_db_raw(),
            &DbMetadataKey::EventPrunerProgress,
            metadata_progress,
        )?;

        let myself = EventStorePruner {
            ledger_db,
            internal_indexer_db,
        };

        info!(
            progress = progress,
            metadata_progress = metadata_progress,
            "Catching up EventStorePruner."
        );
        myself.prune(progress, metadata_progress)?;

        Ok(myself)
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L225-234)
```rust
            self.ledger_pruner.save_min_readable_version(version)?;
            self.state_store
                .state_merkle_pruner
                .save_min_readable_version(version)?;
            self.state_store
                .epoch_snapshot_pruner
                .save_min_readable_version(version)?;
            self.state_store
                .state_kv_pruner
                .save_min_readable_version(version)?;
```

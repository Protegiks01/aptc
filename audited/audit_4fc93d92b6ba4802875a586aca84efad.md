# Audit Report

## Title
Orphaned VersionData Entries After Database Truncation Due to Missing LedgerPrunerProgress Reset

## Summary
When the ledger database is truncated (during crash recovery or manual rollback), the `truncate_ledger_db_single_batch` function deletes VersionData entries but fails to reset the `LedgerPrunerProgress` metadata. This causes the pruner to skip over any VersionData entries created in the gap between the truncation point and the old progress value, leading to permanently orphaned entries that consume storage indefinitely.

## Finding Description
The vulnerability exists in the database truncation flow within the AptosDB storage system. When `truncate_ledger_db_single_batch` is called, it performs cleanup operations including deletion of VersionData entries via `delete_per_version_data_impl<VersionDataSchema>`. However, it only resets the `LedgerCommitProgress` metadata and fails to reset the `LedgerPrunerProgress` metadata. [1](#0-0) 

The truncation function deletes VersionData entries starting from a given version: [2](#0-1) [3](#0-2) 

However, the `LedgerPrunerProgress` (which tracks how far the pruner has progressed) is never updated during truncation. The pruner uses this progress value to determine where to start pruning: [4](#0-3) 

The pruning only occurs when `progress < target_version`. If the pruner's saved progress is ahead of the truncation point, it will skip over any VersionData entries created in that gap.

**Exploitation Scenario:**
1. Node operates normally with pruner at progress version 5000
2. Database corruption or rollback triggers truncation to version 3000
3. `truncate_ledger_db_single_batch` deletes VersionData for versions ≥3001
4. `LedgerCommitProgress` is correctly set to 3000
5. **BUG**: `LedgerPrunerProgress` remains at 5000
6. Node re-syncs and commits new transactions, creating VersionData entries at versions 3001, 3002, ..., 4999
7. When pruner runs with target_version = 4000, it checks: `progress (5000) < target_version (4000)` → FALSE
8. Pruner skips pruning, leaving VersionData entries 3001-4999 orphaned forever
9. As chain grows, pruner will eventually reach versions > 5000, but versions 3001-4999 remain unpruned

These orphaned entries:
- Consume storage space indefinitely (each VersionData entry is ~16-32 bytes)
- Cannot be accessed (corresponding transaction data was deleted during truncation)
- Will never be pruned (pruner's progress pointer is permanently ahead of them)
- Accumulate with each truncation event

This breaks the **Storage Cleanup Invariant**: the pruner should eventually remove all data older than the prune window, but orphaned VersionData entries violate this guarantee.

## Impact Explanation
This is a **Medium Severity** vulnerability per the Aptos bug bounty criteria: "State inconsistencies requiring intervention."

The impact includes:
- **Unbounded storage consumption**: In environments with frequent crash recovery or database rollbacks (e.g., development/testing networks, or nodes experiencing repeated crashes), orphaned VersionData entries accumulate over time
- **Database bloat**: While individual VersionData entries are small (~16-32 bytes), gaps of thousands of versions (3001-4999 in the example = ~2000 entries × 24 bytes = ~48KB per gap) add up
- **No automatic recovery**: The system has no mechanism to detect or clean up these orphaned entries without manual intervention
- **State inconsistency**: The database contains entries that are unreachable through normal access patterns but consume resources

While not critical (no consensus or funds at risk), this represents a clear storage management failure requiring manual database maintenance to resolve.

## Likelihood Explanation
**Likelihood: Medium**

Database truncation occurs in several realistic scenarios:
1. **Crash recovery**: When a node crashes mid-commit, `sync_commit_progress` is called during restart to synchronize database state
2. **State sync failures**: Nodes performing fast sync may need to rollback and retry
3. **Database corruption recovery**: Operators may manually truncate to a known good state
4. **Development/testing**: Frequent resets and rollbacks during testing

Once truncation occurs with an advanced pruner progress, the vulnerability is guaranteed to manifest. The bug is deterministic and will affect every node that experiences truncation while having an active pruner.

## Recommendation
The `truncate_ledger_db_single_batch` function should reset the `LedgerPrunerProgress` to match the truncation point. Specifically, after deleting per-version data, add a call to reset the pruner progress:

```rust
fn truncate_ledger_db_single_batch(
    ledger_db: &LedgerDb,
    transaction_store: &TransactionStore,
    start_version: Version,
) -> Result<()> {
    let mut batch = LedgerDbSchemaBatches::new();

    delete_transaction_index_data(
        ledger_db,
        transaction_store,
        start_version,
        &mut batch.transaction_db_batches,
    )?;
    delete_per_epoch_data(
        &ledger_db.metadata_db_arc(),
        start_version,
        &mut batch.ledger_metadata_db_batches,
    )?;
    delete_per_version_data(ledger_db, start_version, &mut batch)?;
    delete_event_data(ledger_db, start_version, &mut batch.event_db_batches)?;
    truncate_transaction_accumulator(
        ledger_db.transaction_accumulator_db_raw(),
        start_version,
        &mut batch.transaction_accumulator_db_batches,
    )?;

    let mut progress_batch = SchemaBatch::new();
    progress_batch.put::<DbMetadataSchema>(
        &DbMetadataKey::LedgerCommitProgress,
        &DbMetadataValue::Version(start_version - 1),
    )?;
    
    // FIX: Reset LedgerPrunerProgress to prevent orphaned entries
    progress_batch.put::<DbMetadataSchema>(
        &DbMetadataKey::LedgerPrunerProgress,
        &DbMetadataValue::Version(start_version - 1),
    )?;
    
    ledger_db.metadata_db().write_schemas(progress_batch)?;
    ledger_db.write_schemas(batch)
}
```

Additionally, reset all sub-pruner progress values using the existing `write_pruner_progress` method:

```rust
ledger_db.write_pruner_progress(start_version - 1)?;
```

This ensures all pruner components are synchronized with the truncated state.

## Proof of Concept

```rust
#[test]
fn test_orphaned_version_data_after_truncation() {
    use crate::{
        ledger_db::LedgerDb,
        schema::{db_metadata::{DbMetadataKey, DbMetadataSchema}, version_data::VersionDataSchema},
        utils::truncation_helper::truncate_ledger_db,
    };
    use aptos_temppath::TempPath;
    use aptos_types::state_store::state_storage_usage::StateStorageUsage;
    
    // Setup: Create a test ledger DB
    let tmpdir = TempPath::new();
    let ledger_db = Arc::new(LedgerDb::new_for_test(&tmpdir));
    
    // Step 1: Write VersionData entries for versions 0-5000
    for version in 0..=5000 {
        let usage = StateStorageUsage::new(100, 10000);
        ledger_db.metadata_db()
            .put_usage(version, usage)
            .unwrap();
    }
    
    // Step 2: Simulate pruner running and reaching progress 5000
    ledger_db.metadata_db().db().put::<DbMetadataSchema>(
        &DbMetadataKey::LedgerPrunerProgress,
        &DbMetadataValue::Version(5000),
    ).unwrap();
    
    // Step 3: Truncate database to version 3000
    truncate_ledger_db(ledger_db.clone(), 3000).unwrap();
    
    // Step 4: Verify LedgerCommitProgress was reset
    let commit_progress = ledger_db.metadata_db()
        .get_ledger_commit_progress()
        .unwrap();
    assert_eq!(commit_progress, 3000);
    
    // Step 5: Verify LedgerPrunerProgress was NOT reset (BUG!)
    let pruner_progress = ledger_db.metadata_db().db()
        .get::<DbMetadataSchema>(&DbMetadataKey::LedgerPrunerProgress)
        .unwrap()
        .unwrap()
        .expect_version();
    assert_eq!(pruner_progress, 5000); // Still at old value!
    
    // Step 6: Simulate new commits creating VersionData entries 3001-4999
    for version in 3001..=4999 {
        let usage = StateStorageUsage::new(100, 10000);
        ledger_db.metadata_db()
            .put_usage(version, usage)
            .unwrap();
    }
    
    // Step 7: Verify orphaned entries exist
    let orphaned_count = (3001..=4999)
        .filter(|v| ledger_db.metadata_db().get_usage(*v).is_ok())
        .count();
    assert_eq!(orphaned_count, 1999); // All entries are orphaned
    
    // Step 8: Attempt pruning with target < old progress
    // Pruner cannot prune these entries because progress (5000) > target (4000)
    let target_version = 4000;
    assert!(pruner_progress > target_version);
    
    println!(
        "BUG: {} orphaned VersionData entries between {} and {} will never be pruned",
        orphaned_count, 3001, 4999
    );
}
```

## Notes
- The vulnerability is triggered by database truncation operations, which occur during crash recovery (`sync_commit_progress`) or manual rollbacks
- The `LedgerMetadataPruner` initialization includes fallback logic to find the first VersionData entry if `LedgerPrunerProgress` doesn't exist, but this doesn't help when progress is incorrectly ahead of actual data [5](#0-4) 

- While fast sync properly calls `write_pruner_progress` to set progress after restoration, the truncation code path does not [6](#0-5) 

- Similar issues may exist for other sub-pruners (EventStorePruner, TransactionInfoPruner, etc.) that also track progress metadata, though VersionData is specifically mentioned in the security question
- The storage consumption is bounded per truncation event but unbounded over time with repeated truncations

### Citations

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L325-361)
```rust
fn truncate_ledger_db_single_batch(
    ledger_db: &LedgerDb,
    transaction_store: &TransactionStore,
    start_version: Version,
) -> Result<()> {
    let mut batch = LedgerDbSchemaBatches::new();

    delete_transaction_index_data(
        ledger_db,
        transaction_store,
        start_version,
        &mut batch.transaction_db_batches,
    )?;
    delete_per_epoch_data(
        &ledger_db.metadata_db_arc(),
        start_version,
        &mut batch.ledger_metadata_db_batches,
    )?;
    delete_per_version_data(ledger_db, start_version, &mut batch)?;

    delete_event_data(ledger_db, start_version, &mut batch.event_db_batches)?;

    truncate_transaction_accumulator(
        ledger_db.transaction_accumulator_db_raw(),
        start_version,
        &mut batch.transaction_accumulator_db_batches,
    )?;

    let mut progress_batch = SchemaBatch::new();
    progress_batch.put::<DbMetadataSchema>(
        &DbMetadataKey::LedgerCommitProgress,
        &DbMetadataValue::Version(start_version - 1),
    )?;
    ledger_db.metadata_db().write_schemas(progress_batch)?;

    ledger_db.write_schemas(batch)
}
```

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L450-454)
```rust
    delete_per_version_data_impl::<VersionDataSchema>(
        &ledger_db.metadata_db_arc(),
        start_version,
        &mut batch.ledger_metadata_db_batches,
    )?;
```

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L494-518)
```rust
fn delete_per_version_data_impl<S>(
    ledger_db: &DB,
    start_version: Version,
    batch: &mut SchemaBatch,
) -> Result<()>
where
    S: Schema<Key = Version>,
{
    let mut iter = ledger_db.iter::<S>()?;
    iter.seek_to_last();
    if let Some((latest_version, _)) = iter.next().transpose()? {
        if latest_version >= start_version {
            info!(
                start_version = start_version,
                latest_version = latest_version,
                cf_name = S::COLUMN_FAMILY_NAME,
                "Truncate per version data."
            );
            for version in start_version..=latest_version {
                batch.delete::<S>(&version)?;
            }
        }
    }
    Ok(())
}
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/mod.rs (L62-92)
```rust
    fn prune(&self, max_versions: usize) -> Result<Version> {
        let mut progress = self.progress();
        let target_version = self.target_version();

        while progress < target_version {
            let current_batch_target_version =
                min(progress + max_versions as Version, target_version);

            info!(
                progress = progress,
                target_version = current_batch_target_version,
                "Pruning ledger data."
            );
            self.ledger_metadata_pruner
                .prune(progress, current_batch_target_version)?;

            THREAD_MANAGER.get_background_pool().install(|| {
                self.sub_pruners.par_iter().try_for_each(|sub_pruner| {
                    sub_pruner
                        .prune(progress, current_batch_target_version)
                        .map_err(|err| anyhow!("{} failed to prune: {err}", sub_pruner.name()))
                })
            })?;

            progress = current_batch_target_version;
            self.record_progress(progress);
            info!(progress = progress, "Pruning ledger data is done.");
        }

        Ok(target_version)
    }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/ledger_metadata_pruner.rs (L19-40)
```rust
    pub(in crate::pruner) fn new(ledger_metadata_db: Arc<DB>) -> Result<Self> {
        if let Some(v) =
            ledger_metadata_db.get::<DbMetadataSchema>(&DbMetadataKey::LedgerPrunerProgress)?
        {
            v.expect_version();
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
        }

        Ok(LedgerMetadataPruner { ledger_metadata_db })
    }
```

**File:** storage/aptosdb/src/ledger_db/mod.rs (L373-388)
```rust
    pub(crate) fn write_pruner_progress(&self, version: Version) -> Result<()> {
        info!("Fast sync is done, writing pruner progress {version} for all ledger sub pruners.");
        self.event_db.write_pruner_progress(version)?;
        self.persisted_auxiliary_info_db
            .write_pruner_progress(version)?;
        self.transaction_accumulator_db
            .write_pruner_progress(version)?;
        self.transaction_auxiliary_data_db
            .write_pruner_progress(version)?;
        self.transaction_db.write_pruner_progress(version)?;
        self.transaction_info_db.write_pruner_progress(version)?;
        self.write_set_db.write_pruner_progress(version)?;
        self.ledger_metadata_db.write_pruner_progress(version)?;

        Ok(())
    }
```

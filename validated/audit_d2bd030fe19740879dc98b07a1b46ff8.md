# Audit Report

## Title
Incorrect LedgerPrunerProgress Initialization Causes Unintended Data Deletion During Sub-Pruner Catch-Up

## Summary
When `LedgerPrunerProgress` metadata is missing from the database, the fallback initialization logic incorrectly sets it to the first available `VersionData` checkpoint version. Since `VersionData` entries below the actual pruning progress have been deleted by previous pruning operations, this results in an artificially inflated progress value. Sub-pruners then "catch up" to this incorrect value by deleting legitimate ledger data that was never intended to be pruned, causing permanent data loss on the affected node.

## Finding Description

The vulnerability manifests during node initialization when the `LedgerPrunerProgress` metadata key is absent from the database. The fallback initialization logic seeks to the first entry in `VersionDataSchema` to initialize the progress counter: [1](#0-0) 

The developer comment at line 25 explicitly acknowledges uncertainty, stating "I **think** all db should have the LedgerPrunerProgress," indicating this is a recognized edge case without confident validation.

The critical issue is that `VersionData` is only written at checkpoint boundaries, not for every version. The state store selectively writes usage statistics: [2](#0-1) 

After previous pruning operations, `VersionData` entries below the actual pruning progress are deleted: [3](#0-2) 

When `LedgerPruner` initializes, it retrieves this incorrectly high `metadata_progress` and passes it to all sub-pruners: [4](#0-3) 

Each sub-pruner then executes a "catch up" operation. For example, EventStorePruner initializes and catches up: [5](#0-4) 

The sub-pruner retrieves its correctly stored progress (e.g., 9,500,000) via `get_or_initialize_subpruner_progress` but receives the incorrectly inflated `metadata_progress` (e.g., 9,550,000 from the first checkpoint). Line 106 calls `prune(progress, metadata_progress)`, which deletes data from versions 9,500,000 to 9,549,999—data that was never meant to be pruned.

**Root Cause - Non-Atomic Progress Writes:**

A critical finding is that progress keys are written sequentially, not atomically, during fast sync finalization: [6](#0-5) 

The `LedgerPrunerProgress` is written LAST (line 385). If the process crashes or is killed after writing sub-pruner progress keys but before writing `LedgerPrunerProgress`, the node will restart with missing `LedgerPrunerProgress` while sub-pruner progress keys remain at their correct values, triggering the vulnerability.

## Impact Explanation

**Severity: MEDIUM**

This qualifies as **"State inconsistencies requiring manual intervention"** under the Aptos bug bounty program's Medium severity category:

- **Permanent Data Loss**: Critical ledger data (transactions, events, transaction info, write sets) is irreversibly deleted from the affected node for potentially tens of thousands of versions between checkpoint boundaries
- **Historical Query Failures**: The node cannot serve API queries for the deleted version range, breaking historical query guarantees
- **Node-Level Inconsistency**: Creates data gaps on the affected node, though does not impact network-wide consensus or block production
- **Recovery Requirement**: Affected nodes must re-sync from genesis or restore from backup, requiring manual operator intervention
- **No Consensus Impact**: Does not affect agreement on new blocks, network liveness, or validator consensus

The gap between checkpoint boundaries can range from thousands to hundreds of thousands of versions depending on checkpoint frequency configuration, making the data loss substantial for affected nodes.

## Likelihood Explanation

**Likelihood: MEDIUM**

This vulnerability can be triggered through realistic operational scenarios:

1. **Process Interruption During Fast Sync**: The non-atomic progress write sequence means that if a node crashes or is killed during `finalize_state_snapshot` after writing some sub-pruner progress keys but before writing `LedgerPrunerProgress`, the vulnerability triggers on restart

2. **Selective Backup/Restore**: Backup procedures that capture database state at different points in time may preserve sub-pruner progress keys but not `LedgerPrunerProgress` if backups are taken during the progress write sequence

3. **Database Migration**: Migrating from database versions that predate the `LedgerPrunerProgress` feature while retaining sub-pruner progress keys

4. **Metadata Corruption**: Database corruption specifically affecting the metadata column family could selectively impact `LedgerPrunerProgress`

5. **Manual Operations**: Operators performing database maintenance may inadvertently affect metadata keys

The developer's explicit comment acknowledging uncertainty confirms this is a recognized edge case. The non-atomic write sequence in `write_pruner_progress` makes process interruption a realistic trigger mechanism.

## Recommendation

Implement atomic progress initialization to prevent partial metadata state:

1. **Atomic Progress Writes**: Wrap all progress key writes in a single atomic batch operation during `finalize_state_snapshot` to ensure all-or-nothing semantics

2. **Consistent Fallback Logic**: If `LedgerPrunerProgress` is missing during initialization, initialize it to the minimum of all sub-pruner progress keys rather than seeking the first `VersionData` entry:

```rust
pub(in crate::pruner) fn new(ledger_metadata_db: Arc<DB>) -> Result<Self> {
    if let Some(v) = ledger_metadata_db.get::<DbMetadataSchema>(&DbMetadataKey::LedgerPrunerProgress)? {
        v.expect_version();
    } else {
        // If LedgerPrunerProgress is missing, initialize to min of all sub-pruner progress
        // rather than seeking first VersionData to avoid data loss
        let version = 0; // Or determine min from sub-pruner progress keys
        ledger_metadata_db.put::<DbMetadataSchema>(
            &DbMetadataKey::LedgerPrunerProgress,
            &DbMetadataValue::Version(version),
        )?;
    }
    Ok(LedgerMetadataPruner { ledger_metadata_db })
}
```

3. **Validation Check**: Add assertion during sub-pruner initialization to verify that `metadata_progress` is never greater than the sub-pruner's stored progress, failing fast rather than deleting data

4. **Progress Key Validation**: Add consistency checks during initialization to detect and handle partial metadata state

## Proof of Concept

The vulnerability can be demonstrated through the following scenario:

1. Start a node and let it prune to version 9,500,000 with checkpoint interval of 50,000 versions
2. All progress keys correctly stored at 9,500,000
3. Trigger fast sync and interrupt the process after sub-pruner progress writes but before `LedgerPrunerProgress` write (line 385 of `write_pruner_progress`)
4. Verify that sub-pruner progress keys exist at 9,500,000 but `LedgerPrunerProgress` is missing
5. Restart the node
6. Observe `LedgerMetadataPruner::new()` initializing to first `VersionData` at 9,550,000
7. Observe each sub-pruner calling `prune(9500000, 9550000)` during initialization
8. Verify data loss for versions 9,500,000-9,549,999

While a complete PoC requires orchestrating process interruption during specific database write sequences, the code paths and logic are clearly defined in the cited source files, demonstrating that the vulnerability is technically feasible and can occur during normal operational failures.

## Notes

This vulnerability represents an architectural flaw in the pruner initialization and progress tracking system. The use of sequential, non-atomic writes for critical metadata combined with fallback logic that doesn't account for partial state creates a data loss scenario during operational failures. The developer comment acknowledging uncertainty about the presence of `LedgerPrunerProgress` indicates awareness of the edge case but insufficient protection against it. This issue affects node availability and data integrity but does not impact consensus or network-wide state.

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

**File:** storage/aptosdb/src/pruner/ledger_pruner/ledger_metadata_pruner.rs (L48-49)
```rust
        for version in current_progress..target_version {
            batch.delete::<VersionDataSchema>(&version)?;
```

**File:** storage/aptosdb/src/state_store/mod.rs (L881-887)
```rust
            if latest_state.last_checkpoint().next_version() > current_state.next_version() {
                // has a checkpoint in the chunk
                Self::put_usage(latest_state.last_checkpoint(), batch)?;
            }
            if !latest_state.is_checkpoint() {
                // latest state isn't a checkpoint
                Self::put_usage(latest_state, batch)?;
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/mod.rs (L129-170)
```rust
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
        let persisted_auxiliary_info_pruner = Box::new(PersistedAuxiliaryInfoPruner::new(
            Arc::clone(&ledger_db),
            metadata_progress,
        )?);
        let transaction_accumulator_pruner = Box::new(TransactionAccumulatorPruner::new(
            Arc::clone(&ledger_db),
            metadata_progress,
        )?);

        let transaction_auxiliary_data_pruner = Box::new(TransactionAuxiliaryDataPruner::new(
            Arc::clone(&ledger_db),
            metadata_progress,
        )?);

        let transaction_info_pruner = Box::new(TransactionInfoPruner::new(
            Arc::clone(&ledger_db),
            metadata_progress,
        )?);
        let transaction_pruner = Box::new(TransactionPruner::new(
            Arc::clone(&transaction_store),
            Arc::clone(&ledger_db),
            metadata_progress,
            internal_indexer_db,
        )?);
        let write_set_pruner = Box::new(WriteSetPruner::new(
            Arc::clone(&ledger_db),
            metadata_progress,
        )?);
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/event_store_pruner.rs (L90-106)
```rust
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

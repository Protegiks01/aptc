# Audit Report

## Title
Incorrect LedgerPrunerProgress Initialization Causes Unintended Data Deletion During Sub-Pruner Catch-Up

## Summary
When `LedgerPrunerProgress` is missing from the database, the fallback initialization logic in `LedgerMetadataPruner::new()` initializes it to the first available `VersionData` entry. Since previous pruning operations delete old `VersionData` entries, this first entry can be at a version significantly higher than the actual pruning progress. Sub-pruners then incorrectly "catch up" by deleting legitimate ledger data between their stored progress and the incorrectly initialized metadata progress, causing permanent data loss.

## Finding Description

The vulnerability occurs when `LedgerPrunerProgress` is absent from the database metadata. The fallback logic seeks to the first entry in `VersionDataSchema` to initialize the progress counter. [1](#0-0) 

The developer comment explicitly acknowledges uncertainty about whether all databases have this key, implementing a fallback path for "super old" databases. [2](#0-1) 

After previous pruning operations have deleted old `VersionData` entries [3](#0-2) , the first remaining entry may be at a version significantly higher than where pruning actually left off. 

When the `LedgerPruner` initializes, it retrieves this `metadata_progress` and passes it to all sub-pruners during their construction. [4](#0-3) 

Each sub-pruner attempts to "catch up" by pruning from its stored progress to the metadata progress. The `EventStorePruner` demonstrates this pattern: [5](#0-4) 

The same catch-up pattern is used by all sub-pruners including `TransactionInfoPruner`: [6](#0-5) 

The `get_or_initialize_subpruner_progress` function returns the existing sub-pruner progress if present, but the catch-up call still uses the incorrectly high `metadata_progress` as the target. [7](#0-6) 

**Critical Factor: Sparse VersionData Entries**

The vulnerability is exacerbated because `VersionDataSchema` entries are NOT written for every version. They are only written at checkpoints and for the latest committed state. [8](#0-7) 

This means gaps between `VersionData` entries can be substantial, potentially tens of thousands of versions in production scenarios.

**Different Physical Databases**

The progress keys are stored in different physical databases, allowing them to get out of sync during backup/restore or migration operations. The `LedgerPrunerProgress` is stored in the ledger metadata database [9](#0-8) , while sub-pruner progress keys are stored in their respective databases [10](#0-9) .

**Exploitation Scenario:**
1. Database at version 10,000,000, previously pruned up to version 9,500,000
2. All sub-pruner progress keys correctly at 9,500,000 (EventPrunerProgress, TransactionPrunerProgress, etc.)
3. `LedgerPrunerProgress` is lost due to selective backup/restore, migration bug, or metadata corruption
4. `VersionData` entries below 9,500,000 were already deleted during previous pruning
5. First remaining `VersionData` entry is at version 9,550,000 (due to checkpoint-based writing)
6. On node restart:
   - `LedgerMetadataPruner` initializes `LedgerPrunerProgress` to 9,550,000 (incorrect)
   - `EventStorePruner` reads its progress as 9,500,000 but receives metadata_progress of 9,550,000
   - Calls `prune(9_500_000, 9_550_000)` to "catch up"
   - Deletes events from versions 9,500,000 to 9,549,999
7. All sub-pruners repeat this deletion for their respective data (transactions, write sets, transaction info, etc.)

This violates the **State Consistency** invariant by creating permanent gaps in the ledger history where data should exist but has been incorrectly deleted.

## Impact Explanation

**Severity: HIGH**

This qualifies as "State inconsistencies requiring intervention" with significant data loss impact under the Aptos bug bounty program:

- **Permanent Data Loss**: Critical ledger data (transactions, events, transaction info, write sets, auxiliary data) is irreversibly deleted from potentially tens of thousands of versions. The pruning operations permanently remove data from the database with no recovery mechanism.

- **Historical Query Failures**: The node cannot serve queries for the deleted version range, breaking API contracts and causing failures for any client attempting to retrieve historical data in the affected range.

- **Ledger Inconsistencies**: Creates divergence between nodes that experienced the bug and those that didn't, potentially causing issues with state synchronization and historical proof verification.

- **Recovery Cost**: Affected nodes must re-sync from genesis or restore from backup to recover the deleted data, causing significant operational disruption and potential data availability issues for the network.

The gap between sparse `VersionData` entries can be substantial (checkpoint intervals), potentially causing deletion of tens of thousands of versions in realistic production scenarios.

## Likelihood Explanation

**Likelihood: MEDIUM**

This vulnerability can be triggered by legitimate operational scenarios that don't require malicious intent:

1. **Database Migration**: When migrating from old database versions that predate the `LedgerPrunerProgress` feature (as acknowledged in the developer comment), this fallback path will be triggered.

2. **Selective Restore Operations**: Backup/restore procedures that don't preserve all metadata keys consistently, particularly if different column families or databases are restored independently or at different points in time.

3. **Metadata Corruption**: Database corruption affecting specifically the metadata column family where `LedgerPrunerProgress` is stored, while sub-pruner progress keys in other databases remain intact.

4. **Manual Database Operations**: Operators performing maintenance or debugging may inadvertently delete or fail to migrate specific metadata keys.

While the fast sync path properly saves `LedgerPrunerProgress` [11](#0-10) , the vulnerability can still be triggered through the other operational scenarios listed above.

## Recommendation

Add a safety check to prevent sub-pruners from pruning forward when their stored progress is less than the metadata progress during initialization. The initialization should only perform catch-up pruning if the sub-pruner progress was explicitly zero or missing (indicating a new database), not when it has an existing valid progress value.

**Recommended fix for `EventStorePruner::new()` and all similar sub-pruner constructors:**

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

    // Only catch up if this is a new pruner (progress was 0 or missing)
    // Do NOT catch up if we have existing progress less than metadata_progress
    // as this indicates potential metadata_progress corruption/incorrect initialization
    if progress == 0 || progress == metadata_progress {
        info!(
            progress = progress,
            metadata_progress = metadata_progress,
            "Catching up EventStorePruner."
        );
        myself.prune(progress, metadata_progress)?;
    } else if progress < metadata_progress {
        warn!(
            progress = progress,
            metadata_progress = metadata_progress,
            "Skipping catch-up pruning: sub-pruner progress exists but is less than metadata progress. This may indicate incorrect LedgerPrunerProgress initialization."
        );
    }

    Ok(myself)
}
```

Additionally, improve the fallback initialization logic in `LedgerMetadataPruner::new()` to use a safer default or validate against all sub-pruner progress values before initializing.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Creating a database with pruning enabled
2. Pruning to version X
3. Manually deleting the `LedgerPrunerProgress` key from the ledger metadata database
4. Restarting the node
5. Observing that sub-pruners delete data between their stored progress and the incorrectly initialized metadata progress

A full Rust integration test would require setting up the database state and simulating the metadata key loss, which is complex due to the internal nature of the storage layer. However, the code path is clear and deterministic based on the implementation shown in the citations above.

## Notes

This vulnerability is particularly concerning because:

1. **Silent Data Loss**: The deletion happens automatically during initialization without clear warnings that legitimate data is being removed
2. **Production Relevance**: The triggering scenarios (migration, backup/restore, corruption) are realistic operational events
3. **Permanent Impact**: Deleted data cannot be recovered without full re-sync
4. **Multiple Data Types Affected**: All sub-pruners follow the same pattern, so transactions, events, transaction info, write sets, and auxiliary data are all affected simultaneously

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

**File:** storage/aptosdb/src/pruner/ledger_pruner/transaction_info_pruner.rs (L41-54)
```rust
        let progress = get_or_initialize_subpruner_progress(
            ledger_db.transaction_info_db_raw(),
            &DbMetadataKey::TransactionInfoPrunerProgress,
            metadata_progress,
        )?;

        let myself = TransactionInfoPruner { ledger_db };

        info!(
            progress = progress,
            metadata_progress = metadata_progress,
            "Catching up TransactionInfoPruner."
        );
        myself.prune(progress, metadata_progress)?;
```

**File:** storage/aptosdb/src/pruner/pruner_utils.rs (L44-59)
```rust
pub(crate) fn get_or_initialize_subpruner_progress(
    sub_db: &DB,
    progress_key: &DbMetadataKey,
    metadata_progress: Version,
) -> Result<Version> {
    Ok(
        if let Some(v) = sub_db.get::<DbMetadataSchema>(progress_key)? {
            v.expect_version()
        } else {
            sub_db.put::<DbMetadataSchema>(
                progress_key,
                &DbMetadataValue::Version(metadata_progress),
            )?;
            metadata_progress
        },
    )
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

**File:** storage/aptosdb/src/ledger_db/ledger_metadata_db.rs (L57-62)
```rust
    pub(super) fn write_pruner_progress(&self, version: Version) -> Result<()> {
        self.db.put::<DbMetadataSchema>(
            &DbMetadataKey::LedgerPrunerProgress,
            &DbMetadataValue::Version(version),
        )
    }
```

**File:** storage/aptosdb/src/schema/db_metadata/mod.rs (L49-72)
```rust
pub enum DbMetadataKey {
    LedgerPrunerProgress,
    StateMerklePrunerProgress,
    EpochEndingStateMerklePrunerProgress,
    StateKvPrunerProgress,
    StateSnapshotKvRestoreProgress(Version),
    LedgerCommitProgress,
    StateKvCommitProgress,
    OverallCommitProgress,
    StateKvShardCommitProgress(ShardId),
    StateMerkleCommitProgress,
    StateMerkleShardCommitProgress(ShardId),
    EventPrunerProgress,
    TransactionAccumulatorPrunerProgress,
    TransactionInfoPrunerProgress,
    TransactionPrunerProgress,
    WriteSetPrunerProgress,
    StateMerkleShardPrunerProgress(ShardId),
    EpochEndingStateMerkleShardPrunerProgress(ShardId),
    StateKvShardPrunerProgress(ShardId),
    StateMerkleShardRestoreProgress(ShardId, Version),
    TransactionAuxiliaryDataPrunerProgress,
    PersistedAuxiliaryInfoPrunerProgress,
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

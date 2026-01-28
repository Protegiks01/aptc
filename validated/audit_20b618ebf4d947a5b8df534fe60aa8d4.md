# Audit Report

## Title
Incorrect LedgerPrunerProgress Initialization Causes Unintended Data Deletion During Sub-Pruner Catch-Up

## Summary
When `LedgerPrunerProgress` is missing from the database, the fallback initialization logic can set it to an incorrectly high version by using the first available `VersionData` checkpoint. This causes sub-pruners to incorrectly delete legitimate ledger data between their stored progress and the incorrectly initialized metadata progress.

## Finding Description

The vulnerability occurs in the `LedgerMetadataPruner` initialization logic. When `LedgerPrunerProgress` is absent from the database metadata, the fallback path seeks to the first entry in `VersionDataSchema` to initialize the progress counter. [1](#0-0) 

However, `VersionData` is only written at checkpoint boundaries (not every version). [2](#0-1) 

After previous pruning operations have deleted old `VersionData` entries, the first remaining entry may be at a version significantly higher than where pruning actually left off. The `LedgerPruner` then passes this incorrectly high `metadata_progress` to all sub-pruners during initialization. [3](#0-2) 

Each sub-pruner attempts to "catch up" by pruning from its stored progress to the metadata progress. [4](#0-3)  This pattern is consistent across all sub-pruners including `TransactionPruner`, `WriteSetPruner`, `TransactionInfoPruner`, etc.

**Exploitation Scenario:**
1. Database at version 10,000,000, previously pruned up to version 9,500,000
2. All sub-pruner progress keys correctly at 9,500,000 (EventPrunerProgress, TransactionPrunerProgress, etc.)
3. `LedgerPrunerProgress` is lost due to selective backup/restore, migration bug, or metadata corruption
4. `VersionData` entries below 9,500,000 were already deleted during previous pruning
5. First remaining `VersionData` checkpoint is at version 9,550,000
6. On node restart:
   - `LedgerMetadataPruner` initializes `LedgerPrunerProgress` to 9,550,000 (incorrect)
   - Each sub-pruner sees its progress is 9,500,000 but metadata_progress is 9,550,000
   - Calls `prune(9,500,000, 9,550,000)` to "catch up"
   - Deletes legitimate data from versions 9,500,000 to 9,549,999

This violates state consistency by creating permanent gaps in the ledger history where data should exist but has been incorrectly deleted.

## Impact Explanation

**Severity: HIGH**

This qualifies as "State inconsistencies requiring intervention" under the Aptos bug bounty program:

- **Permanent Data Loss**: Critical ledger data (transactions, events, transaction info, write sets, auxiliary data) is irreversibly deleted from potentially tens of thousands of versions
- **Historical Query Failures**: The node cannot serve queries for the deleted version range, breaking API contracts
- **Node Inconsistency**: Creates ledger inconsistencies between nodes that experienced the bug and those that didn't
- **Recovery Cost**: Affected nodes must re-sync from genesis or restore from backup to recover the deleted data, causing operational disruption

The gap between checkpoint versions can be substantial depending on checkpoint frequency, potentially causing deletion of hundreds of thousands of versions in worst-case scenarios.

## Likelihood Explanation

**Likelihood: MEDIUM**

This vulnerability can be triggered by legitimate operational scenarios:

1. **Database Migration**: When migrating from old database versions that predate the `LedgerPrunerProgress` feature
2. **Selective Restore Operations**: Backup/restore procedures that don't preserve all metadata keys consistently
3. **Metadata Corruption**: Database corruption affecting specifically the metadata column family
4. **Manual Database Operations**: Operators performing maintenance may inadvertently delete specific metadata keys

The developer's comment explicitly acknowledges uncertainty, indicating this is a known edge case without confident validation. [5](#0-4) 

## Recommendation

Add validation to ensure `LedgerPrunerProgress` initialization is consistent with actual pruning state:

1. **Store minimum version at database initialization**: Ensure `LedgerPrunerProgress` is always initialized to 0 or the actual minimum readable version during database creation
2. **Validate against sub-pruner progress**: When initializing from fallback, check all sub-pruner progress keys and use the minimum value instead of seeking to first `VersionData`
3. **Add safety check**: Before catch-up pruning, verify the version range contains data that should be pruned by checking for presence of corresponding data entries
4. **Explicit metadata persistence**: During `finalize_state_snapshot`, ensure `LedgerPrunerProgress` is explicitly persisted. [6](#0-5) 

## Proof of Concept

While a full executable PoC requires database manipulation, the vulnerability logic can be demonstrated through the following scenario:

```rust
// Scenario: Database state after previous pruning to version 9,500,000
// - LedgerPrunerProgress: MISSING (due to selective restore)
// - EventPrunerProgress: 9,500,000
// - TransactionPrunerProgress: 9,500,000
// - VersionData entries: First remaining at 9,550,000 (checkpoint)
// 
// On LedgerMetadataPruner::new():
// 1. Seeks to first VersionData -> finds 9,550,000
// 2. Initializes LedgerPrunerProgress to 9,550,000
//
// On EventStorePruner::new(metadata_progress=9,550,000):
// 1. Gets EventPrunerProgress: 9,500,000
// 2. Calls prune(9,500,000, 9,550,000)
// 3. Deletes events from 9,500,000 to 9,549,999 (INCORRECT)
//
// Result: 50,000 versions of legitimate data permanently deleted
```

The code paths are clearly visible in the implementation files cited above, demonstrating this is a logic vulnerability in the fallback initialization path.

### Citations

**File:** storage/aptosdb/src/pruner/ledger_pruner/ledger_metadata_pruner.rs (L25-36)
```rust
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

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L225-225)
```rust
            self.ledger_pruner.save_min_readable_version(version)?;
```

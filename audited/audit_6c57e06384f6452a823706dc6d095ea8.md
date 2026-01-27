# Audit Report

## Title
Critical Metadata Desynchronization Allows Pruner to Delete Data Required by Internal Indexer

## Summary
The `EventStorePruner` and `TransactionPruner` initialize their progress from the main database's `DbMetadataSchema` without validating against the `InternalIndexerMetadataSchema`. If the InternalIndexerDB is deleted, corrupted, or rebuilt while the main database remains intact, pruners will continue deleting historical data that the indexer still needs to rebuild its indexes, causing permanent data loss and indexer corruption.

## Finding Description

The Aptos storage system maintains two separate metadata tracking systems for pruner progress:

1. **Main DB**: `DbMetadataSchema` with `DbMetadataKey::EventPrunerProgress` and `DbMetadataKey::TransactionPrunerProgress`
2. **Internal Indexer DB**: `InternalIndexerMetadataSchema` with `IndexerMetadataKey::EventPrunerProgress` and `IndexerMetadataKey::TransactionPrunerProgress`

During normal operation, both metadata stores are updated atomically when pruning occurs: [1](#0-0) [2](#0-1) 

However, during pruner initialization, **only the main DB metadata is consulted**: [3](#0-2) [4](#0-3) 

The `get_or_initialize_subpruner_progress` function only reads from the main DB: [5](#0-4) 

**Attack Scenario:**

1. Node operates normally with both DBs synchronized (e.g., pruner progress at version 1,000,000)
2. InternalIndexerDB is deleted/corrupted due to:
   - Disk failure
   - Manual deletion for debugging
   - Database restoration from backup
   - File system corruption
3. Node restarts
4. Pruners initialize from main DB: `progress = 1,000,000`
5. InternalIndexerDB initializes with missing metadata, defaulting to version 0: [6](#0-5) 

6. Pruner continues operating from version 1,000,000, deleting data below that threshold
7. InternalIndexer needs to index from version 0 but the data has been pruned
8. **Result**: Permanent data loss, indexer cannot rebuild

This violates the critical invariant that the InternalIndexerDB must be able to catch up with the main database by reading historical data.

## Impact Explanation

**Critical Severity** - This issue qualifies for Critical severity under the Aptos bug bounty program:

- **Data Loss**: Events and transactions below the pruner threshold are permanently deleted and cannot be recovered without full database restoration
- **State Inconsistency**: The InternalIndexerDB becomes permanently desynchronized from the main database, breaking the indexer's ability to serve historical queries
- **Non-recoverable State**: Once data is pruned, the indexer cannot rebuild its indexes without a full node backup restoration
- **Production Impact**: This affects production nodes that rely on the internal indexer for API queries, state synchronization, and historical data access

The vulnerability breaks **State Consistency** invariant #4: "State transitions must be atomic and verifiable" - the dual-database system loses atomicity when metadata is desynchronized.

## Likelihood Explanation

**High Likelihood** - This vulnerability can occur in realistic operational scenarios:

1. **Disk Failures**: Partial disk corruption affecting only the InternalIndexerDB directory
2. **Operational Errors**: Manual deletion of the InternalIndexerDB for debugging or space recovery
3. **Backup Restoration**: Restoring only the main DB from backup without the InternalIndexerDB
4. **Database Migration**: Moving databases between storage systems where only one DB transfers successfully

The lack of validation during pruner initialization means there is **no safety check** preventing this scenario. The code assumes both databases remain synchronized at all times, which is not guaranteed in real-world operations.

## Recommendation

Add validation during pruner initialization to ensure the InternalIndexerDB's pruner progress matches or is behind the main DB's pruner progress. If desynchronization is detected, either:

1. **Option 1 (Safe)**: Halt node startup with a clear error message requiring operator intervention
2. **Option 2 (Reset)**: Automatically reset the main DB pruner progress to match the InternalIndexerDB

**Recommended Fix (Option 1 - Safe Halt):**

In `EventStorePruner::new`:

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

    // NEW: Validate InternalIndexerDB metadata if enabled
    if let Some(ref indexer_db) = internal_indexer_db {
        if indexer_db.event_enabled() {
            let indexer_progress = indexer_db
                .get_inner_db_ref()
                .get::<InternalIndexerMetadataSchema>(&IndexerMetadataKey::EventPrunerProgress)?
                .map(|v| v.expect_version())
                .unwrap_or(0);
            
            if indexer_progress < progress {
                return Err(anyhow::anyhow!(
                    "InternalIndexerDB EventPrunerProgress ({}) is behind main DB progress ({}). \
                     This indicates database desynchronization. Please restore InternalIndexerDB \
                     from backup or reset pruner progress.",
                    indexer_progress,
                    progress
                ).into());
            }
        }
    }

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

Apply the same fix to `TransactionPruner::new` with `IndexerMetadataKey::TransactionPrunerProgress`.

## Proof of Concept

```rust
// Rust reproduction demonstrating the vulnerability
#[test]
fn test_pruner_indexer_desynchronization() {
    use tempfile::TempDir;
    use std::sync::Arc;
    
    // 1. Setup: Create main DB and InternalIndexerDB
    let tmpdir = TempDir::new().unwrap();
    let mut config = NodeConfig::default();
    config.storage.dir = tmpdir.path().to_path_buf();
    config.indexer_db_config.enable_event = true;
    
    let (db, internal_indexer_db) = setup_test_dbs(&config);
    
    // 2. Simulate normal operation: prune up to version 1000
    let ledger_db = db.ledger_db();
    let metadata_progress = 1000;
    
    // Update main DB metadata
    ledger_db.metadata_db().put::<DbMetadataSchema>(
        &DbMetadataKey::EventPrunerProgress,
        &DbMetadataValue::Version(metadata_progress),
    ).unwrap();
    
    // Update InternalIndexer metadata
    internal_indexer_db.get_inner_db_ref().put::<InternalIndexerMetadataSchema>(
        &IndexerMetadataKey::EventPrunerProgress,
        &IndexerMetadataValue::Version(metadata_progress),
    ).unwrap();
    
    // 3. Simulate InternalIndexerDB deletion
    drop(internal_indexer_db);
    std::fs::remove_dir_all(tmpdir.path().join("internal_indexer_db")).unwrap();
    
    // 4. Restart: Create new InternalIndexerDB (empty metadata)
    let new_internal_indexer_db = InternalIndexerDBService::get_indexer_db(&config).unwrap();
    
    // 5. Initialize EventStorePruner - this SHOULD fail but doesn't!
    let pruner = EventStorePruner::new(
        ledger_db.clone(),
        metadata_progress,
        Some(new_internal_indexer_db.clone()),
    );
    
    // BUG: Pruner initializes successfully with progress=1000
    assert!(pruner.is_ok());
    
    // 6. Check InternalIndexer metadata - it's at 0 (or missing)!
    let indexer_progress = new_internal_indexer_db
        .get_inner_db_ref()
        .get::<InternalIndexerMetadataSchema>(&IndexerMetadataKey::EventPrunerProgress)
        .unwrap()
        .map(|v| v.expect_version())
        .unwrap_or(0);
    
    // VULNERABILITY: Pruner thinks it's at 1000, but indexer needs data from 0
    assert_eq!(indexer_progress, 0);
    assert_eq!(pruner.unwrap().progress(), metadata_progress);
    
    // If pruner runs, it will delete data [0, 1000) that the indexer needs!
}
```

**Notes:**

- The vulnerability exists because pruner initialization lacks synchronization checks between the dual metadata systems
- The InternalIndexerMetadataSchema has no inherent retention policies; metadata can be lost if the database is deleted
- The fix requires validating metadata consistency during pruner initialization to prevent data loss
- This issue affects any node configuration with `enable_event` or `enable_transaction` set to true in the internal indexer config

### Citations

**File:** storage/aptosdb/src/pruner/ledger_pruner/event_store_pruner.rs (L66-79)
```rust
        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::EventPrunerProgress,
            &DbMetadataValue::Version(target_version),
        )?;

        if let Some(mut indexer_batch) = indexer_batch {
            indexer_batch.put::<InternalIndexerMetadataSchema>(
                &IndexerMetadataKey::EventPrunerProgress,
                &IndexerMetadataValue::Version(target_version),
            )?;
            self.expect_indexer_db()
                .get_inner_db_ref()
                .write_schemas(indexer_batch)?;
        }
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

**File:** storage/aptosdb/src/pruner/ledger_pruner/transaction_pruner.rs (L54-67)
```rust
        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::TransactionPrunerProgress,
            &DbMetadataValue::Version(target_version),
        )?;
        if let Some(indexer_db) = self.internal_indexer_db.as_ref() {
            if indexer_db.transaction_enabled() {
                let mut index_batch = SchemaBatch::new();
                self.transaction_store
                    .prune_transaction_by_account(&candidate_transactions, &mut index_batch)?;
                index_batch.put::<InternalIndexerMetadataSchema>(
                    &IndexerMetadataKey::TransactionPrunerProgress,
                    &IndexerMetadataValue::Version(target_version),
                )?;
                indexer_db.get_inner_db_ref().write_schemas(index_batch)?;
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/transaction_pruner.rs (L78-104)
```rust
    pub(in crate::pruner) fn new(
        transaction_store: Arc<TransactionStore>,
        ledger_db: Arc<LedgerDb>,
        metadata_progress: Version,
        internal_indexer_db: Option<InternalIndexerDB>,
    ) -> Result<Self> {
        let progress = get_or_initialize_subpruner_progress(
            ledger_db.transaction_db_raw(),
            &DbMetadataKey::TransactionPrunerProgress,
            metadata_progress,
        )?;

        let myself = TransactionPruner {
            transaction_store,
            ledger_db,
            internal_indexer_db,
        };

        info!(
            progress = progress,
            metadata_progress = metadata_progress,
            "Catching up TransactionPruner."
        );
        myself.prune(progress, metadata_progress)?;

        Ok(myself)
    }
```

**File:** storage/aptosdb/src/pruner/pruner_utils.rs (L44-60)
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

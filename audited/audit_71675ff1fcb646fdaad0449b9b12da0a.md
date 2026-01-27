# Audit Report

## Title
TransactionPruner Catch-up Logic Skips Re-pruning When Progress Metadata is Ahead of Actual State

## Summary
The `TransactionPruner::new()` catch-up logic at line 101 does not re-prune data when `DbMetadataKey::TransactionPrunerProgress` is ahead of the actual pruned state. This can occur if `write_pruner_progress()` successfully updates the progress metadata but a crash prevents actual data deletion, resulting in persistent data inconsistency where transactions remain in storage despite metadata indicating they were pruned. [1](#0-0) 

## Finding Description
The vulnerability exists in the initialization and catch-up logic of the TransactionPruner. When a TransactionPruner is created, it retrieves the stored `TransactionPrunerProgress` metadata and attempts to catch up to the `metadata_progress` by calling `prune()`. [2](#0-1) 

The critical flaw occurs when the stored progress equals or exceeds the metadata progress. In this case, `get_pruning_candidate_transactions(start, end)` is called with `start == end` (or `start >= end`), which returns an empty list: [3](#0-2) 

When `start == end`, the iterator seeks to version `start` (line 117), but the loop immediately breaks at line 125 because any transaction at version >= end satisfies the condition, returning an empty candidate list. No re-pruning occurs.

The progress metadata can become ahead of actual state through `LedgerDb::write_pruner_progress()`, which directly writes progress for all sub-pruners without performing actual data deletion: [4](#0-3) 

This is called after fast sync completes: [5](#0-4) 

**Attack Scenario:**
1. After fast sync completes, `finalize_state_snapshot(version=2000)` writes ledger data atomically
2. `save_min_readable_version(2000)` is called, which invokes `write_pruner_progress(2000)`
3. `TransactionPrunerProgress = 2000` is written to the transaction database
4. System crashes before any actual pruning worker runs
5. On restart, `TransactionPruner::new()` reads progress = 2000
6. Catch-up calls `prune(2000, 2000)` which finds no candidates and returns
7. Any old transactions that should have been pruned (e.g., versions 0-1999 if they existed) remain in the database indefinitely

This breaks the **State Consistency** invariant: the database contains data that contradicts its metadata state, violating the assumption that pruner progress accurately reflects data availability.

## Impact Explanation
**Severity: Medium**

This constitutes a **state inconsistency requiring intervention** per the Medium severity criteria. The impacts include:

1. **Storage Bloat**: Nodes retain data that should be pruned, consuming more disk space than configured
2. **Query Inconsistency**: Queries for supposedly pruned transactions succeed when they should fail with "version pruned" errors
3. **Validation Bypass**: The `error_if_ledger_pruned()` check uses `min_readable_version` which would be incorrect, allowing access to data that should be inaccessible [6](#0-5) 

4. **Cross-Node Inconsistency**: Different nodes that crashed at different times could have different historical data availability, potentially causing state sync issues

While this does not directly cause consensus breaks or fund loss, it violates data integrity guarantees and could lead to operational issues requiring manual intervention to detect and repair.

## Likelihood Explanation
**Likelihood: Low-Medium**

This scenario requires specific conditions:
- Fast sync or restore operation completing
- System crash after `write_pruner_progress()` but before pruner worker processes the backlog
- Pre-existing data in the database that should be pruned

While database writes are typically atomic, the separation between writing pruner progress (line 225) and actual asynchronous pruning by the pruner worker creates a window for this inconsistency. The likelihood increases if:
- Nodes frequently crash during initialization
- Fast sync is commonly used
- Storage systems experience corruption

## Recommendation
**Fix: Validate and Re-prune During Catch-up**

Modify `TransactionPruner::new()` to detect when stored progress might be ahead and force validation/re-pruning:

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

    // Validate that progress matches actual state
    // Always attempt catch-up from 0 if progress > 0 to ensure consistency
    if progress > 0 {
        info!(
            progress = progress,
            metadata_progress = metadata_progress,
            "Validating and catching up TransactionPruner."
        );
        // Prune from beginning to ensure consistency
        // This will be a no-op if data was already pruned correctly
        myself.prune(0, progress)?;
    }
    
    if metadata_progress > progress {
        myself.prune(progress, metadata_progress)?;
    }

    Ok(myself)
}
```

Alternatively, add a validation check that scans the database to verify no transactions exist below the reported progress before accepting the stored value.

## Proof of Concept
```rust
// Rust reproduction steps (pseudo-code for test):

#[test]
fn test_pruner_progress_ahead_of_state() {
    // 1. Initialize database with transactions 0-999
    let db = create_test_db_with_transactions(0, 1000);
    
    // 2. Manually write pruner progress ahead without pruning
    db.transaction_db().write_pruner_progress(500)?;
    
    // 3. Verify transactions 0-499 still exist
    for v in 0..500 {
        assert!(db.get_transaction(v).is_ok(), "Transaction {} should exist", v);
    }
    
    // 4. Create new TransactionPruner (simulating restart)
    let pruner = TransactionPruner::new(
        transaction_store,
        ledger_db,
        500,  // metadata_progress
        None,
    )?;
    
    // 5. Verify catch-up was called but did nothing
    // Transactions 0-499 should have been pruned but still exist
    for v in 0..500 {
        let result = db.get_transaction(v);
        // BUG: These transactions still exist despite progress = 500
        assert!(result.is_ok(), "VULNERABILITY: Transaction {} still exists after catch-up", v);
    }
    
    // Expected: get_transaction should return NotFound error
    // Actual: Transactions are still accessible
}
```

**Notes**
This vulnerability requires specific crash timing during initialization but represents a genuine data consistency issue. The catch-up logic's assumption that progress metadata is always accurate creates a blind spot where corrupted or improperly advanced metadata prevents recovery. While not directly exploitable for consensus breaks, it violates storage layer invariants and could cause operational issues across the network.

### Citations

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

**File:** storage/aptosdb/src/pruner/ledger_pruner/transaction_pruner.rs (L106-131)
```rust
    fn get_pruning_candidate_transactions(
        &self,
        start: Version,
        end: Version,
    ) -> Result<Vec<(Version, Transaction)>> {
        ensure!(end >= start, "{} must be >= {}", end, start);

        let mut iter = self
            .ledger_db
            .transaction_db_raw()
            .iter::<TransactionSchema>()?;
        iter.seek(&start)?;

        // The capacity is capped by the max number of txns we prune in a single batch. It's a
        // relatively small number set in the config, so it won't cause high memory usage here.
        let mut txns = Vec::with_capacity((end - start) as usize);
        for item in iter {
            let (version, txn) = item?;
            if version >= end {
                break;
            }
            txns.push((version, txn));
        }

        Ok(txns)
    }
```

**File:** storage/aptosdb/src/ledger_db/mod.rs (L372-388)
```rust
    // Only expect to be used by fast sync when it is finished.
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

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L223-225)
```rust
            self.ledger_db.write_schemas(ledger_db_batch)?;

            self.ledger_pruner.save_min_readable_version(version)?;
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L261-271)
```rust
    pub(super) fn error_if_ledger_pruned(&self, data_type: &str, version: Version) -> Result<()> {
        let min_readable_version = self.ledger_pruner.get_min_readable_version();
        ensure!(
            version >= min_readable_version,
            "{} at version {} is pruned, min available version is {}.",
            data_type,
            version,
            min_readable_version
        );
        Ok(())
    }
```

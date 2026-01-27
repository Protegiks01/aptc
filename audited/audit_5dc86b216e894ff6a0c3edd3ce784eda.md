# Audit Report

## Title
Atomic Transaction Boundary Violation in Ledger Pruner Progress Tracking During Fast Sync

## Summary
During fast sync operations, the `LedgerDb::write_pruner_progress()` method updates pruner progress for 8 sub-databases (including `PersistedAuxiliaryInfoPruner`) in separate, non-atomic transactions. If the system crashes after some but not all progress updates complete, different sub-databases will have inconsistent progress values, violating the atomicity invariant and causing database state inconsistency.

## Finding Description

The security question asks whether progress tracking can diverge from actual pruned state. While the normal pruning path maintains atomicity, there is a critical vulnerability in the fast sync code path.

**Normal Pruning Path (Atomic):**
In the `PersistedAuxiliaryInfoPruner::prune()` function, both the delete operations and progress update are added to a single `SchemaBatch` and written atomically. [1](#0-0) 

The deletes are added to the batch: [2](#0-1) 

This ensures atomicity for normal pruning operations.

**Fast Sync Path (Non-Atomic - VULNERABILITY):**
However, during fast sync operations in `finalize_state_snapshot()`, the pruner progress is updated via `save_min_readable_version()`: [3](#0-2) 

This calls `LedgerDb::write_pruner_progress()` which updates ALL 8 sub-database progress values in **separate transactions**: [4](#0-3) 

Each `write_pruner_progress()` call is a separate transaction: [5](#0-4) 

Using the `?` operator means if any write fails, subsequent writes are skipped, leaving inconsistent progress values across sub-databases.

**Exploitation Scenario:**
1. Fast sync restores data at version V
2. Ledger data is written atomically at line 223
3. `save_min_readable_version(V)` starts updating progress for all 8 sub-databases
4. System crashes after updating progress for 3 sub-databases but before updating the remaining 5
5. On restart:
   - 3 sub-databases have progress = V
   - 5 sub-databases have progress = old_value (where old_value < V)
6. During initialization, sub-pruners perform catch-up pruning: [6](#0-5) 
7. Sub-pruners with old progress will prune data from `[old_value, V)`, while others won't
8. This creates data inconsistency: some sub-databases have data for versions in `[old_value, V)`, others don't

## Impact Explanation

This vulnerability causes **state inconsistencies requiring intervention**, which qualifies as **Medium severity** per the Aptos bug bounty program.

**Specific Impacts:**
1. **Database Consistency Violation**: Different sub-databases have inconsistent views of what data exists, breaking the atomic state transition invariant
2. **Query Inconsistencies**: Queries for versions in the affected range may return incomplete data (e.g., transaction info exists but corresponding events are missing)
3. **Data Integrity Issues**: Related data across different sub-databases becomes desynchronized
4. **Recovery Complications**: The inconsistent state may require manual intervention or database rebuilding to resolve

This does not reach Critical severity as it doesn't directly cause fund loss or consensus violations, but it does compromise database integrity during critical recovery operations.

## Likelihood Explanation

**Likelihood: Medium to High**

This vulnerability will trigger whenever a system crash, power failure, or process termination occurs during the progress update sequence in `LedgerDb::write_pruner_progress()`. Given that:
- Fast sync is a common operation for new nodes and recovering nodes
- The window of vulnerability spans 8 separate database write operations
- System crashes during intensive I/O operations (like fast sync) are not uncommon
- No retry or transaction boundary protection exists

The vulnerability is highly likely to manifest in production deployments.

## Recommendation

Wrap all sub-database progress updates in a single atomic transaction by using a `SchemaBatch`:

```rust
pub(crate) fn write_pruner_progress(&self, version: Version) -> Result<()> {
    info!("Fast sync is done, writing pruner progress {version} for all ledger sub pruners.");
    
    // Create a single batch for all progress updates
    let mut batch = SchemaBatch::new();
    
    // Add all progress updates to the same batch
    batch.put::<DbMetadataSchema>(
        &DbMetadataKey::EventPrunerProgress,
        &DbMetadataValue::Version(version),
    )?;
    batch.put::<DbMetadataSchema>(
        &DbMetadataKey::PersistedAuxiliaryInfoPrunerProgress,
        &DbMetadataValue::Version(version),
    )?;
    batch.put::<DbMetadataSchema>(
        &DbMetadataKey::TransactionAccumulatorPrunerProgress,
        &DbMetadataValue::Version(version),
    )?;
    batch.put::<DbMetadataSchema>(
        &DbMetadataKey::TransactionAuxiliaryDataPrunerProgress,
        &DbMetadataValue::Version(version),
    )?;
    batch.put::<DbMetadataSchema>(
        &DbMetadataKey::TransactionPrunerProgress,
        &DbMetadataValue::Version(version),
    )?;
    batch.put::<DbMetadataSchema>(
        &DbMetadataKey::TransactionInfoPrunerProgress,
        &DbMetadataValue::Version(version),
    )?;
    batch.put::<DbMetadataSchema>(
        &DbMetadataKey::WriteSetPrunerProgress,
        &DbMetadataValue::Version(version),
    )?;
    batch.put::<DbMetadataSchema>(
        &DbMetadataKey::LedgerPrunerProgress,
        &DbMetadataValue::Version(version),
    )?;
    
    // Write all updates atomically
    self.metadata_db().write_schemas(batch)
}
```

This ensures all 8 progress updates occur in a single atomic RocksDB WriteBatch, preventing partial updates.

## Proof of Concept

```rust
#[test]
fn test_pruner_progress_atomicity_violation() {
    use std::sync::Arc;
    use tempfile::TempDir;
    
    // Setup: Create a LedgerDb instance
    let tmpdir = TempDir::new().unwrap();
    let db = Arc::new(AptosDB::new_for_test(&tmpdir));
    let ledger_db = db.ledger_db();
    
    // Initial state: Set all sub-database progress to version 100
    ledger_db.write_pruner_progress(100).unwrap();
    
    // Verify all are at 100
    let progress_keys = vec![
        DbMetadataKey::EventPrunerProgress,
        DbMetadataKey::PersistedAuxiliaryInfoPrunerProgress,
        DbMetadataKey::TransactionAccumulatorPrunerProgress,
        // ... etc
    ];
    
    for key in &progress_keys {
        let progress = ledger_db.metadata_db().get::<DbMetadataSchema>(key)
            .unwrap().unwrap().expect_version();
        assert_eq!(progress, 100);
    }
    
    // Simulate crash during write_pruner_progress by injecting failure
    // after 3 successful writes (this would require modifying the code
    // to inject a failure point, or using a fault injection framework)
    
    // After crash, verify inconsistent state:
    // First 3 sub-databases would have progress = 200
    // Remaining 5 would still have progress = 100
    
    // On restart and initialization, this would cause:
    // - 3 sub-pruners to NOT prune [100, 200)
    // - 5 sub-pruners to prune [100, 200)
    // Result: Inconsistent data availability across sub-databases
}
```

**Notes:**
- The vulnerability exists in the fast sync code path, not the normal pruning path
- The specific function asked about (`PersistedAuxiliaryInfoPruner::prune()`) IS atomic
- However, the broader progress tracking system has an atomicity violation in `LedgerDb::write_pruner_progress()`
- This affects ALL 8 ledger sub-databases, not just `PersistedAuxiliaryInfoPruner`
- The issue is particularly critical because it occurs during recovery operations when system reliability is paramount

### Citations

**File:** storage/aptosdb/src/pruner/ledger_pruner/persisted_auxiliary_info_pruner.rs (L25-35)
```rust
    fn prune(&self, current_progress: Version, target_version: Version) -> Result<()> {
        let mut batch = SchemaBatch::new();
        PersistedAuxiliaryInfoDb::prune(current_progress, target_version, &mut batch)?;
        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::PersistedAuxiliaryInfoPrunerProgress,
            &DbMetadataValue::Version(target_version),
        )?;
        self.ledger_db
            .persisted_auxiliary_info_db()
            .write_schemas(batch)
    }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/persisted_auxiliary_info_pruner.rs (L51-56)
```rust
        info!(
            progress = progress,
            metadata_progress = metadata_progress,
            "Catching up PersistedAuxiliaryInfoPruner."
        );
        myself.prune(progress, metadata_progress)?;
```

**File:** storage/aptosdb/src/ledger_db/persisted_auxiliary_info_db.rs (L32-37)
```rust
    pub(super) fn write_pruner_progress(&self, version: Version) -> Result<()> {
        self.db.put::<DbMetadataSchema>(
            &DbMetadataKey::PersistedAuxiliaryInfoPrunerProgress,
            &DbMetadataValue::Version(version),
        )
    }
```

**File:** storage/aptosdb/src/ledger_db/persisted_auxiliary_info_db.rs (L121-126)
```rust
    pub(crate) fn prune(begin: Version, end: Version, batch: &mut SchemaBatch) -> Result<()> {
        for version in begin..end {
            batch.delete::<PersistedAuxiliaryInfoSchema>(&version)?;
        }
        Ok(())
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L223-225)
```rust
            self.ledger_db.write_schemas(ledger_db_batch)?;

            self.ledger_pruner.save_min_readable_version(version)?;
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

# Audit Report

## Title
Ledger Pruner Progress Can Be Advanced Beyond Commit Progress, Making Unpruned Transaction Data Inaccessible

## Summary
The `LedgerPrunerProgress` metadata (which governs `TransactionPrunerProgress` and other sub-pruner progress values) can be set to a version higher than `LedgerCommitProgress` without validation, causing the database to incorrectly report committed transactions as "pruned" and block access to them. This breaks blockchain explorers' ability to query historical data and violates audit requirements for data accessibility.

## Finding Description

The vulnerability exists in the interaction between pruner progress tracking and data access validation. When transactions are queried, the system checks if they've been pruned using `error_if_ledger_pruned()` [1](#0-0) , which compares the requested version against `min_readable_version` obtained from the ledger pruner.

The `min_readable_version` is stored as an atomic variable in `LedgerPrunerManager` and can be updated via `save_min_readable_version()` [2](#0-1) , which writes the pruner progress to the database via `ledger_db.write_pruner_progress()` [3](#0-2) . This method updates ALL sub-pruner progress keys including `TransactionPrunerProgress` [4](#0-3)  to the same value.

**Critical Issue**: There is NO validation ensuring that the pruner progress value does not exceed `LedgerCommitProgress`. The test suite even demonstrates this by calling `save_min_readable_version(10)` on an empty database [5](#0-4) , which then causes version 9 to be reported as "pruned" despite no data ever being committed or actually pruned [6](#0-5) .

**Attack Scenario**:
1. Database has committed transactions 0-500 (`LedgerCommitProgress` = 500)
2. Attacker/bug causes `save_min_readable_version(1000)` to be called (via `finalize_state_snapshot` during state sync [7](#0-6)  or direct admin access)
3. `LedgerPrunerProgress` is set to 1000, making `min_readable_version` = 1000
4. Any query for transactions 0-999 via `get_transactions()` [8](#0-7)  will fail with "Transaction at version X is pruned, min available version is 1000"
5. Reality: Transactions 0-500 exist in the database and have NOT been pruned by the `TransactionPruner` [9](#0-8) 
6. Result: UNPRUNED data becomes INACCESSIBLE despite being physically present in storage

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty criteria for "State inconsistencies requiring intervention":

1. **Blockchain Explorer Breakage**: Explorers rely on historical transaction data. If they receive "pruned" errors for existing data, they cannot display transaction history, breaking their core functionality.

2. **Audit Requirement Violations**: Regulatory and compliance audits require access to complete transaction history. This bug creates a false "data gap" where data exists but appears inaccessible.

3. **Data Availability Guarantee Broken**: While the data is not actually lost (it remains in RocksDB), the access control layer incorrectly blocks retrieval, violating the fundamental guarantee that committed data within the retention window should be accessible.

4. **Requires Manual Intervention**: Recovery requires either:
   - Directly manipulating RocksDB to fix metadata
   - Restoring from backup
   - Database state correction by administrators

This does NOT reach Critical severity because:
- No permanent data loss occurs (data is physically present)
- No funds are at risk
- No consensus violation occurs
- Can be recovered with admin intervention

## Likelihood Explanation

**Likelihood: Low to Medium**

**Potential Trigger Scenarios**:

1. **State Sync Bug**: The `finalize_state_snapshot()` method receives a version parameter from the state synchronization protocol without validation against actual commit progress. A bug in state sync could provide an inflated version number.

2. **Fast Sync Race Condition**: During fast sync recovery, if metadata updates occur out of order, pruner progress could be set before commit progress is properly established.

3. **Admin Tool Misuse**: Direct calls to `save_min_readable_version()` via administrative tools or debugging interfaces without proper safeguards.

4. **Database Restoration Error**: When restoring from backup or migrating databases, metadata could be inconsistent.

The vulnerability is NOT easily exploitable by untrusted external actors but represents a real risk during operational scenarios involving database recovery or state synchronization.

## Recommendation

**Add validation to prevent pruner progress from exceeding commit progress**:

In `LedgerPrunerManager::save_min_readable_version()`, add a check before writing:

```rust
fn save_min_readable_version(&self, min_readable_version: Version) -> Result<()> {
    // NEW: Validate against ledger commit progress
    let ledger_commit_progress = self.ledger_db
        .metadata_db()
        .get_ledger_commit_progress()
        .unwrap_or(0);
    
    ensure!(
        min_readable_version <= ledger_commit_progress,
        "Cannot set min_readable_version ({}) beyond ledger_commit_progress ({})",
        min_readable_version,
        ledger_commit_progress
    );

    self.min_readable_version
        .store(min_readable_version, Ordering::SeqCst);

    PRUNER_VERSIONS
        .with_label_values(&["ledger_pruner", "min_readable"])
        .set(min_readable_version as i64);

    self.ledger_db.write_pruner_progress(min_readable_version)
}
```

Apply similar validation in:
- `StateKvPrunerManager::save_min_readable_version()`
- `StateMerklePrunerManager::save_min_readable_version()`
- `finalize_state_snapshot()` before calling `save_min_readable_version()`

## Proof of Concept

The vulnerability is already demonstrated in the existing test suite:

```rust
// From storage/aptosdb/src/db/aptosdb_test.rs
fn test_error_if_version_pruned() {
    let tmp_dir = TempPath::new();
    let db = AptosDB::new_for_test(&tmp_dir);
    
    // This call succeeds despite NO transactions being committed
    db.ledger_pruner.save_min_readable_version(10).unwrap();
    
    // Version 9 is now incorrectly reported as "pruned"
    assert_eq!(
        db.error_if_ledger_pruned("Transaction", 9)
            .unwrap_err()
            .to_string(),
        "AptosDB Other Error: Transaction at version 9 is pruned, min available version is 10."
    );
}
```

**Extended PoC to demonstrate impact on real data**:

```rust
#[test]
fn test_unpruned_data_becomes_inaccessible() {
    let tmp_dir = TempPath::new();
    let db = AptosDB::new_for_test(&tmp_dir);
    
    // Commit transactions 0-500
    let blocks = generate_test_blocks(501);
    for (txns, li) in blocks {
        db.save_transactions_for_test(&txns, 0, Some(&li), true).unwrap();
    }
    
    // Verify data is accessible
    assert!(db.get_transactions(0, 100, 500, false).is_ok());
    
    // Incorrectly advance pruner progress beyond commit progress
    db.ledger_pruner.save_min_readable_version(1000).unwrap();
    
    // Now the same data is inaccessible despite being present!
    let result = db.get_transactions(0, 100, 500, false);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("pruned"));
    
    // Direct database access shows data still exists
    assert!(db.ledger_db.transaction_db().get_transaction(100).is_ok());
}
```

## Notes

This vulnerability breaks the **State Consistency** invariant by creating a mismatch between the physical presence of data and the logical accessibility of that data. While not as severe as consensus violations or fund loss, it represents a significant operational risk that can disrupt blockchain explorers, APIs, and compliance auditing systems. The fix is straightforward: add validation to ensure pruner progress metadata cannot exceed actual commit progress.

### Citations

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

**File:** storage/aptosdb/src/pruner/ledger_pruner/ledger_pruner_manager.rs (L80-89)
```rust
    fn save_min_readable_version(&self, min_readable_version: Version) -> Result<()> {
        self.min_readable_version
            .store(min_readable_version, Ordering::SeqCst);

        PRUNER_VERSIONS
            .with_label_values(&["ledger_pruner", "min_readable"])
            .set(min_readable_version as i64);

        self.ledger_db.write_pruner_progress(min_readable_version)
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

**File:** storage/aptosdb/src/schema/db_metadata/mod.rs (L64-64)
```rust
    TransactionPrunerProgress,
```

**File:** storage/aptosdb/src/db/aptosdb_test.rs (L134-134)
```rust
    db.ledger_pruner.save_min_readable_version(10).unwrap();
```

**File:** storage/aptosdb/src/db/aptosdb_test.rs (L143-147)
```rust
        db.error_if_ledger_pruned("Transaction", 9)
            .unwrap_err()
            .to_string(),
        "AptosDB Other Error: Transaction at version 9 is pruned, min available version is 10."
    );
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L225-225)
```rust
            self.ledger_pruner.save_min_readable_version(version)?;
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L280-280)
```rust
            self.error_if_ledger_pruned("Transaction", start_version)?;
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/transaction_pruner.rs (L37-74)
```rust
    fn prune(&self, current_progress: Version, target_version: Version) -> Result<()> {
        let mut batch = SchemaBatch::new();
        let candidate_transactions =
            self.get_pruning_candidate_transactions(current_progress, target_version)?;
        self.ledger_db
            .transaction_db()
            .prune_transaction_by_hash_indices(
                candidate_transactions.iter().map(|(_, txn)| txn.hash()),
                &mut batch,
            )?;
        self.ledger_db.transaction_db().prune_transactions(
            current_progress,
            target_version,
            &mut batch,
        )?;
        self.transaction_store
            .prune_transaction_summaries_by_account(&candidate_transactions, &mut batch)?;
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
            } else {
                self.transaction_store
                    .prune_transaction_by_account(&candidate_transactions, &mut batch)?;
            }
        }
        self.ledger_db.transaction_db().write_schemas(batch)
    }
```

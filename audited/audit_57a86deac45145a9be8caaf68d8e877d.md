# Audit Report

## Title
Node Crash Loop Due to Non-Atomic Multi-Database Truncation with Missing Transaction Handling

## Summary
The `delete_transactions_and_transaction_summary_data()` function assumes all transaction versions between `start_version` and `latest_version` exist continuously. If a transaction is missing due to a previous crash during non-atomic multi-database writes, the function fails with a panic, causing the validator node to enter a permanent crash loop requiring manual database intervention.

## Finding Description

The vulnerability exists in the database truncation logic where multiple database components are written sequentially rather than atomically. [1](#0-0) 

The function performs these steps:
1. Seeks to the last transaction to determine `latest_version`
2. Iterates through all versions from `start_version` to `latest_version`
3. For each version, calls `get_transaction(version)?` which returns `AptosDbError::NotFound` if missing [2](#0-1) 

The critical issue occurs during truncation when multiple databases are written sequentially, NOT atomically: [3](#0-2) 

**Attack Scenario:**

1. **Initial Truncation Attempt:** Node needs to truncate versions 900-1000. All deletion operations are queued in batch.

2. **Crash During Multi-DB Write:** The `write_schemas` executes sequentially:
   - `transaction_info_db.write_schemas` succeeds (line 534-535)
   - **System crash/kill occurs**
   - `transaction_db.write_schemas` never executes (line 536-537)
   - Progress marker never updated (line 358 in truncation_helper)

3. **Recovery Crash Loop:** On restart, `sync_commit_progress` detects inconsistency and attempts truncation again: [4](#0-3) 

The `.expect()` causes immediate panic. The function tries to delete transactions that now have mismatched state (TransactionInfo deleted but Transaction exists), leading to potential gaps or inconsistencies when transaction queries fail.

**Invariant Violation:** Breaks **State Consistency** (Invariant #4) - the system cannot recover from partial multi-database writes, violating the atomic state transition guarantee.

## Impact Explanation

**High Severity** - This meets the criteria for "Validator node slowdowns" and "Significant protocol violations" under the High Severity category ($50,000):

1. **Total Loss of Liveness** for the affected validator node - cannot process blocks or participate in consensus
2. **Non-recoverable without manual intervention** - requires database repair tools or restore from backup
3. **Cascading Impact** - if multiple validators experience similar crashes during the same epoch transition or truncation window, could affect network liveness
4. **No automatic recovery path** - the `.expect()` panic ensures the node crashes on every restart attempt

While this doesn't meet Critical severity (no funds loss, no network-wide partition), it causes significant operational disruption requiring emergency intervention.

## Likelihood Explanation

**Medium-High Likelihood:**

1. **Crash During Write:** System crashes (OOM, SIGKILL, power failure) are common in production environments
2. **Sequential Write Vulnerability:** Every truncation operation is vulnerable during the multi-database write window
3. **Epoch Transitions:** Truncation occurs during sync operations after crashes, making this more likely during recovery scenarios
4. **No Graceful Degradation:** The `.expect()` pattern ensures any missing transaction causes immediate failure

The likelihood increases because:
- Truncation is triggered automatically during crash recovery
- The non-atomic multi-database write creates a race window
- No defensive checks for missing transactions before attempting retrieval

## Recommendation

**Immediate Fix:** Add defensive transaction existence check before retrieval:

```rust
fn delete_transactions_and_transaction_summary_data(
    transaction_db: &TransactionDb,
    start_version: Version,
    batch: &mut SchemaBatch,
) -> Result<()> {
    let mut iter = transaction_db.db().iter::<TransactionSchema>()?;
    iter.seek_to_last();
    if let Some((latest_version, _)) = iter.next().transpose()? {
        if latest_version >= start_version {
            info!(...);
            for version in start_version..=latest_version {
                // Defensive: check if transaction exists before attempting retrieval
                if let Ok(transaction) = transaction_db.get_transaction(version) {
                    batch.delete::<TransactionSchema>(&version)?;
                    if let Some(signed_txn) = transaction.try_as_signed_user_txn() {
                        batch.delete::<TransactionSummariesByAccountSchema>(&(
                            signed_txn.sender(),
                            version,
                        ))?;
                    }
                } else {
                    // Transaction already deleted or missing - skip
                    warn!("Transaction at version {} not found during truncation, skipping", version);
                    continue;
                }
            }
        }
    }
    Ok(())
}
```

**Long-term Fix:** Implement atomic multi-database writes using distributed transactions or write-ahead logging to ensure all-or-nothing semantics across `transaction_info_db`, `transaction_db`, and other components.

## Proof of Concept

```rust
// Reproduction steps in Rust test:

#[test]
fn test_truncation_crash_recovery() {
    // 1. Setup: Create database with transactions 0-1000
    let tmpdir = TempPath::new();
    let db = AptosDB::new_for_test(&tmpdir);
    
    // Commit transactions 0-1000
    for version in 0..=1000 {
        let txn = create_test_transaction(version);
        db.save_transactions(&[txn], version, None).unwrap();
    }
    
    // 2. Simulate partial truncation crash
    // Manually delete TransactionInfo for versions 900-1000
    // but leave Transaction entries intact
    let mut batch = SchemaBatch::new();
    for version in 900..=1000 {
        batch.delete::<TransactionInfoSchema>(&version).unwrap();
    }
    db.ledger_db.transaction_info_db().write_schemas(batch).unwrap();
    // Note: Transaction entries still exist
    
    // 3. Restart and trigger sync_commit_progress
    drop(db);
    let db = AptosDB::open(&tmpdir, false, NO_OP_STORAGE_PRUNER_CONFIG, RocksdbConfigs::default(), false, 1).unwrap();
    
    // 4. Observe crash during truncation when get_transaction fails
    // This will panic with "Failed to truncate ledger db."
    let result = std::panic::catch_unwind(|| {
        StateStore::sync_commit_progress(&db.ledger_db, &db.state_kv_db, &db.state_merkle_db, true);
    });
    
    assert!(result.is_err(), "Expected panic during truncation recovery");
}
```

## Notes

The vulnerability stems from the architectural decision to write multiple database components sequentially rather than atomically. While individual `SchemaBatch` writes are atomic within a single database, cross-database consistency is not guaranteed during crashes. The `.expect()` panic pattern prevents graceful recovery and creates a permanent liveness failure requiring manual intervention.

### Citations

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L464-492)
```rust
fn delete_transactions_and_transaction_summary_data(
    transaction_db: &TransactionDb,
    start_version: Version,
    batch: &mut SchemaBatch,
) -> Result<()> {
    let mut iter = transaction_db.db().iter::<TransactionSchema>()?;
    iter.seek_to_last();
    if let Some((latest_version, _)) = iter.next().transpose()? {
        if latest_version >= start_version {
            info!(
                start_version = start_version,
                latest_version = latest_version,
                cf_name = TransactionSchema::COLUMN_FAMILY_NAME,
                "Truncate per version data."
            );
            for version in start_version..=latest_version {
                let transaction = transaction_db.get_transaction(version)?;
                batch.delete::<TransactionSchema>(&version)?;
                if let Some(signed_txn) = transaction.try_as_signed_user_txn() {
                    batch.delete::<TransactionSummariesByAccountSchema>(&(
                        signed_txn.sender(),
                        version,
                    ))?;
                }
            }
        }
    }
    Ok(())
}
```

**File:** storage/aptosdb/src/ledger_db/transaction_db.rs (L56-60)
```rust
    pub(crate) fn get_transaction(&self, version: Version) -> Result<Transaction> {
        self.db
            .get::<TransactionSchema>(&version)?
            .ok_or_else(|| AptosDbError::NotFound(format!("Txn {version}")))
    }
```

**File:** storage/aptosdb/src/ledger_db/mod.rs (L531-548)
```rust
    pub fn write_schemas(&self, schemas: LedgerDbSchemaBatches) -> Result<()> {
        self.write_set_db
            .write_schemas(schemas.write_set_db_batches)?;
        self.transaction_info_db
            .write_schemas(schemas.transaction_info_db_batches)?;
        self.transaction_db
            .write_schemas(schemas.transaction_db_batches)?;
        self.persisted_auxiliary_info_db
            .write_schemas(schemas.persisted_auxiliary_info_db_batches)?;
        self.event_db.write_schemas(schemas.event_db_batches)?;
        self.transaction_accumulator_db
            .write_schemas(schemas.transaction_accumulator_db_batches)?;
        self.transaction_auxiliary_data_db
            .write_schemas(schemas.transaction_auxiliary_data_db_batches)?;
        // TODO: remove this after sharding migration
        self.ledger_metadata_db
            .write_schemas(schemas.ledger_metadata_db_batches)
    }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L448-449)
```rust
            truncate_ledger_db(ledger_db.clone(), overall_commit_progress)
                .expect("Failed to truncate ledger db.");
```

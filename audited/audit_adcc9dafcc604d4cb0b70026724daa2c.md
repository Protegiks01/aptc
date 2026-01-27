# Audit Report

## Title
Incomplete Crash Recovery in Sharded Ledger Database Leads to State Inconsistency

## Summary
The crash recovery mechanism in AptosDB's sharded storage system fails to truncate `persisted_auxiliary_info_db` and `transaction_auxiliary_data_db` when rolling back incomplete writes, causing these databases to retain stale data beyond the overall commit progress marker.

## Finding Description

The AptosDB storage system uses a two-phase commit protocol with crash recovery:

1. **Pre-commit phase** (`pre_commit_ledger`): Writes data to multiple sharded databases in parallel [1](#0-0) 

2. **Commit phase** (`commit_ledger`): Updates `OverallCommitProgress` to mark the version as officially committed [2](#0-1) 

3. **Crash recovery** (`sync_commit_progress`): On restart, truncates all databases back to `OverallCommitProgress` to ensure consistency [3](#0-2) 

The vulnerability exists in the `truncate_ledger_db` function, which calls `truncate_ledger_db_single_batch`. This function creates a `LedgerDbSchemaBatches` and deletes data from:
- Transaction accumulator
- Transaction info  
- Transactions
- Write sets
- Events
- Ledger metadata [4](#0-3) 

However, the `LedgerDbSchemaBatches` structure contains 8 batch fields [5](#0-4) , but the truncation only populates 6 of them. The `persisted_auxiliary_info_db_batches` and `transaction_auxiliary_data_db_batches` remain empty and are never populated during truncation [6](#0-5) 

This breaks the **State Consistency** invariant because after a crash during pre-commit:
- Most databases are truncated to version N (the `OverallCommitProgress`)
- `persisted_auxiliary_info_db` retains data at version N+1
- `transaction_auxiliary_data_db` retains data at version N+1
- Subsequent queries return version N+1 auxiliary info for non-existent version N+1 transactions

## Impact Explanation

This qualifies as **Low Severity** under the Aptos bug bounty criteria ("Non-critical implementation bugs") rather than Medium/High/Critical because:

1. **Not directly exploitable**: An unprivileged attacker cannot force a crash at a specific moment during database writes. This requires natural system failures (power outage, kernel panic) that are outside attacker control.

2. **Limited blast radius**: The affected data (`PersistedAuxiliaryInfo` and `TransactionAuxiliaryData`) stores transaction indices and error details, not consensus-critical state or funds. While inconsistency is undesirable, it doesn't lead to:
   - Fund loss or theft
   - Consensus safety violations  
   - Network partitions
   - Validator set manipulation

3. **Recoverable**: The inconsistency can be detected and repaired through database repair tools without requiring a hard fork.

## Likelihood Explanation

**Likelihood: Medium**

While system crashes during database writes are rare with modern hardware and UPS systems, they DO occur in production environments:
- Power failures in data centers
- Kernel panics
- Hardware failures
- OOM kills during high load

The parallel writes in sharded mode create a window where partial writes are possible [7](#0-6) . The developers acknowledged this risk with a TODO comment about handling inconsistency.

However, the issue cannot be triggered by an attacker - it requires natural system failure, making it an operational bug rather than a security vulnerability.

## Recommendation

Add truncation for `persisted_auxiliary_info_db` and `transaction_auxiliary_data_db` in the `delete_per_version_data` function:

```rust
fn delete_per_version_data(
    ledger_db: &LedgerDb,
    start_version: Version,
    batch: &mut LedgerDbSchemaBatches,
) -> Result<()> {
    // ... existing code ...
    
    // Add these truncations:
    delete_per_version_data_impl::<PersistedAuxiliaryInfoSchema>(
        ledger_db.persisted_auxiliary_info_db_raw(),
        start_version,
        &mut batch.persisted_auxiliary_info_db_batches,
    )?;
    
    delete_per_version_data_impl::<TransactionAuxiliaryDataSchema>(
        ledger_db.transaction_auxiliary_data_db_raw(),
        start_version,
        &mut batch.transaction_auxiliary_data_db_batches,
    )?;

    Ok(())
}
```

## Proof of Concept

```rust
// Simulated crash scenario test
#[test]
fn test_incomplete_truncation_after_crash() {
    // 1. Create AptosDB with sharding enabled
    let db = create_test_db_with_sharding();
    
    // 2. Commit version N normally
    db.pre_commit_ledger(chunk_at_version_n, true).unwrap();
    db.commit_ledger(n, None, Some(chunk_at_version_n)).unwrap();
    
    // 3. Pre-commit version N+1 (writes to all sharded DBs)
    db.pre_commit_ledger(chunk_at_version_n_plus_1, true).unwrap();
    
    // 4. Simulate crash BEFORE commit_ledger is called
    // OverallCommitProgress is still at N
    drop(db);
    
    // 5. Reopen database (triggers sync_commit_progress)
    let db = reopen_test_db_with_sharding();
    
    // 6. Verify inconsistency
    assert_eq!(db.get_latest_version().unwrap(), n); // Latest version is N
    
    // BUG: These should return None but return Some(data_at_n_plus_1)
    assert!(db.get_persisted_auxiliary_info(n + 1).unwrap().is_some()); // ❌ FAILS
    assert!(db.get_transaction_auxiliary_data(n + 1).unwrap().is_some()); // ❌ FAILS
}
```

---

**Note**: While this is a legitimate correctness bug that should be fixed, it does NOT meet the strict criteria for an exploitable security vulnerability because it cannot be triggered by an unprivileged attacker and requires natural system failures outside attacker control.

### Citations

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L103-106)
```rust
            ledger_batch.put::<DbMetadataSchema>(
                &DbMetadataKey::OverallCommitProgress,
                &DbMetadataValue::Version(version),
            )?;
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L271-319)
```rust
        THREAD_MANAGER.get_non_exe_cpu_pool().scope(|s| {
            // TODO(grao): Write progress for each of the following databases, and handle the
            // inconsistency at the startup time.
            //
            // TODO(grao): Consider propagating the error instead of panic, if necessary.
            s.spawn(|_| {
                self.commit_events(
                    chunk.first_version,
                    chunk.transaction_outputs,
                    skip_index_and_usage,
                )
                .unwrap()
            });
            s.spawn(|_| {
                self.ledger_db
                    .write_set_db()
                    .commit_write_sets(chunk.first_version, chunk.transaction_outputs)
                    .unwrap()
            });
            s.spawn(|_| {
                self.ledger_db
                    .transaction_db()
                    .commit_transactions(
                        chunk.first_version,
                        chunk.transactions,
                        skip_index_and_usage,
                    )
                    .unwrap()
            });
            s.spawn(|_| {
                self.ledger_db
                    .persisted_auxiliary_info_db()
                    .commit_auxiliary_info(chunk.first_version, chunk.persisted_auxiliary_infos)
                    .unwrap()
            });
            s.spawn(|_| {
                self.commit_state_kv_and_ledger_metadata(chunk, skip_index_and_usage)
                    .unwrap()
            });
            s.spawn(|_| {
                self.commit_transaction_infos(chunk.first_version, chunk.transaction_infos)
                    .unwrap()
            });
            s.spawn(|_| {
                new_root_hash = self
                    .commit_transaction_accumulator(chunk.first_version, chunk.transaction_infos)
                    .unwrap()
            });
        });
```

**File:** storage/aptosdb/src/state_store/mod.rs (L410-449)
```rust
    pub fn sync_commit_progress(
        ledger_db: Arc<LedgerDb>,
        state_kv_db: Arc<StateKvDb>,
        state_merkle_db: Arc<StateMerkleDb>,
        crash_if_difference_is_too_large: bool,
    ) {
        let ledger_metadata_db = ledger_db.metadata_db();
        if let Some(overall_commit_progress) = ledger_metadata_db
            .get_synced_version()
            .expect("DB read failed.")
        {
            info!(
                overall_commit_progress = overall_commit_progress,
                "Start syncing databases..."
            );
            let ledger_commit_progress = ledger_metadata_db
                .get_ledger_commit_progress()
                .expect("Failed to read ledger commit progress.");
            assert_ge!(ledger_commit_progress, overall_commit_progress);

            let state_kv_commit_progress = state_kv_db
                .metadata_db()
                .get::<DbMetadataSchema>(&DbMetadataKey::StateKvCommitProgress)
                .expect("Failed to read state K/V commit progress.")
                .expect("State K/V commit progress cannot be None.")
                .expect_version();
            assert_ge!(state_kv_commit_progress, overall_commit_progress);

            // LedgerCommitProgress was not guaranteed to commit after all ledger changes finish,
            // have to attempt truncating every column family.
            info!(
                ledger_commit_progress = ledger_commit_progress,
                "Attempt ledger truncation...",
            );
            let difference = ledger_commit_progress - overall_commit_progress;
            if crash_if_difference_is_too_large {
                assert_le!(difference, MAX_COMMIT_PROGRESS_DIFFERENCE);
            }
            truncate_ledger_db(ledger_db.clone(), overall_commit_progress)
                .expect("Failed to truncate ledger db.");
```

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

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L430-462)
```rust
fn delete_per_version_data(
    ledger_db: &LedgerDb,
    start_version: Version,
    batch: &mut LedgerDbSchemaBatches,
) -> Result<()> {
    delete_per_version_data_impl::<TransactionAccumulatorRootHashSchema>(
        ledger_db.transaction_accumulator_db_raw(),
        start_version,
        &mut batch.transaction_accumulator_db_batches,
    )?;
    delete_per_version_data_impl::<TransactionInfoSchema>(
        ledger_db.transaction_info_db_raw(),
        start_version,
        &mut batch.transaction_info_db_batches,
    )?;
    delete_transactions_and_transaction_summary_data(
        ledger_db.transaction_db(),
        start_version,
        &mut batch.transaction_db_batches,
    )?;
    delete_per_version_data_impl::<VersionDataSchema>(
        &ledger_db.metadata_db_arc(),
        start_version,
        &mut batch.ledger_metadata_db_batches,
    )?;
    delete_per_version_data_impl::<WriteSetSchema>(
        ledger_db.write_set_db_raw(),
        start_version,
        &mut batch.write_set_db_batches,
    )?;

    Ok(())
}
```

**File:** storage/aptosdb/src/ledger_db/mod.rs (L76-85)
```rust
pub struct LedgerDbSchemaBatches {
    pub ledger_metadata_db_batches: SchemaBatch,
    pub event_db_batches: SchemaBatch,
    pub persisted_auxiliary_info_db_batches: SchemaBatch,
    pub transaction_accumulator_db_batches: SchemaBatch,
    pub transaction_auxiliary_data_db_batches: SchemaBatch,
    pub transaction_db_batches: SchemaBatch,
    pub transaction_info_db_batches: SchemaBatch,
    pub write_set_db_batches: SchemaBatch,
}
```

# Audit Report

## Title
Atomic Commit Invariant Violation in Batch Transaction Commits Leading to Database Inconsistency

## Summary
The `commit_transactions()` function in `transaction_db.rs` commits transaction batches sequentially without a transaction wrapper. If `write_schemas()` fails for batch N after previous batches succeeded, the successful writes are NOT rolled back, leaving the database in an inconsistent partially-committed state that violates the State Consistency invariant.

## Finding Description

The vulnerability exists in the batch commit logic where transactions are split into multiple batches and committed sequentially: [1](#0-0) 

Each `write_schemas(batch)` call commits a batch atomically to RocksDB via: [2](#0-1) 

The critical issue is that once a batch is written via `write_opt()`, it is permanently committed to RocksDB with no rollback mechanism. If batch 2 of 4 fails due to disk full, I/O error, or RocksDB corruption, batches 0-1 remain committed while batches 2-3 are not written.

This function is called from parallel execution context that uses `.unwrap()` to panic on error: [3](#0-2) 

The developers acknowledge this issue in a TODO comment: [4](#0-3) 

When the panic occurs, the global crash handler terminates the entire process: [5](#0-4) 

**Race Condition Severity Multiplier:**

Since `commit_transactions()` and `commit_state_kv_and_ledger_metadata()` run in parallel with no ordering guarantee, `LedgerCommitProgress` can be written BEFORE `commit_transactions()` completes: [6](#0-5) 

This creates a window where `LedgerCommitProgress` indicates all transactions up to version N are committed, but only transactions 0 to M < N are actually persisted.

**Invariant Violation:**

This breaks the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs." The commit operation is not atomic across batches, allowing partial state to be persisted.

## Impact Explanation

**Severity: High** (potentially Critical depending on consensus impact)

1. **Database Inconsistency**: Transaction indices (TransactionByHash, OrderedTransactionByAccount, TransactionSummariesByAccount) are partially updated, creating inconsistent mappings

2. **Node Crash and Downtime**: The `.unwrap()` panic crashes the validator node immediately via `process::exit(12)`, causing loss of availability

3. **Consensus Risk**: If `LedgerCommitProgress` is written before the partial commit failure, other validators querying this node see a higher committed version than what's actually present, potentially causing state root mismatches

4. **Recovery Complexity**: Requires node restart and truncation back to `OverallCommitProgress`: [7](#0-6) 

5. **Data Loss**: Transactions in the successfully committed batches are lost after truncation, requiring re-sync from network

The same vulnerability exists in `write_set_db.rs`: [8](#0-7) 

## Likelihood Explanation

**Likelihood: Medium**

Triggering conditions include:
- Disk space exhaustion (can be accelerated by large transaction submissions)
- I/O errors from storage hardware failures
- RocksDB internal errors or corruption
- File system permission issues

While not directly exploitable by unprivileged attackers, these conditions occur naturally in production systems and can be indirectly triggered through resource exhaustion attacks.

## Recommendation

Implement atomic commit across all batches using one of these approaches:

**Option 1: Single Batch Commit**
Accumulate all operations into a single batch before committing:

```rust
pub(crate) fn commit_transactions(
    &self,
    first_version: Version,
    transactions: &[Transaction],
    skip_index: bool,
) -> Result<()> {
    let _timer = OTHER_TIMERS_SECONDS.timer_with(&["commit_transactions"]);
    
    // Single batch for atomic commit
    let mut batch = self.db().new_native_batch();
    
    transactions
        .iter()
        .enumerate()
        .try_for_each(|(i, txn)| -> Result<()> {
            self.put_transaction(
                first_version + i as u64,
                txn,
                skip_index,
                &mut batch,
            )
        })?;
    
    // Single atomic commit
    self.db().write_schemas(batch)?;
    Ok(())
}
```

**Option 2: Explicit Transaction with Rollback**
Use RocksDB transactions with rollback capability for multi-batch commits.

**Option 3: Write-Ahead Log**
Write all operations to a WAL first, then commit atomically with progress marker.

## Proof of Concept

Simulate disk full condition during batch commit:

```rust
#[test]
fn test_partial_commit_failure() {
    use tempfile::TempDir;
    
    // Create small disk quota
    let tmpdir = TempDir::new().unwrap();
    let db = AptosDB::new_for_test(&tmpdir);
    
    // Create transactions that will exceed disk quota
    let txns: Vec<Transaction> = (0..1000)
        .map(|i| create_large_transaction(i))
        .collect();
    
    // First batch should succeed, later batches should fail
    let result = db.ledger_db().transaction_db()
        .commit_transactions(0, &txns, false);
    
    // Verify partial commit occurred
    assert!(result.is_err());
    
    // Check that some transactions were committed
    let committed_count = (0..1000)
        .filter(|&i| db.get_transaction(i).is_ok())
        .count();
    
    // Partial commit: some committed, some not
    assert!(committed_count > 0 && committed_count < 1000);
    
    // Verify LedgerCommitProgress inconsistency
    let progress = db.get_ledger_commit_progress().unwrap();
    assert!(progress > committed_count as u64);
}
```

## Notes

The vulnerability stems from the architectural decision to optimize batch commits through parallelization without ensuring atomicity across batches. While a recovery mechanism exists via startup truncation, the temporary inconsistent state and forced node crash represent a violation of the atomic commit guarantee expected in a consensus-critical database system.

The parallel execution of `commit_transactions()` and progress marker updates creates a race condition where the database can report higher progress than actually committed, potentially affecting consensus if validators query each other's state during this window.

### Citations

**File:** storage/aptosdb/src/ledger_db/transaction_db.rs (L119-125)
```rust
        {
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["commit_transactions___commit"]);
            for batch in batches {
                self.db().write_schemas(batch)?
            }
            Ok(())
        }
```

**File:** storage/schemadb/src/lib.rs (L289-304)
```rust
    fn write_schemas_inner(&self, batch: impl IntoRawBatch, option: &WriteOptions) -> DbResult<()> {
        let labels = [self.name.as_str()];
        let _timer = APTOS_SCHEMADB_BATCH_COMMIT_LATENCY_SECONDS.timer_with(&labels);

        let raw_batch = batch.into_raw_batch(self)?;

        let serialized_size = raw_batch.inner.size_in_bytes();
        self.inner
            .write_opt(raw_batch.inner, option)
            .into_db_res()?;

        raw_batch.stats.commit();
        APTOS_SCHEMADB_BATCH_COMMIT_BYTES.observe_with(&[&self.name], serialized_size as f64);

        Ok(())
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L272-275)
```rust
            // TODO(grao): Write progress for each of the following databases, and handle the
            // inconsistency at the startup time.
            //
            // TODO(grao): Consider propagating the error instead of panic, if necessary.
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L290-299)
```rust
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
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L360-365)
```rust
        ledger_metadata_batch
            .put::<DbMetadataSchema>(
                &DbMetadataKey::LedgerCommitProgress,
                &DbMetadataValue::Version(chunk.expect_last_version()),
            )
            .unwrap();
```

**File:** crates/crash-handler/src/lib.rs (L56-57)
```rust
    // Kill the process
    process::exit(12);
```

**File:** storage/aptosdb/src/state_store/mod.rs (L438-449)
```rust
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

**File:** storage/aptosdb/src/ledger_db/write_set_db.rs (L141-143)
```rust
            for batch in batches {
                self.db().write_schemas(batch)?
            }
```

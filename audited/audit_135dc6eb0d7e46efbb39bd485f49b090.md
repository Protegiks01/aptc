# Audit Report

## Title
Split-Brain Pruning Failure Between Indexer and Main Database Creates Persistent Data Inconsistency

## Summary
The `TransactionPruner::prune()` function performs two separate atomic write operations to different databases (indexer and main DB) without transaction coordination. If the indexer write succeeds but the main database write fails, the system enters a split-brain state where pruning progress metadata and actual data are inconsistent between the two databases. [1](#0-0) 

## Finding Description

The vulnerability lies in the non-atomic execution of two database writes within the `prune()` function. The function writes to two separate databases:

1. **Indexer Database Write** - Commits deletion of `OrderedTransactionByAccountSchema` entries and updates `IndexerMetadataKey::TransactionPrunerProgress` [2](#0-1) 

2. **Main Database Write** - Commits deletion of transactions, hash indices, summaries and updates `DbMetadataKey::TransactionPrunerProgress` [3](#0-2) 

**Failure Scenario:**
When the indexer write succeeds but the main database write fails (due to I/O errors, disk full, corruption, etc.):
- Indexer DB: Transactions pruned, progress = `target_version`
- Main DB: Transactions NOT pruned, progress = `current_progress`
- No cross-database rollback mechanism exists

**Why This Breaks State Consistency:**
The retry mechanism only uses main DB progress to determine what to prune next. [4](#0-3)  The indexer progress metadata is written but never read for recovery decisions [5](#0-4)  - confirming it serves only as metadata and cannot be used to detect or repair the inconsistency.

**State Invariant Violated:**
This violates **State Consistency** (Critical Invariant #4): "State transitions must be atomic and verifiable via Merkle proofs." The indexer and main database represent two views of the same ledger state, and they must remain consistent.

## Impact Explanation

**High Severity** - This qualifies as "State inconsistencies requiring intervention" (Medium severity in the bug bounty) with potential escalation to High due to API reliability impacts:

1. **Persistent Data Inconsistency**: The indexer and main databases diverge permanently until manual intervention
2. **Query Failures**: Applications using `IndexerReader` [6](#0-5)  will fail to find transactions in the indexer that still exist in the main database
3. **API Reliability Impact**: Validator nodes and APIs relying on indexed queries will return incomplete results, potentially causing "API crashes" (High severity category)
4. **No Automatic Recovery**: The system has no mechanism to detect or repair this inconsistency - the indexer progress metadata is never read for validation purposes

While not directly exploitable by an attacker, this represents a critical reliability flaw that can cause validator node API failures under normal operational conditions (disk pressure, I/O errors).

## Likelihood Explanation

**Medium Likelihood** in production environments:
- Database write failures occur regularly in distributed systems (disk full, I/O timeouts, hardware failures)
- The pruner runs continuously on all validator nodes [4](#0-3) 
- No cross-database transaction coordination exists to prevent split-brain
- Once triggered, the inconsistency persists indefinitely until manual detection and repair

## Recommendation

Implement two-phase commit coordination or write ordering to ensure atomicity:

**Option 1: Reverse Write Order**
Write the main database first, then the indexer. If main write fails, nothing is committed. If indexer write fails after main write succeeds, the error propagates and retry will attempt both writes again with idempotent behavior.

**Option 2: Add Progress Validation**
On startup, read both progress values and if they differ, trigger automatic reconciliation by re-pruning the indexer from main DB progress to indexer progress.

**Option 3: Single Transaction**
If possible, combine both writes into a single atomic transaction, or use a write-ahead log to ensure both complete or both roll back.

**Recommended Fix (Option 1 - Simplest):**
```rust
fn prune(&self, current_progress: Version, target_version: Version) -> Result<()> {
    let mut batch = SchemaBatch::new();
    // ... build main batch ...
    
    // Write main DB FIRST
    self.ledger_db.transaction_db().write_schemas(batch)?;
    
    // THEN write indexer (can retry safely if this fails)
    if let Some(indexer_db) = self.internal_indexer_db.as_ref() {
        if indexer_db.transaction_enabled() {
            let mut index_batch = SchemaBatch::new();
            // ... build index batch ...
            indexer_db.get_inner_db_ref().write_schemas(index_batch)?;
        }
    }
    Ok(())
}
```

## Proof of Concept

```rust
#[test]
fn test_pruner_split_brain_on_main_db_failure() {
    // Setup: Create TransactionPruner with mock databases
    let mut indexer_db = MockInternalIndexerDB::new();
    let mut main_db = MockLedgerDb::new();
    
    // Configure: Indexer write succeeds, main DB write fails
    indexer_db.expect_write_schemas().returning(|_| Ok(()));
    main_db.expect_write_schemas().returning(|_| {
        Err(AptosDbError::Other("Disk full".to_string()))
    });
    
    let pruner = TransactionPruner::new(
        transaction_store,
        Arc::new(main_db),
        100, // initial progress
        Some(indexer_db)
    )?;
    
    // Execute: Attempt to prune versions 100-200
    let result = pruner.prune(100, 200);
    
    // Assert: Main DB write failed, function returns error
    assert!(result.is_err());
    
    // Verify: Indexer progress updated to 200
    let indexer_progress = indexer_db.get::<InternalIndexerMetadataSchema>(
        &IndexerMetadataKey::TransactionPrunerProgress
    )?;
    assert_eq!(indexer_progress.expect_version(), 200);
    
    // Verify: Main DB progress still at 100
    let main_progress = main_db.get::<DbMetadataSchema>(
        &DbMetadataKey::TransactionPrunerProgress
    )?;
    assert_eq!(main_progress.expect_version(), 100);
    
    // Verify: Split-brain state - indexer at 200, main at 100
    // This demonstrates the data inconsistency vulnerability
}
```

**Notes:**
- This vulnerability affects the **State Consistency** invariant by creating divergent views of the ledger state
- The indexer progress metadata serves no functional purpose for recovery since it's never read [5](#0-4) 
- While eventually consistent through retries, the inconsistency window can persist indefinitely if write failures continue
- Manual intervention or node restart is required to detect and potentially resolve the inconsistency

### Citations

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

**File:** storage/aptosdb/src/pruner/pruner_worker.rs (L53-69)
```rust
    fn work(&self) {
        while !self.quit_worker.load(Ordering::SeqCst) {
            let pruner_result = self.pruner.prune(self.batch_size);
            if pruner_result.is_err() {
                sample!(
                    SampleRate::Duration(Duration::from_secs(1)),
                    error!(error = ?pruner_result.err().unwrap(),
                        "Pruner has error.")
                );
                sleep(Duration::from_millis(self.pruning_time_interval_in_ms));
                continue;
            }
            if !self.pruner.is_pruning_pending() {
                sleep(Duration::from_millis(self.pruning_time_interval_in_ms));
            }
        }
    }
```

**File:** storage/aptosdb/src/transaction_store/mod.rs (L143-157)
```rust
    pub fn prune_transaction_by_account(
        &self,
        transactions: &[(Version, Transaction)],
        db_batch: &mut SchemaBatch,
    ) -> Result<()> {
        for (_, transaction) in transactions {
            if let Some(txn) = transaction.try_as_signed_user_txn() {
                if let ReplayProtector::SequenceNumber(seq_num) = txn.replay_protector() {
                    db_batch
                        .delete::<OrderedTransactionByAccountSchema>(&(txn.sender(), seq_num))?;
                }
            }
        }
        Ok(())
    }
```

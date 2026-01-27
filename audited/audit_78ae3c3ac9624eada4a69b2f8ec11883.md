# Audit Report

## Title
Non-Atomic Cross-Database Pruning Causes Transient Index-Ledger Inconsistency in Transaction Pruner

## Summary
The `TransactionPruner::prune()` function performs sequential writes to two separate databases (indexer DB at line 67, ledger DB at line 73) without atomicity guarantees. If the indexer write succeeds but the ledger write fails, queries will temporarily return incorrect results as the index indicates data has been pruned while the actual transaction data remains in the ledger. [1](#0-0) 

## Finding Description

When the internal indexer is enabled with transaction indexing, the pruning operation maintains transaction indices in a separate database from the main ledger data. The `prune()` function performs two critical writes:

1. **Line 67**: Writes to indexer DB, deleting `OrderedTransactionByAccountSchema` entries and updating indexer's `TransactionPrunerProgress`
2. **Line 73**: Writes to ledger DB, deleting `TransactionSchema`, `TransactionByHashSchema`, and other data, plus updating ledger's `TransactionPrunerProgress` [2](#0-1) 

These are separate RocksDB instances with no cross-database transaction mechanism. The `write_schemas` method provides atomicity only within a single database. [3](#0-2) 

**Failure Scenario:**
- Indexer write succeeds → `OrderedTransactionByAccountSchema` entries deleted, progress marker advanced
- Ledger write fails (disk I/O error, out of space, etc.) → Transaction data remains, progress marker not updated
- Query arrives via `IndexerReaders.get_account_ordered_transactions` [4](#0-3) 

The indexer's `get_account_ordered_transactions_iter` reads from the indexer DB, finding no entries (already pruned), while the ledger still contains the transaction data. [5](#0-4) 

This violates the **State Consistency** invariant: the index claims transactions don't exist while the ledger data contradicts this.

## Impact Explanation

**Severity: Medium** - "State inconsistencies requiring intervention"

During the inconsistency window:
- API queries return incomplete/incorrect transaction lists for accounts
- Block explorers show missing transactions
- Wallets cannot locate historical transactions via index
- State is inconsistent between index and ledger databases

The pruner worker automatically retries on failure with a 1ms sleep interval, providing eventual self-correction. [6](#0-5) 

However, if write failures persist (sustained disk issues), the inconsistency window extends until manual intervention (fixing underlying hardware issue, node restart with catch-up mechanism). [7](#0-6) 

## Likelihood Explanation

**Likelihood: Low to Moderate**

This requires:
1. Internal indexer enabled with transaction indexing (configuration-dependent)
2. Pruning active (normal operation on mature nodes)
3. Write failure after successful indexer write (disk full, I/O errors, hardware issues)
4. Query during inconsistency window (1ms typical, longer if failures persist)

While not directly exploitable by unprivileged attackers (cannot cause disk failures), it represents an operational reliability issue that manifests under adverse hardware conditions. The transient nature and automatic retry mechanism limit the impact window.

## Recommendation

Implement one of these approaches:

**Option 1: Write Order Reversal** - Write to ledger DB first, then indexer DB. If ledger fails, indexer remains consistent. If indexer fails after ledger succeeds, the retry will attempt to re-prune ledger entries (safe no-ops in RocksDB) and complete the indexer pruning.

**Option 2: Progress Synchronization** - Update both progress markers only after both writes succeed:

```rust
// Perform writes but don't update progress markers yet
if let Some(indexer_db) = self.internal_indexer_db.as_ref() {
    if indexer_db.transaction_enabled() {
        let mut index_batch = SchemaBatch::new();
        self.transaction_store
            .prune_transaction_by_account(&candidate_transactions, &mut index_batch)?;
        // Don't update progress here
        indexer_db.get_inner_db_ref().write_schemas(index_batch)?;
    }
}

// Write ledger data
self.ledger_db.transaction_db().write_schemas(batch)?;

// Only update progress markers after both writes succeed
let mut progress_batch = SchemaBatch::new();
progress_batch.put::<DbMetadataSchema>(
    &DbMetadataKey::TransactionPrunerProgress,
    &DbMetadataValue::Version(target_version),
)?;
self.ledger_db.transaction_db().write_schemas(progress_batch)?;

if let Some(indexer_db) = self.internal_indexer_db.as_ref() {
    if indexer_db.transaction_enabled() {
        let mut index_progress_batch = SchemaBatch::new();
        index_progress_batch.put::<InternalIndexerMetadataSchema>(
            &IndexerMetadataKey::TransactionPrunerProgress,
            &IndexerMetadataValue::Version(target_version),
        )?;
        indexer_db.get_inner_db_ref().write_schemas(index_progress_batch)?;
    }
}
```

**Option 3: Consistency Check** - Before serving queries, verify indexer progress hasn't exceeded ledger progress. Reject queries or fallback to ledger-only paths if inconsistency detected.

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_temppath::TempPath;
    use std::sync::Arc;
    
    #[test]
    fn test_pruner_cross_db_inconsistency() {
        // Setup: Create TransactionPruner with internal indexer enabled
        let tmpdir = TempPath::new();
        let ledger_db = Arc::new(LedgerDb::new(&tmpdir, ...));
        let indexer_db_path = TempPath::new();
        let internal_indexer_db = Some(InternalIndexerDB::new(..., 
            InternalIndexerDBConfig { enable_transaction: true, ... }));
        
        let transaction_store = Arc::new(TransactionStore::new(ledger_db.clone()));
        let pruner = TransactionPruner::new(
            transaction_store,
            ledger_db.clone(),
            0,
            internal_indexer_db.clone()
        ).unwrap();
        
        // Commit test transactions at versions 100-200
        // ...commit_test_transactions(100, 200)...
        
        // Simulate partial failure: 
        // Mock ledger_db.transaction_db().write_schemas() to return error
        // while indexer DB write succeeds
        
        // Inject fault after indexer write but before ledger write
        let result = pruner.prune(100, 200);
        assert!(result.is_err()); // Ledger write failed
        
        // Verify inconsistency:
        // 1. Indexer DB progress should be 200 (write succeeded)
        let indexer_progress = internal_indexer_db.unwrap()
            .get_inner_db_ref()
            .get::<InternalIndexerMetadataSchema>(&IndexerMetadataKey::TransactionPrunerProgress)
            .unwrap()
            .unwrap()
            .expect_version();
        assert_eq!(indexer_progress, 200);
        
        // 2. Ledger DB progress should still be 100 (write failed)
        let ledger_progress = ledger_db.transaction_db_raw()
            .get::<DbMetadataSchema>(&DbMetadataKey::TransactionPrunerProgress)
            .unwrap()
            .unwrap()
            .expect_version();
        assert_eq!(ledger_progress, 100);
        
        // 3. Query via indexer returns no results (entries pruned)
        let indexer_results = internal_indexer_db.unwrap()
            .get_account_ordered_transactions_iter(test_address, 0, 100, 200)
            .unwrap()
            .collect::<Vec<_>>();
        assert!(indexer_results.is_empty()); // Index says "no transactions"
        
        // 4. But ledger still has the data
        let ledger_txn = ledger_db.transaction_db().get_transaction(150).unwrap();
        assert!(ledger_txn.is_some()); // Data still exists!
        
        // This demonstrates the inconsistency: index says no data, ledger has data
    }
}
```

**Notes:**
- This is a transient consistency issue with automatic recovery via retry mechanism
- Primary concern is operational reliability during hardware failures rather than exploitable attack vector
- Impact is bounded by retry latency (typically 1ms) but can extend under persistent failures
- Affects query correctness but not consensus safety or fund security

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

**File:** storage/aptosdb/src/ledger_db/transaction_db.rs (L51-53)
```rust
    pub(crate) fn write_schemas(&self, batch: SchemaBatch) -> Result<()> {
        self.db.write_schemas(batch)
    }
```

**File:** storage/indexer/src/indexer_reader.rs (L116-138)
```rust
    fn get_account_ordered_transactions(
        &self,
        address: AccountAddress,
        start_seq_num: u64,
        limit: u64,
        include_events: bool,
        ledger_version: Version,
    ) -> anyhow::Result<AccountOrderedTransactionsWithProof> {
        if let Some(db_indexer_reader) = &self.db_indexer_reader {
            if db_indexer_reader.indexer_db.transaction_enabled() {
                return Ok(db_indexer_reader.get_account_ordered_transactions(
                    address,
                    start_seq_num,
                    limit,
                    include_events,
                    ledger_version,
                )?);
            } else {
                anyhow::bail!("Interal transaction by account index is not enabled")
            }
        }
        anyhow::bail!("DB indexer reader is not available")
    }
```

**File:** storage/indexer/src/db_indexer.rs (L174-191)
```rust
    pub fn get_account_ordered_transactions_iter(
        &self,
        address: AccountAddress,
        min_seq_num: u64,
        num_versions: u64,
        ledger_version: Version,
    ) -> Result<AccountOrderedTransactionsIter<'_>> {
        let mut iter = self.db.iter::<OrderedTransactionByAccountSchema>()?;
        iter.seek(&(address, min_seq_num))?;
        Ok(AccountOrderedTransactionsIter::new(
            iter,
            address,
            min_seq_num
                .checked_add(num_versions)
                .ok_or(AptosDbError::TooManyRequested(min_seq_num, num_versions))?,
            ledger_version,
        ))
    }
```

**File:** storage/aptosdb/src/pruner/pruner_worker.rs (L53-68)
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
```

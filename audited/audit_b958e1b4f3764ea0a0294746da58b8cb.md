# Audit Report

## Title
State Inconsistency Between Indexer and Ledger Pruning Causing Query Failures

## Summary
The `TransactionPruner::prune()` function performs non-atomic writes to the indexer database and ledger database separately. If the indexer write succeeds but the ledger write fails, the indexer's pruner progress advances ahead of the ledger's progress, causing `get_account_ordered_transactions()` queries to return incomplete results for transactions that should still be available according to `min_readable_version`. [1](#0-0) 

## Finding Description
The vulnerability exists in the write ordering within the pruning operation. When transaction indexing is enabled, the pruner executes two separate database writes:

1. **Indexer database write** - Prunes transaction-by-account mappings and updates `IndexerMetadataKey::TransactionPrunerProgress`
2. **Ledger database write** - Prunes transaction data and updates `DbMetadataKey::TransactionPrunerProgress`

These writes are not wrapped in a distributed transaction, making the operation non-atomic across databases.

**Failure Scenario:**
When the indexer write succeeds but the ledger write fails (due to disk I/O error, disk full, or process crash), the system enters an inconsistent state:

- Indexer has deleted `OrderedTransactionByAccountSchema` entries for pruned versions
- Indexer metadata reports pruning up to `target_version`
- Ledger still contains transaction data for those versions
- Ledger metadata reports pruning only up to `current_progress` (< `target_version`)

**Query Impact:**
The `LedgerPrunerManager` exposes `min_readable_version` via `get_first_txn_version()`, which is calculated from the **ledger's** pruner progress, not the indexer's. [2](#0-1) 

However, `get_account_ordered_transactions()` queries the indexer's `OrderedTransactionByAccountSchema` without validating against `min_readable_version`: [3](#0-2) 

The indexer implementation also lacks this validation: [4](#0-3) 

This is inconsistent with other query methods like `get_transaction_outputs()` which properly validate against `min_readable_version`: [5](#0-4) [6](#0-5) 

**Exploitation Path:**
1. Node runs with pruning enabled (prune_window = 1000 versions)
2. Current state: ledger_version = 2000, min_readable_version = 1000
3. Pruner attempts to prune versions 1000-1099 (target_version = 1100)
4. Indexer write completes successfully - mappings deleted, metadata updated to 1100
5. Ledger write fails - transaction data remains, metadata stays at 1000
6. Client calls `get_first_txn_version()` → returns 1000 (from ledger metadata)
7. Client calls `get_account_ordered_transactions(address=0x123, start_seq_num=5, limit=10)`
8. Query bypasses min_readable_version check
9. Indexer lookup returns empty (mappings already deleted)
10. Client receives 0 transactions instead of expected 10 transactions

This breaks the **State Consistency** invariant that "State transitions must be atomic and verifiable."

## Impact Explanation
**Severity: Medium**

This qualifies as **Medium Severity** under the Aptos Bug Bounty program's "State inconsistencies requiring intervention" category.

**Impacts:**
- **Data Availability**: Clients receive incomplete query results for transactions within the supposedly available range
- **Application Failures**: Wallets, block explorers, and other applications may malfunction due to missing transaction history
- **User Experience**: Users cannot view their complete transaction history even when data should be available
- **Operational Overhead**: Requires either waiting for self-healing on next prune or manual intervention

The system does self-heal on the next pruning cycle, as the pruner reads progress from the ledger database and re-attempts pruning: [7](#0-6) 

However, the inconsistency window can persist for an extended period depending on pruning frequency.

## Likelihood Explanation
**Likelihood: Medium to High in Production Environments**

The failure condition (indexer write succeeds, ledger write fails) can occur through:
- **Disk I/O errors**: Hardware failures, filesystem corruption
- **Disk space exhaustion**: Separate databases on different volumes with different space constraints
- **Process crashes**: Node killed during pruning operation
- **Database errors**: RocksDB internal errors, lock timeouts

These are realistic production scenarios that occur naturally without attacker intervention. In large-scale blockchain deployments with thousands of nodes, such failures are statistically likely over time.

## Recommendation
Implement atomic pruning across both databases by:

1. **Two-Phase Commit Pattern**: Prepare both batches, write indexer, then write ledger. On ledger write failure, implement rollback for indexer.

2. **Unified Progress Tracking**: Store a single pruner progress value that both indexer and ledger respect, or read indexer progress on recovery.

3. **Validation on Query**: Add `min_readable_version` validation to `get_account_ordered_transactions()`:

```rust
fn get_account_ordered_transactions(
    &self,
    address: AccountAddress,
    start_seq_num: u64,
    limit: u64,
    include_events: bool,
    ledger_version: Version,
) -> Result<AccountOrderedTransactionsWithProof> {
    gauged_api("get_account_ordered_transactions", || {
        ensure!(
            !self.state_kv_db.enabled_sharding(),
            "This API is not supported with sharded DB"
        );
        error_if_too_many_requested(limit, MAX_REQUEST_LIMIT)?;

        let txns_with_proofs = self
            .transaction_store
            .get_account_ordered_transactions_iter(
                address,
                start_seq_num,
                limit,
                ledger_version,
            )?
            .map(|result| {
                let (_seq_num, txn_version) = result?;
                // Add validation here
                self.error_if_ledger_pruned("Transaction", txn_version)?;
                self.get_transaction_with_proof(txn_version, ledger_version, include_events)
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(AccountOrderedTransactionsWithProof::new(txns_with_proofs))
    })
}
```

4. **Reverse Write Order**: Write ledger first, then indexer (though this doesn't fully solve atomicity).

## Proof of Concept
```rust
#[cfg(test)]
mod test_pruner_inconsistency {
    use super::*;
    use aptos_temppath::TempPath;
    use aptos_types::transaction::Transaction;
    
    #[test]
    fn test_indexer_ledger_inconsistency_on_failure() {
        // Setup: Create DB with transactions
        let tmpdir = TempPath::new();
        let db = AptosDB::new_for_test(&tmpdir);
        
        // Insert transactions 0-200
        for version in 0..=200 {
            let txn = create_test_transaction(version);
            db.save_transactions(...);
        }
        
        // Enable pruning with window 100
        let pruner = TransactionPruner::new(...);
        
        // Simulate indexer write success, ledger write failure
        // by injecting failure into ledger DB write_schemas
        
        // Step 1: Prune from 0 to 100
        pruner.prune(0, 100).expect_err("Simulated failure");
        
        // Verify inconsistent state:
        // - Indexer metadata shows progress = 100
        let indexer_progress = indexer_db
            .get::<InternalIndexerMetadataSchema>(&IndexerMetadataKey::TransactionPrunerProgress)
            .unwrap()
            .expect_version();
        assert_eq!(indexer_progress, 100);
        
        // - Ledger metadata shows progress = 0
        let ledger_progress = ledger_db
            .get::<DbMetadataSchema>(&DbMetadataKey::TransactionPrunerProgress)
            .unwrap()
            .expect_version();
        assert_eq!(ledger_progress, 0);
        
        // - min_readable_version reports 0 (from ledger)
        let min_readable = db.get_first_txn_version().unwrap();
        assert_eq!(min_readable, Some(0));
        
        // Step 2: Query for account transactions in range [50-60]
        let result = db.get_account_ordered_transactions(
            test_account_address(),
            5, // start_seq_num
            10, // limit
            false,
            200, // ledger_version
        ).unwrap();
        
        // VULNERABILITY: Query returns 0 transactions even though
        // min_readable_version = 0 indicates they should be available
        assert_eq!(result.len(), 0, "Indexer has pruned mappings");
        
        // The transaction data is still in ledger:
        let txn_50 = db.get_transaction_by_version(50, 200, false).unwrap();
        assert!(txn_50.is_some(), "Transaction data still exists in ledger");
    }
}
```

## Notes
The vulnerability is real but requires system-level failure to trigger naturally. The impact is data inconsistency rather than direct security compromise. The system self-heals on the next pruning cycle, but the inconsistency window can cause user-facing application failures and operational issues.

### Citations

**File:** storage/aptosdb/src/pruner/ledger_pruner/transaction_pruner.rs (L58-73)
```rust
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
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/transaction_pruner.rs (L84-88)
```rust
        let progress = get_or_initialize_subpruner_progress(
            ledger_db.transaction_db_raw(),
            &DbMetadataKey::TransactionPrunerProgress,
            metadata_progress,
        )?;
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/ledger_pruner_manager.rs (L48-50)
```rust
    fn get_min_readable_version(&self) -> Version {
        self.min_readable_version.load(Ordering::SeqCst)
    }
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L164-195)
```rust
    fn get_account_ordered_transactions(
        &self,
        address: AccountAddress,
        start_seq_num: u64,
        limit: u64,
        include_events: bool,
        ledger_version: Version,
    ) -> Result<AccountOrderedTransactionsWithProof> {
        gauged_api("get_account_ordered_transactions", || {
            ensure!(
                !self.state_kv_db.enabled_sharding(),
                "This API is not supported with sharded DB"
            );
            error_if_too_many_requested(limit, MAX_REQUEST_LIMIT)?;

            let txns_with_proofs = self
                .transaction_store
                .get_account_ordered_transactions_iter(
                    address,
                    start_seq_num,
                    limit,
                    ledger_version,
                )?
                .map(|result| {
                    let (_seq_num, txn_version) = result?;
                    self.get_transaction_with_proof(txn_version, ledger_version, include_events)
                })
                .collect::<Result<Vec<_>>>()?;

            Ok(AccountOrderedTransactionsWithProof::new(txns_with_proofs))
        })
    }
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L387-387)
```rust
            self.error_if_ledger_pruned("Transaction", start_version)?;
```

**File:** storage/indexer/src/db_indexer.rs (L586-612)
```rust
    pub fn get_account_ordered_transactions(
        &self,
        address: AccountAddress,
        start_seq_num: u64,
        limit: u64,
        include_events: bool,
        ledger_version: Version,
    ) -> Result<AccountOrderedTransactionsWithProof> {
        self.indexer_db
            .ensure_cover_ledger_version(ledger_version)?;
        error_if_too_many_requested(limit, MAX_REQUEST_LIMIT)?;

        let txns_with_proofs = self
            .indexer_db
            .get_account_ordered_transactions_iter(address, start_seq_num, limit, ledger_version)?
            .map(|result| {
                let (_seq_num, txn_version) = result?;
                self.main_db_reader.get_transaction_by_version(
                    txn_version,
                    ledger_version,
                    include_events,
                )
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(AccountOrderedTransactionsWithProof::new(txns_with_proofs))
    }
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

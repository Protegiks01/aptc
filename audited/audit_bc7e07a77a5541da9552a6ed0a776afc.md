# Audit Report

## Title
Transaction Pruner Silently Skips Missing Transactions Leading to Database Inconsistency

## Summary
The `get_pruning_candidate_transactions()` function in the transaction pruner does not validate that all transaction versions in the range [start, end) are present. When gaps exist due to database corruption, the function silently skips missing transactions without detection or reporting, leading to incomplete pruning and orphaned database indices.

## Finding Description

The transaction pruner's `get_pruning_candidate_transactions()` function iterates through transactions in a version range but does not verify version continuity. [1](#0-0) 

In contrast, other transaction retrieval functions in the codebase use the `expect_continuous_versions` trait to detect gaps. [2](#0-1) 

The `ContinuousVersionIter` implementation enforces strict version ordering and fails when gaps are detected. [3](#0-2) 

When the pruner encounters gaps, it proceeds with incomplete data:
1. `prune_transaction_by_hash_indices` only prunes hashes for found transactions [4](#0-3) 
2. `prune_transactions` attempts to delete all versions in the range [5](#0-4) 
3. `prune_transaction_summaries_by_account` only prunes summaries for found transactions [6](#0-5) 
4. Pruner progress is updated as if the full range was processed [7](#0-6) 

This creates orphaned indices (TransactionByHashSchema, TransactionSummariesByAccountSchema, OrderedTransactionByAccountSchema) that persist in the database when their corresponding transaction data is missing or deleted.

## Impact Explanation

This issue qualifies as **Medium severity** under the Aptos bug bounty criteria for "State inconsistencies requiring intervention." The impact includes:

- **Database Integrity Violation**: Orphaned indices remain queryable but point to non-existent transaction data
- **Resource Exhaustion**: Accumulated orphaned indices cause database bloat over time
- **Query Inconsistencies**: Hash-based and account-based transaction lookups return incorrect results
- **Operational Burden**: Requires manual database cleanup or recovery procedures

The issue does not directly impact consensus, fund security, or network availability, limiting its severity to Medium.

## Likelihood Explanation

The likelihood is **Low to Medium**:

**Mitigating Factors:**
- Normal transaction commits have gap detection via `pre_commit_validation` [8](#0-7) 
- The codebase explicitly acknowledges gap risks in commit operations [9](#0-8) 

**Potential Triggers:**
- Physical disk corruption or hardware failures
- Software bugs causing partial transaction writes
- Node crashes during specific database operations
- Race conditions in parallel database operations

While the system prevents gaps during normal operation, if corruption occurs through other means, this vulnerability ensures the issue propagates silently through the pruning process.

## Recommendation

Implement gap detection in `get_pruning_candidate_transactions()` using the existing `expect_continuous_versions` mechanism:

```rust
fn get_pruning_candidate_transactions(
    &self,
    start: Version,
    end: Version,
) -> Result<Vec<(Version, Transaction)>> {
    ensure!(end >= start, "{} must be >= {}", end, start);

    let num_transactions = (end - start) as usize;
    let mut iter = self
        .ledger_db
        .transaction_db_raw()
        .iter::<TransactionSchema>()?;
    iter.seek(&start)?;
    
    // Use expect_continuous_versions to detect gaps
    let txn_iter = iter.expect_continuous_versions(start, num_transactions)?;
    
    let mut txns = Vec::with_capacity(num_transactions);
    for txn_result in txn_iter {
        let txn = txn_result?;
        txns.push((start + txns.len() as u64, txn));
    }

    Ok(txns)
}
```

This ensures that any gaps in the transaction range are detected and reported as errors, preventing silent corruption propagation. The pruner error handling will log the issue and prevent progress marker updates. [10](#0-9) 

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use aptos_temppath::TempPath;
    use crate::AptosDB;
    use aptos_types::transaction::{Transaction, Version};
    use aptos_schemadb::SchemaBatch;

    #[test]
    fn test_pruner_detects_transaction_gaps() {
        let tmp_dir = TempPath::new();
        let db = AptosDB::new_for_test(&tmp_dir);
        
        // Write transactions at versions 0, 1, 2, 4, 5 (gap at version 3)
        let mut batch = SchemaBatch::new();
        for version in [0, 1, 2, 4, 5] {
            let txn = Transaction::StateCheckpoint(Default::default());
            db.ledger_db.transaction_db().put_transaction(
                version, &txn, true, &mut batch
            ).unwrap();
        }
        db.ledger_db.transaction_db().write_schemas(batch).unwrap();
        
        // Create pruner and attempt to get candidates for range [0, 6)
        let pruner = TransactionPruner::new(
            Arc::clone(&db.transaction_store),
            Arc::clone(&db.ledger_db),
            0,
            None,
        ).unwrap();
        
        let result = pruner.get_pruning_candidate_transactions(0, 6);
        
        // Current behavior: Returns 5 transactions (gap at version 3 is silently skipped)
        // Expected behavior: Should return an error detecting the gap
        assert!(result.is_ok()); // Current: passes (BUG)
        let txns = result.unwrap();
        assert_eq!(txns.len(), 5); // Only 5 txns returned instead of 6 (gap silently skipped)
        
        // Verify the gap: version 3 is missing
        let versions: Vec<Version> = txns.iter().map(|(v, _)| *v).collect();
        assert_eq!(versions, vec![0, 1, 2, 4, 5]); // Version 3 is missing
        
        // This demonstrates that pruning would be incomplete:
        // - Indices for version 3 would not be pruned
        // - But the pruner would mark progress as if [0, 6) was fully pruned
    }
}
```

## Notes

This vulnerability represents a **defensive programming gap** rather than a directly exploitable attack vector. While unprivileged attackers cannot directly cause database corruption to create transaction gaps, the lack of gap detection in the pruner means that if corruption occurs through any means (hardware failure, software bugs, operational errors), the issue propagates silently through the system.

The fix aligns the pruner's behavior with the rest of the codebase's transaction handling, which consistently uses `expect_continuous_versions` for gap detection. This improvement enhances database integrity guarantees and operational reliability of Aptos validators.

### Citations

**File:** storage/aptosdb/src/pruner/ledger_pruner/transaction_pruner.rs (L41-46)
```rust
        self.ledger_db
            .transaction_db()
            .prune_transaction_by_hash_indices(
                candidate_transactions.iter().map(|(_, txn)| txn.hash()),
                &mut batch,
            )?;
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/transaction_pruner.rs (L54-57)
```rust
        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::TransactionPrunerProgress,
            &DbMetadataValue::Version(target_version),
        )?;
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

**File:** storage/aptosdb/src/ledger_db/transaction_db.rs (L63-71)
```rust
    pub(crate) fn get_transaction_iter(
        &self,
        start_version: Version,
        num_transactions: usize,
    ) -> Result<impl Iterator<Item = Result<Transaction>> + '_> {
        let mut iter = self.db.iter::<TransactionSchema>()?;
        iter.seek(&start_version)?;
        iter.expect_continuous_versions(start_version, num_transactions)
    }
```

**File:** storage/aptosdb/src/ledger_db/transaction_db.rs (L116-125)
```rust
        // Commit batches one by one for now because committing them in parallel will cause gaps. Although
        // it might be acceptable because we are writing the progress, we want to play on the safer
        // side unless this really becomes the bottleneck on production.
        {
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["commit_transactions___commit"]);
            for batch in batches {
                self.db().write_schemas(batch)?
            }
            Ok(())
        }
```

**File:** storage/aptosdb/src/ledger_db/transaction_db.rs (L169-179)
```rust
    pub(crate) fn prune_transactions(
        &self,
        begin: Version,
        end: Version,
        db_batch: &mut SchemaBatch,
    ) -> Result<()> {
        for version in begin..end {
            db_batch.delete::<TransactionSchema>(&version)?;
        }
        Ok(())
    }
```

**File:** storage/aptosdb/src/utils/iterators.rs (L40-62)
```rust
    fn next_impl(&mut self) -> Result<Option<T>> {
        if self.expected_next_version >= self.end_version {
            return Ok(None);
        }

        let ret = match self.inner.next().transpose()? {
            Some((version, transaction)) => {
                ensure!(
                    version == self.expected_next_version,
                    "{} iterator: first version {}, expecting version {}, got {} from underlying iterator.",
                    std::any::type_name::<T>(),
                    self.first_version,
                    self.expected_next_version,
                    version,
                );
                self.expected_next_version += 1;
                Some(transaction)
            },
            None => None,
        };

        Ok(ret)
    }
```

**File:** storage/aptosdb/src/transaction_store/mod.rs (L159-171)
```rust
    pub fn prune_transaction_summaries_by_account(
        &self,
        transactions: &[(Version, Transaction)],
        db_batch: &mut SchemaBatch,
    ) -> Result<()> {
        for (version, transaction) in transactions {
            if let Some(txn) = transaction.try_as_signed_user_txn() {
                db_batch
                    .delete::<TransactionSummariesByAccountSchema>(&(txn.sender(), *version))?;
            }
        }
        Ok(())
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L247-262)
```rust

        ensure!(!chunk.is_empty(), "chunk is empty, nothing to save.");

        let next_version = self.state_store.current_state_locked().next_version();
        // Ensure the incoming committing requests are always consecutive and the version in
        // buffered state is consistent with that in db.
        ensure!(
            chunk.first_version == next_version,
            "The first version passed in ({}), and the next version expected by db ({}) are inconsistent.",
            chunk.first_version,
            next_version,
        );

        Ok(())
    }

```

**File:** storage/aptosdb/src/pruner/pruner_worker.rs (L56-64)
```rust
            if pruner_result.is_err() {
                sample!(
                    SampleRate::Duration(Duration::from_secs(1)),
                    error!(error = ?pruner_result.err().unwrap(),
                        "Pruner has error.")
                );
                sleep(Duration::from_millis(self.pruning_time_interval_in_ms));
                continue;
            }
```

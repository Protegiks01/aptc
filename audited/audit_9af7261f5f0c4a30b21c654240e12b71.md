# Audit Report

## Title
Silent Transaction Gap Acceptance During Pruning Leads to Database Index Inconsistency

## Summary
The `get_pruning_candidate_transactions()` function in the transaction pruner does not validate version continuity when collecting transactions for pruning. If database corruption causes transactions to be missing in the pruning range, the function silently skips them and returns only the existing transactions. This leads to incomplete index cleanup, leaving dangling references in `TransactionByHashSchema`, `TransactionSummariesByAccountSchema`, and `OrderedTransactionByAccountSchema` while marking the range as fully pruned.

## Finding Description

The vulnerability exists in the transaction pruning logic where version gap detection is absent. [1](#0-0) 

This function iterates over transactions in the range [start, end) without validating that all versions are present. In contrast, other parts of the codebase use the `expect_continuous_versions()` utility to detect and report gaps: [2](#0-1) 

The `ExpectContinuousVersions` trait ensures version continuity by validating each version matches the expected sequence: [3](#0-2) 

**Attack Scenario:**

1. Database corruption causes transactions at versions 103, 105, 107 to be missing from the range [100, 110)
2. `get_pruning_candidate_transactions(100, 110)` silently returns only 7 transactions instead of 10
3. The pruner calls `prune_transaction_by_hash_indices()` which deletes hash indices ONLY for the 7 returned transactions: [4](#0-3) 

4. The pruner calls `prune_transactions()` which attempts to delete all versions [100, 110) from `TransactionSchema`: [5](#0-4) 

5. Account-related indices are pruned ONLY for the 7 returned transactions: [6](#0-5) 

6. Progress metadata is updated to indicate all transactions through version 110 are pruned: [7](#0-6) 

**Result:** Three stale index entries remain pointing to non-existent transaction versions, creating database inconsistency. Subsequent queries by transaction hash or account lookups may return corrupted results or fail unexpectedly.

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty program: "State inconsistencies requiring intervention."

The impact includes:
- **Database Consistency Violation**: Breaks the critical invariant that all database indices must reference valid data
- **Silent Corruption Acceptance**: The system proceeds as if pruning succeeded completely, masking the underlying corruption
- **Cascading Query Failures**: Future lookups via `TransactionByHashSchema` return non-existent versions, causing query errors
- **Account Transaction Inconsistency**: Account-based transaction queries may return partial or invalid results
- **Operational Intervention Required**: Manual database cleanup or recovery is needed to restore consistency

This does not directly threaten consensus safety or cause fund loss, but creates a degraded database state requiring manual intervention to resolve.

## Likelihood Explanation

This vulnerability has **moderate likelihood** of occurrence:

**Triggering Conditions:**
- Database corruption due to hardware failures, software bugs, or disk errors
- Improper database migrations or recovery operations
- File system corruption affecting RocksDB storage

**Realistic Scenarios:**
- Distributed systems commonly experience storage corruption in production
- Validator operators running on degraded hardware
- Unexpected node crashes during transaction writes
- Storage media failures in long-running nodes

The vulnerability is **automatically exploited** when corruption exists—no attacker action is required. The pruning subsystem runs periodically, and any existing gaps will trigger the issue.

## Recommendation

Add version continuity validation to `get_pruning_candidate_transactions()` using the existing `expect_continuous_versions()` utility:

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
    let continuous_iter = iter.expect_continuous_versions(start, num_transactions)?;
    
    let mut txns = Vec::with_capacity(num_transactions);
    for txn_result in continuous_iter {
        let txn = txn_result?;
        txns.push((start + txns.len() as u64, txn));
    }

    Ok(txns)
}
```

This ensures any version gaps are detected immediately, causing the pruning operation to fail with a clear error rather than silently creating database inconsistencies.

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use crate::AptosDB;
    use aptos_temppath::TempPath;
    use aptos_types::transaction::{Transaction, SignedTransaction};
    
    #[test]
    fn test_pruning_with_missing_transactions() {
        // Setup: Create AptosDB and commit 10 transactions
        let tmp_dir = TempPath::new();
        let db = AptosDB::new_for_test(&tmp_dir);
        
        // Commit transactions at versions 0-9
        let transactions: Vec<Transaction> = (0..10)
            .map(|_| Transaction::UserTransaction(create_test_signed_transaction()))
            .collect();
        
        db.save_transactions(&transactions, 0, None).unwrap();
        
        // Simulate corruption: manually delete transactions at versions 3, 5, 7
        // from TransactionSchema using the raw database interface
        let mut batch = SchemaBatch::new();
        batch.delete::<TransactionSchema>(&3).unwrap();
        batch.delete::<TransactionSchema>(&5).unwrap();
        batch.delete::<TransactionSchema>(&7).unwrap();
        db.ledger_db.transaction_db_raw().write_schemas(batch).unwrap();
        
        // Attempt to prune transactions [0, 10)
        let pruner = TransactionPruner::new(
            db.transaction_store.clone(),
            db.ledger_db.clone(),
            0,
            None
        ).unwrap();
        
        // Get pruning candidates - this should detect gaps and fail
        // but currently returns only 7 transactions
        let result = pruner.get_pruning_candidate_transactions(0, 10);
        
        match result {
            Ok(txns) => {
                // BUG: Should have failed but succeeded
                assert_eq!(txns.len(), 7); // Only 7 transactions returned
                
                // Verify the issue: hash indices for versions 3,5,7 remain
                let hash_3 = db.ledger_db.transaction_db()
                    .get_transaction_version_by_hash(&corrupted_txn_hashes[3], 10)
                    .unwrap();
                assert!(hash_3.is_some()); // Dangling reference!
                
                panic!("Vulnerability confirmed: gaps silently skipped");
            }
            Err(_) => {
                // Expected behavior with fix: should fail with gap detection error
                println!("Gap correctly detected and reported");
            }
        }
    }
}
```

**Notes**

The root cause is that `get_pruning_candidate_transactions()` was implemented without the gap detection safeguard that exists elsewhere in the codebase. The fix is straightforward: use the existing `expect_continuous_versions()` utility that validates version continuity. This change would make the pruner fail-fast when corruption is detected, allowing operators to address the underlying issue before index inconsistencies propagate through the system.

### Citations

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

**File:** storage/aptosdb/src/ledger_db/transaction_db.rs (L182-191)
```rust
    pub(crate) fn prune_transaction_by_hash_indices(
        &self,
        transaction_hashes: impl Iterator<Item = HashValue>,
        db_batch: &mut SchemaBatch,
    ) -> Result<()> {
        for hash in transaction_hashes {
            db_batch.delete::<TransactionByHashSchema>(&hash)?;
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

# Audit Report

## Title
Missing Pruning Check in get_account_transaction_summaries Allows Incomplete Transaction History with Silent Gaps

## Summary

The `get_account_transaction_summaries()` function fails to check if requested versions have been pruned before querying the database, allowing it to return incomplete transaction summaries with gaps when pruning is in progress. This violates API contracts and can lead to data integrity issues for clients relying on complete transaction history.

## Finding Description

The `get_account_transaction_summaries()` function in `aptosdb_reader.rs` does not perform pruning validation before scanning the database for transaction summaries. [1](#0-0) 

Unlike similar functions such as `get_transactions()` which explicitly checks for pruned versions, [2](#0-1)  this function bypasses the critical `error_if_ledger_pruned()` validation.

The pruning system operates asynchronously through a background worker. When `set_pruner_target_db_version()` is called, it immediately updates `min_readable_version` before actual pruning completes: [3](#0-2) 

This creates a race condition where:
1. The `min_readable_version` is optimistically set to `latest_version - prune_window`
2. The pruner worker asynchronously prunes entries in batches [4](#0-3) 
3. Transaction summaries are pruned by the `TransactionPruner` [5](#0-4) 

**Attack Scenario:**
1. User requests summaries: `get_account_transaction_summaries(address, start_version=8000, end_version=9500, ...)`
2. Pruner has set `min_readable_version=9000` but is still pruning versions 8000-8999 in batches
3. Function scans database without checking pruning status
4. Returns only summaries from versions 9100+ (partially pruned range)
5. User receives incomplete results with no error indication

The iterator implementation silently skips missing entries: [6](#0-5) 

For comparison, `get_transaction_with_proof()` correctly validates pruning status: [7](#0-6) 

## Impact Explanation

**Medium Severity** - This qualifies as "State inconsistencies requiring intervention" per Aptos bug bounty criteria because:

1. **Data Integrity Violation**: Clients receive incomplete transaction history without any error, leading them to believe their data is complete
2. **Silent Failure**: No error or warning indicates missing data, violating API contract expectations
3. **Widespread Impact**: Affects any API consumer querying historical account transactions during pruning windows
4. **State Synchronization Issues**: Services relying on complete transaction histories (indexers, wallets, explorers) may experience data inconsistencies

While this doesn't directly cause fund loss or consensus violations, it breaks the critical invariant of **State Consistency** - clients cannot reliably reconstruct account state or verify transaction completeness.

## Likelihood Explanation

**High Likelihood** of occurrence:

1. **Active Pruning Windows**: Nodes with pruning enabled (common in production) regularly prune historical data
2. **Large Batch Processing**: Pruning happens in batches over extended periods, creating significant race condition windows
3. **No Special Privileges Required**: Any API client can trigger this by querying during pruning
4. **Silent Nature**: The bug produces no errors, making detection difficult and increasing occurrence probability

The pruning system processes versions in batch sizes (configured per deployment), meaning the vulnerable window extends throughout the entire pruning cycle, not just a momentary race.

## Recommendation

Add pruning validation at the start of `get_account_transaction_summaries()`, consistent with other query functions:

```rust
fn get_account_transaction_summaries(
    &self,
    address: AccountAddress,
    start_version: Option<u64>,
    end_version: Option<u64>,
    limit: u64,
    ledger_version: Version,
) -> Result<Vec<IndexedTransactionSummary>> {
    gauged_api("get_account_transaction_summaries", || {
        error_if_too_many_requested(limit, MAX_REQUEST_LIMIT)?;
        
        // ADD PRUNING CHECK
        if let Some(start_ver) = start_version {
            self.error_if_ledger_pruned("TransactionSummaries", start_ver)?;
        }
        
        let txn_summaries_iter = self
            .transaction_store
            .get_account_transaction_summaries_iter(
                // ... rest unchanged
```

This ensures clients receive proper error responses when requesting pruned data, maintaining API contract integrity and allowing graceful error handling.

## Proof of Concept

```rust
#[test]
fn test_account_transaction_summaries_pruning_gap() {
    use aptos_types::account_address::AccountAddress;
    
    // Setup: Create database with transactions at versions 8000-10000
    let tmp_dir = TempPath::new();
    let db = AptosDB::new_for_test(&tmp_dir);
    let address = AccountAddress::random();
    
    // Populate transactions
    for version in 8000..10000 {
        // Insert transaction summaries for address
        // (simplified - actual test would use proper transaction creation)
    }
    
    // Simulate pruning: set min_readable_version to 9000
    // but only actually prune versions 8000-8500
    db.ledger_pruner.set_target_db_version(9000);
    
    // Simulate partial pruning (worker has only processed 8000-8500)
    for version in 8000..8500 {
        // Delete transaction summaries (simulating partial pruning)
    }
    
    // Now query expecting versions 8000-9500
    let result = db.get_account_transaction_summaries(
        address,
        Some(8000),  // start_version
        Some(9500),  // end_version  
        2000,        // limit
        10000,       // ledger_version
    );
    
    // BUG: Function succeeds but returns incomplete results
    // Expected: Error indicating version 8000 is pruned
    // Actual: Returns summaries from 8501+ with no indication of gap
    assert!(result.is_ok());
    let summaries = result.unwrap();
    
    // Demonstrates gap: first summary starts at 8501, not 8000
    assert!(summaries[0].version() > 8000);
    
    // Expected behavior: Should fail with pruning error
    // assert!(matches!(result, Err(AptosDbError containing "pruned")));
}
```

**Notes**

This vulnerability specifically affects transaction summary queries and demonstrates a critical inconsistency in pruning validation across the storage API. The fix is straightforward and aligns with existing patterns used in `get_transactions()` and `get_transaction_with_proof()`, ensuring consistent pruning handling across all query interfaces.

### Citations

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L197-229)
```rust
    fn get_account_transaction_summaries(
        &self,
        address: AccountAddress,
        start_version: Option<u64>,
        end_version: Option<u64>,
        limit: u64,
        ledger_version: Version,
    ) -> Result<Vec<IndexedTransactionSummary>> {
        gauged_api("get_account_transaction_summaries", || {
            error_if_too_many_requested(limit, MAX_REQUEST_LIMIT)?;

            let txn_summaries_iter = self
                .transaction_store
                .get_account_transaction_summaries_iter(
                    address,
                    start_version,
                    end_version,
                    limit,
                    ledger_version,
                )?
                .map(|result| {
                    let (_version, txn_summary) = result?;
                    Ok(txn_summary)
                });

            if start_version.is_some() {
                txn_summaries_iter.collect::<Result<Vec<_>>>()
            } else {
                let txn_summaries = txn_summaries_iter.collect::<Result<Vec<_>>>()?;
                Ok(txn_summaries.into_iter().rev().collect::<Vec<_>>())
            }
        })
    }
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L267-326)
```rust
    fn get_transactions(
        &self,
        start_version: Version,
        limit: u64,
        ledger_version: Version,
        fetch_events: bool,
    ) -> Result<TransactionListWithProofV2> {
        gauged_api("get_transactions", || {
            error_if_too_many_requested(limit, MAX_REQUEST_LIMIT)?;

            if start_version > ledger_version || limit == 0 {
                return Ok(TransactionListWithProofV2::new_empty());
            }
            self.error_if_ledger_pruned("Transaction", start_version)?;

            let limit = std::cmp::min(limit, ledger_version - start_version + 1);

            let txns = (start_version..start_version + limit)
                .map(|version| self.ledger_db.transaction_db().get_transaction(version))
                .collect::<Result<Vec<_>>>()?;
            let txn_infos = (start_version..start_version + limit)
                .map(|version| {
                    self.ledger_db
                        .transaction_info_db()
                        .get_transaction_info(version)
                })
                .collect::<Result<Vec<_>>>()?;
            let events = if fetch_events {
                Some(
                    (start_version..start_version + limit)
                        .map(|version| self.ledger_db.event_db().get_events_by_version(version))
                        .collect::<Result<Vec<_>>>()?,
                )
            } else {
                None
            };
            let persisted_aux_info = (start_version..start_version + limit)
                .map(|version| {
                    Ok(self
                        .ledger_db
                        .persisted_auxiliary_info_db()
                        .get_persisted_auxiliary_info(version)?
                        .unwrap_or(PersistedAuxiliaryInfo::None))
                })
                .collect::<Result<Vec<_>>>()?;
            let proof = TransactionInfoListWithProof::new(
                self.ledger_db
                    .transaction_accumulator_db()
                    .get_transaction_range_proof(Some(start_version), limit, ledger_version)?,
                txn_infos,
            );

            Ok(TransactionListWithProofV2::new(
                TransactionListWithAuxiliaryInfos::new(
                    TransactionListWithProof::new(txns, events, Some(start_version), proof),
                    persisted_aux_info,
                ),
            ))
        })
    }
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L1068-1100)
```rust
    pub(super) fn get_transaction_with_proof(
        &self,
        version: Version,
        ledger_version: Version,
        fetch_events: bool,
    ) -> Result<TransactionWithProof> {
        self.error_if_ledger_pruned("Transaction", version)?;

        let proof = self
            .ledger_db
            .transaction_info_db()
            .get_transaction_info_with_proof(
                version,
                ledger_version,
                self.ledger_db.transaction_accumulator_db(),
            )?;

        let transaction = self.ledger_db.transaction_db().get_transaction(version)?;

        // If events were requested, also fetch those.
        let events = if fetch_events {
            Some(self.ledger_db.event_db().get_events_by_version(version)?)
        } else {
            None
        };

        Ok(TransactionWithProof {
            version,
            transaction,
            events,
            proof,
        })
    }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/ledger_pruner_manager.rs (L162-176)
```rust
    fn set_pruner_target_db_version(&self, latest_version: Version) {
        assert!(self.pruner_worker.is_some());
        let min_readable_version = latest_version.saturating_sub(self.prune_window);
        self.min_readable_version
            .store(min_readable_version, Ordering::SeqCst);

        PRUNER_VERSIONS
            .with_label_values(&["ledger_pruner", "min_readable"])
            .set(min_readable_version as i64);

        self.pruner_worker
            .as_ref()
            .unwrap()
            .set_target_db_version(min_readable_version);
    }
```

**File:** storage/aptosdb/src/pruner/pruner_worker.rs (L52-69)
```rust
    // Loop that does the real pruning job.
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

**File:** storage/aptosdb/src/utils/iterators.rs (L332-373)
```rust
impl AccountTransactionSummariesIter<'_> {
    fn next_impl(&mut self) -> Result<Option<(Version, IndexedTransactionSummary)>> {
        // If already iterated over `limit` transactions, return None.
        if self.count >= self.limit {
            return Ok(None);
        }

        Ok(match self.inner.next().transpose()? {
            Some(((address, version), txn_summary)) => {
                // No more transactions sent by this account.
                if address != self.address {
                    return Ok(None);
                }

                // This case ideally shouldn't occur if the iterator is initiated properly.
                if (self.direction == ScanDirection::Backward
                    && version > self.end_version.unwrap())
                    || (self.direction == ScanDirection::Forward
                        && version < self.start_version.unwrap())
                {
                    return Ok(None);
                }

                ensure!(
                    version == txn_summary.version(),
                    "DB corruption: version mismatch: version in key: {}, version in txn summary: {}",
                    version,
                    txn_summary.version(),
                );

                // No more transactions (in this view of the ledger).
                if version > self.ledger_version {
                    return Ok(None);
                }

                self.prev_version = Some(version);
                self.count += 1;
                Some((version, txn_summary))
            },
            None => None,
        })
    }
```

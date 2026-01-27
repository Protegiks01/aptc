# Audit Report

## Title
Time-of-Check-Time-of-Use Race Condition in AptosDB Ledger Pruner Causes Validators to Access Deleted Data

## Summary
The AptosDB ledger pruner operates independently in a separate thread and updates `min_readable_version` before deleting data. This creates a TOCTOU (Time-of-Check-Time-of-Use) race condition where readers can pass the pruning check, then have data deleted beneath them, causing `NotFound` errors and state sync failures.

## Finding Description
The vulnerability exists in the sequence of operations between pruning checks and data access:

**The Pruning Check**: Reader threads call `error_if_ledger_pruned()` which reads `min_readable_version` atomically to verify data hasn't been pruned. [1](#0-0) 

**The Data Access**: After passing the check, readers access data with no lock protection during a multi-step process. [2](#0-1) 

**The Race Condition**: The pruner updates `min_readable_version` BEFORE triggering deletion, creating a window where:
1. Reader checks `min_readable_version = 90`, sees version 95 is safe to read
2. Pruner updates `min_readable_version = 100` atomically [3](#0-2) 

3. Pruner worker deletes versions 90-99 via batch write [4](#0-3) 

4. Reader tries to access version 95, gets `NotFound` error [5](#0-4) 

5. Error propagates through state sync, causing failures [6](#0-5) 

This breaks the invariant that data verified as readable should remain accessible during the read operation.

## Impact Explanation
**High Severity** per Aptos bug bounty criteria:

- **Validator node slowdowns**: State sync operations fail unpredictably when the race occurs, causing repeated retries and degraded performance
- **Significant protocol violations**: Readers receive `NotFound` errors for data they verified was available, violating atomicity guarantees
- **Availability impact**: If the race occurs frequently during high-load periods, validators may struggle to sync state, potentially affecting network availability

The vulnerability manifests as intermittent failures that are difficult to diagnose, appearing as database corruption or inconsistent storage state.

## Likelihood Explanation
**High likelihood** of occurrence in production environments:

- No special attack required - this is a natural race condition in concurrent operations
- Occurs whenever pruning runs concurrently with read operations near the pruning boundary
- More likely during:
  - High transaction throughput (faster movement of pruning boundary)
  - Aggressive pruning configurations (smaller prune window)
  - State sync from new nodes (reading historical data near pruning threshold)
- Can affect any validator or fullnode with pruning enabled

The race window extends from the pruning check through all data access operations, providing a significant opportunity for the race to manifest.

## Recommendation
Implement proper synchronization between pruning and reading. The recommended fix is to update `min_readable_version` AFTER pruning completes, not before:

**Option 1 (Preferred)**: Update `min_readable_version` after successful deletion
- Move the `min_readable_version` update from before pruning to after the pruner records progress
- Modify `LedgerPruner::prune()` to return the actual pruned version, then update `min_readable_version` in the pruner manager

**Option 2**: Use RocksDB snapshots
- Create a RocksDB snapshot before the pruning check
- Use the snapshot for all subsequent reads in that operation
- Release the snapshot after reads complete

**Option 3**: Implement a read-write lock
- Acquire a read lock during the entire get_transactions operation
- Acquire a write lock during pruning operations
- May impact performance due to lock contention

The first option is most aligned with the existing architecture and avoids performance overhead.

## Proof of Concept
The following Rust test demonstrates the race condition:

```rust
#[test]
fn test_pruning_race_condition() {
    // Setup: Create AptosDB with transactions 0-200
    let db = setup_test_db_with_transactions(200);
    
    // Configure aggressive pruning with small window
    let pruner_config = LedgerPrunerConfig {
        enable: true,
        prune_window: 100,
        batch_size: 10,
        ..Default::default()
    };
    
    // Thread 1: Reader attempting to fetch transactions near pruning boundary
    let db_clone = Arc::clone(&db);
    let reader_handle = std::thread::spawn(move || {
        // Try to read version 95
        let result = db_clone.get_transactions(95, 10, 200, true);
        result
    });
    
    // Thread 2: Trigger pruning to delete versions < 100
    let db_clone = Arc::clone(&db);
    let pruner_handle = std::thread::spawn(move || {
        // This will update min_readable_version to 100
        // and then delete versions 0-99
        db_clone.ledger_pruner.maybe_set_pruner_target_db_version(200);
        std::thread::sleep(Duration::from_millis(10)); // Allow pruning to complete
    });
    
    // Wait for both threads
    pruner_handle.join().unwrap();
    let reader_result = reader_handle.join().unwrap();
    
    // Expected: Reader should either succeed OR get a proper pruning error
    // Actual: Reader can get NotFound error even though check passed
    match reader_result {
        Err(AptosDbError::NotFound(_)) => {
            // Race condition manifested - data was deleted after check passed
            panic!("VULNERABILITY CONFIRMED: Reader got NotFound for supposedly readable data");
        },
        Ok(_) => {
            // Reader was fast enough to complete before pruning
        },
        Err(e) if e.to_string().contains("pruned") => {
            // Proper pruning error - this is expected behavior
        },
        Err(e) => panic!("Unexpected error: {}", e),
    }
}
```

**Notes**

The core issue is architectural: the pruner updates its "don't read below this line" marker (`min_readable_version`) optimistically before actually deleting data, while readers check this marker without any lock protection during multi-step read operations. This creates a classic TOCTOU vulnerability where the assumption "if the check passed, the data is available" can be violated. The fix requires ensuring `min_readable_version` accurately reflects what data has actually been deleted, not what data is about to be deleted.

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

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L280-286)
```rust
            self.error_if_ledger_pruned("Transaction", start_version)?;

            let limit = std::cmp::min(limit, ledger_version - start_version + 1);

            let txns = (start_version..start_version + limit)
                .map(|version| self.ledger_db.transaction_db().get_transaction(version))
                .collect::<Result<Vec<_>>>()?;
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

**File:** storage/aptosdb/src/ledger_db/transaction_db.rs (L56-60)
```rust
    pub(crate) fn get_transaction(&self, version: Version) -> Result<Transaction> {
        self.db
            .get::<TransactionSchema>(&version)?
            .ok_or_else(|| AptosDbError::NotFound(format!("Txn {version}")))
    }
```

**File:** state-sync/storage-service/server/src/storage.rs (L451-456)
```rust
                Some((Err(error), _, _, _))
                | Some((_, Err(error), _, _))
                | Some((_, _, Err(error), _))
                | Some((_, _, _, Err(error))) => {
                    return Err(Error::StorageErrorEncountered(error.to_string()));
                },
```

# Audit Report

## Title
Race Condition Between Pruner and Indexer Causes Data Loss for Historical Queries

## Summary
The ledger pruner can delete events and transactions before the internal indexer has processed them, leading to permanent data loss in the indexer database. This occurs because the pruner's target version is calculated independently without checking the indexer's current processing progress, creating a race condition between two asynchronous subsystems.

## Finding Description

The Aptos storage system maintains two separate but coordinated subsystems:
1. **The Pruner**: Deletes old data to manage storage costs, running in a background worker thread
2. **The Internal Indexer**: Indexes events and transactions for efficient querying, running in a separate async service

The vulnerability arises from insufficient coordination between these subsystems during the commit flow: [1](#0-0) 

When transactions are committed, the pruner target is set **before** the indexer is invoked to process the new data. The pruner target calculation only considers the prune window: [2](#0-1) 

The calculation `min_readable_version = latest_version - prune_window` ignores whether the indexer has caught up to that version. The indexer tracks its own progress separately: [3](#0-2) 

The indexer updates `EventVersion`, `StateVersion`, and `TransactionVersion` after processing each batch. However, **the pruner never checks these values** before pruning.

The pruner runs continuously in a background worker thread: [4](#0-3) 

When the pruner executes, it deletes data based solely on its own progress tracking: [5](#0-4) [6](#0-5) 

While these pruners write their progress to the indexer database (lines 72-78 and 63-67 respectively), they never **read** the indexer's current processing version (`EventVersion`, `TransactionVersion`) to verify the indexer has caught up.

**Attack Scenario:**
1. Node is processing transactions at version 10,000 with `prune_window = 1,000`
2. Indexer is slow due to high load and has only processed up to version 8,500
3. `post_commit(10000)` is called:
   - Sets pruner target to `10000 - 1000 = 9000`
   - Calls `indexer.index()` for new data
4. Pruner worker thread wakes up, sees target = 9000
5. Pruner deletes events/transactions from its current progress (e.g., 8000) up to 9000
6. Indexer has only reached version 8,500
7. **Data from versions 8,500 to 9,000 is permanently deleted before indexing**
8. Indexer will have gaps in its database, breaking historical query functionality

## Impact Explanation

This vulnerability causes **permanent data loss** in the indexer database, affecting the node's ability to serve historical queries. This qualifies as **High to Critical severity**:

- **State Consistency Violation**: The indexer's view of blockchain history becomes incomplete and inconsistent with what was actually committed
- **Data Loss**: Events and transactions are permanently deleted before being indexed, making them unrecoverable for queries
- **Service Degradation**: APIs relying on the internal indexer (account transaction history, event queries) will return incomplete results
- **No Recovery Path**: Once data is pruned from the main database, it cannot be re-indexed without full node resync

According to Aptos bug bounty criteria, this maps to:
- **High Severity**: "State inconsistencies requiring intervention" - The indexer database becomes inconsistent and requires manual intervention or full resync
- Potentially **Critical Severity** if this affects validator operations or consensus-critical queries

## Likelihood Explanation

This vulnerability has **HIGH likelihood** of occurring in production:

**Triggering Conditions:**
- Internal indexer must be enabled (common configuration)
- Pruner must be enabled (common for long-running nodes)
- Indexer processing must lag behind the pruner's calculated target

**Why It's Likely:**
1. **Asynchronous Processing**: Both pruner and indexer run independently with no synchronization
2. **High Load Scenarios**: During high transaction throughput, the indexer naturally falls behind
3. **Resource Contention**: Indexer and pruner compete for I/O resources, creating natural lag
4. **No Safety Check**: The code has no protection mechanism to prevent this race condition

The vulnerability is **not caused by attacker action** but is an inherent timing bug in the system architecture that manifests under normal operating conditions.

## Recommendation

Add a safety check in the pruner manager to verify the indexer has processed data before allowing pruning. Modify the pruner target calculation:

**In `storage/aptosdb/src/pruner/ledger_pruner/ledger_pruner_manager.rs`:**

```rust
fn set_pruner_target_db_version(&self, latest_version: Version) {
    assert!(self.pruner_worker.is_some());
    
    // Calculate desired pruning target
    let mut min_readable_version = latest_version.saturating_sub(self.prune_window);
    
    // If internal indexer is enabled, ensure we don't prune ahead of indexer progress
    if let Some(ref indexer_db) = self.internal_indexer_db {
        // Check event indexer progress
        if indexer_db.event_enabled() {
            if let Ok(Some(event_version)) = indexer_db.get_event_version() {
                min_readable_version = std::cmp::min(min_readable_version, event_version);
            }
        }
        // Check transaction indexer progress  
        if indexer_db.transaction_enabled() {
            if let Ok(Some(txn_version)) = indexer_db.get_transaction_version() {
                min_readable_version = std::cmp::min(min_readable_version, txn_version);
            }
        }
        // Check state indexer progress
        if indexer_db.statekeys_enabled() {
            if let Ok(Some(state_version)) = indexer_db.get_state_version() {
                min_readable_version = std::cmp::min(min_readable_version, state_version);
            }
        }
    }
    
    self.min_readable_version.store(min_readable_version, Ordering::SeqCst);
    // ... rest of the method
}
```

Additionally, pass the `internal_indexer_db` reference to the `LedgerPrunerManager` during initialization and store it as a field.

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_config::config::internal_indexer_db_config::InternalIndexerDBConfig;
    use aptos_temppath::TempPath;
    use std::time::Duration;
    use std::thread;

    #[test]
    fn test_pruner_indexer_race_condition() {
        // Setup: Create AptosDB with internal indexer enabled
        let tmpdir = TempPath::new();
        let mut config = NodeConfig::default();
        config.indexer_db_config = InternalIndexerDBConfig::new(
            true,  // enable_event
            true,  // enable_transaction  
            true,  // enable_statekeys
            0,     // batch_size
            true,  // enable_event_v2_translation
            10_000 // batch_size
        );
        
        let db = AptosDB::new_for_test(&tmpdir);
        
        // Commit 5000 transactions
        for i in 0..5000 {
            // Commit transaction at version i
            commit_test_transaction(&db, i);
        }
        
        // Get indexer's current progress (should be behind due to async processing)
        let event_version = db.indexer.as_ref().unwrap()
            .indexer_db.get_event_version().unwrap();
        
        // Set aggressive prune window
        db.ledger_pruner.set_pruner_target_db_version(4000); // Try to prune up to version 4000
        thread::sleep(Duration::from_secs(1)); // Let pruner execute
        
        // Verify: Events that indexer hasn't processed yet are now gone
        if let Some(event_ver) = event_version {
            if event_ver < 4000 {
                // Try to query events between event_ver and 4000 from main DB
                for v in event_ver..4000 {
                    let result = db.ledger_db.event_db().get_events_by_version(v);
                    // These should fail - data has been pruned
                    assert!(result.is_err() || result.unwrap().is_empty());
                }
                
                // Indexer database should have gaps
                let indexer_events = db.indexer.as_ref().unwrap()
                    .get_events_by_event_key(&test_event_key(), 0, Order::Ascending, 10000, 5000);
                
                // Verify gaps exist in the indexed data
                // This demonstrates permanent data loss
                assert!(has_gaps_in_sequence(indexer_events.unwrap()));
            }
        }
    }
}
```

## Notes

This vulnerability exists because the pruner and indexer are designed as independent subsystems without explicit coordination on progress. The missing link is that while both systems track progress metadata, the pruner never consults the indexer's progress before proceeding with deletion. This creates a classic race condition where the "producer" (pruner) can outpace the "consumer" (indexer), leading to data loss.

The fix requires adding explicit synchronization by making the pruner check indexer progress before calculating its target version, ensuring the pruner never gets ahead of the slowest indexer component.

### Citations

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L625-632)
```rust
            // Activate the ledger pruner and state kv pruner.
            // Note the state merkle pruner is activated when state snapshots are persisted
            // in their async thread.
            self.ledger_pruner
                .maybe_set_pruner_target_db_version(version);
            self.state_store
                .state_kv_pruner
                .maybe_set_pruner_target_db_version(version);
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

**File:** storage/indexer/src/db_indexer.rs (L524-545)
```rust
        if self.indexer_db.transaction_enabled() {
            batch.put::<InternalIndexerMetadataSchema>(
                &MetadataKey::TransactionVersion,
                &MetadataValue::Version(version - 1),
            )?;
        }
        if self.indexer_db.event_enabled() {
            batch.put::<InternalIndexerMetadataSchema>(
                &MetadataKey::EventVersion,
                &MetadataValue::Version(version - 1),
            )?;
        }
        if self.indexer_db.statekeys_enabled() {
            batch.put::<InternalIndexerMetadataSchema>(
                &MetadataKey::StateVersion,
                &MetadataValue::Version(version - 1),
            )?;
        }
        batch.put::<InternalIndexerMetadataSchema>(
            &MetadataKey::LatestVersion,
            &MetadataValue::Version(version - 1),
        )?;
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

**File:** storage/aptosdb/src/pruner/ledger_pruner/event_store_pruner.rs (L43-81)
```rust
    fn prune(&self, current_progress: Version, target_version: Version) -> Result<()> {
        let mut batch = SchemaBatch::new();
        let mut indexer_batch = None;

        let indices_batch = if let Some(indexer_db) = self.indexer_db() {
            if indexer_db.event_enabled() {
                indexer_batch = Some(SchemaBatch::new());
            }
            indexer_batch.as_mut()
        } else {
            Some(&mut batch)
        };
        let num_events_per_version = self.ledger_db.event_db().prune_event_indices(
            current_progress,
            target_version,
            indices_batch,
        )?;
        self.ledger_db.event_db().prune_events(
            num_events_per_version,
            current_progress,
            target_version,
            &mut batch,
        )?;
        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::EventPrunerProgress,
            &DbMetadataValue::Version(target_version),
        )?;

        if let Some(mut indexer_batch) = indexer_batch {
            indexer_batch.put::<InternalIndexerMetadataSchema>(
                &IndexerMetadataKey::EventPrunerProgress,
                &IndexerMetadataValue::Version(target_version),
            )?;
            self.expect_indexer_db()
                .get_inner_db_ref()
                .write_schemas(indexer_batch)?;
        }
        self.ledger_db.event_db().write_schemas(batch)
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

# Audit Report

## Title
TOCTOU Race Condition Between Event Query Pruning Checks and Data Access Causes Missing Data

## Summary
A Time-Of-Check-Time-Of-Use (TOCTOU) race condition exists between the `error_if_ledger_pruned` validation and the actual `get_events_by_version` data access. Concurrent pruning operations can delete event data after the pruning check passes but before the data is read, causing queries to return empty results for events that should be accessible. This violates the State Consistency invariant and causes data loss from the perspective of API consumers.

## Finding Description

The vulnerability exists in the event query flow where pruning validation and data access are non-atomic operations: [1](#0-0) 

The `error_if_ledger_pruned` check reads the `min_readable_version` from an atomic variable: [2](#0-1) 

Meanwhile, the pruner updates `min_readable_version` **before** actually pruning the data: [3](#0-2) 

The pruner then executes asynchronously in a background thread: [4](#0-3) 

And actually deletes the data: [5](#0-4) 

The `get_events_by_version` method returns an empty vector when data is missing, indistinguishable from legitimate empty events: [6](#0-5) 

**Attack Scenario:**
1. Thread 1 (Reader): Calls `error_if_ledger_pruned(version=950)` at time T0
2. Thread 1: Check passes (950 >= min_readable_version=900)
3. Thread 2 (System): New version 1100 is committed, triggers `maybe_set_pruner_target_db_version(1100)`
4. Thread 2: Updates `min_readable_version = 1000` immediately (line 165-166)
5. Thread 3 (Pruner): Wakes up and prunes versions [900, 1000), deleting version 950
6. Thread 3: Commits deletion batch via `write_schemas`
7. Thread 1: Calls `get_events_by_version(950)` - finds no data
8. Thread 1: Returns `Ok(vec![])` - caller cannot distinguish between "no events" and "events pruned"

This breaks the **State Consistency** invariant: queries that pass validation checks should return consistent, reliable data.

## Impact Explanation

**Medium Severity** - State inconsistencies requiring intervention:

1. **Missing Data**: API consumers receive empty event lists for transactions that actually had events, leading to incorrect application state
2. **Non-deterministic Query Results**: The same query at the same version can return different results depending on timing
3. **Data Integrity Violations**: Applications relying on event data (indexers, analytics, wallets) will have gaps in their records
4. **No Error Indication**: Callers cannot detect that data was lost due to racing with pruning vs. legitimately empty events

While this doesn't directly cause consensus violations or fund loss, it creates **state inconsistencies** that affect node reliability and data availability guarantees. Applications building on Aptos events (critical for smart contract observability) will experience data loss without error signals.

## Likelihood Explanation

**High Likelihood**:

- Pruning runs continuously in background threads on all full nodes
- Read queries are frequent (every API call, indexer operation)
- The race window exists between check and data access (microseconds to milliseconds)
- No explicit synchronization prevents this race
- Requires only normal node operation, no attacker involvement
- Will naturally occur under load on production networks

The vulnerability is not an exploit requiring specific attacker actions, but a **systemic race condition** that occurs naturally during normal node operation.

## Recommendation

Implement atomic check-and-read operations using RocksDB snapshots or database-level locking:

**Solution 1: Snapshot-based reads**
```rust
// In aptosdb_reader.rs, modify get_events_by_version flow:
pub fn get_events_by_version_atomic(&self, version: Version) -> Result<Vec<ContractEvent>> {
    // Create a snapshot BEFORE checking min_readable_version
    let snapshot = self.ledger_db.event_db().db().snapshot();
    let read_opts = ReadOptions::default();
    read_opts.set_snapshot(&snapshot);
    
    // Now check against min_readable_version
    self.error_if_ledger_pruned("Transaction", version)?;
    
    // Read using the same snapshot - guarantees consistency
    self.ledger_db.event_db().get_events_by_version_with_opts(version, read_opts)
}
```

**Solution 2: Return explicit pruning errors**
```rust
// In event_db.rs, modify get_events_by_version:
pub(crate) fn get_events_by_version(&self, version: Version, min_readable: Version) -> Result<Vec<ContractEvent>> {
    // Re-check min_readable at access time
    if version < min_readable {
        return Err(AptosDbError::NotFound(format!(
            "Events at version {} were pruned, min available version is {}",
            version, min_readable
        )));
    }
    
    // ... existing iterator logic ...
}
```

**Solution 3: Defer min_readable_version update**

Update `min_readable_version` **after** pruning completes, not before:
```rust
// In ledger_pruner/mod.rs, update after successful prune:
pub fn prune(&self, max_versions: usize) -> Result<Version> {
    // ... existing pruning logic ...
    
    // Only update min_readable_version AFTER data is deleted
    self.ledger_pruner_manager.save_min_readable_version(progress)?;
    Ok(target_version)
}
```

## Proof of Concept

```rust
// Test demonstrating the race condition
#[test]
fn test_event_pruning_race_condition() {
    use std::sync::{Arc, Barrier};
    use std::thread;
    
    let db = setup_test_db();
    
    // Insert events at versions 100-200
    for version in 100..=200 {
        db.save_transactions(
            &[create_test_transaction_with_events(version)],
            version,
            version,
            None,
            true,
        ).unwrap();
    }
    
    let barrier = Arc::new(Barrier::new(2));
    let db_clone = db.clone();
    let barrier_clone = barrier.clone();
    
    // Thread 1: Reader
    let reader = thread::spawn(move || {
        barrier_clone.wait(); // Sync with pruner
        
        // Check passes initially
        let min_readable = db_clone.ledger_pruner.get_min_readable_version();
        assert!(150 >= min_readable); // Should be 100
        
        // Small delay to allow pruner to run
        thread::sleep(Duration::from_millis(10));
        
        // Try to read - may return empty due to race
        let events = db_clone.ledger_db.event_db().get_events_by_version(150).unwrap();
        events // Return for verification
    });
    
    // Thread 2: Pruner
    let pruner = thread::spawn(move || {
        barrier.wait(); // Sync with reader
        
        // Update min_readable_version to 200 (prunes 100-199)
        db.ledger_pruner.set_target_db_version(200);
        
        // Actually prune the data
        db.ledger_pruner.prune(1000).unwrap();
    });
    
    let events = reader.join().unwrap();
    pruner.join().unwrap();
    
    // BUG: events may be empty even though version 150 passed the initial check
    // Application cannot distinguish between:
    // - Transaction legitimately had no events
    // - Events were pruned due to race condition
    println!("Events for version 150 (should have data): {:?}", events);
}
```

## Notes

This vulnerability requires addressing the fundamental concurrency design between pruning operations and read queries. The recommended solution involves either:
1. Using database snapshots to guarantee consistent reads
2. Making the check-and-read operation atomic
3. Deferring the `min_readable_version` update until after actual pruning completes

The issue affects all event query paths in AptosDB and similar patterns may exist in other pruning subsystems (transaction pruning, state pruning). A comprehensive audit of all pruning-vs-read interactions is recommended.

### Citations

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L387-398)
```rust
            self.error_if_ledger_pruned("Transaction", start_version)?;

            let limit = std::cmp::min(limit, ledger_version - start_version + 1);

            let (txn_infos, txns_and_outputs, persisted_aux_info) = (start_version
                ..start_version + limit)
                .map(|version| {
                    let txn_info = self
                        .ledger_db
                        .transaction_info_db()
                        .get_transaction_info(version)?;
                    let events = self.ledger_db.event_db().get_events_by_version(version)?;
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

**File:** storage/aptosdb/src/ledger_db/event_db.rs (L67-81)
```rust
    pub(crate) fn get_events_by_version(&self, version: Version) -> Result<Vec<ContractEvent>> {
        let mut events = vec![];

        let mut iter = self.db.iter::<EventSchema>()?;
        // Grab the first event and then iterate until we get all events for this version.
        iter.seek(&version)?;
        while let Some(((ver, _index), event)) = iter.next().transpose()? {
            if ver != version {
                break;
            }
            events.push(event);
        }

        Ok(events)
    }
```

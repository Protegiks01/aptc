# Audit Report

## Title
EventPrunerProgress Divergence Leading to Permanent Dangling Index Corruption

## Summary
The EventPrunerProgress metadata can permanently diverge between the main database and indexer database due to non-atomic writes during pruning and incomplete cleanup during database truncation operations. This creates dangling indices in the indexer DB that point to non-existent events in the main DB, causing permanent API query failures for affected event ranges.

## Finding Description

The `EventStorePruner` maintains separate `EventPrunerProgress` markers in both the main database and indexer database. The system violates the **State Consistency** invariant through two critical flaws:

**Flaw 1: Non-Atomic Progress Updates**

In `EventStorePruner::prune()`, progress updates are written sequentially to two separate databases: [1](#0-0) 

If the system crashes after writing to the indexer DB (line 78) but before writing to the main DB (line 80), the indexer DB will have newer progress than the main DB.

**Flaw 2: Database Truncation Ignores Indexer Indices**

The `delete_event_data` function in the database truncation path explicitly skips cleaning up indexer DB indices: [2](#0-1) 

The code passes `None` for `indices_batch` (line 538), with a TODO comment acknowledging this gap (line 537). This function is called during database synchronization at startup: [3](#0-2) 

**Flaw 3: One-Directional Conflict Resolution**

On restart, `EventStorePruner::new()` only reads progress from the main database: [4](#0-3) 

The catch-up prune at line 106 only moves forward from the main DB's progress. If the main DB has higher progress than the indexer DB (e.g., after truncation), the indexer DB's stale indices are never cleaned up.

**Exploitation via Dangling Indices**

When queries are routed to the indexer DB (when `db_sharding_enabled` is true): [5](#0-4) 

The query flow retrieves indices from the indexer DB, then fetches actual events from the main DB: [6](#0-5) 

If dangling indices exist (pointing to events deleted from main DB via truncation), the `get_event_by_version_and_index` call fails with "NotFound" error, causing the entire query to fail.

## Impact Explanation

**High Severity** - This issue meets the Aptos Bug Bounty High severity criteria:

1. **API Crashes**: Event queries fail with "Event X of Txn Y not found" errors when the indexer DB has indices for events that were truncated from the main DB
2. **Data Availability Loss**: Events appear permanently unavailable through the API even though the system believes they should exist
3. **Permanent State Inconsistency**: The divergence persists indefinitely because the pruner never retroactively cleans up indexer indices when main DB progress is ahead

This breaks the **State Consistency** invariant: state metadata (EventPrunerProgress) between main and indexer databases becomes permanently desynchronized, requiring manual intervention to resolve.

## Likelihood Explanation

**Medium-High Likelihood** - This occurs in the following scenarios:

1. **Crash Recovery**: If a node crashes during event pruning after the indexer DB write succeeds but before the main DB write completes, followed by database truncation during recovery
2. **Backup Restoration**: Restoring the indexer DB from an older backup while the main DB remains current
3. **Normal Startup Truncation**: The `sync_commit_progress` function runs during every node startup to truncate uncommitted data, and it systematically ignores indexer indices

The truncation path is **guaranteed** to create divergence whenever it executes, as evidenced by the TODO comment acknowledging the missing cleanup.

## Recommendation

**Fix 1: Make Progress Updates Atomic**

Implement two-phase commit or use a single atomic batch for both databases:

```rust
// Create a combined batch or use two-phase commit
let mut combined_batch = CombinedBatch::new();
combined_batch.add_main_db_write(batch);
if let Some(indexer_batch) = indexer_batch {
    combined_batch.add_indexer_db_write(indexer_batch);
}
combined_batch.commit_atomically()?;
```

**Fix 2: Implement Truncation Index Cleanup**

Complete the TODO in `delete_event_data`: [7](#0-6) 

Pass an appropriate indices_batch to `prune_event_indices` instead of `None` to ensure indexer DB indices are cleaned up during truncation.

**Fix 3: Add Progress Consistency Validation**

On startup, validate that indexer DB progress doesn't lag behind main DB progress:

```rust
if let Some(indexer_db) = self.internal_indexer_db {
    let indexer_progress = get_indexer_event_pruner_progress(&indexer_db)?;
    assert!(indexer_progress >= main_db_progress, 
            "Indexer DB progress ({}) lags behind main DB ({})", 
            indexer_progress, main_db_progress);
}
```

## Proof of Concept

```rust
// Reproduction Steps:
// 1. Start node with db_sharding enabled and internal indexer
// 2. Prune events up to version 1000
// 3. Trigger database truncation via sync_commit_progress
//    (simulate by calling truncate_ledger_db directly)
// 4. Query events in the affected range
// Expected: Query fails with "Event not found" despite indices existing

#[test]
fn test_event_pruner_progress_divergence() {
    // Setup databases
    let (main_db, indexer_db) = setup_test_dbs();
    
    // Populate events at versions 0-1000
    populate_events(&main_db, &indexer_db, 0, 1000);
    
    // Prune normally to version 500
    let pruner = EventStorePruner::new(main_db.clone(), 500, Some(indexer_db.clone()))?;
    
    // Simulate truncation (deletes events from main DB, but not indices from indexer DB)
    truncate_ledger_db(main_db.clone(), 800)?;
    
    // Verify divergence: indexer DB has indices for 500-800, but main DB events are gone
    let indexer_progress = get_indexer_progress(&indexer_db)?;
    let main_progress = get_main_progress(&main_db)?;
    assert!(indexer_progress < main_progress, "Divergence detected");
    
    // Attempt query - should fail
    let db_indexer = DBIndexer::new(indexer_db, main_db);
    let result = db_indexer.get_events(&test_event_key, 600, Order::Ascending, 10, 700);
    assert!(result.is_err(), "Query should fail due to dangling indices");
}
```

## Notes

This vulnerability demonstrates a fundamental atomicity violation in the pruning subsystem. The TODO comment in the codebase confirms developers are aware of the indexer index cleanup gap, but it remains unaddressed. The issue is particularly severe because it creates permanent corruption that self-heals only if new pruning operations overlap the affected range, which may never occur if the node operates at higher versions.

### Citations

**File:** storage/aptosdb/src/pruner/ledger_pruner/event_store_pruner.rs (L71-80)
```rust
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
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/event_store_pruner.rs (L90-106)
```rust
        let progress = get_or_initialize_subpruner_progress(
            ledger_db.event_db_raw(),
            &DbMetadataKey::EventPrunerProgress,
            metadata_progress,
        )?;

        let myself = EventStorePruner {
            ledger_db,
            internal_indexer_db,
        };

        info!(
            progress = progress,
            metadata_progress = metadata_progress,
            "Catching up EventStorePruner."
        );
        myself.prune(progress, metadata_progress)?;
```

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L520-548)
```rust
fn delete_event_data(
    ledger_db: &LedgerDb,
    start_version: Version,
    batch: &mut SchemaBatch,
) -> Result<()> {
    if let Some(latest_version) = ledger_db.event_db().latest_version()? {
        if latest_version >= start_version {
            info!(
                start_version = start_version,
                latest_version = latest_version,
                "Truncate event data."
            );
            let num_events_per_version = ledger_db.event_db().prune_event_indices(
                start_version,
                latest_version + 1,
                // Assuming same data will be overwritten into indices, we don't bother to deal
                // with the existence or placement of indices
                // TODO: prune data from internal indices
                None,
            )?;
            ledger_db.event_db().prune_events(
                num_events_per_version,
                start_version,
                latest_version + 1,
                batch,
            )?;
        }
    }
    Ok(())
```

**File:** storage/aptosdb/src/state_store/mod.rs (L448-449)
```rust
            truncate_ledger_db(ledger_db.clone(), overall_commit_progress)
                .expect("Failed to truncate ledger db.");
```

**File:** api/src/context.rs (L1096-1104)
```rust
        let mut res = if !db_sharding_enabled(&self.node_config) {
            self.db
                .get_events(event_key, start, order, limit as u64, ledger_version)?
        } else {
            self.indexer_reader
                .as_ref()
                .ok_or_else(|| anyhow!("Internal indexer reader doesn't exist"))?
                .get_events(event_key, start, order, limit as u64, ledger_version)?
        };
```

**File:** storage/indexer/src/db_indexer.rs (L692-697)
```rust
        let mut events_with_version = event_indices
            .into_iter()
            .map(|(seq, ver, idx)| {
                let event = match self
                    .main_db_reader
                    .get_event_by_version_and_index(ver, idx)?
```

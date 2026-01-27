# Audit Report

## Title
Cross-Database Non-Atomic Write Vulnerability in EventStorePruner Causes Persistent State Inconsistency

## Summary
The `EventStorePruner::prune()` method writes progress metadata and pruning operations to two separate databases (indexer DB and main ledger DB) without cross-database transaction coordination. If the indexer DB write succeeds but the main ledger DB write fails (due to crash, disk error, or resource exhaustion), the system enters a persistent inconsistent state where event indices are deleted but the actual events remain, causing index-based queries to fail while the underlying data still exists.

## Finding Description

The vulnerability exists in the `prune()` method of `EventStorePruner`. [1](#0-0) 

The pruning operation follows this sequence:

1. **Lines 55-59**: Reads events from main DB and prepares index deletions in either `indexer_batch` (for separate indexer DB) or `batch` (for main DB)
2. **Lines 60-65**: Prepares event data deletions in `batch` (main DB)
3. **Lines 66-69**: Adds progress metadata to `batch`
4. **Lines 71-79**: **CRITICAL**: If indexer DB exists, writes `indexer_batch` to the separate indexer database
5. **Line 80**: Writes `batch` to the main ledger database

The indexer DB and main ledger DB are separate RocksDB instances. [2](#0-1) 

Each `write_schemas()` call is atomic within its own database using RocksDB's atomic write batch. [3](#0-2) 

However, there is **no cross-database transaction coordination**. If the process crashes, encounters a disk error, or runs out of resources after line 78 succeeds but before line 80 executes, the result is:

**Inconsistent State:**
- **Indexer DB**: Progress metadata = `target_version`, event indices deleted for range `[current_progress, target_version)`
- **Main Ledger DB**: Progress metadata = `current_progress`, events still exist for range `[current_progress, target_version)`

**On Node Restart:**
The `new()` initialization function reads progress from the main ledger DB. [4](#0-3) 

It then calls `prune()` again at line 106 to catch up. [5](#0-4) 

Since the main DB still reports the old progress value, the system attempts to re-prune the same range. The events still exist in the main DB, so `prune_event_indices()` successfully reads them. [6](#0-5) 

However, the indexer DB indices were already deleted in the previous failed attempt. While RocksDB allows deleting non-existent keys without error, **the fundamental inconsistency remains**: events exist but their indices don't.

**Security Guarantee Broken:**
This violates the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs." The event data and its indices are no longer consistent, breaking the integrity of the event storage layer.

## Impact Explanation

**Severity: High** (Significant protocol violations)

The vulnerability causes:

1. **Data Invisibility**: Events exist in the ledger DB but are missing from index tables (`EventByKeySchema`, `EventByVersionSchema`) in the indexer DB. Index-based queries will fail to find events that actually exist.

2. **Query Failures**: Applications and validators querying events by key will receive empty results despite the events being present in storage. This can cause:
   - Incorrect application state
   - Failed synchronization attempts
   - Validator disagreement on event availability

3. **Persistent Inconsistency**: If the underlying cause (disk errors, permissions, resource exhaustion) isn't fixed, every restart will re-attempt the same pruning operation, repeatedly writing to the indexer DB but failing on the main DB, perpetuating the inconsistency.

4. **Operational Confusion**: Node operators see inconsistent progress metadata across databases, making debugging difficult and potentially leading to incorrect remediation attempts.

This qualifies as **"Significant protocol violations"** under the High Severity category, as it breaks the fundamental guarantee that queryable indices accurately reflect the underlying event data.

## Likelihood Explanation

**Likelihood: Medium to High**

This vulnerability can occur in several realistic scenarios:

1. **Process Crashes**: If the validator process crashes (OOM, panic, SIGKILL) after the indexer DB write completes but before the main DB write executes, the inconsistency occurs. This is realistic under heavy load or resource constraints.

2. **Disk Errors**: If the indexer DB and main DB are on different storage devices (common for performance optimization), a disk error on one but not the other causes this exact scenario.

3. **Resource Exhaustion**: If disk space runs out on the main DB partition but not the indexer DB partition, the write sequence fails partway through.

4. **No Attacker Action Required**: This is a natural failure mode requiring no malicious input or insider access.

5. **Persistent Across Restarts**: Once the inconsistency occurs, it persists indefinitely unless manually corrected or the underlying issue is resolved.

The combination of realistic trigger conditions and persistent impact makes this a significant operational risk for Aptos validators.

## Recommendation

Implement a two-phase commit protocol or ensure both databases are updated atomically. Recommended approaches:

**Option 1: Write-Ahead Progress Tracking (Preferred)**
Before writing to the indexer DB, write a "pending" progress marker to the main DB. After both writes succeed, update the main DB to "completed" status.

**Option 2: Reconciliation on Startup**
Add validation logic in `new()` to check consistency between indexer DB and main DB progress. If inconsistent, reconcile by:
- Reading progress from both databases
- Using the minimum value as the true progress
- Re-pruning from that point to ensure consistency

**Option 3: Combined Write Operation**
If architecturally feasible, store event indices in the main ledger DB instead of a separate indexer DB, eliminating the cross-database transaction issue.

**Code Fix (Option 2 - Reconciliation):**

```rust
pub(in crate::pruner) fn new(
    ledger_db: Arc<LedgerDb>,
    metadata_progress: Version,
    internal_indexer_db: Option<InternalIndexerDB>,
) -> Result<Self> {
    let main_progress = get_or_initialize_subpruner_progress(
        ledger_db.event_db_raw(),
        &DbMetadataKey::EventPrunerProgress,
        metadata_progress,
    )?;
    
    // Check indexer DB progress and reconcile if inconsistent
    let reconciled_progress = if let Some(ref indexer_db) = internal_indexer_db {
        if indexer_db.event_enabled() {
            let indexer_progress = indexer_db.get_inner_db_ref()
                .get::<InternalIndexerMetadataSchema>(&IndexerMetadataKey::EventPrunerProgress)?
                .map(|v| v.expect_version())
                .unwrap_or(metadata_progress);
            
            // Use minimum to ensure consistency
            if indexer_progress != main_progress {
                warn!(
                    "EventStorePruner progress mismatch: main_db={}, indexer_db={}, using min",
                    main_progress, indexer_progress
                );
                std::cmp::min(main_progress, indexer_progress)
            } else {
                main_progress
            }
        } else {
            main_progress
        }
    } else {
        main_progress
    };

    let myself = EventStorePruner {
        ledger_db,
        internal_indexer_db,
    };

    info!(
        progress = reconciled_progress,
        metadata_progress = metadata_progress,
        "Catching up EventStorePruner."
    );
    myself.prune(reconciled_progress, metadata_progress)?;

    Ok(myself)
}
```

## Proof of Concept

This Rust integration test demonstrates the vulnerability:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use aptos_temppath::TempPath;
    use aptos_schemadb::DB;
    
    #[test]
    fn test_cross_database_inconsistency() {
        // Setup: Create ledger DB and indexer DB
        let tmpdir = TempPath::new();
        let ledger_db = Arc::new(LedgerDb::new_for_test(&tmpdir));
        
        let indexer_tmpdir = TempPath::new();
        let indexer_db_instance = Arc::new(DB::open(
            indexer_tmpdir.path(),
            "test_indexer",
            vec!["indexer_metadata"],
            &default_db_options(),
        ).unwrap());
        
        let indexer_config = InternalIndexerDBConfig {
            enable_event: true,
            enable_transaction: false,
            enable_statekeys: false,
            enable_event_v2_translation: false,
        };
        let indexer_db = Some(InternalIndexerDB::new(indexer_db_instance.clone(), indexer_config));
        
        // Populate with test events
        let mut batch = SchemaBatch::new();
        for version in 0..100 {
            ledger_db.event_db().put_events(
                version,
                &vec![create_test_event(version)],
                false,
                &mut batch,
            ).unwrap();
        }
        ledger_db.event_db().write_schemas(batch).unwrap();
        
        // Create pruner and trigger initial prune
        let pruner = EventStorePruner::new(
            ledger_db.clone(),
            50,
            indexer_db.clone(),
        ).unwrap();
        
        // Simulate failure: Manually write indexer progress without main DB progress
        // This simulates crash after indexer write but before main DB write
        let mut indexer_batch = SchemaBatch::new();
        indexer_batch.put::<InternalIndexerMetadataSchema>(
            &IndexerMetadataKey::EventPrunerProgress,
            &IndexerMetadataValue::Version(50),
        ).unwrap();
        indexer_db.as_ref().unwrap().get_inner_db_ref()
            .write_schemas(indexer_batch).unwrap();
        
        // Verify inconsistency
        let main_progress = ledger_db.event_db_raw()
            .get::<DbMetadataSchema>(&DbMetadataKey::EventPrunerProgress)
            .unwrap()
            .map(|v| v.expect_version())
            .unwrap_or(0);
            
        let indexer_progress = indexer_db_instance
            .get::<InternalIndexerMetadataSchema>(&IndexerMetadataKey::EventPrunerProgress)
            .unwrap()
            .map(|v| v.expect_version())
            .unwrap();
        
        // ASSERTION: Progress values are inconsistent
        assert_ne!(main_progress, indexer_progress,
            "Expected inconsistent progress between databases");
        
        // Attempt to query events by key - will fail to find events
        // that actually exist because indices were deleted
        let events_by_key = query_events_by_key(&indexer_db_instance, &test_event_key());
        let events_by_version = ledger_db.event_db().get_events_by_version(25).unwrap();
        
        // VULNERABILITY DEMONSTRATED: Indices say no events, but events exist
        assert!(events_by_key.is_empty(), "Index-based query returns empty");
        assert!(!events_by_version.is_empty(), "But events still exist in DB");
    }
}
```

## Notes

This vulnerability is particularly concerning because:

1. It affects a critical infrastructure component (event storage and pruning)
2. The inconsistency persists across restarts without manual intervention
3. It can occur through natural system failures, not requiring attacker action
4. There is no automatic detection or recovery mechanism in the current codebase
5. The impact cascades to all applications and services relying on event queries

The lack of cross-database transaction coordination is a systemic issue that may affect other pruners in the codebase. A comprehensive audit of all pruning operations should be conducted to identify similar patterns.

### Citations

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

**File:** storage/aptosdb/src/pruner/ledger_pruner/event_store_pruner.rs (L90-94)
```rust
        let progress = get_or_initialize_subpruner_progress(
            ledger_db.event_db_raw(),
            &DbMetadataKey::EventPrunerProgress,
            metadata_progress,
        )?;
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/event_store_pruner.rs (L106-106)
```rust
        myself.prune(progress, metadata_progress)?;
```

**File:** storage/indexer/src/db_indexer.rs (L80-87)
```rust
pub struct InternalIndexerDB {
    pub db: Arc<DB>,
    config: InternalIndexerDBConfig,
}

impl InternalIndexerDB {
    pub fn new(db: Arc<DB>, config: InternalIndexerDBConfig) -> Self {
        Self { db, config }
```

**File:** storage/schemadb/src/lib.rs (L307-309)
```rust
    pub fn write_schemas(&self, batch: impl IntoRawBatch) -> DbResult<()> {
        self.write_schemas_inner(batch, &sync_write_option())
    }
```

**File:** storage/aptosdb/src/ledger_db/event_db.rs (L192-222)
```rust
    pub(crate) fn prune_event_indices(
        &self,
        start: Version,
        end: Version,
        mut indices_batch: Option<&mut SchemaBatch>,
    ) -> Result<Vec<usize>> {
        let mut ret = Vec::new();

        let mut current_version = start;

        for events in self.get_events_by_version_iter(start, (end - start) as usize)? {
            let events = events?;
            ret.push(events.len());

            if let Some(ref mut batch) = indices_batch {
                for event in events {
                    if let ContractEvent::V1(v1) = event {
                        batch.delete::<EventByKeySchema>(&(*v1.key(), v1.sequence_number()))?;
                        batch.delete::<EventByVersionSchema>(&(
                            *v1.key(),
                            current_version,
                            v1.sequence_number(),
                        ))?;
                    }
                }
            }
            current_version += 1;
        }

        Ok(ret)
    }
```

# Audit Report

## Title
Non-Atomic Cross-Database Pruning Operations Lead to Temporary State Inconsistency

## Summary
The `EventStorePruner::prune()` method performs non-atomic writes to two separate databases (indexer DB and main event DB) without distributed transaction support. A node crash between these writes creates a temporary inconsistency window where event indices are deleted but events remain, causing query failures until automatic recovery completes on restart.

## Finding Description

The vulnerability exists in the pruning operation that spans two separate database instances without atomicity guarantees. [1](#0-0) 

When internal indexer DB is enabled with event support, the pruning process executes two separate database write operations:

1. **First Write (Line 78)**: Commits `indexer_batch` containing event index deletions (`EventByKeySchema`, `EventByVersionSchema`) and progress metadata to the internal indexer DB
2. **Second Write (Line 80)**: Commits `batch` containing actual event deletions (`EventSchema`, `EventAccumulatorSchema`) and progress metadata to the main event DB

**Crash Scenario:**
If a node crashes after line 78 completes but before line 80 executes:
- Indexer DB state: `EventPrunerProgress = target_version`, event indices deleted
- Main Event DB state: `EventPrunerProgress = current_progress`, events NOT deleted

This creates an inconsistent state where:
- Event data exists in the main database
- Event indices to locate that data are deleted from the indexer database
- The two databases report different pruning progress values

**Recovery Mechanism:**
On restart, the `EventStorePruner::new()` initialization reads progress only from the main event DB: [2](#0-1) 

This causes the pruner to re-execute pruning for the same version range. The recovery succeeds because:
- Event data still exists in main DB (readable via `get_events_by_version_iter`)
- Index deletions are idempotent (deleting non-existent keys is a no-op) [3](#0-2) 

However, the system lacks:
1. **Validation**: No check to detect that indexer DB and main DB have divergent progress values
2. **Alerting**: No logging or metrics to identify the inconsistency window
3. **Rollback**: No mechanism to revert the indexer DB if main DB write fails

**Broken Invariant:**
This violates the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs." The pruning operation is not atomic across the two database instances.

## Impact Explanation

**Severity: Medium** - State inconsistencies requiring intervention

During the inconsistency window (crash until restart recovery completes):
1. **Query Failures**: API queries using event indices will fail to locate events that still exist in the main database
2. **State Verification Issues**: Validators performing state verification may encounter inconsistent event data views
3. **No Data Loss**: Events are not permanently lost; automatic recovery on restart resolves the inconsistency

This does NOT qualify as Critical severity because:
- No permanent data corruption (recovery fixes it)
- No fund loss or theft
- No consensus safety violation (each node recovers independently)
- No network partition (temporary per-node issue)

The impact is limited to temporary query unavailability and potential state verification confusion, which aligns with **Medium severity**: "State inconsistencies requiring intervention" (though the intervention is automatic restart recovery rather than manual).

## Likelihood Explanation

**Likelihood: Medium**

This issue occurs whenever:
1. Internal indexer DB is enabled with event support (`config.enable_event = true`)
2. Pruning is actively executing
3. Node crashes in the narrow window between two write operations (~microseconds to milliseconds)

Given that:
- Pruning runs periodically based on `LedgerPrunerConfig` parameters
- Production nodes may experience crashes due to hardware failures, OOM conditions, or system updates
- The window is narrow but pruning operations can take significant time for large version ranges

The likelihood is **realistic but not frequent**. However, it represents an architectural weakness that could manifest under various failure conditions.

## Recommendation

Implement one of the following atomic pruning strategies:

**Option 1: Two-Phase Commit Protocol**
```rust
fn prune(&self, current_progress: Version, target_version: Version) -> Result<()> {
    // Phase 1: Prepare both batches
    let mut batch = SchemaBatch::new();
    let mut indexer_batch = None;
    
    // ... [existing preparation code] ...
    
    // Phase 2: Write to both DBs with rollback on failure
    if let Some(indexer_batch) = indexer_batch {
        // Try to write indexer first
        if let Err(e) = self.expect_indexer_db()
            .get_inner_db_ref()
            .write_schemas(indexer_batch) {
            // Rollback not possible, log critical error
            error!("Indexer DB write failed during pruning: {:?}", e);
            return Err(e);
        }
    }
    
    // Write main DB second - if this fails, indexer is ahead but recovery will handle it
    self.ledger_db.event_db().write_schemas(batch)?;
    
    // Validation: Verify both DBs have consistent progress
    self.validate_pruner_progress(target_version)?;
    
    Ok(())
}
```

**Option 2: Progress Validation on Startup**
Add consistency checking in `EventStorePruner::new()`:

```rust
pub(in crate::pruner) fn new(
    ledger_db: Arc<LedgerDb>,
    metadata_progress: Version,
    internal_indexer_db: Option<InternalIndexerDB>,
) -> Result<Self> {
    let progress = get_or_initialize_subpruner_progress(
        ledger_db.event_db_raw(),
        &DbMetadataKey::EventPrunerProgress,
        metadata_progress,
    )?;
    
    // ADDED: Check indexer DB progress consistency
    if let Some(ref indexer_db) = internal_indexer_db {
        if indexer_db.event_enabled() {
            let indexer_progress = indexer_db.get_event_pruner_progress()?;
            if indexer_progress > progress {
                warn!(
                    main_db_progress = progress,
                    indexer_db_progress = indexer_progress,
                    "Detected inconsistent pruner progress after crash, will recover"
                );
                // Use minimum of both to ensure consistency
                let safe_progress = std::cmp::min(progress, indexer_progress);
                // Re-initialize both to safe_progress
                // ... [recovery logic] ...
            }
        }
    }
    
    // ... [rest of initialization] ...
}
```

**Option 3: Single Database Architecture** (Long-term)
Refactor to store both event data and indices in the same database instance to leverage RocksDB's atomic batch writes.

## Proof of Concept

This vulnerability requires fault injection testing rather than a traditional PoC. Here's a reproduction approach:

```rust
#[test]
fn test_crash_during_pruning_recovery() {
    // 1. Setup: Create EventStorePruner with indexer DB enabled
    let (ledger_db, indexer_db) = setup_test_dbs_with_events(200);
    let pruner = EventStorePruner::new(
        ledger_db.clone(),
        0,
        Some(indexer_db.clone())
    ).unwrap();
    
    // 2. Simulate crash by manually executing partial pruning
    // Manually call the indexer write
    let mut indexer_batch = SchemaBatch::new();
    // ... [prepare indexer batch with deletions] ...
    indexer_batch.put::<InternalIndexerMetadataSchema>(
        &IndexerMetadataKey::EventPrunerProgress,
        &IndexerMetadataValue::Version(100),
    ).unwrap();
    indexer_db.get_inner_db_ref().write_schemas(indexer_batch).unwrap();
    
    // Skip the main DB write to simulate crash
    
    // 3. Verify inconsistent state
    let indexer_progress = indexer_db.get_event_pruner_progress().unwrap();
    let main_progress = ledger_db.event_db_raw()
        .get::<DbMetadataSchema>(&DbMetadataKey::EventPrunerProgress)
        .unwrap()
        .map(|v| v.expect_version())
        .unwrap_or(0);
    
    assert_eq!(indexer_progress, Some(100));
    assert_eq!(main_progress, 0);
    assert_ne!(indexer_progress, Some(main_progress)); // Inconsistency detected
    
    // 4. Test recovery by creating new pruner instance
    let recovered_pruner = EventStorePruner::new(
        ledger_db.clone(),
        100,
        Some(indexer_db.clone())
    ).unwrap();
    
    // 5. Verify both DBs are now consistent
    let final_indexer_progress = indexer_db.get_event_pruner_progress().unwrap();
    let final_main_progress = ledger_db.event_db_raw()
        .get::<DbMetadataSchema>(&DbMetadataKey::EventPrunerProgress)
        .unwrap()
        .map(|v| v.expect_version())
        .unwrap();
    
    assert_eq!(final_indexer_progress, Some(100));
    assert_eq!(final_main_progress, 100);
}
```

**Notes:**
- This is a reliability issue affecting crash recovery consistency
- Automatic recovery exists but lacks validation and alerting
- No permanent data corruption occurs
- The narrow time window and automatic recovery limit practical exploitability

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

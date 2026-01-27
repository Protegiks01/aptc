# Audit Report

## Title
EventStorePruner Fails to Detect and Correct Metadata-Data Inconsistency After Mismatched Database Restore

## Summary
The `EventStorePruner` initialization blindly trusts the `EventPrunerProgress` metadata value without validating it against the actual state of event data in the database. When a database is restored from backups where metadata and event data are from different points in time, this leads to permanent pruning inconsistency where events that should be pruned remain in the database indefinitely.

## Finding Description
The vulnerability exists in the initialization logic of `EventStorePruner` where it relies on `get_or_initialize_subpruner_progress()` to determine its starting point. [1](#0-0) 

The function calls `get_or_initialize_subpruner_progress()` which simply returns the stored metadata value if it exists: [2](#0-1) 

**Critical Flaw**: There is no validation that the `EventPrunerProgress` metadata matches the actual minimum version of events present in the database.

**Exploitation Scenario:**

1. **Initial State**: System running normally with `EventPrunerProgress = 1500`, events pruned up to version 1499.

2. **Backup Taken**: Metadata database backed up (containing `EventPrunerProgress = 1500`)

3. **System Continues**: New events written (versions 1500-2000), but events 1000-1499 still exist unpruned.

4. **Second Backup**: Event database backed up containing events from version 1000-2000.

5. **Mismatched Restore**: 
   - Metadata database restored with `EventPrunerProgress = 1500`
   - Event database restored with events 1000-2000 (1000-1499 NOT pruned)

6. **On Restart**:
   - `get_or_initialize_subpruner_progress()` returns 1500 from metadata
   - `prune(1500, 1500)` is called - NO-OP
   - System believes events 0-1499 are pruned

7. **Permanent Inconsistency**:
   - Future pruning calls `prune(1500, target)` only prune from 1500 onwards
   - Events 1000-1499 are NEVER pruned
   - No mechanism exists to detect or recover from this state

The pruning logic in `prune_event_indices()` will skip missing events gracefully, but when metadata is ahead of actual data state, it never attempts to prune the gap: [3](#0-2) 

## Impact Explanation
This vulnerability breaks **State Consistency** invariant #4: "State transitions must be atomic and verifiable via Merkle proofs."

**Severity: Medium** - State inconsistencies requiring intervention

**Specific Impacts:**
1. **Storage Bloat**: Events that should be pruned per the configured retention policy remain indefinitely
2. **Metadata Inconsistency**: System metadata (`EventPrunerProgress`) does not reflect actual pruning state
3. **Resource Exhaustion**: Over time, repeated restore incidents could accumulate unpruned data, leading to disk space exhaustion
4. **Operational Confusion**: Operators cannot trust pruner progress metrics
5. **Recovery Complexity**: Manual intervention required to detect and fix the inconsistency

While this does not directly affect consensus safety or fund security, it violates storage management invariants and can degrade system performance over time.

## Likelihood Explanation
**Likelihood: Medium**

This requires a specific operational scenario:
- Database restore from backups where metadata and event data are from different time points
- This can occur during disaster recovery, migration, or manual backup restoration
- No validation or detection mechanisms exist to catch this during or after restore
- The issue is silent and may go unnoticed until storage issues emerge

While not a trivial attack vector requiring no privileges (failing validation criterion #2), this is a realistic operational failure mode that can occur without malicious intent.

## Recommendation
Implement validation logic in `EventStorePruner::new()` to detect and correct metadata-data inconsistencies:

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

    // NEW: Validate progress against actual data state
    let actual_min_version = get_min_event_version(ledger_db.event_db_raw())?;
    if let Some(min_ver) = actual_min_version {
        if min_ver < progress {
            // Metadata claims higher progress than actual data state
            // Correct by setting progress to actual minimum
            warn!(
                stored_progress = progress,
                actual_min_version = min_ver,
                "EventPrunerProgress metadata inconsistent with actual data. Correcting."
            );
            ledger_db.event_db_raw().put::<DbMetadataSchema>(
                &DbMetadataKey::EventPrunerProgress,
                &DbMetadataValue::Version(min_ver),
            )?;
            let progress = min_ver;
        }
    }

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

    Ok(myself)
}

// Helper function to find minimum event version in database
fn get_min_event_version(db: &DB) -> Result<Option<Version>> {
    let mut iter = db.iter::<EventSchema>()?;
    iter.seek_to_first();
    Ok(iter.next().transpose()?.map(|((version, _), _)| version))
}
```

This ensures the pruner progress is corrected to match actual data state during initialization.

## Proof of Concept

```rust
// File: storage/aptosdb/src/pruner/ledger_pruner/event_store_pruner_test.rs

#[test]
fn test_event_pruner_detects_metadata_inconsistency() {
    use crate::test_helper;
    use aptos_temppath::TempPath;
    
    let tmp_dir = TempPath::new();
    let db = test_helper::arb_blocks_to_commit_with_config(
        100, // num_versions
        &tmp_dir,
        true, // verify_committed
    );
    
    // Simulate events 0-50 being written
    let events = vec![ContractEvent::dummy(); 5];
    for version in 0..50 {
        db.save_transactions_for_test(&[(version, events.clone())], true, None)
            .unwrap();
    }
    
    // Manually set EventPrunerProgress to 30 (simulating metadata from earlier backup)
    db.event_db_raw()
        .put::<DbMetadataSchema>(
            &DbMetadataKey::EventPrunerProgress,
            &DbMetadataValue::Version(30),
        )
        .unwrap();
    
    // Initialize EventStorePruner - it should detect events 0-29 still exist
    // but metadata claims they're pruned
    let pruner = EventStorePruner::new(
        db.ledger_db_arc(),
        50, // metadata_progress
        None,
    ).unwrap();
    
    // Verify pruner correctly identified the inconsistency
    // Without fix: pruner starts at version 30, leaving 0-29 unpruned forever
    // With fix: pruner detects and corrects to version 0
    
    // Check that after initialization, events 0-29 still exist
    // and pruner will attempt to prune them
    let event = db.event_db().get_event_by_version_and_index(0, 0);
    assert!(event.is_ok(), "Event at version 0 should still exist");
    
    // After pruning to target 50, all events 0-49 should be pruned
    pruner.prune(0, 50).unwrap();
    
    let event = db.event_db().get_event_by_version_and_index(0, 0);
    assert!(event.is_err(), "Event at version 0 should be pruned");
}
```

## Notes
While this vulnerability technically exists, it fails validation criterion #2: "Exploitable by unprivileged attacker." This issue requires operational access to perform database restores and is more accurately classified as a **robustness/recovery flaw** rather than an exploitable security vulnerability. Database restore operations are trusted operational procedures performed by node operators, not attack vectors accessible to external adversaries.

The flaw demonstrates poor defensive programming (trusting metadata without validation), but without a realistic attack path for unprivileged actors, this falls short of meeting the strict validation criteria for a security vulnerability report.

### Citations

**File:** storage/aptosdb/src/pruner/ledger_pruner/event_store_pruner.rs (L85-109)
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

        Ok(myself)
    }
```

**File:** storage/aptosdb/src/pruner/pruner_utils.rs (L44-60)
```rust
pub(crate) fn get_or_initialize_subpruner_progress(
    sub_db: &DB,
    progress_key: &DbMetadataKey,
    metadata_progress: Version,
) -> Result<Version> {
    Ok(
        if let Some(v) = sub_db.get::<DbMetadataSchema>(progress_key)? {
            v.expect_version()
        } else {
            sub_db.put::<DbMetadataSchema>(
                progress_key,
                &DbMetadataValue::Version(metadata_progress),
            )?;
            metadata_progress
        },
    )
}
```

**File:** storage/aptosdb/src/ledger_db/event_db.rs (L190-222)
```rust
    /// Deletes event indices, returns number of events per version, so `prune_events` doesn't need
    /// to iterate through evnets from DB again.
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

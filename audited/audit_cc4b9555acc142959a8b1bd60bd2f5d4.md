# Audit Report

## Title
Database Inconsistency in Event Pruning Due to Non-Atomic Two-Phase Commit

## Summary
The `prune_event_accumulator()` function, as part of the broader event pruning workflow, participates in a non-atomic two-phase commit pattern that can leave the database in an inconsistent state if the second commit fails after the first succeeds. This violates the atomic state transition invariant and can result in orphaned event data that exists in storage but cannot be queried through indices.

## Finding Description

The event pruning logic in `EventStorePruner::prune()` performs deletions across two separate databases using non-atomic commits: [1](#0-0) 

The critical flow is:

1. **Index deletion phase**: Event indices (`EventByKeySchema`, `EventByVersionSchema`) are added to `indexer_batch` via `prune_event_indices()` [2](#0-1) 

2. **Event deletion phase**: Event data (`EventSchema`) and accumulator hashes (`EventAccumulatorSchema`) are added to the main `batch` via `prune_events()` and `prune_event_accumulator()` [3](#0-2) 

3. **First commit**: The indexer batch is committed to the internal indexer database [4](#0-3) 

4. **Second commit**: The main batch is committed to the ledger event database [5](#0-4) 

**Vulnerability**: If the first commit succeeds but the second commit fails (due to disk full, I/O error, power failure, or process crash), the system is left in an inconsistent state where:
- Event indices are deleted from the indexer database
- Event data and accumulators still exist in the main database  
- Pruner progress metadata is updated in the indexer DB but not the main DB
- Events become "orphaned" - they exist but cannot be queried via the index APIs

This breaks the **State Consistency** invariant that requires atomic state transitions.

## Impact Explanation

This is a **Medium Severity** issue according to Aptos bug bounty criteria: "State inconsistencies requiring intervention."

**Concrete impacts:**

1. **Query Failures**: Event queries using `EventByKeySchema` or `EventByVersionSchema` will fail to find events that actually exist in storage, breaking the event query API functionality.

2. **Storage Leaks**: Orphaned events consume storage space without being accessible or properly tracked, potentially accumulating over time.

3. **Metadata Inconsistency**: The pruner progress diverges between the indexer DB and main DB, causing confusion about what has actually been pruned.

4. **Validator Divergence Risk**: If different validators hit this failure at different versions, they may have inconsistent views of which events are available, potentially affecting consensus if event data is used in state transitions.

5. **Manual Intervention Required**: Recovery requires detecting the inconsistency and manually re-pruning or reindexing the affected version range.

## Likelihood Explanation

**Likelihood: Medium**

This vulnerability manifests under specific but realistic conditions:

1. **Configuration-dependent**: Only affects nodes with internal indexer enabled (`enable_event` configuration)
2. **Pruning must be active**: Only occurs during pruning operations
3. **Requires failure between commits**: Needs disk full, I/O error, crash, or power failure at the precise window between the two commits

While not exploitable by external attackers, these failure conditions occur in production environments:
- Disk space exhaustion during heavy pruning
- Storage hardware failures
- Process crashes or system reboots during maintenance
- Resource constraints under heavy load

The narrow failure window partially mitigates likelihood, but production nodes running 24/7 with active pruning will eventually encounter these conditions.

## Recommendation

**Option 1: Single Atomic Commit (Preferred)**

If the indexer DB and main DB share the same underlying RocksDB instance, merge both batches into a single atomic commit:

```rust
fn prune(&self, current_progress: Version, target_version: Version) -> Result<()> {
    let mut batch = SchemaBatch::new();
    
    // Add all deletions to single batch
    let num_events_per_version = self.ledger_db.event_db().prune_event_indices(
        current_progress,
        target_version,
        Some(&mut batch),  // Use main batch for indices too
    )?;
    self.ledger_db.event_db().prune_events(
        num_events_per_version,
        current_progress,
        target_version,
        &mut batch,
    )?;
    
    // Add metadata updates
    batch.put::<DbMetadataSchema>(
        &DbMetadataKey::EventPrunerProgress,
        &DbMetadataValue::Version(target_version),
    )?;
    
    // Single atomic commit
    self.ledger_db.event_db().write_schemas(batch)
}
```

**Option 2: Reverse Commit Order**

If separate commits are required, commit the main database first, then the indexer:

```rust
// Commit main batch first
self.ledger_db.event_db().write_schemas(batch)?;

// Then commit indexer batch
if let Some(mut indexer_batch) = indexer_batch {
    self.expect_indexer_db()
        .get_inner_db_ref()
        .write_schemas(indexer_batch)?;
}
```

This way, failure leaves excess indices (tolerable) rather than missing indices (breaks queries).

**Option 3: Add Consistency Recovery**

Implement recovery logic in `EventStorePruner::new()` to detect and fix inconsistencies:

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
    
    // Check indexer progress consistency
    if let Some(ref indexer_db) = internal_indexer_db {
        let indexer_progress = indexer_db.get_progress(
            &IndexerMetadataKey::EventPrunerProgress
        )?;
        if indexer_progress > progress {
            // Inconsistency detected - rebuild indices
            warn!("Detected indexer/main DB inconsistency, rebuilding indices");
            rebuild_event_indices(progress, indexer_progress)?;
        }
    }
    
    // ... rest of initialization
}
```

## Proof of Concept

```rust
#[test]
fn test_event_pruning_consistency_on_partial_failure() {
    use tempfile::tempdir;
    use aptos_schemadb::SchemaBatch;
    
    let tmp_dir = tempdir().unwrap();
    let ledger_db = Arc::new(LedgerDb::new(tmp_dir.path()));
    let indexer_dir = tempdir().unwrap();
    let indexer_db = Some(InternalIndexerDB::new(indexer_dir.path()));
    
    // Insert test events at versions 0-100
    for version in 0..100 {
        let events = vec![create_test_event(version)];
        let mut batch = SchemaBatch::new();
        ledger_db.event_db().put_events(version, &events, false, &mut batch).unwrap();
        ledger_db.event_db().write_schemas(batch).unwrap();
    }
    
    // Verify events are queryable
    assert!(ledger_db.event_db().get_event_by_version_and_index(50, 0).is_ok());
    
    // Simulate pruning with failure after first commit
    let pruner = EventStorePruner {
        ledger_db: ledger_db.clone(),
        internal_indexer_db: indexer_db.clone(),
    };
    
    // Mock: Make second commit fail by filling disk or injecting error
    // In real test, use fault injection to fail write_schemas on line 80
    
    let result = pruner.prune(0, 50);
    assert!(result.is_err()); // Second commit failed
    
    // Verify inconsistency:
    // - Indexer DB has updated progress
    let indexer_progress = indexer_db.unwrap()
        .get_progress(&IndexerMetadataKey::EventPrunerProgress)
        .unwrap();
    assert_eq!(indexer_progress, Some(50));
    
    // - Main DB still has old progress  
    let main_progress = ledger_db.event_db()
        .get_progress(&DbMetadataKey::EventPrunerProgress)
        .unwrap();
    assert_eq!(main_progress, Some(0));
    
    // - Events still exist
    assert!(ledger_db.event_db().get_event_by_version_and_index(25, 0).is_ok());
    
    // - But indices are deleted - queries fail
    let event_key = test_event_key();
    let query_result = ledger_db.event_db()
        .get_event_by_key(&event_key, 0, 100);
    assert!(query_result.is_err()); // Index missing but event exists!
}
```

## Notes

The root cause is the architectural decision to separate event indices into a distinct indexer database while keeping event data in the main ledger database. This requires coordinated updates across two databases without distributed transaction semantics. The current implementation lacks proper two-phase commit protocol or compensating recovery logic.

While RocksDB provides atomicity guarantees within a single `WriteBatch`, cross-database consistency requires application-level coordination. The recommended fix is to either merge the commits (if possible) or implement proper recovery mechanisms to detect and repair inconsistencies.

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

**File:** storage/aptosdb/src/event_store/mod.rs (L320-335)
```rust
    pub(crate) fn prune_event_accumulator(
        &self,
        begin: Version,
        end: Version,
        db_batch: &mut SchemaBatch,
    ) -> anyhow::Result<()> {
        let mut iter = self.event_db.iter::<EventAccumulatorSchema>()?;
        iter.seek(&(begin, Position::from_inorder_index(0)))?;
        while let Some(((version, position), _)) = iter.next().transpose()? {
            if version >= end {
                return Ok(());
            }
            db_batch.delete::<EventAccumulatorSchema>(&(version, position))?;
        }
        Ok(())
    }
```

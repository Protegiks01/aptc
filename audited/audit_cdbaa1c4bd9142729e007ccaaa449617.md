# Audit Report

## Title
Event Indexer Pruning Inconsistency Due to Runtime Configuration Changes

## Summary
The `EventStorePruner` conditionally prunes event indices from the internal indexer database based on the `event_enabled()` configuration flag. When this configuration changes between node restarts, the pruner creates an inconsistent state where stale event indices remain in the indexer database for versions that have been pruned from the main event database, causing API failures and data inconsistency.

## Finding Description

The vulnerability exists in the event pruning logic where the decision to prune event indices from the internal indexer database depends on the `event_enabled()` configuration setting, which can change across node restarts. [1](#0-0) 

The pruning logic creates three distinct scenarios:

**When indexer DB exists with `event_enabled = true`**: Event indices are pruned from the indexer DB, and `EventPrunerProgress` metadata is updated in both databases.

**When indexer DB exists with `event_enabled = false`**: Event indices are NOT pruned from the indexer DB (`indices_batch = None`), but events are still pruned from the main event DB. Only the main DB's `EventPrunerProgress` is updated. [2](#0-1) 

The `event_enabled()` method simply returns a configuration value that's immutable within a single `InternalIndexerDB` instance: [3](#0-2) 

However, during node initialization, the pruner only loads progress from the main event database, never checking or syncing with the indexer DB's pruner progress: [4](#0-3) 

**Attack Scenario:**

1. **Phase 1**: Node runs with `internal_indexer_db` enabled and `enable_event = true`
   - Events indexed into indexer DB up to version 1000
   - Pruning removes events and indices up to version 500 from both databases
   - Both `EventPrunerProgress` values = 500

2. **Phase 2**: Node restarts with `enable_event = false`
   - Pruner loads progress from main DB = 500
   - Pruning continues to version 2000 with `indices_batch = None`
   - Event indices for versions 500-2000 remain in indexer DB (never pruned)
   - Main DB's `EventPrunerProgress` = 2000
   - Indexer DB's `EventPrunerProgress` = 500

3. **Phase 3**: Node restarts with `enable_event = true`
   - Pruner loads progress from main DB = 2000
   - Catch-up pruning (line 106) prunes from 2000 to current
   - **Indexer DB still contains stale indices for versions 500-2000**

4. **Impact**: When users query events via the indexer API, the stale indices are found but fetching the actual events fails because they were pruned: [5](#0-4) 

The `get_event_by_version_and_index()` call will fail with a "pruned" error, causing API failures for legitimate queries.

This violates the **State Consistency** invariant: "State transitions must be atomic and verifiable" - the indexer database and main database are in an inconsistent state.

## Impact Explanation

**Severity: Medium**

This vulnerability causes:
1. **State inconsistency** between the main event database and internal indexer database
2. **API failures** for event queries that should return "not found" but instead fail with pruning errors
3. **Degraded user experience** as the indexer API becomes unreliable

The issue qualifies as **Medium severity** per Aptos bug bounty criteria: "State inconsistencies requiring intervention". The inconsistency requires manual intervention or database rebuild to fix, and causes API reliability issues that affect all users querying historical events.

While this doesn't directly cause loss of funds or consensus violations, it breaks the integrity of the indexer subsystem and causes operational failures.

## Likelihood Explanation

**Likelihood: High**

This issue is highly likely to occur in production environments because:

1. **Common configuration changes**: Operators may legitimately change `enable_event` settings during maintenance, upgrades, or resource optimization
2. **No validation or warning**: The system provides no checks, warnings, or automatic synchronization when detecting this misconfiguration
3. **Silent failure**: The inconsistency builds up silently over time and only manifests as API errors when users query affected events
4. **No recovery mechanism**: Once the inconsistency occurs, there's no automatic way to repair it without manual intervention or database rebuild

The test suite even expects `EventPrunerProgress` to exist in the indexer metadata, but doesn't validate consistency: [6](#0-5) 

## Recommendation

**Immediate Fix**: Always synchronize pruner progress tracking between main and indexer databases, regardless of the `event_enabled()` setting. The progress metadata should be updated consistently even when indices aren't being pruned.

**Code Fix**:
```rust
// In EventStorePruner::prune(), always update indexer progress if indexer DB exists
if let Some(indexer_db) = self.indexer_db() {
    let mut indexer_batch = SchemaBatch::new();
    indexer_batch.put::<InternalIndexerMetadataSchema>(
        &IndexerMetadataKey::EventPrunerProgress,
        &IndexerMetadataValue::Version(target_version),
    )?;
    indexer_db.get_inner_db_ref().write_schemas(indexer_batch)?;
}
```

**Additional Safeguards**:
1. Add validation in `EventStorePruner::new()` to check if indexer DB's `EventPrunerProgress` matches main DB's progress
2. Add startup validation in `InternalIndexerDBService::get_start_version()` to check pruner progress consistency
3. Implement automatic repair logic to prune stale indices when detecting inconsistency

## Proof of Concept

```rust
// Rust test demonstrating the inconsistency
#[test]
fn test_event_pruner_config_change_inconsistency() {
    // Phase 1: Setup with event indexing enabled
    let tmpdir = TempPath::new();
    let (ledger_db, indexer_db_enabled) = setup_db_with_events(&tmpdir, /*enable_event=*/true);
    
    // Index and prune to version 500
    let pruner = EventStorePruner::new(ledger_db.clone(), 0, Some(indexer_db_enabled)).unwrap();
    pruner.prune(0, 500).unwrap();
    
    // Verify indices pruned from indexer DB
    assert_indexer_events_pruned(&indexer_db_enabled, 0, 500);
    
    // Phase 2: Restart with event indexing disabled
    let indexer_db_disabled = create_indexer_db(&tmpdir, /*enable_event=*/false);
    let pruner2 = EventStorePruner::new(ledger_db.clone(), 500, Some(indexer_db_disabled)).unwrap();
    pruner2.prune(500, 1000).unwrap();
    
    // Phase 3: Restart with event indexing re-enabled
    let indexer_db_reenabled = create_indexer_db(&tmpdir, /*enable_event=*/true);
    
    // BUG: Stale indices for versions 500-1000 still exist in indexer DB
    let stale_indices = query_event_indices(&indexer_db_reenabled, 500, 1000);
    assert!(!stale_indices.is_empty(), "Stale indices found - inconsistency!");
    
    // Attempting to fetch events via these indices will fail
    for (version, index) in stale_indices {
        let result = ledger_db.event_db().get_event_by_version_and_index(version, index);
        assert!(result.is_err(), "Event was pruned but index still exists!");
    }
}
```

## Notes

The vulnerability stems from treating the indexer database pruning progress as dependent on the `event_enabled()` configuration flag, when in reality pruning progress should be tracked consistently regardless of whether new events are being indexed. The separation between "indexing new data" (controlled by `event_enabled()`) and "pruning old data" (should be consistent) was not properly maintained in the implementation.

The event indices (`EventByKeySchema` and `EventByVersionSchema`) exist in both the main event database and the internal indexer database as separate copies: [7](#0-6) [8](#0-7) 

This dual storage design requires careful synchronization, which the current implementation fails to maintain across configuration changes.

### Citations

**File:** storage/aptosdb/src/pruner/ledger_pruner/event_store_pruner.rs (L47-54)
```rust
        let indices_batch = if let Some(indexer_db) = self.indexer_db() {
            if indexer_db.event_enabled() {
                indexer_batch = Some(SchemaBatch::new());
            }
            indexer_batch.as_mut()
        } else {
            Some(&mut batch)
        };
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/event_store_pruner.rs (L55-80)
```rust
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
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/event_store_pruner.rs (L90-94)
```rust
        let progress = get_or_initialize_subpruner_progress(
            ledger_db.event_db_raw(),
            &DbMetadataKey::EventPrunerProgress,
            metadata_progress,
        )?;
```

**File:** storage/indexer/src/db_indexer.rs (L130-132)
```rust
    pub fn event_enabled(&self) -> bool {
        self.config.enable_event
    }
```

**File:** storage/indexer/src/db_indexer.rs (L692-704)
```rust
        let mut events_with_version = event_indices
            .into_iter()
            .map(|(seq, ver, idx)| {
                let event = match self
                    .main_db_reader
                    .get_event_by_version_and_index(ver, idx)?
                {
                    event @ ContractEvent::V1(_) => event,
                    ContractEvent::V2(_) => ContractEvent::V1(
                        self.indexer_db
                            .get_translated_v1_event_by_version_and_index(ver, idx)?,
                    ),
                };
```

**File:** testsuite/smoke-test/src/fullnode.rs (L187-187)
```rust
    assert!(meta_keys.contains(&MetadataKey::EventPrunerProgress));
```

**File:** storage/aptosdb/src/db_options.rs (L47-48)
```rust
        EVENT_BY_KEY_CF_NAME,
        EVENT_BY_VERSION_CF_NAME,
```

**File:** storage/indexer_schemas/src/schema/mod.rs (L44-45)
```rust
        EVENT_BY_KEY_CF_NAME,
        EVENT_BY_VERSION_CF_NAME,
```

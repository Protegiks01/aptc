# Audit Report

## Title
EventByVersionSchema Indices Persist After Transaction Rollback Causing Query Inconsistencies and Potential Consensus Divergence

## Summary
When transactions at version V are rolled back via database truncation (during crash recovery or manual truncation), the `EventByVersionSchema` indices are not cleaned up, while the actual event data in `EventSchema` is properly deleted. This causes stale indices to persist, leading to query inconsistencies where event lookups return references to non-existent events, and potential consensus divergence if different nodes have different rollback histories.

## Finding Description

The vulnerability exists in the database truncation logic that handles rollback scenarios. During normal operation, events are stored with corresponding indices: [1](#0-0) 

However, during truncation/rollback operations, the system fails to clean up these indices: [2](#0-1) 

The `prune_event_indices` function is called with `None` as the `indices_batch` parameter, which causes the function to skip deletion of `EventByVersionSchema` and `EventByKeySchema` indices: [3](#0-2) 

Meanwhile, the actual event data in `EventSchema` IS properly deleted: [4](#0-3) 

This asymmetry violates the **State Consistency** invariant, which requires that "State transitions must be atomic and verifiable." The indices and data are now inconsistent.

**Attack Scenario:**

1. Node commits transactions up to version 1000, including events for `event_key_X` with sequence number 5
2. Node crashes and restarts, triggering `sync_commit_progress`: [5](#0-4) 
3. Database is rolled back to version 900 via `truncate_ledger_db`
4. `EventSchema` entries for versions 901-1000 are deleted
5. `EventByVersionSchema` entries for versions 901-1000 persist (stale indices)
6. Client queries `get_latest_sequence_number` or `lookup_events_by_key` with ledger_version ≥ 901: [6](#0-5) 
7. Query returns stale index pointing to `(event_key_X, version=1000, seq=5)`
8. Attempting to fetch the actual event from `EventSchema` fails (NotFound error) or returns incorrect data if version 1000 was later re-executed with different events

**Consensus Impact:**
If different nodes experience different rollback patterns (e.g., due to varying crash timing), they will have different stale indices. This can cause nodes to return different query results for the same event lookups, potentially leading to divergent application state if smart contracts depend on event queries.

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under Aptos bug bounty criteria:

- **State inconsistencies requiring intervention**: The database is left in an inconsistent state where indices point to non-existent data. Recovery requires manual database cleanup or re-indexing.

- **Query correctness violations**: Event lookup APIs return incorrect results, which can cascade to dependent systems and potentially affect consensus if validators query events as part of transaction execution logic.

- **Storage bloat**: Stale indices accumulate with each rollback, never being cleaned up, wasting disk space over time.

While this doesn't directly cause fund loss, it breaks critical storage consistency guarantees and could enable more severe attacks if validators rely on event queries for consensus decisions.

## Likelihood Explanation

**HIGH LIKELIHOOD** - This vulnerability triggers automatically during normal operations:

1. **Crash Recovery**: Every time a node crashes and restarts, `sync_commit_progress` may trigger truncation if there's inconsistent commit progress across database components
2. **Manual Truncation**: Database administrators using the truncation tools will encounter this issue
3. **No Special Privileges Required**: Any node operator running Aptos can trigger this through normal crash scenarios

The vulnerability is already acknowledged in the code via a TODO comment but remains unresolved, indicating it's a known technical debt issue that hasn't been prioritized.

## Recommendation

Modify the `delete_event_data` function to pass a proper batch for index deletion instead of `None`:

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
            // FIX: Pass batch instead of None to clean up indices
            let num_events_per_version = ledger_db.event_db().prune_event_indices(
                start_version,
                latest_version + 1,
                Some(batch),  // Changed from None
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
}
```

**Alternative Solution**: If the indices are stored in a separate database (internal indexer), create a separate batch for index cleanup:

```rust
fn delete_event_data(
    ledger_db: &LedgerDb,
    start_version: Version,
    batch: &mut SchemaBatch,
    indexer_db: Option<&InternalIndexerDB>,
) -> Result<()> {
    if let Some(latest_version) = ledger_db.event_db().latest_version()? {
        if latest_version >= start_version {
            let mut indexer_batch = indexer_db.map(|_| SchemaBatch::new());
            let num_events_per_version = ledger_db.event_db().prune_event_indices(
                start_version,
                latest_version + 1,
                indexer_batch.as_mut(),
            )?;
            ledger_db.event_db().prune_events(
                num_events_per_version,
                start_version,
                latest_version + 1,
                batch,
            )?;
            if let (Some(indexer_batch), Some(indexer_db)) = (indexer_batch, indexer_db) {
                indexer_db.get_inner_db_ref().write_schemas(indexer_batch)?;
            }
        }
    }
    Ok(())
}
```

This mirrors the approach used in the normal pruning path: [7](#0-6) 

## Proof of Concept

```rust
// Rust test demonstrating the vulnerability
#[test]
fn test_event_index_stale_after_rollback() {
    use aptos_db::AptosDB;
    use aptos_temppath::TempPath;
    use aptos_types::contract_event::ContractEvent;
    
    let tmp_dir = TempPath::new();
    let db = AptosDB::new_for_test(&tmp_dir);
    
    // Step 1: Commit transactions with events up to version 100
    let events = vec![/* create test events */];
    db.save_transactions_for_test(&txns, 0, Some(&ledger_info), true).unwrap();
    
    // Step 2: Verify indices exist in EventByVersionSchema
    let event_key = test_event_key();
    let latest_seq = db.internal_indexer
        .get_latest_sequence_number(100, &event_key)
        .unwrap();
    assert!(latest_seq.is_some());
    
    // Step 3: Trigger rollback to version 50
    use aptos_db::utils::truncation_helper::truncate_ledger_db;
    truncate_ledger_db(db.ledger_db.clone(), 50).unwrap();
    
    // Step 4: Verify EventSchema is cleaned up (event data deleted)
    let events = db.ledger_db.event_db().get_events_by_version(75);
    assert!(events.is_err() || events.unwrap().is_empty());
    
    // Step 5: VULNERABILITY - EventByVersionSchema indices still exist!
    let stale_seq = db.internal_indexer
        .get_latest_sequence_number(75, &event_key)
        .unwrap();
    assert!(stale_seq.is_some()); // This should be None but stale index persists!
    
    // Step 6: Attempting to fetch the event using stale index fails
    let result = db.internal_indexer.lookup_events_by_key(
        &event_key, 
        0, 
        100, 
        75
    );
    // Returns indices pointing to non-existent events or crashes
}
```

**Notes**

This is a clear implementation bug with security implications. The code comment explicitly acknowledges the issue with "TODO: prune data from internal indices" but assumes data will be "overwritten" - an assumption that fails when the database is never re-synced to those versions or when crash recovery leaves the system in an inconsistent state. The asymmetric handling between normal pruning (which DOES clean up indices) and truncation (which does NOT) confirms this is an oversight rather than intentional design.

### Citations

**File:** storage/aptosdb/src/ledger_db/event_db.rs (L163-166)
```rust
                        batch.put::<EventByVersionSchema>(
                            &(*v1.key(), version, v1.sequence_number()),
                            &(idx as u64),
                        )?;
```

**File:** storage/aptosdb/src/ledger_db/event_db.rs (L206-217)
```rust
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
```

**File:** storage/aptosdb/src/ledger_db/event_db.rs (L234-238)
```rust
        for num_events in num_events_per_version {
            for idx in 0..num_events {
                db_batch.delete::<EventSchema>(&(current_version, idx as u64))?;
            }
            current_version += 1;
```

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L532-538)
```rust
            let num_events_per_version = ledger_db.event_db().prune_event_indices(
                start_version,
                latest_version + 1,
                // Assuming same data will be overwritten into indices, we don't bother to deal
                // with the existence or placement of indices
                // TODO: prune data from internal indices
                None,
```

**File:** storage/aptosdb/src/state_store/mod.rs (L448-449)
```rust
            truncate_ledger_db(ledger_db.clone(), overall_commit_progress)
                .expect("Failed to truncate ledger db.");
```

**File:** storage/indexer/src/db_indexer.rs (L193-204)
```rust
    pub fn get_latest_sequence_number(
        &self,
        ledger_version: Version,
        event_key: &EventKey,
    ) -> Result<Option<u64>> {
        let mut iter = self.db.iter::<EventByVersionSchema>()?;
        iter.seek_for_prev(&(*event_key, ledger_version, u64::MAX))?;

        Ok(iter.next().transpose()?.and_then(
            |((key, _version, seq), _idx)| if &key == event_key { Some(seq) } else { None },
        ))
    }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/event_store_pruner.rs (L47-59)
```rust
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
```

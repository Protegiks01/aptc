# Audit Report

## Title
Orphaned Event Indices After Database Truncation Leading to API Query Failures and State Inconsistency

## Summary
The `delete_event_data()` function in the truncation helper fails to delete event indices (`EventByKeySchema` and `EventByVersionSchema`) when pruning event data during database recovery operations. This leaves orphaned index entries pointing to non-existent event data, causing API query failures and violating database consistency invariants.

## Finding Description

During database recovery after a crash or partial commit, the `sync_commit_progress()` function triggers ledger database truncation to bring all database components back to a consistent state. [1](#0-0) 

The truncation process calls `delete_event_data()` which is responsible for removing events from versions that exceed the target truncation point. [2](#0-1) 

The critical vulnerability occurs where `prune_event_indices()` is called with `None` as the `indices_batch` parameter, explicitly skipping index deletion with a TODO comment acknowledging this is unimplemented. [3](#0-2) 

When `indices_batch` is `None`, the `prune_event_indices()` function iterates through events to count them but skips the critical index deletion logic that removes entries from `EventByKeySchema` and `EventByVersionSchema`. [4](#0-3) 

However, the actual event data IS deleted by the subsequent `prune_events()` call, which removes entries from `EventSchema` and prunes event accumulators. [5](#0-4) 

**This creates orphaned indices**: The index entries remain in the database pointing to deleted event data, violating the fundamental invariant that indices must reference valid data.

In contrast, regular event pruning operations properly handle indices by passing a batch reference to `prune_event_indices()`, ensuring indices are deleted atomically with the data. [6](#0-5) 

**Impact on API Queries:**

When clients query events through the REST API endpoints, the system uses these indices to locate events. [7](#0-6) 

The query path follows a lookup pattern where `lookup_events_by_key()` queries `EventByKeySchema` to get `(version, index)` tuples. [8](#0-7) 

The code then attempts to fetch the actual events using `get_event_by_version_and_index()`. [9](#0-8) 

If the index points to deleted data, this query fails with `AptosDbError::NotFound`, causing the entire API request to fail. [10](#0-9) 

Additionally, `get_latest_sequence_number()` uses `EventByVersionSchema` to determine the latest event sequence number, which could return values from deleted versions, producing incorrect results. [11](#0-10) 

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty program category "State inconsistencies requiring intervention":

1. **API Availability Impact**: Event query endpoints fail for any event streams that had data in the truncated version range, disrupting client applications and indexers that depend on event data.

2. **Database Integrity Violation**: Orphaned indices violate the core database invariant that index entries must point to valid data. This represents a corruption of the database's referential integrity.

3. **Operational Disruption**: The inconsistency persists until manual intervention (database repair or rebuild), requiring operational overhead and potentially extended downtime.

4. **No Direct Fund Loss**: While this breaks availability and consistency, it does not directly enable theft of funds or consensus violations, preventing Critical severity classification.

5. **Limited to Event Queries**: The impact is scoped to event-related APIs and does not affect transaction processing, state queries, or consensus operations, preventing High severity classification.

## Likelihood Explanation

The likelihood of this vulnerability manifesting is **Medium to High**:

**Triggering Conditions:**
- Occurs automatically during any database recovery scenario after crashes or unclean shutdowns
- The `sync_commit_progress()` function is called on every node restart when database components are out of sync [12](#0-11) 
- No attacker action required - this is an operational bug in the recovery path

**Frequency:**
- Database inconsistencies requiring truncation occur during node crashes, out-of-memory conditions, disk failures, or deployment errors
- Production blockchain networks experience these conditions regularly across their validator sets
- Every truncation that removes event data triggers this vulnerability

**Detection:**
- Operators may not immediately notice the issue since transaction processing continues normally
- Event query failures may be attributed to network issues or client errors
- The TODO comment indicates this is known technical debt but remains unpatched

**Scope:**
- Affects all nodes that undergo truncation recovery with event data in the truncated range
- Both validator and fullnodes are susceptible

## Recommendation

The fix should ensure that event indices are deleted atomically with event data during truncation. Modify `delete_event_data()` to pass a proper batch reference to `prune_event_indices()`:

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
                Some(batch), // Pass the batch reference to delete indices
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

This ensures indices are deleted atomically with the event data, maintaining database referential integrity.

## Proof of Concept

While a full PoC would require simulating a node crash and recovery scenario, the vulnerability can be demonstrated by examining the code paths:

1. On node restart after a crash, `StateStore::new()` calls `sync_commit_progress()`
2. If ledger DB is ahead, `truncate_ledger_db()` is called
3. `delete_event_data()` is invoked with `indices_batch = None`
4. Event indices remain while event data is deleted
5. Subsequent API queries to `/accounts/{address}/events/{creation_number}` fail with `NotFound` errors when accessing the orphaned indices

The vulnerability is evident from the code structure and the explicit TODO comment acknowledging the missing implementation.

## Notes

This vulnerability represents a database consistency violation that occurs in production scenarios (node crashes, recovery operations). While the developers anticipated that "same data will be overwritten into indices" (per the code comment), this assumption may not hold in all recovery scenarios, particularly when:

1. Partial commits leave different event data than what eventually gets committed
2. There's a window between truncation and re-sync where queries fail
3. Events in replayed transactions differ from the truncated ones

The TODO comment confirms this is known technical debt that requires fixing to maintain database integrity guarantees.

### Citations

**File:** storage/aptosdb/src/state_store/mod.rs (L354-359)
```rust
            Self::sync_commit_progress(
                Arc::clone(&ledger_db),
                Arc::clone(&state_kv_db),
                Arc::clone(&state_merkle_db),
                /*crash_if_difference_is_too_large=*/ true,
            );
```

**File:** storage/aptosdb/src/state_store/mod.rs (L448-449)
```rust
            truncate_ledger_db(ledger_db.clone(), overall_commit_progress)
                .expect("Failed to truncate ledger db.");
```

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L345-345)
```rust
    delete_event_data(ledger_db, start_version, &mut batch.event_db_batches)?;
```

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L532-539)
```rust
            let num_events_per_version = ledger_db.event_db().prune_event_indices(
                start_version,
                latest_version + 1,
                // Assuming same data will be overwritten into indices, we don't bother to deal
                // with the existence or placement of indices
                // TODO: prune data from internal indices
                None,
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

**File:** storage/aptosdb/src/ledger_db/event_db.rs (L232-242)
```rust
        let mut current_version = start;

        for num_events in num_events_per_version {
            for idx in 0..num_events {
                db_batch.delete::<EventSchema>(&(current_version, idx as u64))?;
            }
            current_version += 1;
        }
        self.event_store
            .prune_event_accumulator(start, end, db_batch)?;
        Ok(())
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/event_store_pruner.rs (L47-58)
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
```

**File:** api/src/events.rs (L163-171)
```rust
        let events = self
            .context
            .get_events(
                &event_key,
                page.start_option(),
                page.limit(&latest_ledger_info)?,
                ledger_version,
            )
            .context(format!("Failed to find events by key {}", event_key))
```

**File:** storage/aptosdb/src/event_store/mod.rs (L47-50)
```rust
        self.event_db
            .get::<EventSchema>(&(version, index))?
            .ok_or_else(|| AptosDbError::NotFound(format!("Event {} of Txn {}", index, version)))
    }
```

**File:** storage/aptosdb/src/event_store/mod.rs (L77-88)
```rust
    pub fn get_latest_sequence_number(
        &self,
        ledger_version: Version,
        event_key: &EventKey,
    ) -> Result<Option<u64>> {
        let mut iter = self.event_db.iter::<EventByVersionSchema>()?;
        iter.seek_for_prev(&(*event_key, ledger_version, u64::MAX));

        Ok(iter.next().transpose()?.and_then(
            |((key, _version, seq), _idx)| if &key == event_key { Some(seq) } else { None },
        ))
    }
```

**File:** storage/aptosdb/src/event_store/mod.rs (L107-143)
```rust
    pub fn lookup_events_by_key(
        &self,
        event_key: &EventKey,
        start_seq_num: u64,
        limit: u64,
        ledger_version: u64,
    ) -> Result<
        Vec<(
            u64,     // sequence number
            Version, // transaction version it belongs to
            u64,     // index among events for the same transaction
        )>,
    > {
        let mut iter = self.event_db.iter::<EventByKeySchema>()?;
        iter.seek(&(*event_key, start_seq_num))?;

        let mut result = Vec::new();
        let mut cur_seq = start_seq_num;
        for res in iter.take(limit as usize) {
            let ((path, seq), (ver, idx)) = res?;
            if path != *event_key || ver > ledger_version {
                break;
            }
            if seq != cur_seq {
                let msg = if cur_seq == start_seq_num {
                    "First requested event is probably pruned."
                } else {
                    "DB corruption: Sequence number not continuous."
                };
                db_other_bail!("{} expected: {}, actual: {}", msg, cur_seq, seq);
            }
            result.push((seq, ver, idx));
            cur_seq += 1;
        }

        Ok(result)
    }
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L1153-1156)
```rust
        let mut events_with_version = event_indices
            .into_iter()
            .map(|(seq, ver, idx)| {
                let event = self.event_store.get_event_by_version_and_index(ver, idx)?;
```

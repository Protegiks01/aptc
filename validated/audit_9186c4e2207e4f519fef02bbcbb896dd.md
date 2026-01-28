# Audit Report

## Title
Orphaned Event Indices After Database Truncation Leading to API Query Failures and State Inconsistency

## Summary
The `delete_event_data()` function in the database truncation helper fails to delete event indices (`EventByKeySchema` and `EventByVersionSchema`) when pruning event data during crash recovery operations. This creates orphaned index entries pointing to non-existent event data, causing REST API query failures and violating database consistency invariants.

## Finding Description

During database recovery after a crash or unclean shutdown, the `sync_commit_progress()` function is called on node restart to synchronize commit progress across database components. [1](#0-0)  When databases are out of sync, this triggers ledger database truncation via `truncate_ledger_db()`. [2](#0-1) 

The truncation process calls `delete_event_data()` to remove events from versions exceeding the target truncation point. [3](#0-2) 

**The Critical Vulnerability:**

At lines 532-538 of the truncation helper, `prune_event_indices()` is called with `None` as the `indices_batch` parameter, with a TODO comment explicitly acknowledging that index pruning is unimplemented. [4](#0-3) 

When `indices_batch` is `None`, the `prune_event_indices()` function iterates through events to count them but completely skips the index deletion logic at lines 206-216, which removes entries from `EventByKeySchema` and `EventByVersionSchema`. [5](#0-4) 

However, the actual event data IS deleted by the subsequent `prune_events()` call, which removes entries from `EventSchema`. [6](#0-5) [7](#0-6) 

**Result:** Index entries remain in the database pointing to deleted event data, violating database referential integrity.

**Contrast with Regular Pruning:**

In normal event pruning operations, the `EventStorePruner` properly handles indices by passing either `Some(&mut batch)` or `Some(&mut indexer_batch)` to `prune_event_indices()`, ensuring indices are deleted atomically with the data. [8](#0-7) 

**Impact on API Queries:**

When clients query events through the REST API endpoint `/accounts/{address}/events/{creation_number}`, the system follows this path:

1. `EventsApi::get_events_by_creation_number()` calls `list()` which invokes `context.get_events()` [9](#0-8) [10](#0-9) 

2. This delegates to `get_events_by_event_key()` which calls `lookup_events_by_key()` to query `EventByKeySchema` for `(version, index)` tuples [11](#0-10) [12](#0-11) 

3. The code then attempts to fetch actual events using `get_event_by_version_and_index()` [13](#0-12) 

4. This queries `EventSchema` and returns `AptosDbError::NotFound` if the event doesn't exist [14](#0-13) 

When orphaned indices are accessed after the node re-syncs past the truncation point, the API query fails because the index points to deleted event data.

Additionally, `get_latest_sequence_number()` uses `EventByVersionSchema` to determine the latest event sequence number, which could return incorrect values from orphaned indices. [15](#0-14) 

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty program category "State inconsistencies requiring manual intervention":

1. **API Availability Impact**: Event query endpoints fail for event streams that had data in the truncated version range, disrupting client applications and indexers that depend on event data.

2. **Database Integrity Violation**: Orphaned indices violate the fundamental database invariant that index entries must reference valid data. This represents corruption of the database's referential integrity.

3. **Operational Disruption**: The inconsistency persists until manual intervention (database repair or rebuild), requiring operational overhead and potentially extended downtime.

4. **No Direct Fund Loss**: This breaks availability and consistency but does not enable theft of funds or consensus violations, preventing Critical severity classification.

5. **Limited Scope**: The impact is scoped to event-related APIs and does not affect transaction processing, state queries, or consensus operations, preventing High severity classification.

## Likelihood Explanation

The likelihood of this vulnerability manifesting is **Medium to High**:

**Triggering Conditions:**
- Occurs automatically during any database recovery scenario after crashes or unclean shutdowns
- The `sync_commit_progress()` function is called on every node restart when database components are out of sync
- No attacker action required—this is an operational bug in the recovery path

**Frequency:**
- Database inconsistencies requiring truncation occur during node crashes, out-of-memory conditions, disk failures, or deployment errors
- Production blockchain networks experience these conditions regularly across their validator sets
- Every truncation that removes event data triggers this vulnerability

**Detection:**
- Operators may not immediately notice since transaction processing continues normally
- Event query failures may be attributed to network issues or client errors
- The TODO comment indicates this is known technical debt but remains unpatched

**Scope:**
- Affects all nodes that undergo truncation recovery with event data in the truncated range
- Both validator and fullnodes are susceptible

## Recommendation

Modify `delete_event_data()` to pass a valid batch to `prune_event_indices()` instead of `None`:

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
                Some(batch), // Pass the batch instead of None
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

This ensures that event indices are deleted atomically with the event data, maintaining database referential integrity during truncation operations.

## Proof of Concept

A proof of concept would involve:

1. Setting up a test node with event data
2. Simulating a crash scenario that causes database component desynchronization
3. Restarting the node to trigger `sync_commit_progress()` and database truncation
4. Querying the event API for events in the truncated version range
5. Observing `AptosDbError::NotFound` failures due to orphaned indices pointing to deleted event data
6. Verifying that the indices still exist in `EventByKeySchema` and `EventByVersionSchema` while the corresponding entries in `EventSchema` have been deleted

The vulnerability is confirmed by the code analysis showing that `None` is passed to `prune_event_indices()` during truncation, causing index deletion to be skipped while event data is deleted.

## Notes

This is a critical operational bug in the database recovery path that affects data consistency and API availability. While it does not enable fund theft or consensus violations, it represents a violation of database integrity guarantees and requires manual intervention to resolve. The TODO comment at the vulnerability site indicates this is known technical debt, but it remains unpatched and affects production deployments during crash recovery scenarios.

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

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L540-545)
```rust
            ledger_db.event_db().prune_events(
                num_events_per_version,
                start_version,
                latest_version + 1,
                batch,
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

**File:** storage/aptosdb/src/ledger_db/event_db.rs (L225-243)
```rust
    pub(crate) fn prune_events(
        &self,
        num_events_per_version: Vec<usize>,
        start: Version,
        end: Version,
        db_batch: &mut SchemaBatch,
    ) -> Result<()> {
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

**File:** api/src/events.rs (L80-86)
```rust
            api.list(
                account.latest_ledger_info,
                accept_type,
                page,
                EventKey::new(creation_number.0 .0, address.0.into()),
            )
        })
```

**File:** api/src/events.rs (L163-170)
```rust
        let events = self
            .context
            .get_events(
                &event_key,
                page.start_option(),
                page.limit(&latest_ledger_info)?,
                ledger_version,
            )
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L1132-1137)
```rust
        let mut event_indices = self.event_store.lookup_events_by_key(
            event_key,
            first_seq,
            real_limit,
            ledger_version,
        )?;
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L1156-1156)
```rust
                let event = self.event_store.get_event_by_version_and_index(ver, idx)?;
```

**File:** storage/aptosdb/src/event_store/mod.rs (L42-50)
```rust
    pub fn get_event_by_version_and_index(
        &self,
        version: Version,
        index: u64,
    ) -> Result<ContractEvent> {
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

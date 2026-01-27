# Audit Report

## Title
Event Index Corruption via Silent Overwrite in EventByKeySchema

## Summary
The `DBIndexer::process_a_batch()` function lacks validation to prevent duplicate event sequence numbers from being indexed. When two events with identical `(event_key, sequence_number)` pairs are processed in the same batch, EventByKeySchema silently overwrites the earlier event's `(version, idx)` tuple, causing permanent event history corruption that may go undetected.

## Finding Description
At lines 436-440 in `storage/indexer/src/db_indexer.rs`, V1 events are indexed without checking for duplicate `(event_key, sequence_number)` pairs: [1](#0-0) 

The `SchemaBatch::put()` method appends write operations to an internal vector without duplicate checking: [2](#0-1) 

When the batch is committed to RocksDB, multiple writes to the same key result in the last write winning (overwrite): [3](#0-2) 

**Breaking Event History Integrity Invariant:**

The Aptos event system guarantees unique `(GUID, sequence_number)` pairs per the event specification. However, the indexer's lack of validation creates a defense-in-depth gap. If the Move VM or event emission logic has a bug allowing duplicate sequence numbers, or if malicious native functions manipulate event metadata, the indexer will silently corrupt event history.

**Detection Limitations:**

The existing validation in `lookup_events_by_key` only checks for sequence number continuity (gaps), not overwrites: [4](#0-3) 

If event A at `(key, seq=5, version=100, idx=0)` is overwritten by event B at `(key, seq=5, version=101, idx=3)`, the sequence appears continuous (5, 6, 7...) and the corruption is **undetected**.

## Impact Explanation
**Severity: High (Defense-in-Depth Failure)**

This vulnerability does not directly allow exploitation by external attackers, but it represents a critical defense-in-depth failure that amplifies the impact of potential Move VM bugs:

1. **Event History Corruption**: Applications relying on complete event history (indexers, analytics, audit trails) would miss events silently
2. **Consensus Non-Determinism Risk**: If different validators process events differently due to timing or caching issues, event indices could diverge
3. **No Detection Mechanism**: The corruption bypasses existing validation checks
4. **Permanent Data Loss**: Overwritten events are permanently lost from the index (though still in EventSchema)

While this requires a separate vulnerability to trigger (Move VM bug or malicious native function), the silent failure mode and lack of validation make this a significant weakness in critical infrastructure.

## Likelihood Explanation
**Likelihood: Low (Requires Precondition)**

Direct exploitation requires one of:
- **Move VM bug** allowing duplicate event sequence numbers to be emitted
- **Malicious native function** manipulating event metadata
- **Race condition** in V2 event translation (mitigated by caching)
- **Indexer manipulation** requiring node-level access

Under normal operation with correct Move VM behavior, duplicate sequence numbers should not occur because:
- EventHandle counters are incremented atomically in Move code
- V2 translation uses in-memory caching to prevent duplicates within batches
- Batch commits are atomic (no partial indexing)

However, the lack of defensive validation means **any** future bug in event emission will cause silent corruption rather than failing safely.

## Recommendation
**Add duplicate detection during event indexing:**

```rust
// In process_a_batch(), before indexing V1 events:
if self.indexer_db.event_enabled() {
    let mut indexed_events: HashSet<(EventKey, u64)> = HashSet::new();
    events.iter().enumerate().try_for_each(|(idx, event)| {
        if let ContractEvent::V1(v1) = event {
            let key_seq = (*v1.key(), v1.sequence_number());
            
            // Check for duplicates within batch
            ensure!(
                indexed_events.insert(key_seq.clone()),
                "Duplicate event sequence number detected: key={:?}, seq={}",
                key_seq.0,
                key_seq.1
            );
            
            // Optional: Check against DB for cross-batch duplicates
            if self.indexer_db.db.get::<EventByKeySchema>(&key_seq)?.is_some() {
                warn!("Event already indexed: key={:?}, seq={}", key_seq.0, key_seq.1);
            }
            
            batch.put::<EventByKeySchema>(&key_seq, &(version, idx as u64))?;
            // ... rest of indexing
        }
        Ok::<(), AptosDbError>(())
    })?;
}
```

**Alternative: Add validation on read with alerting:** [5](#0-4) 

Enhance the error message to include alerts when corruption is detected during reads.

## Proof of Concept
**PoC cannot be demonstrated** because:

1. **No known Move VM bug** exists that allows duplicate event sequence numbers
2. **Cannot manipulate event emission** without modifying core Move runtime
3. **Test environment** would require injecting malformed events at the VM level

**Theoretical scenario** (not implementable without VM modification):
```
Transaction at version 100:
  - Emits Event V1: (key=K, seq=5, version=100, idx=0)
  - Hypothetical VM bug causes: (key=K, seq=5, version=100, idx=1)
  
Indexing result:
  - EventByKeySchema[(K, 5)] = (100, 0)  // First write
  - EventByKeySchema[(K, 5)] = (100, 1)  // Overwrites first
  
Result: Event at idx=0 is permanently lost from index
Reading events starting at seq=5 returns idx=1 only
```

Without ability to trigger duplicate sequence numbers in Move, a complete PoC cannot be provided.

---

**Notes:**

This issue exists in the indexer component specifically. The main event storage in `storage/aptosdb/src/ledger_db/event_db.rs` has identical behavior: [6](#0-5) 

Both indexer and main storage lack duplicate validation, making this a systemic defense-in-depth gap rather than an isolated issue.

### Citations

**File:** storage/indexer/src/db_indexer.rs (L232-239)
```rust
            if seq != cur_seq {
                let msg = if cur_seq == start_seq_num {
                    "First requested event is probably pruned."
                } else {
                    "DB corruption: Sequence number not continuous."
                };
                bail!("{} expected: {}, actual: {}", msg, cur_seq, seq);
            }
```

**File:** storage/indexer/src/db_indexer.rs (L434-440)
```rust
                    if let ContractEvent::V1(v1) = event {
                        batch
                            .put::<EventByKeySchema>(
                                &(*v1.key(), v1.sequence_number()),
                                &(version, idx as u64),
                            )
                            .expect("Failed to put events by key to a batch");
```

**File:** storage/schemadb/src/batch.rs (L156-163)
```rust
    fn raw_put(&mut self, cf_name: ColumnFamilyName, key: Vec<u8>, value: Vec<u8>) -> DbResult<()> {
        self.rows
            .entry(cf_name)
            .or_default()
            .push(WriteOp::Value { key, value });

        Ok(())
    }
```

**File:** storage/schemadb/src/batch.rs (L183-190)
```rust
        for (cf_name, rows) in rows.iter() {
            let cf_handle = db.get_cf_handle(cf_name)?;
            for write_op in rows {
                match write_op {
                    WriteOp::Value { key, value } => db_batch.put_cf(cf_handle, key, value),
                    WriteOp::Deletion { key } => db_batch.delete_cf(cf_handle, key),
                }
            }
```

**File:** storage/aptosdb/src/event_store/mod.rs (L130-136)
```rust
            if seq != cur_seq {
                let msg = if cur_seq == start_seq_num {
                    "First requested event is probably pruned."
                } else {
                    "DB corruption: Sequence number not continuous."
                };
                db_other_bail!("{} expected: {}, actual: {}", msg, cur_seq, seq);
```

**File:** storage/aptosdb/src/ledger_db/event_db.rs (L157-167)
```rust
                if let ContractEvent::V1(v1) = event {
                    if !skip_index {
                        batch.put::<EventByKeySchema>(
                            &(*v1.key(), v1.sequence_number()),
                            &(version, idx as u64),
                        )?;
                        batch.put::<EventByVersionSchema>(
                            &(*v1.key(), version, v1.sequence_number()),
                            &(idx as u64),
                        )?;
                    }
```

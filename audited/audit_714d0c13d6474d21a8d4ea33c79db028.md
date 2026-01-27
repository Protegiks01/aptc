# Audit Report

## Title
Event Sequence Number Monotonicity Validation Gap in Internal Indexer Verification

## Summary
The `verify_event_by_key()` function in the database debugger validation tool does not validate that event sequence numbers are monotonically increasing or continuous for a given event key, potentially allowing database corruption or indexer bugs to go undetected during validation.

## Finding Description

The validation function `verify_event_by_key()` only checks that individual events exist in the internal indexer database with matching version and index values, but does not verify the critical invariant that event sequence numbers must be strictly monotonic and continuous for each event key. [1](#0-0) 

The function simply looks up each event by `(event_key, seq_num)` and verifies existence, but when called from `verify_events()`, it iterates through events as they appear in transactions without tracking whether sequence numbers for a specific event key are monotonic or have gaps. [2](#0-1) 

In contrast, the production query path in `lookup_events_by_key()` DOES validate sequence number continuity: [3](#0-2) 

This creates an inconsistency where corrupted or incorrectly indexed events could pass validation but fail during actual queries.

The internal indexer directly stores events without sequence validation: [4](#0-3) 

**Attack Scenarios:**
1. **Event V2 Translation Bug**: If the event sequence number cache or `EventSequenceNumberSchema` becomes desynchronized, events could be indexed with non-monotonic or gapped sequence numbers.
2. **Database Corruption**: Direct database corruption affecting the internal indexer would not be detected by this validation.
3. **Concurrent Processing Race**: The indexer uses concurrent caching which could theoretically lead to sequence number conflicts. [5](#0-4) 

## Impact Explanation

**Severity Assessment: Medium**

While this is a validation gap rather than a direct execution vulnerability, it has significant implications:

- **Event History Integrity**: Events are the primary audit trail for blockchain state changes, including coin transfers, NFT operations, and governance actions
- **Query Inconsistency**: Corrupted event indices could cause different query results from different code paths
- **Detection Failure**: Database corruption or indexer bugs affecting event ordering would not be caught during validation runs

This does not qualify as High/Critical severity because:
- It's a debugging/validation tool limitation, not a runtime security enforcement failure
- Normal event emission through Move code ensures proper sequencing
- Query operations do validate continuity
- No direct path to funds loss or consensus violation

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability could manifest through:
- Bugs in the event V2 translation engine managing sequence numbers
- Database restoration/migration issues
- Race conditions in concurrent event indexing

However, exploitation requires an underlying bug in event storage or indexing, not just the validation gap itself.

## Recommendation

Add sequence number monotonicity validation to `verify_events()`:

```rust
fn verify_events(
    transaction_list: &TransactionListWithProofV2,
    internal_indexer_db: &DB,
    start_version: u64,
) -> Result<()> {
    let mut version = start_version;
    // Track last seen sequence number per event key
    let mut last_seq_per_key: HashMap<EventKey, u64> = HashMap::new();
    
    match &transaction_list.get_transaction_list_with_proof().events {
        None => return Ok(()),
        Some(event_vec) => {
            for events in event_vec {
                for (idx, event) in events.iter().enumerate() {
                    match event {
                        ContractEvent::V1(event) => {
                            let seq_num = event.sequence_number();
                            let event_key = event.key();
                            
                            // Validate monotonicity
                            if let Some(&last_seq) = last_seq_per_key.get(event_key) {
                                ensure!(
                                    seq_num > last_seq,
                                    "Event sequence number not monotonic: key={:?}, prev={}, curr={}",
                                    event_key, last_seq, seq_num
                                );
                            }
                            last_seq_per_key.insert(*event_key, seq_num);
                            
                            verify_event_by_version(event_key, seq_num, internal_indexer_db, version, idx)?;
                            verify_event_by_key(event_key, seq_num, internal_indexer_db, idx, version)?;
                        },
                        _ => continue,
                    }
                }
                version += 1;
            }
        },
    }
    
    // Additional validation: for each event key, verify no gaps by querying full range
    for (event_key, last_seq) in last_seq_per_key {
        // Use lookup_events_by_key which validates continuity
        let _events = EventStore::new(Arc::clone(&internal_indexer_db))
            .lookup_events_by_key(&event_key, 0, last_seq + 1, version - 1)?;
    }
    
    Ok(())
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_types::{contract_event::ContractEvent, event::EventKey};
    
    #[test]
    fn test_non_monotonic_events_undetected() {
        // Setup: Create internal indexer DB with events having non-monotonic sequence numbers
        let tmpdir = aptos_temppath::TempPath::new();
        let internal_db = open_internal_indexer_db(&tmpdir, &RocksdbConfig::default()).unwrap();
        
        let event_key = EventKey::random();
        let mut batch = SchemaBatch::new();
        
        // Insert events with sequence numbers: 0, 2, 1 (non-monotonic)
        batch.put::<EventByKeySchema>(&(event_key, 0), &(100, 0)).unwrap();
        batch.put::<EventByKeySchema>(&(event_key, 2), &(101, 0)).unwrap(); // Skip 1
        batch.put::<EventByKeySchema>(&(event_key, 1), &(102, 0)).unwrap(); // Out of order
        
        internal_db.write_schemas(batch).unwrap();
        
        // Create transaction list with events in order they appear in blocks
        let events_v100 = vec![create_v1_event(event_key, 0)];
        let events_v101 = vec![create_v1_event(event_key, 2)];
        let events_v102 = vec![create_v1_event(event_key, 1)];
        
        let txn_list = create_transaction_list_with_events(vec![
            events_v100, events_v101, events_v102
        ]);
        
        // Current implementation will PASS validation (bug)
        assert!(verify_events(&txn_list, &internal_db, 100).is_ok());
        
        // But querying would FAIL (inconsistency)
        let event_store = EventStore::new(Arc::new(internal_db));
        assert!(event_store.lookup_events_by_key(&event_key, 0, 3, 102).is_err());
    }
}
```

**Notes:**
- This vulnerability is a validation tool limitation rather than a direct runtime security flaw
- The production code path for event queries (`lookup_events_by_key()`) does validate continuity, providing some protection
- The root cause would typically be a bug in event indexing or database corruption, but the validation gap prevents detection
- Events are critical for audit trails, so validation completeness is important for database integrity verification

### Citations

**File:** storage/aptosdb/src/db_debugger/validation.rs (L228-253)
```rust
fn verify_event_by_key(
    event_key: &EventKey,
    seq_num: u64,
    internal_indexer_db: &DB,
    expected_idx: usize,
    expected_version: u64,
) -> Result<()> {
    match internal_indexer_db.get::<EventByKeySchema>(&(*event_key, seq_num)) {
        Ok(None) => {
            panic!("Event not found in internal indexer db: {:?}", event_key);
        },
        Err(e) => {
            panic!("Error while fetching event: {:?}", e);
        },
        Ok(Some((version, idx))) => {
            assert!(idx as usize == expected_idx && version == expected_version);
            if version as usize % SAMPLE_RATE == 0 {
                println!(
                    "Processed {} at {:?}, {:?}",
                    version, event_key, expected_idx
                );
            }
        },
    }
    Ok(())
}
```

**File:** storage/aptosdb/src/db_debugger/validation.rs (L276-316)
```rust
fn verify_events(
    transaction_list: &TransactionListWithProofV2,
    internal_indexer_db: &DB,
    start_version: u64,
) -> Result<()> {
    let mut version = start_version;
    match &transaction_list.get_transaction_list_with_proof().events {
        None => {
            return Ok(());
        },
        Some(event_vec) => {
            for events in event_vec {
                for (idx, event) in events.iter().enumerate() {
                    match event {
                        ContractEvent::V1(event) => {
                            let seq_num = event.sequence_number();
                            let event_key = event.key();
                            verify_event_by_version(
                                event_key,
                                seq_num,
                                internal_indexer_db,
                                version,
                                idx,
                            )?;
                            verify_event_by_key(
                                event_key,
                                seq_num,
                                internal_indexer_db,
                                idx,
                                version,
                            )?;
                        },
                        _ => continue,
                    }
                }
                version += 1;
            }
        },
    }
    Ok(())
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

**File:** storage/indexer/src/db_indexer.rs (L464-469)
```rust
                                batch
                                    .put::<EventByKeySchema>(
                                        &(key, sequence_number),
                                        &(version, idx as u64),
                                    )
                                    .expect("Failed to put events by key to a batch");
```

**File:** storage/indexer/src/event_v2_translator.rs (L68-74)
```rust
pub struct EventV2TranslationEngine {
    pub main_db_reader: Arc<dyn DbReader>,
    pub internal_indexer_db: Arc<DB>,
    // Map from event type to translator
    pub translators: HashMap<TypeTag, Box<dyn EventV2Translator + Send + Sync>>,
    event_sequence_number_cache: DashMap<EventKey, u64>,
}
```

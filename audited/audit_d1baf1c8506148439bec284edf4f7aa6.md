# Audit Report

## Title
EventSequenceNumberSchema Corruption Leads to Silent Event Skipping and Indexer Inconsistency

## Summary
The indexer's `decode_key()` function in EventSequenceNumberSchema lacks retry logic and error recovery mechanisms. When database corruption occurs, the indexer silently skips affected events, logs a warning, and continues processing, resulting in permanent sequence number gaps in the indexed event stream.

## Finding Description

The EventSequenceNumberSchema stores event sequence numbers using BCS encoding. [1](#0-0) 

When processing V2 events for translation, the indexer reads from this schema to determine the next sequence number. [2](#0-1) 

If the stored data is corrupted (due to disk errors, bit flips, or database inconsistencies), `decode_key()` or `decode_value()` will fail with a BCS deserialization error. This error propagates through the translator's `translate_event_v2_to_v1` method and is caught by the error handler. [3](#0-2) 

The error handler logs a warning but converts all translation errors to `Ok(None)`, causing the event to be completely skipped from indexing. [4](#0-3) 

This creates permanent gaps in the EventByKeySchema and EventByVersionSchema indices, which are later detected when users query events. [5](#0-4) 

## Impact Explanation

This issue qualifies as **Medium Severity** because:

1. **State Inconsistency**: Different nodes with different corruption patterns will have inconsistent indexer state, violating the "State Consistency" invariant
2. **Data Availability**: Users querying events via the indexer API will receive incomplete results with unexplained gaps
3. **No Self-Recovery**: Once events are skipped, they remain missing permanently unless the entire indexer is rebuilt from scratch
4. **Silent Failure**: The system continues operating normally while silently losing data, making the issue difficult to detect

However, impact is limited because:
- The canonical blockchain data remains intact
- Consensus is not affected
- No funds are at risk
- Only indexer queries are impacted

## Likelihood Explanation

**Likelihood: Low to Medium**

Database corruption can occur through:
1. **Hardware failures**: Disk errors, memory corruption, power failures
2. **Software bugs**: RocksDB bugs, OS filesystem issues
3. **Operational errors**: Interrupted writes, improper shutdowns
4. **State sync issues**: Corrupted data during database restoration

While individual corruption events may be rare on a single node, across a distributed network with many nodes running continuously, the cumulative probability is non-negligible. The lack of any detection or recovery mechanism means corrupted entries persist indefinitely.

## Recommendation

Implement robust error recovery mechanisms:

1. **Add Validation on Read**: Verify BCS data integrity before deserialization
2. **Implement Retry Logic**: On decode failure, attempt to rebuild the sequence number by querying EventByKeySchema
3. **Add Corruption Detection**: Periodic integrity checks on EventSequenceNumberSchema
4. **Improve Error Handling**: Instead of silently skipping events, either:
   - Rebuild the sequence number from existing indexed events
   - Halt indexing and alert operators of corruption
   - Mark the event key as requiring manual intervention
5. **Add Checksums**: Include checksums in stored data to detect corruption early

Example fix for `get_next_sequence_number`:

```rust
pub fn get_next_sequence_number(&self, event_key: &EventKey, default: u64) -> Result<u64> {
    if let Some(seq) = self.get_cached_sequence_number(event_key) {
        return Ok(seq + 1);
    }
    
    match self.internal_indexer_db.get::<EventSequenceNumberSchema>(event_key) {
        Ok(Some(seq)) => Ok(seq + 1),
        Ok(None) => Ok(default),
        Err(e) => {
            // Attempt recovery by querying EventByKeySchema
            warn!("EventSequenceNumberSchema corrupted for key {:?}, attempting recovery: {}", event_key, e);
            match self.recover_sequence_number_from_index(event_key) {
                Ok(recovered_seq) => {
                    self.cache_sequence_number(event_key, recovered_seq);
                    Ok(recovered_seq + 1)
                }
                Err(recovery_error) => {
                    error!("Failed to recover sequence number for key {:?}: {}", event_key, recovery_error);
                    Err(e) // Propagate original error
                }
            }
        }
    }
}
```

## Proof of Concept

```rust
// Test demonstrating the vulnerability
#[test]
fn test_corrupted_sequence_number_skips_events() {
    // Setup indexer with EventSequenceNumberSchema
    let (indexer_db, main_db) = setup_test_dbs();
    let engine = EventV2TranslationEngine::new(main_db.clone(), indexer_db.clone());
    
    // Write valid sequence number for event_key_1
    let event_key_1 = EventKey::new(1, AccountAddress::random());
    indexer_db.put::<EventSequenceNumberSchema>(&event_key_1, &5).unwrap();
    
    // Manually corrupt the database entry for event_key_1
    // (In practice, this would happen due to disk/memory errors)
    corrupt_database_entry(indexer_db, &event_key_1);
    
    // Create a V2 event that requires translation using event_key_1
    let v2_event = create_test_coin_deposit_event();
    
    // Attempt translation - should fail to read sequence number
    let result = engine.translate_event_v2_to_v1(&v2_event);
    
    // Verify: translation returns Ok(None), event is skipped
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
    
    // Verify: event is NOT indexed in EventByKeySchema
    let indexed_events = indexer_db.get_events_by_key(&event_key_1, 0, 100);
    // Gap exists: events before corruption are indexed, this event is missing
    assert_sequence_gap_exists(indexed_events);
}
```

## Notes

The vulnerability exists but has **limited exploitability** because:
- External attackers cannot directly corrupt the local RocksDB database
- Malicious node operators (insider threat) are outside the trust model
- Natural corruption requires hardware/software failures

This is primarily a **robustness issue** affecting data availability rather than a critical security vulnerability. However, it violates the "State Consistency" invariant by allowing different nodes to have inconsistent indexer states, which could impact applications relying on the indexer API for event data.

### Citations

**File:** storage/indexer_schemas/src/schema/event_sequence_number/mod.rs (L36-38)
```rust
    fn decode_key(data: &[u8]) -> Result<Self> {
        Ok(bcs::from_bytes(data)?)
    }
```

**File:** storage/indexer/src/event_v2_translator.rs (L190-200)
```rust
    pub fn get_next_sequence_number(&self, event_key: &EventKey, default: u64) -> Result<u64> {
        if let Some(seq) = self.get_cached_sequence_number(event_key) {
            Ok(seq + 1)
        } else {
            let seq = self
                .internal_indexer_db
                .get::<EventSequenceNumberSchema>(event_key)?
                .map_or(default, |seq| seq + 1);
            Ok(seq)
        }
    }
```

**File:** storage/indexer/src/db_indexer.rs (L230-242)
```rust
                break;
            }
            if seq != cur_seq {
                let msg = if cur_seq == start_seq_num {
                    "First requested event is probably pruned."
                } else {
                    "DB corruption: Sequence number not continuous."
                };
                bail!("{} expected: {}, actual: {}", msg, cur_seq, seq);
            }
            result.push((seq, ver, idx));
            cur_seq += 1;
        }
```

**File:** storage/indexer/src/db_indexer.rs (L450-482)
```rust
                            if let Some(translated_v1_event) =
                                self.translate_event_v2_to_v1(v2).map_err(|e| {
                                    anyhow::anyhow!(
                                        "Failed to translate event: {:?}. Error: {}",
                                        v2,
                                        e
                                    )
                                })?
                            {
                                let key = *translated_v1_event.key();
                                let sequence_number = translated_v1_event.sequence_number();
                                self.event_v2_translation_engine
                                    .cache_sequence_number(&key, sequence_number);
                                event_keys.insert(key);
                                batch
                                    .put::<EventByKeySchema>(
                                        &(key, sequence_number),
                                        &(version, idx as u64),
                                    )
                                    .expect("Failed to put events by key to a batch");
                                batch
                                    .put::<EventByVersionSchema>(
                                        &(key, version, sequence_number),
                                        &(idx as u64),
                                    )
                                    .expect("Failed to put events by version to a batch");
                                batch
                                    .put::<TranslatedV1EventSchema>(
                                        &(version, idx as u64),
                                        &translated_v1_event,
                                    )
                                    .expect("Failed to put translated v1 events to a batch");
                            }
```

**File:** storage/indexer/src/db_indexer.rs (L562-580)
```rust
            let result = translator.translate_event_v2_to_v1(v2, &self.event_v2_translation_engine);
            match result {
                Ok(v1) => Ok(Some(v1)),
                Err(e) => {
                    // If the token object collection uses ConcurrentSupply, skip the translation and ignore the error.
                    // This is expected, as the event handle won't be found in either FixedSupply or UnlimitedSupply.
                    let is_ignored_error = (v2.type_tag() == &*MINT_TYPE
                        || v2.type_tag() == &*BURN_TYPE)
                        && e.to_string().contains("resource not found");
                    if !is_ignored_error {
                        warn!(
                            "Failed to translate event: {:?}. Error: {}",
                            v2,
                            e.to_string()
                        );
                    }
                    Ok(None)
                },
            }
```

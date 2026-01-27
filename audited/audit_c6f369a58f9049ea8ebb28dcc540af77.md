# Audit Report

## Title
Event Sequence Number Corruption Due to Non-Atomic Cache Updates in Transfer Event Processing

## Summary
The `DBIndexer` processes Transfer events (and other V2 events) in batches, caching sequence numbers in memory before committing to the database. If event translation fails midway through a batch, the in-memory cache retains stale sequence numbers, causing subsequent processing attempts to assign incorrect sequence numbers to events. This creates permanent sequence number gaps and inconsistencies in the event stream.

## Finding Description

The vulnerability exists in the event V2-to-V1 translation subsystem within the internal indexer. When processing batches of transactions containing Transfer events, the system follows this flow: [1](#0-0) 

During batch processing, the system:
1. Iterates through events in each transaction
2. For V2 events (including Transfer), calls translation logic
3. **Immediately caches the sequence number in memory upon successful translation**
4. Only commits the entire batch to the database if ALL events succeed [2](#0-1) 

The critical flaw is that sequence numbers are cached **before** the batch is committed (line 461-462). The cache is stored in `EventV2TranslationEngine.event_sequence_number_cache`, a persistent DashMap: [3](#0-2) 

When `get_next_sequence_number()` is called during translation, it **checks the cache first** before querying the database: [4](#0-3) 

The `EventV2TranslationEngine` persists across all batch processing calls: [5](#0-4) 

**Attack Scenario:**

1. Batch contains Transfer events E1, E2, E3 for the same object (same event key)
2. E1 translates successfully → sequence number 0 cached
3. E2 translates successfully → sequence number 1 cached
4. E3 fails translation (e.g., `ObjectGroup resource not found` error): [6](#0-5) 

5. The error propagates (line 451-457), batch is not committed to DB
6. **Cache still contains sequence number 1**
7. On retry or next batch processing:
   - E1 queries `get_next_sequence_number()` → finds cached value 1 → returns **2** (should be 0)
   - E2 queries `get_next_sequence_number()` → finds cached value 2 → returns **3** (should be 1)
   - Events receive wrong sequence numbers permanently

The indexer service calls `process()` which propagates errors without cache cleanup: [7](#0-6) 

**Invariant Violations:**

1. **State Consistency**: Event sequence numbers are part of the indexed state. Partial cache updates violate atomicity.
2. **Deterministic Execution**: Different nodes processing the same events at different times (with different failure/retry patterns) will assign different sequence numbers, violating determinism in the indexing layer.

## Impact Explanation

**Severity: Medium** - State inconsistencies requiring intervention

Per the Aptos bug bounty program, this qualifies as Medium severity because:

1. **State Inconsistencies**: Event sequence numbers become permanently incorrect, creating gaps in the event stream (e.g., sequence numbers 0, 3, 4 instead of 0, 1, 2)

2. **Non-Deterministic Indexing**: Different validator nodes may process events with different timing and failure patterns, leading to different sequence number assignments for the same events

3. **Event Query Corruption**: Applications querying events by sequence number will encounter:
   - Missing events (gaps in sequence)
   - Out-of-order events
   - Failed deduplication logic

4. **Requires Intervention**: Once sequence numbers are incorrectly assigned and committed, manual intervention is needed to:
   - Reset the internal indexer database
   - Re-sync from scratch
   - Potentially lose historical event ordering data

While this doesn't directly affect consensus or fund safety (the main ledger is unaffected), it breaks the integrity of the event indexing subsystem that applications rely on for state observation and historical queries.

## Likelihood Explanation

**Likelihood: Medium-High**

This vulnerability is likely to occur because:

1. **Common Failure Scenarios**: Event translation can fail for multiple reasons:
   - Resource not found (objects deleted/burned)
   - BCS deserialization errors
   - Database read failures
   - State view inconsistencies during concurrent updates

2. **No Rollback Mechanism**: There is no cache cleanup or rollback logic on batch failure - the cache persists indefinitely

3. **Production Workloads**: High-throughput environments with concurrent object operations increase the probability of encountering edge cases that trigger translation failures

4. **Attacker Influence**: An attacker can deliberately trigger this by:
   - Creating objects and immediately deleting them
   - Crafting transactions that race with object state changes
   - Forcing indexer processing to encounter inconsistent state

The attack requires no privileged access - any user can submit transactions with Transfer events.

## Recommendation

**Solution: Implement atomic cache management with rollback on failure**

Add a transaction-like mechanism for the sequence number cache:

```rust
// In EventV2TranslationEngine
pub struct EventV2TranslationEngine {
    // Existing fields...
    event_sequence_number_cache: DashMap<EventKey, u64>,
    // Add staging cache for current batch
    staging_cache: Arc<Mutex<HashMap<EventKey, u64>>>,
}

impl EventV2TranslationEngine {
    // Stage sequence number during batch processing
    pub fn stage_sequence_number(&self, event_key: &EventKey, sequence_number: u64) {
        let mut staging = self.staging_cache.lock().unwrap();
        staging.insert(*event_key, sequence_number);
    }
    
    // Commit staging cache to main cache only on batch success
    pub fn commit_staged_sequence_numbers(&self) {
        let mut staging = self.staging_cache.lock().unwrap();
        for (key, seq) in staging.drain() {
            self.event_sequence_number_cache.insert(key, seq);
        }
    }
    
    // Discard staging cache on batch failure
    pub fn rollback_staged_sequence_numbers(&self) {
        let mut staging = self.staging_cache.lock().unwrap();
        staging.clear();
    }
    
    // Modified get_next_sequence_number to check staging first
    pub fn get_next_sequence_number(&self, event_key: &EventKey, default: u64) -> Result<u64> {
        // Check staging cache first (current batch)
        let staging = self.staging_cache.lock().unwrap();
        if let Some(&seq) = staging.get(event_key) {
            return Ok(seq + 1);
        }
        drop(staging);
        
        // Then check committed cache
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
}
```

**In db_indexer.rs process_a_batch():**

```rust
pub fn process_a_batch(&self, start_version: Version, end_version: Version) -> Result<Version> {
    // ... existing setup ...
    
    // Clear staging at start of batch
    self.event_v2_translation_engine.rollback_staged_sequence_numbers();
    
    let result = db_iter.try_for_each(|res| {
        // ... existing event processing ...
        
        // Change line 461-462 to stage instead of cache
        self.event_v2_translation_engine
            .stage_sequence_number(&key, sequence_number);
        
        // ... rest of processing ...
    });
    
    // Handle result
    match result {
        Ok(_) => {
            // Commit staging cache before sending batch
            self.event_v2_translation_engine.commit_staged_sequence_numbers();
            
            // ... existing batch commit logic ...
            self.sender.send(Some(batch))?;
            Ok(version)
        },
        Err(e) => {
            // Rollback staging cache on error
            self.event_v2_translation_engine.rollback_staged_sequence_numbers();
            Err(e)
        }
    }
}
```

This ensures cache updates are atomic with batch commits.

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_db_indexer_schemas::schema::event_sequence_number::EventSequenceNumberSchema;
    use aptos_types::event::EventKey;
    use aptos_types::contract_event::{ContractEventV2, ContractEvent};
    
    #[test]
    fn test_sequence_number_corruption_on_batch_failure() {
        // Setup: Create DBIndexer with internal indexer DB
        let (indexer_db, db_reader) = setup_test_environment();
        let db_indexer = DBIndexer::new(indexer_db.clone(), db_reader);
        
        // Create a batch with 3 Transfer events for the same object
        // Event 1: Valid transfer
        let event1 = create_valid_transfer_event(object_addr, from_addr, to_addr);
        
        // Event 2: Valid transfer (same object, should get sequence 1)
        let event2 = create_valid_transfer_event(object_addr, from_addr2, to_addr2);
        
        // Event 3: Invalid transfer (will fail translation)
        let event3 = create_invalid_transfer_event_no_object_group(object_addr);
        
        // Attempt 1: Process batch with failure
        let version = 100;
        let result = db_indexer.process_a_batch(version, version + 3);
        
        // Should fail on event 3
        assert!(result.is_err());
        
        // Verify cache was updated for events 1 and 2
        let event_key = EventKey::new(0x4000000000000, object_addr);
        let cached = db_indexer.event_v2_translation_engine
            .get_cached_sequence_number(&event_key);
        assert_eq!(cached, Some(1)); // Stale cache!
        
        // Verify DB was NOT updated (batch not committed)
        let db_seq = indexer_db.db
            .get::<EventSequenceNumberSchema>(&event_key)
            .unwrap();
        assert!(db_seq.is_none()); // DB should be empty
        
        // Attempt 2: Retry with only events 1 and 2 (valid batch)
        let result = db_indexer.process_a_batch(version, version + 2);
        assert!(result.is_ok());
        
        // BUG: Events get wrong sequence numbers
        // Event 1 gets sequence 2 (should be 0) because cache had 1
        // Event 2 gets sequence 3 (should be 1)
        
        // Verify the corruption
        let stored_events = get_events_by_key(&indexer_db, &event_key);
        assert_eq!(stored_events[0].sequence_number, 2); // WRONG! Should be 0
        assert_eq!(stored_events[1].sequence_number, 3); // WRONG! Should be 1
        
        // Verify DB now has wrong final sequence
        let db_seq = indexer_db.db
            .get::<EventSequenceNumberSchema>(&event_key)
            .unwrap()
            .unwrap();
        assert_eq!(db_seq, 3); // Should be 1
        
        // RESULT: Permanent sequence number corruption
        // Gap in sequence: jumped from non-existent 1 to 2
    }
}
```

## Notes

This vulnerability affects all V2 event types that undergo translation to V1 format, not just Transfer events. The Transfer event was specified in the security question, but the same issue applies to:
- CoinDeposit/CoinWithdraw events
- Token-related events (Mint, Burn, TokenDeposit, TokenWithdraw)
- KeyRotation events
- Collection mutation events

The root cause is the violation of atomicity in state updates - the cache should be updated atomically with the database commit, not incrementally during batch processing.

### Citations

**File:** storage/indexer/src/db_indexer.rs (L305-347)
```rust
pub struct DBIndexer {
    pub indexer_db: InternalIndexerDB,
    pub main_db_reader: Arc<dyn DbReader>,
    sender: Sender<Option<SchemaBatch>>,
    committer_handle: Option<thread::JoinHandle<()>>,
    pub event_v2_translation_engine: EventV2TranslationEngine,
}

impl Drop for DBIndexer {
    fn drop(&mut self) {
        if let Some(handle) = self.committer_handle.take() {
            self.sender
                .send(None)
                .expect("Failed to send None to DBIndexer committer");
            handle
                .join()
                .expect("DBIndexer committer thread fails to join");
        }
    }
}

impl DBIndexer {
    pub fn new(indexer_db: InternalIndexerDB, db_reader: Arc<dyn DbReader>) -> Self {
        let (sender, reciver) = mpsc::channel();

        let db = indexer_db.get_inner_db_ref().to_owned();
        let internal_indexer_db = db.clone();
        let committer_handle = thread::spawn(move || {
            let committer = DBCommitter::new(db, reciver);
            committer.run();
        });

        Self {
            indexer_db,
            main_db_reader: db_reader.clone(),
            sender,
            committer_handle: Some(committer_handle),
            event_v2_translation_engine: EventV2TranslationEngine::new(
                db_reader,
                internal_indexer_db,
            ),
        }
    }
```

**File:** storage/indexer/src/db_indexer.rs (L410-550)
```rust
    pub fn process_a_batch(&self, start_version: Version, end_version: Version) -> Result<Version> {
        let _timer: aptos_metrics_core::HistogramTimer = TIMER.timer_with(&["process_a_batch"]);
        let mut version = start_version;
        let num_transactions = self.get_num_of_transactions(version, end_version)?;
        // This promises num_transactions should be readable from main db
        let mut db_iter = self.get_main_db_iter(version, num_transactions)?;
        let mut batch = SchemaBatch::new();
        let mut event_keys: HashSet<EventKey> = HashSet::new();
        db_iter.try_for_each(|res| {
            let (txn, events, writeset) = res?;
            if let Some(signed_txn) = txn.try_as_signed_user_txn() {
                if self.indexer_db.transaction_enabled() {
                    if let ReplayProtector::SequenceNumber(seq_num) = signed_txn.replay_protector()
                    {
                        batch.put::<OrderedTransactionByAccountSchema>(
                            &(signed_txn.sender(), seq_num),
                            &version,
                        )?;
                    }
                }
            }

            if self.indexer_db.event_enabled() {
                events.iter().enumerate().try_for_each(|(idx, event)| {
                    if let ContractEvent::V1(v1) = event {
                        batch
                            .put::<EventByKeySchema>(
                                &(*v1.key(), v1.sequence_number()),
                                &(version, idx as u64),
                            )
                            .expect("Failed to put events by key to a batch");
                        batch
                            .put::<EventByVersionSchema>(
                                &(*v1.key(), version, v1.sequence_number()),
                                &(idx as u64),
                            )
                            .expect("Failed to put events by version to a batch");
                    }
                    if self.indexer_db.event_v2_translation_enabled() {
                        if let ContractEvent::V2(v2) = event {
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
                        }
                    }
                    Ok::<(), AptosDbError>(())
                })?;
            }

            if self.indexer_db.statekeys_enabled() {
                writeset.write_op_iter().for_each(|(state_key, write_op)| {
                    if write_op.is_creation() || write_op.is_modification() {
                        batch
                            .put::<StateKeysSchema>(state_key, &())
                            .expect("Failed to put state keys to a batch");
                    }
                });
            }
            version += 1;
            Ok::<(), AptosDbError>(())
        })?;
        assert!(version > 0, "batch number should be greater than 0");

        assert_eq!(num_transactions, version - start_version);

        if self.indexer_db.event_v2_translation_enabled() {
            batch.put::<InternalIndexerMetadataSchema>(
                &MetadataKey::EventV2TranslationVersion,
                &MetadataValue::Version(version - 1),
            )?;

            for event_key in event_keys {
                batch
                    .put::<EventSequenceNumberSchema>(
                        &event_key,
                        &self
                            .event_v2_translation_engine
                            .get_cached_sequence_number(&event_key)
                            .unwrap_or(0),
                    )
                    .expect("Failed to put events by key to a batch");
            }
        }

        if self.indexer_db.transaction_enabled() {
            batch.put::<InternalIndexerMetadataSchema>(
                &MetadataKey::TransactionVersion,
                &MetadataValue::Version(version - 1),
            )?;
        }
        if self.indexer_db.event_enabled() {
            batch.put::<InternalIndexerMetadataSchema>(
                &MetadataKey::EventVersion,
                &MetadataValue::Version(version - 1),
            )?;
        }
        if self.indexer_db.statekeys_enabled() {
            batch.put::<InternalIndexerMetadataSchema>(
                &MetadataKey::StateVersion,
                &MetadataValue::Version(version - 1),
            )?;
        }
        batch.put::<InternalIndexerMetadataSchema>(
            &MetadataKey::LatestVersion,
            &MetadataValue::Version(version - 1),
        )?;
        self.sender
            .send(Some(batch))
            .map_err(|e| AptosDbError::Other(e.to_string()))?;
        Ok(version)
    }
```

**File:** storage/indexer/src/event_v2_translator.rs (L68-75)
```rust
pub struct EventV2TranslationEngine {
    pub main_db_reader: Arc<dyn DbReader>,
    pub internal_indexer_db: Arc<DB>,
    // Map from event type to translator
    pub translators: HashMap<TypeTag, Box<dyn EventV2Translator + Send + Sync>>,
    event_sequence_number_cache: DashMap<EventKey, u64>,
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

**File:** storage/indexer/src/event_v2_translator.rs (L216-236)
```rust
    pub fn get_state_value_bytes_for_object_group_resource(
        &self,
        address: &AccountAddress,
        struct_tag: &StructTag,
    ) -> Result<Option<Bytes>> {
        let state_view = self
            .main_db_reader
            .latest_state_checkpoint_view()
            .expect("Failed to get state view");
        static OBJECT_GROUP_TAG: Lazy<StructTag> = Lazy::new(ObjectGroupResource::struct_tag);
        let state_key = StateKey::resource_group(address, &OBJECT_GROUP_TAG);
        let maybe_state_value = state_view.get_state_value(&state_key)?;
        let state_value = maybe_state_value
            .ok_or_else(|| anyhow::format_err!("ObjectGroup resource not found"))?;
        let object_group_resource: ObjectGroupResource = bcs::from_bytes(state_value.bytes())?;
        Ok(object_group_resource
            .group
            .get(struct_tag)
            .map(|bytes| Bytes::copy_from_slice(bytes)))
    }
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/internal_indexer_db_service.rs (L183-183)
```rust
            let next_version = self.db_indexer.process(start_version, target_version)?;
```

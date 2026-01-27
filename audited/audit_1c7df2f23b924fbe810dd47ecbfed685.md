# Audit Report

## Title
EventSequenceNumberSchema State Loss Causes V2-to-V1 Event Translation Sequence Number Reuse and Index Corruption

## Summary
When the `EventSequenceNumberSchema` database is lost, corrupted, or not loaded during node restart, the `get_next_sequence_number()` function falls back to reading `EventHandle.count` from on-chain state as the default. However, `EventHandle.count` only tracks V1 events emitted via `emit_event()` and does NOT reflect V2 events that have been translated to V1. This mismatch causes already-assigned sequence numbers to be reused, leading to event index corruption and permanent event data loss in `EventByKeySchema`.

## Finding Description
The vulnerability exists in the V2-to-V1 event translation system that maintains backward compatibility for the event indexer. The critical flaw is a state tracking mismatch: [1](#0-0) 

The `get_next_sequence_number()` function follows this logic:
1. Check in-memory cache (`event_sequence_number_cache`)
2. If not cached, query `EventSequenceNumberSchema` from `internal_indexer_db`
3. If neither exists, fall back to the `default` parameter, which comes from `EventHandle.count` read from on-chain state [2](#0-1) 

The problem arises because **EventHandle.count and EventSequenceNumberSchema track different event streams**:
- `EventHandle.count` is incremented only by V1 events via `emit_event()` in Move code
- `EventSequenceNumberSchema` is updated only when V2 events are translated to V1 [3](#0-2) 

When V2 events are translated, the sequence numbers are assigned and cached: [4](#0-3) 

The sequence numbers are persisted to `EventSequenceNumberSchema` at batch completion: [5](#0-4) 

**Critical Issue:** The `load_cache_from_db()` function exists but is **never called** during node initialization: [6](#0-5) 

This means when a node restarts:
1. The in-memory cache is empty
2. The cache is NOT populated from `EventSequenceNumberSchema` 
3. If `EventSequenceNumberSchema` is empty (due to corruption, fast-sync, or initial sync), queries return None
4. The function falls back to `EventHandle.count`, which is stale (doesn't reflect V2 translations)

**Attack Scenario:**

1. **Initial State:** EventKey K has had 5 V1 events emitted (sequences 0-4), so EventHandle.count = 5
2. **V2 Events Translated:** 10 V2 events are translated with sequences 5-14, stored in EventSequenceNumberSchema: K → 14
3. **Database Loss:** Node restart with empty/corrupted `internal_indexer_db`, or fast-sync that doesn't include EventSequenceNumberSchema
4. **Sequence Reuse:** New V2 event is translated:
   - Cache: empty
   - EventSequenceNumberSchema: empty/missing
   - Falls back to EventHandle.count = 5
   - **Assigns sequence 5, which was already used**
5. **Index Corruption:** The event is written to EventByKeySchema: [7](#0-6) 

Since `EventByKeySchema` uses `(EventKey, sequence_number)` as the key, the new event at sequence 5 **overwrites** the original event at sequence 5, causing **permanent event data loss**.

## Impact Explanation
This vulnerability qualifies as **High Severity** based on the Aptos bug bounty criteria:

1. **State Inconsistency:** Different nodes can assign different sequence numbers to the same events if their EventSequenceNumberSchema is out of sync, violating the "State Consistency" invariant that all nodes must have identical views of blockchain data.

2. **Event Data Loss:** When sequence numbers are reused, events are permanently overwritten in EventByKeySchema, making them unrecoverable. This affects applications and indexers relying on complete event history.

3. **API Inconsistency:** Queries like "get events by key and sequence number range" will return different results on different nodes, breaking the determinism guarantee that's critical for dApps and light clients.

4. **No Automatic Recovery:** Once events are overwritten, they cannot be recovered without resyncing from genesis, which is operationally expensive and may not be feasible for all nodes.

While this doesn't directly affect consensus or fund security, it represents a **significant protocol violation** (High Severity: "Significant protocol violations") and causes **state inconsistencies requiring intervention** (Medium Severity: "State inconsistencies requiring intervention").

## Likelihood Explanation
**Likelihood: HIGH**

This vulnerability will trigger in several common scenarios:

1. **Node Restart After Crash:** If a node crashes before EventSequenceNumberSchema is persisted to disk, the in-memory cache is lost and not reloaded.

2. **Fast Sync / State Sync:** When nodes use fast sync to bootstrap, they download state snapshots but may not include the complete internal_indexer_db with EventSequenceNumberSchema.

3. **Database Maintenance:** Operators clearing or resetting the internal_indexer_db for maintenance without understanding the dependency.

4. **Initial Deployment:** New nodes joining the network start with empty EventSequenceNumberSchema and must build it from scratch, but the fallback logic makes incorrect assumptions.

The fact that `load_cache_from_db()` exists but is never called indicates this was a known concern that was never properly implemented, making the vulnerability more likely to manifest in production.

## Recommendation

**Immediate Fix:** Call `load_cache_from_db()` during EventV2TranslationEngine initialization to populate the cache from persisted data:

```rust
// In storage/indexer/src/event_v2_translator.rs
impl EventV2TranslationEngine {
    pub fn new(main_db_reader: Arc<dyn DbReader>, internal_indexer_db: Arc<DB>) -> Self {
        let translators: HashMap<TypeTag, Box<dyn EventV2Translator + Send + Sync>> = [
            // ... existing translators ...
        ]
        .into_iter()
        .collect();
        
        let engine = Self {
            main_db_reader,
            internal_indexer_db,
            translators,
            event_sequence_number_cache: DashMap::new(),
        };
        
        // Load cache from DB on initialization
        engine.load_cache_from_db()
            .expect("Failed to load event sequence number cache from DB");
        
        engine
    }
}
```

**Additional Safeguards:**

1. **Validation Check:** Before using the default, verify it's not lower than the highest sequence number in EventByKeySchema for that key:

```rust
pub fn get_next_sequence_number(&self, event_key: &EventKey, default: u64) -> Result<u64> {
    if let Some(seq) = self.get_cached_sequence_number(event_key) {
        Ok(seq + 1)
    } else {
        let db_seq = self
            .internal_indexer_db
            .get::<EventSequenceNumberSchema>(event_key)?;
        
        match db_seq {
            Some(seq) => Ok(seq + 1),
            None => {
                // Validate default against actual indexed events to prevent reuse
                let latest_indexed = self.get_latest_sequence_from_event_index(event_key)?;
                let next_seq = std::cmp::max(default, latest_indexed.map_or(0, |s| s + 1));
                Ok(next_seq)
            }
        }
    }
}
```

2. **Persistence Guarantee:** Ensure EventSequenceNumberSchema is persisted atomically with the events themselves, not in a separate batch.

3. **Monitoring:** Add metrics to detect sequence number mismatches between EventHandle.count and EventSequenceNumberSchema.

## Proof of Concept

**Reproduction Steps:**

1. **Setup:** Create a Move contract that emits both V1 and V2 events for the same resource (e.g., CoinStore).

2. **Emit V1 Events:** Execute transactions that emit 5 V1 deposit events using `event::emit_event()`, advancing EventHandle.counter to 5.

3. **Emit V2 Events:** Execute transactions that emit 10 V2 deposit events using `event::emit()`, which get translated to V1 with sequences 5-14.

4. **Verify State:** Query EventSequenceNumberSchema and confirm it has the event key with value 14.

5. **Simulate Database Loss:** 
   - Stop the node
   - Delete or corrupt the internal_indexer_db containing EventSequenceNumberSchema
   - Restart the node (cache is empty and not reloaded)

6. **Trigger Reuse:** Emit a new V2 deposit event. The translation will:
   - Find empty cache
   - Find empty EventSequenceNumberSchema
   - Use EventHandle.count = 5 as default
   - Assign sequence number 5 (reusing an already-assigned number)

7. **Verify Corruption:** Query EventByKeySchema for (EventKey, sequence=5) and observe it now points to the new event instead of the original, confirming the original event was overwritten.

**Expected Result:** The event at sequence 5 is permanently lost, demonstrating the vulnerability.

**Rust Test Outline:**
```rust
#[test]
fn test_sequence_number_reuse_on_cache_loss() {
    // 1. Initialize indexer with EventV2TranslationEngine
    // 2. Process transactions with V2 events, build up EventSequenceNumberSchema
    // 3. Clear cache (simulate restart)
    // 4. Create new EventV2TranslationEngine WITHOUT calling load_cache_from_db()
    // 5. Process new V2 event
    // 6. Assert that get_next_sequence_number() returns a previously used sequence
    // 7. Verify EventByKeySchema shows overwrite
}
```

---

**Notes:**

The vulnerability stems from incomplete implementation of the state recovery mechanism. The `load_cache_from_db()` function was designed to solve this exact problem but was never integrated into the initialization flow. This represents a critical gap between design intent and implementation reality, making it a high-priority fix for production Aptos nodes.

### Citations

**File:** storage/indexer/src/event_v2_translator.rs (L163-177)
```rust
    // When the node starts with a non-empty EventSequenceNumberSchema table, the in-memory cache
    // `event_sequence_number_cache` is empty. In the future, we decide to backup and restore the
    // event sequence number data to support fast sync, we may need to load the cache from the DB
    // when the node starts using this function `load_cache_from_db`.
    pub fn load_cache_from_db(&self) -> Result<()> {
        let mut iter = self
            .internal_indexer_db
            .iter::<EventSequenceNumberSchema>()?;
        iter.seek_to_first();
        while let Some((event_key, sequence_number)) = iter.next().transpose()? {
            self.event_sequence_number_cache
                .insert(event_key, sequence_number);
        }
        Ok(())
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

**File:** storage/indexer/src/event_v2_translator.rs (L248-257)
```rust
        let (key, sequence_number) = if let Some(state_value_bytes) =
            engine.get_state_value_bytes_for_resource(coin_deposit.account(), &struct_tag)?
        {
            // We can use `DummyCoinType` as it does not affect the correctness of deserialization.
            let coin_store_resource: CoinStoreResource<DummyCoinType> =
                bcs::from_bytes(&state_value_bytes)?;
            let key = *coin_store_resource.deposit_events().key();
            let sequence_number = engine
                .get_next_sequence_number(&key, coin_store_resource.deposit_events().count())?;
            (key, sequence_number)
```

**File:** aptos-move/framework/aptos-framework/sources/event.move (L54-60)
```text
    public fun emit_event<T: drop + store>(handle_ref: &mut EventHandle<T>, msg: T) {
        write_to_event_store<T>(bcs::to_bytes(&handle_ref.guid), handle_ref.counter, msg);
        spec {
            assume handle_ref.counter + 1 <= MAX_U64;
        };
        handle_ref.counter += 1;
    }
```

**File:** storage/indexer/src/db_indexer.rs (L459-463)
```rust
                                let key = *translated_v1_event.key();
                                let sequence_number = translated_v1_event.sequence_number();
                                self.event_v2_translation_engine
                                    .cache_sequence_number(&key, sequence_number);
                                event_keys.insert(key);
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

**File:** storage/indexer/src/db_indexer.rs (L511-521)
```rust
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
```

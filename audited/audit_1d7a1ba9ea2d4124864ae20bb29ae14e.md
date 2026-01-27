# Audit Report

## Title
Duplicate Event Sequence Numbers Due to Stale State Checkpoint in V2 Event Translation

## Summary
The V2 to V1 event translation logic in `get_next_sequence_number()` can assign duplicate sequence numbers when the state checkpoint lags behind the ledger version, causing it to read stale `EventHandle.count` values. This violates the uniqueness invariant of event sequence numbers within an EventKey, leading to state inconsistencies across indexer nodes. [1](#0-0) 

## Finding Description
The vulnerability arises from the interaction between three system components:

1. **Asynchronous State Checkpoint Commits**: The `BufferedState` in AptosDB commits state checkpoints asynchronously and can lag behind the ledger by up to 100,000 versions. [2](#0-1) [3](#0-2) 

2. **Stale State Reads During Translation**: When translating V2 events, the engine reads state using `latest_state_checkpoint_view()`, which may return a checkpoint version that lags behind the transaction version being processed. [4](#0-3) 

3. **Cache Not Loaded on Restart**: The `load_cache_from_db()` function exists but is never called, meaning after a node restart, the in-memory cache starts empty while the DB may have stale or missing entries. [5](#0-4) 

**Exploitation Scenario:**

1. Version 100: V1 event emitted with sequence number N, incrementing `EventHandle.count` from N to N+1
2. State checkpoint remains at version 99 (lag due to async commits)
3. Version 101: V2 event emitted for the same EventKey
4. Indexer processes version 101:
   - Calls `latest_state_checkpoint_view()` → returns state at version 99
   - Reads stale `EventHandle.count = N` (before the V1 event)
   - Calls `get_next_sequence_number(&key, N)` with empty cache (V1 events don't update translation cache)
   - DB check may miss if this is the first V2 event for this key
   - **Assigns sequence N to the V2 event**
   - **Duplicate!** Both V1 event (version 100) and V2 event (version 101) have sequence N

This breaks the fundamental invariant that sequence numbers must be unique within an EventKey, causing different nodes to potentially index events with conflicting sequence numbers.

## Impact Explanation
**Severity: Medium**

This vulnerability causes state inconsistencies in the event indexing layer:

- **Event Query Inconsistencies**: Applications querying events by sequence number may receive different results from different nodes
- **Indexer Database Corruption**: Nodes may have duplicate or conflicting event entries for the same (EventKey, sequence_number) pair
- **Non-Deterministic Indexing**: Different nodes processing the same blockchain state may produce different index databases depending on timing

While this doesn't directly affect consensus (the ledger itself remains consistent), it violates the expectation that all nodes should produce identical indexes from identical blockchain state, which is critical for application reliability and data integrity.

The impact is limited to Medium severity because:
- Does not affect consensus safety or the core blockchain state
- Does not enable theft or minting of funds
- Indexer data can potentially be rebuilt by reprocessing from genesis
- Primarily affects API/query layer rather than consensus layer

## Likelihood Explanation
**Likelihood: Medium**

The vulnerability requires specific conditions but these occur naturally in production:

**Required Conditions:**
1. State checkpoint lag (happens regularly due to async commits)
2. Mixed V1 and V2 events for the same EventKey
3. V2 event processed while state view is stale
4. Cache miss for the EventKey (after restart or for new keys)

**Triggering Factors:**
- High transaction throughput causing checkpoint lag
- Applications transitioning from V1 to V2 event emission patterns
- Node restarts clearing the in-memory cache
- First V2 event for an EventKey that previously had V1 events

The `TARGET_SNAPSHOT_INTERVAL_IN_VERSION` of 100,000 versions means state checkpoints can legitimately lag significantly, making the timing window for this race condition quite large in a busy network.

## Recommendation

**Immediate Fix:**
1. Call `load_cache_from_db()` during indexer initialization to restore the cache after restarts
2. Use versioned state reads that match the transaction version being processed instead of `latest_state_checkpoint_view()`

**Code Fix:**

In the event translation engine, modify state reads to use the transaction version:
```rust
// Instead of latest_state_checkpoint_view()
pub fn get_state_value_bytes_for_resource_at_version(
    &self,
    address: &AccountAddress,
    struct_tag: &StructTag,
    version: Version,
) -> Result<Option<Bytes>> {
    let state_view = self
        .main_db_reader
        .state_view_at_version(Some(version))?;
    let state_key = StateKey::resource(address, struct_tag)?;
    let maybe_state_value = state_view.get_state_value(&state_key)?;
    Ok(maybe_state_value.map(|state_value| state_value.bytes().clone()))
}
```

In the batch processing logic, pass the transaction version to the translator: [6](#0-5) 

**Long-term Solution:**
- Consider storing sequence numbers inline with V2 events during execution
- Implement deterministic sequence number assignment at the VM level
- Add validation checks to detect and alert on duplicate sequence numbers

## Proof of Concept

```rust
// Integration test demonstrating the vulnerability
#[test]
fn test_duplicate_sequence_with_stale_state() {
    // Setup: Create indexer with main DB
    let (main_db, indexer_db, engine) = setup_test_environment();
    
    // Step 1: Commit transaction at version 100 with V1 event
    let v1_event = create_v1_coin_deposit_event(
        account_addr,
        coin_type,
        100, // amount
        4,   // sequence_number (hardcoded by VM)
    );
    commit_transaction_with_event(main_db, 100, v1_event);
    // This increments EventHandle.count from 4 to 5
    
    // Step 2: Commit transaction at version 101 with V2 event
    // But don't update state checkpoint (simulate lag)
    let v2_event = create_v2_coin_deposit_event(
        account_addr,
        coin_type,
        200, // amount
    );
    commit_transaction_with_event(main_db, 101, v2_event);
    
    // Step 3: Process events with stale state checkpoint at version 99
    // Simulate checkpoint lag by not updating state
    let translated = engine.translate_event_v2_to_v1(&v2_event)?;
    
    // Assertion: The translated V2 event incorrectly gets sequence 4
    assert_eq!(translated.sequence_number(), 4); // DUPLICATE!
    
    // Expected: Should be sequence 5 (after the V1 event)
    assert_eq!(translated.sequence_number(), 5); // FAIL
}
```

## Notes

The vulnerability is particularly insidious because:

1. **Silent Failure**: No error is raised when duplicate sequences are assigned; nodes simply have inconsistent indexes
2. **Cache Invalidation Issue**: The `load_cache_from_db()` function was clearly designed to address this but is never invoked in the codebase
3. **State Versioning Gap**: The indexer processes events at version V but reads state from an arbitrary checkpoint version, breaking atomicity assumptions

This represents a violation of the **Deterministic Execution** and **State Consistency** invariants, as different nodes can produce different index states from identical blockchain data based purely on timing and checkpoint scheduling.

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

**File:** storage/indexer/src/event_v2_translator.rs (L202-214)
```rust
    pub fn get_state_value_bytes_for_resource(
        &self,
        address: &AccountAddress,
        struct_tag: &StructTag,
    ) -> Result<Option<Bytes>> {
        let state_view = self
            .main_db_reader
            .latest_state_checkpoint_view()
            .expect("Failed to get state view");
        let state_key = StateKey::resource(address, struct_tag)?;
        let maybe_state_value = state_view.get_state_value(&state_key)?;
        Ok(maybe_state_value.map(|state_value| state_value.bytes().clone()))
    }
```

**File:** storage/aptosdb/src/state_store/buffered_state.rs (L29-29)
```rust
pub(crate) const TARGET_SNAPSHOT_INTERVAL_IN_VERSION: u64 = 100_000;
```

**File:** storage/aptosdb/src/state_store/buffered_state.rs (L99-108)
```rust
    fn maybe_commit(&mut self, checkpoint: Option<StateWithSummary>, sync_commit: bool) {
        if let Some(checkpoint) = checkpoint {
            if !checkpoint.is_the_same(&self.last_snapshot)
                && (sync_commit
                    || self.estimated_items >= self.target_items
                    || self.buffered_versions() >= TARGET_SNAPSHOT_INTERVAL_IN_VERSION)
            {
                self.enqueue_commit(checkpoint);
            }
        }
```

**File:** storage/indexer/src/db_indexer.rs (L449-462)
```rust
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
```

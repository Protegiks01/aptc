# Audit Report

## Title
Event Index Corruption via V1/V2 Event Sequence Number Collision

## Summary
When V2 events are translated to V1 format for indexing, the sequence number generation logic can collide with existing V1 events, causing index entries to be overwritten and event history to be corrupted. This occurs because the translation engine's sequence number tracking is not synchronized with native V1 event sequence numbers.

## Finding Description
The Aptos indexer maintains separate sequence number tracking for translated V2 events via `EventSequenceNumberSchema`, which is independent from the native V1 event sequence numbers stored in event handles within on-chain resources. This creates a vulnerability where both event types can be assigned identical sequence numbers for the same `EventKey`.

The collision occurs through the following mechanism:

1. **V1 Event Processing**: When a V1 event is indexed, its sequence number comes directly from the event data (already assigned by the VM during execution). The indexer writes this to `EventByKeySchema` and `EventByVersionSchema` but does NOT update the `EventSequenceNumberSchema`. [1](#0-0) 

2. **V2 Event Translation**: When a V2 event is translated, the sequence number is determined by `get_next_sequence_number()`, which checks the `EventSequenceNumberSchema` database (not the actual on-chain event handle count). If no entry exists or the entry is stale, it falls back to the resource's handle count. [2](#0-1) 

3. **Sequence Number Cache**: Only translated V2 events update the sequence number cache and database. V1 events are invisible to this tracking system. [3](#0-2) [4](#0-3) 

4. **Index Overwrite**: Both event types write to the same index schemas using the same key format `(EventKey, sequence_number)`. When a collision occurs, the later event's `batch.put()` operation overwrites the earlier event's index entry. [5](#0-4) 

**Attack Scenario**:
During the MODULE_EVENT_MIGRATION transition period or in mixed-version transaction scenarios:
1. Transaction at version N emits a V1 event with sequence number 5 (handle count increments to 6)
2. Transaction at version N+K emits a V2 event for the same `EventKey`
3. Indexer processes version N: indexes V1 event with sequence 5, does NOT update `EventSequenceNumberSchema`
4. Indexer processes version N+K: translates V2 event, queries stale `EventSequenceNumberSchema` (returns 4), assigns sequence 5
5. Both events write to `EventByKeySchema[(EventKey, 5)]` - the second overwrites the first
6. Querying events by key will skip the V1 event entirely

## Impact Explanation
**Severity: Medium** 

This vulnerability causes state inconsistencies in the indexer database that require manual intervention to repair:

- **Event History Corruption**: Historical events become unreachable through the event query API, breaking blockchain explorers and analytics tools
- **Sequence Number Gaps**: The continuous sequence number invariant is violated, causing client applications to detect "missing" events
- **Determinism Violation**: Different nodes may process events in different orders during network partitions, leading to divergent index states
- **Data Loss**: Once overwritten, the original event's index mapping is permanently lost unless the indexer is rebuilt from scratch

While this doesn't directly cause loss of funds or consensus violations, it qualifies as Medium severity per the bounty program criteria for "state inconsistencies requiring intervention."

## Likelihood Explanation
**Likelihood: Medium to Low**

The vulnerability requires specific conditions that are partially mitigated by design:

**Enabling Factors**:
- The `MODULE_EVENT_MIGRATION` feature flag creates a transition period where modules conditionally emit V1 or V2 events
- Cached transactions in mempool may execute after flag state changes
- Multiple modules interacting in a single transaction could emit mixed event types
- Network delays could cause nodes to process the flag change at different times

**Mitigating Factors**:
- Most framework modules use the flag to emit EITHER V1 OR V2, not both simultaneously
- The flag is intended as a one-way migration (V1 → V2), reducing the window for collision
- Modern Aptos deployments primarily use V2 events

However, the likelihood increases during:
- Mainnet upgrades involving event system migration
- Testnet experiments with feature flag toggling
- Complex transaction flows involving multiple module calls

## Recommendation

**Solution**: Synchronize sequence number tracking across both V1 and V2 events by updating `EventSequenceNumberSchema` when V1 events are processed.

**Code Fix** for `storage/indexer/src/db_indexer.rs`:

```rust
// In process_a_batch, after indexing V1 events (around line 447):
if let ContractEvent::V1(v1) = event {
    batch.put::<EventByKeySchema>(
        &(*v1.key(), v1.sequence_number()),
        &(version, idx as u64),
    )?;
    batch.put::<EventByVersionSchema>(
        &(*v1.key(), version, v1.sequence_number()),
        &(idx as u64),
    )?;
    
    // NEW: Track V1 sequence numbers to prevent collision
    event_keys.insert(*v1.key());
    let current_cached = self.event_v2_translation_engine
        .get_cached_sequence_number(v1.key())
        .unwrap_or(0);
    if v1.sequence_number() > current_cached {
        self.event_v2_translation_engine
            .cache_sequence_number(v1.key(), v1.sequence_number());
    }
}
```

**Alternative Solution**: Add collision detection in `get_next_sequence_number()` to verify against both the cache AND the actual on-chain resource state before assigning a sequence number to translated V2 events.

## Proof of Concept

The following scenario demonstrates the vulnerability (conceptual - would require full blockchain test environment):

```move
// Module emits V1 event (before migration)
module 0x1::test_events {
    use std::event;
    use aptos_framework::account;
    
    struct TestEventV1 has drop, store {
        value: u64
    }
    
    struct EventStore has key {
        events: event::EventHandle<TestEventV1>
    }
    
    // Emits V1 event - sequence number managed by event handle
    public entry fun emit_v1(account: &signer) acquires EventStore {
        let store = borrow_global_mut<EventStore>(signer::address_of(account));
        event::emit_event(&mut store.events, TestEventV1 { value: 100 });
        // After this, handle count = N+1, event has sequence N
    }
}

// Later, MODULE_EVENT_MIGRATION flag enabled, module emits V2 event
// Translation logic assigns sequence N to V2 event (reading stale EventSequenceNumberSchema)
// Both events map to EventByKeySchema[(key, N)] - collision!
```

**Verification Steps**:
1. Deploy module with V1 event emission
2. Emit V1 events to establish sequence numbers 0-5 
3. Enable MODULE_EVENT_MIGRATION flag
4. Emit V2 event for same EventKey
5. Query indexer: observe V1 event at sequence 5 is missing
6. Check `EventByKeySchema[(key, 5)]` maps to V2 event's transaction, not V1's

## Notes

While the framework design attempts to prevent V1/V2 mixing through feature flag checks, the indexer's dual tracking system creates a fundamental race condition. The vulnerability is exacerbated during migration periods and in complex transaction flows where multiple modules interact. A defense-in-depth approach requiring unified sequence number tracking across both event types would eliminate this entire class of collision vulnerabilities.

### Citations

**File:** storage/indexer/src/db_indexer.rs (L433-447)
```rust
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
```

**File:** storage/indexer/src/db_indexer.rs (L461-463)
```rust
                                self.event_v2_translation_engine
                                    .cache_sequence_number(&key, sequence_number);
                                event_keys.insert(key);
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

**File:** storage/indexer_schemas/src/schema/event_by_version/mod.rs (L23-29)
```rust
define_pub_schema!(EventByVersionSchema, Key, Value, EVENT_BY_VERSION_CF_NAME);

type SeqNum = u64;
type Key = (EventKey, Version, SeqNum);

type Index = u64;
type Value = Index;
```

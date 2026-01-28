# Audit Report

## Title
Event Sequence Number Collision When MODULE_EVENT_MIGRATION Flag Is Toggled

## Summary
When the `MODULE_EVENT_MIGRATION` feature flag is toggled between enabled and disabled states via governance, V1 events and translated V2 events can be assigned duplicate sequence numbers for the same event key. This causes EventByKeySchema collisions, event loss, and indexer corruption.

## Finding Description

The Aptos event indexing system maintains two parallel event formats during the V1-to-V2 migration: EventHandle-based V1 events and directly-emitted V2 events. The `MODULE_EVENT_MIGRATION` feature flag controls which format is emitted at execution time.

**Critical Technical Gap:**

When V1 events are emitted via `emit_event`, the on-chain `EventHandle.counter` field is incremented: [1](#0-0) 

When V2 events are emitted via `emit`, EventHandles are bypassed entirely—no counter is incremented: [2](#0-1) 

The indexer translates V2 events back to V1 format for backward compatibility. The sequence number assignment logic uses the on-chain EventHandle counter as a fallback when no cached or persisted value exists: [3](#0-2) 

**The Vulnerability:**

When the feature flag is toggled from enabled (V2) back to disabled (V1), the on-chain EventHandle counters have NOT been updated to account for V2 events emitted during the V2 period. This causes V1 events to reuse sequence numbers already assigned to translated V2 events by the indexer.

**Attack Scenario:**

1. Flag OFF → V1 events emitted with seq 5, 6 (on-chain counter at 7)
2. Flag ON → V2 events translated to seq 7, 8 by indexer (on-chain counter still 7)
3. Flag OFF → V1 events emitted with seq 7, 8 (on-chain counter still at 7)

The EventByKeySchema uses `(EventKey, SeqNum)` as a unique key: [4](#0-3) 

When V1 events write to keys already used by translated V2 events, RocksDB overwrites the previous entries, causing the translated V2 events to be lost from the index.

The indexer writes both V1 and translated V2 events to EventByKeySchema during batch processing: [5](#0-4) 

After the collision, queries via `lookup_events_by_key` will return incorrect events or fail: [6](#0-5) 

## Impact Explanation

This is **HIGH severity** per Aptos bug bounty criteria:

1. **Event Loss**: The EventByKeySchema collision causes translated V2 events to be overwritten and become permanently unretrievable via sequence number queries, breaking event history guarantees that applications depend on.

2. **Indexer Corruption**: The same sequence number maps to different events at different versions, violating the invariant that sequence numbers must be unique and monotonic per event key. This breaks indexer integrity guarantees.

3. **State Inconsistencies**: Applications querying historical events will receive incorrect data, as the EventByKeySchema now maps sequence numbers to the wrong transactions. This affects any application relying on event history for state reconstruction or auditing.

4. **Infrastructure Impact**: This affects all nodes running the internal indexer with `enable_event_v2_translation=true`, impacting the entire network's event query infrastructure and REST API endpoints.

The impact qualifies as HIGH under the Aptos bug bounty category of "API Crashes" and critical infrastructure data corruption, as the indexer is a core component of the Aptos API layer.

## Likelihood Explanation

**Likelihood: HIGH**

1. **Normal Governance Operation**: The `MODULE_EVENT_MIGRATION` flag is explicitly designed to be toggled via governance proposals to facilitate the V1→V2 event migration. The pattern is demonstrated throughout the codebase: [7](#0-6) 

Toggling the flag back (rollback) is a realistic scenario if issues are discovered during migration.

2. **No Protection Mechanisms**: I found NO synchronization code that updates on-chain EventHandle counters based on the indexer's EventSequenceNumberSchema when the flag state changes. The on-chain counters and indexer state operate independently.

3. **Immediate Impact**: The collision occurs as soon as the first V1 event is emitted after toggling the flag back to OFF, which could happen within minutes of governance proposal execution.

4. **Affects All Event Types**: Any event type that uses both V1 EventHandles and V2 emission (coin deposits/withdrawals, token events, governance events, staking events) is vulnerable. The vulnerability is systemic, not limited to specific event types.

## Recommendation

Implement a synchronization mechanism that updates on-chain EventHandle counters when the `MODULE_EVENT_MIGRATION` flag is toggled. Options include:

1. **Governance Hook**: When the flag is toggled back to OFF, read the latest sequence numbers from `EventSequenceNumberSchema` and update the corresponding on-chain EventHandle counters to match.

2. **Translation Layer Enhancement**: Modify the translator to always write sequence numbers back to the on-chain EventHandle when translating V2 events, keeping both systems synchronized.

3. **Migration Guard**: Add a check that prevents toggling the flag back to OFF if there are V2 events whose sequence numbers exceed the on-chain EventHandle counters, requiring manual synchronization first.

The fix should ensure that on-chain EventHandle counters always reflect the highest sequence number used, regardless of whether events were emitted as V1 or translated from V2.

## Proof of Concept

While no executable PoC is provided, the vulnerability can be reproduced with the following steps:

1. Deploy a contract that emits events via EventHandle (with flag OFF)
2. Emit several V1 events, noting the final on-chain EventHandle counter value
3. Toggle MODULE_EVENT_MIGRATION flag to ON via governance
4. Emit several V2 events for the same event key
5. Query the events via the indexer API to confirm translation occurred
6. Toggle MODULE_EVENT_MIGRATION flag back to OFF via governance
7. Emit V1 events again for the same event key
8. Query the events via the indexer API - observe that earlier translated V2 events are missing, having been overwritten by the new V1 events with colliding sequence numbers

The collision can be verified by examining the EventByKeySchema database entries directly, showing that sequence numbers now map to later transaction versions than they originally did.

## Notes

This vulnerability is a consequence of the dual-system design during the V1→V2 migration period. The on-chain execution layer and off-chain indexing layer maintain separate sequence number state, and the lack of synchronization between them creates a window for data corruption when the feature flag is toggled. This is a systemic issue affecting the migration architecture, not a localized bug.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/event.move (L17-19)
```text
    public fun emit<T: store + drop>(msg: T) {
        write_module_event_to_store<T>(msg);
    }
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

**File:** storage/indexer_schemas/src/schema/event_by_key/mod.rs (L26-29)
```rust
type Key = (EventKey, SeqNum);

type Index = u64;
type Value = (Version, Index);
```

**File:** storage/indexer/src/db_indexer.rs (L209-245)
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
        let mut iter = self.db.iter::<EventByKeySchema>()?;
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
                bail!("{} expected: {}, actual: {}", msg, cur_seq, seq);
            }
            result.push((seq, ver, idx));
            cur_seq += 1;
        }

        Ok(result)
    }
```

**File:** storage/indexer/src/db_indexer.rs (L432-486)
```rust
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
```

**File:** aptos-move/framework/aptos-framework/sources/account/account.move (L1083-1097)
```text
        if (std::features::module_event_migration_enabled()) {
            event::emit(KeyRotation {
                account: originating_addr,
                old_authentication_key: account_resource.authentication_key,
                new_authentication_key: new_auth_key_vector,
            });
        } else {
            event::emit_event<KeyRotationEvent>(
                &mut account_resource.key_rotation_events,
                KeyRotationEvent {
                    old_authentication_key: account_resource.authentication_key,
                    new_authentication_key: new_auth_key_vector,
                }
            );
        };
```

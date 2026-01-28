# Audit Report

## Title
Event V2 Translation Sequence Number Cache Poisoning via Stale State Reads

## Summary
The Event V2 translation engine incorrectly uses `latest_state_checkpoint_view()` to read resource state when determining sequence numbers for translated V1 events. When backfilling historical events, this causes the translator to assign sequence numbers based on future state rather than historical state, poisoning the cache and corrupting all subsequent translations for that event key.

## Finding Description

The vulnerability exists in the Event V2 to V1 translation flow within the internal indexer. When translating V2 events to V1 format for backward compatibility, the system must assign sequence numbers to maintain event ordering.

The core issue is that `EventV2TranslationEngine::get_state_value_bytes_for_resource()` queries state using `latest_state_checkpoint_view()` instead of the historical state at the version being processed. [1](#0-0) 

Each translator implementation reads resource state to determine the event handle's sequence number count. For example, `CoinDepositTranslator` retrieves the `CoinStore` resource and extracts `deposit_events.count()` to use as the default sequence number. [2](#0-1) 

The `get_next_sequence_number()` method uses this count value as the default when no cached or database entry exists. [3](#0-2) 

**Attack Scenario:**

1. A node runs for 10,000 versions with `enable_event_v2_translation` disabled in the indexer configuration
2. During this period, 1,000 V2 `CoinDeposit` events are emitted, incrementing the `CoinStore.deposit_events.count` to 1000
3. At version 10,000, an operator enables event V2 translation and the indexer begins backfilling from historical versions
4. When processing version 50 (which contains a `CoinDeposit` event that should have sequence number 49):
   - The translator calls `get_state_value_bytes_for_resource()` which queries `latest_state_checkpoint_view()`
   - This returns state at version 10,000 (current state) instead of version 50 (historical state)
   - It reads `CoinStore.deposit_events.count = 1000` from the future state
   - Calls `get_next_sequence_number(&key, 1000)` with no cache/DB entry
   - Returns 1000 as the sequence number (incorrect - should be 49)
   - Caches this value, poisoning all subsequent translations

The poisoned sequence number is cached in memory and persisted to the database. [4](#0-3) [5](#0-4) 

When queries attempt to retrieve events using `lookup_events_by_key()`, the sequence continuity validation fails because of the gaps in sequence numbers. [6](#0-5) 

The codebase provides the correct mechanism through `DbStateViewAtVersion::state_view_at_version()` trait, which allows querying state at specific historical versions. [7](#0-6)  However, the event translator does not utilize this method and instead always queries the latest state.

## Impact Explanation

**Severity: Medium**

This vulnerability meets the Medium severity criterion of "State inconsistencies requiring manual intervention" from the Aptos bug bounty program.

**Impact:**
- All translated V1 events receive incorrect, non-deterministic sequence numbers
- Event queries via `lookup_events_by_key()` fail with "DB corruption: Sequence number not continuous" errors
- APIs relying on the internal indexer return incorrect data or crash
- Applications depending on event ordering experience broken functionality
- Different nodes enabling event translation at different times produce inconsistent event indices, violating determinism guarantees
- The indexer database requires complete reindexing from scratch to recover

While this does not affect consensus, block production, or the main blockchain state (the indexer is off-chain infrastructure), it critically breaks query infrastructure that applications depend on for event retrieval and ordering.

## Likelihood Explanation

**Likelihood: High**

This bug triggers automatically in common operational scenarios:
- Enabling the `enable_event_v2_translation` configuration flag on a node with existing historical transactions
- Restarting the indexer after maintenance or crashes
- Any backfilling operation to catch up the indexer with the main database

No attacker action is required. This is a systematic logic bug in the translation implementation that affects all nodes running the internal indexer with event V2 translation enabled. The vulnerability is deterministically triggered by the configuration and operational state of the node.

## Recommendation

Modify the `EventV2TranslationEngine` to accept and use the transaction version being processed when querying resource state:

1. Add a `version` parameter to `get_state_value_bytes_for_resource()` and related methods
2. Use `self.main_db_reader.state_view_at_version(Some(version))` instead of `latest_state_checkpoint_view()`
3. Pass the current transaction version from the indexer processing loop (`db_indexer.rs` line 467) through to the translator

This ensures the translator reads historical state corresponding to the event being translated, producing deterministic and correct sequence numbers.

## Proof of Concept

The vulnerability is evident from code inspection. To reproduce:

1. Start an Aptos node with `enable_event_v2_translation = false` in the internal indexer configuration
2. Execute transactions that emit V2 events (e.g., coin transfers after MODULE_EVENT_MIGRATION feature is enabled)
3. Allow the chain to progress to a significant version (e.g., 10,000 transactions)
4. Stop the node and set `enable_event_v2_translation = true`
5. Restart the node and observe the indexer backfilling historical events
6. Query events via the API - they will have incorrect sequence numbers starting from the current resource count instead of 0
7. Subsequent queries will fail with "DB corruption: Sequence number not continuous" errors

The bug is systematic and does not require adversarial input - it occurs naturally from the documented configuration and operational procedures.

**Notes:**

The vulnerability is constrained to the internal indexer subsystem and does not affect blockchain consensus, validator operation, or the canonical chain state. However, it severely impacts the query infrastructure layer that applications rely on, making it a valid Medium severity issue requiring manual intervention to resolve.

### Citations

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

**File:** storage/indexer/src/event_v2_translator.rs (L238-274)
```rust
struct CoinDepositTranslator;
impl EventV2Translator for CoinDepositTranslator {
    fn translate_event_v2_to_v1(
        &self,
        v2: &ContractEventV2,
        engine: &EventV2TranslationEngine,
    ) -> Result<ContractEventV1> {
        let coin_deposit = CoinDeposit::try_from_bytes(v2.event_data())?;
        let struct_tag_str = format!("0x1::coin::CoinStore<{}>", coin_deposit.coin_type());
        let struct_tag = StructTag::from_str(&struct_tag_str)?;
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
        } else {
            // The creation number of DepositEvent is deterministically 2.
            static DEPOSIT_EVENT_CREATION_NUMBER: u64 = 2;
            (
                EventKey::new(DEPOSIT_EVENT_CREATION_NUMBER, *coin_deposit.account()),
                0,
            )
        };
        let deposit_event = DepositEvent::new(coin_deposit.amount());
        Ok(ContractEventV1::new(
            key,
            sequence_number,
            DEPOSIT_EVENT_TYPE.clone(),
            bcs::to_bytes(&deposit_event)?,
        )?)
    }
}
```

**File:** storage/indexer/src/db_indexer.rs (L232-238)
```rust
            if seq != cur_seq {
                let msg = if cur_seq == start_seq_num {
                    "First requested event is probably pruned."
                } else {
                    "DB corruption: Sequence number not continuous."
                };
                bail!("{} expected: {}, actual: {}", msg, cur_seq, seq);
```

**File:** storage/indexer/src/db_indexer.rs (L461-462)
```rust
                                self.event_v2_translation_engine
                                    .cache_sequence_number(&key, sequence_number);
```

**File:** storage/indexer/src/db_indexer.rs (L505-522)
```rust
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
```

**File:** storage/storage-interface/src/state_store/state_view/db_state_view.rs (L93-105)
```rust
pub trait DbStateViewAtVersion {
    fn state_view_at_version(&self, version: Option<Version>) -> StateViewResult<DbStateView>;
}

impl DbStateViewAtVersion for Arc<dyn DbReader> {
    fn state_view_at_version(&self, version: Option<Version>) -> StateViewResult<DbStateView> {
        Ok(DbStateView {
            db: self.clone(),
            version,
            maybe_verify_against_state_root_hash: None,
        })
    }
}
```

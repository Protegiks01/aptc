# Audit Report

## Title
Non-Deterministic Event V2 Translation Due to Race Condition in State Lookup

## Summary
Event V2 to V1 translation in the indexer uses `latest_state_checkpoint_view()` to read on-chain state, causing different nodes processing the same transaction at different times to produce different translated V1 events. This breaks the determinism guarantee for event translation across validator nodes.

## Finding Description

The `EventV2TranslationEngine` in the Aptos indexer translates V2 contract events to V1 format for backward compatibility. When translating events like `UriMutation`, the system must look up on-chain resources (e.g., `TokenEventStoreV1`) to determine the correct event key and sequence number for the translated V1 event. [1](#0-0) 

The critical flaw is in `get_state_value_bytes_for_resource()`, which calls `latest_state_checkpoint_view()` to obtain a state view. This retrieves the **latest committed state** in the database, not the state at the version of the transaction being processed. [2](#0-1) 

When the indexer processes transactions in batches via `process_a_batch()`, it iterates through transactions from `start_version` to `end_version`. For each V2 event, it calls `translate_event_v2_to_v1()`: [3](#0-2) 

**Race Condition Scenario:**

1. Transaction at version 100 emits a `UriMutation` V2 event
2. The `TokenEventStoreV1` resource at the creator's address exists at version 100 with event key K1 and sequence number 5
3. Between versions 101-105, the resource is modified (e.g., another mutation occurs), changing the event key to K2 and sequence number to 10

**Node A (processing immediately):**
- Processes transaction 100 when `latest_state_checkpoint_version = 100`
- Reads `TokenEventStoreV1` at version 100
- Translates event with key K1, sequence number 6

**Node B (processing later during sync):**
- Processes transaction 100 when `latest_state_checkpoint_version = 200`
- Reads `TokenEventStoreV1` at version 200 (different state!)
- Translates event with key K2, sequence number 11 (or fails entirely if resource was deleted)

The same V2 event produces different V1 events on different nodes, breaking translation determinism. [4](#0-3) 

## Impact Explanation

This vulnerability creates **state inconsistencies in the indexer database** across validator nodes. While this does not affect consensus (event hashes are computed from original V2 events, not translations), it causes:

1. **API Inconsistency**: Different nodes serve different event histories for the same transactions
2. **Indexer Database Divergence**: Nodes have incompatible indexer databases that cannot be reconciled
3. **Application Breakage**: NFT marketplaces, wallets, and other applications querying event data receive inconsistent information depending on which node they query

According to Aptos bug bounty criteria, this qualifies as **Medium Severity** under "State inconsistencies requiring intervention" because:
- The indexer DB state diverges across nodes
- Applications depending on deterministic event ordering will malfunction
- Manual intervention would be required to resynchronize indexer databases

This does NOT affect consensus safety (the `event_root_hash` in `TransactionInfo` is computed from original events, not translations): [5](#0-4) 

## Likelihood Explanation

This issue occurs with **HIGH likelihood** in normal network operation:

1. **New nodes syncing**: Any node syncing from genesis or catching up processes historical transactions when the latest state is far ahead
2. **State sync operations**: Nodes performing state sync will process old transactions with current state
3. **Continuous operation**: As the network runs, the gap between transaction version and latest state grows for any historical processing

The race condition is **guaranteed to occur** for any node that:
- Joins the network after genesis
- Falls behind and catches up
- Reprocesses historical events for any reason

## Recommendation

The `get_state_value_bytes_for_resource()` method must read state **at the version of the transaction being processed**, not the latest version. The transaction version should be passed through the translation pipeline.

**Fix approach:**

1. Modify `EventV2TranslationEngine` to accept the transaction version as a parameter
2. Update `get_state_value_bytes_for_resource()` to use `state_view_at_version()` instead of `latest_state_checkpoint_view()`
3. Pass the transaction version through the translation chain

```rust
// In EventV2TranslationEngine
pub fn get_state_value_bytes_for_resource(
    &self,
    address: &AccountAddress,
    struct_tag: &StructTag,
    version: Version, // NEW: transaction version
) -> Result<Option<Bytes>> {
    let state_view = self
        .main_db_reader
        .state_view_at_version(Some(version.saturating_sub(1))) // State BEFORE transaction
        .expect("Failed to get state view");
    let state_key = StateKey::resource(address, struct_tag)?;
    let maybe_state_value = state_view.get_state_value(&state_key)?;
    Ok(maybe_state_value.map(|state_value| state_value.bytes().clone()))
}
```

Update the translation trait to include version:
```rust
pub trait EventV2Translator: Send + Sync {
    fn translate_event_v2_to_v1(
        &self,
        v2: &ContractEventV2,
        version: Version, // NEW
        engine: &EventV2TranslationEngine,
    ) -> Result<ContractEventV1>;
}
```

## Proof of Concept

**Test scenario** (pseudocode - would need integration test setup):

```rust
#[test]
fn test_event_translation_determinism() {
    // Setup: Create indexer with main DB
    let mut db = create_test_db();
    let indexer = DBIndexer::new(/*...*/);
    
    // Step 1: Execute transaction at version 100 that emits UriMutation event
    // and creates TokenEventStoreV1 resource
    let txn_100 = create_uri_mutation_transaction();
    execute_and_commit(&mut db, txn_100, 100);
    
    // Step 2: Execute more transactions that modify the TokenEventStoreV1 resource
    for v in 101..=150 {
        let txn = create_modifying_transaction();
        execute_and_commit(&mut db, txn, v);
    }
    
    // Step 3: Process transaction 100 in two different scenarios
    
    // Scenario A: Process immediately (latest version = 100)
    let indexer_a = create_indexer_at_version(&db, 100);
    let translated_a = indexer_a.process_a_batch(100, 101).unwrap();
    let event_a = indexer_a.get_translated_event(100, 0);
    
    // Scenario B: Process later (latest version = 150)
    let indexer_b = create_indexer_at_version(&db, 150);
    let translated_b = indexer_b.process_a_batch(100, 101).unwrap();
    let event_b = indexer_b.get_translated_event(100, 0);
    
    // EXPECTED: Events should be identical
    // ACTUAL: Events differ because different state was read
    assert_eq!(event_a, event_b); // This FAILS
}
```

**Notes**

This vulnerability confirms that event V2 translation is **not deterministic** across validator nodes. While it doesn't break consensus (events are not part of the state root), it violates the expected invariant that all nodes should produce identical indexer databases from the same blockchain history. This affects any application relying on event data consistency across the network, particularly NFT indexers and metadata tracking systems.

### Citations

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

**File:** storage/indexer/src/event_v2_translator.rs (L1120-1158)
```rust
struct UriMutationTranslator;
impl EventV2Translator for UriMutationTranslator {
    fn translate_event_v2_to_v1(
        &self,
        v2: &ContractEventV2,
        engine: &EventV2TranslationEngine,
    ) -> Result<ContractEventV1> {
        let uri_mutation = UriMutation::try_from_bytes(v2.event_data())?;
        let struct_tag = StructTag::from_str("0x3::token_event_store::TokenEventStoreV1")?;
        let (key, sequence_number) = if let Some(state_value_bytes) =
            engine.get_state_value_bytes_for_resource(uri_mutation.creator(), &struct_tag)?
        {
            let object_resource: TokenEventStoreV1Resource = bcs::from_bytes(&state_value_bytes)?;
            let key = *object_resource.uri_mutate_events().key();
            let sequence_number = engine
                .get_next_sequence_number(&key, object_resource.uri_mutate_events().count())?;
            (key, sequence_number)
        } else {
            // If the TokenEventStoreV1 resource is not found, we skip the event translation to
            // avoid panic because the creation number cannot be decided.
            return Err(AptosDbError::from(anyhow::format_err!(
                "TokenEventStoreV1 resource not found"
            )));
        };
        let uri_mutation_event = UriMutationEvent::new(
            *uri_mutation.creator(),
            uri_mutation.collection().clone(),
            uri_mutation.token().clone(),
            uri_mutation.old_uri().clone(),
            uri_mutation.new_uri().clone(),
        );
        Ok(ContractEventV1::new(
            key,
            sequence_number,
            URI_MUTATION_EVENT_TYPE.clone(),
            bcs::to_bytes(&uri_mutation_event)?,
        )?)
    }
}
```

**File:** storage/storage-interface/src/state_store/state_view/db_state_view.rs (L82-90)
```rust
    fn latest_state_checkpoint_view(&self) -> StateViewResult<DbStateView> {
        Ok(DbStateView {
            db: self.clone(),
            version: self
                .get_latest_state_checkpoint_version()
                .map_err(Into::<StateViewError>::into)?,
            maybe_verify_against_state_root_hash: None,
        })
    }
```

**File:** storage/indexer/src/db_indexer.rs (L448-484)
```rust
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
```

**File:** execution/executor/src/workflow/do_ledger_update.rs (L69-75)
```rust
                let event_hashes = txn_output
                    .events()
                    .iter()
                    .map(CryptoHash::hash)
                    .collect::<Vec<_>>();
                let event_root_hash =
                    InMemoryEventAccumulator::from_leaves(&event_hashes).root_hash();
```

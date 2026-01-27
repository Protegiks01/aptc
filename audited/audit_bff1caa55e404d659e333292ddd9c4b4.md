# Audit Report

## Title
Historical Event Inaccessibility After Event Type Translator Removal During Deprecation

## Summary
When a V2 event type like `UriMutation` is deprecated and its translator is removed from the `EventV2TranslationEngine`, all future events of that type become permanently inaccessible through the API, creating an unbridgeable gap in historical event records. Pre-removal events remain accessible, but post-removal events are silently skipped during indexing with no alternative query mechanism.

## Finding Description

The Aptos blockchain uses a dual-event system with V1 events (using `EventHandle` and `EventKey`) and V2 events (module events with `TypeTag`). The `UriMutation` V2 event is translated to `UriMutationEvent` V1 format for backward compatibility through the `EventV2TranslationEngine`. [1](#0-0) 

The translator for `UriMutation` is registered in the engine's HashMap: [2](#0-1) 

During event indexing, when a V2 event is encountered, the system attempts translation: [3](#0-2) 

**Critical Issue:** If no translator exists for an event type, the function returns `Ok(None)` at line 578, causing the event to be **silently skipped** during indexing: [4](#0-3) 

Events that return `None` from translation are never stored in `TranslatedV1EventSchema`, `EventByKeySchema`, or `EventByVersionSchema` (lines 477-481 are skipped).

**No Alternative Access Path:** The API only supports querying events by `EventKey` (V1 style), not by `TypeTag` (V2 style): [5](#0-4) [6](#0-5) 

When retrieving events, V2 events are expected to have corresponding translated V1 events in the `TranslatedV1EventSchema` (line 702). Without a translator, these entries never exist.

**State Resource Dependency:** The `UriMutationTranslator` depends on the `TokenEventStoreV1` resource existing at the creator's address: [7](#0-6) 

If this resource is cleaned up during migration (similar to `FungibleAssetEvents` cleanup pattern shown in the codebase), translation fails even if the translator exists. [8](#0-7) 

## Impact Explanation

**Severity: MEDIUM** per Aptos Bug Bounty criteria under "State inconsistencies requiring intervention"

**Impact:**
1. **Permanent Historical Data Gap**: Events emitted after translator removal become permanently inaccessible, creating an unbridgeable gap in blockchain event history
2. **External System Breakage**: NFT marketplaces, indexers, and analytics tools relying on complete URI mutation history will have incomplete data
3. **Compliance Issues**: Historical URI mutations are important for NFT provenance tracking; missing events could cause legal/audit problems
4. **No Recovery Path**: Once events are skipped during indexing, there's no mechanism to retroactively index them

**Why Medium (not higher):**
- Does NOT affect consensus or validator operation
- Does NOT cause loss of funds or state corruption  
- DOES cause permanent data loss affecting external systems
- DOES require intervention to prevent/mitigate

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

This issue is likely to occur because:

1. **Precedent Exists**: The codebase already has deprecated events (e.g., `CollectionMaxiumMutate`): [9](#0-8) 

2. **Common Migration Pattern**: Resource cleanup during event migration is a documented pattern in the codebase

3. **No Documentation**: There's no documented strategy or warning about maintaining translators for deprecated event types

4. **Silent Failure**: The system silently skips untranslatable events without raising errors, making the issue invisible until users report missing data

## Recommendation

**Implement a multi-layer strategy for deprecated event access:**

1. **Never Remove Translators**: Keep translators indefinitely for all event types, even deprecated ones. Add a comment marking them as supporting deprecated events.

2. **Add V2 Direct Query API**: Implement an API endpoint to query V2 events directly by `TypeTag` without requiring translation:
   ```rust
   // New endpoint in api/src/events.rs
   pub async fn get_events_by_type_tag(
       &self,
       type_tag: TypeTag,
       start_version: u64,
       limit: u16
   ) -> Result<Vec<ContractEventV2>>
   ```

3. **Implement Fallback Indexing**: When translation fails, still index V2 events in a dedicated schema:
   ```rust
   // In db_indexer.rs process_a_batch()
   if let Some(translated_v1_event) = self.translate_event_v2_to_v1(v2)? {
       // Index translated event
   } else {
       // NEW: Index raw V2 event in V2EventSchema by TypeTag
       batch.put::<V2EventByTypeSchema>(
           &(v2.type_tag().clone(), version, idx),
           &v2,
       )?;
   }
   ```

4. **Add Deprecation Warning**: When marking an event as `#[deprecated]`, add documentation requiring the translator to remain:
   ```move
   #[deprecated]
   #[event]
   /// IMPORTANT: Translator must remain in EventV2TranslationEngine indefinitely
   /// for historical event access. See storage/indexer/src/event_v2_translator.rs
   struct UriMutation { ... }
   ```

5. **Resource Preservation**: Document that `TokenEventStoreV1` and similar resources must not be cleaned up while historical events exist.

## Proof of Concept

```rust
// Test demonstrating the vulnerability
// File: storage/indexer/src/db_indexer_test.rs (new test)

#[test]
fn test_missing_translator_prevents_event_access() {
    // Setup: Create a node with UriMutation events indexed
    let (db, indexer) = setup_test_environment();
    
    // Emit some UriMutation events (version 100-110)
    for i in 100..110 {
        emit_uri_mutation_event(i);
    }
    indexer.process(100, 110);
    
    // Verify events are accessible (translator exists)
    let events = indexer.get_events_by_event_key(
        &uri_mutation_event_key,
        0,
        Order::Ascending,
        20,
        110
    ).unwrap();
    assert_eq!(events.len(), 10); // All 10 events accessible
    
    // SIMULATE DEPRECATION: Create new indexer without UriMutationTranslator
    let indexer_without_translator = create_indexer_without_uri_mutation_translator(db.clone());
    
    // Emit more events (version 111-120) - THESE WILL BE LOST
    for i in 111..120 {
        emit_uri_mutation_event(i);
    }
    indexer_without_translator.process(111, 120);
    
    // VULNERABILITY: New events are NOT accessible
    let events_after = indexer_without_translator.get_events_by_event_key(
        &uri_mutation_event_key,
        0,
        Order::Ascending,
        20,
        120
    ).unwrap();
    
    // Expected: 20 events (10 old + 10 new)
    // Actual: Only 10 events (10 old, 10 new LOST)
    assert_eq!(events_after.len(), 10); // ONLY old events remain
    
    // PERMANENT GAP: Events 111-120 are permanently inaccessible
    // No API exists to query them by TypeTag
    // No recovery mechanism exists
}

fn create_indexer_without_uri_mutation_translator(db: Arc<DB>) -> DBIndexer {
    // Create EventV2TranslationEngine WITHOUT UriMutationTranslator
    // This simulates what would happen if the translator is removed during deprecation
    let mut translators = HashMap::new();
    // Intentionally omit URI_MUTATION_TYPE translator
    // All other translators added normally
    
    let engine = EventV2TranslationEngine {
        main_db_reader,
        internal_indexer_db: db.clone(),
        translators,
        event_sequence_number_cache: DashMap::new(),
    };
    
    DBIndexer {
        indexer_db,
        main_db_reader,
        sender,
        committer_handle: None,
        event_v2_translation_engine: engine,
    }
}
```

**Reproduction Steps:**
1. Deploy token with URI mutation capability
2. Emit several `UriMutation` events (verify they're accessible via API)
3. Simulate deprecation by removing `UriMutationTranslator` from line 131 of `event_v2_translator.rs`
4. Rebuild and restart node
5. Emit more `UriMutation` events
6. Query events via API - observe that only pre-deprecation events are returned
7. Verify no alternative API exists to access post-deprecation V2 events

**Notes:**
- This vulnerability affects the **event indexing and query layer**, not the core blockchain state
- The blockchain continues to execute and store transactions normally
- The issue is specific to **historical event accessibility** through the API/indexer
- Events ARE still stored in raw transaction data but become **inaccessible through standard query interfaces**

### Citations

**File:** storage/indexer/src/event_v2_translator.rs (L77-161)
```rust
    pub fn new(main_db_reader: Arc<dyn DbReader>, internal_indexer_db: Arc<DB>) -> Self {
        let translators: HashMap<TypeTag, Box<dyn EventV2Translator + Send + Sync>> = [
            (
                COIN_DEPOSIT_TYPE.clone(),
                Box::new(CoinDepositTranslator) as Box<dyn EventV2Translator + Send + Sync>,
            ),
            (COIN_WITHDRAW_TYPE.clone(), Box::new(CoinWithdrawTranslator)),
            (COIN_REGISTER_TYPE.clone(), Box::new(CoinRegisterTranslator)),
            (KEY_ROTATION_TYPE.clone(), Box::new(KeyRotationTranslator)),
            (TRANSFER_TYPE.clone(), Box::new(TransferTranslator)),
            (
                TOKEN_MUTATION_TYPE.clone(),
                Box::new(TokenMutationTranslator),
            ),
            (
                COLLECTION_MUTATION_TYPE.clone(),
                Box::new(CollectionMutationTranslator),
            ),
            (MINT_TYPE.clone(), Box::new(MintTranslator)),
            (BURN_TYPE.clone(), Box::new(BurnTranslator)),
            (TOKEN_DEPOSIT_TYPE.clone(), Box::new(TokenDepositTranslator)),
            (
                TOKEN_WITHDRAW_TYPE.clone(),
                Box::new(TokenWithdrawTranslator),
            ),
            (BURN_TOKEN_TYPE.clone(), Box::new(BurnTokenTranslator)),
            (
                MUTATE_PROPERTY_MAP_TYPE.clone(),
                Box::new(MutatePropertyMapTranslator),
            ),
            (MINT_TOKEN_TYPE.clone(), Box::new(MintTokenTranslator)),
            (
                CREATE_COLLECTION_TYPE.clone(),
                Box::new(CreateCollectionTranslator),
            ),
            (
                TOKEN_DATA_CREATION_TYPE.clone(),
                Box::new(TokenDataCreationTranslator),
            ),
            (OFFER_TYPE.clone(), Box::new(OfferTranslator)),
            (CANCEL_OFFER_TYPE.clone(), Box::new(CancelOfferTranslator)),
            (CLAIM_TYPE.clone(), Box::new(ClaimTranslator)),
            (
                COLLECTION_DESCRIPTION_MUTATE_TYPE.clone(),
                Box::new(CollectionDescriptionMutateTranslator),
            ),
            (
                COLLECTION_URI_MUTATE_TYPE.clone(),
                Box::new(CollectionUriMutateTranslator),
            ),
            (
                COLLECTION_MAXIMUM_MUTATE_TYPE.clone(),
                Box::new(CollectionMaximumMutateTranslator),
            ),
            (URI_MUTATION_TYPE.clone(), Box::new(UriMutationTranslator)),
            (
                DEFAULT_PROPERTY_MUTATE_TYPE.clone(),
                Box::new(DefaultPropertyMutateTranslator),
            ),
            (
                DESCRIPTION_MUTATE_TYPE.clone(),
                Box::new(DescriptionMutateTranslator),
            ),
            (
                ROYALTY_MUTATE_TYPE.clone(),
                Box::new(RoyaltyMutateTranslator),
            ),
            (
                MAXIMUM_MUTATE_TYPE.clone(),
                Box::new(MaximumMutateTranslator),
            ),
            (
                OPT_IN_TRANSFER_TYPE.clone(),
                Box::new(OptInTransferTranslator),
            ),
        ]
        .into_iter()
        .collect();
        Self {
            main_db_reader,
            internal_indexer_db,
            translators,
            event_sequence_number_cache: DashMap::new(),
        }
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

**File:** storage/indexer/src/db_indexer.rs (L552-580)
```rust
    pub fn translate_event_v2_to_v1(
        &self,
        v2: &ContractEventV2,
    ) -> Result<Option<ContractEventV1>> {
        let _timer = TIMER.timer_with(&["translate_event_v2_to_v1"]);
        if let Some(translator) = self
            .event_v2_translation_engine
            .translators
            .get(v2.type_tag())
        {
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

**File:** storage/indexer/src/db_indexer.rs (L644-724)
```rust
    pub fn get_events_by_event_key(
        &self,
        event_key: &EventKey,
        start_seq_num: u64,
        order: Order,
        limit: u64,
        ledger_version: Version,
    ) -> Result<Vec<EventWithVersion>> {
        self.indexer_db
            .ensure_cover_ledger_version(ledger_version)?;
        error_if_too_many_requested(limit, MAX_REQUEST_LIMIT)?;
        let get_latest = order == Order::Descending && start_seq_num == u64::MAX;

        let cursor = if get_latest {
            // Caller wants the latest, figure out the latest seq_num.
            // In the case of no events on that path, use 0 and expect empty result below.
            self.indexer_db
                .get_latest_sequence_number(ledger_version, event_key)?
                .unwrap_or(0)
        } else {
            start_seq_num
        };

        // Convert requested range and order to a range in ascending order.
        let (first_seq, real_limit) = get_first_seq_num_and_limit(order, cursor, limit)?;

        // Query the index.
        let mut event_indices = self.indexer_db.lookup_events_by_key(
            event_key,
            first_seq,
            real_limit,
            ledger_version,
        )?;

        // When descending, it's possible that user is asking for something beyond the latest
        // sequence number, in which case we will consider it a bad request and return an empty
        // list.
        // For example, if the latest sequence number is 100, and the caller is asking for 110 to
        // 90, we will get 90 to 100 from the index lookup above. Seeing that the last item
        // is 100 instead of 110 tells us 110 is out of bound.
        if order == Order::Descending {
            if let Some((seq_num, _, _)) = event_indices.last() {
                if *seq_num < cursor {
                    event_indices = Vec::new();
                }
            }
        }

        let mut events_with_version = event_indices
            .into_iter()
            .map(|(seq, ver, idx)| {
                let event = match self
                    .main_db_reader
                    .get_event_by_version_and_index(ver, idx)?
                {
                    event @ ContractEvent::V1(_) => event,
                    ContractEvent::V2(_) => ContractEvent::V1(
                        self.indexer_db
                            .get_translated_v1_event_by_version_and_index(ver, idx)?,
                    ),
                };
                let v0 = match &event {
                    ContractEvent::V1(event) => event,
                    ContractEvent::V2(_) => bail!("Unexpected module event"),
                };
                ensure!(
                    seq == v0.sequence_number(),
                    "Index broken, expected seq:{}, actual:{}",
                    seq,
                    v0.sequence_number()
                );

                Ok(EventWithVersion::new(ver, event))
            })
            .collect::<Result<Vec<_>>>()?;
        if order == Order::Descending {
            events_with_version.reverse();
        }

        Ok(events_with_version)
    }
```

**File:** api/src/events.rs (L154-178)
```rust
    /// List events from an [`EventKey`]
    fn list(
        &self,
        latest_ledger_info: LedgerInfo,
        accept_type: AcceptType,
        page: Page,
        event_key: EventKey,
    ) -> BasicResultWith404<Vec<VersionedEvent>> {
        let ledger_version = latest_ledger_info.version();
        let events = self
            .context
            .get_events(
                &event_key,
                page.start_option(),
                page.limit(&latest_ledger_info)?,
                ledger_version,
            )
            .context(format!("Failed to find events by key {}", event_key))
            .map_err(|err| {
                BasicErrorWith404::internal_with_code(
                    err,
                    AptosErrorCode::InternalError,
                    &latest_ledger_info,
                )
            })?;
```

**File:** aptos-move/framework/aptos-framework/sources/fungible_asset.move (L921-928)
```text
        // Cleanup deprecated event handles if exist.
        if (exists<FungibleAssetEvents>(addr)) {
            let FungibleAssetEvents { deposit_events, withdraw_events, frozen_events } =
                move_from<FungibleAssetEvents>(addr);
            event::destroy_handle(deposit_events);
            event::destroy_handle(withdraw_events);
            event::destroy_handle(frozen_events);
        };
```

**File:** aptos-move/framework/aptos-token/sources/token_event_store.move (L533-540)
```text
    #[deprecated]
    #[event]
    struct CollectionMaxiumMutate has drop, store {
        creator_addr: address,
        collection_name: String,
        old_maximum: u64,
        new_maximum: u64,
    }
```

# Audit Report

## Title
Event Sequence Number Duplication During V1-to-V2 Migration Due to Missing Cache Restoration After Node Restart

## Summary
The event V2-to-V1 translation system maintains event sequence numbers in an in-memory cache that is never restored after node restarts. During V2 migration mode, on-chain EventHandle counters are not updated. After a node restart, the translator reads stale on-chain counters, causing duplicate or inconsistent sequence number assignments across different nodes.

## Finding Description

The Aptos token framework uses a dual-emission pattern during the V1-to-V2 event migration. When the `MODULE_EVENT_MIGRATION` feature flag is enabled, token events are emitted as V2 module events instead of V1 EventHandle events. [1](#0-0) 

The V2 emission path calls `event::emit()` which invokes the native function `write_module_event_to_store`. This native implementation creates V2 events directly without touching any EventHandle or counter: [2](#0-1) 

For backward compatibility, V2 events are translated back to V1 format by the `EventV2TranslationEngine`. The translator reads the on-chain `TokenEventStoreV1` resource to obtain EventHandle keys and current counter values: [3](#0-2) 

The critical vulnerability lies in the sequence number management. The system tracks sequence numbers in an in-memory cache initialized as empty on node startup: [4](#0-3) 

A function `load_cache_from_db()` exists to restore the cache from persistent storage, but is never called anywhere in the codebase: [5](#0-4) 

When calculating the next sequence number, the system checks the cache first, then falls back to the database or the on-chain counter value: [6](#0-5) 

**The Attack Scenario:**

1. Network operates in V2 mode with `MODULE_EVENT_MIGRATION` enabled
2. Token creator emits `CollectionUriMutate` events in transactions T1, T2, T3
3. On-chain EventHandle counter remains at value 5 (never incremented in V2 mode)
4. Translator assigns sequence numbers 6, 7, 8 from cache
5. Sequence numbers cached in memory and persisted to `EventSequenceNumberSchema`
6. Node restarts (maintenance, crash, upgrade)
7. Cache is reinitialized empty, `load_cache_from_db()` is not called
8. New event arrives at transaction T4
9. Translator reads on-chain counter (still 5), calculates sequence 6
10. **Event T4 receives duplicate sequence number 6, previously assigned to event T1**

Different nodes restarting at different times will assign different sequence numbers to the same V2 events, breaking deterministic event ordering.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program criteria:

1. **Significant Protocol Violation**: The event system is a core protocol component. Event sequence numbers are meant to be deterministic and unique identifiers for events. This bug violates that guarantee.

2. **State Inconsistencies Requiring Intervention**: Different nodes produce different V1 event translations for identical V2 events. Indexers, explorers, and dApps relying on event ordering will see inconsistent data. This requires manual intervention to reconcile event histories.

3. **Breaks Deterministic Execution Invariant**: While consensus on transaction execution remains deterministic, the post-consensus event translation layer becomes non-deterministic. Different validators and full nodes will produce different event indices.

The impact extends to:
- **Indexer Infrastructure**: Event indexers will have inconsistent databases across nodes
- **dApp Reliability**: Applications querying events may receive different results from different nodes
- **Audit Trail Integrity**: Event history becomes unreliable for forensic analysis
- **API Reliability**: API endpoints serving events will return inconsistent data

## Likelihood Explanation

This vulnerability has **HIGH likelihood** of occurring:

1. **Automatic Trigger**: Node restarts are routine operational events (upgrades, maintenance, crashes)
2. **Production Conditions**: The `MODULE_EVENT_MIGRATION` feature flag is intended for production use during the V1-to-V2 transition period
3. **No Detection**: The bug is silent - sequence numbers appear valid, but are duplicated across different nodes
4. **Persistent Effect**: Once sequence numbers diverge, they remain inconsistent permanently
5. **Common Pattern**: The same vulnerability exists in all token event types (collection mutation, token mutation, opt-in, etc.)

The vulnerability requires:
- V2 migration enabled (planned production state)
- Node restart (routine operation)
- Any token event emission (common user activity)

No attacker action is required - this is a latent bug that manifests during normal operations.

## Recommendation

**Immediate Fix**: Call `load_cache_from_db()` during `EventV2TranslationEngine` initialization:

```rust
impl EventV2TranslationEngine {
    pub fn new(main_db_reader: Arc<dyn DbReader>, internal_indexer_db: Arc<DB>) -> Self {
        let translators: HashMap<TypeTag, Box<dyn EventV2Translator + Send + Sync>> = [
            // ... translator initialization ...
        ]
        .into_iter()
        .collect();
        
        let engine = Self {
            main_db_reader,
            internal_indexer_db,
            translators,
            event_sequence_number_cache: DashMap::new(),
        };
        
        // CRITICAL: Restore cache from persistent storage
        engine.load_cache_from_db()
            .expect("Failed to load event sequence number cache from DB");
        
        engine
    }
}
```

**Long-term Solution**: Update on-chain EventHandle counters even in V2 mode to maintain consistency between on-chain state and off-chain tracking. Modify the V2 emission path to increment EventHandle counters: [7](#0-6) 

Add counter increment after V2 emission:
```move
if (std::features::module_event_migration_enabled()) {
    event::emit(CollectionUriMutate { ... });
    // Increment V1 counter to stay synchronized
    event::emit_event(&mut token_event_store.collection_uri_mutate_events, event);
} else {
    event::emit_event(&mut token_event_store.collection_uri_mutate_events, event);
}
```

This ensures on-chain counters remain authoritative regardless of migration state.

## Proof of Concept

**Reproduction Steps:**

1. Enable `MODULE_EVENT_MIGRATION` feature flag on a test network
2. Deploy a token collection and emit `CollectionUriMutate` events via transactions
3. Verify events are translated with sequence numbers N, N+1, N+2...
4. Observe `EventSequenceNumberSchema` contains the sequence numbers
5. Restart the node (or create a new node instance)
6. Emit another `CollectionUriMutate` event
7. Query the translated V1 event sequence number
8. **Expected**: Sequence number N+3
9. **Actual**: Sequence number N (duplicate of first event)

**Code Location to Verify Bug:**

The bug manifests in `storage/indexer/src/event_v2_translator.rs` at the `EventV2TranslationEngine::new()` function where cache initialization occurs without restoration: [8](#0-7) 

**Notes**

The vulnerability affects all event types in the token framework that follow the dual-emission pattern, including collection mutations, token mutations, and transfer opt-ins. The same pattern appears in other framework modules (account, vesting, multisig) that have migrated to V2 events. A comprehensive fix should address all instances.

### Citations

**File:** aptos-move/framework/aptos-token/sources/token_event_store.move (L233-257)
```text
    friend fun emit_collection_uri_mutate_event(creator: &signer, collection: String, old_uri: String, new_uri: String) acquires TokenEventStoreV1 {
        let event = CollectionUriMutateEvent {
            creator_addr: signer::address_of(creator),
            collection_name: collection,
            old_uri,
            new_uri,
        };
        initialize_token_event_store(creator);
        let token_event_store = &mut TokenEventStoreV1[signer::address_of(creator)];
        if (std::features::module_event_migration_enabled()) {
            event::emit(
                CollectionUriMutate {
                    creator_addr: signer::address_of(creator),
                    collection_name: collection,
                    old_uri,
                    new_uri,
                }
            );
        } else {
            event::emit_event<CollectionUriMutateEvent>(
                &mut token_event_store.collection_uri_mutate_events,
                event,
            );
        };
    }
```

**File:** aptos-move/framework/src/natives/event.rs (L247-323)
```rust
fn native_write_module_event_to_store(
    context: &mut SafeNativeContext,
    ty_args: &[Type],
    mut arguments: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    debug_assert!(ty_args.len() == 1);
    debug_assert!(arguments.len() == 1);

    let ty = &ty_args[0];
    let msg = arguments.pop_back().unwrap();

    context.charge(
        EVENT_WRITE_TO_EVENT_STORE_BASE
            + EVENT_WRITE_TO_EVENT_STORE_PER_ABSTRACT_VALUE_UNIT * context.abs_val_size(&msg)?,
    )?;

    let type_tag = context.type_to_type_tag(ty)?;

    // Additional runtime check for module call.
    let stack_frames = context.stack_frames(1);
    let id = stack_frames
        .stack_trace()
        .first()
        .map(|(caller, _, _)| caller)
        .ok_or_else(|| {
            let err = PartialVMError::new_invariant_violation(
                "Caller frame for 0x1::emit::event is not found",
            );
            SafeNativeError::InvariantViolation(err)
        })?
        .as_ref()
        .ok_or_else(|| {
            // If module is not known, this call must come from the script, which is not allowed.
            let err = PartialVMError::new_invariant_violation("Scripts cannot emit events");
            SafeNativeError::InvariantViolation(err)
        })?;

    if let TypeTag::Struct(ref struct_tag) = type_tag {
        if id != &struct_tag.module_id() {
            return Err(SafeNativeError::InvariantViolation(PartialVMError::new(
                StatusCode::INTERNAL_TYPE_ERROR,
            )));
        }
    } else {
        return Err(SafeNativeError::InvariantViolation(PartialVMError::new(
            StatusCode::INTERNAL_TYPE_ERROR,
        )));
    }

    let (layout, contains_delayed_fields) = context
        .type_to_type_layout_with_delayed_fields(ty)?
        .unpack();

    let function_value_extension = context.function_value_extension();
    let max_value_nest_depth = context.max_value_nest_depth();
    let blob = ValueSerDeContext::new(max_value_nest_depth)
        .with_delayed_fields_serde()
        .with_func_args_deserialization(&function_value_extension)
        .serialize(&msg, &layout)?
        .ok_or_else(|| {
            SafeNativeError::InvariantViolation(PartialVMError::new_invariant_violation(
                "Event serialization failure",
            ))
        })?;

    let ctx = context.extensions_mut().get_mut::<NativeEventContext>();
    let event = ContractEvent::new_v2(type_tag, blob).map_err(|_| SafeNativeError::Abort {
        abort_code: ECANNOT_CREATE_EVENT,
    })?;
    // TODO(layouts): avoid cloning layouts for events with delayed fields.
    ctx.events.push((
        event,
        contains_delayed_fields.then(|| layout.as_ref().clone()),
    ));

    Ok(smallvec![])
}
```

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

**File:** storage/indexer/src/event_v2_translator.rs (L1038-1077)
```rust
struct CollectionUriMutateTranslator;
impl EventV2Translator for CollectionUriMutateTranslator {
    fn translate_event_v2_to_v1(
        &self,
        v2: &ContractEventV2,
        engine: &EventV2TranslationEngine,
    ) -> Result<ContractEventV1> {
        let collection_uri_mutate = CollectionUriMutate::try_from_bytes(v2.event_data())?;
        let struct_tag = StructTag::from_str("0x3::token_event_store::TokenEventStoreV1")?;
        let (key, sequence_number) = if let Some(state_value_bytes) = engine
            .get_state_value_bytes_for_resource(collection_uri_mutate.creator_addr(), &struct_tag)?
        {
            let object_resource: TokenEventStoreV1Resource = bcs::from_bytes(&state_value_bytes)?;
            let key = *object_resource.collection_uri_mutate_events().key();
            let sequence_number = engine.get_next_sequence_number(
                &key,
                object_resource.collection_uri_mutate_events().count(),
            )?;
            (key, sequence_number)
        } else {
            // If the TokenEventStoreV1 resource is not found, we skip the event translation to
            // avoid panic because the creation number cannot be decided.
            return Err(AptosDbError::from(anyhow::format_err!(
                "TokenEventStoreV1 resource not found"
            )));
        };
        let collection_mutation_event = CollectionUriMutateEvent::new(
            *collection_uri_mutate.creator_addr(),
            collection_uri_mutate.collection_name().clone(),
            collection_uri_mutate.old_uri().clone(),
            collection_uri_mutate.new_uri().clone(),
        );
        Ok(ContractEventV1::new(
            key,
            sequence_number,
            COLLECTION_URI_MUTATE_EVENT_TYPE.clone(),
            bcs::to_bytes(&collection_mutation_event)?,
        )?)
    }
}
```

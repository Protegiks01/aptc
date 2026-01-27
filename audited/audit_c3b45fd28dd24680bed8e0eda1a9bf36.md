# Audit Report

## Title
Event Stream Fragmentation During ConcurrentSupply Migration Causes Burns to Be Invisible to V1 Event APIs

## Summary
When a token collection is upgraded from `FixedSupply`/`UnlimitedSupply` to `ConcurrentSupply`, all subsequent burn operations emit only v2 `Burn` events. The indexer's event translator intentionally fails to convert these v2 events back to v1 `BurnEvent` format, causing these burns to be completely absent from v1 event query APIs (`get_events_by_event_key`). This creates data fragmentation where different collections' burns are accessible through different API versions, breaking supply tracking for applications still using v1 event APIs.

## Finding Description

The vulnerability exists in the interaction between three components:

**1. Event Emission Logic in Collection Module**

In the `decrement_supply` function, burn events are emitted differently based on supply type: [1](#0-0) 

For `ConcurrentSupply`, the new v2 `Burn` event is **always** emitted, with no feature flag check. [2](#0-1) 

For `FixedSupply`, the event type depends on the feature flag state.

**2. Collection Upgrade Destroys V1 Event Handles**

When `upgrade_to_concurrent` is called, the old supply resources are destroyed: [3](#0-2) 

This removes the `FixedSupply`/`UnlimitedSupply` resources that contain event handles.

**3. Event Translator Silently Fails for ConcurrentSupply**

The indexer attempts to translate v2 `Burn` events to v1 format: [4](#0-3) 

When the required resources don't exist (ConcurrentSupply case), translation fails with an error. [5](#0-4) 

The error is intentionally suppressed for `BURN_TYPE` events when resources are not found, returning `Ok(None)`.

**4. Failed Translations Are Not Indexed** [6](#0-5) 

When translation returns `None`, the event is not indexed in `EventByKeySchema`, making it invisible to v1 event queries.

**Attack Scenario:**

1. Collection owner creates collection with `FixedSupply` (max_supply=1000)
2. Feature flag `module_event_migration_enabled()` is OFF globally
3. Burns emit v1 `BurnEvent` events, indexed in v1 event stream
4. Collection owner calls `upgrade_to_concurrent` to improve parallelism
5. `FixedSupply` resource is destroyed, `ConcurrentSupply` is created
6. All subsequent burns emit v2 `Burn` events (always, no flag check)
7. Indexer attempts to translate v2 events to v1 format
8. Translation fails (resources don't exist), returns `Ok(None)`
9. Burns are NOT indexed in v1 event schemas
10. Applications querying `get_events_by_event_key` for burn events miss all post-upgrade burns
11. Supply accounting becomes incorrect for v1 API consumers

## Impact Explanation

**HIGH Severity** - Significant Protocol Violations

This vulnerability causes:

1. **Data Fragmentation**: Burns are split across v1 and v2 event streams based on collection supply type, with no single API providing complete data
2. **Supply Accounting Errors**: Applications tracking token supply via v1 `BurnEvent` queries will have incorrect data, showing higher supply than actual
3. **Indexer Inconsistency**: Different query methods (v1 vs v2 APIs) return different results for the same collection
4. **Silent Failures**: The error is intentionally suppressed, providing no indication to users that data is incomplete
5. **Protocol Invariant Violation**: Breaks the state consistency invariant that all state transitions must be verifiable through event streams

This meets **HIGH severity** criteria:
- Significant protocol violations affecting event consistency
- State inconsistencies requiring manual intervention to reconcile
- Impacts all applications using v1 event APIs during migration period
- No error signals or documentation warning of incomplete data

## Likelihood Explanation

**HIGH Likelihood** - This will occur deterministically for any collection that upgrades to `ConcurrentSupply` before the global feature flag is enabled.

Contributing factors:
- `upgrade_to_concurrent` is a public function callable by any collection owner via `ExtendRef`
- `ConcurrentSupply` is the recommended supply type for parallelization
- Feature flag migration is gradual, creating an extended window of vulnerability
- No documentation warns users that upgrading affects event visibility
- No safeguards prevent upgrade during migration period

Expected frequency: Every collection upgrade to `ConcurrentSupply` triggers this issue until all consumers migrate to v2 APIs.

## Recommendation

**Immediate Fix**: Add explicit validation to prevent `upgrade_to_concurrent` when the feature flag is disabled:

```move
public fun upgrade_to_concurrent(
    ref: &ExtendRef,
) acquires FixedSupply, UnlimitedSupply {
    // Add this check at function start
    assert!(
        std::features::module_event_migration_enabled(),
        error::invalid_state(EUPGRADE_REQUIRES_MIGRATION_FLAG)
    );
    
    let metadata_object_address = object::address_from_extend_ref(ref);
    // ... rest of function
}
```

**Long-term Solution**: 

1. Document the event migration strategy clearly, warning that ConcurrentSupply uses only v2 events
2. Provide a migration guide for applications to query both v1 and v2 event streams during transition
3. Consider emitting both v1 and v2 events during migration period for full compatibility
4. Add API warnings when querying v1 events for collections with ConcurrentSupply

**Alternative**: Make the translator succeed by storing the event key in ConcurrentSupply:

```move
struct ConcurrentSupply has key {
    current_supply: Aggregator<u64>,
    total_minted: Aggregator<u64>,
    // Add this to enable v1 translation
    legacy_burn_event_key: EventKey,
}
```

## Proof of Concept

```move
#[test(creator = @0x123)]
fun test_burn_event_fragmentation(creator: &signer) acquires FixedSupply, UnlimitedSupply, ConcurrentSupply {
    use std::features;
    use aptos_framework::event;
    
    let creator_address = signer::address_of(creator);
    let name = string::utf8(b"Test Collection");
    
    // Create collection with FixedSupply
    let constructor_ref = create_fixed_collection(
        creator, 
        string::utf8(b"desc"), 
        1000, 
        name, 
        option::none(), 
        string::utf8(b"uri")
    );
    
    // Downgrade to FixedSupply (for testing v1 events)
    downgrade_from_concurrent_for_test(&object::generate_extend_ref(&constructor_ref));
    
    let collection = object::address_to_object<Collection>(
        create_collection_address(&creator_address, &name)
    );
    
    // Burn with FixedSupply - emits v1 BurnEvent
    decrement_supply(&collection, @0xBEEF, option::some(1), creator_address);
    
    // Verify v1 event was emitted (this would be checked via event query in real scenario)
    // Note: In production, this would be queried via get_events_by_event_key
    
    // Upgrade to ConcurrentSupply
    upgrade_to_concurrent(&object::generate_extend_ref(&constructor_ref));
    
    // Burn with ConcurrentSupply - emits v2 Burn
    decrement_supply(&collection, @0xDEAD, option::some(2), creator_address);
    
    // v2 event is emitted
    assert!(event::emitted_events<Burn>().length() == 1, 0);
    
    // BUT: v1 event query would NOT see this second burn
    // The BurnEvent stream only has 1 event (the first burn)
    // The second burn is ONLY in the v2 Burn stream
    // Applications using get_events_by_event_key will miss the second burn
}
```

**Notes**

This vulnerability represents a fundamental design issue in the event migration strategy. While the intentional suppression of translation errors (lines 566-578 in db_indexer.rs) suggests this behavior may be "by design," it creates serious data consistency and availability problems for applications during the migration period. The silent nature of the failure—returning `Ok(None)` without logging for "expected" errors—means applications have no indication their data is incomplete. This breaks the critical invariant that event streams provide a complete audit log of all state transitions.

### Citations

**File:** aptos-move/framework/aptos-token-objects/sources/collection.move (L474-485)
```text
        if (exists<ConcurrentSupply>(collection_addr)) {
            let supply = &mut ConcurrentSupply[collection_addr];
            aggregator_v2::sub(&mut supply.current_supply, 1);

            event::emit(
                Burn {
                    collection: collection_addr,
                    index: *index.borrow(),
                    token,
                    previous_owner,
                },
            );
```

**File:** aptos-move/framework/aptos-token-objects/sources/collection.move (L486-506)
```text
        } else if (exists<FixedSupply>(collection_addr)) {
            let supply = &mut FixedSupply[collection_addr];
            supply.current_supply -= 1;
            if (std::features::module_event_migration_enabled()) {
                event::emit(
                    Burn {
                        collection: collection_addr,
                        index: *index.borrow(),
                        token,
                        previous_owner,
                    },
                );
            } else {
                event::emit_event(
                    &mut supply.burn_events,
                    BurnEvent {
                        index: *index.borrow(),
                        token,
                    },
                );
            };
```

**File:** aptos-move/framework/aptos-token-objects/sources/collection.move (L543-583)
```text
        let (supply, current_supply, total_minted, burn_events, mint_events) = if (exists<FixedSupply>(
            metadata_object_address
        )) {
            let FixedSupply {
                current_supply,
                max_supply,
                total_minted,
                burn_events,
                mint_events,
            } = move_from<FixedSupply>(metadata_object_address);

            let supply = ConcurrentSupply {
                current_supply: aggregator_v2::create_aggregator(max_supply),
                total_minted: aggregator_v2::create_unbounded_aggregator(),
            };
            (supply, current_supply, total_minted, burn_events, mint_events)
        } else if (exists<UnlimitedSupply>(metadata_object_address)) {
            let UnlimitedSupply {
                current_supply,
                total_minted,
                burn_events,
                mint_events,
            } = move_from<UnlimitedSupply>(metadata_object_address);

            let supply = ConcurrentSupply {
                current_supply: aggregator_v2::create_unbounded_aggregator(),
                total_minted: aggregator_v2::create_unbounded_aggregator(),
            };
            (supply, current_supply, total_minted, burn_events, mint_events)
        } else {
            // untracked collection is already concurrent, and other variants too.
            abort error::invalid_argument(EALREADY_CONCURRENT)
        };

        // update current state:
        aggregator_v2::add(&mut supply.current_supply, current_supply);
        aggregator_v2::add(&mut supply.total_minted, total_minted);
        move_to(&metadata_object_signer, supply);

        event::destroy_handle(burn_events);
        event::destroy_handle(mint_events);
```

**File:** storage/indexer/src/event_v2_translator.rs (L568-595)
```rust
        let (key, sequence_number) = if let Some(state_value_bytes) = engine
            .get_state_value_bytes_for_object_group_resource(
                burn.collection(),
                &fixed_supply_struct_tag,
            )? {
            let fixed_supply_resource: FixedSupplyResource = bcs::from_bytes(&state_value_bytes)?;
            let key = *fixed_supply_resource.burn_events().key();
            let sequence_number = engine
                .get_next_sequence_number(&key, fixed_supply_resource.burn_events().count())?;
            (key, sequence_number)
        } else if let Some(state_value_bytes) = engine
            .get_state_value_bytes_for_object_group_resource(
                burn.collection(),
                &unlimited_supply_struct_tag,
            )?
        {
            let unlimited_supply_resource: UnlimitedSupplyResource =
                bcs::from_bytes(&state_value_bytes)?;
            let key = *unlimited_supply_resource.burn_events().key();
            let sequence_number = engine
                .get_next_sequence_number(&key, unlimited_supply_resource.burn_events().count())?;
            (key, sequence_number)
        } else {
            // If the collection resource is not found, we skip the event translation to avoid panic
            // because the creation number cannot be decided. The collection may have ConcurrentSupply.
            return Err(AptosDbError::from(anyhow::format_err!(
                "FixedSupply or UnlimitedSupply resource not found"
            )));
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

**File:** storage/indexer/src/db_indexer.rs (L566-578)
```rust
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
```

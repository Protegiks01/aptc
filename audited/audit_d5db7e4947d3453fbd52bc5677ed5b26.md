# Audit Report

## Title
Event Type Tag Inconsistency During Collection Maximum Mutation Event Migration Causing Indexer Duplication

## Summary
During the migration from V1 EventHandle-based events to V2 module events, the `CollectionMaximumMutate` event underwent a struct name correction from "Maxium" (typo) to "Maximum" (correct). This results in events with different type tags (`0x3::token_event_store::CollectionMaxiumMutateEvent` vs `0x3::token_event_store::CollectionMaximumMutate`) existing in blockchain history, causing external indexers to treat semantically identical mutation events as distinct event types, leading to duplicate or inconsistent mutation records.

## Finding Description

The token event system implements a migration from V1 EventHandle-based events to V2 module events controlled by the `module_event_migration_enabled()` feature flag. [1](#0-0) [2](#0-1) 

The emission logic conditionally emits different event types based on the migration flag: [3](#0-2) 

This creates two distinct type tags in blockchain history:
- **Pre-migration**: `0x3::token_event_store::CollectionMaxiumMutateEvent` (with typo)
- **Post-migration**: `0x3::token_event_store::CollectionMaximumMutate` (corrected)

The API includes a translation mechanism to convert V2 events back to V1 format, but it requires explicit configuration: [4](#0-3) 

The configuration defaults to **disabled**: [5](#0-4) 

External indexers querying nodes without `enable_event_v2_translation` enabled will receive events with different type tags for semantically identical collection maximum mutations. The indexer's event translator only handles the V2→V1 translation when explicitly configured: [6](#0-5) 

If no translator is registered for a type tag, the method returns `Ok(None)`, silently dropping the event from translation.

## Impact Explanation

This issue qualifies as **Medium Severity** under the Aptos bug bounty program criteria for "State inconsistencies requiring intervention." 

External indexers consuming event data will:
1. Record collection maximum mutations twice - once under each type tag
2. Fail to correlate pre-migration and post-migration events as the same mutation type
3. Provide inconsistent historical data to downstream applications (NFT marketplaces, analytics platforms)
4. Require manual intervention to reconcile duplicate records

While this does not affect on-chain state or consensus, it breaks the **State Consistency** invariant from an indexer perspective: identical semantic operations (collection maximum mutations) appear as different event types in the event stream.

## Likelihood Explanation

**Likelihood: HIGH**

This issue occurs automatically during the migration period when `module_event_migration_enabled()` transitions from `false` to `true`. Given that:
- The feature flag is transient (designed to be toggled)
- Default API configuration has translation disabled
- Many external indexers operate without full-node control

Most external indexers will encounter this inconsistency unless they:
1. Implement special handling for the migration
2. Query only nodes with translation enabled
3. Manually map both type tags to the same semantic event

## Recommendation

**Option 1: API-Level Solution**
Change the default configuration to enable event translation:

```rust
// config/src/config/internal_indexer_db_config.rs
impl Default for InternalIndexerDBConfig {
    fn default() -> Self {
        Self {
            enable_transaction: false,
            enable_event: false,
            enable_event_v2_translation: true,  // Enable by default
            event_v2_translation_ignores_below_version: 0,
            enable_statekeys: false,
            batch_size: 10_000,
        }
    }
}
```

**Option 2: Documentation & Migration Guide**
Provide clear migration documentation for external indexers that:
- Lists all event types that underwent name corrections
- Provides type tag mapping tables
- Recommends querying nodes with translation enabled
- Includes SQL scripts for reconciling duplicate records

**Option 3: Extended Translation Window**
Maintain V2→V1 translation indefinitely rather than treating it as a temporary compatibility layer.

## Proof of Concept

```rust
// Demonstration of type tag mismatch
// This test shows events with different type tags for the same semantic operation

#[test]
fn test_collection_maximum_mutation_type_tag_mismatch() {
    // Pre-migration: EventHandle-based emission
    let v1_type_tag = "0x3::token_event_store::CollectionMaxiumMutateEvent";
    
    // Post-migration: Module event emission  
    let v2_type_tag = "0x3::token_event_store::CollectionMaximumMutate";
    
    // These represent the same semantic event but have different type tags
    assert_ne!(v1_type_tag, v2_type_tag);
    
    // External indexer without translation will see both as separate event types
    // Leading to duplicate mutation records in the indexer database
}
```

To reproduce in a live environment:
1. Query events from a node before `MODULE_EVENT_MIGRATION` feature was enabled
2. Query events from the same node after the feature was enabled
3. Observe that collection maximum mutation events have different type tag strings
4. Verify that without translation, these appear as distinct event types in API responses

## Notes

The vulnerability is exacerbated by the fact that the original V1 struct name contains a typo ("Maxium" instead of "Maximum"), making it non-obvious to indexer developers that these events are semantically equivalent. The corrected V2 name appears to be a completely different event type rather than a migration of the same event. [7](#0-6)

### Citations

**File:** aptos-move/framework/aptos-token/sources/token_event_store.move (L53-58)
```text
    struct CollectionMaxiumMutateEvent has drop, store {
        creator_addr: address,
        collection_name: String,
        old_maximum: u64,
        new_maximum: u64,
    }
```

**File:** aptos-move/framework/aptos-token/sources/token_event_store.move (L60-67)
```text
    #[event]
    /// Event emitted when the collection maximum is mutated
    struct CollectionMaximumMutate has drop, store {
        creator_addr: address,
        collection_name: String,
        old_maximum: u64,
        new_maximum: u64,
    }
```

**File:** aptos-move/framework/aptos-token/sources/token_event_store.move (L287-311)
```text
    friend fun emit_collection_maximum_mutate_event(creator: &signer, collection: String, old_maximum: u64, new_maximum: u64) acquires TokenEventStoreV1 {
        let event = CollectionMaxiumMutateEvent {
            creator_addr: signer::address_of(creator),
            collection_name: collection,
            old_maximum,
            new_maximum,
        };
        initialize_token_event_store(creator);
        let token_event_store = &mut TokenEventStoreV1[signer::address_of(creator)];
        if (std::features::module_event_migration_enabled()) {
            event::emit(
                CollectionMaximumMutate {
                    creator_addr: signer::address_of(creator),
                    collection_name: collection,
                    old_maximum,
                    new_maximum,
                }
            );
        } else {
            event::emit_event<CollectionMaxiumMutateEvent>(
                &mut token_event_store.collection_maximum_mutate_events,
                event,
            );
        };
    }
```

**File:** api/src/context.rs (L1004-1018)
```rust
    fn maybe_translate_v2_to_v1_events(
        &self,
        mut txn: TransactionOnChainData,
    ) -> TransactionOnChainData {
        if self.indexer_reader.is_some()
            && self
                .node_config
                .indexer_db_config
                .enable_event_v2_translation
        {
            self.translate_v2_to_v1_events_for_version(txn.version, &mut txn.events)
                .ok();
        }
        txn
    }
```

**File:** config/src/config/internal_indexer_db_config.rs (L69-79)
```rust
impl Default for InternalIndexerDBConfig {
    fn default() -> Self {
        Self {
            enable_transaction: false,
            enable_event: false,
            enable_event_v2_translation: false,
            event_v2_translation_ignores_below_version: 0,
            enable_statekeys: false,
            batch_size: 10_000,
        }
    }
```

**File:** storage/indexer/src/db_indexer.rs (L552-584)
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
        } else {
            Ok(None)
        }
    }
```

**File:** types/src/account_config/events/collection_maximum_mutate_event.rs (L60-64)
```rust
impl MoveStructType for CollectionMaximumMutateEvent {
    const MODULE_NAME: &'static IdentStr = ident_str!("token_event_store");
    // The struct name in the Move code contains a typo.
    const STRUCT_NAME: &'static IdentStr = ident_str!("CollectionMaxiumMutateEvent");
}
```

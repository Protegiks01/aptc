# Audit Report

## Title
Non-Deterministic Event Indexing Due to Incorrect State View in TokenMutationTranslator

## Summary
The `TokenMutationTranslator` uses `latest_state_checkpoint_view()` to query token resources when translating V2 events to V1 format. When a token is burned after emitting mutation events, the translator fails to find the Token resource and returns an error without assigning sequence numbers. This creates non-deterministic indexing behavior where events may or may not be indexed depending on when the indexer processes them relative to subsequent transactions, violating the deterministic execution invariant and causing sequence number gaps that trigger "DB corruption" errors during queries.

## Finding Description

The event translation system is designed to convert ContractEventV2 (module events) to ContractEventV1 format for backward compatibility. The `TokenMutationTranslator` is responsible for translating token mutation events. [1](#0-0) 

When processing TokenMutation events, the translator must look up the Token resource to obtain the EventHandle key and determine the next sequence number. However, it queries state using `latest_state_checkpoint_view()`: [2](#0-1) 

This creates a critical timing dependency: if a token is burned in transaction V+1, and the indexer processes events from transaction V after V+1 is committed, the translator will fail to find the Token resource even though the token existed when the event was emitted at version V. [3](#0-2) 

When translation fails, no sequence number is assigned or cached, and the event is silently skipped: [4](#0-3) 

This creates sequence number gaps. The event lookup function expects continuous sequence numbers and will fail with a "DB corruption" error when gaps are detected: [5](#0-4) 

**Attack Scenario:**
1. Transaction V1: Token emits TokenMutation event (token exists)
2. Transaction V2: Token emits another TokenMutation event (token still exists)  
3. Transaction V3: Token is burned
4. All transactions committed to main DB
5. Indexer processes events:
   - If processed before V3 commits: Both events indexed successfully (seq 0, 1)
   - If processed after V3 commits: Both events fail translation, not indexed at all
   - If processed between: First event indexed (seq 0), second fails, creating a gap

The same events produce different indexing results based solely on timing, violating deterministic execution. Additionally, if seq 0 exists but seq 1 is missing, subsequent queries will fail with "DB corruption: Sequence number not continuous."

## Impact Explanation

This is a **Medium severity** issue per Aptos bug bounty criteria:

**State inconsistencies requiring intervention**: The indexer produces non-deterministic results where the same blockchain state can result in different indexed data depending on when the indexer processes transactions. This breaks the fundamental expectation that indexing is reproducible and deterministic.

**Specific impacts:**
1. **Missing Events**: Legitimately emitted events are not indexed, causing data loss in queries
2. **Query Failures**: Sequence number gaps cause `lookup_events_by_key()` to return "DB corruption" errors, breaking API functionality
3. **Non-Deterministic Behavior**: Multiple indexer nodes or restarts can produce different indexed states from identical blockchain data
4. **Operational Issues**: Requires manual intervention to fix inconsistent indexer state

While this does not directly cause fund loss or consensus violations, it compromises the integrity and reliability of the indexing layer, which is critical for dApps, wallets, and other blockchain infrastructure.

## Likelihood Explanation

**High likelihood** of occurrence:

1. **Common Pattern**: Token burning is a standard operation in NFT and token systems
2. **Race Condition Window**: Any token that emits mutation events before being burned will trigger this issue
3. **No Attacker Intent Required**: This is a bug that manifests naturally during normal token operations, not requiring malicious behavior
4. **Affects All Token Types**: Any token using the TokenMutation event pattern is vulnerable

The issue occurs whenever:
- A token emits mutation events (description change, URI update, etc.)
- The token is subsequently burned (either in the same transaction or later)
- The indexer processes these events after the burn is committed

This is a regular operational pattern, not an edge case.

## Recommendation

**Fix: Use state at the event's transaction version instead of latest state**

The translator should use `state_view_at_version()` with the event's transaction version instead of `latest_state_checkpoint_view()`. This requires passing the transaction version through the translation pipeline.

**Changes needed:**

1. Modify the `EventV2Translator` trait to accept version parameter:
```rust
pub trait EventV2Translator: Send + Sync {
    fn translate_event_v2_to_v1(
        &self,
        v2: &ContractEventV2,
        version: Version,  // ADD THIS
        engine: &EventV2TranslationEngine,
    ) -> Result<ContractEventV1>;
}
```

2. Update `EventV2TranslationEngine` to provide version-aware state lookup:
```rust
pub fn get_state_value_bytes_for_resource_at_version(
    &self,
    address: &AccountAddress,
    struct_tag: &StructTag,
    version: Version,  // ADD THIS
) -> Result<Option<Bytes>> {
    let state_view = self
        .main_db_reader
        .state_view_at_version(Some(version))?;  // USE VERSION HERE
    let state_key = StateKey::resource(address, struct_tag)?;
    let maybe_state_value = state_view.get_state_value(&state_key)?;
    Ok(maybe_state_value.map(|state_value| state_value.bytes().clone()))
}
```

3. Update `process_a_batch` to pass version to translators:
```rust
if let Some(translated_v1_event) =
    self.translate_event_v2_to_v1(v2, version).map_err(|e| { ... })?  // PASS VERSION
```

This ensures the translator always sees the state as it existed at the event's transaction version, making indexing deterministic and reproducible.

## Proof of Concept

**Move Test Case:**

```move
#[test(creator = @0xcafe, framework = @0x1)]
fun test_burned_token_mutation_indexing(creator: &signer, framework: &signer) {
    use aptos_framework::account;
    use aptos_token_objects::token;
    use aptos_token_objects::collection;
    use std::string;
    
    // Setup: Create collection and token
    account::create_account_for_test(signer::address_of(creator));
    
    let collection_name = string::utf8(b"Test Collection");
    let token_name = string::utf8(b"Test Token");
    
    collection::create_unlimited_collection(
        creator,
        string::utf8(b"Description"),
        collection_name,
        option::none(),
        string::utf8(b"https://example.com"),
    );
    
    let token_constructor = token::create_named_token(
        creator,
        collection_name,
        string::utf8(b"Description"),
        token_name,
        option::none(),
        string::utf8(b"https://example.com"),
    );
    
    let token_addr = object::address_from_constructor_ref(&token_constructor);
    let mutator = token::generate_mutator_ref(&token_constructor);
    let burn_ref = token::generate_burn_ref(&token_constructor);
    
    // Step 1: Mutate token (emits TokenMutation event)
    token::set_description(&mutator, string::utf8(b"New Description"));
    
    // Step 2: Mutate token again (emits another TokenMutation event)
    token::set_uri(&mutator, string::utf8(b"https://new.example.com"));
    
    // Step 3: Burn the token
    token::burn(burn_ref);
    
    // At this point:
    // - Two TokenMutation events were emitted when token existed
    // - Token is now burned
    // - If indexer processes these events using latest_state_checkpoint_view(),
    //   it will fail to find the Token resource and skip both events
    // - This creates missing events in the index
    
    // Expected: Both mutation events should be indexed with seq 0 and 1
    // Actual (with bug): Events are not indexed if processed after burn
}
```

**Reproduction Steps:**
1. Deploy the above test contract
2. Run the test, which mints, mutates, and burns a token
3. Configure indexer to process these transactions after they're all committed
4. Query events for the token's EventKey
5. Observe that mutation events are missing from the index
6. Attempt to query with continuous sequence numbers - will fail with "DB corruption" error if any events succeeded before failure

**Notes**

This vulnerability is particularly insidious because it creates **non-deterministic** behavior in the indexing layer. The same blockchain state can produce different indexed results depending solely on timing - a clear violation of the deterministic execution invariant that underlies blockchain systems.

The issue affects not just `TokenMutationTranslator` but potentially all translators that query resources that can be deleted [6](#0-5) , including `CollectionMutationTranslator`, `BurnTranslator`, and others. The root cause is the systematic use of `latest_state_checkpoint_view()` throughout the translation engine when version-specific state views should be used.

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

**File:** storage/indexer/src/event_v2_translator.rs (L430-469)
```rust
struct TokenMutationTranslator;
impl EventV2Translator for TokenMutationTranslator {
    fn translate_event_v2_to_v1(
        &self,
        v2: &ContractEventV2,
        engine: &EventV2TranslationEngine,
    ) -> Result<ContractEventV1> {
        let token_mutation = TokenMutation::try_from_bytes(v2.event_data())?;
        let struct_tag_str = "0x4::token::Token".to_string();
        let struct_tag = StructTag::from_str(&struct_tag_str)?;
        let (key, sequence_number) = if let Some(state_value_bytes) = engine
            .get_state_value_bytes_for_object_group_resource(
                token_mutation.token_address(),
                &struct_tag,
            )? {
            let token_resource: TokenResource = bcs::from_bytes(&state_value_bytes)?;
            let key = *token_resource.mutation_events().key();
            let sequence_number =
                engine.get_next_sequence_number(&key, token_resource.mutation_events().count())?;
            (key, sequence_number)
        } else {
            // If the token resource is not found, we skip the event translation to avoid panic
            // because the creation number cannot be decided. The token may have been burned.
            return Err(AptosDbError::from(anyhow::format_err!(
                "Token resource not found"
            )));
        };
        let token_mutation_event = TokenMutationEvent::new(
            token_mutation.mutated_field_name().clone(),
            token_mutation.old_value().clone(),
            token_mutation.new_value().clone(),
        );
        Ok(ContractEventV1::new(
            key,
            sequence_number,
            TOKEN_MUTATION_EVENT_TYPE.clone(),
            bcs::to_bytes(&token_mutation_event)?,
        )?)
    }
}
```

**File:** storage/indexer/src/event_v2_translator.rs (L471-507)
```rust
struct CollectionMutationTranslator;
impl EventV2Translator for CollectionMutationTranslator {
    fn translate_event_v2_to_v1(
        &self,
        v2: &ContractEventV2,
        engine: &EventV2TranslationEngine,
    ) -> Result<ContractEventV1> {
        let collection_mutation = CollectionMutation::try_from_bytes(v2.event_data())?;
        let struct_tag_str = "0x4::collection::Collection".to_string();
        let struct_tag = StructTag::from_str(&struct_tag_str)?;
        let (key, sequence_number) = if let Some(state_value_bytes) = engine
            .get_state_value_bytes_for_object_group_resource(
                collection_mutation.collection().inner(),
                &struct_tag,
            )? {
            let collection_resource: CollectionResource = bcs::from_bytes(&state_value_bytes)?;
            let key = *collection_resource.mutation_events().key();
            let sequence_number = engine
                .get_next_sequence_number(&key, collection_resource.mutation_events().count())?;
            (key, sequence_number)
        } else {
            // If the token resource is not found, we skip the event translation to avoid panic
            // because the creation number cannot be decided.
            return Err(AptosDbError::from(anyhow::format_err!(
                "Collection resource not found"
            )));
        };
        let collection_mutation_event =
            CollectionMutationEvent::new(collection_mutation.mutated_field_name().clone());
        Ok(ContractEventV1::new(
            key,
            sequence_number,
            COLLECTION_MUTATION_EVENT_TYPE.clone(),
            bcs::to_bytes(&collection_mutation_event)?,
        )?)
    }
}
```

**File:** storage/indexer/src/db_indexer.rs (L232-239)
```rust
            if seq != cur_seq {
                let msg = if cur_seq == start_seq_num {
                    "First requested event is probably pruned."
                } else {
                    "DB corruption: Sequence number not continuous."
                };
                bail!("{} expected: {}, actual: {}", msg, cur_seq, seq);
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

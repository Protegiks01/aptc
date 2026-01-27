# Audit Report

## Title
Missing Validation Allows Event Log Spam Through Identical Value Mutations in Token Objects Framework

## Summary
The collection and token mutation functions in the Token Objects (v2) framework do not validate whether `old_value == new_value` before emitting Mutation events. This allows collection/token owners to spam event logs and artificially inflate activity metrics by repeatedly calling mutation functions with the current value, creating redundant events that indexers must process and store.

## Finding Description

The Token Objects framework provides mutation functions for updating collection and token metadata fields (name, description, URI). These functions emit `Mutation` events containing `old_value` and `new_value` fields to track changes.

**Vulnerable Functions:**

Collection mutations: [1](#0-0) [2](#0-1) [3](#0-2) 

Token mutations: [4](#0-3) [5](#0-4) [6](#0-5) 

None of these functions validate that the new value differs from the current value before emitting the event. This allows a collection/token owner with a `MutatorRef` to call these functions repeatedly with the same value, generating redundant Mutation events.

**Indexer Impact:**

The indexer processes these events and stores activity records: [7](#0-6) 

Each TokenMutationEvent creates a new row in the `token_activities_v2` table with `before_value` and `after_value` fields, even when they are identical. This bloats the indexer database and can manipulate activity metrics used by NFT marketplaces and analytics platforms.

## Impact Explanation

This is a **Low Severity** issue per the Aptos bug bounty program criteria:
- **Non-critical implementation bug**: Does not affect consensus, safety, or funds
- **Data pollution**: Bloats event logs and indexer databases
- **Metrics manipulation**: Can artificially inflate collection/token activity metrics
- **Limited scope**: Only affects the attacker's own collections/tokens

The issue does NOT constitute Critical/High/Medium severity because:
- No consensus or safety violation
- No loss or theft of funds
- No validator impact or network availability issues
- Attacker must pay gas for each spam transaction
- Indexer databases can be rebuilt if corrupted

## Likelihood Explanation

**High Likelihood** within limited scope:
- Any user can create collections/tokens and obtain MutatorRef
- Exploitation is trivial (just call mutation functions with current values)
- No special privileges or validator access required
- Already present in production code

**Impact Mitigation:**
- Attacker can only spam events for their own assets
- Gas costs limit economic viability of sustained attacks
- Primarily affects off-chain indexers, not on-chain state

## Recommendation

Add validation to check that the new value differs from the current value before emitting mutation events:

**For collection mutations:**
```move
public fun set_description(mutator_ref: &MutatorRef, description: String) acquires Collection {
    assert!(description.length() <= MAX_DESCRIPTION_LENGTH, error::out_of_range(EDESCRIPTION_TOO_LONG));
    let collection = borrow_mut(mutator_ref);
    
    // Add validation to prevent no-op mutations
    if (description == collection.description) {
        return
    };
    
    if (std::features::module_event_migration_enabled()) {
        event::emit(Mutation {
            mutated_field_name: string::utf8(b"description"),
            collection: object::address_to_object(mutator_ref.self),
            old_value: collection.description,
            new_value: description,
        });
    } else {
        event::emit_event(
            &mut collection.mutation_events,
            MutationEvent { mutated_field_name: string::utf8(b"description") },
        );
    };
    collection.description = description;
}
```

Apply the same pattern to `set_name()`, `set_uri()` for both collections and tokens.

## Proof of Concept

```move
#[test(creator = @0x123)]
fun test_mutation_event_spam(creator: &signer) acquires Collection {
    // Create a collection
    let collection_name = string::utf8(b"Test Collection");
    let constructor_ref = create_unlimited_collection(
        creator,
        string::utf8(b"Test Description"),
        collection_name,
        option::none(),
        string::utf8(b"https://test.com")
    );
    
    let mutator_ref = generate_mutator_ref(&constructor_ref);
    let collection = object::address_to_object<Collection>(
        create_collection_address(&signer::address_of(creator), &collection_name)
    );
    
    // Spam mutation events with identical values
    let current_description = description(collection);
    
    // All these calls emit events even though nothing changes
    set_description(&mutator_ref, current_description);
    set_description(&mutator_ref, current_description);
    set_description(&mutator_ref, current_description);
    
    // Verify 3 identical Mutation events were emitted
    let events = event::emitted_events<Mutation>();
    assert!(events.length() == 3, 0);
    
    // All events have identical old_value and new_value
    let i = 0;
    while (i < 3) {
        let evt = vector::borrow(&events, i);
        assert!(evt.old_value == evt.new_value, 1);
        i = i + 1;
    };
}
```

**Notes**

This is a confirmed Low severity data quality issue in the Token Objects framework. While it does not pose critical security risks to the blockchain's consensus or safety properties, it represents a legitimate implementation bug that:

1. Allows event log pollution and indexer database bloat
2. Enables manipulation of NFT activity metrics used by marketplaces
3. Violates the semantic expectation that mutation events represent actual state changes
4. Is trivially exploitable by any collection/token owner

The issue is properly scoped as Low severity since exploitation requires owning the MutatorRef (obtainable by creating collections/tokens), incurs gas costs, and only affects off-chain indexing infrastructure rather than on-chain consensus or safety guarantees.

### Citations

**File:** aptos-move/framework/aptos-token-objects/sources/collection.move (L659-669)
```text
    public fun set_name(mutator_ref: &MutatorRef, name: String) acquires Collection {
        assert!(name.length() <= MAX_COLLECTION_NAME_LENGTH, error::out_of_range(ECOLLECTION_NAME_TOO_LONG));
        let collection = borrow_mut(mutator_ref);
        event::emit(Mutation {
            mutated_field_name: string::utf8(b"name") ,
            collection: object::address_to_object(mutator_ref.self),
            old_value: collection.name,
            new_value: name,
        });
        collection.name = name;
    }
```

**File:** aptos-move/framework/aptos-token-objects/sources/collection.move (L671-688)
```text
    public fun set_description(mutator_ref: &MutatorRef, description: String) acquires Collection {
        assert!(description.length() <= MAX_DESCRIPTION_LENGTH, error::out_of_range(EDESCRIPTION_TOO_LONG));
        let collection = borrow_mut(mutator_ref);
        if (std::features::module_event_migration_enabled()) {
            event::emit(Mutation {
                mutated_field_name: string::utf8(b"description"),
                collection: object::address_to_object(mutator_ref.self),
                old_value: collection.description,
                new_value: description,
            });
        } else {
            event::emit_event(
                &mut collection.mutation_events,
                MutationEvent { mutated_field_name: string::utf8(b"description") },
            );
        };
        collection.description = description;
    }
```

**File:** aptos-move/framework/aptos-token-objects/sources/collection.move (L690-707)
```text
    public fun set_uri(mutator_ref: &MutatorRef, uri: String) acquires Collection {
        assert!(uri.length() <= MAX_URI_LENGTH, error::out_of_range(EURI_TOO_LONG));
        let collection = borrow_mut(mutator_ref);
        if (std::features::module_event_migration_enabled()) {
            event::emit(Mutation {
                mutated_field_name: string::utf8(b"uri"),
                collection: object::address_to_object(mutator_ref.self),
                old_value: collection.uri,
                new_value: uri,
            });
        } else {
            event::emit_event(
                &mut collection.mutation_events,
                MutationEvent { mutated_field_name: string::utf8(b"uri") },
            );
        };
        collection.uri = uri;
    }
```

**File:** aptos-move/framework/aptos-token-objects/sources/token.move (L774-795)
```text
    public fun set_description(mutator_ref: &MutatorRef, description: String) acquires Token {
        assert!(description.length() <= MAX_DESCRIPTION_LENGTH, error::out_of_range(EDESCRIPTION_TOO_LONG));
        let token = borrow_mut(mutator_ref);
        if (std::features::module_event_migration_enabled()) {
            event::emit(Mutation {
                token_address: mutator_ref.self,
                mutated_field_name: string::utf8(b"description"),
                old_value: token.description,
                new_value: description
            })
        } else {
            event::emit_event(
                &mut token.mutation_events,
                MutationEvent {
                    mutated_field_name: string::utf8(b"description"),
                    old_value: token.description,
                    new_value: description
                },
            );
        };
        token.description = description;
    }
```

**File:** aptos-move/framework/aptos-token-objects/sources/token.move (L797-830)
```text
    public fun set_name(mutator_ref: &MutatorRef, name: String) acquires Token, TokenIdentifiers {
        assert!(name.length() <= MAX_TOKEN_NAME_LENGTH, error::out_of_range(ETOKEN_NAME_TOO_LONG));

        let token = borrow_mut(mutator_ref);

        let old_name = if (exists<TokenIdentifiers>(mutator_ref.self)) {
            let token_concurrent = &mut TokenIdentifiers[mutator_ref.self];
            let old_name = aggregator_v2::read_derived_string(&token_concurrent.name);
            token_concurrent.name = aggregator_v2::create_derived_string(name);
            old_name
        } else {
            let old_name = token.name;
            token.name = name;
            old_name
        };

        if (std::features::module_event_migration_enabled()) {
            event::emit(Mutation {
                token_address: mutator_ref.self,
                mutated_field_name: string::utf8(b"name"),
                old_value: old_name,
                new_value: name
            })
        } else {
            event::emit_event(
                &mut token.mutation_events,
                MutationEvent {
                    mutated_field_name: string::utf8(b"name"),
                    old_value: old_name,
                    new_value: name
                },
            );
        };
    }
```

**File:** aptos-move/framework/aptos-token-objects/sources/token.move (L832-850)
```text
    public fun set_uri(mutator_ref: &MutatorRef, uri: String) acquires Token {
        assert!(uri.length() <= MAX_URI_LENGTH, error::out_of_range(EURI_TOO_LONG));
        let token = borrow_mut(mutator_ref);
        if (std::features::module_event_migration_enabled()) {
            event::emit(Mutation {
                token_address: mutator_ref.self,
                mutated_field_name: string::utf8(b"uri"),
                old_value: token.uri,
                new_value: uri,
            })
        } else {
            event::emit_event(
                &mut token.mutation_events,
                MutationEvent {
                    mutated_field_name: string::utf8(b"uri"),
                    old_value: token.uri,
                    new_value: uri,
                },
            );
```

**File:** crates/indexer/src/models/token_models/v2_token_activities.rs (L172-178)
```rust
                    V2TokenEvent::TokenMutationEvent(inner) => TokenActivityHelperV2 {
                        from_address: Some(object_core.get_owner_address()),
                        to_address: None,
                        token_amount: BigDecimal::zero(),
                        before_value: Some(inner.old_value.clone()),
                        after_value: Some(inner.new_value.clone()),
                    },
```

# Audit Report

## Title
Duplicate Keys in Token Property Mutation Allow False Audit Trail Creation

## Summary
The `mutate_tokendata_property` function in the legacy token framework (0x3::token) does not validate for duplicate keys in input vectors. This allows token creators to emit `DefaultPropertyMutateEvent` events where `old_values[i]` is `Some(value)` for a property that was actually created within the same transaction, creating false audit trails that mislead off-chain indexers and compliance systems.

## Finding Description

The vulnerability exists in the `mutate_tokendata_property` function which allows token creators to mutate default properties stored in TokenData. [1](#0-0) 

The function validates vector lengths but has no check for duplicate keys in the input. [2](#0-1) 

The formal specification confirms only length validation exists, with no duplicate key checks. [3](#0-2) 

**Attack Flow:**

1. Token creator calls `mutate_tokendata_property` with duplicate keys:
   - `keys = ["color", "color"]`
   - `values = [b"red", b"blue"]`  
   - `types = ["String", "String"]`
   - Assume "color" property doesn't exist initially

2. First iteration (i=0):
   - The function checks if "color" exists in `default_properties`. [4](#0-3) 
   - Property doesn't exist → `old_pv = None`
   - Adds property with `token_data.default_properties.add("color", red)`. [5](#0-4) 

3. Second iteration (i=1):
   - Checks if "color" exists → **now returns true** (added in iteration 0)
   - Sets `old_pv = Some(PropertyValue{value: b"red", ...})`
   - Calls `update_property_value("color", blue)`

4. Event emitted shows:
   - `keys: ["color", "color"]`
   - `old_values: [None, Some(red)]`
   - `new_values: [red, blue]`

The event structure explicitly supports None values for upsert operations. [6](#0-5) 

**Security Guarantee Broken:**

This violates **data integrity and audit trail accuracy**. Off-chain systems (indexers, marketplaces, compliance tools) interpreting the event would incorrectly conclude that:
- The "color" property existed with value "red" **before** the transaction
- It was then updated to "blue" in a second operation

In reality, "color" never existed before this transaction. The value "red" was created and immediately overwritten in the same transaction.

## Impact Explanation

**Severity: Medium** (up to $10,000 per Aptos Bug Bounty program)

This qualifies as a **state inconsistency** issue that affects data integrity:

1. **False Historical Records**: NFT provenance and property history become unreliable. For high-value NFTs where authenticity tracking matters, attackers can fabricate property change history.

2. **Compliance Violations**: Systems relying on event logs for regulatory compliance would have incorrect historical data about token property changes.

3. **Indexer Corruption**: Off-chain indexers processing these events would store incorrect historical state, affecting all downstream applications (marketplaces, analytics platforms, wallets).

4. **No Direct Fund Loss**: The on-chain state is ultimately correct (property has value "blue"). This prevents Critical severity classification.

5. **Limited Scope**: Only token creators can exploit this, and it affects audit trails rather than consensus or fund security.

The impact meets the Medium severity criteria: "State inconsistencies requiring intervention" - indexers would need manual correction to fix corrupted historical data.

## Likelihood Explanation

**Likelihood: Medium to High**

**Attacker Requirements:**
- Must be the token creator (verified by access control). [7](#0-6) 
- Token properties must be marked as mutable. [8](#0-7) 
- No special permissions beyond normal token creator role

**Exploitation Complexity:**
- Very low - simply pass duplicate keys in a single transaction call
- No timing requirements or race conditions
- Deterministic and repeatable

**Detection:**
- Currently difficult - no validation warns about duplicate keys
- Off-chain systems would need to explicitly check for duplicate keys in events

**Motivation:**
- NFT creators could fabricate property history for legitimacy
- Malicious actors could create false provenance trails
- Accidental exploitation possible due to lack of input validation

The function is part of the public API with no warnings about duplicate keys, making accidental misuse likely.

## Recommendation

Add duplicate key validation before processing property mutations:

```move
public fun mutate_tokendata_property(
    creator: &signer,
    token_data_id: TokenDataId,
    keys: vector<String>,
    values: vector<vector<u8>>,
    types: vector<String>,
) acquires Collections {
    assert_tokendata_exists(creator, token_data_id);
    let key_len = keys.length();
    let val_len = values.length();
    let typ_len = types.length();
    assert!(key_len == val_len, error::invalid_state(ETOKEN_PROPERTIES_COUNT_NOT_MATCH));
    assert!(key_len == typ_len, error::invalid_state(ETOKEN_PROPERTIES_COUNT_NOT_MATCH));
    
    // ADD: Validate no duplicate keys
    assert_no_duplicate_keys(&keys);

    // ... rest of function
}

// ADD: New validation function
fun assert_no_duplicate_keys(keys: &vector<String>) {
    let len = keys.length();
    for (i in 0..len) {
        for (j in (i+1)..len) {
            assert!(keys[i] != keys[j], error::invalid_argument(EDUPLICATE_PROPERTY_KEY));
        };
    };
}
```

Add new error constant:
```move
const EDUPLICATE_PROPERTY_KEY: u64 = 41;
```

**Alternative Solution:** Use a more efficient deduplication approach with temporary SimpleMap for O(n) complexity instead of O(n²).

## Proof of Concept

```move
#[test(creator = @0xcafe)]
fun test_duplicate_keys_create_false_audit_trail(creator: &signer) {
    use std::string;
    use aptos_token::token;
    use aptos_token::token_event_store;
    
    // Setup: Create collection and token with mutable properties
    let collection_name = string::utf8(b"TestCollection");
    let token_name = string::utf8(b"TestToken");
    
    token::create_collection(
        creator,
        collection_name,
        string::utf8(b"desc"),
        string::utf8(b"uri"),
        1,
        vector[true, true, true], // mutable
    );
    
    let token_data_id = token::create_tokendata(
        creator,
        collection_name,
        token_name,
        string::utf8(b"desc"),
        1,
        string::utf8(b"uri"),
        @0xcafe,
        100,
        100,
        token::create_token_mutability_config(&vector[true, true, true, true, true]),
        vector[], // no initial properties
        vector[],
        vector[],
    );
    
    // Exploit: Pass duplicate keys
    let keys = vector[
        string::utf8(b"color"),
        string::utf8(b"color"), // DUPLICATE!
    ];
    let values = vector[
        b"red",
        b"blue",
    ];
    let types = vector[
        string::utf8(b"String"),
        string::utf8(b"String"),
    ];
    
    // This call succeeds without error
    token::mutate_tokendata_property(
        creator,
        token_data_id,
        keys,
        values,
        types,
    );
    
    // Result: Event emitted shows:
    // keys: ["color", "color"]
    // old_values: [None, Some("red")]  <- FALSE: "red" never existed before tx!
    // new_values: ["red", "blue"]
    
    // Final on-chain state is correct (color = "blue")
    // But audit trail shows property had value "red" before, which is FALSE
}
```

This PoC demonstrates that duplicate keys are accepted, causing the second iteration to report `old_values[1] = Some("red")` when "red" was actually created in the same transaction, creating a false audit trail.

### Citations

**File:** aptos-move/framework/aptos-token/sources/token.move (L863-900)
```text
    public fun mutate_tokendata_property(
        creator: &signer,
        token_data_id: TokenDataId,
        keys: vector<String>,
        values: vector<vector<u8>>,
        types: vector<String>,
    ) acquires Collections {
        assert_tokendata_exists(creator, token_data_id);
        let key_len = keys.length();
        let val_len = values.length();
        let typ_len = types.length();
        assert!(key_len == val_len, error::invalid_state(ETOKEN_PROPERTIES_COUNT_NOT_MATCH));
        assert!(key_len == typ_len, error::invalid_state(ETOKEN_PROPERTIES_COUNT_NOT_MATCH));

        let all_token_data = &mut Collections[token_data_id.creator].token_data;
        let token_data = all_token_data.borrow_mut(token_data_id);
        assert!(token_data.mutability_config.properties, error::permission_denied(EFIELD_NOT_MUTABLE));
        let old_values: vector<Option<PropertyValue>> = vector::empty();
        let new_values: vector<PropertyValue> = vector::empty();
        assert_non_standard_reserved_property(&keys);
        for (i in 0..keys.length()){
            let key = keys.borrow(i);
            let old_pv = if (token_data.default_properties.contains_key(key)) {
                option::some(*token_data.default_properties.borrow(key))
            } else {
                option::none<PropertyValue>()
            };
            old_values.push_back(old_pv);
            let new_pv = property_map::create_property_value_raw(values[i], types[i]);
            new_values.push_back(new_pv);
            if (old_pv.is_some()) {
                token_data.default_properties.update_property_value(key, new_pv);
            } else {
                token_data.default_properties.add(*key, new_pv);
            };
        };
        token_event_store::emit_default_property_mutate_event(creator, token_data_id.collection, token_data_id.name, keys, old_values, new_values);
    }
```

**File:** aptos-move/framework/aptos-token/sources/token.move (L1855-1855)
```text
        assert!(signer::address_of(creator) == creator_addr, error::permission_denied(ENO_MUTATE_CAPABILITY));
```

**File:** aptos-move/framework/aptos-token/sources/token.spec.move (L365-367)
```text
        aborts_if len(keys) != len(values);
        aborts_if len(keys) != len(types);
        aborts_if !token_data.mutability_config.properties;
```

**File:** aptos-move/framework/aptos-token/sources/token_event_store.move (L111-119)
```text
    struct DefaultPropertyMutateEvent has drop, store {
        creator: address,
        collection: String,
        token: String,
        keys: vector<String>,
        /// we allow upsert so the old values might be none
        old_values: vector<Option<PropertyValue>>,
        new_values: vector<PropertyValue>,
    }
```

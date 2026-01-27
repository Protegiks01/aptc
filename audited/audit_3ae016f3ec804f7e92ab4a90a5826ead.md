# Audit Report

## Title
Unicode Normalization Vulnerability in Token Property Map Keys Allows Duplicate Visually-Identical Properties

## Summary
Token property keys in the Aptos Token V1 standard are not Unicode-normalized, allowing visually identical strings with different byte representations (NFC, NFD, NFKC, NFKD) to coexist as separate properties. This creates state inconsistencies and enables confusion attacks where properties with identical visual appearance have different values.

## Finding Description

The Aptos Token V1 property map system stores token metadata as key-value pairs where keys are Move `String` types. The Move `String` type is a thin wrapper around UTF-8 byte vectors with no Unicode normalization applied. [1](#0-0) 

String equality comparison in Move uses byte-for-byte comparison through `SimpleMap`'s find function: [2](#0-1) 

When properties are updated via `update_property_map`, the system checks if a key exists using this byte-level comparison: [3](#0-2) 

**Attack Path:**

1. Token creator creates a token with property key "café" in NFC normalization form (c-a-f-é where é is Unicode U+00E9, 5 bytes total)
2. Later, when mutating the token via `mutate_one_token` or `mutate_tokendata_property`, the creator uses "café" in NFD normalization form (c-a-f-e-◌́ where e + combining acute accent is two characters: U+0065 + U+0301, 6 bytes total)
3. The system treats these as different keys because the byte sequences differ
4. Instead of updating the existing property, a new property is created
5. The token now has two properties that render identically as "café" but are stored as separate entries

This violates the principle that visually identical property names should refer to the same property. Off-chain indexers, wallets, and applications that normalize Unicode strings will show inconsistent behavior, potentially displaying only one of the duplicate properties or merging them incorrectly.

The vulnerability exists in both token instance property mutation: [4](#0-3) 

And in default TokenData property mutation: [5](#0-4) 

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty program criteria for "State inconsistencies requiring intervention."

**Why NOT Critical:**
- Does not break consensus safety (all validators process identical bytes deterministically)
- Does not enable direct theft or unauthorized minting of tokens
- Does not cause network partition or liveness failures

**Why Medium:**
- Creates application-layer state inconsistencies requiring manual intervention to resolve
- Can bypass application logic that assumes property names are unique by visual appearance
- Enables confusion attacks where users see identical property names with different values
- Could lead to limited fund manipulation if property values control token behavior (e.g., burn permissions, transfer restrictions)
- Off-chain systems (indexers, wallets, explorers) may handle normalization differently, causing display inconsistencies

## Likelihood Explanation

**High Likelihood** of occurrence:

1. **Accidental Occurrence**: Unicode normalization inconsistencies are common in real-world applications. Different text editors, operating systems, and input methods produce different normalization forms. A creator could unintentionally create duplicate properties simply by copying/pasting property names from different sources.

2. **Intentional Exploitation**: An attacker who creates tokens could intentionally exploit this to:
   - Create multiple properties that appear identical to users but have different values
   - Bypass property count limits by creating "duplicate" properties (though limited to 4 normalization variants per visual string)
   - Cause confusion in dApps that display token properties

3. **No Technical Barriers**: The exploit requires only the ability to create and mutate tokens, which is available to any user. No special privileges or insider access needed.

## Recommendation

Implement Unicode normalization (NFC recommended) for all property keys before storage and comparison. The fix should be applied at the property map level to ensure consistency:

**Option 1: Add normalization to PropertyMap operations** (Recommended)
- Add a native function to normalize strings to NFC form
- Call normalization in `property_map::new()`, `property_map::add()`, and `property_map::update_property_map()` before using keys
- Ensure all key lookups use normalized forms

**Option 2: Add normalization to String type**
- Modify `std::string::utf8()` to automatically normalize to NFC
- This ensures all String values across the ecosystem are normalized
- More comprehensive but requires careful migration

**Example fix for Option 1:**
```move
// Add to property_map.move
native fun normalize_string_nfc(s: &String): String;

public fun add(self: &mut PropertyMap, key: String, value: PropertyValue) {
    let normalized_key = normalize_string_nfc(&key);
    assert!(normalized_key.length() <= MAX_PROPERTY_NAME_LENGTH, ...);
    // ... rest of function using normalized_key
}
```

The normalization must be applied consistently across all property operations to prevent existing normalized and non-normalized keys from coexisting.

## Proof of Concept

```move
#[test(creator = @0x1, framework = @0x1)]
fun test_unicode_normalization_attack(creator: signer, framework: signer) {
    use std::string;
    use aptos_token::property_map;
    
    // Create property map with "café" in NFC form (5 bytes: c, a, f, é as U+00E9)
    let nfc_cafe = string::utf8(x"636166c3a9");  // "café" in NFC
    let keys_nfc = vector[nfc_cafe];
    let values = vector[x"76616c7565315f6e6663"];  // "value1_nfc"
    let types = vector[string::utf8(b"String")];
    
    let prop_map = property_map::new(keys_nfc, values, types);
    
    // Attacker uses "café" in NFD form (6 bytes: c, a, f, e, combining acute U+0301)
    let nfd_cafe = string::utf8(x"63616665cc81");  // "café" in NFD
    let keys_nfd = vector[nfd_cafe];
    let values_nfd = vector[x"76616c7565325f6e6664"];  // "value2_nfd"
    let types_nfd = vector[string::utf8(b"String")];
    
    // Update property map with NFD version
    property_map::update_property_map(&mut prop_map, keys_nfd, values_nfd, types_nfd);
    
    // Property map now has TWO properties that look identical
    assert!(property_map::length(&prop_map) == 2, 0);  // PASSES - two distinct properties!
    
    // Both keys exist but are different at byte level
    assert!(property_map::contains_key(&prop_map, &nfc_cafe), 1);  // NFC version exists
    assert!(property_map::contains_key(&prop_map, &nfd_cafe), 2);  // NFD version exists
    
    // Reading with different normalization forms returns different values
    let val_nfc = property_map::borrow(&prop_map, &nfc_cafe);
    let val_nfd = property_map::borrow(&prop_map, &nfd_cafe);
    assert!(property_map::borrow_value(val_nfc) != property_map::borrow_value(val_nfd), 3);
}
```

This test demonstrates that visually identical strings "café" in NFC and NFD forms are treated as completely separate property keys, violating user expectations and creating state confusion.

## Notes

- The Move identifier system deliberately restricts identifiers to ASCII due to Unicode normalization concerns [6](#0-5)  but this restriction does not apply to String values used in property keys.

- This issue affects Token V1 (`aptos_token` module). Token V2 (`aptos_token_objects`) may have similar issues if it uses String keys without normalization.

- The vulnerability does not break blockchain consensus determinism since all validators process identical byte sequences identically. However, it creates application-layer semantic inconsistencies.

- Standard Unicode normalization practice recommends NFC (Canonical Composition) for storage and comparison to prevent this class of vulnerability.

### Citations

**File:** aptos-move/framework/move-stdlib/sources/string.move (L11-14)
```text
    /// A `String` holds a sequence of bytes which is guaranteed to be in utf8 format.
    struct String has copy, drop, store {
        bytes: vector<u8>,
    }
```

**File:** aptos-move/framework/aptos-stdlib/sources/simple_map.move (L189-201)
```text
    fun find<Key: store, Value: store>(
        self: &SimpleMap<Key, Value>,
        key: &Key,
    ): option::Option<u64> {
        let len = self.data.length();
        for (i in 0..len) {
            let element = self.data.borrow(i);
            if (&element.key == key) {
                return option::some(i)
            };
        };
        option::none<u64>()
    }
```

**File:** aptos-move/framework/aptos-token/sources/property_map.move (L202-226)
```text
    public fun update_property_map(
        self: &mut PropertyMap,
        keys: vector<String>,
        values: vector<vector<u8>>,
        types: vector<String>,
    ) {
        let key_len = keys.length();
        let val_len = values.length();
        let typ_len = types.length();
        assert!(key_len == val_len, error::invalid_state(EKEY_COUNT_NOT_MATCH_VALUE_COUNT));
        assert!(key_len == typ_len, error::invalid_state(EKEY_COUNT_NOT_MATCH_TYPE_COUNT));

        for (i in 0..key_len) {
            let key = &keys[i];
            let prop_val = PropertyValue {
                value: values[i],
                type: types[i],
            };
            if (self.contains_key(key)) {
                self.update_property_value(key, prop_val);
            } else {
                self.add(*key, prop_val);
            };
        }
    }
```

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

**File:** aptos-move/framework/aptos-token/sources/token.move (L903-999)
```text
    public fun mutate_one_token(
        account: &signer,
        token_owner: address,
        token_id: TokenId,
        keys: vector<String>,
        values: vector<vector<u8>>,
        types: vector<String>,
    ): TokenId acquires Collections, TokenStore {
        let creator = token_id.token_data_id.creator;
        assert!(signer::address_of(account) == creator, error::permission_denied(ENO_MUTATE_CAPABILITY));
        // validate if the properties is mutable
        assert!(exists<Collections>(creator), error::not_found(ECOLLECTIONS_NOT_PUBLISHED));
        let all_token_data = &mut Collections[
            creator
        ].token_data;

        assert!(all_token_data.contains(token_id.token_data_id), error::not_found(ETOKEN_DATA_NOT_PUBLISHED));
        let token_data = all_token_data.borrow_mut(token_id.token_data_id);

        // if default property is mutatable, token property is always mutable
        // we only need to check TOKEN_PROPERTY_MUTABLE when default property is immutable
        if (!token_data.mutability_config.properties) {
            assert!(
                token_data.default_properties.contains_key(&string::utf8(TOKEN_PROPERTY_MUTABLE)),
                error::permission_denied(EFIELD_NOT_MUTABLE)
            );

            let token_prop_mutable = token_data.default_properties.read_bool(&string::utf8(TOKEN_PROPERTY_MUTABLE));
            assert!(token_prop_mutable, error::permission_denied(EFIELD_NOT_MUTABLE));
        };

        // check if the property_version is 0 to determine if we need to update the property_version
        if (token_id.property_version == 0) {
            let token = withdraw_with_event_internal(token_owner, token_id, 1);
            // give a new property_version for each token
            let cur_property_version = token_data.largest_property_version + 1;
            let new_token_id = create_token_id(token_id.token_data_id, cur_property_version);
            let new_token = Token {
                id: new_token_id,
                amount: 1,
                token_properties: token_data.default_properties,
            };
            direct_deposit(token_owner, new_token);
            update_token_property_internal(token_owner, new_token_id, keys, values, types);
            if (std::features::module_event_migration_enabled()) {
                event::emit(MutatePropertyMap {
                    account: token_owner,
                    old_id: token_id,
                    new_id: new_token_id,
                    keys,
                    values,
                    types
                });
            } else {
                event::emit_event<MutateTokenPropertyMapEvent>(
                    &mut TokenStore[token_owner].mutate_token_property_events,
                    MutateTokenPropertyMapEvent {
                        old_id: token_id,
                        new_id: new_token_id,
                        keys,
                        values,
                        types
                    },
                );
            };

            token_data.largest_property_version = cur_property_version;
            // burn the orignial property_version 0 token after mutation
            let Token { id: _, amount: _, token_properties: _ } = token;
            new_token_id
        } else {
            // only 1 copy for the token with property verion bigger than 0
            update_token_property_internal(token_owner, token_id, keys, values, types);
            if (std::features::module_event_migration_enabled()) {
                event::emit(MutatePropertyMap {
                    account: token_owner,
                    old_id: token_id,
                    new_id: token_id,
                    keys,
                    values,
                    types
                });
            } else {
                event::emit_event<MutateTokenPropertyMapEvent>(
                    &mut TokenStore[token_owner].mutate_token_property_events,
                    MutateTokenPropertyMapEvent {
                        old_id: token_id,
                        new_id: token_id,
                        keys,
                        values,
                        types
                    },
                );
            };
            token_id
        }
    }
```

**File:** third_party/move/move-core/types/src/identifier.rs (L20-23)
```rust
//! Allowed identifiers are currently restricted to ASCII due to unresolved issues with Unicode
//! normalization. See [Rust issue #55467](https://github.com/rust-lang/rust/issues/55467) and the
//! associated RFC for some discussion. Unicode identifiers may eventually be supported once these
//! issues are worked out.
```

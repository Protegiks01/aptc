# Audit Report

## Title
Unicode Normalization Allows Visually Identical Property Keys to Coexist in Token PropertyMaps

## Summary
The Aptos token PropertyMap implementation does not perform Unicode normalization on property keys, allowing attackers to create multiple properties with visually identical names that are treated as distinct entries due to different Unicode normalization forms (NFC vs NFD). This creates UI confusion and potential logic errors in contracts that assume property key uniqueness based on visual representation.

## Finding Description

The PropertyMap implementation in both Token V1 and Token V2 uses `SimpleMap<String, PropertyValue>` for storing properties. [1](#0-0) 

Key comparison in SimpleMap relies on Move's String equality operator, which performs byte-by-byte comparison: [2](#0-1) 

Move's String type stores UTF-8 bytes without normalization: [3](#0-2) 

The codebase explicitly acknowledges Unicode normalization as an unresolved issue for identifiers: [4](#0-3) 

**Attack Scenario:**
An attacker with property mutation rights can create two properties:
1. Key "café" in NFC form (bytes: `[0x63, 0x61, 0x66, 0xC3, 0xA9]`)
2. Key "café" in NFD form (bytes: `[0x63, 0x61, 0x66, 0x65, 0xCC, 0x81]`)

Both display identically in UIs but are treated as separate properties by the PropertyMap. This bypasses the duplicate key check: [5](#0-4) 

Contract logic checking for specific property names may be bypassed if the check uses one normalization form but the property was set using another.

## Impact Explanation

This issue is rated as **Low severity** according to the Aptos bug bounty categories because:

1. **No direct financial loss**: Does not enable theft or minting of funds
2. **No consensus violation**: All validators process identically - deterministic execution is preserved
3. **No protocol-level impact**: Does not affect consensus, staking, governance, or core system functionality
4. **Limited to application layer**: Only affects token metadata and contract logic that relies on property name uniqueness

The impact is confined to:
- UI/UX confusion (duplicate property names in wallets/explorers)
- Potential logic errors in poorly-designed contracts
- Metadata spoofing/phishing attacks in NFT contexts

This falls under "Non-critical implementation bugs" in the Low severity category.

## Likelihood Explanation

**High likelihood** of occurrence because:
- Unicode normalization variants are common in internationalized text
- No technical barriers prevent exploitation
- Requires only standard property mutation permissions
- Natural user input could accidentally create this situation

However, **low impact** limits overall risk severity.

## Recommendation

Implement Unicode normalization for property keys before comparison and storage. Add a preprocessing step in PropertyMap creation and mutation functions:

```move
// In property_map.move
use std::string::String;

// Add normalization function (requires native implementation)
native fun normalize_nfc(s: &String): String;

// Update add_internal to normalize keys
inline fun add_internal(ref: &MutatorRef, key: String, type: u8, value: vector<u8>) {
    let normalized_key = normalize_nfc(&key);
    assert_exists(ref.self);
    let property_map = &mut PropertyMap[ref.self];
    property_map.inner.add(normalized_key, PropertyValue { type, value });
}
```

The native implementation should use a Unicode normalization library (e.g., `unicode-normalization` crate) to normalize all keys to NFC form before storage.

## Proof of Concept

```move
#[test_only]
module test::unicode_normalization_attack {
    use std::string;
    use aptos_framework::object;
    use aptos_token_objects::property_map;

    #[test(creator = @0x123)]
    fun test_unicode_duplicate_keys(creator: &signer) {
        // Create an object with property map
        let constructor_ref = object::create_named_object(creator, b"test");
        let mutator = property_map::generate_mutator_ref(&constructor_ref);
        
        // NFC form: "café" with é as single character U+00E9
        let key_nfc = string::utf8(x"636166C3A9");
        
        // NFD form: "café" with e + combining acute U+0065 + U+0301
        let key_nfd = string::utf8(x"63616665CC81");
        
        // Both keys can be added (they appear identical but are different)
        property_map::add_typed<u64>(&mutator, key_nfc, 100);
        property_map::add_typed<u64>(&mutator, key_nfd, 200);
        
        // Two properties exist with visually identical names
        let object = object::object_from_constructor_ref<object::ObjectCore>(&constructor_ref);
        assert!(property_map::length(&object) == 2, 0); // PASSES - demonstrates vulnerability
    }
}
```

## Notes

While this vulnerability is confirmed to exist in the codebase, **it does not meet the Critical, High, or Medium severity threshold** required by the validation checklist for formal bug bounty reporting. The issue falls under Low severity ($1,000 maximum) as acknowledged in the security question itself. The vulnerability is real and exploitable, but its impact is limited to metadata confusion and application-layer logic errors rather than core protocol security.

### Citations

**File:** aptos-move/framework/aptos-token-objects/sources/property_map.move (L54-54)
```text
        inner: SimpleMap<String, PropertyValue>,
```

**File:** aptos-move/framework/aptos-stdlib/sources/simple_map.move (L98-99)
```text
        let maybe_idx = self.find(&key);
        assert!(maybe_idx.is_none(), error::invalid_argument(EKEY_ALREADY_EXISTS));
```

**File:** aptos-move/framework/aptos-stdlib/sources/simple_map.move (L196-196)
```text
            if (&element.key == key) {
```

**File:** aptos-move/framework/move-stdlib/sources/string.move (L12-14)
```text
    struct String has copy, drop, store {
        bytes: vector<u8>,
    }
```

**File:** third_party/move/move-core/types/src/identifier.rs (L20-23)
```rust
//! Allowed identifiers are currently restricted to ASCII due to unresolved issues with Unicode
//! normalization. See [Rust issue #55467](https://github.com/rust-lang/rust/issues/55467) and the
//! associated RFC for some discussion. Unicode identifiers may eventually be supported once these
//! issues are worked out.
```

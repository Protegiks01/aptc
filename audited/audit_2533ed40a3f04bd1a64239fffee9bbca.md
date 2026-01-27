# Audit Report

## Title
Unicode Homograph Attack: Collection Names Allow Visually Identical Impersonation Without Normalization

## Summary
The Aptos token framework (both V1 and V2) does not perform Unicode normalization on collection names or URIs, allowing attackers to create visually identical collections using different Unicode representations (homograph attacks) to impersonate legitimate collections and deceive users.

## Finding Description

The Move `String` type is implemented as a wrapper around `vector<u8>` with UTF-8 validation but **no Unicode normalization**. [1](#0-0) 

When collections are created in Token V1, the `create_collection` function validates only the length of the collection name, not its Unicode normalization form. [2](#0-1) 

The duplicate collection check uses raw byte comparison via table lookup. [3](#0-2) 

Table operations serialize keys using BCS (Binary Canonical Serialization) without normalization. [4](#0-3) 

In Token V2, collection addresses are deterministically derived from the raw UTF-8 bytes of the name. [5](#0-4) 

**Attack Scenario:**
1. Legitimate creator creates collection "Bored Apes" using standard Latin characters
2. Attacker creates collection "Bored Apes" using Cyrillic 'а' (U+0430) instead of Latin 'a' (U+0061), or using NFD decomposition "café" (e + ◌́) instead of NFC "café" (é)
3. Both collections appear visually identical in most UIs
4. Users purchase NFTs from the fake collection, believing it's the legitimate one
5. Attacker profits while users lose funds and the legitimate creator's reputation is damaged

The Move team is explicitly aware of this issue, as documented in the identifier validation code which restricts Move identifiers to ASCII specifically to avoid Unicode normalization problems. [6](#0-5) 

However, this restriction was **not extended** to user-provided String data like collection names and URIs.

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty criteria: "Limited funds loss or manipulation."

Users can suffer financial losses by:
- Purchasing NFTs from fake collections at market prices
- Listing legitimate NFTs in fake collections (if marketplace UI shows wrong collection)
- Brand/reputation damage to legitimate creators

The impact is limited because:
- It requires user interaction (users must choose to transact with the fake collection)
- Sophisticated marketplaces can implement additional validation
- The blockchain state itself remains consistent

## Likelihood Explanation

**Likelihood: HIGH**

- Trivial to execute: Creating Unicode variants requires no technical sophistication
- Wide attack surface: Affects all collection names and URIs in both Token V1 and V2
- Already a known attack vector: Homograph attacks are well-documented in domains like DNS (IDN homograph attacks)
- No protocol-level defenses: The vulnerability exists at the core framework level

However, there is an important caveat: The bug bounty program explicitly excludes "Social engineering, phishing, or key theft" from scope. This vulnerability could be characterized as **protocol-enabled phishing** rather than a pure protocol bug, which may place it outside the bounty scope despite the technical validity of the finding.

## Recommendation

Implement Unicode normalization for collection names and URIs at the protocol level:

1. **Add Unicode normalization to the Move stdlib**: Create a native function that normalizes strings to NFC (Normalization Form Canonical Composition)

2. **Normalize on collection creation**: Modify `create_collection` to normalize the name before storage:
   ```move
   public fun create_collection(
       creator: &signer,
       name: String,
       // ... other params
   ) {
       let normalized_name = string::normalize_nfc(name); // New function
       assert!(normalized_name.length() <= MAX_COLLECTION_NAME_LENGTH, ...);
       // Use normalized_name for all operations
   }
   ```

3. **Alternative: Restrict character set**: Follow the identifier approach and restrict collection names to ASCII-only or a safe Unicode subset

4. **Backwards compatibility**: For existing collections, implement a migration strategy or add validation at the marketplace/indexer layer

## Proof of Concept

```move
#[test(creator1 = @0x111, creator2 = @0x222)]
fun test_unicode_homograph_attack(creator1: &signer, creator2: &signer) {
    use std::string;
    
    account::create_account_for_test(signer::address_of(creator1));
    account::create_account_for_test(signer::address_of(creator2));
    
    // Legitimate collection with Latin 'a' (U+0061)
    let legitimate_name = string::utf8(b"Bored Apes");
    create_collection(
        creator1,
        legitimate_name,
        string::utf8(b"Legitimate collection"),
        string::utf8(b"https://legit.com"),
        1000,
        vector<bool>[false, false, false],
    );
    
    // Fake collection with Cyrillic 'а' (U+0430) - visually identical
    // In UTF-8: Latin 'a' = 0x61, Cyrillic 'а' = 0xD0 0xB0
    let fake_name = string::utf8(b"Bored \xD0\xB0pes"); // Cyrillic а in "Bored Apes"
    
    // This should fail if normalization exists, but succeeds without it
    create_collection(
        creator2,
        fake_name,
        string::utf8(b"Fake collection"),
        string::utf8(b"https://fake.com"),
        1000,
        vector<bool>[false, false, false],
    );
    
    // Both collections exist with visually identical names
    assert!(check_collection_exists(signer::address_of(creator1), legitimate_name), 1);
    assert!(check_collection_exists(signer::address_of(creator2), fake_name), 2);
    
    // But they are treated as different collections in storage
    assert!(legitimate_name != fake_name, 3); // Byte comparison shows they differ
}
```

## Notes

**Important Limitation**: While this finding is technically valid (Unicode normalization does not occur, homograph attacks are possible), it may fall under the "Social engineering, phishing, or key theft" exclusion in the bug bounty program. The vulnerability represents **protocol-enabled phishing** rather than a direct protocol security flaw.

The distinction is that:
- The protocol correctly enforces uniqueness at the byte level
- Visual similarity is a display/UI concern, not a protocol invariant violation
- This requires user deception rather than exploiting a protocol bug

Marketplaces and wallets can mitigate this by implementing their own Unicode normalization, visual similarity detection, or collection verification systems. However, a protocol-level fix would provide stronger security guarantees across the entire ecosystem.

### Citations

**File:** aptos-move/framework/move-stdlib/sources/string.move (L11-14)
```text
    /// A `String` holds a sequence of bytes which is guaranteed to be in utf8 format.
    struct String has copy, drop, store {
        bytes: vector<u8>,
    }
```

**File:** aptos-move/framework/aptos-token/sources/token.move (L1169-1170)
```text
        assert!(name.length() <= MAX_COLLECTION_NAME_LENGTH, error::invalid_argument(ECOLLECTION_NAME_TOO_LONG));
        assert!(uri.length() <= MAX_URI_LENGTH, error::invalid_argument(EURI_TOO_LONG));
```

**File:** aptos-move/framework/aptos-token/sources/token.move (L1187-1190)
```text
        assert!(
            !collection_data.contains(name),
            error::already_exists(ECOLLECTION_ALREADY_EXISTS),
        );
```

**File:** aptos-move/framework/table-natives/src/lib.rs (L531-531)
```rust
    let key_bytes = serialize_key(&function_value_extension, &table.key_layout, &key)?;
```

**File:** aptos-move/framework/aptos-token-objects/sources/collection.move (L367-370)
```text
    public fun create_collection_seed(name: &String): vector<u8> {
        assert!(name.length() <= MAX_COLLECTION_NAME_LENGTH, error::out_of_range(ECOLLECTION_NAME_TOO_LONG));
        *name.bytes()
    }
```

**File:** third_party/move/move-core/types/src/identifier.rs (L20-23)
```rust
//! Allowed identifiers are currently restricted to ASCII due to unresolved issues with Unicode
//! normalization. See [Rust issue #55467](https://github.com/rust-lang/rust/issues/55467) and the
//! associated RFC for some discussion. Unicode identifiers may eventually be supported once these
//! issues are worked out.
```

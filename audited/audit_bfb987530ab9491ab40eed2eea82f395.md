# Audit Report

## Title
Mutability Flags Can Be Changed After Token Creation Through Delete-and-Recreate Attack

## Summary
Token creators can change mutability flags (maximum_mutable, uri_mutable, description_mutable, properties_mutable, royalty_mutable) after initial token creation by burning all tokens to delete the TokenData, then recreating it with the same name but different mutability settings. This violates creator promises about token immutability and affects both on-chain state and the indexer's current_token_datas table.

## Finding Description

The Aptos Token v1 standard allows TokenData to be automatically deleted when all tokens of that type are burned and supply reaches zero. [1](#0-0) 

After deletion, the same token name can be recreated because the creation function only checks that the TokenData doesn't currently exist. [2](#0-1) 

When recreating, the creator can specify completely different mutability flags than the original, as these are set during TokenData initialization. [3](#0-2) 

The TokenMutabilityConfig struct defines five boolean flags that control whether token metadata can be modified. [4](#0-3) 

The indexer's current_token_datas table updates all fields including mutability flags when processing newer transactions, treating the recreated token as an update to the same token_data_id_hash. [5](#0-4) 

**Attack Scenario:**
1. Creator creates "RareArt" token with maximum=100, all mutability flags set to false, and BURNABLE_BY_CREATOR=true
2. Creator announces: "Immutable metadata guaranteed forever!"
3. Users purchase tokens based on this immutability promise
4. Creator burns all 100 tokens using burn_by_creator function [6](#0-5) 
5. TokenData is automatically deleted when supply reaches 0
6. Creator recreates "RareArt" with identical name but all mutability flags set to true
7. Creator can now mutate URI, properties, royalty, and description, breaking original promise

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty program criteria for "State inconsistencies requiring intervention."

**Impacts:**
- **Trust Violation**: Creators can retroactively break immutability promises made to token holders
- **Marketplace Manipulation**: NFTs marketed and sold as "immutable" can later become mutable
- **Metadata Manipulation**: URIs pointing to token metadata can be changed after sale
- **Royalty Manipulation**: Royalty percentages and payee addresses can be modified post-sale
- **Indexer Inconsistency**: The current_token_datas table shows new mutability flags without clear indication of change

The vulnerability does not lead to direct fund loss or consensus violations, but creates state inconsistencies that can be exploited for fraud and requires off-chain intervention to detect and mitigate.

## Likelihood Explanation

**Likelihood: Medium-to-Low**

The attack requires specific preconditions:
- Token must have maximum > 0 (limited supply with tracking)
- All tokens must be burnable (BURNABLE_BY_CREATOR or BURNABLE_BY_OWNER set to true)
- Creator must be able to burn or acquire all tokens in circulation
- Economic cost of burning all tokens must be acceptable to attacker

However, the attack is straightforward to execute once conditions are met, requires no special privileges beyond being the token creator, and leaves limited forensic evidence in the current state (only historical token_datas table shows the change).

## Recommendation

**Primary Fix:** Prevent TokenData recreation after deletion by maintaining a permanent record of token_data_ids that have been created, similar to a tombstone pattern.

Add a new field to Collections struct:
```move
struct Collections has key {
    collection_data: Table<String, CollectionData>,
    token_data: Table<TokenDataId, TokenData>,
    deleted_token_data_ids: Table<TokenDataId, bool>, // New field
    // ... existing event handles
}
```

Modify the create_tokendata function to check the tombstone:
```move
// After line 1284, add:
assert!(
    !collections.deleted_token_data_ids.contains(token_data_id),
    error::invalid_argument(ETOKEN_DATA_PREVIOUSLY_EXISTED),
);
```

When deleting TokenData, mark it in the tombstone table instead of allowing recreation:
```move
// At line 744, before destroy_token_data:
collections.deleted_token_data_ids.add(token_id.token_data_id, true);
```

**Alternative Fix:** Add a version number to TokenData that increments on recreation, making it clear to users and the indexer that the token has been recreated with potentially different properties.

**Indexer Fix:** Update the indexer to track TokenData recreation events and flag tokens that have been deleted and recreated in the current_token_datas table.

## Proof of Concept

```move
#[test_only]
module test_mutability_flag_attack {
    use aptos_token::token;
    use std::string;
    use std::signer;
    use aptos_framework::account;

    #[test(creator = @0xCAFE, holder = @0xBEEF)]
    public fun test_mutability_flag_change_attack(
        creator: signer,
        holder: signer
    ) {
        let creator_addr = signer::address_of(&creator);
        let holder_addr = signer::address_of(&holder);
        
        account::create_account_for_test(creator_addr);
        account::create_account_for_test(holder_addr);

        let collection_name = string::utf8(b"TestCollection");
        let token_name = string::utf8(b"TestToken");
        
        // Step 1: Create collection
        token::create_collection(
            &creator,
            collection_name,
            string::utf8(b"Test"),
            string::utf8(b"https://test.com"),
            100,
            vector[false, false, false], // Collection mutability
        );

        // Step 2: Create token with IMMUTABLE flags and burnable
        let property_keys = vector[string::utf8(b"TOKEN_BURNABLE_BY_CREATOR")];
        let property_values = vector[bcs::to_bytes(&true)];
        let property_types = vector[string::utf8(b"bool")];
        
        token::create_token_script(
            &creator,
            collection_name,
            token_name,
            string::utf8(b"Immutable token"),
            10, // mint 10 tokens
            10, // maximum 10 tokens
            string::utf8(b"https://immutable.com/metadata.json"),
            creator_addr,
            100,
            10,
            vector[false, false, false, false, false], // All IMMUTABLE
            property_keys,
            property_values,
            property_types,
        );

        let token_data_id = token::create_token_data_id(creator_addr, collection_name, token_name);
        let config_before = token::get_tokendata_mutability_config(token_data_id);
        
        // Verify original config is immutable
        assert!(!token::get_token_mutability_uri(&config_before), 1);
        assert!(!token::get_token_mutability_maximum(&config_before), 2);
        
        // Step 3: Burn all tokens to trigger deletion
        let token_id = token::create_token_id_raw(creator_addr, collection_name, token_name, 0);
        token::burn_by_creator(&creator, creator_addr, collection_name, token_name, 0, 10);
        
        // Step 4: Recreate with MUTABLE flags
        token::create_token_script(
            &creator,
            collection_name,
            token_name,
            string::utf8(b"Now mutable!"),
            5,
            5,
            string::utf8(b"https://mutable.com/new_metadata.json"),
            creator_addr,
            100,
            10,
            vector[true, true, true, true, true], // All MUTABLE now!
            property_keys,
            property_values,
            property_types,
        );
        
        // Step 5: Verify mutability flags have changed
        let config_after = token::get_tokendata_mutability_config(token_data_id);
        assert!(token::get_token_mutability_uri(&config_after), 3);
        assert!(token::get_token_mutability_maximum(&config_after), 4);
        
        // Attack successful: same token_data_id now has different mutability flags!
    }
}
```

## Notes

- This vulnerability only affects Token v1 (0x3::token), not the newer object-based Token v2 standard
- The historical token_datas table maintains records of all states, but the current_token_datas table shows only the latest state without indication of recreation
- Tokens with maximum=0 (unlimited supply) are not vulnerable as their TokenData is never deleted
- The vulnerability requires economic feasibility of burning all tokens, limiting practical exploitation

### Citations

**File:** aptos-move/framework/aptos-token/sources/token.move (L217-229)
```text
    /// This config specifies which fields in the TokenData are mutable
    struct TokenMutabilityConfig has copy, store, drop {
        /// control if the token maximum is mutable
        maximum: bool,
        /// control if the token uri is mutable
        uri: bool,
        /// control if the token royalty is mutable
        royalty: bool,
        /// control if the token description is mutable
        description: bool,
        /// control if the property map is mutable
        properties: bool,
    }
```

**File:** aptos-move/framework/aptos-token/sources/token.move (L624-631)
```text
    public entry fun burn_by_creator(
        creator: &signer,
        owner: address,
        collection: String,
        name: String,
        property_version: u64,
        amount: u64,
    ) acquires Collections, TokenStore {
```

**File:** aptos-move/framework/aptos-token/sources/token.move (L742-744)
```text
            // Delete the token_data if supply drops to 0.
            if (token_data.supply == 0) {
                destroy_token_data(collections.token_data.remove(token_id.token_data_id));
```

**File:** aptos-move/framework/aptos-token/sources/token.move (L1282-1285)
```text
        assert!(
            !collections.token_data.contains(token_data_id),
            error::already_exists(ETOKEN_DATA_ALREADY_EXISTS),
        );
```

**File:** aptos-move/framework/aptos-token/sources/token.move (L1299-1309)
```text
        let token_data = TokenData {
            maximum,
            largest_property_version: 0,
            supply: 0,
            uri,
            royalty: create_royalty(royalty_points_numerator, royalty_points_denominator, royalty_payee_address),
            name,
            description,
            default_properties: property_map::new(property_keys, property_values, property_types),
            mutability_config: token_mutate_config,
        };
```

**File:** crates/indexer/src/processors/token_processor.rs (L438-442)
```rust
                    maximum_mutable.eq(excluded(maximum_mutable)),
                    uri_mutable.eq(excluded(uri_mutable)),
                    description_mutable.eq(excluded(description_mutable)),
                    properties_mutable.eq(excluded(properties_mutable)),
                    royalty_mutable.eq(excluded(royalty_mutable)),
```

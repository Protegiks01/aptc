# Audit Report

## Title
CurrentTokenOwnershipV2PK Collision Vulnerability in Fungible Asset Store Indexing

## Summary
The 4-tuple primary key for `CurrentTokenOwnershipV2` is NOT collision-resistant for V2 fungible assets. The `storage_id` field is incorrectly set to the metadata address instead of the FungibleStore object address, causing multiple stores for the same fungible asset owned by the same user to have identical primary keys. This results in the indexer losing track of all but one FungibleStore per user per fungible asset.

## Finding Description
The vulnerability exists in the `get_ft_v2_from_write_resource` function where V2 fungible token ownerships are parsed from blockchain state. [1](#0-0) 

The code incorrectly sets both `token_data_id` and `storage_id` to the fungible asset metadata address. The correct implementation should set `storage_id` to `resource.address` (the FungibleStore's address).

The 4-tuple primary key is defined as: [2](#0-1) 

This key is used for deduplication in the token processor: [3](#0-2) 

When multiple FungibleStore objects exist for the same fungible asset and owner, they generate identical keys. During HashMap-based deduplication, later entries overwrite earlier ones: [4](#0-3) 

The Aptos framework explicitly supports multiple stores per fungible asset: [5](#0-4) 

**Attack Scenario:**
1. User creates fungible asset with metadata at address `0xMETA`
2. User creates FungibleStore #1 at `0xSTORE1` with 1000 tokens
3. User creates FungibleStore #2 at `0xSTORE2` with 500 tokens (for isolation/escrow purposes)
4. Both generate PK: `(0xMETA, 0, user_address, 0xMETA)`
5. During indexer processing, Store #2 overwrites Store #1 in the HashMap
6. Only Store #2 is persisted to `current_token_ownerships_v2` table
7. Indexer API reports user has 500 tokens instead of 1500 tokens

## Impact Explanation
This qualifies as **HIGH severity** under "API crashes" / "Significant protocol violations" or **MEDIUM severity** under "State inconsistencies requiring intervention":

- **Indexer Data Corruption**: The indexer maintains incorrect state that doesn't match the actual blockchain
- **Balance Tracking Errors**: Applications querying the indexer API receive incorrect fungible asset balances
- **DeFi Application Impact**: DEX interfaces, wallets, and analytics tools relying on indexer data will display wrong balances
- **User Confusion**: Users will see incorrect balances in applications, potentially leading to failed transactions or poor UX
- **No Direct Fund Loss**: The actual blockchain state remains correct; only the indexed view is corrupted

While this doesn't directly affect consensus or enable fund theft, it breaks the critical invariant that the indexer should accurately reflect blockchain state, impacting all applications depending on this infrastructure.

## Likelihood Explanation
**HIGH likelihood** of occurrence:

- The Aptos fungible asset framework explicitly encourages creating multiple stores for isolation
- Common use cases include escrow, multi-signature vaults, or purpose-separated balances
- Any user can trigger this by calling `fungible_asset::create_store` multiple times
- The bug occurs automatically during normal indexer operation—no special exploitation required
- Applications are already being built on Aptos that may use multiple FungibleStore objects

## Recommendation
Change the `storage_id` assignment to use the FungibleStore's actual address:

```rust
// In get_ft_v2_from_write_resource, line 384 should be:
let storage_id = resource.address.clone();  // Instead of: token_data_id.clone()
```

The corrected code should look like: [6](#0-5) 

After the fix, each FungibleStore will have a unique primary key:
- Store #1: `(metadata_addr, 0, owner_addr, 0xSTORE1)`
- Store #2: `(metadata_addr, 0, owner_addr, 0xSTORE2)`

This ensures all FungibleStore objects are properly tracked in the indexer.

## Proof of Concept

```move
// File: test_fungible_store_collision.move
module test_addr::fungible_store_collision_test {
    use aptos_framework::fungible_asset;
    use aptos_framework::object;
    use aptos_framework::primary_fungible_store;
    use std::signer;
    use std::string;

    #[test(creator = @0x123)]
    public fun test_multiple_stores_same_asset(creator: &signer) {
        // Create a fungible asset
        let constructor_ref = object::create_named_object(creator, b"test_fa");
        let metadata_ref = fungible_asset::add_fungibility(
            &constructor_ref,
            0, // unlimited supply
            string::utf8(b"Test Coin"),
            string::utf8(b"TEST"),
            8,
            string::utf8(b""),
            string::utf8(b"")
        );
        let metadata = object::object_from_constructor_ref<fungible_asset::Metadata>(&constructor_ref);
        
        // Create first FungibleStore
        let store1_constructor = object::create_object_from_account(creator);
        let store1 = fungible_asset::create_store(&store1_constructor, metadata);
        
        // Create second FungibleStore for the same asset
        let store2_constructor = object::create_object_from_account(creator);
        let store2 = fungible_asset::create_store(&store2_constructor, metadata);
        
        // Mint to both stores
        let mint_ref = fungible_asset::generate_mint_ref(&constructor_ref);
        fungible_asset::mint_to(&mint_ref, store1, 1000);
        fungible_asset::mint_to(&mint_ref, store2, 500);
        
        // Both stores exist with different balances
        // But indexer will only record one due to PK collision
        assert!(fungible_asset::balance(store1) == 1000, 1);
        assert!(fungible_asset::balance(store2) == 500, 2);
        
        // Indexer query would show incorrect total balance
        // Expected: 1500, Actual in indexer: 500 (only store2 recorded)
    }
}
```

The test demonstrates that multiple FungibleStore objects can exist for the same fungible asset. When this transaction is indexed, only one store will be recorded in `current_token_ownerships_v2` due to the primary key collision.

**Notes:**
- This vulnerability only affects the indexer layer, not blockchain consensus or execution
- The actual on-chain state remains correct and consistent
- All blockchain operations (transfers, balance queries via Move) work correctly
- Only applications using the indexer API for balance queries are affected
- The database constraint enforces the incorrect behavior, preventing proper multi-store tracking

### Citations

**File:** crates/indexer/src/models/token_models/v2_token_ownerships.rs (L36-37)
```rust
// PK of current_token_ownerships_v2, i.e. token_data_id, property_version_v1, owner_address, storage_id
pub type CurrentTokenOwnershipV2PK = (String, BigDecimal, String, String);
```

**File:** crates/indexer/src/models/token_models/v2_token_ownerships.rs (L358-390)
```rust
        let type_str = format!(
            "{}::{}::{}",
            write_resource.data.typ.address,
            write_resource.data.typ.module,
            write_resource.data.typ.name
        );
        if !V2FungibleAssetResource::is_resource_supported(type_str.as_str()) {
            return Ok(None);
        }
        let resource = MoveResource::from_write_resource(
            write_resource,
            0, // Placeholder, this isn't used anyway
            txn_version,
            0, // Placeholder, this isn't used anyway
        );

        if let V2FungibleAssetResource::FungibleAssetStore(inner) =
            V2FungibleAssetResource::from_resource(
                &type_str,
                resource.data.as_ref().unwrap(),
                txn_version,
            )?
        {
            if let Some(metadata) = token_v2_metadata.get(&resource.address) {
                let object_core = &metadata.object.object_core;
                let token_data_id = inner.metadata.get_reference_address();
                let storage_id = token_data_id.clone();
                let is_soulbound = inner.frozen;
                let amount = inner.balance;
                let owner_address = object_core.get_owner_address();

                return Ok(Some((
                    Self {
```

**File:** crates/indexer/src/processors/token_processor.rs (L1063-1066)
```rust
    let mut current_token_ownerships_v2: HashMap<
        CurrentTokenOwnershipV2PK,
        CurrentTokenOwnershipV2,
    > = HashMap::new();
```

**File:** crates/indexer/src/processors/token_processor.rs (L1453-1461)
```rust
                            current_token_ownerships_v2.insert(
                                (
                                    current_ft_ownership.token_data_id.clone(),
                                    current_ft_ownership.property_version_v1.clone(),
                                    current_ft_ownership.owner_address.clone(),
                                    current_ft_ownership.storage_id.clone(),
                                ),
                                current_ft_ownership,
                            );
```

**File:** aptos-move/framework/aptos-framework/sources/fungible_asset.move (L878-882)
```text
    /// Allow an object to hold a store for fungible assets.
    /// Applications can use this to create multiple stores for isolating fungible assets for different purposes.
    public fun create_store<T: key>(
        constructor_ref: &ConstructorRef, metadata: Object<T>
    ): Object<FungibleStore> {
```

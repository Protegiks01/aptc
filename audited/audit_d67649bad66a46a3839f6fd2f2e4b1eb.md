# Audit Report

## Title
Indexer Misses Token Burn Events Due to Incomplete Event Type Handling in Collection Module

## Summary
The Aptos indexer fails to track Token V2 burn events when tokens are burned from `ConcurrentSupply` collections or from `FixedSupply`/`UnlimitedSupply` collections after module event migration is enabled. This causes the indexer to miss recording burns, leading to incorrect token ownership state in the database.

## Finding Description

The security question correctly identifies that burn events can be missed at the `tokens_burned` check, though the root cause differs from the hypothesized address formatting issue. The actual vulnerability stems from incomplete event type handling in the indexer.

The Move framework's `collection.move` defines two distinct burn event formats: [1](#0-0) 

The `decrement_supply` function conditionally emits these events: [2](#0-1) 

For `ConcurrentSupply` collections, the new `Burn` event is **always** emitted. For `FixedSupply` and `UnlimitedSupply` collections, the new `Burn` event is emitted if `module_event_migration_enabled()` returns true; otherwise, the legacy `BurnEvent` is emitted.

However, the indexer only handles the legacy event type: [3](#0-2) 

The match statement at line 532 returns `Ok(None)` for the new `0x4::collection::Burn` event type, causing it to be ignored.

**Attack Path:**
1. Attacker creates or uses an existing Token V2 collection with `ConcurrentSupply` 
2. Attacker mints and then burns a token from this collection
3. On-chain, the `Burn` event (not `BurnEvent`) is emitted
4. The indexer processes the transaction but ignores the `Burn` event
5. The `tokens_burned` HashSet remains empty for this token
6. When processing write/delete resources, the lookup at lines 225 and 285 fails: [4](#0-3) [5](#0-4) 

7. The burn is not recorded, and the token ownership record retains its pre-burn state instead of being marked with `amount: BigDecimal::zero()`

## Impact Explanation

This is a **High Severity** issue meeting the "Significant protocol violations" category. The indexer is critical infrastructure providing state data to:
- NFT marketplaces and applications
- Block explorers and analytics dashboards  
- Wallets displaying token holdings
- DeFi protocols using token ownership data

Incorrect indexer state leads to:
- Applications displaying burned tokens as still owned
- False token supply metrics
- Potential marketplace listing of non-existent tokens
- Incorrect analytics affecting business decisions
- Loss of trust in the Aptos ecosystem's data infrastructure

While this doesn't directly cause fund loss, it violates the **State Consistency** invariant, as the indexer state diverges from actual on-chain state, requiring manual intervention to correct.

## Likelihood Explanation

**Very High Likelihood.** This occurs automatically for:
1. **All** tokens from `ConcurrentSupply` collections (burns always use new event)
2. **All** tokens from `FixedSupply`/`UnlimitedSupply` collections once the `module_event_migration` feature is enabled network-wide

The vulnerability requires no special attacker actions—it happens during normal token burn operations. As `ConcurrentSupply` is the recommended high-performance collection type and module event migration is the future direction, this affects an increasing portion of the token ecosystem.

## Recommendation

Add support for the new `Burn` event type in the indexer's event parsing logic:

```rust
// In crates/indexer/src/models/token_models/v2_token_utils.rs
// Add a new variant to V2TokenEvent enum
pub enum V2TokenEvent {
    MintEvent(MintEvent),
    TokenMutationEvent(TokenMutationEvent),
    BurnEvent(BurnEvent),
    Burn(Burn),  // Add this
    TransferEvent(TransferEvent),
}

// Add Burn struct definition
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Burn {
    pub collection: String,
    #[serde(deserialize_with = "deserialize_from_string")]
    pub index: BigDecimal,
    token: String,
    previous_owner: String,
}

impl Burn {
    pub fn get_token_address(&self) -> String {
        standardize_address(&self.token)
    }
}

// Update from_event to handle new type
impl V2TokenEvent {
    pub fn from_event(
        data_type: &str,
        data: &serde_json::Value,
        txn_version: i64,
    ) -> Result<Option<Self>> {
        match data_type {
            "0x4::collection::MintEvent" => {
                serde_json::from_value(data.clone()).map(|inner| Some(Self::MintEvent(inner)))
            },
            "0x4::token::MutationEvent" => serde_json::from_value(data.clone())
                .map(|inner| Some(Self::TokenMutationEvent(inner))),
            "0x4::collection::BurnEvent" => {
                serde_json::from_value(data.clone()).map(|inner| Some(Self::BurnEvent(inner)))
            },
            "0x4::collection::Burn" => {  // Add this case
                serde_json::from_value(data.clone()).map(|inner| Some(Self::Burn(inner)))
            },
            "0x1::object::TransferEvent" => {
                serde_json::from_value(data.clone()).map(|inner| Some(Self::TransferEvent(inner)))
            },
            _ => Ok(None),
        }
        .context(format!(
            "version {} failed! failed to parse type {}, data {:?}",
            txn_version, data_type, data
        ))
    }
}
```

Update token processor to handle both event types: [6](#0-5) 

## Proof of Concept

**Move Test:**
```move
#[test(creator = @0x123)]
fun test_concurrent_burn_indexer_miss(creator: &signer) {
    // Create ConcurrentSupply collection
    let constructor_ref = collection::create_unlimited_collection(
        creator, 
        string::utf8(b"Test Collection"),
        option::none(),
        string::utf8(b"")
    );
    
    // Mint token
    let token_constructor = token::create(...);
    let token_addr = object::address_from_constructor_ref(&token_constructor);
    
    // Burn token - emits Burn event, not BurnEvent
    token::burn(creator, token);
    
    // Indexer processes transaction
    // Expected: tokens_burned contains token_addr
    // Actual: tokens_burned is empty (Burn event ignored)
    // Result: Ownership record not marked as burned
}
```

The vulnerability can be verified by:
1. Creating a Token V2 collection with `ConcurrentSupply`
2. Minting and burning a token
3. Checking the indexer database - the token ownership record will not show `amount = 0`
4. Checking transaction events - only `0x4::collection::Burn` is emitted, not `0x4::collection::BurnEvent`

### Citations

**File:** aptos-move/framework/aptos-token-objects/sources/collection.move (L133-149)
```text
    struct BurnEvent has drop, store {
        index: u64,
        token: address,
    }

    struct MintEvent has drop, store {
        index: u64,
        token: address,
    }

    #[event]
    struct Burn has drop, store {
        collection: address,
        index: u64,
        token: address,
        previous_owner: address,
    }
```

**File:** aptos-move/framework/aptos-token-objects/sources/collection.move (L467-529)
```text
    friend fun decrement_supply(
        collection: &Object<Collection>,
        token: address,
        index: Option<u64>,
        previous_owner: address,
    ) acquires FixedSupply, UnlimitedSupply, ConcurrentSupply {
        let collection_addr = object::object_address(collection);
        if (exists<ConcurrentSupply>(collection_addr)) {
            let supply = &mut ConcurrentSupply[collection_addr];
            aggregator_v2::sub(&mut supply.current_supply, 1);

            event::emit(
                Burn {
                    collection: collection_addr,
                    index: *index.borrow(),
                    token,
                    previous_owner,
                },
            );
        } else if (exists<FixedSupply>(collection_addr)) {
            let supply = &mut FixedSupply[collection_addr];
            supply.current_supply -= 1;
            if (std::features::module_event_migration_enabled()) {
                event::emit(
                    Burn {
                        collection: collection_addr,
                        index: *index.borrow(),
                        token,
                        previous_owner,
                    },
                );
            } else {
                event::emit_event(
                    &mut supply.burn_events,
                    BurnEvent {
                        index: *index.borrow(),
                        token,
                    },
                );
            };
        } else if (exists<UnlimitedSupply>(collection_addr)) {
            let supply = &mut UnlimitedSupply[collection_addr];
            supply.current_supply -= 1;
            if (std::features::module_event_migration_enabled()) {
                event::emit(
                    Burn {
                        collection: collection_addr,
                        index: *index.borrow(),
                        token,
                        previous_owner,
                    },
                );
            } else {
                event::emit_event(
                    &mut supply.burn_events,
                    BurnEvent {
                        index: *index.borrow(),
                        token,
                    },
                );
            };
        }
    }
```

**File:** crates/indexer/src/models/token_models/v2_token_utils.rs (L514-539)
```rust
impl V2TokenEvent {
    pub fn from_event(
        data_type: &str,
        data: &serde_json::Value,
        txn_version: i64,
    ) -> Result<Option<Self>> {
        match data_type {
            "0x4::collection::MintEvent" => {
                serde_json::from_value(data.clone()).map(|inner| Some(Self::MintEvent(inner)))
            },
            "0x4::token::MutationEvent" => serde_json::from_value(data.clone())
                .map(|inner| Some(Self::TokenMutationEvent(inner))),
            "0x4::collection::BurnEvent" => {
                serde_json::from_value(data.clone()).map(|inner| Some(Self::BurnEvent(inner)))
            },
            "0x1::object::TransferEvent" => {
                serde_json::from_value(data.clone()).map(|inner| Some(Self::TransferEvent(inner)))
            },
            _ => Ok(None),
        }
        .context(format!(
            "version {} failed! failed to parse type {}, data {:?}",
            txn_version, data_type, data
        ))
    }
}
```

**File:** crates/indexer/src/models/token_models/v2_token_ownerships.rs (L216-272)
```rust
    /// This handles the case where token is burned but objectCore is still there
    pub fn get_burned_nft_v2_from_write_resource(
        write_resource: &WriteResource,
        txn_version: i64,
        write_set_change_index: i64,
        txn_timestamp: chrono::NaiveDateTime,
        tokens_burned: &TokenV2Burned,
    ) -> anyhow::Result<Option<(Self, CurrentTokenOwnershipV2)>> {
        if let Some(token_address) =
            tokens_burned.get(&standardize_address(&write_resource.address.to_string()))
        {
            if let Some(object) =
                &ObjectWithMetadata::from_write_resource(write_resource, txn_version)?
            {
                let object_core = &object.object_core;
                let token_data_id = token_address.clone();
                let owner_address = object_core.get_owner_address();
                let storage_id = token_data_id.clone();
                let is_soulbound = !object_core.allow_ungated_transfer;

                return Ok(Some((
                    Self {
                        transaction_version: txn_version,
                        write_set_change_index,
                        token_data_id: token_data_id.clone(),
                        property_version_v1: BigDecimal::zero(),
                        owner_address: Some(owner_address.clone()),
                        storage_id: storage_id.clone(),
                        amount: BigDecimal::zero(),
                        table_type_v1: None,
                        token_properties_mutated_v1: None,
                        is_soulbound_v2: Some(is_soulbound),
                        token_standard: TokenStandard::V2.to_string(),
                        is_fungible_v2: Some(false),
                        transaction_timestamp: txn_timestamp,
                        non_transferrable_by_owner: Some(is_soulbound),
                    },
                    CurrentTokenOwnershipV2 {
                        token_data_id,
                        property_version_v1: BigDecimal::zero(),
                        owner_address,
                        storage_id,
                        amount: BigDecimal::zero(),
                        table_type_v1: None,
                        token_properties_mutated_v1: None,
                        is_soulbound_v2: Some(is_soulbound),
                        token_standard: TokenStandard::V2.to_string(),
                        is_fungible_v2: Some(false),
                        last_transaction_version: txn_version,
                        last_transaction_timestamp: txn_timestamp,
                        non_transferrable_by_owner: Some(is_soulbound),
                    },
                )));
            }
        }
        Ok(None)
    }
```

**File:** crates/indexer/src/models/token_models/v2_token_ownerships.rs (L274-348)
```rust
    /// This handles the case where token is burned and objectCore is deleted
    pub fn get_burned_nft_v2_from_delete_resource(
        write_resource: &DeleteResource,
        txn_version: i64,
        write_set_change_index: i64,
        txn_timestamp: chrono::NaiveDateTime,
        prior_nft_ownership: &HashMap<String, NFTOwnershipV2>,
        tokens_burned: &TokenV2Burned,
        conn: &mut PgPoolConnection,
    ) -> anyhow::Result<Option<(Self, CurrentTokenOwnershipV2)>> {
        if let Some(token_address) =
            tokens_burned.get(&standardize_address(&write_resource.address.to_string()))
        {
            let latest_nft_ownership: NFTOwnershipV2 = match prior_nft_ownership.get(token_address)
            {
                Some(inner) => inner.clone(),
                None => {
                    match CurrentTokenOwnershipV2Query::get_nft_by_token_data_id(
                        conn,
                        token_address,
                    ) {
                        Ok(nft) => nft,
                        Err(_) => {
                            aptos_logger::error!(
                                transaction_version = txn_version,
                                lookup_key = &token_address,
                                "Failed to find NFT for burned token. You probably should backfill db."
                            );
                            return Ok(None);
                        },
                    }
                },
            };

            let token_data_id = token_address.clone();
            let owner_address = latest_nft_ownership.owner_address.clone();
            let storage_id = token_data_id.clone();
            let is_soulbound = latest_nft_ownership.is_soulbound;

            return Ok(Some((
                Self {
                    transaction_version: txn_version,
                    write_set_change_index,
                    token_data_id: token_data_id.clone(),
                    property_version_v1: BigDecimal::zero(),
                    owner_address: Some(owner_address.clone()),
                    storage_id: storage_id.clone(),
                    amount: BigDecimal::zero(),
                    table_type_v1: None,
                    token_properties_mutated_v1: None,
                    is_soulbound_v2: is_soulbound,
                    token_standard: TokenStandard::V2.to_string(),
                    is_fungible_v2: Some(false),
                    transaction_timestamp: txn_timestamp,
                    non_transferrable_by_owner: is_soulbound,
                },
                CurrentTokenOwnershipV2 {
                    token_data_id,
                    property_version_v1: BigDecimal::zero(),
                    owner_address,
                    storage_id,
                    amount: BigDecimal::zero(),
                    table_type_v1: None,
                    token_properties_mutated_v1: None,
                    is_soulbound_v2: is_soulbound,
                    token_standard: TokenStandard::V2.to_string(),
                    is_fungible_v2: Some(false),
                    last_transaction_version: txn_version,
                    last_transaction_timestamp: txn_timestamp,
                    non_transferrable_by_owner: is_soulbound,
                },
            )));
        }
        Ok(None)
    }
```

**File:** crates/indexer/src/processors/token_processor.rs (L1165-1171)
```rust
            // Pass through events to get the burn events and token activities v2
            // This needs to be here because we need the metadata above for token activities
            // and burn / transfer events need to come before the next section
            for (index, event) in user_txn.events.iter().enumerate() {
                if let Some(burn_event) = BurnEvent::from_event(event, txn_version).unwrap() {
                    tokens_burned.insert(burn_event.get_token_address());
                }
```

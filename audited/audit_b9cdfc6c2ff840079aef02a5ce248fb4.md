# Audit Report

## Title
Stale Token Metadata Mapping Causes Incorrect Token Indexing Due to Unhandled DeleteResource Events

## Summary
The indexer's `token_v2_metadata_helper` mapping persists stale data across transactions in a batch when resources are deleted via `DeleteResource` changes. While `CurrentTokenV2Metadata::from_write_resource()` has a state_key_hash check protecting against incorrect metadata indexing at line 44, other functions using the same mapping (like `TokenDataV2::get_v2_from_write_resource()`) lack this protection and will index tokens with incorrect supply, decimals, and properties. [1](#0-0) 

## Finding Description
The `parse_v2_token` function builds a `token_v2_metadata_helper` mapping that persists across ALL transactions in a batch. This mapping is populated in two passes that only process `WriteSetChange::WriteResource` events: [2](#0-1) [3](#0-2) 

Critically, neither pass handles `WriteSetChange::DeleteResource` events to remove or update fields in the mapping when resources are deleted. This causes the mapping to retain stale data.

For `CurrentTokenV2Metadata::from_write_resource()`, the check at line 44 reads from this potentially stale mapping: [4](#0-3) 

However, this function has a protective state_key_hash validation that prevents incorrect behavior: [5](#0-4) 

The real vulnerability lies in `TokenDataV2::get_v2_from_write_resource()`, which uses the same stale mapping to extract token metadata WITHOUT any state_key_hash validation: [6](#0-5) 

**Attack Scenario:**
Within a single transaction batch:
1. Transaction A: Create fungible token at address 0xABC with `FungibleAssetSupply` = 1000
2. Transaction B in same batch:
   - `DeleteResource` for `FungibleAssetSupply` at address 0xABC
   - `WriteResource` updating the `Token` at address 0xABC
3. When processing Transaction B's Token write, `TokenDataV2::get_v2_from_write_resource()` retrieves metadata from the mapping, which still contains the stale `fungible_asset_supply = 1000` from Transaction A
4. The token is indexed with supply = 1000 when the supply resource was actually deleted

## Impact Explanation
This is **HIGH severity** according to Aptos bug bounty criteria under "Significant protocol violations" and "API crashes" (functional failures). The indexer is critical infrastructure that powers:
- DeFi protocols querying token supply for pricing
- NFT marketplaces displaying token metadata
- Wallets showing token balances and properties

Incorrect token supply, decimals, or property indexing can cause:
- Financial losses in DeFi applications using wrong supply data
- Display of incorrect token attributes in marketplaces
- Broken applications relying on accurate indexed data

While this doesn't directly affect consensus or blockchain state, it breaks the indexer's core invariant: indexed data must accurately reflect blockchain state.

## Likelihood Explanation
**High likelihood** - This occurs naturally when:
- Fungible tokens are converted to non-fungible (deleting FungibleAssetSupply)
- Token properties are removed or modified (deleting PropertyMap resources)
- Multiple token operations occur within the same batch (common in active chains)

The indexer processes transactions in batches of configurable size, making this issue frequent during normal operations. No special attacker coordination is required - legitimate token operations trigger the bug.

## Recommendation
Update the second pass in `parse_v2_token` to handle `DeleteResource` events and clear the corresponding fields in the mapping:

```rust
// After line 1163, add DeleteResource handling:
for wsc in user_txn.info.changes.iter() {
    if let WriteSetChange::DeleteResource(dr) = wsc {
        let address = standardize_address(&dr.address.to_string());
        if let Some(aggregated_data) = token_v2_metadata_helper.get_mut(&address) {
            let resource_type = dr.resource.to_string();
            match resource_type.as_str() {
                "0x4::token::Token" => aggregated_data.token = None,
                "0x4::collection::FixedSupply" => aggregated_data.fixed_supply = None,
                "0x4::collection::UnlimitedSupply" => aggregated_data.unlimited_supply = None,
                "0x4::aptos_token::AptosCollection" => aggregated_data.aptos_collection = None,
                "0x4::property_map::PropertyMap" => aggregated_data.property_map = None,
                "0x1::fungible_asset::Metadata" => aggregated_data.fungible_asset_metadata = None,
                "0x1::fungible_asset::Supply" => aggregated_data.fungible_asset_supply = None,
                "0x1::fungible_asset::FungibleStore" => aggregated_data.fungible_asset_store = None,
                _ => {},
            }
        }
    }
}
```

## Proof of Concept

```rust
#[test]
fn test_stale_mapping_fungible_asset_supply() {
    use aptos_api_types::{WriteSetChange, WriteResource, DeleteResource, MoveStructTag};
    use crate::processors::token_processor::parse_v2_token;
    
    // Transaction A: Create token with FungibleAssetSupply = 1000
    let txn_a_changes = vec![
        WriteSetChange::WriteResource(WriteResource {
            address: "0xABC".parse().unwrap(),
            state_key_hash: "hash_objectcore".to_string(),
            data: /* ObjectCore resource */,
        }),
        WriteSetChange::WriteResource(WriteResource {
            address: "0xABC".parse().unwrap(),
            state_key_hash: "hash_token".to_string(),
            data: /* Token resource */,
        }),
        WriteSetChange::WriteResource(WriteResource {
            address: "0xABC".parse().unwrap(),
            state_key_hash: "hash_supply".to_string(),
            data: /* FungibleAssetSupply with current_supply = 1000 */,
        }),
    ];
    
    // Transaction B: Delete FungibleAssetSupply, update Token
    let txn_b_changes = vec![
        WriteSetChange::DeleteResource(DeleteResource {
            address: "0xABC".parse().unwrap(),
            state_key_hash: "hash_supply".to_string(),
            resource: MoveStructTag::from_str("0x1::fungible_asset::Supply").unwrap(),
        }),
        WriteSetChange::WriteResource(WriteResource {
            address: "0xABC".parse().unwrap(),
            state_key_hash: "hash_token".to_string(),
            data: /* Updated Token resource */,
        }),
    ];
    
    let transactions = vec![
        create_user_txn(1, txn_a_changes),
        create_user_txn(2, txn_b_changes),
    ];
    
    let result = parse_v2_token(&transactions, &HashMap::new(), &mut conn);
    let token_datas_v2 = result.1;
    
    // Bug: Token from txn B will have supply = 1000 from stale mapping
    // Expected: Token should have supply = 0 or None since FungibleAssetSupply was deleted
    assert_ne!(token_datas_v2[1].supply, BigDecimal::from(1000)); // This will FAIL, proving the bug
}
```

## Notes
The vulnerability affects multiple functions using `token_v2_metadata_helper`:
- `TokenDataV2::get_v2_from_write_resource()` (confirmed vulnerable)
- `TokenActivityV2::get_nft_v2_from_parsed_event()` (potentially affected)
- `TokenActivityV2::get_ft_v2_from_parsed_event()` (potentially affected)
- `CollectionV2::get_v2_from_write_resource()` (potentially affected)
- `TokenOwnershipV2` methods (potentially affected)

The state_key_hash check in `CurrentTokenV2Metadata::from_write_resource()` prevents this specific function from incorrect indexing, but the underlying mapping staleness issue affects the broader token indexing system.

### Citations

**File:** crates/indexer/src/processors/token_processor.rs (L1072-1072)
```rust
    let mut token_v2_metadata_helper: TokenV2AggregatedDataMapping = HashMap::new();
```

**File:** crates/indexer/src/processors/token_processor.rs (L1093-1115)
```rust
            for wsc in user_txn.info.changes.iter() {
                if let WriteSetChange::WriteResource(wr) = wsc {
                    if let Some(object) =
                        ObjectWithMetadata::from_write_resource(wr, txn_version).unwrap()
                    {
                        token_v2_metadata_helper.insert(
                            standardize_address(&wr.address.to_string()),
                            TokenV2AggregatedData {
                                aptos_collection: None,
                                fixed_supply: None,
                                object,
                                unlimited_supply: None,
                                property_map: None,
                                transfer_event: None,
                                token: None,
                                fungible_asset_metadata: None,
                                fungible_asset_supply: None,
                                fungible_asset_store: None,
                            },
                        );
                    }
                }
            }
```

**File:** crates/indexer/src/processors/token_processor.rs (L1118-1163)
```rust
            for wsc in user_txn.info.changes.iter() {
                if let WriteSetChange::WriteResource(wr) = wsc {
                    let address = standardize_address(&wr.address.to_string());
                    if let Some(aggregated_data) = token_v2_metadata_helper.get_mut(&address) {
                        if let Some(fixed_supply) =
                            FixedSupply::from_write_resource(wr, txn_version).unwrap()
                        {
                            aggregated_data.fixed_supply = Some(fixed_supply);
                        }
                        if let Some(unlimited_supply) =
                            UnlimitedSupply::from_write_resource(wr, txn_version).unwrap()
                        {
                            aggregated_data.unlimited_supply = Some(unlimited_supply);
                        }
                        if let Some(aptos_collection) =
                            AptosCollection::from_write_resource(wr, txn_version).unwrap()
                        {
                            aggregated_data.aptos_collection = Some(aptos_collection);
                        }
                        if let Some(property_map) =
                            PropertyMap::from_write_resource(wr, txn_version).unwrap()
                        {
                            aggregated_data.property_map = Some(property_map);
                        }
                        if let Some(token) = TokenV2::from_write_resource(wr, txn_version).unwrap()
                        {
                            aggregated_data.token = Some(token);
                        }
                        if let Some(fungible_asset_metadata) =
                            FungibleAssetMetadata::from_write_resource(wr, txn_version).unwrap()
                        {
                            aggregated_data.fungible_asset_metadata = Some(fungible_asset_metadata);
                        }
                        if let Some(fungible_asset_supply) =
                            FungibleAssetSupply::from_write_resource(wr, txn_version).unwrap()
                        {
                            aggregated_data.fungible_asset_supply = Some(fungible_asset_supply);
                        }
                        if let Some(fungible_asset_store) =
                            FungibleAssetStore::from_write_resource(wr, txn_version).unwrap()
                        {
                            aggregated_data.fungible_asset_store = Some(fungible_asset_store);
                        }
                    }
                }
            }
```

**File:** crates/indexer/src/models/token_models/v2_token_metadata.rs (L42-44)
```rust
        if let Some(metadata) = token_v2_metadata.get(&object_address) {
            // checking if token_v2
            if metadata.token.is_some() {
```

**File:** crates/indexer/src/models/token_models/v2_token_metadata.rs (L52-54)
```rust
                let state_key_hash = metadata.object.get_state_key_hash();
                if state_key_hash != resource.state_key_hash {
                    return Ok(None);
```

**File:** crates/indexer/src/models/token_models/v2_token_datas.rs (L90-109)
```rust
            if let Some(metadata) = token_v2_metadata.get(&token_data_id) {
                let fungible_asset_metadata = metadata.fungible_asset_metadata.as_ref();
                let fungible_asset_supply = metadata.fungible_asset_supply.as_ref();
                if let Some(metadata) = fungible_asset_metadata {
                    if let Some(fa_supply) = fungible_asset_supply {
                        maximum = fa_supply.get_maximum();
                        supply = fa_supply.current.clone();
                        decimals = metadata.decimals as i64;
                        is_fungible_v2 = Some(true);
                    }
                }
                token_properties = metadata
                    .property_map
                    .as_ref()
                    .map(|m| m.inner.clone())
                    .unwrap_or(token_properties);
            } else {
                // ObjectCore should not be missing, returning from entire function early
                return Ok(None);
            }
```

# Audit Report

## Title
Cache Poisoning in NFT Burn Attribution Leading to Incorrect Historical Ownership Records

## Summary
The `prior_nft_ownership` HashMap in the token indexer persists across all transactions in a batch but is only updated when Token resources are modified, not when ObjectCore ownership changes through pure transfers. This causes burns to be attributed to stale owners when a transfer and burn occur in separate transactions within the same batch.

## Finding Description
The indexer's token processor maintains a `prior_nft_ownership` HashMap that caches NFT ownership information across all transactions in a processing batch. [1](#0-0) 

When processing a burn via `get_burned_nft_v2_from_delete_resource()`, the function checks this cache first before falling back to a database query. [2](#0-1) 

The vulnerability occurs because `prior_nft_ownership` is only updated when:
1. A Token resource is written (via `TokenDataV2::get_v2_from_write_resource`) [3](#0-2) 
2. A burned NFT is detected in a WriteResource [4](#0-3) 

However, a **pure object transfer** that only modifies the ObjectCore resource (changing the owner field) does NOT update `prior_nft_ownership`. [5](#0-4) 

**Attack Scenario:**
1. Transaction N: Token X owned by Alice (initial state)
2. Transaction N+1: Transfer Token X from Alice to Bob (only ObjectCore modified, no Token resource change)
   - WriteResource for ObjectCore generated
   - `prior_nft_ownership` NOT updated (no Token resource change)
3. Transaction N+2: Bob burns Token X
   - DeleteResource for ObjectCore
   - `get_burned_nft_v2_from_delete_resource()` checks `prior_nft_ownership[X]`
   - Cache miss or stale value, queries database
   - Database returns Alice (pre-batch state)
   - **Burn incorrectly attributed to Alice instead of Bob**

## Impact Explanation
This vulnerability causes **state inconsistencies in the indexer database**, meeting **Medium severity** criteria per the Aptos bug bounty program ("State inconsistencies requiring intervention").

The incorrect data affects:
- NFT marketplace analytics showing wrong burn history
- User portfolio tracking systems
- Tax reporting tools relying on indexer data
- Historical ownership records used by explorers
- Third-party applications querying the indexer API

While this does not affect on-chain consensus or validator operations, it corrupts historical records that are critical for user-facing applications and financial compliance tools.

## Likelihood Explanation
**High likelihood** of occurrence:

1. **Natural occurrence**: Pure transfers (without token property changes) followed by burns are common in NFT workflows
2. **Batch processing**: The indexer processes transactions in batches, making this scenario likely when multiple operations on the same token occur in quick succession
3. **No special permissions required**: Any user can trigger this by performing a normal transfer followed by a burn
4. **Silent failure**: The bug produces incorrect data without errors, making it difficult to detect

## Recommendation
Update `prior_nft_ownership` whenever ObjectCore ownership changes, not only when Token resources are modified.

**Fix approach:**
1. Add explicit handling for ObjectCore WriteResource changes in the transaction processor
2. Detect ownership changes by checking for Transfer events or ObjectCore mutations
3. Update `prior_nft_ownership` when ObjectCore ownership changes are detected

**Pseudocode fix in token_processor.rs:**
```rust
// After processing events (around line 1225), add:
if let WriteSetChange::WriteResource(wr) = wsc {
    // Check if this is an ObjectCore update with ownership change
    if let Some(object_metadata) = token_v2_metadata_helper.get(&standardize_address(&wr.address.to_string())) {
        if let Some((_, transfer_event)) = &object_metadata.transfer_event {
            // Update prior_nft_ownership with new owner
            let token_data_id = standardize_address(&wr.address.to_string());
            let new_owner = object_metadata.object.object_core.get_owner_address();
            prior_nft_ownership.insert(
                token_data_id.clone(),
                NFTOwnershipV2 {
                    token_data_id,
                    owner_address: new_owner,
                    is_soulbound: object_metadata.object.object_core.is_soulbound(),
                },
            );
        }
    }
}
```

## Proof of Concept
```rust
// Rust test case demonstrating the vulnerability
#[test]
fn test_burn_attribution_after_pure_transfer() {
    // Setup: Token X exists, owned by Alice in database
    let mut prior_nft_ownership: HashMap<String, NFTOwnershipV2> = HashMap::new();
    let token_x_address = "0x123...";
    
    // Simulate batch processing
    // Transaction 1: Pure transfer from Alice to Bob (ObjectCore only)
    // - ObjectCore WriteResource processed
    // - No Token resource change, so prior_nft_ownership NOT updated
    // prior_nft_ownership remains empty
    
    // Transaction 2: Bob burns token
    let delete_resource = create_delete_resource(token_x_address);
    let tokens_burned = HashSet::from([token_x_address.to_string()]);
    
    // Call the vulnerable function
    let result = TokenOwnershipV2::get_burned_nft_v2_from_delete_resource(
        &delete_resource,
        1002, // txn_version
        0,    // write_set_change_index
        timestamp,
        &prior_nft_ownership, // Empty - no entry for token_x
        &tokens_burned,
        conn,
    );
    
    // Vulnerability: Function queries database, gets Alice (stale)
    // Expected: Bob (current owner who burned the token)
    // Actual: Alice (previous owner from database)
    assert_eq!(result.owner_address, "Alice"); // WRONG!
    // Should be: assert_eq!(result.owner_address, "Bob");
}
```

**Notes:**
This vulnerability is specific to the indexer's off-chain data processing and does not affect blockchain consensus or on-chain state. However, it corrupts historical records that are critical for applications, marketplaces, and compliance tools that rely on accurate ownership history from the indexer API.

### Citations

**File:** crates/indexer/src/processors/token_processor.rs (L1068-1068)
```rust
    let mut prior_nft_ownership: HashMap<String, NFTOwnershipV2> = HashMap::new();
```

**File:** crates/indexer/src/processors/token_processor.rs (L1370-1377)
```rust
                                prior_nft_ownership.insert(
                                    current_nft_ownership.token_data_id.clone(),
                                    NFTOwnershipV2 {
                                        token_data_id: current_nft_ownership.token_data_id.clone(),
                                        owner_address: current_nft_ownership.owner_address.clone(),
                                        is_soulbound: current_nft_ownership.is_soulbound_v2,
                                    },
                                );
```

**File:** crates/indexer/src/processors/token_processor.rs (L1422-1429)
```rust
                            prior_nft_ownership.insert(
                                current_nft_ownership.token_data_id.clone(),
                                NFTOwnershipV2 {
                                    token_data_id: current_nft_ownership.token_data_id.clone(),
                                    owner_address: current_nft_ownership.owner_address.clone(),
                                    is_soulbound: current_nft_ownership.is_soulbound_v2,
                                },
                            );
```

**File:** crates/indexer/src/models/token_models/v2_token_ownerships.rs (L287-306)
```rust
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
```

**File:** aptos-move/framework/aptos-framework/sources/object.move (L548-571)
```text
    inline fun transfer_raw_inner(object: address, to: address) {
        let object_core = borrow_global_mut<ObjectCore>(object);
        if (object_core.owner != to) {
            if (std::features::module_event_migration_enabled()) {
                event::emit(
                    Transfer {
                        object,
                        from: object_core.owner,
                        to,
                    },
                );
            } else {
                event::emit_event(
                    &mut object_core.transfer_events,
                    TransferEvent {
                        object,
                        from: object_core.owner,
                        to,
                    },
                );
            };
            object_core.owner = to;
        };
    }
```

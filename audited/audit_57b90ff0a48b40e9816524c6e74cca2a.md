# Audit Report

## Title
Indexer Conflates Temporary Freezing with Permanent Soulbound Status Allowing Transfer Restriction Bypass

## Summary
The Aptos indexer derives the `is_soulbound_v2` field solely from `ObjectCore.allow_ungated_transfer`, treating temporarily frozen tokens (which can be unfrozen by creators) identically to permanently soulbound tokens. This allows token creators to manipulate perceived transferability, deceiving applications and users that rely on indexer data to determine if tokens are permanently non-transferable.

## Finding Description
The vulnerability exists in the semantic interpretation layer between on-chain state and off-chain indexer representation.

**On-Chain Behavior:** [1](#0-0) 

The `ObjectCore` struct contains `allow_ungated_transfer` which controls whether ungated transfers are permitted. [2](#0-1) [3](#0-2) 

These functions allow toggling `allow_ungated_transfer` when a `TransferRef` exists.

**Token Minting Paths:** [4](#0-3) 

Tokens minted via `mint_token_object()` in freezable collections receive a stored `TransferRef`. [5](#0-4) 

Soulbound tokens use `disable_ungated_transfer()` but the `TransferRef` is dropped and never stored.

**Freeze/Unfreeze Functions:** [6](#0-5) [7](#0-6) 

These functions allow creators to toggle transferability for tokens with stored `TransferRef`.

**Indexer Interpretation:** [8](#0-7) 

The indexer derives soulbound status as `is_soulbound = !object_core.allow_ungated_transfer`, making no distinction between:
1. Temporarily frozen tokens (have stored `TransferRef`, reversible)
2. True soulbound tokens (no stored `TransferRef`, irreversible)
3. Untransferable tokens (have `Untransferable` resource, permanent)

**Attack Path:**
1. Creator mints token via `mint_token_object()` in collection with `tokens_freezable_by_creator = true`
2. Token has stored `TransferRef` in its `AptosToken` resource
3. Creator calls `freeze_transfer()` → `allow_ungated_transfer` becomes `false`
4. Indexer marks token as `is_soulbound_v2 = true`, `non_transferrable_by_owner = true`
5. Applications/users query indexer and see token as permanently non-transferable
6. Creator later calls `unfreeze_transfer()` → `allow_ungated_transfer` becomes `true`
7. Token is now transferable, bypassing perceived restrictions

## Impact Explanation
This qualifies as **Medium severity** under the "State inconsistencies requiring intervention" category because:

1. **Semantic Violation**: The indexer provides misleading information about token transferability that applications rely upon for critical business logic
2. **Deception Vector**: Enables creators to manipulate perceived token characteristics for malicious purposes
3. **Application Impact**: DApps making decisions based on soulbound status (marketplaces, credential systems, achievement platforms) could be compromised
4. **Limited Scope**: Does not affect on-chain consensus or directly cause fund loss, but creates exploitable discrepancies between indexer data and on-chain capabilities

## Likelihood Explanation  
**HIGH likelihood** because:
- Common pattern: Many collections enable `tokens_freezable_by_creator` for flexibility
- Low barrier: Any token creator can exploit this with standard API calls
- Undetectable: No on-chain indicator distinguishes reversible vs permanent non-transferability in indexer schema
- Widespread reliance: Most applications use indexer APIs rather than parsing raw on-chain state

## Recommendation
Add distinction in indexer schema between temporary and permanent non-transferability:

```rust
// In v2_token_ownerships.rs
pub struct CurrentTokenOwnershipV2 {
    // Existing fields...
    pub is_soulbound_v2: Option<bool>,
    pub is_frozen_by_creator: Option<bool>,  // NEW: Temporary freeze state
    pub is_permanently_untransferable: Option<bool>, // NEW: Has Untransferable resource
    pub non_transferrable_by_owner: Option<bool>,
}
```

Modify parsing logic to check:
1. Query whether `Untransferable` resource exists at object address (permanent)
2. Check if `AptosToken` has `transfer_ref.is_some()` (indicates freezable/unfreezable)
3. Set `is_soulbound_v2` only for truly permanent cases

Applications should then check `is_permanently_untransferable` for irrevocable soulbound status.

## Proof of Concept

```move
// test_soulbound_bypass.move
#[test(creator = @0x123)]
fun test_freeze_appears_as_soulbound(creator: &signer) {
    // Step 1: Create freezable collection
    aptos_token::create_collection(
        creator,
        string::utf8(b"Test Collection"),
        1000,
        string::utf8(b"Test"),
        string::utf8(b"uri"),
        false, false, false, false, false, false, false,
        false,
        true,  // tokens_freezable_by_creator = true
        0, 1
    );
    
    // Step 2: Mint token (gets TransferRef stored)
    let token = aptos_token::mint_token_object(
        creator,
        string::utf8(b"Test Collection"),
        string::utf8(b"desc"),
        string::utf8(b"Token"),
        string::utf8(b"uri"),
        vector[], vector[], vector[]
    );
    
    // Step 3: Token is transferable
    assert!(object::ungated_transfer_allowed(token), 0);
    // Indexer would show: is_soulbound_v2 = false
    
    // Step 4: Freeze token
    aptos_token::freeze_transfer(creator, token);
    
    // Step 5: Token appears non-transferable
    assert!(!object::ungated_transfer_allowed(token), 1);
    // Indexer would show: is_soulbound_v2 = true <-- MISLEADING
    
    // Step 6: Unfreeze token - BYPASS
    aptos_token::unfreeze_transfer(creator, token);
    
    // Step 7: Token is transferable again
    assert!(object::ungated_transfer_allowed(token), 2);
    // Indexer would show: is_soulbound_v2 = false
    // But applications may have cached the "soulbound" state!
}
```

**Notes**
The core blockchain is functioning as designed. The vulnerability is in the indexer's semantic interpretation that applications depend upon for security-critical decisions about token transferability.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/object.move (L98-108)
```text
    struct ObjectCore has key {
        /// Used by guid to guarantee globally unique objects and create event streams
        guid_creation_num: u64,
        /// The address (object or account) that owns this object
        owner: address,
        /// Object transferring is a common operation, this allows for disabling and enabling
        /// transfers bypassing the use of a TransferRef.
        allow_ungated_transfer: bool,
        /// Emitted events upon transferring of ownership.
        transfer_events: event::EventHandle<TransferEvent>,
    }
```

**File:** aptos-move/framework/aptos-framework/sources/object.move (L445-448)
```text
    public fun disable_ungated_transfer(self: &TransferRef) acquires ObjectCore {
        let object = borrow_global_mut<ObjectCore>(self.self);
        object.allow_ungated_transfer = false;
    }
```

**File:** aptos-move/framework/aptos-framework/sources/object.move (L459-463)
```text
    public fun enable_ungated_transfer(self: &TransferRef) acquires ObjectCore {
        assert!(!exists<Untransferable>(self.self), error::permission_denied(EOBJECT_NOT_TRANSFERRABLE));
        let object = borrow_global_mut<ObjectCore>(self.self);
        object.allow_ungated_transfer = true;
    }
```

**File:** aptos-move/framework/aptos-token-objects/sources/aptos_token.move (L206-213)
```text
        // If tokens are freezable, add a transfer ref to be able to freeze transfers
        let freezable_by_creator = are_collection_tokens_freezable(collection);
        if (freezable_by_creator) {
            let aptos_token_addr = object::address_from_constructor_ref(&constructor_ref);
            let aptos_token = &mut AptosToken[aptos_token_addr];
            let transfer_ref = object::generate_transfer_ref(&constructor_ref);
            aptos_token.transfer_ref.fill(transfer_ref);
        };
```

**File:** aptos-move/framework/aptos-token-objects/sources/aptos_token.move (L264-272)
```text
        );

        let transfer_ref = object::generate_transfer_ref(&constructor_ref);
        let linear_transfer_ref = object::generate_linear_transfer_ref(&transfer_ref);
        object::transfer_with_ref(linear_transfer_ref, soul_bound_to);
        object::disable_ungated_transfer(&transfer_ref);

        object::object_from_constructor_ref(&constructor_ref)
    }
```

**File:** aptos-move/framework/aptos-token-objects/sources/aptos_token.move (L397-405)
```text
    public entry fun freeze_transfer<T: key>(creator: &signer, token: Object<T>) acquires AptosCollection, AptosToken {
        let aptos_token = authorized_borrow(&token, creator);
        assert!(
            are_collection_tokens_freezable(token::collection_object(token))
                && aptos_token.transfer_ref.is_some(),
            error::permission_denied(EFIELD_NOT_MUTABLE),
        );
        object::disable_ungated_transfer(aptos_token.transfer_ref.borrow());
    }
```

**File:** aptos-move/framework/aptos-token-objects/sources/aptos_token.move (L407-418)
```text
    public entry fun unfreeze_transfer<T: key>(
        creator: &signer,
        token: Object<T>
    ) acquires AptosCollection, AptosToken {
        let aptos_token = authorized_borrow(&token, creator);
        assert!(
            are_collection_tokens_freezable(token::collection_object(token))
                && aptos_token.transfer_ref.is_some(),
            error::permission_denied(EFIELD_NOT_MUTABLE),
        );
        object::enable_ungated_transfer(aptos_token.transfer_ref.borrow());
    }
```

**File:** crates/indexer/src/models/token_models/v2_token_ownerships.rs (L131-131)
```rust
        let is_soulbound = !object_core.allow_ungated_transfer;
```

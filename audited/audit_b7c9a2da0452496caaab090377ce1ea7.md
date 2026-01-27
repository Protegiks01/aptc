# Audit Report

## Title
Front-Running Royalty Manipulation Enables Theft of Marketplace Payments

## Summary
Token creators can exploit a timing vulnerability to redirect marketplace royalty payments by calling `mutate_tokendata_royalty` immediately before purchase transactions complete. The vulnerability arises because marketplaces compute royalty information at purchase time rather than listing time, reading mutable state that creators can change arbitrarily.

## Finding Description

The Aptos token framework allows creators to modify royalty payee addresses at any time through the `mutate_tokendata_royalty` function, while marketplace purchase flows retrieve royalty information dynamically at payment time. This creates a front-running vulnerability where creators can redirect royalty payments intended for legitimate beneficiaries.

**Attack Flow:**

1. Token creator mints a token with `royalty.payee_address = 0xLEGITIMATE_BENEFICIARY` and `mutability_config.royalty = true`
2. Token is sold to a secondary owner who lists it on a marketplace for 10,000 APT
3. When a purchase transaction enters the mempool, the creator monitors for it
4. Creator front-runs by submitting `mutate_tokendata_royalty` transaction with `new_royalty.payee_address = 0xATTACKER_CONTROLLED`
5. Purchase completes, calling `complete_purchase` which invokes `listing::compute_royalty`
6. `compute_royalty` reads current TokenData state via `tokenv1::get_royalty(token_id)` → `get_tokendata_royalty` [1](#0-0) 
7. Function returns the NEWLY CHANGED royalty from live storage [2](#0-1) 
8. Royalty payment of (e.g.) 500 APT goes to attacker's address instead of legitimate beneficiary

**Root Cause Analysis:**

The marketplace `compute_royalty` function retrieves royalty data at purchase time: [3](#0-2) 

This data is read from the token's current mutable TokenData state, not from an immutable snapshot at listing time. The `mutate_tokendata_royalty` function only verifies the caller is the creator and royalty is mutable, with no checks for pending sales: [4](#0-3) 

When a purchase executes, the royalty is extracted first and sent to the payee address retrieved at that moment: [5](#0-4) 

The creator authorization check only validates the signer is the token creator with no consideration for timing or active listings: [6](#0-5) 

## Impact Explanation

**Severity: Medium to High**

This vulnerability enables **theft of royalty payments** which constitutes "Limited funds loss or manipulation" (Medium severity per Aptos bug bounty). However, the systemic nature across all marketplace transactions could elevate this to High severity.

**Quantified Impact:**
- **Per-transaction theft**: 0-100% of royalty amount (typically 2.5-10% of sale price)
- **Example**: 10,000 APT sale with 5% royalty = 500 APT stolen per attack
- **Scale**: Affects every marketplace using the standard token framework pattern
- **Victim**: Legitimate royalty beneficiaries (artists, creators, DAOs)

The vulnerability breaks the economic security guarantee that royalty payments reach their designated recipients. While not affecting consensus or validator operations, it represents systematic theft of user funds through protocol-level manipulation.

## Likelihood Explanation

**Likelihood: High**

The attack is highly feasible because:

1. **Low Barrier**: Only requires being a token creator with mutable royalty configuration
2. **Observable**: Purchase transactions are visible in mempool before execution
3. **Timing**: Creator can submit mutation transaction with higher gas to ensure ordering
4. **No Detection**: No on-chain mechanism alerts or prevents the attack
5. **Economic Incentive**: Direct financial gain proportional to sale price

Factors increasing likelihood:
- MEV infrastructure enables sophisticated transaction ordering
- Multiple marketplace implementations follow the vulnerable pattern
- No time-locks or cooling periods on royalty changes
- Attacks are reversible (change payee back after theft) making them harder to detect

The only deterrent is reputational damage, which is ineffective for pseudonymous creators or those executing exit scams.

## Recommendation

**Short-term Fix (Marketplace Layer):**

Marketplaces should snapshot royalty information at listing creation time and enforce that snapshot during payment:

```move
struct FixedPriceListing<phantom CoinType> has key {
    price: u64,
    // Add royalty snapshot
    royalty_snapshot: Option<RoyaltySnapshot>,
}

struct RoyaltySnapshot has store, copy, drop {
    payee_address: address,
    numerator: u64,
    denominator: u64,
}

// At listing creation, capture current royalty
fun init_fixed_price_internal<CoinType>(...) {
    let royalty_snapshot = if (token_has_royalty(...)) {
        let (payee, num, denom) = get_current_royalty(...);
        option::some(RoyaltySnapshot { payee_address: payee, numerator: num, denominator: denom })
    } else {
        option::none()
    };
    // Store snapshot in listing
}

// At purchase, use snapshot instead of live data
```

**Long-term Fix (Framework Layer):**

Add time-lock or notification mechanism to royalty mutations:

```move
public fun mutate_tokendata_royalty(
    creator: &signer, 
    token_data_id: TokenDataId, 
    royalty: Royalty
) acquires Collections {
    // Existing checks...
    assert!(token_data.mutability_config.royalty, EFIELD_NOT_MUTABLE);
    
    // NEW: Add time-lock delay
    let current_time = timestamp::now_seconds();
    if (option::is_some(&token_data.royalty_change_pending)) {
        let pending = option::borrow(&token_data.royalty_change_pending);
        assert!(current_time >= pending.effective_time, EROYALTY_CHANGE_PENDING);
    };
    
    // Schedule change for future (e.g., 7 days)
    token_data.royalty_change_pending = option::some(PendingRoyaltyChange {
        new_royalty: royalty,
        effective_time: current_time + ROYALTY_CHANGE_DELAY,
    });
    
    // Emit warning event
    token_event_store::emit_royalty_change_scheduled_event(...);
}
```

## Proof of Concept

```move
#[test(aptos_framework = @0x1, marketplace = @0x111, creator = @0x222, seller = @0x333, buyer = @0x444, attacker = @0x555)]
fun test_royalty_front_running_attack(
    aptos_framework: &signer,
    marketplace: &signer,
    creator: &signer,
    seller: &signer,
    buyer: &signer,
    attacker: &signer,
) {
    // Setup: Initialize accounts with APT
    test_utils::setup(aptos_framework, marketplace, seller, buyer);
    
    // 1. Creator mints token with legitimate royalty payee
    let creator_addr = signer::address_of(creator);
    let collection = string::utf8(b"Test Collection");
    let token_name = string::utf8(b"Test Token");
    
    tokenv1::create_collection_script(
        creator,
        collection,
        string::utf8(b"Test"),
        string::utf8(b"https://test.com"),
        1,
        vector[true, true, true], // All mutable
    );
    
    tokenv1::create_token_script(
        creator,
        collection,
        token_name,
        string::utf8(b"Test Token"),
        1,
        1,
        string::utf8(b"https://test.com/token"),
        creator_addr, // Initial legitimate payee
        100, // 5% royalty (5/100)
        5,
        vector[true, true, true, true, true, true], // All mutable including royalty
        vector[],
        vector[],
        vector[],
    );
    
    // 2. Transfer token to seller
    tokenv1::transfer_with_opt_in(creator, creator_addr, collection, token_name, 0, signer::address_of(seller), 1);
    
    // 3. Seller lists token on marketplace
    let fee_schedule = test_utils::fee_schedule(marketplace);
    let token_container = listing::create_tokenv1_container(seller, creator_addr, collection, token_name, 0);
    let listing = coin_listing::init_fixed_price_internal<AptosCoin>(
        seller,
        object::convert(token_container),
        fee_schedule,
        timestamp::now_seconds(),
        10000, // 10,000 APT price
    );
    
    // Verify initial royalty payee is creator
    let (initial_payee, initial_royalty) = listing::compute_royalty(listing, 10000);
    assert!(initial_payee == creator_addr, 1);
    assert!(initial_royalty == 500, 2); // 5% of 10000 = 500 APT
    
    // 4. ATTACK: Creator front-runs purchase by changing payee to attacker
    let attacker_addr = signer::address_of(attacker);
    let token_data_id = tokenv1::create_token_data_id(creator_addr, collection, token_name);
    let malicious_royalty = tokenv1::create_royalty(5, 100, attacker_addr);
    tokenv1::mutate_tokendata_royalty(creator, token_data_id, malicious_royalty);
    
    // 5. Buyer purchases - royalty now goes to attacker!
    let buyer_initial_balance = coin::balance<AptosCoin>(signer::address_of(buyer));
    let attacker_initial_balance = coin::balance<AptosCoin>(attacker_addr);
    
    coin_listing::purchase<AptosCoin>(buyer, listing);
    
    // 6. VERIFY ATTACK SUCCESS: Attacker received the royalty payment
    let attacker_final_balance = coin::balance<AptosCoin>(attacker_addr);
    let stolen_royalty = attacker_final_balance - attacker_initial_balance;
    
    assert!(stolen_royalty == 500, 3); // Attacker stole 500 APT royalty
    assert!(coin::balance<AptosCoin>(creator_addr) == 10000, 4); // Creator got nothing
}
```

## Notes

This vulnerability is architectural - it stems from the interaction between the token framework's mutable state design and marketplace implementations that read state dynamically. While the `mutability_config.royalty` flag is intentional, the lack of time-locks or listing-awareness enables timing attacks.

The RoyaltyMutateEvent type definition [7](#0-6)  tracks mutations for off-chain indexing but provides no on-chain protection.

Any marketplace following the standard pattern from the examples is vulnerable. Third-party marketplaces should implement royalty snapshots at listing time until framework-level protections are added.

### Citations

**File:** aptos-move/framework/aptos-token/sources/token.move (L831-850)
```text
    public fun mutate_tokendata_royalty(creator: &signer, token_data_id: TokenDataId, royalty: Royalty) acquires Collections {
        assert_tokendata_exists(creator, token_data_id);

        let all_token_data = &mut Collections[token_data_id.creator].token_data;
        let token_data = all_token_data.borrow_mut(token_data_id);
        assert!(token_data.mutability_config.royalty, error::permission_denied(EFIELD_NOT_MUTABLE));

        token_event_store::emit_token_royalty_mutate_event(
            creator,
            token_data_id.collection,
            token_data_id.name,
            token_data.royalty.royalty_points_numerator,
            token_data.royalty.royalty_points_denominator,
            token_data.royalty.payee_address,
            royalty.royalty_points_numerator,
            royalty.royalty_points_denominator,
            royalty.payee_address
        );
        token_data.royalty = royalty;
    }
```

**File:** aptos-move/framework/aptos-token/sources/token.move (L1576-1579)
```text
    public fun get_royalty(token_id: TokenId): Royalty acquires Collections {
        let token_data_id = token_id.token_data_id;
        get_tokendata_royalty(token_data_id)
    }
```

**File:** aptos-move/framework/aptos-token/sources/token.move (L1662-1670)
```text
    public fun get_tokendata_royalty(token_data_id: TokenDataId): Royalty acquires Collections {
        let creator_address = token_data_id.creator;
        assert!(exists<Collections>(creator_address), error::not_found(ECOLLECTIONS_NOT_PUBLISHED));
        let all_token_data = &Collections[creator_address].token_data;
        assert!(all_token_data.contains(token_data_id), error::not_found(ETOKEN_DATA_NOT_PUBLISHED));

        let token_data = all_token_data.borrow(token_data_id);
        token_data.royalty
    }
```

**File:** aptos-move/framework/aptos-token/sources/token.move (L1853-1859)
```text
    fun assert_tokendata_exists(creator: &signer, token_data_id: TokenDataId) acquires Collections {
        let creator_addr = token_data_id.creator;
        assert!(signer::address_of(creator) == creator_addr, error::permission_denied(ENO_MUTATE_CAPABILITY));
        assert!(exists<Collections>(creator_addr), error::not_found(ECOLLECTIONS_NOT_PUBLISHED));
        let all_token_data = &Collections[creator_addr].token_data;
        assert!(all_token_data.contains(token_data_id), error::not_found(ETOKEN_DATA_NOT_PUBLISHED));
    }
```

**File:** aptos-move/move-examples/marketplace/sources/listing.move (L244-274)
```text
    public fun compute_royalty(
        object: Object<Listing>,
        amount: u64,
    ): (address, u64) acquires Listing, TokenV1Container {
        let listing = borrow_listing(object);
        let obj_addr = object::object_address(&listing.object);
        if (exists<TokenV1Container>(obj_addr)) {
            let token_container = borrow_global<TokenV1Container>(obj_addr);
            let token_id = tokenv1::get_token_id(&token_container.token);
            let royalty = tokenv1::get_royalty(token_id);

            let payee_address = tokenv1::get_royalty_payee(&royalty);
            let numerator = tokenv1::get_royalty_numerator(&royalty);
            let denominator = tokenv1::get_royalty_denominator(&royalty);
            let royalty_amount = bounded_percentage(amount, numerator, denominator);
            (payee_address, royalty_amount)
        } else {
            let royalty = tokenv2::royalty(listing.object);
            if (option::is_some(&royalty)) {
                let royalty = option::destroy_some(royalty);
                let payee_address = royalty::payee_address(&royalty);
                let numerator = royalty::numerator(&royalty);
                let denominator = royalty::denominator(&royalty);

                let royalty_amount = bounded_percentage(amount, numerator, denominator);
                (payee_address, royalty_amount)
            } else {
                (@0x0, 0)
            }
        }
    }
```

**File:** aptos-move/move-examples/marketplace/sources/coin_listing.move (L485-524)
```text
    inline fun complete_purchase<CoinType>(
        completer: &signer,
        purchaser_addr: address,
        object: Object<Listing>,
        coins: Coin<CoinType>,
        type: String,
    ) {
        let token_metadata = listing::token_metadata(object);

        let price = coin::value(&coins);
        let (royalty_addr, royalty_charge) = listing::compute_royalty(object, price);
        let (seller, fee_schedule) = listing::close(completer, object, purchaser_addr);

        // Take royalty first
        if (royalty_charge != 0) {
            let royalty = coin::extract(&mut coins, royalty_charge);
            aptos_account::deposit_coins(royalty_addr, royalty);
        };

        // Take commission of what's left, creators get paid first
        let commission_charge = fee_schedule::commission(fee_schedule, price);
        let actual_commission_charge = math64::min(coin::value(&coins), commission_charge);
        let commission = coin::extract(&mut coins, actual_commission_charge);
        aptos_account::deposit_coins(fee_schedule::fee_address(fee_schedule), commission);

        // Seller gets what is left
        aptos_account::deposit_coins(seller, coins);

        events::emit_listing_filled(
            fee_schedule,
            type,
            object::object_address(&object),
            seller,
            purchaser_addr,
            price,
            commission_charge,
            royalty_charge,
            token_metadata,
        );
    }
```

**File:** types/src/account_config/events/royalty_mutate_event.rs (L16-27)
```rust
#[derive(Debug, Deserialize, Serialize)]
pub struct RoyaltyMutateEvent {
    creator: AccountAddress,
    collection: String,
    token: String,
    old_royalty_numerator: u64,
    old_royalty_denominator: u64,
    old_royalty_payee_addr: AccountAddress,
    new_royalty_numerator: u64,
    new_royalty_denominator: u64,
    new_royalty_payee_addr: AccountAddress,
}
```

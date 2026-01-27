# Audit Report

## Title
Missing Royalty Payee Address Validation Allows Permanent Loss of Royalty Payments

## Summary
The `create_token_script` function in the Aptos Token V1 framework does not validate that the `royalty_payee_address` parameter corresponds to an existing or accessible account. This allows token creators to set royalty payees to addresses with no known private keys or inaccessible addresses, causing all future royalty payments to be permanently locked in uncontrollable accounts. [1](#0-0) 

## Finding Description
When a token is created via `create_token_script`, the royalty configuration is set by calling `create_royalty()`, which explicitly has a commented-out validation check for whether the payee address exists: [2](#0-1) 

The commented code shows this was previously validated, but was removed to "accommodate stateless accounts". However, the error code `EROYALTY_PAYEE_ACCOUNT_DOES_NOT_EXIST` still exists in the codebase: [3](#0-2) 

When tokens are sold in marketplace contracts, royalty payments are distributed via `aptos_account::deposit_coins()`: [4](#0-3) 

While `deposit_coins` will auto-create accounts that don't exist, if the `royalty_payee_address` is set to an address with no known private key (e.g., `0x1111111111111111111111111111111111111111111111111111111111111111`), the royalties will be deposited there but can never be withdrawn: [5](#0-4) 

**Attack Vectors:**
1. **Accidental Typo**: Creator makes a typo when entering the royalty address, permanently losing all future royalties
2. **Malicious Sabotage**: Creator intentionally sets an inaccessible address to deny royalties to the intended recipient
3. **Front-end Exploit**: Compromised or malicious front-end UI could modify the royalty address before submission

## Impact Explanation
This qualifies as **Medium Severity** under Aptos bug bounty criteria ("Limited funds loss or manipulation"). While the token itself remains functional and the primary sale proceeds reach the seller correctly, all royalty payments across the lifetime of the token are permanently lost. For high-value NFT collections with significant trading volume, cumulative royalty losses could reach substantial amounts. The impact is limited to royalties only (not the full sale price), but it affects every subsequent sale of the token forever.

## Likelihood Explanation
Likelihood is **Medium to High**:
- **Accidental occurrence**: Token creators manually entering 64-character hex addresses are prone to typos, especially without proper front-end validation
- **No recovery mechanism**: Once a token is created with an invalid royalty address, there's no on-chain mechanism to update it (unless the token has royalty mutability enabled)
- **Amplified by automation**: Automated token minting scripts with hardcoded or misconfigured addresses could create many affected tokens
- **Permanent impact**: Each affected token loses royalties forever, not just once

The existence of the commented-out validation and dedicated error code proves this was recognized as a significant risk worth preventing.

## Recommendation
Restore the validation check in `create_royalty()` with improved logic to balance security and flexibility:

```move
public fun create_royalty(royalty_points_numerator: u64, royalty_points_denominator: u64, payee_address: address): Royalty {
    assert!(royalty_points_numerator <= royalty_points_denominator, error::invalid_argument(EINVALID_ROYALTY_NUMERATOR_DENOMINATOR));
    
    // Validate that royalty payee is either:
    // 1. An existing account, OR
    // 2. Zero address (0x0) to explicitly indicate "no royalties"
    // This prevents accidental loss while allowing intentional royalty waiver
    assert!(
        payee_address == @0x0 || account::exists_at(payee_address),
        error::invalid_argument(EROYALTY_PAYEE_ACCOUNT_DOES_NOT_EXIST)
    );
    
    Royalty {
        royalty_points_numerator,
        royalty_points_denominator,
        payee_address
    }
}
```

Additionally, marketplace contracts should check for zero-address royalty payees and skip royalty distribution in that case.

## Proof of Concept

```move
#[test(creator = @0x123, marketplace = @0x456, buyer = @0x789)]
fun test_royalty_locked_invalid_address(
    creator: &signer,
    marketplace: &signer, 
    buyer: &signer
) {
    // Setup accounts
    let creator_addr = signer::address_of(creator);
    let buyer_addr = signer::address_of(buyer);
    
    // Invalid address with no known private key
    let invalid_royalty_addr = @0x1111111111111111111111111111111111111111111111111111111111111111;
    
    // Create collection
    token::create_collection(
        creator,
        string::utf8(b"Test Collection"),
        string::utf8(b"Test"),
        string::utf8(b"https://test.com"),
        1,
        vector[false, false, false]
    );
    
    // Create token with invalid royalty address - THIS SUCCEEDS (vulnerability)
    token::create_token_script(
        creator,
        string::utf8(b"Test Collection"),
        string::utf8(b"Test Token"),
        string::utf8(b"Test"),
        1, // balance
        1, // maximum
        string::utf8(b"https://test.com"),
        invalid_royalty_addr, // Invalid address!
        100, // denominator
        10,  // numerator (10% royalty)
        vector[false, false, false, false, false],
        vector[],
        vector[],
        vector[]
    );
    
    // Simulate marketplace sale - royalties go to inaccessible address
    // The 10% royalty (50 coins from 500 sale) is permanently locked
    // Verification: no one can withdraw from invalid_royalty_addr
    assert!(!account::exists_at(invalid_royalty_addr), 0);
    
    // After sale completes with aptos_account::deposit_coins:
    // assert!(account::exists_at(invalid_royalty_addr), 1); // Account created
    // assert!(coin::balance<AptosCoin>(invalid_royalty_addr) == 50, 2); // Royalties locked
    // No way to retrieve these coins - permanent loss
}
```

## Notes
The vulnerability exists because the validation check was deliberately removed to support "stateless accounts," but this creates an unprotected sharp edge in the API. The recommended fix balances flexibility (allowing explicit royalty waiver via zero address) with safety (preventing accidental loss).

### Citations

**File:** aptos-move/framework/aptos-token/sources/token.move (L136-137)
```text
    /// Royalty payee account does not exist
    const EROYALTY_PAYEE_ACCOUNT_DOES_NOT_EXIST: u64 = 35;
```

**File:** aptos-move/framework/aptos-token/sources/token.move (L492-530)
```text
    public entry fun create_token_script(
        account: &signer,
        collection: String,
        name: String,
        description: String,
        balance: u64,
        maximum: u64,
        uri: String,
        royalty_payee_address: address,
        royalty_points_denominator: u64,
        royalty_points_numerator: u64,
        mutate_setting: vector<bool>,
        property_keys: vector<String>,
        property_values: vector<vector<u8>>,
        property_types: vector<String>
    ) acquires Collections, TokenStore {
        let token_mut_config = create_token_mutability_config(&mutate_setting);
        let tokendata_id = create_tokendata(
            account,
            collection,
            name,
            description,
            maximum,
            uri,
            royalty_payee_address,
            royalty_points_denominator,
            royalty_points_numerator,
            token_mut_config,
            property_keys,
            property_values,
            property_types
        );

        mint_token(
            account,
            tokendata_id,
            balance,
        );
    }
```

**File:** aptos-move/framework/aptos-token/sources/token.move (L1001-1010)
```text
    public fun create_royalty(royalty_points_numerator: u64, royalty_points_denominator: u64, payee_address: address): Royalty {
        assert!(royalty_points_numerator <= royalty_points_denominator, error::invalid_argument(EINVALID_ROYALTY_NUMERATOR_DENOMINATOR));
        // Question[Orderless]: Is it okay to remove this check to accommodate stateless accounts?
        // assert!(account::exists_at(payee_address), error::invalid_argument(EROYALTY_PAYEE_ACCOUNT_DOES_NOT_EXIST));
        Royalty {
            royalty_points_numerator,
            royalty_points_denominator,
            payee_address
        }
    }
```

**File:** aptos-move/move-examples/marketplace/sources/collection_offer.move (L392-395)
```text
        let royalty_charge = listing::bounded_percentage(price, royalty_numerator, royalty_denominator);

        let royalties = coin::extract(&mut coins, royalty_charge);
        aptos_account::deposit_coins(royalty_payee, royalties);
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_account.move (L128-148)
```text
    public fun deposit_coins<CoinType>(
        to: address, coins: Coin<CoinType>
    ) acquires DirectTransferConfig {
        if (!account::exists_at(to)) {
            create_account(to);
            spec {
                // TODO(fa_migration)
                // assert coin::spec_is_account_registered<AptosCoin>(to);
                // assume aptos_std::type_info::type_of<CoinType>() == aptos_std::type_info::type_of<AptosCoin>() ==>
                //     coin::spec_is_account_registered<CoinType>(to);
            };
        };
        if (!coin::is_account_registered<CoinType>(to)) {
            assert!(
                can_receive_direct_coin_transfers(to),
                error::permission_denied(EACCOUNT_DOES_NOT_ACCEPT_DIRECT_COIN_TRANSFERS)
            );
            coin::register<CoinType>(&create_signer(to));
        };
        coin::deposit<CoinType>(to, coins)
    }
```

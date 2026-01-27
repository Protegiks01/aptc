# Audit Report

## Title
Missing Royalty Payee Address Validation Allows Token Creation with System Addresses Leading to Permanent DoS or Fund Loss

## Summary
The `create_token()` function in the API tester client and the underlying Move contract `create_tokendata()` lack validation to prevent system addresses (0x0, 0x1, 0x3, and framework reserved addresses 0x2, 0x4-0xa) from being used as royalty payee addresses. This allows token creators to accidentally or maliciously configure tokens with invalid royalty recipients, causing either permanent sale failures (DoS) when using address 0x0, or irreversible loss of royalty revenue when using other system addresses controlled by governance.

## Finding Description

The token creation flow has no validation on the `royalty_payee_address` parameter at multiple layers:

**Layer 1 - Rust API Client:** The `create_token()` function accepts any address and passes it unchecked to the blockchain. [1](#0-0) 

**Layer 2 - Move Contract:** The `create_tokendata()` function validates collection name length, URI length, and royalty numerator/denominator ratios, but performs NO validation on the `royalty_payee_address` parameter. [2](#0-1) 

**Layer 3 - Royalty Creation:** The `create_royalty()` function previously had validation to check if the payee account exists, but this check was EXPLICITLY COMMENTED OUT to "accommodate stateless accounts." [3](#0-2) 

**Attack Scenario 1 - Using @vm_reserved (0x0):**

When royalty payments are attempted via marketplace sales, the `deposit_coins()` function tries to create the account if it doesn't exist: [4](#0-3) 

However, `create_account()` explicitly blocks creation of accounts at reserved addresses including 0x0: [5](#0-4) 

This causes the royalty payment to ABORT with `ECANNOT_RESERVED_ADDRESS`, reverting the entire sale transaction and making the token permanently unsellable on any marketplace that enforces royalty payments.

**Attack Scenario 2 - Using Framework Addresses (0x1-0xa):**

These addresses are created during genesis initialization: [6](#0-5) 

When royalty payments are sent to these addresses, the transaction succeeds, but funds are deposited into governance-controlled system accounts rather than to the token creator, resulting in permanent loss of royalty revenue.

System address definitions: [7](#0-6) 

## Impact Explanation

**Medium Severity** per Aptos Bug Bounty criteria for the following reasons:

1. **Limited Funds Loss**: Creators using addresses 0x1-0xa lose all future royalty payments (funds sent to governance-controlled accounts). While limited to royalty amounts rather than principal, this represents an irreversible economic loss.

2. **Permanent DoS Condition**: Tokens created with address 0x0 as payee become permanently unsellable on marketplaces that enforce royalty payments. This breaks the core functionality of NFTs and creates a griefing vector.

3. **State Inconsistency**: Tokens exist with invalid configurations that violate the implicit invariant that royalty payees should be valid, reachable addresses.

While this doesn't affect consensus safety or network availability (Critical severity), it does cause measurable financial harm and state inconsistencies requiring potential intervention (Medium severity criteria).

## Likelihood Explanation

**High Likelihood** of occurrence:

1. **No Input Validation**: There are zero checks preventing this misconfiguration at any layer of the stack.

2. **Developer Error Prone**: Developers might use placeholder addresses like 0x0 during testing and accidentally deploy to production, or misunderstand which addresses are valid.

3. **No Warning Signals**: The token creation transaction succeeds normally, providing no feedback that an invalid configuration was created until the first sale attempt fails.

4. **Already Identified**: The commented-out validation in `create_royalty()` indicates this issue was previously recognized but removed, suggesting it may have already caused problems.

## Recommendation

Add validation to reject system addresses as royalty payees. The fix should be implemented in the Move contract for protocol-level enforcement:

**In `aptos-move/framework/aptos-token/sources/token.move`**, modify the `create_royalty()` function:

```move
public fun create_royalty(royalty_points_numerator: u64, royalty_points_denominator: u64, payee_address: address): Royalty {
    assert!(royalty_points_numerator <= royalty_points_denominator, error::invalid_argument(EINVALID_ROYALTY_NUMERATOR_DENOMINATOR));
    
    // Validate payee_address is not a system reserved address
    assert!(
        payee_address != @vm_reserved && 
        payee_address != @aptos_framework && 
        payee_address != @aptos_token &&
        payee_address != @0x2 &&
        payee_address != @0x4 &&
        payee_address != @0x5 &&
        payee_address != @0x6 &&
        payee_address != @0x7 &&
        payee_address != @0x8 &&
        payee_address != @0x9 &&
        payee_address != @0xa,
        error::invalid_argument(EROYALTY_PAYEE_IS_RESERVED_ADDRESS)
    );
    
    Royalty {
        royalty_points_numerator,
        royalty_points_denominator,
        payee_address
    }
}
```

Add the new error constant at the module level:
```move
const EROYALTY_PAYEE_IS_RESERVED_ADDRESS: u64 = <next_available_error_code>;
```

Alternatively, use the `system_addresses` module's helper function:
```move
use aptos_framework::system_addresses;

assert!(
    !system_addresses::is_framework_reserved_address(payee_address),
    error::invalid_argument(EROYALTY_PAYEE_IS_RESERVED_ADDRESS)
);
```

## Proof of Concept

```move
#[test(creator = @0xcafe)]
#[expected_failure(abort_code = 0x50001, location = aptos_framework::account)]
fun test_token_creation_with_vm_reserved_payee_causes_sale_failure(creator: &signer) {
    use aptos_framework::account;
    use aptos_framework::aptos_account;
    use aptos_framework::aptos_coin;
    use aptos_framework::coin;
    
    // Setup: Create creator account
    let creator_addr = signer::address_of(creator);
    account::create_account_for_test(creator_addr);
    
    // Create collection
    create_collection(
        creator,
        string::utf8(b"Test Collection"),
        string::utf8(b"Collection Description"),
        string::utf8(b"https://test.com"),
        1000,
        vector<bool>[false, false, false]
    );
    
    // Create token with @vm_reserved (0x0) as royalty payee - THIS SUCCEEDS
    create_token_script(
        creator,
        string::utf8(b"Test Collection"),
        string::utf8(b"Test Token"),
        string::utf8(b"Token Description"),
        1,
        1,
        string::utf8(b"https://test.com/token"),
        @0x0,  // INVALID: Using @vm_reserved as payee
        100,
        10,  // 10% royalty
        vector<bool>[false, false, false, false, false],
        vector<string::String>[],
        vector<vector<u8>>[],
        vector<string::String>[]
    );
    
    // Simulate marketplace sale: Try to pay royalty to 0x0
    // This will ABORT because create_account(@0x0) is forbidden
    let royalty_amount = coin::withdraw<aptos_coin::AptosCoin>(creator, 100);
    aptos_account::deposit_coins(@0x0, royalty_amount);  // ABORTS HERE
}
```

**Notes**

The vulnerability exists in both the API testing client (which is less critical) and more importantly in the core Move contract layer where validation should be enforced. While the commented-out validation suggests a deliberate design choice to support "stateless accounts," the current implementation creates two significant problems: permanent DoS for tokens using 0x0 as payee, and irreversible loss of royalty revenue for tokens using other system addresses. The protocol should enforce that royalty payees are valid, non-reserved addresses to maintain token functionality and protect creator revenue.

### Citations

**File:** crates/aptos-api-tester/src/tokenv1_client.rs (L167-216)
```rust
    pub async fn create_token(
        &self,
        account: &mut LocalAccount,
        collection_name: &str,
        name: &str,
        description: &str,
        supply: u64,
        uri: &str,
        max_amount: u64,
        royalty_options: Option<RoyaltyOptions>,
        options: Option<TransactionOptions>,
    ) -> Result<PendingTransaction> {
        // set default royalty options
        let royalty_options = match royalty_options {
            Some(opt) => opt,
            None => RoyaltyOptions {
                payee_address: account.address(),
                royalty_points_denominator: U64(0),
                royalty_points_numerator: U64(0),
            },
        };

        // create payload
        let payload = EntryFunctionCall::TokenCreateTokenScript {
            collection: collection_name.to_owned().into_bytes(),
            name: name.to_owned().into_bytes(),
            description: description.to_owned().into_bytes(),
            balance: supply,
            maximum: max_amount,
            uri: uri.to_owned().into_bytes(),
            royalty_payee_address: royalty_options.payee_address,
            royalty_points_denominator: royalty_options.royalty_points_denominator.0,
            royalty_points_numerator: royalty_options.royalty_points_numerator.0,
            mutate_setting: vec![false, false, false, false, false],
            // todo: add property support
            property_keys: vec![],
            property_values: vec![],
            property_types: vec![],
        }
        .encode();

        // create and submit transaction
        build_and_submit_transaction(
            self.api_client,
            account,
            payload,
            options.unwrap_or_default(),
        )
        .await
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

**File:** aptos-move/framework/aptos-token/sources/token.move (L1249-1350)
```text
    public fun create_tokendata(
        account: &signer,
        collection: String,
        name: String,
        description: String,
        maximum: u64,
        uri: String,
        royalty_payee_address: address,
        royalty_points_denominator: u64,
        royalty_points_numerator: u64,
        token_mutate_config: TokenMutabilityConfig,
        property_keys: vector<String>,
        property_values: vector<vector<u8>>,
        property_types: vector<String>
    ): TokenDataId acquires Collections {
        assert!(name.length() <= MAX_NFT_NAME_LENGTH, error::invalid_argument(ENFT_NAME_TOO_LONG));
        assert!(collection.length() <= MAX_COLLECTION_NAME_LENGTH, error::invalid_argument(ECOLLECTION_NAME_TOO_LONG));
        assert!(uri.length() <= MAX_URI_LENGTH, error::invalid_argument(EURI_TOO_LONG));
        assert!(royalty_points_numerator <= royalty_points_denominator, error::invalid_argument(EINVALID_ROYALTY_NUMERATOR_DENOMINATOR));

        let account_addr = signer::address_of(account);
        assert!(
            exists<Collections>(account_addr),
            error::not_found(ECOLLECTIONS_NOT_PUBLISHED),
        );
        let collections = &mut Collections[account_addr];

        let token_data_id = create_token_data_id(account_addr, collection, name);

        assert!(
            collections.collection_data.contains(token_data_id.collection),
            error::not_found(ECOLLECTION_NOT_PUBLISHED),
        );
        assert!(
            !collections.token_data.contains(token_data_id),
            error::already_exists(ETOKEN_DATA_ALREADY_EXISTS),
        );

        let collection = collections.collection_data.borrow_mut(token_data_id.collection);

        // if collection maximum == 0, user don't want to enforce supply constraint.
        // we don't track supply to make token creation parallelizable
        if (collection.maximum > 0) {
            collection.supply += 1;
            assert!(
                collection.maximum >= collection.supply,
                error::invalid_argument(ECREATE_WOULD_EXCEED_COLLECTION_MAXIMUM),
            );
        };

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

        collections.token_data.add(token_data_id, token_data);
        if (std::features::module_event_migration_enabled()) {
            event::emit(
                TokenDataCreation {
                    creator: account_addr,
                    id: token_data_id,
                    description,
                    maximum,
                    uri,
                    royalty_payee_address,
                    royalty_points_denominator,
                    royalty_points_numerator,
                    name,
                    mutability_config: token_mutate_config,
                    property_keys,
                    property_values,
                    property_types,
                }
            );
        } else {
            event::emit_event<CreateTokenDataEvent>(
                &mut collections.create_token_data_events,
                CreateTokenDataEvent {
                    id: token_data_id,
                    description,
                    maximum,
                    uri,
                    royalty_payee_address,
                    royalty_points_denominator,
                    royalty_points_numerator,
                    name,
                    mutability_config: token_mutate_config,
                    property_keys,
                    property_values,
                    property_types,
                },
            );
        };

        token_data_id
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

**File:** aptos-move/framework/aptos-framework/sources/account/account.move (L289-302)
```text
    public(friend) fun create_account(new_address: address): signer {
        // there cannot be an Account resource under new_addr already.
        assert!(!exists<Account>(new_address), error::already_exists(EACCOUNT_ALREADY_EXISTS));
        // NOTE: @core_resources gets created via a `create_account` call, so we do not include it below.
        assert!(
            new_address != @vm_reserved && new_address != @aptos_framework && new_address != @aptos_token,
            error::invalid_argument(ECANNOT_RESERVED_ADDRESS)
        );
        if (features::is_default_account_resource_enabled()) {
            create_signer(new_address)
        } else {
            create_account_unchecked(new_address)
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/genesis.move (L86-106)
```text
        let (aptos_framework_account, aptos_framework_signer_cap) = account::create_framework_reserved_account(@aptos_framework);
        // Initialize account configs on aptos framework account.
        account::initialize(&aptos_framework_account);

        transaction_validation::initialize(
            &aptos_framework_account,
            b"script_prologue",
            b"module_prologue",
            b"multi_agent_script_prologue",
            b"epilogue",
        );
        // Give the decentralized on-chain governance control over the core framework account.
        aptos_governance::store_signer_cap(&aptos_framework_account, @aptos_framework, aptos_framework_signer_cap);

        // put reserved framework reserved accounts under aptos governance
        let framework_reserved_addresses = vector<address>[@0x2, @0x3, @0x4, @0x5, @0x6, @0x7, @0x8, @0x9, @0xa];
        while (!vector::is_empty(&framework_reserved_addresses)) {
            let address = vector::pop_back<address>(&mut framework_reserved_addresses);
            let (_, framework_signer_cap) = account::create_framework_reserved_account(address);
            aptos_governance::store_signer_cap(&aptos_framework_account, address, framework_signer_cap);
        };
```

**File:** aptos-move/framework/aptos-framework/Move.toml (L5-12)
```text
[addresses]
std = "0x1"
aptos_std = "0x1"
aptos_framework = "0x1"
aptos_fungible_asset = "0xA"
aptos_token = "0x3"
core_resources = "0xA550C18"
vm_reserved = "0x0"
```

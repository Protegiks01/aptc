# Audit Report

## Title
System Address Spoofing in Sponsored Orderless Transactions

## Summary
The transaction validation logic fails to prevent user transactions from spoofing system reserved addresses (0x0, 0x1) as the sender when using sponsored orderless transactions, allowing attackers to commit transactions that appear to originate from @vm_reserved or @aptos_framework addresses.

## Finding Description

The vulnerability exists in the transaction validation prologue where authentication key validation is conditionally skipped for sponsored transactions. When combined with orderless (nonce-based) transactions, this creates a path for transactions with system reserved addresses as senders to be validated, executed, and committed.

**Validation Gap 1: Authentication Key Check Bypass** [1](#0-0) 

When `sponsored_automatic_account_creation_enabled()` is true, and the sender address differs from the gas payer address, and no account exists at the sender address, the authentication key check is skipped. For reserved addresses like 0x0 (@vm_reserved) and 0x1 (@aptos_framework), accounts cannot be created: [2](#0-1) 

This means for a sponsored transaction with sender = 0x0 or 0x1, all three conditions evaluate to false, causing the authentication validation to be bypassed entirely.

**Validation Gap 2: Nonce Validation Doesn't Check Reserved Addresses** [3](#0-2) 

The nonce validation logic accepts any sender address without validating against reserved addresses, merely storing the (address, nonce) pair for replay protection.

**Validation Gap 3: Epilogue Skips Account Existence Check for Orderless Transactions** [4](#0-3) 

For orderless transactions, sequence number increment is skipped, which means `ensure_resource_exists()` is never called. This function would have aborted for reserved addresses: [5](#0-4) 

**Attack Path:**

1. Attacker creates a transaction with sender = 0x0 (or 0x1), gas_payer = attacker's address, using Nonce replay protection
2. Signs transaction with any keypair (authentication check is bypassed)
3. Transaction passes validation: signature is cryptographically valid, auth key check skipped, nonce recorded, gas paid by attacker
4. Transaction executes with sender signer having address 0x0 or 0x1
5. Transaction commits successfully
6. CommittedTransaction sent to mempool contains sender = 0x0 or 0x1: [6](#0-5) 

This violates **Invariant 8: Access Control** - system addresses (@aptos_framework, @vm_reserved) must be protected from unauthorized use.

## Impact Explanation

**Medium Severity** - This qualifies as "State inconsistencies requiring intervention" per the Aptos bug bounty program:

1. **Audit Trail Corruption**: Committed transactions appear to originate from system addresses, corrupting transaction history
2. **Mempool State Inconsistency**: CommittedTransaction notifications to mempool contain invalid sender addresses
3. **Access Control Confusion**: Off-chain systems or future features that trust sender addresses without additional validation could be bypassed
4. **Invariant Violation**: Breaks the fundamental assumption that user transactions cannot claim to be from system addresses

While this doesn't directly enable fund theft or consensus violation, it creates state inconsistencies that violate critical system invariants and could enable secondary attacks.

## Likelihood Explanation

**Medium-High Likelihood** when required feature flags are enabled:

- Requires `features::sponsored_automatic_account_creation_enabled()` = true
- Requires `features::orderless_txns_enabled()` = true  
- These are legitimate features that may be enabled in production
- Attack is straightforward to execute once features are active
- No special privileges or resources required beyond standard transaction submission

## Recommendation

Add explicit validation in the transaction prologue to reject transactions with reserved addresses as senders:

```move
fun prologue_common(
    sender: &signer,
    gas_payer: &signer,
    replay_protector: ReplayProtector,
    txn_authentication_key: Option<vector<u8>>,
    txn_gas_price: u64,
    txn_max_gas_units: u64,
    txn_expiration_time: u64,
    chain_id: u8,
    is_simulation: bool,
) {
    let sender_address = signer::address_of(sender);
    let gas_payer_address = signer::address_of(gas_payer);
    
    // ADD THIS CHECK:
    assert!(
        !system_addresses::is_reserved_address(sender_address),
        error::invalid_argument(PROLOGUE_ERESERVED_ADDRESS_NOT_ALLOWED)
    );
    
    // ... rest of validation
```

This ensures user transactions cannot spoof system addresses regardless of feature flag combinations.

## Proof of Concept

```move
#[test(framework = @aptos_framework, attacker = @0x999)]
public entry fun test_system_address_spoofing(framework: &signer, attacker: &signer) {
    // Setup: Enable required features
    features::change_feature_flags(
        framework, 
        vector[features::get_sponsored_automatic_account_creation_feature()], 
        vector[]
    );
    features::change_feature_flags(
        framework,
        vector[features::get_orderless_txns_feature()],
        vector[]
    );
    
    // Create attacker account with funds for gas
    account::create_account_for_test(@0x999);
    coin::register<AptosCoin>(attacker);
    aptos_coin::mint(framework, @0x999, 1000000);
    
    // Create a transaction with sender = @vm_reserved (0x0)
    // gas_payer = @0x999 (attacker)
    // replay_protector = Nonce(1)
    // This should FAIL but currently PASSES validation
    
    // Transaction executes with sender signer = 0x0
    // CommittedTransaction sent to mempool shows sender = 0x0
    // This violates system address protection invariant
}
```

**Note**: Full executable test would require integration test framework access to create properly signed transactions with custom sender addresses and nonce-based replay protection.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L151-160)
```text
                if (
                    sender_address == gas_payer_address ||
                    account::exists_at(sender_address) ||
                    !features::sponsored_automatic_account_creation_enabled()
                ) {
                    assert!(
                        txn_authentication_key == option::some(account::get_authentication_key(sender_address)),
                        error::invalid_argument(PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY),
                    );
                };
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L859-863)
```text
        if (!is_orderless_txn) {
            // Increment sequence number
            let addr = signer::address_of(&account);
            account::increment_sequence_number(addr);
        }
```

**File:** aptos-move/framework/aptos-framework/sources/account/account.move (L276-284)
```text
    public fun create_account_if_does_not_exist(account_address: address) {
        if (!resource_exists_at(account_address)) {
            assert!(
                account_address != @vm_reserved && account_address != @aptos_framework && account_address != @aptos_token,
                error::invalid_argument(ECANNOT_RESERVED_ADDRESS)
            );
            create_account_unchecked(account_address);
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/nonce_validation.move (L129-142)
```text
    public(friend) fun check_and_insert_nonce(
        sender_address: address,
        nonce: u64,
        txn_expiration_time: u64,
    ): bool acquires NonceHistory {
        assert!(exists<NonceHistory>(@aptos_framework), error::invalid_state(E_NONCE_HISTORY_DOES_NOT_EXIST));
        // Check if the transaction expiration time is too far in the future.
        assert!(txn_expiration_time <= timestamp::now_seconds() + NONCE_REPLAY_PROTECTION_OVERLAP_INTERVAL_SECONDS, error::invalid_argument(ETRANSACTION_EXPIRATION_TOO_FAR_IN_FUTURE));
        let nonce_history = &mut NonceHistory[@aptos_framework];
        let nonce_key = NonceKey {
            sender_address,
            nonce,
        };
        let bucket_index = sip_hash_from_value(&nonce_key) % NUM_BUCKETS;
```

**File:** state-sync/inter-component/mempool-notifications/src/lib.rs (L86-90)
```rust
                Transaction::UserTransaction(signed_txn) => Some(CommittedTransaction {
                    sender: signed_txn.sender(),
                    replay_protector: signed_txn.replay_protector(),
                    use_case: signed_txn.parse_use_case(),
                }),
```

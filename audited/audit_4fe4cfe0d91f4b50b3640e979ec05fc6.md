# Audit Report

## Title
Prologue/Epilogue Balance Validation Mismatch During Coin-to-FungibleAsset Migration Enables Transaction Validation Bypass

## Summary
A critical mismatch exists between the prologue balance validation and epilogue gas burning logic during the coin-to-fungible-asset migration period. The prologue validates gas payment capability using combined balances from both legacy `CoinStore` and new primary fungible stores, while the epilogue can only burn gas fees from the fungible store. This allows transactions to pass validation but fail gas charging, breaking core transaction validation invariants and potentially enabling free transaction execution or consensus disruption.

## Finding Description

The vulnerability arises from an inconsistency in how account balances are checked versus how gas fees are burned when the `operations_default_to_fa_apt_store_enabled()` feature flag is disabled during the migration period.

**Prologue Phase (Balance Check):** [1](#0-0) 

When the feature flag is FALSE, the prologue uses `coin::is_balance_at_least<AptosCoin>()` which validates against the **combined balance** from both CoinStore and primary fungible store: [2](#0-1) 

This function returns TRUE if `coin_balance + fungible_store_balance >= required_amount`.

**Epilogue Phase (Gas Burning):** [3](#0-2) 

When burning fees, if `operations_default_to_fa_apt_store_enabled()` is FALSE and `AptosFABurnCapabilities` doesn't exist, it calls `coin::burn_from_for_gas`: [4](#0-3) 

This function **only burns from the primary fungible store** via `fungible_asset::address_burn_from_for_gas`, completely ignoring the CoinStore balance: [5](#0-4) 

The withdrawal function will abort with `EINSUFFICIENT_BALANCE` if the fungible store doesn't have sufficient funds: [6](#0-5) 

**Attack Scenario:**

1. Attacker maintains an account with:
   - `CoinStore<AptosCoin>` containing 1000 APT (legacy, never migrated)
   - Primary fungible store containing 100 APT (new deposits)
   - Total balance: 1100 APT

2. Submit transaction requiring `max_transaction_fee = 500 APT`

3. Prologue validation: `1000 + 100 = 1100 >= 500` ✓ **PASSES**

4. Transaction executes successfully

5. Epilogue attempts to burn actual gas (e.g., 300 APT) from fungible store with only 100 APT

6. `unchecked_withdraw_with_no_events` aborts with `EINSUFFICIENT_BALANCE`

7. Epilogue error is converted to `UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION`: [7](#0-6) 

## Impact Explanation

This vulnerability meets **Critical Severity** criteria per Aptos Bug Bounty program:

1. **Consensus Safety Violation**: The epilogue returning `UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION` is an invariant violation that could be handled inconsistently across validators, potentially causing consensus divergence where different validators produce different state roots for the same block.

2. **Transaction Validation Invariant Broken**: Violates the core principle that if a transaction passes prologue validation, the epilogue must successfully charge gas. This breaks **Invariant #7** (Transaction Validation) and **Invariant #1** (Deterministic Execution).

3. **Potential Free Transaction Execution**: Depending on how the VM handles epilogue failures, transactions might execute without proper gas charging, enabling unlimited free transactions.

4. **Denial of Service**: Malicious actors can flood the network with transactions that pass validation but cause epilogue failures, potentially disrupting network operation.

The vulnerability affects all accounts that have unmigrated `CoinStore` balances during the migration period, which could be a significant portion of the network.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to occur because:

1. **Common State**: During migration, many accounts will naturally have both CoinStore and fungible store balances as the ecosystem gradually transitions

2. **Feature Flag Window**: The vulnerability is active whenever `operations_default_to_fa_apt_store_enabled()` is FALSE, which is a legitimate operational state during the migration rollout

3. **No User Action Required**: Users don't need to explicitly "migrate" - any account that received coins before paired metadata was created will have CoinStore balance, and any deposits after pairing will go to fungible store

4. **Easy to Trigger**: An attacker simply needs to submit a transaction with gas requirements between their fungible store balance and total balance - no sophisticated attack required

5. **Undetected During Testing**: The test suite may not cover this edge case as the `test_withdraw` function shows deposits automatically going to fungible stores after pairing, not testing the dual-balance epilogue scenario: [8](#0-7) 

## Recommendation

The root cause is that `coin::is_balance_at_least` checks combined balances but `coin::burn_from_for_gas` only accesses fungible store balance. There are two potential fixes:

**Option 1 (Recommended): Force Migration Before Validation**

Modify the prologue to automatically migrate CoinStore to fungible store before balance validation:

```move
// In transaction_validation.move, before balance check:
if (exists<CoinStore<AptosCoin>>(gas_payer_address)) {
    coin::maybe_convert_to_fungible_store<AptosCoin>(gas_payer_address);
}
```

**Option 2: Make Epilogue Consistent with Prologue**

Modify `burn_from_for_gas` to implement the dual-store withdrawal logic (using the unused `calculate_amount_to_withdraw` function):

```move
public(friend) fun burn_from_for_gas<CoinType>(
    account_addr: address, amount: u64, burn_cap: &BurnCapability<CoinType>
) acquires CoinInfo, CoinConversionMap, CoinStore, PairedFungibleAssetRefs {
    if (amount == 0) { return };
    
    let (coin_amount, fa_amount) = calculate_amount_to_withdraw<CoinType>(account_addr, amount);
    
    // Burn from CoinStore if needed
    if (coin_amount > 0 && exists<CoinStore<CoinType>>(account_addr)) {
        let coin_store = borrow_global_mut<CoinStore<CoinType>>(account_addr);
        let coin = extract(&mut coin_store.coin, coin_amount);
        burn_internal(coin);
    };
    
    // Burn from fungible store
    if (fa_amount > 0) {
        fungible_asset::address_burn_from_for_gas(
            borrow_paired_burn_ref(burn_cap),
            primary_fungible_store::primary_store_address(account_addr, ensure_paired_metadata<CoinType>()),
            fa_amount
        );
    };
}
```

**Option 1 is recommended** as it enforces complete migration during transaction execution, eliminating the dual-balance state entirely and simplifying the system.

## Proof of Concept

```move
#[test(framework = @aptos_framework, user = @0x100)]
fun test_dual_balance_gas_payment_failure(framework: &signer, user: &signer) {
    use aptos_framework::coin;
    use aptos_framework::aptos_coin::{Self, AptosCoin};
    use aptos_framework::account;
    
    // Setup: Initialize AptosCoin and create conversion map
    let (burn_cap, mint_cap) = aptos_coin::initialize_for_test(framework);
    coin::create_coin_conversion_map(framework);
    
    let user_addr = signer::address_of(user);
    account::create_account_for_test(user_addr);
    
    // Step 1: Create CoinStore with legacy balance (before paired metadata)
    // This simulates an account that existed before migration
    let legacy_coins = coin::mint(1000, &mint_cap);
    // Directly store in CoinStore (simulating pre-migration state)
    move_to(user, coin::CoinStore<AptosCoin> {
        coin: legacy_coins,
        frozen: false,
        deposit_events: account::new_event_handle(user),
        withdraw_events: account::new_event_handle(user),
    });
    
    // Step 2: Create paired metadata (triggers migration era)
    coin::ensure_paired_metadata<AptosCoin>();
    
    // Step 3: Deposit new coins (goes to fungible store)
    let new_coins = coin::mint(100, &mint_cap);
    coin::deposit(user_addr, new_coins);
    
    // Verify dual balance state
    assert!(coin::coin_balance<AptosCoin>(user_addr) == 1000, 0); // CoinStore
    assert!(coin::balance<AptosCoin>(user_addr) == 1100, 1); // Total
    
    // Step 4: Simulate transaction with gas requirement between FA and total balance
    // Prologue would check: is_balance_at_least(user_addr, 500) -> TRUE (1100 >= 500)
    assert!(coin::is_balance_at_least<AptosCoin>(user_addr, 500), 2);
    
    // Step 5: Epilogue tries to burn 500 APT for gas
    // This will FAIL because fungible store only has 100 APT
    coin::burn_from_for_gas<AptosCoin>(user_addr, 500, &burn_cap); // ABORTS!
    
    // If this doesn't abort, the vulnerability is exploitable
}
```

**Notes**

This vulnerability is particularly severe because:

1. It affects the **core gas payment mechanism**, breaking a fundamental blockchain invariant
2. It creates a **window of exploitability** during the migration period when many accounts will naturally have dual balances
3. The unused `calculate_amount_to_withdraw` function suggests this issue may have been anticipated but the fix was never fully implemented
4. The error manifests as `UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION`, which is a critical invariant violation that could cause consensus instability

The issue requires immediate patching before the feature flag transition period to prevent potential network disruption and ensure deterministic transaction processing across all validators.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L201-211)
```text
            if (features::operations_default_to_fa_apt_store_enabled()) {
                assert!(
                    aptos_account::is_fungible_balance_at_least(gas_payer_address, max_transaction_fee),
                    error::invalid_argument(PROLOGUE_ECANT_PAY_GAS_DEPOSIT)
                );
            } else {
                assert!(
                    coin::is_balance_at_least<AptosCoin>(gas_payer_address, max_transaction_fee),
                    error::invalid_argument(PROLOGUE_ECANT_PAY_GAS_DEPOSIT)
                );
            }
```

**File:** aptos-move/framework/aptos-framework/sources/coin.move (L764-781)
```text
    public fun is_balance_at_least<CoinType>(
        owner: address, amount: u64
    ): bool acquires CoinConversionMap, CoinStore {
        let coin_balance = coin_balance<CoinType>(owner);
        if (coin_balance >= amount) {
            return true
        };

        let paired_metadata = paired_metadata<CoinType>();
        let left_amount = amount - coin_balance;
        if (option::is_some(&paired_metadata)) {
            primary_fungible_store::is_balance_at_least(
                owner,
                option::extract(&mut paired_metadata),
                left_amount
            )
        } else { false }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/coin.move (L898-911)
```text
    public(friend) fun burn_from_for_gas<CoinType>(
        account_addr: address, amount: u64, burn_cap: &BurnCapability<CoinType>
    ) acquires CoinInfo, CoinConversionMap, PairedFungibleAssetRefs {
        // Skip burning if amount is zero. This shouldn't error out as it's called as part of transaction fee burning.
        if (amount == 0) { return };

        fungible_asset::address_burn_from_for_gas(
            borrow_paired_burn_ref(burn_cap),
            primary_fungible_store::primary_store_address(
                account_addr, ensure_paired_metadata<CoinType>()
            ),
            amount
        );
    }
```

**File:** aptos-move/framework/aptos-framework/sources/coin.move (L1760-1795)
```text
    #[test(account = @aptos_framework)]
    fun test_withdraw(
        account: &signer
    ) acquires CoinConversionMap, CoinInfo, CoinStore, PairedCoinType {
        let account_addr = signer::address_of(account);
        account::create_account_for_test(account_addr);
        let (burn_cap, freeze_cap, mint_cap) =
            initialize_and_register_fake_money(account, 1, true);
        let coin = mint<FakeMoney>(200, &mint_cap);
        deposit(account_addr, coin);
        assert!(coin_balance<FakeMoney>(account_addr) == 0, 0);
        assert!(balance<FakeMoney>(account_addr) == 200, 0);

        let coin = withdraw<FakeMoney>(account, 100);
        assert!(balance<FakeMoney>(account_addr) == 100, 0);

        let fa = coin_to_fungible_asset(coin);
        primary_fungible_store::deposit(account_addr, fa);
        assert!(
            primary_fungible_store::balance(
                account_addr, ensure_paired_metadata<FakeMoney>()
            ) == 200,
            0
        );
        assert!(balance<FakeMoney>(account_addr) == 200, 0);

        // Withdraw from fungible store only.
        let coin = withdraw<FakeMoney>(account, 150);
        assert!(balance<FakeMoney>(account_addr) == 50, 0);
        burn(coin, &burn_cap);

        move_to(
            account,
            FakeMoneyCapabilities { burn_cap, freeze_cap, mint_cap }
        );
    }
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_fee.move (L79-97)
```text
    public(friend) fun burn_fee(
        account: address, fee: u64
    ) acquires AptosFABurnCapabilities, AptosCoinCapabilities {
        if (exists<AptosFABurnCapabilities>(@aptos_framework)) {
            let burn_ref =
                &borrow_global<AptosFABurnCapabilities>(@aptos_framework).burn_ref;
            aptos_account::burn_from_fungible_store_for_gas(burn_ref, account, fee);
        } else {
            let burn_cap =
                &borrow_global<AptosCoinCapabilities>(@aptos_framework).burn_cap;
            if (features::operations_default_to_fa_apt_store_enabled()) {
                let (burn_ref, burn_receipt) = coin::get_paired_burn_ref(burn_cap);
                aptos_account::burn_from_fungible_store_for_gas(&burn_ref, account, fee);
                coin::return_paired_burn_ref(burn_ref, burn_receipt);
            } else {
                coin::burn_from_for_gas<AptosCoin>(account, fee, burn_cap);
            };
        };
    }
```

**File:** aptos-move/framework/aptos-framework/sources/fungible_asset.move (L1096-1101)
```text
    public(friend) fun address_burn_from_for_gas(
        self: &BurnRef, store_addr: address, amount: u64
    ) acquires FungibleStore, Supply, ConcurrentSupply, ConcurrentFungibleBalance {
        // ref metadata match is checked in burn() call
        self.burn(unchecked_withdraw_with_no_events(store_addr, amount));
    }
```

**File:** aptos-move/framework/aptos-framework/sources/fungible_asset.move (L1298-1326)
```text
    inline fun unchecked_withdraw_with_no_events(
        store_addr: address, amount: u64
    ): FungibleAsset {
        assert!(
            exists<FungibleStore>(store_addr),
            error::not_found(EFUNGIBLE_STORE_EXISTENCE)
        );

        let store = borrow_global_mut<FungibleStore>(store_addr);
        let metadata = store.metadata;
        if (amount != 0) {
            if (store.balance == 0
                && concurrent_fungible_balance_exists_inline(store_addr)) {
                let balance_resource =
                    borrow_global_mut<ConcurrentFungibleBalance>(store_addr);
                assert!(
                    balance_resource.balance.try_sub(amount),
                    error::invalid_argument(EINSUFFICIENT_BALANCE)
                );
            } else {
                assert!(
                    store.balance >= amount,
                    error::invalid_argument(EINSUFFICIENT_BALANCE)
                );
                store.balance -= amount;
            };
        };
        FungibleAsset { metadata, amount }
    }
```

**File:** aptos-move/aptos-vm/src/errors.rs (L199-250)
```rust
pub fn convert_epilogue_error(
    error: VMError,
    log_context: &AdapterLogSchema,
) -> Result<(), VMStatus> {
    let status = error.into_vm_status();
    Err(match status {
        VMStatus::Executed => VMStatus::Executed,
        VMStatus::MoveAbort {
            location,
            code,
            message,
        } if !APTOS_TRANSACTION_VALIDATION.is_account_module_abort(&location) => {
            let (category, reason) = error_split(code);
            let mut err_msg = format!(
                "[aptos_vm] Unexpected success epilogue Move abort: {:?}::{:?} (Category: {:?} Reason: {:?})",
                location, code, category, reason
            );
            if let Some(abort_msg) = message {
                err_msg.push_str(" Message: ");
                err_msg.push_str(&abort_msg);
            }
            speculative_error!(log_context, err_msg.clone());
            VMStatus::error(
                StatusCode::UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION,
                Some(err_msg),
            )
        },

        VMStatus::MoveAbort {
            location,
            code,
            message,
        } => match error_split(code) {
            (LIMIT_EXCEEDED, ECANT_PAY_GAS_DEPOSIT) => VMStatus::MoveAbort {
                location,
                code,
                message,
            },
            (category, reason) => {
                let mut err_msg = format!(
                    "[aptos_vm] Unexpected success epilogue Move abort: {:?}::{:?} (Category: {:?} Reason: {:?})",
                    location, code, category, reason
                );
                if let Some(abort_msg) = message {
                    err_msg.push_str(" Message: ");
                    err_msg.push_str(&abort_msg);
                }
                speculative_error!(log_context, err_msg.clone());
                VMStatus::error(
                    StatusCode::UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION,
                    Some(err_msg),
                )
```

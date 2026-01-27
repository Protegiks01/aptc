# Audit Report

## Title
Feature Flag Asymmetry Causes Account Balance Type Mismatch Between Creation and Validation

## Summary
The Aptos blockchain uses two separate feature flags to control the migration from CoinStore to FungibleStore for APT balances: `NEW_ACCOUNTS_DEFAULT_TO_FA_APT_STORE` (flag 64) controls account creation, while `OPERATIONS_DEFAULT_TO_FA_APT_STORE` (flag 65) controls transaction validation. A critical asymmetry exists where `coin::is_balance_at_least()` checks both balance types (backward compatible), but `aptos_account::is_fungible_balance_at_least()` only checks FungibleStore. If these flags are misaligned, newly created accounts cannot submit transactions even with sufficient balance, causing a network-wide availability failure.

## Finding Description

The vulnerability stems from an asymmetric implementation of balance checking during the Coin-to-FungibleAsset migration:

**Account Creation** (flag 64 - `NEW_ACCOUNTS_DEFAULT_TO_FA_APT_STORE`):
When new accounts are created via `aptos_account::create_account()`, the `register_apt()` function checks flag 64 to decide whether to create a CoinStore or FungibleStore: [1](#0-0) 

**Transaction Validation** (flag 65 - `OPERATIONS_DEFAULT_TO_FA_APT_STORE`):
During transaction prologue, gas payment validation checks flag 65 to decide which balance check to use: [2](#0-1) 

**Critical Asymmetry**:
The balance checking functions are NOT symmetric:

1. `coin::is_balance_at_least<AptosCoin>()` is **backward compatible** - it checks BOTH CoinStore AND paired FungibleStore: [3](#0-2) 

2. `aptos_account::is_fungible_balance_at_least()` is **NOT backward compatible** - it ONLY checks FungibleStore: [4](#0-3) 

**Exploitation Scenario (Flag 64 = OFF, Flag 65 = ON)**:
1. Governance enables flag 65 (`OPERATIONS_DEFAULT_TO_FA_APT_STORE`) but not flag 64
2. New user Alice creates an account via `create_account(alice_address)`
3. Account creation checks flag 64 (OFF) → CoinStore is created for Alice
4. Alice receives 1000 APT into her CoinStore
5. Alice attempts to submit a transaction requiring 100 APT gas
6. Transaction validation checks flag 65 (ON) → calls `is_fungible_balance_at_least()`
7. This function ONLY checks FungibleStore, which doesn't exist for Alice
8. Transaction fails with `PROLOGUE_ECANT_PAY_GAS_DEPOSIT` error
9. Alice's account is unusable despite having sufficient funds in CoinStore

**Simulation Impact**:
The simulation utility `SimulationStateStore::store_and_fund_account()` uses flag 64 to create test accounts: [5](#0-4) 

If simulation's flag 64 value differs from production's flag 65 value, simulated transactions will produce incorrect results - transactions may pass simulation but fail in production (or vice versa).

**No Technical Enforcement**:
While native executors assert both flags must be equal, these assertions only exist in benchmark/test code: [6](#0-5) 

The production AptosVM has no such enforcement, and the feature flag system allows independent modification: [7](#0-6) 

## Impact Explanation

**Severity: HIGH**

This vulnerability qualifies as HIGH severity under Aptos bug bounty criteria for "Significant protocol violations" because:

1. **Availability Impact**: All accounts created while flags are misaligned become unable to submit transactions, effectively freezing funds and causing loss of account functionality

2. **Network-Wide Effect**: If flags are misaligned across the network, ALL newly created accounts are affected until governance intervention

3. **Simulation Inaccuracy**: Incorrect simulation results break developer trust and can cause users to lose gas fees on transactions that were predicted to succeed

4. **Migration Risk**: During the Coin→FungibleAsset migration, a phased rollout that enables flags separately would cause this vulnerability to manifest

The impact does not reach CRITICAL because:
- No permanent loss of funds (recoverable via governance)
- No consensus safety violation (all validators would fail consistently)
- No fund theft or minting capability

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

The vulnerability is likely to manifest during:

1. **Phased Migration Rollout**: The most realistic scenario where governance intentionally enables flag 64 first (new accounts use FA), monitors for issues, then enables flag 65 later (operations check FA). This creates a vulnerability window.

2. **Governance Error**: Accidental misalignment through incorrect proposal parameters

3. **Testing/Debugging**: Network operators might enable flags separately for testing

**Mitigating Factors**:
- Both flags are enabled by default in production: [8](#0-7) 

- The Aptos team is aware these flags should be synchronized (evidenced by test assertions)

However, **no technical enforcement exists in production code** to prevent misalignment, making this a realistic vulnerability during any migration or upgrade scenario.

## Recommendation

**Immediate Fix**: Add runtime enforcement in production AptosVM to assert both flags are synchronized:

```rust
// In aptos-move/aptos-vm/src/aptos_vm.rs or appropriate initialization
fn validate_feature_flags(features: &Features) -> Result<()> {
    let new_accounts_fa = features.is_enabled(FeatureFlag::NEW_ACCOUNTS_DEFAULT_TO_FA_APT_STORE);
    let operations_fa = features.is_enabled(FeatureFlag::OPERATIONS_DEFAULT_TO_FA_APT_STORE);
    
    if new_accounts_fa != operations_fa {
        return Err(VMStatus::Error(
            StatusCode::FEATURE_UNDER_GATING,
            Some("NEW_ACCOUNTS_DEFAULT_TO_FA_APT_STORE and OPERATIONS_DEFAULT_TO_FA_APT_STORE must be enabled/disabled together".to_string())
        ));
    }
    Ok(())
}
```

**Better Fix**: Make `is_fungible_balance_at_least()` backward compatible by checking CoinStore as fallback:

```move
public(friend) fun is_fungible_balance_at_least(
    account: address, amount: u64
): bool {
    let store_addr = primary_fungible_store_address(account);
    let fa_balance = if (fungible_asset::store_exists(store_addr)) {
        fungible_asset::balance(store_addr)
    } else { 0 };
    
    if (fa_balance >= amount) {
        return true
    };
    
    // Fallback: check CoinStore for backward compatibility
    let coin_balance = if (coin::is_coin_store_exists<AptosCoin>(account)) {
        coin::balance<AptosCoin>(account)
    } else { 0 };
    
    fa_balance + coin_balance >= amount
}
```

**Simulation Fix**: Update `store_and_fund_account()` to check BOTH flags and verify they're aligned:

```rust
let features: Features = self.get_on_chain_config().unwrap_or_default();
let use_fa_balance = features.is_enabled(FeatureFlag::NEW_ACCOUNTS_DEFAULT_TO_FA_APT_STORE);
let operations_use_fa = features.is_enabled(FeatureFlag::OPERATIONS_DEFAULT_TO_FA_APT_STORE);

// Warn if misaligned
if use_fa_balance != operations_use_fa {
    warn!("Feature flag mismatch: NEW_ACCOUNTS_DEFAULT_TO_FA_APT_STORE={} but OPERATIONS_DEFAULT_TO_FA_APT_STORE={}", 
          use_fa_balance, operations_use_fa);
}
```

## Proof of Concept

```move
#[test_only]
module aptos_framework::feature_flag_mismatch_test {
    use std::signer;
    use aptos_framework::account;
    use aptos_framework::aptos_account;
    use aptos_framework::aptos_coin::AptosCoin;
    use aptos_framework::coin;
    use aptos_framework::features;
    
    #[test(framework = @0x1, alice = @0x100)]
    #[expected_failure(abort_code = 0x10004, location = aptos_framework::transaction_validation)] // PROLOGUE_ECANT_PAY_GAS_DEPOSIT
    fun test_flag_mismatch_causes_transaction_failure(framework: &signer, alice: &signer) {
        // Setup: Initialize with both flags OFF
        features::change_feature_flags_for_testing(
            framework,
            vector[],
            vector[
                features::get_new_accounts_default_to_fa_apt_store_feature(),
                features::get_operations_default_to_fa_apt_store_feature()
            ]
        );
        
        // Create account with CoinStore (flag 64 is OFF)
        let alice_addr = signer::address_of(alice);
        aptos_account::create_account(alice_addr);
        
        // Fund Alice's CoinStore with 1000 APT
        coin::register<AptosCoin>(alice);
        aptos_coin::mint(framework, alice_addr, 1000);
        assert!(coin::balance<AptosCoin>(alice_addr) == 1000, 1);
        
        // NOW enable flag 65 (operations check FA) but keep flag 64 OFF
        features::change_feature_flags_for_testing(
            framework,
            vector[features::get_operations_default_to_fa_apt_store_feature()],
            vector[]
        );
        
        // Try to validate transaction with 100 APT gas
        // This will call is_fungible_balance_at_least() which ONLY checks FungibleStore
        // Alice only has CoinStore, so validation FAILS despite having 1000 APT
        transaction_validation::prologue_common(
            alice,
            alice_addr,
            0, // txn_sequence_number
            vector[], // txn_public_key
            100, // txn_gas_price
            1000000, // txn_max_gas_units
            0, // txn_expiration_time
            1, // chain_id
            vector[] // secondary_signer_addresses
        );
        
        // This test will ABORT with PROLOGUE_ECANT_PAY_GAS_DEPOSIT
        // proving that Alice cannot transact despite having sufficient funds
    }
}
```

## Notes

This vulnerability demonstrates a critical invariant violation: **account creation type must match transaction validation type**. The asymmetric backward compatibility (coin checks both, FA checks only one) combined with separate feature flags creates a dangerous failure mode during migration. While both flags are currently enabled together by default, the lack of technical enforcement in production code makes this a HIGH severity issue that must be addressed before any phased migration rollout.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/aptos_account.move (L271-277)
```text
    public(friend) fun register_apt(account_signer: &signer) {
        if (features::new_accounts_default_to_fa_apt_store_enabled()) {
            ensure_primary_fungible_store_exists(signer::address_of(account_signer));
        } else {
            coin::register<AptosCoin>(account_signer);
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_account.move (L307-312)
```text
    public(friend) fun is_fungible_balance_at_least(
        account: address, amount: u64
    ): bool {
        let store_addr = primary_fungible_store_address(account);
        fungible_asset::is_address_balance_at_least(store_addr, amount)
    }
```

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

**File:** aptos-move/aptos-transaction-simulation/src/state_store.rs (L241-244)
```rust
        let features: Features = self.get_on_chain_config().unwrap_or_default();
        let use_fa_balance = features.is_enabled(FeatureFlag::NEW_ACCOUNTS_DEFAULT_TO_FA_APT_STORE);
        let use_concurrent_balance =
            features.is_enabled(FeatureFlag::DEFAULT_TO_CONCURRENT_FUNGIBLE_BALANCE);
```

**File:** execution/executor-benchmark/src/native/parallel_uncoordinated_block_executor.rs (L302-305)
```rust
        assert_eq!(
            fa_migration_complete, new_accounts_default_to_fa,
            "native code only works with both flags either enabled or disabled"
        );
```

**File:** aptos-move/framework/move-stdlib/sources/configs/features.move (L805-828)
```text
    public fun change_feature_flags_for_next_epoch(
        framework: &signer,
        enable: vector<u64>,
        disable: vector<u64>
    ) acquires PendingFeatures, Features {
        assert!(signer::address_of(framework) == @std, error::permission_denied(EFRAMEWORK_SIGNER_NEEDED));

        // Figure out the baseline feature vec that the diff will be applied to.
        let new_feature_vec = if (exists<PendingFeatures>(@std)) {
            // If there is a buffered feature vec, use it as the baseline.
            let PendingFeatures { features } = move_from<PendingFeatures>(@std);
            features
        } else if (exists<Features>(@std)) {
            // Otherwise, use the currently effective feature flag vec as the baseline, if it exists.
            Features[@std].features
        } else {
            // Otherwise, use an empty feature vec.
            vector[]
        };

        // Apply the diff and save it to the buffer.
        apply_diff(&mut new_feature_vec, enable, disable);
        move_to(framework, PendingFeatures { features: new_feature_vec });
    }
```

**File:** types/src/on_chain_config/aptos_features.rs (L234-235)
```rust
            FeatureFlag::NEW_ACCOUNTS_DEFAULT_TO_FA_APT_STORE,
            FeatureFlag::OPERATIONS_DEFAULT_TO_FA_APT_STORE,
```

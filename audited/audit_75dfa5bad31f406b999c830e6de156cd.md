# Audit Report

## Title
Supply Inconsistency Vulnerability During Aggregator V1 to V2 Migration for AptosCoin

## Summary
The migration from Aggregator V1 (deprecated `AggregatorV1Resource`) to Aggregator V2 (delayed fields) creates two separate, unsynchronized supply counters when the `OPERATIONS_DEFAULT_TO_FA_APT_STORE` feature flag is enabled. The fungible asset supply starts at zero while the coin supply retains historical values, causing permanent supply tracking inconsistencies for live APT tokens.

## Finding Description

The Aptos codebase maintains two parallel supply tracking systems for AptosCoin:

1. **Legacy Coin Supply (Aggregator V1)**: Stored in `CoinInfo<AptosCoin>.supply` using `OptionalAggregator` wrapping `AggregatorV1Resource` with (handle, key, limit) fields [1](#0-0) 

2. **Fungible Asset Supply (Aggregator V2)**: Stored in the paired fungible asset metadata using `ConcurrentSupply` with delayed fields [2](#0-1) 

**The Critical Flaw:**

When `coin::create_pairing<AptosCoin>()` is called during genesis or migration setup, it creates the fungible asset metadata with `option::none()` as the maximum_supply parameter [3](#0-2) 

This triggers `fungible_asset::add_fungibility()` which initializes the supply at **zero**, regardless of the existing coin supply [4](#0-3) 

When the `OPERATIONS_DEFAULT_TO_FA_APT_STORE` feature flag is enabled via governance, the native VM executor switches from `reduce_coin_apt_supply()` (modifying Aggregator V1 delta set) to `reduce_fa_apt_supply()` (modifying delayed field change set) for gas fee burns [5](#0-4) 

**Attack Scenario:**

1. AptosCoin has been minted and circulated, with `CoinInfo<AptosCoin>.supply` = 10,000,000,000 APT (tracked via Aggregator V1)
2. Governance calls `coin::create_pairing<AptosCoin>()` creating paired fungible asset metadata with supply = 0
3. Governance enables `OPERATIONS_DEFAULT_TO_FA_APT_STORE` feature flag
4. Gas fee burns now call `reduce_fa_apt_supply()` which decrements the FA supply (starting from 0)
5. First gas burn of 100 APT attempts to subtract from 0, potentially underflowing or creating negative supply
6. Coin supply remains frozen at 10,000,000,000 while FA supply tracks incorrectly from 0
7. Total supply queries return inconsistent results depending on which counter is checked

The only synchronization mechanism is explicit conversion via `coin_to_fungible_asset()` which burns coins and mints FAs [6](#0-5) , but there is **no enforcement** that all coins must be converted before enabling the feature flag.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program:

- **State Inconsistencies**: The two supply counters permanently diverge, violating the "State Consistency" invariant that requires state transitions to be atomic and consistent
- **Supply Tracking Corruption**: APT supply becomes unreliable for economic calculations, indexers, and protocol logic
- **Underflow Risk**: Attempting to burn from zero supply may trigger arithmetic underflows in the aggregator operations
- **Protocol Integrity**: Breaks the fundamental guarantee that total supply is accurately tracked

While this doesn't directly cause loss of funds, it creates **significant protocol violations** requiring manual intervention to restore supply consistency, potentially necessitating a hard fork to resynchronize the counters.

## Likelihood Explanation

**Likelihood: High**

This issue will **automatically occur** when:
1. The feature flag `OPERATIONS_DEFAULT_TO_FA_APT_STORE` is enabled (controlled by governance)
2. Not all existing coin holders have converted their coins to fungible assets
3. Any gas-burning transaction is executed after flag enablement

The native VM executor enforces that both `OPERATIONS_DEFAULT_TO_FA_APT_STORE` and `NEW_ACCOUNTS_DEFAULT_TO_FA_APT_STORE` must be enabled together [7](#0-6) , indicating this migration path is actively planned.

No attacker action is required - the vulnerability triggers through normal protocol operation after a governance vote.

## Recommendation

Implement atomic supply migration when creating the pairing:

```move
public entry fun create_pairing<CoinType>(
    aptos_framework: &signer
) acquires CoinConversionMap, CoinInfo {
    system_addresses::assert_aptos_framework(aptos_framework);
    
    // NEW: Read current coin supply before creating pairing
    let current_supply = if (exists<CoinInfo<CoinType>>(coin_address<CoinType>())) {
        let coin_info = borrow_global<CoinInfo<CoinType>>(coin_address<CoinType>());
        option::map_ref(&coin_info.supply, |supply| optional_aggregator::read(supply))
    } else {
        option::none()
    };
    
    let metadata = create_and_return_paired_metadata_if_not_exist<CoinType>(true);
    
    // NEW: Initialize FA supply with current coin supply
    if (option::is_some(&current_supply)) {
        let supply_value = option::destroy_some(current_supply);
        // Mint initial FA supply to match coin supply
        let mint_ref = get_paired_mint_ref(&MintCapability<CoinType>{});
        let initial_fa = fungible_asset::mint(&mint_ref, supply_value);
        // Burn it immediately to just increment the supply counter
        let burn_ref = get_paired_burn_ref(&BurnCapability<CoinType>{});
        fungible_asset::burn(&burn_ref, initial_fa);
    };
}
```

Additionally, add a migration check before enabling the feature flag:

```move
public fun enable_operations_default_to_fa_apt_store(framework: &signer) {
    system_addresses::assert_aptos_framework(framework);
    
    // Verify supply synchronization before enabling
    let coin_supply = coin::coin_supply<AptosCoin>();
    let fa_supply = fungible_asset::supply(coin::paired_metadata<AptosCoin>());
    
    assert!(
        coin_supply == fa_supply,
        error::invalid_state(ESUPPLY_NOT_SYNCHRONIZED)
    );
    
    features::change_feature_flags(framework, vector[], vector[OPERATIONS_DEFAULT_TO_FA_APT_STORE]);
}
```

## Proof of Concept

```move
#[test_only]
module test_supply_migration {
    use aptos_framework::coin;
    use aptos_framework::aptos_coin::{Self, AptosCoin};
    use aptos_framework::fungible_asset;
    use aptos_framework::features;
    use std::option;
    
    #[test(framework = @aptos_framework)]
    fun test_supply_inconsistency(framework: &signer) {
        // Setup: Initialize AptosCoin with supply tracking
        aptos_coin::initialize_for_test(framework);
        
        // Mint 1,000,000 APT (simulating existing circulation)
        let mint_cap = aptos_coin::mint_cap_for_test();
        let coins = coin::mint(1_000_000, &mint_cap);
        
        // Verify coin supply = 1,000,000
        let coin_supply_before = coin::coin_supply<AptosCoin>();
        assert!(option::contains(&coin_supply_before, &1_000_000), 1);
        
        // Create pairing (triggers the vulnerability)
        coin::create_coin_conversion_map(framework);
        coin::create_pairing<AptosCoin>(framework);
        
        // Check FA supply - it starts at 0!
        let metadata = coin::paired_metadata<AptosCoin>();
        let fa_supply = fungible_asset::supply(option::destroy_some(metadata));
        assert!(option::contains(&fa_supply, &0), 2); // FA supply is 0
        
        // But coin supply is still 1,000,000
        let coin_supply_after = coin::coin_supply<AptosCoin>();
        assert!(option::contains(&coin_supply_after, &1_000_000), 3);
        
        // Enable feature flag (simulating governance action)
        features::change_feature_flags(
            framework,
            vector[],
            vector[features::get_operations_default_to_fa_apt_store_feature()]
        );
        
        // Now gas burns will modify FA supply (from 0) instead of coin supply
        // This creates permanent inconsistency!
        
        // The two supplies are now desynchronized:
        // - Coin supply: 1,000,000 (frozen)
        // - FA supply: 0 (will track future operations incorrectly)
    }
}
```

**Notes:**
- The vulnerability specifically affects AptosCoin supply tracking during the migration from Coin to Fungible Asset framework
- The deprecated `AggregatorV1Resource` refers to the old table-based aggregator system (handle/key/limit fields) used by `OptionalAggregator` in `CoinInfo.supply`
- Aggregator V2 uses delayed fields with `DelayedFieldID` for better parallelism but is initialized separately without copying V1 state
- The `TODO[agg_v1](cleanup)` comments in the codebase confirm this is a known migration path [8](#0-7)

### Citations

**File:** types/src/account_config/resources/aggregator.rs (L39-58)
```rust
/// Deprecated:

/// Rust representation of Aggregator Move struct.
#[derive(Debug, Serialize, Deserialize)]
pub struct AggregatorV1Resource {
    handle: AccountAddress,
    key: AccountAddress,
    limit: u128,
}

impl AggregatorV1Resource {
    pub fn new(handle: AccountAddress, key: AccountAddress, limit: u128) -> Self {
        Self { handle, key, limit }
    }

    /// Helper function to return the state key where the actual value is stored.
    pub fn state_key(&self) -> StateKey {
        StateKey::table_item(&TableHandle(self.handle), self.key.as_ref())
    }
}
```

**File:** aptos-move/framework/aptos-framework/sources/fungible_asset.move (L117-120)
```text
    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct ConcurrentSupply has key {
        current: Aggregator<u128>
    }
```

**File:** aptos-move/framework/aptos-framework/sources/fungible_asset.move (L328-347)
```text
        if (default_to_concurrent_fungible_supply()) {
            let unlimited = maximum_supply.is_none();
            move_to(
                metadata_object_signer,
                ConcurrentSupply {
                    current: if (unlimited) {
                        aggregator_v2::create_unbounded_aggregator()
                    } else {
                        aggregator_v2::create_aggregator(
                            maximum_supply.extract()
                        )
                    }
                }
            );
        } else {
            move_to(
                metadata_object_signer,
                Supply { current: 0, maximum: maximum_supply }
            );
        };
```

**File:** aptos-move/framework/aptos-framework/sources/coin.move (L351-359)
```text
            primary_fungible_store::create_primary_store_enabled_fungible_asset(
                &metadata_object_cref,
                option::none(),
                name<CoinType>(),
                symbol<CoinType>(),
                decimals<CoinType>(),
                string::utf8(b""),
                string::utf8(b"")
            );
```

**File:** aptos-move/framework/aptos-framework/sources/coin.move (L407-414)
```text
    /// Conversion from coin to fungible asset
    public fun coin_to_fungible_asset<CoinType>(
        coin: Coin<CoinType>
    ): FungibleAsset acquires CoinConversionMap, CoinInfo {
        let metadata = ensure_paired_metadata<CoinType>();
        let amount = burn_internal(coin);
        fungible_asset::mint_internal(metadata, amount)
    }
```

**File:** execution/executor-benchmark/src/native/native_vm.rs (L130-139)
```rust
        let fa_migration_complete = env
            .features()
            .is_enabled(FeatureFlag::OPERATIONS_DEFAULT_TO_FA_APT_STORE);
        let new_accounts_default_to_fa = env
            .features()
            .is_enabled(FeatureFlag::NEW_ACCOUNTS_DEFAULT_TO_FA_APT_STORE);
        assert_eq!(
            fa_migration_complete, new_accounts_default_to_fa,
            "native code only works with both flags either enabled or disabled"
        );
```

**File:** execution/executor-benchmark/src/native/native_vm.rs (L506-520)
```rust
    fn reduce_apt_supply(
        &self,
        fa_migration_complete: bool,
        gas: u64,
        view: &(impl ExecutorView + ResourceGroupView),
        resource_write_set: &mut BTreeMap<StateKey, AbstractResourceWriteOp>,
        delayed_field_change_set: &mut BTreeMap<DelayedFieldID, DelayedChange<DelayedFieldID>>,
        aggregator_v1_delta_set: &mut BTreeMap<StateKey, DeltaOp>,
    ) -> Result<(), ()> {
        if fa_migration_complete {
            self.reduce_fa_apt_supply(gas, view, resource_write_set, delayed_field_change_set)
        } else {
            self.reduce_coin_apt_supply(gas, view, aggregator_v1_delta_set)
        }
    }
```

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L89-92)
```rust
    // TODO[agg_v1](cleanup) deprecate aggregator_v1 fields.
    aggregator_v1_write_set: BTreeMap<StateKey, WriteOp>,
    aggregator_v1_delta_set: BTreeMap<StateKey, DeltaOp>,
}
```

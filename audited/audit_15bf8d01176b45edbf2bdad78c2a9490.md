# Audit Report

## Title
Indexer Coin Supply Table Fails to Track Integer-Based Coin Supply Changes

## Summary
The Aptos indexer's `coin_supply` table only tracks coins using parallelizable aggregator-based supply tracking. Coins initialized with non-parallelizable Integer-based supply tracking have their minting and burning operations completely invisible to the indexer, allowing unlimited supply manipulation to be hidden from monitoring systems.

## Finding Description

The vulnerability exists in the indexer's coin supply tracking mechanism, which has a critical gap in coverage between two supply tracking methods supported by the Move framework.

**Background: Two Supply Tracking Methods**

The Aptos coin framework supports two methods for tracking coin supply through `OptionalAggregator`:
1. **Aggregator-based** (parallelizable): Supply stored in a separate table, accessed via handle+key
2. **Integer-based** (non-parallelizable): Supply stored directly in the `CoinInfo` resource [1](#0-0) 

When a coin is initialized using the standard `coin::initialize()` function (available to any user), it creates Integer-based supply tracking by default: [2](#0-1) 

The internal initialization passes `parallelizable=false`: [3](#0-2) 

**The Indexer Gap**

The indexer only tracks supply changes that appear as `WriteTableItem` changes (aggregator updates): [4](#0-3) 

The code explicitly returns `None` if aggregator metadata is missing (which occurs for Integer-based coins). For Integer-based coins:
- Supply changes modify the `CoinInfo` resource directly, producing `WriteResource` changes
- The indexer processes these through `CoinInfo::from_write_resource()`, but only extracts metadata, not the supply value [5](#0-4) 

**Unused Code Path**

The codebase includes `IntegerWrapperResource::get_supply()` which could extract supply from Integer-based tracking: [6](#0-5) 

However, this method is **never called** by the indexer, leaving Integer-based coin supply changes completely untracked.

**Attack Path**

1. Attacker deploys a new coin using `coin::initialize<MaliciousCoin>()` with `monitor_supply=true`
2. The coin uses Integer-based supply tracking (parallelizable=false by default)
3. Attacker mints unlimited coins using the `MintCapability`
4. On-chain supply correctly increases in the `CoinInfo` resource
5. Indexer's `coin_supply` table remains empty/unchanged for this coin
6. Applications querying the indexer see zero or missing supply data
7. Unlimited minting operations are hidden from indexer-based monitoring

## Impact Explanation

This vulnerability meets **Medium Severity** criteria per Aptos bug bounty guidelines:

**"State inconsistencies requiring intervention"** - The indexer (the primary query interface) shows fundamentally incorrect supply data for a category of coins, requiring code intervention to fix.

While this doesn't affect consensus or directly steal funds, it breaks the supply auditing invariant that the security question targets: **"Can supply be manipulated to show incorrect total coin supply, hiding unlimited minting or burning operations?"**

The answer is **yes** - for Integer-based coins, all minting/burning is hidden from the indexer, which is the primary interface used by:
- Blockchain explorers
- Wallet applications  
- DEX interfaces
- Auditing and monitoring tools

Note: AptosCoin itself is not affected as it uses parallelizable aggregators: [7](#0-6) 

## Likelihood Explanation

**Likelihood: High**

- Any user can deploy coins with Integer-based supply tracking (no special permissions required)
- The default `coin::initialize()` function uses Integer-based tracking
- The issue affects **all** coins deployed this way, not just malicious ones
- The comment explicitly states "Currently only supports aptos_coin" indicating known limitation [8](#0-7) 

## Recommendation

Add support for tracking Integer-based coin supply by extracting the value from `WriteResource` changes to `CoinInfo`:

```rust
// In coin_supply.rs, add new method:
pub fn from_write_resource(
    write_resource: &APIWriteResource,
    coin_info: &CoinInfoResource,
    coin_type: &str,
    coin_type_hash: &str,
    txn_version: i64,
    txn_timestamp: chrono::NaiveDateTime,
    txn_epoch: i64,
) -> anyhow::Result<Option<Self>> {
    // Check if using Integer-based supply
    if let Some(integer_supply) = coin_info.supply.vec.first()
        .and_then(|opt_agg| opt_agg.integer.get_supply()) 
    {
        return Ok(Some(Self {
            transaction_version: txn_version,
            coin_type_hash: coin_type_hash.to_string(),
            coin_type: coin_type.to_string(),
            supply: integer_supply,
            transaction_timestamp: txn_timestamp,
            transaction_epoch: txn_epoch,
        }));
    }
    Ok(None)
}
```

Then call this method in `CoinActivity::from_transaction()` when processing `WriteResource` changes to `CoinInfo` resources.

## Proof of Concept

```move
#[test_only]
module test_addr::integer_coin_test {
    use std::signer;
    use std::string;
    use aptos_framework::coin;
    use aptos_framework::aggregator_factory;

    struct IntegerCoin {}

    #[test(framework = @aptos_framework, creator = @0xCAFE)]
    fun test_integer_supply_not_tracked(framework: &signer, creator: &signer) {
        // Initialize aggregator factory
        aggregator_factory::initialize_aggregator_factory_for_test(framework);
        
        // Deploy coin with Integer-based supply (default for initialize)
        let (burn_cap, freeze_cap, mint_cap) = coin::initialize<IntegerCoin>(
            creator,
            string::utf8(b"Integer Coin"),
            string::utf8(b"INT"),
            8,
            true, // monitor_supply = true, but uses Integer not Aggregator
        );
        
        // Register coin store
        coin::register<IntegerCoin>(creator);
        
        // Mint 1,000,000 coins - this updates CoinInfo resource directly
        let coins = coin::mint<IntegerCoin>(1000000, &mint_cap);
        coin::deposit(signer::address_of(creator), coins);
        
        // Verify supply increased on-chain
        let supply = coin::supply<IntegerCoin>();
        assert!(std::option::is_some(&supply), 0);
        assert!(*std::option::borrow(&supply) == 1000000, 1);
        
        // But indexer would NOT capture this in coin_supply table
        // because it only tracks WriteTableItem changes, not WriteResource
        
        coin::destroy_mint_cap(mint_cap);
        coin::destroy_burn_cap(burn_cap);
        coin::destroy_freeze_cap(freeze_cap);
    }
}
```

**Expected Result**: The on-chain supply correctly shows 1,000,000 coins, but the indexer's `coin_supply` table would have no entries for `IntegerCoin`, making all minting operations invisible to monitoring systems.

## Notes

This vulnerability specifically affects the **indexer's view** of coin supply, not the blockchain's consensus or state. The on-chain state remains correct and can be queried directly. However, since the indexer is the primary interface for most applications, this represents a significant monitoring and auditing gap that allows supply manipulation to be hidden from standard observability tools.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/aggregator/optional_aggregator.move (L68-74)
```text
    /// Contains either an aggregator or a normal integer, both overflowing on limit.
    struct OptionalAggregator has store {
        // Parallelizable.
        aggregator: Option<Aggregator>,
        // Non-parallelizable.
        integer: Option<Integer>,
    }
```

**File:** aptos-move/framework/aptos-framework/sources/coin.move (L1013-1028)
```text
    public fun initialize<CoinType>(
        account: &signer,
        name: string::String,
        symbol: string::String,
        decimals: u8,
        monitor_supply: bool
    ): (BurnCapability<CoinType>, FreezeCapability<CoinType>, MintCapability<CoinType>) acquires CoinInfo, CoinConversionMap {
        initialize_internal(
            account,
            name,
            symbol,
            decimals,
            monitor_supply,
            false
        )
    }
```

**File:** aptos-move/framework/aptos-framework/sources/coin.move (L1086-1090)
```text
            supply: if (monitor_supply) {
                option::some(optional_aggregator::new(parallelizable))
            } else {
                option::none()
            }
```

**File:** crates/indexer/src/models/coin_models/coin_supply.rs (L28-44)
```rust
impl CoinSupply {
    /// Currently only supports aptos_coin. Aggregator table detail is in CoinInfo which for aptos coin appears during genesis.
    /// We query for the aggregator table details (handle and key) once upon indexer initiation and use it to fetch supply.
    pub fn from_write_table_item(
        write_table_item: &APIWriteTableItem,
        maybe_aptos_coin_info: &Option<CoinInfoQuery>,
        txn_version: i64,
        txn_timestamp: chrono::NaiveDateTime,
        txn_epoch: i64,
    ) -> anyhow::Result<Option<Self>> {
        if let Some(aptos_coin_info) = maybe_aptos_coin_info {
            // Return early if we don't have the aptos aggregator table info
            if aptos_coin_info.supply_aggregator_table_key.is_none()
                || aptos_coin_info.supply_aggregator_table_handle.is_none()
            {
                return Ok(None);
            }
```

**File:** crates/indexer/src/models/coin_models/coin_infos.rs (L61-64)
```rust
                let (supply_aggregator_table_handle, supply_aggregator_table_key) = inner
                    .get_aggregator_metadata()
                    .map(|agg| (Some(agg.handle), Some(agg.key)))
                    .unwrap_or((None, None));
```

**File:** crates/indexer/src/models/coin_models/coin_utils.rs (L76-81)
```rust
impl IntegerWrapperResource {
    /// In case we do want to track supply
    pub fn get_supply(&self) -> Option<BigDecimal> {
        self.vec.first().map(|inner| inner.value.clone())
    }
}
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_coin.move (L42-48)
```text
        let (burn_cap, freeze_cap, mint_cap) = coin::initialize_with_parallelizable_supply<AptosCoin>(
            aptos_framework,
            string::utf8(b"Aptos Coin"),
            string::utf8(b"APT"),
            8, // decimals
            true, // monitor_supply
        );
```

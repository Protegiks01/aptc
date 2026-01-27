# Audit Report

## Title
Division-by-Zero in Indexer's Inactive Pool Metadata Extraction Causes Denial of Service

## Summary
The indexer function `get_inactive_pool_metadata_from_write_table_item()` performs unvalidated division by `scaling_factor` when processing `pool_u64_unbound::Pool` table items. Since the Move function `create_with_scaling_factor()` accepts zero as a valid parameter, an attacker can create a malicious pool with `scaling_factor=0`, write it to a table, and cause the indexer to panic with division-by-zero, resulting in a denial of service.

## Finding Description

The vulnerability exists in the indexer's processing of inactive pool metadata. The function `get_inactive_pool_metadata_from_write_table_item()` extracts pool information from table items and performs a division operation without validating the denominator. [1](#0-0) 

At line 160, the code performs: `let total_shares = &inner.total_shares / &inner.scaling_factor;` without checking if `scaling_factor` is non-zero.

The `StakeTableItem::from_table_item_type()` function deserializes JSON data for any table item claiming to be of type `0x1::pool_u64_unbound::Pool`: [2](#0-1) 

The root cause is that the Move function `pool_u64_unbound::create_with_scaling_factor()` accepts any `u64` value, including zero, without validation: [3](#0-2) 

**Attack Path:**

1. Attacker deploys a custom Move module that uses `pool_u64_unbound`
2. Module creates a table with value type `0x1::pool_u64_unbound::Pool`
3. Module calls `pool_u64_unbound::create_with_scaling_factor(0)` to create a malicious pool
4. Module writes this pool to the table (valid on-chain operation)
5. Transaction is executed and committed to blockchain
6. Indexer processes the `WriteTableItem` change
7. Indexer calls `get_inactive_pool_metadata_from_write_table_item()`
8. At line 160, division by zero occurs
9. Rust's `BigDecimal` division panics on zero divisor
10. Indexer crashes

The indexer processes this metadata in `delegator_balances.rs`: [4](#0-3) 

This vulnerability breaks the assumption that all on-chain data can be safely processed by the indexer. While the delegation pool module correctly uses a non-zero `SHARES_SCALING_FACTOR`: [5](#0-4) 

The indexer must handle **all** pool table items, not just those from delegation pools, and any module can create pools with invalid scaling factors.

## Impact Explanation

**Severity: HIGH**

This vulnerability meets the Aptos bug bounty criteria for **High Severity** due to:

1. **Indexer Crash/DoS**: The indexer will panic and stop processing blocks when encountering a malicious pool, causing service disruption
2. **Data Availability Loss**: Applications depending on indexer data (delegation pool tracking, staking analytics) will stop receiving updates
3. **Operational Impact**: Requires manual intervention to restart/rebuild the indexer state
4. **Widespread Effect**: Affects all nodes running the indexer service

Per the bug bounty program, "API crashes" are explicitly listed as High Severity impacts. The indexer is a critical API component for querying blockchain state.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to be exploited because:

1. **Low Barrier to Entry**: Any user can deploy Move modules on Aptos (permissionless)
2. **Simple Exploit**: Creating a pool with `scaling_factor=0` requires minimal code
3. **No On-Chain Cost**: The attack is a legitimate Move operation, not requiring consensus manipulation
4. **Guaranteed Trigger**: Any indexer processing the malicious transaction will crash deterministically
5. **No Prevention**: No validation exists in either the Move module or the indexer to prevent this

The only requirement is deploying a simple Move module like:

```move
module attacker::exploit {
    use aptos_std::pool_u64_unbound;
    use aptos_std::table;
    
    public entry fun create_malicious_pool() {
        let pool = pool_u64_unbound::create_with_scaling_factor(0);
        let pools = table::new();
        table::add(&mut pools, 0, pool);
        // store pools somewhere...
    }
}
```

## Recommendation

**Immediate Fix**: Add validation in the indexer before performing division:

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
        // VALIDATION: Check for zero scaling_factor
        if inner.scaling_factor.is_zero() {
            return Err(anyhow::anyhow!(
                "Invalid pool at version {}: scaling_factor cannot be zero",
                txn_version
            ));
        }
        
        let total_coins = inner.total_coins;
        let total_shares = &inner.total_shares / &inner.scaling_factor;
        Ok(Some(PoolBalanceMetadata {
            // ... rest of the code
        }))
    } else {
        Ok(None)
    }
}
```

**Long-Term Fix**: Add validation in the Move module to prevent creating invalid pools:

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

**Move Module PoC** (demonstrating the attack):

```move
module attacker::pool_exploit {
    use aptos_std::pool_u64_unbound;
    use aptos_framework::account;
    use std::signer;
    use aptos_std::table_with_length as table;
    
    struct MaliciousPoolStore has key {
        pools: table::TableWithLength<u64, pool_u64_unbound::Pool>,
    }
    
    /// Creates a pool with scaling_factor=0 and stores it in a table
    /// This will cause any indexer processing this transaction to crash
    public entry fun create_malicious_pool(account: &signer) {
        let malicious_pool = pool_u64_unbound::create_with_scaling_factor(0);
        
        let pools = table::new<u64, pool_u64_unbound::Pool>();
        table::add(&mut pools, 0, malicious_pool);
        
        move_to(account, MaliciousPoolStore { pools });
    }
}
```

**Expected Result**: 
- Move module compiles and deploys successfully
- Transaction executes and commits on-chain
- Indexer crashes when processing the `WriteTableItem` for the pool table
- Error: "thread panicked at 'Division by zero'"

## Notes

This vulnerability demonstrates a critical mismatch between on-chain validation (or lack thereof) and off-chain indexer assumptions. The Move VM allows creation of pools with `scaling_factor=0` as it's a valid `u64` value, but the indexer assumes all pools have non-zero scaling factors. This type of vulnerability is particularly dangerous because the malicious data is permanently stored on-chain and will repeatedly crash any indexer attempting to process the historical blockchain state.

### Citations

**File:** crates/indexer/src/models/stake_models/delegator_pools.rs (L148-172)
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
            let total_coins = inner.total_coins;
            let total_shares = &inner.total_shares / &inner.scaling_factor;
            Ok(Some(PoolBalanceMetadata {
                transaction_version: txn_version,
                total_coins,
                total_shares,
                scaling_factor: inner.scaling_factor,
                shares_table_handle: inner.shares.inner.get_handle(),
                parent_table_handle: standardize_address(&write_table_item.handle.to_string()),
            }))
        } else {
            Ok(None)
        }
    }
```

**File:** crates/indexer/src/models/stake_models/stake_utils.rs (L95-112)
```rust
impl StakeTableItem {
    pub fn from_table_item_type(
        data_type: &str,
        data: &serde_json::Value,
        txn_version: i64,
    ) -> Result<Option<Self>> {
        match data_type {
            "0x1::pool_u64_unbound::Pool" => {
                serde_json::from_value(data.clone()).map(|inner| Some(StakeTableItem::Pool(inner)))
            },
            _ => Ok(None),
        }
        .context(format!(
            "version {} failed! failed to parse type {}, data {:?}",
            txn_version, data_type, data
        ))
    }
}
```

**File:** aptos-move/framework/aptos-stdlib/sources/pool_u64_unbound.move (L62-70)
```text
    /// Create a new pool with custom `scaling_factor`.
    public fun create_with_scaling_factor(scaling_factor: u64): Pool {
        Pool {
            total_coins: 0,
            total_shares: 0,
            shares: table::new<address, u128>(),
            scaling_factor,
        }
    }
```

**File:** crates/indexer/src/models/stake_models/delegator_balances.rs (L87-104)
```rust
                    "cannot parse string as u64: {:?}, version {}",
                    data.value, txn_version
                ))?;
            let shares = shares / &pool_balance.scaling_factor;
            Ok(Some(Self {
                delegator_address,
                pool_address,
                pool_type: "active_shares".to_string(),
                table_handle: table_handle.clone(),
                last_transaction_version: txn_version,
                shares,
                parent_table_handle: table_handle,
            }))
        } else {
            Ok(None)
        }
    }

```

**File:** aptos-move/framework/aptos-framework/sources/delegation_pool.move (L247-247)
```text
    const SHARES_SCALING_FACTOR: u64 = 10000000000000000;
```

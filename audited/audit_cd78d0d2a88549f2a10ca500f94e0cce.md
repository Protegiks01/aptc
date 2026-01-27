# Audit Report

## Title
Indexer Panic on Missing Table Info for Delegation Pool Share Handles

## Summary
The Aptos indexer does not validate that table handles extracted from `DelegationPoolResource` have corresponding table info before processing share updates. When table info is missing, the indexer panics instead of gracefully handling the error, causing service disruption.

## Finding Description
The `SharesInnerResource` struct contains a table handle that points to on-chain share data for delegation pools. [1](#0-0) 

When processing delegation pool resources, the indexer extracts table handles without validating that table info exists: [2](#0-1) 

The `WriteTableItem.data` field is optional and only populated when table info can be found: [3](#0-2) 

When table info is missing, the API returns `None` for the `data` field: [4](#0-3) 

However, the indexer's delegation balance processing code unconditionally unwraps this optional field, causing a panic: [5](#0-4) 

The same panic occurs for inactive shares: [6](#0-5) 

## Impact Explanation
This is a **Medium Severity** issue (per Aptos Bug Bounty criteria). While it causes indexer crashes/errors, it does not affect:
- Consensus safety or liveness
- On-chain state integrity  
- Validator operations
- Transaction processing

However, it does cause service disruption for indexer API consumers who rely on delegation pool data. The indexer cannot process transactions containing share updates for affected pools until table info becomes available.

## Likelihood Explanation
This issue is **Moderate to High likelihood** in the following scenarios:
1. **Race conditions**: When a new delegation pool is created and shares are immediately modified before table info is indexed
2. **Node configuration**: When the node serving data does not have table indexer enabled
3. **State pruning**: When table info has been pruned from storage
4. **Indexer restarts**: When the indexer processes historical data and encounters gaps in table info

The issue is exacerbated during periods of high delegation pool activity or when indexers are syncing from nodes with different configurations.

## Recommendation
Replace the `unwrap_or_else` panic with graceful error handling. When `data` is `None`, log a warning and skip processing that specific table item:

```rust
let data = match write_table_item.data.as_ref() {
    Some(d) => d,
    None => {
        aptos_logger::warn!(
            transaction_version = txn_version,
            table_handle = %table_handle,
            "Table data not available for active share item, skipping"
        );
        return Ok(None);
    }
};
```

Additionally, implement retry logic or table info validation when extracting handles from delegation pool resources to ensure table info is available before storing the mapping.

## Proof of Concept

```rust
// Reproduction scenario:
// 1. Start indexer with table indexer disabled on source node
// 2. Create a delegation pool on-chain
// 3. Add stake to the pool (triggers share table item write)
// 4. Indexer attempts to process the WriteTableItem
// 5. write_table_item.data is None (table info not available)
// 6. Code calls unwrap_or_else and panics

#[test]
fn test_missing_table_info_causes_panic() {
    let write_table_item = APIWriteTableItem {
        handle: HexEncodedBytes::from(vec![0x1; 32]),
        key: HexEncodedBytes::from(vec![0x2; 32]),
        value: HexEncodedBytes::from(vec![0x3; 32]),
        data: None, // Simulate missing table info
        state_key_hash: "0x123".to_string(),
    };
    
    let mut pool_mapping = ShareToStakingPoolMapping::new();
    pool_mapping.insert(
        "0x0101010101010101010101010101010101010101010101010101010101010101".to_string(),
        DelegatorPoolBalanceMetadata {
            transaction_version: 1,
            staking_pool_address: "0xpool".to_string(),
            total_coins: BigDecimal::from(100),
            total_shares: BigDecimal::from(100),
            scaling_factor: BigDecimal::from(1),
            operator_commission_percentage: BigDecimal::from(0),
            active_share_table_handle: "0x0101010101010101010101010101010101010101010101010101010101010101".to_string(),
            inactive_share_table_handle: "0xdeadbeef".to_string(),
        }
    );
    
    // This will panic with "This table item should be an active share item"
    let result = CurrentDelegatorBalance::get_active_share_from_write_table_item(
        &write_table_item,
        1,
        &pool_mapping
    );
    
    // Expected: Should return Ok(None) or Err, not panic
    // Actual: Panics with unwrap_or_else message
}
```

## Notes
The vulnerability is specific to the indexer service and does not impact blockchain consensus or on-chain operations. However, it represents a **state inconsistency requiring intervention** (Medium Severity category) as operators must manually address indexer crashes and potentially backfill missing data. The fix is straightforward but critical for indexer reliability in production environments where table info availability cannot be guaranteed.

### Citations

**File:** crates/indexer/src/models/stake_models/stake_utils.rs (L35-38)
```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SharesInnerResource {
    pub inner: Table,
}
```

**File:** crates/indexer/src/models/stake_models/delegator_pools.rs (L140-141)
```rust
                active_share_table_handle: inner.active_shares.shares.inner.get_handle(),
                inactive_share_table_handle: inner.inactive_shares.get_handle(),
```

**File:** api/types/src/transaction.rs (L1183-1186)
```rust
    // This is optional, and only possible to populate if the table indexer is enabled for this node
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub data: Option<DecodedTableData>,
```

**File:** api/types/src/convert.rs (L561-566)
```rust
        let table_info = match self.get_table_info(handle)? {
            Some(ti) => ti,
            None => {
                log_missing_table_info(handle);
                return Ok(None); // if table item not found return None anyway to avoid crash
            },
```

**File:** crates/indexer/src/models/stake_models/delegator_balances.rs (L72-77)
```rust
            let data = write_table_item.data.as_ref().unwrap_or_else(|| {
                panic!(
                    "This table item should be an active share item, table_item {:?}, version {}",
                    write_table_item, txn_version
                )
            });
```

**File:** crates/indexer/src/models/stake_models/delegator_balances.rs (L133-137)
```rust
            let data = write_table_item.data.as_ref().unwrap_or_else(|| {
                panic!(
                    "This table item should be an active share item, table_item {:?}, version {}",
                    write_table_item, txn_version
                )
```

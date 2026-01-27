# Audit Report

## Title
Indexer Denial of Service via Unhandled None Data Field in Table Item Processing

## Summary
Multiple indexer model conversion functions use `.unwrap()` on the optional `data` field of `WriteTableItem` without null checking, causing panic-based crashes when processing transactions from nodes that have table indexing disabled or missing table metadata. This enables trivial DoS attacks against NFT and token indexing infrastructure.

## Finding Description

The `WriteTableItem` struct contains an optional `data` field of type `Option<DecodedTableData>` that is only populated when the node has table indexing enabled. [1](#0-0) 

When table info is unavailable, the conversion logic explicitly returns `None` to avoid crashes: [2](#0-1) 

The `get_table_info` function returns `None` when the `indexer_reader` is not configured or lacks table metadata: [3](#0-2) 

However, the indexer assumes this field is always populated and uses `.unwrap()` without checking in **seven critical locations**:

**Collection Data Processing:** [4](#0-3) 

**Table Item Processing (4 instances):** [5](#0-4) [6](#0-5) 

**Table Metadata Processing (2 instances):** [7](#0-6) 

**Attack Path:**

1. Attacker submits any transaction containing table writes (e.g., NFT mint, token transfer)
2. The transaction is committed to the blockchain normally
3. An indexer fetches this transaction from a node via the Context API
4. The node's `MoveConverter` is created with the node's `indexer_reader`: [8](#0-7) 
5. If `indexer_reader` is `None` or lacks table info, the converter creates `WriteTableItem` with `data: None`
6. The indexer calls conversion functions that unwrap the `data` field
7. The indexer panics and crashes

Note that `CoinSupply` correctly handles the optional field: [9](#0-8) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under Aptos bug bounty criteria due to "API crashes." The indexer is critical infrastructure that:

- Powers NFT marketplaces and wallets requiring token ownership data
- Enables token discovery and metadata queries
- Supports analytics and blockchain explorers
- Provides historical transaction lookup for dApps

When indexers crash:
- NFT collection browsing becomes unavailable
- Token ownership queries fail
- Transaction history services stop functioning
- Ecosystem applications experience cascading failures

The vulnerability is **not** a consensus or validator node issue—blockchain operation continues normally. However, the ecosystem-wide impact on off-chain infrastructure that relies on indexers justifies High severity classification.

## Likelihood Explanation

**Very High Likelihood:**

1. **Configuration Commonality**: The `indexer_reader` is optional per the `Context` constructor, and many nodes run without table indexing enabled for performance reasons.

2. **Trigger Simplicity**: Any transaction with table writes triggers the vulnerability. Common operations include:
   - NFT minting (creates `TokenData`, `Token`, `CollectionData` table writes)
   - Token transfers (updates ownership tables)
   - Collection updates (modifies collection metadata)

3. **No Special Permissions Required**: Any user can submit these transactions—no validator access or special privileges needed.

4. **Wide Attack Surface**: All seven vulnerable code locations are executed during normal indexer operation when processing token/NFT transactions.

## Recommendation

Replace all `.unwrap()` calls on `WriteTableItem.data` with proper `Option` handling. Follow the defensive pattern used in `CoinSupply::from_write_table_item`:

```rust
// In collection_datas.rs line 92:
let table_item_data = match table_item.data.as_ref() {
    Some(data) => data,
    None => {
        aptos_logger::warn!(
            transaction_version = txn_version,
            table_handle = %table_item.handle,
            "Skipping collection data: table item data not available (table indexing may be disabled)"
        );
        return Ok(None);
    }
};

// In move_tables.rs, return early if data is missing:
pub fn from_write_table_item(
    write_table_item: &WriteTableItem,
    write_set_change_index: i64,
    transaction_version: i64,
    transaction_block_height: i64,
) -> Option<(Self, CurrentTableItem)> {
    let data = write_table_item.data.as_ref()?;
    Some((
        Self {
            // ... rest of initialization using data
        },
        CurrentTableItem {
            // ... rest of initialization using data
        }
    ))
}
```

Update callers to handle the `None` case gracefully by skipping items without decoded data rather than crashing.

## Proof of Concept

```rust
#[cfg(test)]
mod indexer_panic_test {
    use super::*;
    use aptos_api_types::{WriteTableItem, HexEncodedBytes};
    
    #[test]
    #[should_panic(expected = "unwrap")]
    fn test_collection_data_panics_on_none_data() {
        // Create a WriteTableItem with None data field
        // (simulating a node without table indexing)
        let write_table_item = WriteTableItem {
            state_key_hash: "0xabc".to_string(),
            handle: HexEncodedBytes::from(vec![1, 2, 3]),
            key: HexEncodedBytes::from(vec![4, 5, 6]),
            value: HexEncodedBytes::from(vec![7, 8, 9]),
            data: None, // Table indexing disabled
        };
        
        let table_handle_to_owner = std::collections::HashMap::new();
        let mut conn = establish_test_connection();
        
        // This will panic on line 92 with "called `Option::unwrap()` on a `None` value"
        let _ = CollectionData::from_write_table_item(
            &write_table_item,
            1000,
            chrono::Utc::now().naive_utc(),
            &table_handle_to_owner,
            &mut conn,
        );
    }
    
    #[test]
    #[should_panic(expected = "unwrap")]
    fn test_table_item_panics_on_none_data() {
        let write_table_item = WriteTableItem {
            state_key_hash: "0xdef".to_string(),
            handle: HexEncodedBytes::from(vec![10, 11, 12]),
            key: HexEncodedBytes::from(vec![13, 14, 15]),
            value: HexEncodedBytes::from(vec![16, 17, 18]),
            data: None, // Table indexing disabled
        };
        
        // This will panic on line 66/67 with "called `Option::unwrap()` on a `None` value"
        let _ = TableItem::from_write_table_item(
            &write_table_item,
            0,
            1000,
            100,
        );
    }
}
```

**Notes**

This vulnerability exists in the indexer codebase, not the core consensus or validator nodes. While the blockchain itself continues operating normally, the ecosystem-wide impact on NFT marketplaces, wallets, and dApps that depend on indexer data justifies High severity classification per bug bounty criteria. The issue is trivially exploitable by submitting any NFT-related transaction to a network where indexers consume from nodes with table indexing disabled—a common operational configuration.

### Citations

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

**File:** api/types/src/convert.rs (L1060-1065)
```rust
    fn get_table_info(&self, handle: TableHandle) -> Result<Option<TableInfo>> {
        if let Some(indexer_reader) = self.indexer_reader.as_ref() {
            return Ok(indexer_reader.get_table_info(handle).unwrap_or(None));
        }
        Ok(None)
    }
```

**File:** crates/indexer/src/models/token_models/collection_datas.rs (L92-92)
```rust
        let table_item_data = table_item.data.as_ref().unwrap();
```

**File:** crates/indexer/src/models/move_tables.rs (L66-67)
```rust
                decoded_key: write_table_item.data.as_ref().unwrap().key.clone(),
                decoded_value: Some(write_table_item.data.as_ref().unwrap().value.clone()),
```

**File:** crates/indexer/src/models/move_tables.rs (L74-75)
```rust
                decoded_key: write_table_item.data.as_ref().unwrap().key.clone(),
                decoded_value: Some(write_table_item.data.as_ref().unwrap().value.clone()),
```

**File:** crates/indexer/src/models/move_tables.rs (L127-128)
```rust
            key_type: table_item.data.as_ref().unwrap().key_type.clone(),
            value_type: table_item.data.as_ref().unwrap().value_type.clone(),
```

**File:** crates/indexer/src/indexer/fetcher.rs (L244-245)
```rust
    let state_view = context.latest_state_view().unwrap();
    let converter = state_view.as_converter(context.db.clone(), context.indexer_reader.clone());
```

**File:** crates/indexer/src/models/coin_models/coin_supply.rs (L45-49)
```rust
            if let Some(data) = &write_table_item.data {
                // Return early if not aggregator table type
                if !(data.key_type == "address" && data.value_type == "u128") {
                    return Ok(None);
                }
```

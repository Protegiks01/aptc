# Audit Report

## Title
Indexer Node Crash Due to Missing Table Data Validation in WriteTableItem Processing

## Summary
The indexer crashes when processing `WriteTableItem` changes from fullnodes that have table indexing disabled. Multiple `unwrap()` calls on the optional `data` field cause panic, preventing the indexer from processing any subsequent transactions and causing complete state query service outages.

## Finding Description

The vulnerability exists in the indexer's table processing logic where it assumes `WriteTableItem.data` is always populated, but this field is optional and only populated when the source fullnode has table indexing enabled.

**Root Cause Location:** [1](#0-0) 

The `from_write_table_item()` function performs multiple `unwrap()` calls without checking if `data` is `None`.

**Additional Panic Point:** [2](#0-1) 

The `TableMetadata::from_write_table_item()` also unwraps the `data` field, and is called in the same code path.

**Why `data` Can Be None:** [3](#0-2) 

The `WriteTableItem` struct explicitly defines `data` as `Option<DecodedTableData>` with a comment stating it's only populated when table indexer is enabled. [4](#0-3) 

When `get_table_info()` returns `None` (because `indexer_reader` is not configured), the function intentionally returns `Ok(None)` to avoid crashes at the fullnode level. [5](#0-4) 

The `get_table_info()` returns `None` when `indexer_reader` is not configured on the fullnode.

**Default Configuration:** [6](#0-5) 

The default table info service mode is `Disabled`, making this scenario common in production.

**Attack Path:**

1. A fullnode runs with table indexer disabled (default configuration)
2. Any transaction containing table operations commits to the chain
3. The fullnode creates `WriteTableItem` with `data: None` when converting to API format
4. An indexer fetches this transaction via the fullnode's API [7](#0-6) 

5. During processing, the indexer calls the vulnerable functions [8](#0-7) 

6. The indexer panics on the first `unwrap()` call
7. The panic propagates and crashes the entire indexer process [9](#0-8) 

## Impact Explanation

This is **HIGH severity** per Aptos bug bounty criteria:

- **API crashes**: The indexer API becomes completely unavailable, unable to serve state queries
- **Validator node slowdowns**: While not a validator node itself, the indexer is critical infrastructure that many services depend on

The impact includes:
- Complete indexer service outage (non-recoverable without manual intervention)
- All downstream services (block explorers, wallets, dApps) lose ability to query recent state
- The indexer cannot resume processing - it will crash repeatedly on the same transaction
- No automatic recovery mechanism exists

This does NOT qualify as CRITICAL because:
- No loss of funds
- No consensus/safety violation
- Blockchain itself continues operating normally

## Likelihood Explanation

**Very High Likelihood:**

1. **Common Configuration**: The default `IndexerTableInfoConfig` has table indexer disabled, so many production fullnodes operate this way
2. **Common Operations**: Table operations (`WriteTableItem`) occur frequently in normal Aptos transactions
3. **No Validation**: There's no configuration validation to prevent indexers from connecting to fullnodes without table indexing enabled
4. **Zero Attacker Requirements**: No special privileges needed - any regular transaction with table operations triggers this
5. **Widespread Deployment**: Production indexers routinely connect to various fullnode endpoints

## Recommendation

Add defensive null checks before accessing the `data` field. The functions should either:
1. Return an error when `data` is `None`, or  
2. Skip table processing gracefully, or
3. Validate during indexer startup that the connected fullnode has table indexing enabled

**Recommended Fix for `TableItem::from_write_table_item()`:**

```rust
pub fn from_write_table_item(
    write_table_item: &WriteTableItem,
    write_set_change_index: i64,
    transaction_version: i64,
    transaction_block_height: i64,
) -> Result<(Self, CurrentTableItem), String> {
    let data = write_table_item.data.as_ref()
        .ok_or_else(|| format!(
            "WriteTableItem data is None for handle {:?}. \
            Ensure the source fullnode has table indexing enabled.",
            write_table_item.handle
        ))?;
    
    Ok((
        Self {
            transaction_version,
            write_set_change_index,
            transaction_block_height,
            key: write_table_item.key.to_string(),
            table_handle: standardize_address(&write_table_item.handle.to_string()),
            decoded_key: data.key.clone(),
            decoded_value: Some(data.value.clone()),
            is_deleted: false,
        },
        CurrentTableItem {
            table_handle: standardize_address(&write_table_item.handle.to_string()),
            key_hash: hash_str(&write_table_item.key.to_string()),
            key: write_table_item.key.to_string(),
            decoded_key: data.key.clone(),
            decoded_value: Some(data.value.clone()),
            last_transaction_version: transaction_version,
            is_deleted: false,
        },
    ))
}
```

Similar fix needed for `TableMetadata::from_write_table_item()`.

## Proof of Concept

**Setup:**
1. Configure a fullnode with table indexer disabled (default)
2. Start an indexer pointing to this fullnode
3. Execute any transaction with table operations (e.g., token minting, staking operations)

**Rust Test Reproduction:**

```rust
#[test]
fn test_write_table_item_with_none_data_panics() {
    use aptos_api_types::{WriteTableItem, HexEncodedBytes};
    use crate::models::move_tables::TableItem;
    
    // Create WriteTableItem with data: None (simulating fullnode without table indexer)
    let write_table_item = WriteTableItem {
        state_key_hash: "0xabc".to_string(),
        handle: HexEncodedBytes::from(vec![1, 2, 3]),
        key: HexEncodedBytes::from(vec![4, 5, 6]),
        value: HexEncodedBytes::from(vec![7, 8, 9]),
        data: None, // This is None when table indexer is disabled
    };
    
    // This will panic with "called `Option::unwrap()` on a `None` value"
    let result = std::panic::catch_unwind(|| {
        TableItem::from_write_table_item(&write_table_item, 0, 1, 1)
    });
    
    assert!(result.is_err(), "Expected panic but function succeeded");
}
```

The panic will occur at the first `unwrap()` call, crashing the indexer node and preventing all future transaction processing until manual intervention.

**Notes:**

This vulnerability represents a critical operational risk for the Aptos indexer infrastructure. The configuration mismatch between fullnodes (table indexer often disabled for performance) and indexers (expecting table data) creates a systemic availability issue. The lack of graceful error handling means a single transaction with table operations can permanently disable indexer services until configuration is corrected and the indexer is manually restarted at a safe version.

### Citations

**File:** crates/indexer/src/models/move_tables.rs (L53-80)
```rust
    pub fn from_write_table_item(
        write_table_item: &WriteTableItem,
        write_set_change_index: i64,
        transaction_version: i64,
        transaction_block_height: i64,
    ) -> (Self, CurrentTableItem) {
        (
            Self {
                transaction_version,
                write_set_change_index,
                transaction_block_height,
                key: write_table_item.key.to_string(),
                table_handle: standardize_address(&write_table_item.handle.to_string()),
                decoded_key: write_table_item.data.as_ref().unwrap().key.clone(),
                decoded_value: Some(write_table_item.data.as_ref().unwrap().value.clone()),
                is_deleted: false,
            },
            CurrentTableItem {
                table_handle: standardize_address(&write_table_item.handle.to_string()),
                key_hash: hash_str(&write_table_item.key.to_string()),
                key: write_table_item.key.to_string(),
                decoded_key: write_table_item.data.as_ref().unwrap().key.clone(),
                decoded_value: Some(write_table_item.data.as_ref().unwrap().value.clone()),
                last_transaction_version: transaction_version,
                is_deleted: false,
            },
        )
    }
```

**File:** crates/indexer/src/models/move_tables.rs (L124-130)
```rust
    pub fn from_write_table_item(table_item: &WriteTableItem) -> Self {
        Self {
            handle: table_item.handle.to_string(),
            key_type: table_item.data.as_ref().unwrap().key_type.clone(),
            value_type: table_item.data.as_ref().unwrap().value_type.clone(),
        }
    }
```

**File:** api/types/src/transaction.rs (L1176-1187)
```rust
/// Change set to write a table item
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Object)]
pub struct WriteTableItem {
    pub state_key_hash: String,
    pub handle: HexEncodedBytes,
    pub key: HexEncodedBytes,
    pub value: HexEncodedBytes,
    // This is optional, and only possible to populate if the table indexer is enabled for this node
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub data: Option<DecodedTableData>,
}
```

**File:** api/types/src/convert.rs (L555-578)
```rust
    pub fn try_write_table_item_into_decoded_table_data(
        &self,
        handle: TableHandle,
        key: &[u8],
        value: &[u8],
    ) -> Result<Option<DecodedTableData>> {
        let table_info = match self.get_table_info(handle)? {
            Some(ti) => ti,
            None => {
                log_missing_table_info(handle);
                return Ok(None); // if table item not found return None anyway to avoid crash
            },
        };

        let key = self.try_into_move_value(&table_info.key_type, key)?;
        let value = self.try_into_move_value(&table_info.value_type, value)?;

        Ok(Some(DecodedTableData {
            key: key.json().unwrap(),
            key_type: table_info.key_type.to_canonical_string(),
            value: value.json().unwrap(),
            value_type: table_info.value_type.to_canonical_string(),
        }))
    }
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

**File:** config/src/config/indexer_table_info_config.rs (L41-48)
```rust
impl Default for IndexerTableInfoConfig {
    fn default() -> Self {
        Self {
            parser_task_count: DEFAULT_PARSER_TASK_COUNT,
            parser_batch_size: DEFAULT_PARSER_BATCH_SIZE,
            table_info_service_mode: TableInfoServiceMode::Disabled,
        }
    }
```

**File:** crates/indexer/src/indexer/fetcher.rs (L244-246)
```rust
    let state_view = context.latest_state_view().unwrap();
    let converter = state_view.as_converter(context.db.clone(), context.indexer_reader.clone());

```

**File:** crates/indexer/src/models/write_set_changes.rs (L118-140)
```rust
            APIWriteSetChange::WriteTableItem(table_item) => {
                let (ti, cti) = TableItem::from_write_table_item(
                    table_item,
                    index,
                    transaction_version,
                    transaction_block_height,
                );
                (
                    Self {
                        transaction_version,
                        hash: table_item.state_key_hash.clone(),
                        transaction_block_height,
                        type_,
                        address: String::default(),
                        index,
                    },
                    WriteSetChangeDetail::Table(
                        ti,
                        cti,
                        Some(TableMetadata::from_write_table_item(table_item)),
                    ),
                )
            },
```

**File:** crates/indexer/src/runtime.rs (L226-243)
```rust
            let processed_result: ProcessingResult = match res {
                // When the batch is empty b/c we're caught up, continue to next batch
                None => continue,
                Some(Ok(res)) => res,
                Some(Err(tpe)) => {
                    let (err, start_version, end_version, _) = tpe.inner();
                    error!(
                        processor_name = processor_name,
                        start_version = start_version,
                        end_version = end_version,
                        error =? err,
                        "Error processing batch!"
                    );
                    panic!(
                        "Error in '{}' while processing batch: {:?}",
                        processor_name, err
                    );
                },
```

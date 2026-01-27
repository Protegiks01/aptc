# Audit Report

## Title
Postgres Indexer Crashes on Table Write Operations Due to Unchecked Optional Field Access

## Summary
The postgres-based indexer crashes with a panic when processing blockchain transactions containing table write operations because the `from_write_table_item()` function calls `.unwrap()` on an optional field that can legitimately be `None` when the table info indexer is not configured.

## Finding Description

The `WriteTableItem` structure contains an optional `data` field of type `Option<DecodedTableData>` that is only populated when the table indexer is enabled and table metadata is available. [1](#0-0) 

The `MoveConverter` explicitly handles the case where table info is unavailable by returning `None` to avoid crashes during transaction processing. [2](#0-1) 

When the `indexer_reader` is not configured (which is a valid configuration scenario), the `get_table_info()` method returns `Ok(None)`. [3](#0-2) 

However, the postgres-based indexer's `TableItem::from_write_table_item()` function unconditionally calls `.unwrap()` on this optional field multiple times. [4](#0-3) 

The postgres-based indexer explicitly creates its API context with `indexer_reader = None`, confirming this is a legitimate runtime configuration. [5](#0-4) 

The `from_write_table_item()` function is called during critical write set change processing, which handles all table item writes from blockchain transactions. [6](#0-5) 

**Attack Path:**
1. Node operator enables postgres-based indexer but does not configure the internal table info indexer (valid configuration)
2. Any blockchain transaction performs a table write operation (normal operation)
3. Postgres indexer fetches the transaction from the API
4. API's `MoveConverter` creates `WriteTableItem` with `data = None` (because `indexer_reader` is `None`)
5. Indexer calls `from_write_table_item()` to process the write set change
6. Function calls `.unwrap()` on `None` value
7. **Indexer panics and crashes**

## Impact Explanation

This qualifies as **High Severity** per the Aptos bug bounty criteria under "API crashes". The postgres-based indexer is a critical service that provides indexed blockchain data to applications and explorers. When it crashes:

- All indexer functionality becomes unavailable
- Applications relying on indexed data lose access to historical blockchain data
- The indexer must be manually restarted
- Data indexing falls behind the blockchain tip
- Service degradation affects the entire ecosystem using the indexer

While this doesn't affect consensus or validator operations directly, it represents a significant availability issue for a critical infrastructure component.

## Likelihood Explanation

**Likelihood: High**

This vulnerability will trigger in any deployment where:
- The postgres-based indexer is enabled (common configuration)
- The internal table info indexer is not configured or unavailable (also common)
- Any transaction performs table write operations (frequent occurrence on Aptos blockchain)

This is not a theoretical edge case—it represents a configuration mismatch where two independently configured subsystems (postgres indexer and table info indexer) have incompatible expectations. The postgres indexer assumes decoded table data will always be available, but the API layer correctly handles its absence.

The issue will manifest immediately upon processing the first transaction with table writes, making it easily triggerable through normal blockchain operations.

## Recommendation

Replace all `.unwrap()` calls on the optional `data` field with proper error handling or default values. The fix should either:

1. **Skip processing when data is unavailable** (graceful degradation):
   - Return early when `write_table_item.data.is_none()`
   - Log a warning indicating table metadata is unavailable

2. **Use default/placeholder values** (partial functionality):
   - Populate `decoded_key` and `decoded_value` with JSON null values
   - Store only the raw bytes in the database

3. **Propagate the error** (fail fast):
   - Return a `Result` type and handle the error at the caller level
   - Provide clear error messages about missing table indexer configuration

The recommended approach is option 1 (graceful degradation) combined with configuration validation at startup to warn operators if postgres indexer is enabled without table info indexer.

## Proof of Concept

**Reproduction Steps:**

1. Configure an Aptos node with:
   - `indexer.enabled = true` (postgres indexer enabled)
   - Internal table info indexer disabled or not configured
   - Postgres database configured

2. Deploy a Move module that uses table operations, for example:
   ```
   // Any standard module using Table<K,V>
   use aptos_std::table::Table;
   ```

3. Submit a transaction that writes to a table (e.g., token minting, staking operations, or any DApp operation using tables)

4. Monitor the indexer logs

**Expected Result:**
The indexer panics with an error similar to:
```
thread 'indexer' panicked at 'called `Option::unwrap()` on a `None` value', crates/indexer/src/models/move_tables.rs:66
```

**Validation:**
This can be verified by examining the indexer runtime bootstrap code which explicitly passes `None` for the indexer_reader parameter, confirming this is a real production configuration scenario.

## Notes

This vulnerability represents a mismatch between two subsystems:
- The API layer (`MoveConverter`) correctly handles missing table metadata by setting `data = None`
- The postgres indexer incorrectly assumes this field is always populated

The issue was likely introduced when the table info indexer was made optional/configurable, but the postgres indexer's assumptions were not updated accordingly. The security question correctly identified that version/format evolution could cause crashes, though the actual issue is simpler—it's an unchecked optional field rather than a versioning problem.

### Citations

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

**File:** crates/indexer/src/runtime.rs (L93-99)
```rust
        let context = Arc::new(Context::new(
            chain_id,
            db,
            mp_sender,
            node_config,
            None, /* table info reader */
        ));
```

**File:** crates/indexer/src/models/write_set_changes.rs (L118-139)
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
```

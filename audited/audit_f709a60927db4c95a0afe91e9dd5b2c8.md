# Audit Report

## Title
Indexer Crashes and Loses Deletion Records When Processing Table Item Deletions from Nodes with Default Configuration

## Summary
The Aptos indexer component crashes with a panic when processing `DeleteTableItem` entries from nodes running with default configuration (table indexer disabled). This causes permanent loss of deletion records in the `table_items` historical table, violating the guarantee that `is_deleted` properly tracks deletion history across transaction versions.

## Finding Description

The vulnerability exists in the indexer's table item processing logic. When a transaction deletes a table item, the indexer must record this deletion in the `table_items` PostgreSQL table with `is_deleted=true` to maintain historical deletion tracking.

**The Attack Path:**

1. **Default Node Configuration**: Aptos nodes run with `TableInfoServiceMode::Disabled` by default. [1](#0-0) 

2. **Missing Data Field**: When the table indexer is disabled, the node's API cannot populate the `data` field in `DeleteTableItem` because `get_table_info()` fails with "Indexer not enabled." [2](#0-1) 

3. **API Returns None**: The API's `try_delete_table_item_into_deleted_table_data()` function catches this error and returns `Ok(None)`, resulting in `DeleteTableItem.data = None`. [3](#0-2) 

4. **Panic in Indexer**: The indexer's `from_delete_table_item()` function attempts to extract the decoded key from the `data` field using `.unwrap_or_else(|| { panic!(...) })`, which panics when `data` is `None`. [4](#0-3) 

5. **Process Crash**: The panic propagates through the processing pipeline, causing the entire indexer process to crash. [5](#0-4) 

6. **Data Loss**: The deletion record is never inserted into the `table_items` database table, permanently losing the historical deletion record. [6](#0-5) 

**Security Guarantee Broken:**

This violates the **State Consistency** invariant (#4) which requires state transitions to be atomic and verifiable. The `table_items` table is designed to maintain complete historical records of all table item changes across transaction versions. The schema explicitly includes an `is_deleted` field for tracking deletions. [7](#0-6) 

## Impact Explanation

**Severity: Medium**

This qualifies as **Medium Severity** per the Aptos Bug Bounty criteria:
- **State inconsistencies requiring intervention**: The indexer database becomes incomplete, missing critical deletion history. Applications relying on the indexer for historical table item queries will receive incorrect data.
- **Service availability**: Any indexer instance connected to nodes with default configuration will crash repeatedly when encountering table item deletions, requiring manual intervention to restart and potential code patches to work around the issue.

The impact is NOT Critical because:
- It does not affect the core blockchain consensus or execution layer
- It does not cause loss of funds or consensus violations
- The blockchain itself continues to function correctly; only the indexer component is affected

However, the impact is significant because:
- Indexers are critical infrastructure for querying blockchain history
- Many applications depend on indexer data for analytics and state queries
- The default configuration makes this issue widespread and likely to occur in production

## Likelihood Explanation

**Likelihood: HIGH**

This issue is highly likely to occur because:

1. **Default Configuration**: Nodes run with `TableInfoServiceMode::Disabled` by default, meaning most production nodes will not have the table indexer enabled. [1](#0-0) 

2. **Common Operation**: Table item deletions are a normal part of Move smart contract execution. Any contract using the `Table` type from the Aptos Framework can delete items.

3. **Guaranteed Trigger**: Every single transaction that deletes a table item will trigger the crash when processed by an indexer connected to a node with default configuration.

4. **Widespread Deployment**: Independent indexer operators typically connect to public RPC nodes or run their own nodes with default configuration, making this a common production scenario.

## Recommendation

**Immediate Fix:**

Modify the `from_delete_table_item()` function to handle the case where `data` is `None` gracefully instead of panicking:

```rust
pub fn from_delete_table_item(
    delete_table_item: &DeleteTableItem,
    write_set_change_index: i64,
    transaction_version: i64,
    transaction_block_height: i64,
) -> (Self, CurrentTableItem) {
    let decoded_key = delete_table_item
        .data
        .as_ref()
        .map(|d| d.key.clone())
        .unwrap_or_else(|| {
            // If data is missing, use the raw key bytes as fallback
            serde_json::json!({
                "bytes": delete_table_item.key.to_string()
            })
        });
    
    // ... rest of the function
}
```

**Long-term Solution:**

1. Enable table indexer by default on nodes that serve indexer traffic
2. Add validation at the API level to ensure `DeleteTableItem.data` is always populated before returning to indexers
3. Update documentation to clearly specify the table indexer requirement for running indexer components

## Proof of Concept

**Setup:**
1. Deploy an Aptos node with default configuration (table indexer disabled)
2. Run the indexer component connecting to this node
3. Execute a Move transaction that deletes a table item:

```move
module test_addr::table_delete_test {
    use aptos_std::table::{Self, Table};
    
    struct TestResource has key {
        items: Table<u64, u64>
    }
    
    public entry fun delete_item(account: &signer, key: u64) acquires TestResource {
        let resource = borrow_global_mut<TestResource>(signer::address_of(account));
        table::remove(&mut resource.items, key);
    }
}
```

**Expected Result:**
- The indexer panics with message: "Could not extract data from DeletedTableItem"
- The indexer process crashes
- The deletion record is never written to the `table_items` database table
- Historical deletion tracking is permanently lost

**Verification:**
Query the `table_items` table for the deletion transaction version - the record will be missing, confirming the data loss.

## Notes

This vulnerability affects the data integrity of the indexer subsystem rather than the core blockchain protocol. However, it represents a significant operational issue that impacts the ability to reliably track historical state changes across the Aptos blockchain. The issue is exacerbated by the default configuration making it the norm rather than the exception.

### Citations

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

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L1178-1183)
```rust
    fn get_table_info_option(&self, handle: TableHandle) -> Result<Option<TableInfo>> {
        match &self.indexer {
            Some(indexer) => indexer.get_table_info(handle),
            None => bail!("Indexer not enabled."),
        }
    }
```

**File:** api/types/src/convert.rs (L580-599)
```rust
    pub fn try_delete_table_item_into_deleted_table_data(
        &self,
        handle: TableHandle,
        key: &[u8],
    ) -> Result<Option<DeletedTableData>> {
        let table_info = match self.get_table_info(handle)? {
            Some(ti) => ti,
            None => {
                log_missing_table_info(handle);
                return Ok(None); // if table item not found return None anyway to avoid crash
            },
        };

        let key = self.try_into_move_value(&table_info.key_type, key)?;

        Ok(Some(DeletedTableData {
            key: key.json().unwrap(),
            key_type: table_info.key_type.to_canonical_string(),
        }))
    }
```

**File:** crates/indexer/src/models/move_tables.rs (L82-120)
```rust
    pub fn from_delete_table_item(
        delete_table_item: &DeleteTableItem,
        write_set_change_index: i64,
        transaction_version: i64,
        transaction_block_height: i64,
    ) -> (Self, CurrentTableItem) {
        let decoded_key = delete_table_item
            .data
            .as_ref()
            .unwrap_or_else(|| {
                panic!(
                    "Could not extract data from DeletedTableItem '{:?}'",
                    delete_table_item
                )
            })
            .key
            .clone();
        (
            Self {
                transaction_version,
                write_set_change_index,
                transaction_block_height,
                key: delete_table_item.key.to_string(),
                table_handle: standardize_address(&delete_table_item.handle.to_string()),
                decoded_key: decoded_key.clone(),
                decoded_value: None,
                is_deleted: true,
            },
            CurrentTableItem {
                table_handle: standardize_address(&delete_table_item.handle.to_string()),
                key_hash: hash_str(&delete_table_item.key.to_string()),
                key: delete_table_item.key.to_string(),
                decoded_key,
                decoded_value: None,
                last_transaction_version: transaction_version,
                is_deleted: true,
            },
        )
    }
```

**File:** crates/indexer/src/runtime.rs (L230-243)
```rust
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

**File:** crates/indexer/src/processors/default_processor.rs (L360-377)
```rust
fn insert_table_items(
    conn: &mut PgConnection,
    items_to_insert: &[TableItem],
) -> Result<(), diesel::result::Error> {
    use schema::table_items::dsl::*;
    let chunks = get_chunks(items_to_insert.len(), TableItem::field_count());
    for (start_ind, end_ind) in chunks {
        execute_with_better_error(
            conn,
            diesel::insert_into(schema::table_items::table)
                .values(&items_to_insert[start_ind..end_ind])
                .on_conflict((transaction_version, write_set_change_index))
                .do_nothing(),
            None,
        )?;
    }
    Ok(())
}
```

**File:** crates/indexer/migrations/2022-08-08-043603_core_tables/up.sql (L281-296)
```sql
CREATE TABLE table_items (
  key text NOT NULL,
  transaction_version BIGINT NOT NULL,
  write_set_change_index BIGINT NOT NULL,
  transaction_block_height BIGINT NOT NULL,
  table_handle VARCHAR(66) NOT NULL,
  decoded_key jsonb NOT NULL,
  decoded_value jsonb,
  is_deleted BOOLEAN NOT NULL,
  inserted_at TIMESTAMP NOT NULL DEFAULT NOW(),
  -- Constraints
  PRIMARY KEY (transaction_version, write_set_change_index),
  CONSTRAINT fk_transaction_versions FOREIGN KEY (transaction_version) REFERENCES transactions (version)
);
CREATE INDEX ti_hand_ver_key_index ON table_items (table_handle, transaction_version);
CREATE INDEX ti_insat_index ON table_items (inserted_at);
```

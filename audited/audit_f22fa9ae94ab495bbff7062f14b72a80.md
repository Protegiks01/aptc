# Audit Report

## Title
Indexer Denial of Service via Unchecked Table Data Access Leading to Panic

## Summary
The Aptos indexer (`crates/indexer/`) crashes with a panic when processing any transaction containing table writes due to unconditional `.unwrap()` calls on `Option<DecodedTableData>` that is always `None` due to missing table info reader configuration.

## Finding Description

The vulnerability exists in a configuration mismatch between how the indexer fetches transactions and how it processes them:

**Configuration Issue:**
When the indexer bootstraps, it creates an API Context without a table info reader: [1](#0-0) 

**Transaction Fetching:**
When fetching transactions, the converter uses this `None` indexer_reader to decode table items: [2](#0-1) 

**API Conversion Returns None:**
During conversion, when table info cannot be found (because `indexer_reader` is `None`), the `data` field is set to `None`: [3](#0-2) [4](#0-3) [5](#0-4) 

**Processing Crashes:**
The indexer models unconditionally unwrap this `None` value, causing a panic: [6](#0-5) [7](#0-6) 

**Attack Path:**
1. Attacker submits any transaction that writes to a Move table (e.g., token transfer, staking operation, any contract using tables)
2. Transaction executes successfully on-chain
3. Indexer fetches the transaction batch
4. Conversion creates `WriteTableItem` with `data: None`
5. Processing calls `TableItem::from_write_table_item()` 
6. Panic occurs at `.unwrap()` calls on lines 66, 67, 74, 75, 127, 128
7. Indexer crashes and stops processing all subsequent transactions

## Impact Explanation

This is a **High Severity** vulnerability per Aptos Bug Bounty criteria:
- **API crashes**: The indexer is a critical API component that applications depend on for querying blockchain state
- Complete denial of service of the indexer - it cannot process any transactions after encountering a table write
- The crash is persistent - the indexer will crash again when restarted and tries to process the same transaction
- All applications relying on the indexer (wallets, DEXs, explorers, etc.) will stop receiving state updates
- The issue affects data availability but not the blockchain itself (validators continue operating normally)

## Likelihood Explanation

**Extremely High** - This will trigger on ANY transaction containing table writes:
- Move tables are ubiquitous in Aptos (token standards, staking, governance, most dApps)
- No special transaction crafting needed - normal user operations trigger this
- The bug exists in production configuration where `indexer_reader: None` is hardcoded
- Every indexer instance running with default configuration will crash on first table write transaction

## Recommendation

**Fix Option 1 - Enable Table Info Reader:**
Modify the indexer bootstrap to include the table info reader: [8](#0-7) 

Change line 98 from `None` to pass an actual `IndexerReader` implementation that has access to table metadata.

**Fix Option 2 - Handle None Data Gracefully:**
Modify the table item processing to handle missing data: [6](#0-5) 

Replace `.unwrap()` calls with proper error handling or default values. However, this would result in incomplete indexer data, so Option 1 is preferred.

**Recommended Fix:** Implement Option 1 by creating and passing an `IndexerReader` instance that can access table metadata when the indexer is initialized.

## Proof of Concept

**Rust Reproduction Steps:**

1. Start an Aptos node with indexer enabled (default configuration)
2. Submit a simple transaction that writes to a table:

```move
script {
    use aptos_framework::table;
    
    fun test_table(account: &signer) {
        let t = table::new<u64, u64>();
        table::add(&mut t, 1, 100);
        table::destroy_empty(t);
    }
}
```

3. Observe indexer logs - it will panic with: "thread panicked at 'called `Option::unwrap()` on a `None` value'"
4. Indexer process terminates and cannot continue processing transactions
5. Any restart will crash again on the same transaction

**Alternative - Using Existing Transactions:**
Simply wait for any user to perform a token transfer or staking operation (which use tables internally). The indexer will crash immediately upon processing such transactions.

**Notes**

This vulnerability represents a critical operational failure in the indexer component. While it doesn't affect blockchain consensus or validator operation, it completely breaks the indexer's core function of tracking blockchain state. The bug is guaranteed to occur in production as long as the indexer uses the default configuration where `indexer_reader` is `None`. The fix requires proper initialization of table metadata access during indexer bootstrap.

### Citations

**File:** crates/indexer/src/runtime.rs (L92-100)
```rust
    runtime.spawn(async move {
        let context = Arc::new(Context::new(
            chain_id,
            db,
            mp_sender,
            node_config,
            None, /* table info reader */
        ));
        run_forever(indexer_config, context).await;
```

**File:** crates/indexer/src/indexer/fetcher.rs (L244-246)
```rust
    let state_view = context.latest_state_view().unwrap();
    let converter = state_view.as_converter(context.db.clone(), context.indexer_reader.clone());

```

**File:** api/types/src/convert.rs (L543-549)
```rust
                WriteSetChange::WriteTableItem(WriteTableItem {
                    state_key_hash,
                    handle: hex_handle,
                    key,
                    value: bytes.to_vec().into(),
                    data,
                })
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

**File:** crates/indexer/src/models/move_tables.rs (L123-131)
```rust
impl TableMetadata {
    pub fn from_write_table_item(table_item: &WriteTableItem) -> Self {
        Self {
            handle: table_item.handle.to_string(),
            key_type: table_item.data.as_ref().unwrap().key_type.clone(),
            value_type: table_item.data.as_ref().unwrap().value_type.clone(),
        }
    }
}
```

# Audit Report

## Title
Infinite Loop DoS in Table Info Indexer Leading to API Thread Exhaustion

## Summary
The `get_table_info_with_retry()` function in the table info indexer contains an unbounded retry loop with no timeout mechanism. When querying transaction details via the API for transactions containing table items with unindexed table handles, API threads block indefinitely, leading to thread pool exhaustion and complete API unavailability.

## Finding Description

The vulnerability exists in the table info indexer's retry mechanism. [1](#0-0) 

This function implements an infinite loop that continuously retries fetching table information with only a 10ms sleep between attempts. There is no maximum retry limit or timeout - the `retried` counter increments indefinitely but is only used for logging purposes.

The function is called from the IndexerReader trait implementation: [2](#0-1) 

The critical attack path occurs when API requests retrieve transaction details. The conversion process iterates through write set changes: [3](#0-2) 

For table item operations, the converter attempts to decode the table data: [4](#0-3) 

When processing table items, the code calls: [5](#0-4) 

The code attempts to handle missing table info gracefully with `.unwrap_or(None)`: [6](#0-5) 

However, this error handling is ineffective because `get_table_info_with_retry()` **never returns** - it blocks the calling thread indefinitely in the retry loop.

**Conditions where table handles are never indexed:**

The codebase explicitly acknowledges that table items can exist without their parent table info being indexed through the `pending_on` mechanism: [7](#0-6) 

And the warning confirms this scenario: [8](#0-7) 

**Attack Scenario:**
1. Indexer lags behind the chain or encounters parse failures for certain table structures
2. Table items are written to state but their parent table's `TableInfo` is never indexed
3. User queries a transaction containing such table items via `/transactions/{version}` API
4. API spawns thread to process request
5. Thread calls `get_table_info_with_retry()` and blocks forever
6. Multiple concurrent requests create multiple blocked threads
7. API thread pool is exhausted
8. Node API becomes completely unresponsive

This breaks the **Resource Limits** invariant - operations must respect computational limits and cannot consume unbounded resources.

## Impact Explanation

This is a **High Severity** vulnerability per the Aptos bug bounty criteria:

- **API crashes**: The node's REST API becomes completely unresponsive once the thread pool is exhausted
- **Validator node slowdowns**: Fullnodes and validators running the API service experience resource exhaustion
- **Significant protocol violations**: Nodes cannot serve read requests, violating availability guarantees

The impact extends beyond typical DoS because:
1. No cleanup mechanism exists - blocked threads never recover
2. Requires node restart to restore service
3. Can be triggered repeatedly by any API user
4. Affects critical infrastructure (validator APIs, fullnode APIs)

## Likelihood Explanation

**HIGH Likelihood**

This vulnerability can be triggered through multiple natural scenarios:

1. **Indexer lag**: The async table info indexer processes blocks separately from the main chain. During high load or catchup, the indexer may lag behind, causing API requests for recent transactions to encounter unindexed tables.

2. **Database corruption**: Any corruption in the indexer database that loses table info records will cause permanent blocking for affected table handles.

3. **Parsing failures**: The indexer parsing logic may fail on certain edge cases or malformed Move data structures, leaving table handles permanently unindexed.

4. **Race conditions**: Rapid queries immediately after table creation can race with the async indexer.

The attack requires:
- No authentication (public API)
- No special permissions
- Simply querying transaction details via standard API endpoints
- Can be automated to repeatedly exhaust thread pools

## Recommendation

Implement a timeout mechanism with a maximum retry count:

```rust
pub fn get_table_info_with_retry(&self, handle: TableHandle) -> Result<Option<TableInfo>> {
    const MAX_RETRIES: u64 = 100; // 1 second total wait time (100 * 10ms)
    let mut retried = 0;
    
    loop {
        if let Ok(Some(table_info)) = self.get_table_info(handle) {
            return Ok(Some(table_info));
        }

        if retried >= MAX_RETRIES {
            aptos_logger::warn!(
                retry_count = retried,
                table_handle = handle.0.to_canonical_string(),
                "[DB] Failed to get table info after maximum retries, returning None"
            );
            return Ok(None); // Return None instead of blocking forever
        }

        // Log the first failure, and then sample subsequent failures to avoid log spam
        if retried == 0 {
            log_table_info_failure(handle, retried);
        } else {
            sample!(
                SampleRate::Duration(Duration::from_secs(1)),
                log_table_info_failure(handle, retried)
            );
        }

        retried += 1;
        std::thread::sleep(Duration::from_millis(TABLE_INFO_RETRY_TIME_MILLIS));
    }
}
```

Additionally, the API layer should handle missing table info gracefully: [9](#0-8) 

This already returns `None` on missing table info, which is correct behavior - the fix above ensures it actually reaches this code path.

## Proof of Concept

```rust
// Test demonstrating the infinite loop behavior
#[test]
fn test_infinite_loop_dos_on_missing_table_info() {
    use aptos_db_indexer::db_v2::IndexerAsyncV2;
    use aptos_schemadb::DB;
    use aptos_types::state_store::table::TableHandle;
    use aptos_types::account_address::AccountAddress;
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};
    
    // Create a new indexer with empty database
    let tmpdir = tempfile::tempdir().unwrap();
    let db = DB::open(
        tmpdir.path(),
        "test_db",
        vec![],
        &Default::default(),
    ).unwrap();
    
    let indexer = Arc::new(IndexerAsyncV2::new(db).unwrap());
    
    // Create a non-existent table handle
    let fake_handle = TableHandle(AccountAddress::from_hex_literal("0xdeadbeef").unwrap());
    
    // Spawn thread to call get_table_info_with_retry
    let indexer_clone = Arc::clone(&indexer);
    let start_time = Instant::now();
    
    let handle = thread::spawn(move || {
        // This will block forever!
        indexer_clone.get_table_info_with_retry(fake_handle)
    });
    
    // Wait 2 seconds - the thread should still be blocked
    thread::sleep(Duration::from_secs(2));
    
    // Thread is still running (blocked in infinite loop)
    assert!(!handle.is_finished());
    assert!(start_time.elapsed() >= Duration::from_secs(2));
    
    // In production, this thread would never complete
    // We need to abort the test to prevent it from hanging
    // (In real scenario, this exhausts the API thread pool)
}
```

**Notes**

This vulnerability is particularly severe because it combines multiple failure modes:

1. **Silent failure**: No error is returned to alert operators
2. **Resource leak**: Blocked threads are never recovered
3. **Cascading failure**: Each new API request creates another blocked thread
4. **No automatic recovery**: Requires manual node restart

The root cause is the design assumption that the async indexer will "eventually" index all table handles, without accounting for edge cases where this assumption breaks down. The migration comment in the code suggests this is transitional code, but the lack of timeout protection makes it a production security issue.

### Citations

**File:** storage/indexer/src/db_v2.rs (L153-173)
```rust
    pub fn get_table_info_with_retry(&self, handle: TableHandle) -> Result<Option<TableInfo>> {
        let mut retried = 0;
        loop {
            if let Ok(Some(table_info)) = self.get_table_info(handle) {
                return Ok(Some(table_info));
            }

            // Log the first failure, and then sample subsequent failures to avoid log spam
            if retried == 0 {
                log_table_info_failure(handle, retried);
            } else {
                sample!(
                    SampleRate::Duration(Duration::from_secs(1)),
                    log_table_info_failure(handle, retried)
                );
            }

            retried += 1;
            std::thread::sleep(Duration::from_millis(TABLE_INFO_RETRY_TIME_MILLIS));
        }
    }
```

**File:** storage/indexer/src/db_v2.rs (L175-187)
```rust
    pub fn is_indexer_async_v2_pending_on_empty(&self) -> bool {
        if !self.pending_on.is_empty() {
            let pending_keys: Vec<TableHandle> =
                self.pending_on.iter().map(|entry| *entry.key()).collect();
            aptos_logger::warn!(
                "There are still pending table items to parse due to unknown table info for table handles: {:?}",
                pending_keys
            );
            false
        } else {
            true
        }
    }
```

**File:** storage/indexer/src/db_v2.rs (L279-299)
```rust
    fn collect_table_info_from_table_item(
        &mut self,
        handle: TableHandle,
        bytes: &Bytes,
    ) -> Result<()> {
        match self.get_table_info(handle)? {
            Some(table_info) => {
                let mut infos = vec![];
                self.annotator
                    .collect_table_info(&table_info.value_type, bytes, &mut infos)?;
                self.process_table_infos(infos)?
            },
            None => {
                self.pending_on
                    .entry(handle)
                    .or_default()
                    .insert(bytes.clone());
            },
        }
        Ok(())
    }
```

**File:** storage/indexer/src/indexer_reader.rs (L47-52)
```rust
    fn get_table_info(&self, handle: TableHandle) -> anyhow::Result<Option<TableInfo>> {
        if let Some(table_info_reader) = &self.table_info_reader {
            return Ok(table_info_reader.get_table_info_with_retry(handle)?);
        }
        anyhow::bail!("Table info reader is not available")
    }
```

**File:** api/types/src/convert.rs (L263-267)
```rust
            changes: write_set
                .into_write_op_iter()
                .filter_map(|(sk, wo)| self.try_into_write_set_changes(sk, wo).ok())
                .flatten()
                .collect(),
```

**File:** api/types/src/convert.rs (L519-553)
```rust
    pub fn try_table_item_into_write_set_change(
        &self,
        state_key_hash: String,
        handle: TableHandle,
        key: Vec<u8>,
        op: WriteOp,
    ) -> Result<WriteSetChange> {
        let hex_handle = handle.0.to_vec().into();
        let key: HexEncodedBytes = key.into();
        let ret = match op.bytes() {
            None => {
                let data = self.try_delete_table_item_into_deleted_table_data(handle, &key.0)?;

                WriteSetChange::DeleteTableItem(DeleteTableItem {
                    state_key_hash,
                    handle: hex_handle,
                    key,
                    data,
                })
            },
            Some(bytes) => {
                let data =
                    self.try_write_table_item_into_decoded_table_data(handle, &key.0, bytes)?;

                WriteSetChange::WriteTableItem(WriteTableItem {
                    state_key_hash,
                    handle: hex_handle,
                    key,
                    value: bytes.to_vec().into(),
                    data,
                })
            },
        };
        Ok(ret)
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

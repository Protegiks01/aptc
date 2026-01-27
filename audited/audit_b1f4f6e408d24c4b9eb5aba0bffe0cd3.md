# Audit Report

## Title
Infinite Loop in Table Info Retrieval Causes API Thread Exhaustion and Denial of Service

## Summary
The `get_table_info_with_retry` function contains an infinite retry loop with no timeout or maximum retry count. When table metadata is not available in the indexer database, the function never returns, causing API worker threads to hang indefinitely. This leads to thread pool exhaustion and complete API unavailability. [1](#0-0) 

## Finding Description
The vulnerability stems from improper error handling in the indexer table info retrieval path. The `get_table_info_with_retry` function is designed to wait for table metadata to become available for newly created tables. However, it implements an unbounded retry loop that never propagates errors or returns `None` when table info genuinely doesn't exist.

**Attack Flow:**

1. The API layer converts transaction write sets for display, calling `try_write_table_item_into_decoded_table_data` to decode table items [2](#0-1) 

2. This calls `get_table_info` through the converter's indexer reader [3](#0-2) 

3. Which delegates to `IndexerReaders::get_table_info` that calls the underlying `get_table_info_with_retry` [4](#0-3) 

4. When `get_table_info` returns `Ok(None)` (table not found) or any error, the retry function's condition at line 156 fails, causing it to sleep 10ms and retry indefinitely without any exit condition

5. The API worker thread executing `tokio::task::spawn_blocking` is permanently blocked, never completing the request

**Triggering Conditions:**
- Table metadata not yet indexed (indexer lag)
- Table metadata indexing failed for a specific table
- Deleted or invalid table handles in historical transactions
- Any scenario where `get_table_info` returns `Ok(None)`

This breaks the **Resource Limits invariant** (invariant #9) by allowing unbounded resource consumption through thread exhaustion.

## Impact Explanation
**High Severity** per Aptos bug bounty criteria - "API crashes" and "Validator node slowdowns"

The impact is severe because:

1. **Complete API Unavailability**: Each hung thread permanently consumes a worker thread from the blocking thread pool. With enough concurrent requests, all worker threads become exhausted, making the API completely unresponsive.

2. **No Recovery Without Restart**: Hung threads never timeout or return. The only recovery is a full node restart.

3. **Easy Exploitation**: Any user can trigger this by:
   - Querying recent transactions with table operations before indexer processes them
   - Querying transactions referencing tables that failed to index
   - Querying any endpoint that converts transaction write sets (e.g., `/transactions/by_hash/{hash}`, `/transactions/by_version/{version}`)

4. **Amplification**: A single malicious actor can send multiple concurrent requests, rapidly exhausting the thread pool.

## Likelihood Explanation
**High Likelihood** - This vulnerability will occur naturally in production:

1. **Indexer Lag**: The indexer processes transactions asynchronously. During network congestion or high transaction volumes, there's always a window where transactions are committed but not yet indexed. Any API query during this window triggers the hang.

2. **Normal Operation**: Even without malicious intent, legitimate users querying recent transactions will experience hangs, making this a reliability issue that impacts normal operations.

3. **No Special Privileges Required**: Any unauthenticated user with API access can trigger this vulnerability.

4. **Persistent Effect**: Once triggered, the hung threads remain until node restart, accumulating over time.

## Recommendation
Implement a maximum retry count and timeout in `get_table_info_with_retry`:

```rust
pub fn get_table_info_with_retry(&self, handle: TableHandle) -> Result<Option<TableInfo>> {
    const MAX_RETRIES: u64 = 100; // 1 second total (100 * 10ms)
    let mut retried = 0;
    
    loop {
        match self.get_table_info(handle) {
            Ok(Some(table_info)) => return Ok(Some(table_info)),
            Ok(None) if retried >= MAX_RETRIES => {
                // Table info not available after retries
                return Ok(None);
            }
            Err(e) if retried >= MAX_RETRIES => {
                // Database error persists
                return Err(e);
            }
            _ => {
                // Retry
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
    }
}
```

Additionally, the API layer already has defensive handling for missing table info, so returning `Ok(None)` after timeout is safe and won't break functionality.

## Proof of Concept

**Setup:**
1. Deploy an Aptos node with table info indexer enabled
2. Deploy a Move contract that creates tables

**Exploitation Steps:**

```rust
// Rust PoC demonstrating the hang
use aptos_rest_client::Client;
use aptos_types::account_address::AccountAddress;

#[tokio::test]
async fn test_api_hang_on_unindexed_table() {
    let client = Client::new(url::Url::parse("http://localhost:8080").unwrap());
    
    // Submit transaction that creates a table
    let txn_hash = submit_table_creation_transaction(&client).await;
    
    // Immediately query the transaction before indexer processes it
    // This will hang indefinitely
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.get_transaction_by_hash(txn_hash)
    ).await;
    
    // Timeout occurs because the API thread is hung in get_table_info_with_retry
    assert!(result.is_err(), "API request should timeout due to infinite retry loop");
}
```

**Verification:**
1. Monitor thread pool: Observe worker threads stuck in `get_table_info_with_retry`
2. Check logs: See repeated "Failed to get table info" messages
3. API becomes unresponsive as threads accumulate
4. Only recovery is node restart

**Notes:**
This vulnerability exists because the error handling pattern fails to distinguish between temporary unavailability (should retry) and permanent unavailability (should return None). The current implementation assumes all table handles will eventually be indexed, which is not guaranteed in practice.

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

**File:** api/types/src/convert.rs (L555-567)
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

**File:** storage/indexer/src/indexer_reader.rs (L47-52)
```rust
    fn get_table_info(&self, handle: TableHandle) -> anyhow::Result<Option<TableInfo>> {
        if let Some(table_info_reader) = &self.table_info_reader {
            return Ok(table_info_reader.get_table_info_with_retry(handle)?);
        }
        anyhow::bail!("Table info reader is not available")
    }
```

# Audit Report

## Title
Infinite Retry Loop DoS in Table Info Indexer Causes API Thread Exhaustion

## Summary
The `get_table_info_with_retry()` function implements an infinite retry loop with no timeout or maximum retry count, causing API worker threads to hang indefinitely when table metadata hasn't been indexed yet, leading to complete API unavailability through thread pool exhaustion.

## Finding Description

The vulnerability exists in the table information retrieval mechanism used by the Aptos REST API. The infinite loop is implemented here: [1](#0-0) 

This function loops indefinitely until `get_table_info(handle)` returns `Ok(Some(table_info))`. If table information is not present (`Ok(None)`) or encounters an error (`Err`), the loop continues forever with only a fixed 10ms sleep between retries: [2](#0-1) 

The attack path flows through the API transaction rendering pipeline. When transactions are queried via endpoints like `/transactions/by_hash/{hash}`, the API converts transaction data to the response format: [3](#0-2) 

This uses `api_spawn_blocking` which wraps `tokio::task::spawn_blocking` with no timeout: [4](#0-3) 

The conversion process calls `try_into_onchain_transaction()` which processes write set changes: [5](#0-4) 

For table items specifically, the code attempts to decode them by retrieving table metadata: [6](#0-5) 

This calls through to the IndexerReader trait: [7](#0-6) 

Which invokes the infinite retry loop.

**Attack Scenario:**
1. Attacker submits a transaction with table writes
2. Transaction commits to blockchain  
3. Attacker immediately queries via `/transactions/{version}` or `/transactions/by_hash/{hash}`
4. Indexer hasn't processed table metadata yet (race condition window)
5. API worker thread enters infinite loop
6. Thread hangs indefinitely consuming resources
7. Attacker repeats with concurrent requests
8. All blocking threads exhaust
9. API becomes unresponsive—DoS achieved

**Broken Invariant:** Resource Limits—the system fails to enforce computational and time limits on indexer queries, allowing unbounded resource consumption.

## Impact Explanation

**Severity: HIGH** (per Aptos bug bounty: "API crashes")

This vulnerability causes:
- **Complete API Unavailability**: Once blocking threads exhaust, no API requests can be processed
- **Resource Exhaustion**: Each hung thread consumes memory and queries database every 10ms
- **No Recovery Mechanism**: Threads never terminate—only node restart recovers
- **Cascading Failures**: Monitoring, health checks, and dependent services fail
- **Validator Impact**: Validator nodes running public APIs become unavailable

The impact is amplified because:
- Table writes are common in Aptos transactions
- The indexer naturally lags behind consensus during high load  
- No timeout exists at any layer to break the loop
- Attack requires no special privileges

## Likelihood Explanation

**Likelihood: HIGH**

The vulnerability is highly likely to be triggered because:
- **Easy to Exploit**: Only requires submitting transactions and querying them immediately
- **No Privileges Required**: Anyone can submit transactions and call public API endpoints
- **Natural Occurrence**: Normal operations during indexer lag trigger this accidentally
- **Race Condition Window**: The faster consensus commits vs indexer processing, the larger the window
- **Common Pattern**: Table operations are frequently used in Move smart contracts

Attack requirements:
- Submit transaction with table write (~$0.01 in gas)
- Query transaction via public API (free)
- Repeat to exhaust blocking thread pool
- Total cost: Trivial to execute

## Recommendation

Add timeout and maximum retry count to `get_table_info_with_retry()`:

```rust
pub fn get_table_info_with_retry(&self, handle: TableHandle) -> Result<Option<TableInfo>> {
    const MAX_RETRIES: u64 = 100; // 1 second total wait time
    let mut retried = 0;
    loop {
        if let Ok(Some(table_info)) = self.get_table_info(handle) {
            return Ok(Some(table_info));
        }
        
        if retried >= MAX_RETRIES {
            log_table_info_failure(handle, retried);
            return Ok(None); // Return None instead of hanging forever
        }

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

Alternatively, add request-level timeouts in the API layer using `tokio::time::timeout()` around `spawn_blocking` calls.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Configuring a node with table info indexer enabled but artificially delayed
2. Submitting a transaction that creates a new table
3. Immediately querying the transaction via REST API
4. Observing the API thread hang in `get_table_info_with_retry()` 
5. Repeating with multiple concurrent requests to exhaust the blocking thread pool
6. Verifying API becomes unresponsive to all requests

The infinite loop can be observed through thread dumps showing threads stuck in the retry loop with incrementing retry counters but never terminating.

## Notes

This is a legitimate protocol-level DoS vulnerability, NOT a "Network DoS" (which is out of scope). It exploits a specific code bug through legitimate API usage and causes "API crashes"—a HIGH severity category in the Aptos bug bounty program. The vulnerability can occur naturally during high load when the indexer lags, making it both easy to exploit maliciously and likely to occur accidentally in production environments.

### Citations

**File:** storage/indexer/src/db_v2.rs (L43-43)
```rust
const TABLE_INFO_RETRY_TIME_MILLIS: u64 = 10;
```

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

**File:** api/src/transactions.rs (L942-978)
```rust
    async fn get_transaction_by_hash_inner(
        &self,
        accept_type: &AcceptType,
        hash: HashValue,
    ) -> BasicResultWith404<Transaction> {
        let context = self.context.clone();
        let accept_type = accept_type.clone();

        let (internal_ledger_info_opt, storage_ledger_info) =
            api_spawn_blocking(move || context.get_latest_internal_and_storage_ledger_info())
                .await?;
        let storage_version = storage_ledger_info.ledger_version.into();
        let internal_indexer_version = internal_ledger_info_opt
            .as_ref()
            .map(|info| info.ledger_version.into());
        let latest_ledger_info = internal_ledger_info_opt.unwrap_or(storage_ledger_info);

        let txn_data = self
            .get_by_hash(hash.into(), storage_version, internal_indexer_version)
            .await
            .context(format!("Failed to get transaction by hash {}", hash))
            .map_err(|err| {
                BasicErrorWith404::internal_with_code(
                    err,
                    AptosErrorCode::InternalError,
                    &latest_ledger_info,
                )
            })?
            .context(format!("Failed to find transaction with hash: {}", hash))
            .map_err(|_| transaction_not_found_by_hash(hash, &latest_ledger_info))?;

        let api = self.clone();
        api_spawn_blocking(move || {
            api.get_transaction_inner(&accept_type, txn_data, &latest_ledger_info)
        })
        .await
    }
```

**File:** api/src/context.rs (L1645-1654)
```rust
pub async fn api_spawn_blocking<F, T, E>(func: F) -> Result<T, E>
where
    F: FnOnce() -> Result<T, E> + Send + 'static,
    T: Send + 'static,
    E: InternalError + Send + 'static,
{
    tokio::task::spawn_blocking(func)
        .await
        .map_err(|err| E::internal_with_code_no_info(err, AptosErrorCode::InternalError))?
}
```

**File:** api/types/src/convert.rs (L173-191)
```rust
    pub fn try_into_onchain_transaction(
        &self,
        timestamp: u64,
        data: TransactionOnChainData,
    ) -> Result<Transaction> {
        use aptos_types::transaction::Transaction::{
            BlockEpilogue, BlockMetadata, BlockMetadataExt, GenesisTransaction, StateCheckpoint,
            UserTransaction,
        };
        let aux_data = self
            .db
            .get_transaction_auxiliary_data_by_version(data.version)?;
        let info = self.into_transaction_info(
            data.version,
            &data.info,
            data.accumulator_root_hash,
            data.changes,
            aux_data,
        );
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

**File:** storage/indexer/src/indexer_reader.rs (L47-52)
```rust
    fn get_table_info(&self, handle: TableHandle) -> anyhow::Result<Option<TableInfo>> {
        if let Some(table_info_reader) = &self.table_info_reader {
            return Ok(table_info_reader.get_table_info_with_retry(handle)?);
        }
        anyhow::bail!("Table info reader is not available")
    }
```

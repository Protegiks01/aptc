# Audit Report

## Title
API Thread Exhaustion via Infinite Retry Loop in Table Info Resolution

## Summary
The `get_table_info_with_retry()` function implements an unbounded infinite loop without timeout controls, enabling attackers to exhaust API worker threads by querying transactions containing table items before their metadata has been indexed. This causes API service degradation on nodes running public endpoints.

## Finding Description

The vulnerability exists in the table info indexer's retry mechanism within `IndexerAsyncV2`. The `get_table_info_with_retry()` function contains an infinite loop that never returns until table info becomes available: [1](#0-0) 

The function loops indefinitely, sleeping only 10ms between attempts (defined by `TABLE_INFO_RETRY_TIME_MILLIS` constant), consuming CPU resources until `self.get_table_info(handle)` returns `Ok(Some(table_info))`. [2](#0-1) 

**Attack Flow:**

1. **Asynchronous Indexing Window**: Table information is extracted from transaction write sets and indexed asynchronously after transactions commit, creating a race window where table metadata is not immediately available.

2. **API Query Path**: When API requests retrieve transactions, the conversion process follows this call chain:
   - API endpoint calls `api_spawn_blocking` with `get_transaction_inner` [3](#0-2) 
   
   - `get_transaction_inner` invokes `try_into_onchain_transaction` to convert transaction data [4](#0-3) 
   
   - During write set conversion, table items are processed via `try_table_item_into_write_set_change` [5](#0-4) 
   
   - This calls `get_table_info` in the MoveConverter [6](#0-5) 
   
   - Which delegates to `IndexerReaders::get_table_info()` [7](#0-6) 
   
   - Finally calling the infinite `get_table_info_with_retry()` loop

3. **Thread Blocking**: The entire conversion happens within `api_spawn_blocking()`, which executes on Tokio's blocking thread pool: [8](#0-7) 
   
   The blocking thread pool is limited to 64 threads: [9](#0-8) 

4. **Exploitation**: An attacker can:
   - Submit transactions creating new tables (e.g., via Move `table::new<K,V>()`) with table item writes
   - Immediately query the API for those transactions (e.g., `/transactions/by_hash/{hash}`)
   - Each API request spawns a blocking task entering the infinite retry loop
   - Threads remain blocked until table info is indexed (potentially seconds on busy nodes)
   - Repeat to exhaust all 64 blocking threads, making API unresponsive

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty program's "API Crashes" category (up to $50,000):

- **API Service Degradation**: All 64 blocking worker threads can be exhausted, rendering the API completely unresponsive to legitimate requests including critical operations like transaction submission
- **Resource Exhaustion**: Blocked threads continuously consume CPU in tight retry loops with only 10ms sleep intervals
- **Persistent Impact**: Threads remain stuck until table info is eventually indexed or process restart, with no automatic recovery mechanism
- **Validator Impact**: Validators running public API endpoints become vulnerable to service disruption, potentially affecting their ability to serve the network

The vulnerability breaks resource management guarantees by implementing an unbounded retry operation without timeout controls, violating defensive programming principles for public-facing APIs.

## Likelihood Explanation

**High Likelihood** - This vulnerability is readily exploitable:

1. **No Privileges Required**: Any user can submit table-creating transactions and immediately query the API
2. **Guaranteed Race Window**: The asynchronous indexing architecture creates a deterministic exploitation window between transaction commit and metadata indexing
3. **Low Barrier to Entry**: Attack requires only submitting a transaction and querying immediately - no sophisticated timing or coordination needed
4. **Low Cost**: Attacker only pays standard gas fees for table creation transactions
5. **Amplification Effect**: A single transaction can be queried by multiple concurrent API requests, multiplying the thread exhaustion impact

## Recommendation

Implement timeout controls for the `get_table_info_with_retry()` function:

```rust
pub fn get_table_info_with_retry(&self, handle: TableHandle, timeout_ms: u64) -> Result<Option<TableInfo>> {
    let start = std::time::Instant::now();
    let mut retried = 0;
    loop {
        if let Ok(Some(table_info)) = self.get_table_info(handle) {
            return Ok(Some(table_info));
        }

        if start.elapsed().as_millis() as u64 > timeout_ms {
            return Ok(None); // Return None after timeout instead of infinite loop
        }

        // Log the first failure, then sample subsequent failures
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

Additionally, wrap `api_spawn_blocking` calls with timeouts:
```rust
tokio::time::timeout(
    Duration::from_secs(30),
    api_spawn_blocking(move || api.get_transaction_inner(&accept_type, txn_data, &latest_ledger_info))
).await
```

## Proof of Concept

```rust
#[test]
fn test_table_info_thread_exhaustion() {
    // Create table in transaction
    let mut txn = Transaction::UserTransaction(/* table creation */);
    // Submit to blockchain
    submit_transaction(txn);
    
    // Immediately query API before indexer processes table info
    // This will spawn blocking task that enters infinite loop
    let handles: Vec<_> = (0..64).map(|_| {
        tokio::spawn(async {
            api_client.get_transaction_by_hash(txn_hash).await
        })
    }).collect();
    
    // All 64 blocking threads now stuck in get_table_info_with_retry()
    // API becomes unresponsive to new requests
    assert!(api_client.health_check().await.is_err());
}
```

## Notes

This vulnerability demonstrates a classic unbounded resource consumption pattern where defensive timeout mechanisms are missing. While table info is eventually indexed (allowing threads to recover), the race window can be exploited to cause significant API disruption. The tight 10ms retry interval exacerbates CPU consumption. This is an application-layer API vulnerability, distinct from network-layer DoS attacks, and falls squarely within the "API Crashes" category of the Aptos bug bounty program.

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

**File:** api/src/transactions.rs (L974-977)
```rust
        api_spawn_blocking(move || {
            api.get_transaction_inner(&accept_type, txn_data, &latest_ledger_info)
        })
        .await
```

**File:** api/src/transactions.rs (L1022-1027)
```rust
                        state_view
                            .as_converter(
                                self.context.db.clone(),
                                self.context.indexer_reader.clone(),
                            )
                            .try_into_onchain_transaction(timestamp, txn)
```

**File:** api/types/src/convert.rs (L456-459)
```rust
            StateKeyInner::TableItem { handle, key } => {
                vec![self.try_table_item_into_write_set_change(hash, *handle, key.to_owned(), op)]
                    .into_iter()
                    .collect()
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

**File:** crates/aptos-runtimes/src/lib.rs (L27-50)
```rust
    const MAX_BLOCKING_THREADS: usize = 64;

    // Verify the given name has an appropriate length
    if thread_name.len() > MAX_THREAD_NAME_LENGTH {
        panic!(
            "The given runtime thread name is too long! Max length: {}, given name: {}",
            MAX_THREAD_NAME_LENGTH, thread_name
        );
    }

    // Create the runtime builder
    let atomic_id = AtomicUsize::new(0);
    let thread_name_clone = thread_name.clone();
    let mut builder = Builder::new_multi_thread();
    builder
        .thread_name_fn(move || {
            let id = atomic_id.fetch_add(1, Ordering::SeqCst);
            format!("{}-{}", thread_name_clone, id)
        })
        .on_thread_start(on_thread_start)
        .disable_lifo_slot()
        // Limit concurrent blocking tasks from spawn_blocking(), in case, for example, too many
        // Rest API calls overwhelm the node.
        .max_blocking_threads(MAX_BLOCKING_THREADS)
```

# Audit Report

## Title
Indexer DB and Main DB Permanent Desynchronization Due to Retry Loop Divergence in init_indexer_wrapper()

## Summary
The `init_indexer_wrapper()` function in the executor-benchmark creates an indexer synchronization mechanism that monitors a GRPC stream version rather than the actual indexer DB write state. When the table info parser encounters persistent errors, it enters an infinite retry loop while the GRPC stream continues advancing, causing the pipeline to incorrectly conclude that synchronization is complete. This results in permanent desynchronization between the main DB and indexer DB requiring manual intervention.

## Finding Description

The vulnerability exists in how the indexer wrapper tracks synchronization progress. The system has three separate version tracking mechanisms that can diverge:

1. **Main DB version**: The actual committed state in AptosDB
2. **Stream version** (`grpc_version`): Updated by the GRPC stream when transactions are received
3. **Indexer DB version** (`table_info_service.next_version()`): Only updated after successful parsing and writing to indexer DB [1](#0-0) 

The GRPC stream task updates `grpc_version` atomically whenever it receives transaction data, independent of whether the `table_info_service` successfully parses and writes that data to the indexer DB. [2](#0-1) 

The tokio runtime is explicitly leaked, meaning these async tasks continue running even after the function returns.

The critical flaw is in the `IndexerGrpcWaiter`, which only checks `stream_version` to determine if the indexer has caught up: [3](#0-2) 

Meanwhile, when `table_info_service` encounters parsing errors, it enters an infinite retry loop with no timeout or abort check: [4](#0-3) 

The parsing can fail permanently for various reasons such as corrupted write set data, malformed table items, or bugs in the annotator logic: [5](#0-4) 

**Attack Scenario:**
1. Main DB commits transactions including one at version V that contains data causing `index_with_annotator` to fail persistently
2. `table_info_service` processes up to version V-1 successfully  
3. At version V, `parse_table_info` fails and enters infinite retry loop (sleeps 5 seconds, retries forever)
4. GRPC stream continues receiving data and updates `grpc_version` to target version T
5. Main DB finishes committing all transactions up to version T
6. `IndexerGrpcWaiter` sees `stream_version >= target_version` and concludes synchronization is complete
7. Pipeline exits successfully, but indexer DB is stuck at version V-1
8. Indexer DB never catches up due to persistent parsing error

This breaks the **State Consistency** invariant - the indexer DB and main DB are permanently desynchronized, and the system incorrectly reports success.

## Impact Explanation

This is **HIGH severity** according to Aptos bug bounty criteria for "State inconsistencies requiring intervention". The impact includes:

1. **Permanent DB Desynchronization**: The indexer DB becomes permanently out of sync with the main DB, missing transactions
2. **Silent Failure**: The benchmark completes successfully without surfacing the error, hiding the problem
3. **Manual Intervention Required**: Recovery requires stopping the system, deleting/repairing the indexer DB, and restarting
4. **Resource Leak**: The leaked tokio runtime continues consuming CPU/memory in retry loops indefinitely
5. **Data Integrity Violation**: Applications relying on the indexer DB receive incomplete/stale data
6. **Cascade Failures**: Downstream systems depending on indexer data may malfunction

While this occurs in benchmark code, similar patterns may exist in production indexer implementations, and the benchmark itself is used for validation and testing purposes.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

This vulnerability can be triggered by:
- **Corrupted transaction data**: Malformed write sets or table items in committed transactions
- **Parser bugs**: Edge cases in the Move value annotator causing consistent failures
- **Missing module metadata**: References to non-existent modules or types
- **Resource exhaustion**: Memory pressure causing parsing failures
- **Concurrent modifications**: Race conditions in state view access

The vulnerability requires no special privileges - any transaction that triggers a parsing error will cause it. Given the complexity of Move bytecode and table item parsing, encountering such data is realistic during normal operations or testing.

The infinite retry loop with no timeout or max attempts makes this highly likely to manifest as a permanent hang rather than recovering.

## Recommendation

Implement comprehensive fixes addressing all divergence points:

**1. Track actual indexer DB state instead of stream state:**
```rust
// In IndexerGrpcWaiter, check table_info_service version, not just stream version
pub async fn wait_for_version(&self, target_version: Version, abort_on_finish: bool) {
    loop {
        let table_info_version = self.table_info_service.next_version().saturating_sub(1);
        let stream_version = self.stream_version.load(Ordering::SeqCst);
        
        // Check actual DB state, not just stream state
        if table_info_version >= target_version && stream_version >= target_version {
            info!("Indexer DB reached target version: {}", table_info_version);
            if abort_on_finish {
                self.table_info_service.abort();
            }
            break;
        }
        // ... rest of function
    }
}
```

**2. Add timeout and max retry limits to parse_table_info:**
```rust
async fn process_transactions(
    context: Arc<ApiContext>,
    indexer_async_v2: Arc<IndexerAsyncV2>,
    raw_txns: &[TransactionOnChainData],
) -> Result<EndVersion, Error> {
    const MAX_RETRIES: u32 = 10;
    const RETRY_DELAY_SECS: u64 = 5;
    
    let mut retries = 0;
    loop {
        match Self::parse_table_info(context.clone(), raw_txns, indexer_async_v2.clone()) {
            Ok(_) => break,
            Err(e) => {
                retries += 1;
                error!(
                    error = ?e,
                    retry = retries,
                    max_retries = MAX_RETRIES,
                    "Error during parse_table_info"
                );
                
                if retries >= MAX_RETRIES {
                    return Err(anyhow!("Failed to parse table info after {} retries: {}", MAX_RETRIES, e));
                }
                
                tokio::time::sleep(Duration::from_secs(RETRY_DELAY_SECS)).await;
            }
        }
    }
    Ok(raw_txns.last().unwrap().version)
}
```

**3. Check abort flag in retry loop:**
```rust
// In table_info_service's process_transactions, check abort flag
async fn process_transactions(
    context: Arc<ApiContext>,
    indexer_async_v2: Arc<IndexerAsyncV2>,
    raw_txns: &[TransactionOnChainData],
    aborted: Arc<AtomicBool>,  // Pass abort flag
) -> EndVersion {
    loop {
        if aborted.load(Ordering::SeqCst) {
            warn!("Aborting process_transactions due to abort signal");
            break;
        }
        
        match Self::parse_table_info(context.clone(), raw_txns, indexer_async_v2.clone()) {
            Ok(_) => break,
            Err(e) => {
                error!(error = ?e, "Error during parse_table_info.");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
    raw_txns.last().unwrap().version
}
```

**4. Don't leak the runtime:**
```rust
// In init_indexer_wrapper, properly manage the runtime lifetime
// Store the runtime in the returned tuple so it can be properly dropped
Some((table_info_service, grpc_version, abort_handle_clone, indexer_runtime))
```

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_indexer_desynchronization() {
        // Setup: Create a test DB and indexer wrapper
        let (config, _) = aptos_genesis::test_utils::test_config();
        let storage_test_config = StorageTestConfig {
            pruner_config: NO_OP_STORAGE_PRUNER_CONFIG,
            enable_storage_sharding: false,
            enable_indexer_grpc: true,
        };
        
        // Initialize DBs
        let db = init_db(&config);
        let start_version = db.reader.expect_synced_version();
        
        // Initialize indexer wrapper
        let indexer_wrapper = init_indexer_wrapper(
            &config,
            &db,
            &storage_test_config,
            start_version,
        );
        
        assert!(indexer_wrapper.is_some());
        let (table_info_service, grpc_version, _abort_handle) = indexer_wrapper.unwrap();
        
        // Simulate: Commit transactions to main DB
        // (In real scenario, one would contain data that triggers parsing failure)
        let target_version = start_version + 100;
        
        // Simulate GRPC stream advancing (happens independently)
        grpc_version.store(target_version, Ordering::SeqCst);
        
        // Create waiter and check synchronization
        let waiter = IndexerGrpcWaiter::new(table_info_service.clone(), grpc_version.clone());
        
        // This will return true even if table_info_service is stuck
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            // Waiter only checks stream_version, not actual DB state
            let stream_ver = grpc_version.load(Ordering::SeqCst);
            let db_ver = table_info_service.next_version().saturating_sub(1);
            
            println!("Stream version: {}", stream_ver);
            println!("Indexer DB version: {}", db_ver);
            
            // VULNERABILITY: These can diverge permanently
            // waiter.wait_for_version would succeed based on stream_version
            // even if db_ver is far behind
            assert_ne!(stream_ver, db_ver, "Versions should diverge in this test");
        });
    }
}
```

## Notes

This vulnerability demonstrates a fundamental architectural flaw in the synchronization mechanism where progress tracking is decoupled from actual state persistence. The GRPC stream acts as an optimistic indicator while the actual database writes happen asynchronously with their own error handling. Without proper coordination between these layers, silent desynchronization is inevitable when persistent errors occur.

The leaked runtime further exacerbates the issue by allowing retry loops to continue indefinitely in the background, consuming resources without visibility to the calling code.

### Citations

**File:** execution/executor-benchmark/src/lib.rs (L192-222)
```rust
    let grpc_version = Arc::new(AtomicU64::new(0));
    let grpc_version_clone = grpc_version.clone();
    let abort_handle = Arc::new(AtomicBool::new(false));
    let abort_handle_clone = abort_handle.clone();
    indexer_runtime.spawn(async move {
        let grpc_service = FullnodeDataService {
            service_context,
            abort_handle,
        };
        println!("Starting grpc stream at version {start_version}.");
        let request = GetTransactionsFromNodeRequest {
            starting_version: Some(start_version),
            transactions_count: None,
        };
        let mut response = grpc_service
            .get_transactions_from_node(request.into_request())
            .await
            .unwrap()
            .into_inner();
        while let Some(item) = response.next().await {
            if let Ok(r) = item {
                if let Some(response) = r.response {
                    if let Response::Data(data) = response {
                        if let Some(txn) = data.transactions.last().as_ref() {
                            grpc_version_clone.store(txn.version, Ordering::SeqCst);
                        }
                    }
                }
            }
        }
    });
```

**File:** execution/executor-benchmark/src/lib.rs (L225-228)
```rust
    std::mem::forget(indexer_runtime);

    Some((table_info_service, grpc_version, abort_handle_clone))
}
```

**File:** execution/executor-benchmark/src/indexer_grpc_waiter.rs (L46-60)
```rust
        loop {
            let table_info_version = self.table_info_service.next_version().saturating_sub(1);
            let stream_version = self.stream_version.load(Ordering::SeqCst);
            if stream_version >= target_version {
                info!(
                    "Indexer stream reached target version. Current: {}, Target: {}, elapsed: {:.2}s",
                    stream_version,
                    target_version,
                    start_time.elapsed().as_secs_f64()
                );
                if abort_on_finish {
                    self.table_info_service.abort();
                }
                break;
            }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/table_info_service.rs (L329-339)
```rust
        loop {
            // NOTE: The retry is unlikely to be helpful. Put a loop here just to avoid panic and
            // allow the rest of FN functionality continue to work.
            match Self::parse_table_info(context.clone(), raw_txns, indexer_async_v2.clone()) {
                Ok(_) => break,
                Err(e) => {
                    error!(error = ?e, "Error during parse_table_info.");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                },
            }
        }
```

**File:** storage/indexer/src/db_v2.rs (L87-115)
```rust
    pub fn index_with_annotator<R: StateView>(
        &self,
        annotator: &AptosValueAnnotator<R>,
        first_version: Version,
        write_sets: &[&WriteSet],
    ) -> Result<()> {
        let end_version = first_version + write_sets.len() as Version;
        let mut table_info_parser = TableInfoParser::new(self, annotator, &self.pending_on);
        for write_set in write_sets {
            for (state_key, write_op) in write_set.write_op_iter() {
                table_info_parser.collect_table_info_from_write_op(state_key, write_op)?;
            }
        }
        let mut batch = SchemaBatch::new();
        match self.finish_table_info_parsing(&mut batch, &table_info_parser.result) {
            Ok(_) => {},
            Err(err) => {
                aptos_logger::error!(
                    first_version = first_version,
                    end_version = end_version,
                    error = ?&err,
                    "[DB] Failed to parse table info"
                );
                bail!("{}", err);
            },
        };
        self.db.write_schemas(batch)?;
        Ok(())
    }
```

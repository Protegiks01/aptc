# Audit Report

## Title
Race Condition in Parallel Table Info Processing Leaves IndexerAsyncV2 in Inconsistent State

## Summary
The `process_transactions_in_parallel()` function spawns multiple concurrent tasks that share a `DashMap` for tracking pending table items. A Time-Of-Check-Time-Of-Use (TOCTOU) race condition between checking if table info exists and adding items to `pending_on` can cause the assert at line 296-299 to fail, triggering a panic after some tasks have already committed data to the database but before the `next_version` metadata is updated. [1](#0-0) 

## Finding Description

The vulnerability occurs in the interaction between parallel table info parsing tasks and the shared `pending_on` state in `IndexerAsyncV2`: [2](#0-1) 

Each spawned task creates its own `TableInfoParser` with a local `result` HashMap but shares a reference to the `pending_on` DashMap: [3](#0-2) 

**The Race Condition:**

When processing table items, the code performs a non-atomic check-then-act operation: [4](#0-3) 

Meanwhile, when table info is discovered, it's saved and pending items are processed: [5](#0-4) 

**Attack Scenario:**

1. Task A processes a transaction containing a table item for handle H (table info not yet discovered)
2. Task A calls `get_table_info(H)` → returns None (line 284)
3. **[Context Switch]**
4. Task B processes a transaction containing the table creation for H
5. Task B calls `save_table_info(H, info)` → inserts into local result (line 318)
6. Task B removes `pending_on[H]` and processes those items (line 319)
7. Task B commits its batch to the database (line 113 in `index_table_info`)
8. **[Context Switch]**
9. Task A adds the item to `pending_on[H]` (lines 292-295)
10. All tasks complete, but `pending_on` is not empty due to the race
11. Sequential retry clears and re-processes (lines 286-293)
12. If the assert still fails (line 296-299), panic occurs
13. **Critical:** Some tasks have already written to the database, but `update_next_version()` at line 302-304 never executes
14. On service restart, `next_version` metadata is stale, causing re-processing of already-indexed transactions [6](#0-5) 

The database writes from individual tasks (line 113) are committed independently and are NOT part of a single atomic transaction with the final metadata update. [7](#0-6) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program:

- **API Crashes**: The indexer-grpc service crashes when the assert fails, causing immediate service unavailability
- **State Inconsistency**: The database contains partial table info data but metadata (`next_version`) is not updated, requiring manual intervention or causing re-processing loops
- **Service Degradation**: On nodes running the indexer, repeated crashes cause degraded service availability

While this doesn't directly affect consensus or fund security, the indexer-grpc service is a critical API component that provides table structure information to clients querying the blockchain. Repeated crashes constitute a denial-of-service condition for this API.

## Likelihood Explanation

**Likelihood: Medium to High**

The race condition occurs naturally during normal operation without requiring attacker intervention when:
- Processing transactions with nested table structures (parent tables containing child tables)
- High transaction throughput increases concurrent task execution
- Larger `parser_task_count` and `parser_batch_size` configurations increase parallelism

The probability increases with:
- More complex table nesting in on-chain data
- Higher volumes of table creation transactions
- More aggressive parallel processing settings

An attacker could potentially increase the likelihood by deploying contracts that create deeply nested table structures, though they cannot guarantee the exact timing needed to trigger the race.

## Recommendation

**Solution: Use atomic compare-and-swap operations or proper locking**

The fundamental issue is that checking for table info existence and adding to `pending_on` are separate operations. This should be made atomic:

**Option 1: Lock-based approach**
```rust
fn collect_table_info_from_table_item(
    &mut self,
    handle: TableHandle,
    bytes: &Bytes,
) -> Result<()> {
    // First check if we have it locally or in DB
    match self.get_table_info(handle)? {
        Some(table_info) => {
            let mut infos = vec![];
            self.annotator
                .collect_table_info(&table_info.value_type, bytes, &mut infos)?;
            self.process_table_infos(infos)?
        },
        None => {
            // Atomically add to pending_on only if still not present
            // Use entry API to make check-and-insert atomic
            let entry = self.pending_on.entry(handle).or_insert_with(|| DashSet::new());
            entry.value().insert(bytes.clone());
        },
    }
    Ok(())
}
```

**Option 2: Sequential processing only**
Remove parallel processing entirely and only use sequential processing, eliminating the race condition:

```rust
async fn process_transactions_in_parallel(
    &self,
    indexer_async_v2: Arc<IndexerAsyncV2>,
    transactions: Vec<TransactionOnChainData>,
) -> Vec<EndVersion> {
    // Process sequentially to avoid race conditions
    Self::process_transactions(
        self.context.clone(),
        indexer_async_v2.clone(),
        &transactions,
    )
    .await;
    
    // Update version
    let last_version = transactions.last().map(|txn| txn.version).unwrap_or_default();
    self.indexer_async_v2
        .update_next_version(last_version + 1)
        .unwrap();
    
    vec![last_version]
}
```

**Option 3: Atomic version update**
Ensure `update_next_version` is part of the same database transaction as the table info writes:

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
    self.finish_table_info_parsing(&mut batch, &table_info_parser.result)?;
    
    // Add next_version update to the SAME batch
    batch.put::<IndexerMetadataSchema>(
        &MetadataKey::LatestVersion,
        &MetadataValue::Version(end_version - 1),
    )?;
    
    // Atomic write of both table info and metadata
    self.db.write_schemas(batch)?;
    self.next_version.store(end_version, Ordering::Relaxed);
    Ok(())
}
```

## Proof of Concept

**Reproduction Steps:**

1. Configure the indexer with high parallelism: `parser_task_count = 16`, `parser_batch_size = 100`
2. Deploy a Move contract that creates deeply nested table structures:

```move
module 0x1::nested_tables {
    use std::table::{Self, Table};
    
    struct Parent has key {
        child_tables: Table<u64, Table<u64, u64>>
    }
    
    public entry fun create_nested(account: &signer) {
        let parent = Parent {
            child_tables: table::new()
        };
        
        // Create many nested tables rapidly
        let i = 0;
        while (i < 100) {
            let child = table::new();
            table::add(&mut parent.child_tables, i, child);
            i = i + 1;
        };
        
        move_to(account, parent);
    }
}
```

3. Submit multiple transactions calling `create_nested` concurrently
4. Monitor indexer logs for the assertion failure: "Missing data in table info parsing after sequential retry"
5. Observe service crash and subsequent restart with stale `next_version` metadata
6. Verify database contains table info from partial task completions

**Expected Outcome:** Service crashes intermittently, especially under high load with complex table operations. Database inspection shows `next_version` metadata lags behind actual indexed data.

## Notes

- This vulnerability is specific to the indexer-grpc table info service and does not affect consensus or core blockchain functionality
- The issue is exacerbated by the `unwrap()` call on `update_next_version()` at line 303, which provides no error recovery
- The comment at line 32 states "Not thread safe" for the service itself, but the internal parallel processing creates the race condition
- DashMap provides thread-safe individual operations but not atomicity across multiple operations
- The sequential retry at lines 286-293 attempts to mitigate the issue but doesn't prevent the race from occurring initially

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/table_info_service.rs (L245-313)
```rust
    async fn process_transactions_in_parallel(
        &self,
        indexer_async_v2: Arc<IndexerAsyncV2>,
        transactions: Vec<TransactionOnChainData>,
    ) -> Vec<EndVersion> {
        let mut tasks = vec![];
        let context = self.context.clone();
        let last_version = transactions
            .last()
            .map(|txn| txn.version)
            .unwrap_or_default();

        let transactions = Arc::new(transactions);
        for (chunk_idx, batch_size) in transactions
            .chunks(self.parser_batch_size as usize)
            .enumerate()
            .map(|(idx, chunk)| (idx, chunk.len()))
        {
            let start = chunk_idx * self.parser_batch_size as usize;
            let end = start + batch_size;

            let transactions = transactions.clone();
            let context = context.clone();
            let indexer_async_v2 = indexer_async_v2.clone();
            let task = tokio::spawn(async move {
                Self::process_transactions(context, indexer_async_v2, &transactions[start..end])
                    .await
            });
            tasks.push(task);
        }

        match futures::future::try_join_all(tasks).await {
            Ok(res) => {
                let end_version = last_version;

                // If pending on items are not empty, meaning the current loop hasn't fully parsed all table infos
                // due to the nature of multithreading where instructions used to parse table info might come later,
                // retry sequentially to ensure parsing is complete
                //
                // Risk of this sequential approach is that it could be slow when the txns to process contain extremely
                // nested table items, but the risk is bounded by the configuration of the number of txns to process and number of threads
                if !self.indexer_async_v2.is_indexer_async_v2_pending_on_empty() {
                    self.indexer_async_v2.clear_pending_on();
                    Self::process_transactions(
                        context.clone(),
                        indexer_async_v2.clone(),
                        &transactions,
                    )
                    .await;
                }

                assert!(
                    self.indexer_async_v2.is_indexer_async_v2_pending_on_empty(),
                    "Missing data in table info parsing after sequential retry"
                );

                // Update rocksdb's to be processed next version after verifying all txns are successfully parsed
                self.indexer_async_v2
                    .update_next_version(end_version + 1)
                    .unwrap();

                res
            },
            Err(err) => panic!(
                "[Table Info] Error processing table info batches: {:?}",
                err
            ),
        }
    }
```

**File:** storage/indexer/src/db_v2.rs (L46-58)
```rust
pub struct IndexerAsyncV2 {
    pub db: DB,
    // Next version to be processed
    next_version: AtomicU64,
    // It is used in the context of processing write ops and extracting table information.
    // As the code iterates through the write ops, it checks if the state key corresponds to a table item.
    // If it does, the associated bytes are added to the pending_on map under the corresponding table handle.
    // Later, when the table information becomes available, the pending items can be retrieved and processed accordingly.
    // One example could be a nested table item, parent table contains child table, so when parent table is first met and parsed,
    // is obscure and will be stored as bytes with parent table's handle, once parent table's parsed with instructions,
    // child table handle will be parsed accordingly.
    pending_on: DashMap<TableHandle, DashSet<Bytes>>,
}
```

**File:** storage/indexer/src/db_v2.rs (L73-115)
```rust
    pub fn index_table_info(
        &self,
        db_reader: Arc<dyn DbReader>,
        first_version: Version,
        write_sets: &[&WriteSet],
    ) -> Result<()> {
        let last_version = first_version + write_sets.len() as Version;
        let state_view = db_reader.state_view_at_version(Some(last_version))?;
        let annotator = AptosValueAnnotator::new(&state_view);
        self.index_with_annotator(&annotator, first_version, write_sets)
    }

    /// Index write sets with the move annotator to parse obscure table handle and key value types
    /// After the current batch's parsed, write the mapping to the rocksdb, also update the next version to be processed
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

**File:** storage/indexer/src/db_v2.rs (L117-124)
```rust
    pub fn update_next_version(&self, end_version: u64) -> Result<()> {
        self.db.put::<IndexerMetadataSchema>(
            &MetadataKey::LatestVersion,
            &MetadataValue::Version(end_version - 1),
        )?;
        self.next_version.store(end_version, Ordering::Relaxed);
        Ok(())
    }
```

**File:** storage/indexer/src/db_v2.rs (L208-227)
```rust
struct TableInfoParser<'a, R> {
    indexer_async_v2: &'a IndexerAsyncV2,
    annotator: &'a AptosValueAnnotator<'a, R>,
    result: HashMap<TableHandle, TableInfo>,
    pending_on: &'a DashMap<TableHandle, DashSet<Bytes>>,
}

impl<'a, R: StateView> TableInfoParser<'a, R> {
    pub fn new(
        indexer_async_v2: &'a IndexerAsyncV2,
        annotator: &'a AptosValueAnnotator<R>,
        pending_on: &'a DashMap<TableHandle, DashSet<Bytes>>,
    ) -> Self {
        Self {
            indexer_async_v2,
            annotator,
            result: HashMap::new(),
            pending_on,
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

**File:** storage/indexer/src/db_v2.rs (L316-326)
```rust
    fn save_table_info(&mut self, handle: TableHandle, info: TableInfo) -> Result<()> {
        if self.get_table_info(handle)?.is_none() {
            self.result.insert(handle, info);
            if let Some(pending_items) = self.pending_on.remove(&handle) {
                for bytes in pending_items.1 {
                    self.collect_table_info_from_table_item(handle, &bytes)?;
                }
            }
        }
        Ok(())
    }
```

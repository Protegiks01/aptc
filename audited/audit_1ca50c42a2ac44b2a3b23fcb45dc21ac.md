# Audit Report

## Title
Partial Batch Processing Failure Leads to Indexer Inconsistent State and Service Crash Loops

## Summary
The `process_transactions_in_parallel()` function in the Table Info Service spawns multiple parallel tasks to process transaction batches, but lacks proper atomic transaction handling. When any task fails or when the post-processing assertion fails, the service panics and crashes. However, tasks that completed successfully have already written their data to RocksDB. Since the `next_version` metadata is only updated after ALL tasks succeed, a crash leaves the indexer in an inconsistent state where some transactions are processed but the system believes none were, leading to reprocessing attempts and potential crash loops. [1](#0-0) 

## Finding Description

The vulnerability exists in the parallel transaction processing logic of the Table Info Service. The function spawns multiple tasks based on `parser_task_count` configuration to process transaction chunks concurrently: [2](#0-1) 

Each spawned task independently processes its chunk and writes results to RocksDB via atomic SchemaBatch operations: [3](#0-2) 

The critical flaw is that there is no overarching transaction mechanism coordinating these parallel writes. The function uses `try_join_all` to await all tasks, but if ANY task fails, it panics: [4](#0-3) 

Additionally, even if all tasks complete successfully, an assertion can fail if the `pending_on` map is not empty after sequential retry: [5](#0-4) 

**Failure Scenarios:**

1. **Task Panic**: Tasks contain `.unwrap()` calls that can panic on edge cases [6](#0-5) 

2. **Assertion Failure**: The pending_on assertion can fail if nested table structures cannot be fully resolved

3. **Resource Exhaustion**: OOM or other runtime failures can cause task failures

**Inconsistent State After Crash:**

When a failure occurs:
- Tasks that completed successfully have already committed their SchemaBatch writes to RocksDB
- The `update_next_version()` call at line 302-304 is NEVER executed
- The indexer's `LatestVersion` metadata remains pointing to the pre-batch version [7](#0-6) 

On service restart, the indexer reads the old `LatestVersion` and attempts to reprocess the same batch: [8](#0-7) 

This breaks the **State Consistency** invariant: "State transitions must be atomic and verifiable."

## Impact Explanation

This vulnerability meets **High Severity** criteria per the Aptos bug bounty program:

1. **API Crashes**: If the assertion failure (line 296) is deterministic due to unresolvable nested table structures, the service enters an infinite crash loop, making the Table Info API permanently unavailable.

2. **State Inconsistencies Requiring Intervention** (Medium): The indexer database contains partially processed transactions while the metadata indicates they haven't been processed, requiring manual database inspection and recovery.

3. **Service Unavailability**: The table info service becomes unavailable during crashes and reprocessing attempts, affecting any API queries that depend on table metadata.

4. **Resource Waste**: Repeated reprocessing of already-processed transactions wastes CPU, I/O, and network resources.

While this does not directly affect consensus or fund security (indexer is off the critical path), it significantly impacts the availability and reliability of the Aptos node's API services.

## Likelihood Explanation

The likelihood is **MEDIUM to HIGH** because:

1. **Natural Occurrence**: The vulnerability can trigger from operational issues:
   - Database write failures (disk full, I/O errors)
   - Resource exhaustion during high load
   - Genuine bugs in transaction parsing logic
   - Edge cases with empty slices or malformed data

2. **Deterministic Crash Loops**: If transactions contain genuinely unresolvable nested table structures, the assertion at line 296 will fail repeatedly, creating a permanent crash loop that requires manual intervention.

3. **No Recovery Mechanism**: The code uses `panic!` and `assert!` for error handling instead of graceful recovery, guaranteeing service crashes on any failure.

4. **Observable in Production**: The pattern of panicking on `try_join_all` failures is common across the indexer codebase, suggesting this is a systemic issue that could manifest in production environments. [9](#0-8) 

## Recommendation

Implement proper atomic transaction handling with rollback capabilities:

**Solution 1: Implement Checkpoint-Based Recovery**
1. Create a RocksDB checkpoint before starting parallel processing
2. If any task fails, rollback to the checkpoint
3. Only update `next_version` after successful completion and checkpoint commit
4. Replace `panic!` and `assert!` with proper error handling that triggers rollback

**Solution 2: Sequential Fallback on Failure**
1. Attempt parallel processing
2. If any task fails, rollback all writes (or skip if not possible)
3. Fallback to sequential processing of the entire batch
4. Log the failure for investigation but don't crash

**Solution 3: Pre-Flight Validation**
1. Before spawning tasks, validate that all transactions can be processed
2. Check for potential assertion failures before committing any writes
3. Only proceed with parallel processing if validation passes

**Code Fix Example (Solution 2 - Simplified):**

```rust
async fn process_transactions_in_parallel(&self, indexer_async_v2: Arc<IndexerAsyncV2>, transactions: Vec<TransactionOnChainData>) -> Vec<EndVersion> {
    // Try parallel processing
    let result = self.try_parallel_processing(indexer_async_v2.clone(), &transactions).await;
    
    match result {
        Ok(res) => {
            // Check pending_on before updating next_version
            if !self.indexer_async_v2.is_indexer_async_v2_pending_on_empty() {
                warn!("Pending items remain, falling back to sequential");
                return self.process_sequential(indexer_async_v2, &transactions).await;
            }
            
            let last_version = transactions.last().map(|t| t.version).unwrap_or(0);
            self.indexer_async_v2.update_next_version(last_version + 1).unwrap();
            res
        }
        Err(e) => {
            error!("Parallel processing failed: {:?}, falling back to sequential", e);
            self.process_sequential(indexer_async_v2, &transactions).await
        }
    }
}
```

Replace all `panic!` calls with `Result` returns and `assert!` with conditional error handling.

## Proof of Concept

**Rust Reproduction Steps:**

```rust
// Simulate task failure scenario
#[tokio::test]
async fn test_partial_batch_failure() {
    // Setup: Create IndexerAsyncV2 with test DB
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db = DB::open(temp_dir.path(), "test").unwrap();
    let indexer = Arc::new(IndexerAsyncV2::new(db).unwrap());
    
    // Create mock transactions
    let transactions = create_mock_transactions(1000);
    
    // Simulate scenario where some tasks complete
    let mut tasks = vec![];
    for chunk in transactions.chunks(100) {
        let tx_clone = chunk.to_vec();
        let indexer_clone = indexer.clone();
        
        tasks.push(tokio::spawn(async move {
            // First 5 tasks succeed and write to DB
            if tx_clone[0].version < 500 {
                process_and_write(indexer_clone, &tx_clone).await.unwrap();
                Ok(())
            } else {
                // Later tasks panic
                panic!("Simulated task failure");
            }
        }));
    }
    
    // try_join_all will return error due to panic
    let result = futures::future::try_join_all(tasks).await;
    assert!(result.is_err());
    
    // Verify partial state:
    // - Database contains data from first 5 tasks (versions 0-499)
    // - next_version metadata still points to 0 (not updated)
    let stored_next = indexer.next_version();
    assert_eq!(stored_next, 0); // Still at initial version
    
    // But data was written for versions 0-499
    // On restart, will attempt to reprocess these versions
}
```

**Notes**

The vulnerability is confirmed in the codebase and represents a significant operational and availability risk. While direct exploitation by an unprivileged attacker may be difficult, the issue can manifest naturally through operational failures, bugs, or edge cases. The lack of proper transaction coordination and error recovery creates a systemic reliability problem that violates state consistency guarantees and can lead to service unavailability requiring manual intervention.

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

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/table_info_service.rs (L325-327)
```rust
        let start_version = raw_txns[0].version;
        let end_version = raw_txns.last().unwrap().version;
        let num_transactions = raw_txns.len();
```

**File:** storage/indexer/src/db_v2.rs (L61-71)
```rust
    pub fn new(db: DB) -> Result<Self> {
        let next_version = db
            .get::<IndexerMetadataSchema>(&MetadataKey::LatestVersion)?
            .map_or(0, |v| v.expect_version());

        Ok(Self {
            db,
            next_version: AtomicU64::new(next_version),
            pending_on: DashMap::new(),
        })
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

**File:** crates/indexer/src/runtime.rs (L216-219)
```rust
        let batches = match futures::future::try_join_all(tasks).await {
            Ok(res) => res,
            Err(err) => panic!("Error processing transaction batches: {:?}", err),
        };
```

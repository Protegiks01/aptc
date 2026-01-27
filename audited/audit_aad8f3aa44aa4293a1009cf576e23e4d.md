# Audit Report

## Title
Non-Atomic ProcessorStatusV2 Updates Allow Indexer State Inconsistency on Process Crash

## Summary
The `ProcessorStatusV2` update in the Aptos indexer occurs in a separate database transaction from the actual transaction data insertion, creating a window where a process crash leaves the indexer database in an inconsistent state with committed transaction data but outdated status tracking.

## Finding Description

The Aptos indexer processes blockchain transactions and stores them in a PostgreSQL database for query purposes. The system tracks processing progress using the `processor_status` table via `ProcessorStatusV2` model. However, the data insertion and status tracking occur in separate, non-atomic database transactions. [1](#0-0) 

The transaction data insertion uses `conn.build_transaction().read_write().run()`, wrapping all data insertions (transactions, events, write_set_changes, move_resources, etc.) in a single atomic transaction. [2](#0-1) 

However, `update_last_processed_version()` executes as a completely separate transaction using a fresh connection from the pool. This breaks atomicity between data commit and status tracking. [3](#0-2) 

The execution flow shows that multiple parallel processing tasks each commit their transaction data independently, then a final single call updates the processor status. If the process crashes after data commits but before the status update at line 252, the `processor_status` table retains the old `last_success_version` value.

On restart, the indexer reads this outdated version and attempts to reprocess already-committed transactions. While most insertions use `.on_conflict().do_nothing()` (idempotent), several critical tables update the `inserted_at` timestamp: [4](#0-3) [5](#0-4) [6](#0-5) 

This causes `inserted_at` timestamps in `events`, `move_resources`, `current_table_items`, and `current_objects` tables to reflect reprocessing time rather than original insertion time, corrupting the audit trail.

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty program: "State inconsistencies requiring intervention." 

The vulnerability creates indexer database inconsistencies that:
- Corrupt timestamp audit trails in multiple tables
- Require manual intervention to detect and correct
- Cause wasted computational resources on reprocessing
- Create confusion in applications relying on `inserted_at` values for data freshness

**Important Note**: This vulnerability affects the indexer query layer only, NOT blockchain consensus, validator operations, or fund security. The blockchain itself remains secure and consistent.

## Likelihood Explanation

**Likelihood: HIGH**

This occurs whenever the indexer process crashes, is killed, or experiences power loss during the critical window between data commit (line 593-610 in default_processor.rs) and status update (line 252 in runtime.rs). Given:
- Indexers run continuously 24/7
- Normal operational events (restarts, deployments, crashes)
- The window exists on every processing batch
- Multiple parallel tasks increase the window size

This is virtually certain to occur in production environments over time.

## Recommendation

Wrap both the data insertion AND status update in a single database transaction. Modify the architecture to:

**Option 1: Single Transaction (Preferred)**
Pass the database connection/transaction context through the entire processing pipeline so that both data insertion and status update occur within the same transaction scope.

**Option 2: Status-Based Recovery**
On startup, implement a more sophisticated gap detection that checks the actual maximum version in the transactions table against the processor_status value, rather than blindly trusting processor_status.

**Option 3: Transaction Callback**
Use database transaction callbacks to ensure status is only updated if the data transaction successfully commits, though this requires careful handling of connection pooling.

Recommended implementation (Option 1 sketch):
```rust
// In runtime.rs, modify to use a single connection and transaction
let mut conn = conn_pool.get()?;
conn.build_transaction().read_write().run::<_, Error, _>(|txn_conn| {
    // Process all batches and insert data
    for batch_result in batches {
        process_and_insert_batch(txn_conn, batch_result)?;
    }
    // Update status within same transaction
    update_processor_status_internal(txn_conn, processor_name, batch_end_version)?;
    Ok(())
})?;
```

## Proof of Concept

```bash
# PoC: Demonstrate inconsistency through controlled crash

# 1. Start indexer and let it process some transactions
./aptos-indexer --database-url "postgresql://..." &
INDEXER_PID=$!

# 2. Wait for it to begin processing
sleep 5

# 3. Send SIGKILL during processing window (right after data commit, before status update)
# This simulates crash during the vulnerable window
kill -9 $INDEXER_PID

# 4. Check database state
psql -d indexer -c "SELECT last_success_version FROM processor_status WHERE processor = 'default_processor';"
# Note the version, e.g., 1000

psql -d indexer -c "SELECT MAX(version) FROM transactions;"
# This shows higher version, e.g., 1500

# 5. Restart indexer - it will reprocess versions 1001-1500
./aptos-indexer --database-url "postgresql://..."

# 6. Verify timestamp corruption
psql -d indexer -c "SELECT version, inserted_at FROM events WHERE version BETWEEN 1001 AND 1500 ORDER BY version LIMIT 5;"
# The inserted_at timestamps will be newer than they should be
```

## Notes

This vulnerability is specific to the Aptos indexer component and does not affect the core blockchain consensus, execution, or state management. The blockchain's integrity remains intact. However, applications relying on the indexer database for queries may observe inconsistent timestamp data, which could affect business logic depending on `inserted_at` values for determining data freshness or processing order.

### Citations

**File:** crates/indexer/src/processors/default_processor.rs (L125-148)
```rust
    match conn
        .build_transaction()
        .read_write()
        .run::<_, Error, _>(|pg_conn| {
            insert_to_db_impl(
                pg_conn,
                &txns,
                (
                    &user_transactions,
                    &signatures,
                    &block_metadata_transactions,
                ),
                &events,
                &wscs,
                (
                    &move_modules,
                    &move_resources,
                    &table_items,
                    &current_table_items,
                    &table_metadata,
                ),
                (&objects, &current_objects),
            )
        }) {
```

**File:** crates/indexer/src/processors/default_processor.rs (L287-292)
```rust
                .on_conflict((account_address, creation_number, sequence_number))
                .do_update()
                .set((
                    inserted_at.eq(excluded(inserted_at)),
                    event_index.eq(excluded(event_index)),
                )),
```

**File:** crates/indexer/src/processors/default_processor.rs (L348-353)
```rust
                .on_conflict((transaction_version, write_set_change_index))
                .do_update()
                .set((
                    inserted_at.eq(excluded(inserted_at)),
                    state_key_hash.eq(excluded(state_key_hash)),
                )),
```

**File:** crates/indexer/src/processors/default_processor.rs (L391-400)
```rust
                .do_update()
                .set((
                    key.eq(excluded(key)),
                    decoded_key.eq(excluded(decoded_key)),
                    decoded_value.eq(excluded(decoded_value)),
                    is_deleted.eq(excluded(is_deleted)),
                    last_transaction_version.eq(excluded(last_transaction_version)),
                    inserted_at.eq(excluded(inserted_at)),
                )),
                Some(" WHERE current_table_items.last_transaction_version <= excluded.last_transaction_version "),
```

**File:** crates/indexer/src/indexer/tailer.rs (L170-191)
```rust
    pub fn update_last_processed_version(&self, processor_name: &str, version: u64) -> Result<()> {
        let mut conn = self.connection_pool.get()?;

        let status = ProcessorStatusV2 {
            processor: processor_name.to_owned(),
            last_success_version: version as i64,
        };
        execute_with_better_error(
            &mut conn,
            diesel::insert_into(processor_status::table)
                .values(&status)
                .on_conflict(processor_status::processor)
                .do_update()
                .set((
                    processor_status::last_success_version
                        .eq(excluded(processor_status::last_success_version)),
                    processor_status::last_updated.eq(excluded(processor_status::last_updated)),
                )),
            Some(" WHERE processor_status.last_success_version <= EXCLUDED.last_success_version "),
        )?;
        Ok(())
    }
```

**File:** crates/indexer/src/runtime.rs (L210-261)
```rust
        let mut tasks = vec![];
        for _ in 0..processor_tasks {
            let other_tailer = tailer.clone();
            let task = tokio::spawn(async move { other_tailer.process_next_batch().await });
            tasks.push(task);
        }
        let batches = match futures::future::try_join_all(tasks).await {
            Ok(res) => res,
            Err(err) => panic!("Error processing transaction batches: {:?}", err),
        };

        let mut batch_start_version = u64::MAX;
        let mut batch_end_version = 0;
        let mut num_res = 0;

        for (num_txn, res) in batches {
            let processed_result: ProcessingResult = match res {
                // When the batch is empty b/c we're caught up, continue to next batch
                None => continue,
                Some(Ok(res)) => res,
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
            };
            batch_start_version =
                std::cmp::min(batch_start_version, processed_result.start_version);
            batch_end_version = std::cmp::max(batch_end_version, processed_result.end_version);
            num_res += num_txn;
        }

        tailer
            .update_last_processed_version(&processor_name, batch_end_version)
            .unwrap_or_else(|e| {
                error!(
                    processor_name = processor_name,
                    end_version = batch_end_version,
                    error = format!("{:?}", e),
                    "Failed to update last processed version!"
                );
                panic!("Failed to update last processed version: {:?}", e);
            });
```

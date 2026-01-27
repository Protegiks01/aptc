# Audit Report

## Title
Indexer Crash Due to Unhandled Block Height Collision on Database Re-insertion

## Summary
The Aptos indexer crashes when attempting to insert a `BlockMetadataTransaction` with a duplicate `block_height` value. The database schema enforces a UNIQUE constraint on `block_height`, but the insertion code only handles conflicts on `version`, not `block_height`. When a constraint violation occurs, the error propagates and causes the entire indexer process to panic and crash. [1](#0-0) 

## Finding Description

The `block_metadata_transactions` table has UNIQUE constraints on both `version` (primary key) and `block_height`. However, the insertion logic only handles conflicts for the `version` column: [2](#0-1) 

When two different transactions attempt insertion with the same `block_height` but different `version` values, PostgreSQL raises a UNIQUE constraint violation on the `block_height` column. This error is not caught by the `on_conflict(version)` clause, causing the database operation to fail.

The error propagates through the call stack and reaches the runtime's main processing loop, where it explicitly panics: [3](#0-2) 

**Attack Scenarios:**

1. **Re-indexing Without Database Cleanup**: An administrator restarts the indexer from an earlier version (e.g., version 500) without clearing the database that already contains blocks up to version 1000. The indexer will attempt to re-insert blocks with heights that already exist, causing immediate crash.

2. **Concurrent Indexer Instances**: Running multiple indexer processes against the same database can lead to race conditions where different transactions attempt to claim the same block height.

3. **Database State Inconsistency**: If the database contains stale or corrupted data from a previous run, legitimate indexing operations can trigger the constraint violation.

The block_height value is derived during transaction fetching from blockchain data and is tracked locally: [4](#0-3) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program's "API crashes" category (up to $50,000). 

The indexer is critical infrastructure that enables:
- Historical transaction queries
- Account balance lookups  
- Token and NFT tracking
- DApp data synchronization

When the indexer crashes:
- All API queries that depend on indexed data fail
- DApps lose access to critical blockchain history
- Monitoring and analytics systems become unavailable
- The entire indexer must be restarted manually

While this does not affect consensus or validator operations (the indexer is off-chain infrastructure), it causes significant service disruption to the Aptos ecosystem.

## Likelihood Explanation

**Likelihood: High**

This issue can easily occur in common operational scenarios:

1. **Re-indexing Operations**: When debugging issues or recovering from corruption, operators commonly restart indexing from earlier blocks. If the database isn't cleared, this immediately triggers the crash.

2. **Configuration Mistakes**: Setting the wrong `starting_version` in the indexer config while keeping the existing database causes instant failure.

3. **Database Restoration**: Restoring from an old backup while the indexer tries to continue from a newer version creates height collisions.

4. **Development/Testing**: Developers testing indexer code frequently encounter this when reusing databases.

The vulnerability requires no attacker action - it's triggered by normal operational procedures. The lack of proper conflict handling on `block_height` is a clear implementation oversight.

## Recommendation

**Fix**: Modify the `insert_block_metadata_transactions` function to handle conflicts on `block_height` in addition to `version`. Since both fields have UNIQUE constraints, both must be included in the conflict resolution:

```rust
fn insert_block_metadata_transactions(
    conn: &mut PgConnection,
    items_to_insert: &[BlockMetadataTransactionModel],
) -> Result<(), diesel::result::Error> {
    use schema::block_metadata_transactions::dsl::*;
    let chunks = get_chunks(
        items_to_insert.len(),
        BlockMetadataTransactionModel::field_count(),
    );
    for (start_ind, end_ind) in chunks {
        execute_with_better_error(
            conn,
            diesel::insert_into(schema::block_metadata_transactions::table)
                .values(&items_to_insert[start_ind..end_ind])
                .on_conflict(version)
                .do_nothing()
                .on_conflict(block_height)  // Add this
                .do_nothing(),              // Add this
            None,
        )?;
    }
    Ok(())
}
```

However, Diesel doesn't support multiple `on_conflict` clauses directly. A better approach is to use a composite conflict target or handle the error gracefully without panicking:

**Alternative Fix**: Catch and log the error instead of panicking: [5](#0-4) 

Replace the `panic!` with error logging and retry logic, or skip the conflicting batch and continue processing.

**Best Fix**: Modify the insertion to use proper conflict resolution on both constraints by restructuring the query or using raw SQL with `ON CONFLICT ON CONSTRAINT`.

## Proof of Concept

**Setup:**
1. Start an Aptos indexer and let it process blocks 0-100
2. Database now contains `block_metadata_transactions` with heights 0-100
3. Stop the indexer process

**Trigger:**
1. Configure indexer with `starting_version = 50`
2. Start the indexer without clearing the database
3. Indexer fetches block information starting from version 50
4. Attempts to insert block metadata with `block_height = 50` (or whatever height corresponds to version 50)
5. PostgreSQL returns: `ERROR: duplicate key value violates unique constraint "block_metadata_transactions_block_height_key"`
6. Error propagates through `insert_to_db` → `process_transactions` → runtime loop
7. Runtime panics with: `Error in 'default_processor' while processing batch: ...`
8. Indexer process terminates

**Verification Steps:**
```bash
# Terminal 1: Start indexer and index blocks 0-100
cargo run --bin aptos-indexer -- --config config.yaml

# Terminal 2: After some blocks are indexed, check database
psql -d aptos_indexer -c "SELECT COUNT(*) FROM block_metadata_transactions;"

# Stop indexer (Ctrl+C)

# Terminal 1: Restart with earlier starting_version
# Edit config.yaml: starting_version = 50
cargo run --bin aptos-indexer -- --config config.yaml

# Observe immediate crash with constraint violation error
```

## Notes

- This vulnerability affects all indexer processors (`DefaultTransactionProcessor`, `TokenTransactionProcessor`, etc.) since they all use the same insertion logic
- The issue is exacerbated by the lack of idempotency in re-indexing operations
- While the indexer is off-chain infrastructure (not affecting consensus), its availability is critical for ecosystem usability
- The fix should include proper conflict resolution or graceful error handling to allow the indexer to skip duplicate blocks and continue processing

### Citations

**File:** crates/indexer/migrations/2022-08-08-043603_core_tables/up.sql (L85-87)
```sql
CREATE TABLE block_metadata_transactions (
  version BIGINT UNIQUE PRIMARY KEY NOT NULL,
  block_height BIGINT UNIQUE NOT NULL,
```

**File:** crates/indexer/src/processors/default_processor.rs (L254-274)
```rust
fn insert_block_metadata_transactions(
    conn: &mut PgConnection,
    items_to_insert: &[BlockMetadataTransactionModel],
) -> Result<(), diesel::result::Error> {
    use schema::block_metadata_transactions::dsl::*;
    let chunks = get_chunks(
        items_to_insert.len(),
        BlockMetadataTransactionModel::field_count(),
    );
    for (start_ind, end_ind) in chunks {
        execute_with_better_error(
            conn,
            diesel::insert_into(schema::block_metadata_transactions::table)
                .values(&items_to_insert[start_ind..end_ind])
                .on_conflict(version)
                .do_nothing(),
            None,
        )?;
    }
    Ok(())
}
```

**File:** crates/indexer/src/runtime.rs (L225-243)
```rust
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
```

**File:** crates/indexer/src/indexer/fetcher.rs (L241-265)
```rust
    let mut block_height = block_event.height();
    let mut block_height_bcs = aptos_api_types::U64::from(block_height);

    let state_view = context.latest_state_view().unwrap();
    let converter = state_view.as_converter(context.db.clone(), context.indexer_reader.clone());

    let mut transactions = vec![];
    for (ind, raw_txn) in raw_txns.into_iter().enumerate() {
        let txn_version = raw_txn.version;
        // Do not update block_height if first block is block metadata
        if ind > 0 {
            // Update the timestamp if the next block occurs
            if let Some(txn) = raw_txn.transaction.try_as_block_metadata_ext() {
                timestamp = txn.timestamp_usecs();
                epoch = txn.epoch();
                epoch_bcs = aptos_api_types::U64::from(epoch);
                block_height += 1;
                block_height_bcs = aptos_api_types::U64::from(block_height);
            } else if let Some(txn) = raw_txn.transaction.try_as_block_metadata() {
                timestamp = txn.timestamp_usecs();
                epoch = txn.epoch();
                epoch_bcs = aptos_api_types::U64::from(epoch);
                block_height += 1;
                block_height_bcs = aptos_api_types::U64::from(block_height);
            }
```

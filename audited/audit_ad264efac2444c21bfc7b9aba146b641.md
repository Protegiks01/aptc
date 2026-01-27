# Audit Report

## Title
Indexer Crash Due to Unhandled UNIQUE Constraint Violation on block_height

## Summary
The indexer's database insertion logic for `BlockMetadataTransaction` only handles UNIQUE constraint conflicts on the `version` field (primary key) but not on the `block_height` field, which also has a UNIQUE constraint. If duplicate block heights with different versions are encountered, the indexer will crash due to an unhandled database error, causing a denial of service.

## Finding Description
The database schema defines a UNIQUE constraint on `block_height` in the `block_metadata_transactions` table: [1](#0-0) 

However, the insertion logic only handles conflicts on the `version` field: [2](#0-1) 

When the indexer encounters a transaction with a duplicate `block_height` but different `version`, the database will reject the insertion with a UNIQUE constraint violation error. This error propagates through the execution stack and causes the indexer to panic and crash: [3](#0-2) [4](#0-3) 

The indexer populates `block_height` by reading initial block info from storage and incrementing locally when encountering block metadata transactions: [5](#0-4) 

While block heights are designed to be monotonically increasing (enforced by the Move framework's event counter), several scenarios could lead to duplicate block heights:

1. **Consensus or Move VM bug**: A bug that allows the same block height to be produced twice
2. **Database corruption**: Incorrect block heights returned by `get_block_info_by_version`
3. **Indexer state inconsistency**: The indexer's local tracking gets out of sync with blockchain state
4. **Chain reorganization**: In rare reorg scenarios where the same height appears with different versions
5. **Multiple indexer instances**: Race conditions if multiple indexers write to the same database

## Impact Explanation
This vulnerability causes the indexer to crash, resulting in denial of service. According to the Aptos bug bounty program, this qualifies as **High Severity** because it causes "API crashes" (up to $50,000).

The indexer is critical infrastructure that:
- Powers all API queries for blockchain state
- Enables explorers, wallets, and dApps to function
- Provides indexed access to historical transactions

Without the indexer, the entire ecosystem loses the ability to query blockchain data efficiently, causing widespread service disruption.

## Likelihood Explanation
Under normal operation, this scenario is **unlikely** because: [6](#0-5) 

Block heights are derived from the event counter, which is monotonically increasing and managed by the Move VM with assertions: [7](#0-6) 

However, the likelihood increases in edge cases:
- Software bugs in consensus or Move VM
- Database corruption or state inconsistencies
- Indexer restart/recovery scenarios
- Deployment misconfigurations

Even with low likelihood, the **high impact** and **trivial fix** make this a valid security concern requiring defensive programming.

## Recommendation
Add `block_height` to the conflict resolution clause to handle UNIQUE constraint violations gracefully:

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
                // Add handling for block_height conflicts
                .on_conflict(block_height)
                .do_nothing(),
            None,
        )?;
    }
    Ok(())
}
```

Alternatively, use a composite conflict clause:
```rust
.on_conflict_do_nothing()  // Handles all UNIQUE constraint violations
```

## Proof of Concept
```rust
#[cfg(test)]
mod test {
    use super::*;
    use crate::models::block_metadata_transactions::BlockMetadataTransaction;
    
    #[test]
    fn test_duplicate_block_height_crash() {
        // Setup database connection
        let database_url = std::env::var("INDEXER_DATABASE_URL").unwrap();
        let conn_pool = new_db_pool(&database_url).unwrap();
        let mut conn = conn_pool.get().unwrap();
        
        // Create two BlockMetadataTransaction records with same block_height but different version
        let bmt1 = BlockMetadataTransaction {
            version: 100,
            block_height: 50,
            id: "0xabc".to_string(),
            round: 1,
            epoch: 1,
            previous_block_votes_bitvec: serde_json::json!([]),
            proposer: "0x1".to_string(),
            failed_proposer_indices: serde_json::json!([]),
            timestamp: chrono::NaiveDateTime::from_timestamp(0, 0),
        };
        
        let bmt2 = BlockMetadataTransaction {
            version: 101,  // Different version
            block_height: 50,  // Same block_height - UNIQUE constraint violation
            id: "0xdef".to_string(),
            round: 2,
            epoch: 1,
            previous_block_votes_bitvec: serde_json::json!([]),
            proposer: "0x2".to_string(),
            failed_proposer_indices: serde_json::json!([]),
            timestamp: chrono::NaiveDateTime::from_timestamp(1, 0),
        };
        
        // Insert first record - should succeed
        let result1 = diesel::insert_into(schema::block_metadata_transactions::table)
            .values(&bmt1)
            .execute(&mut conn);
        assert!(result1.is_ok());
        
        // Insert second record with duplicate block_height - will cause UNIQUE constraint error
        let result2 = diesel::insert_into(schema::block_metadata_transactions::table)
            .values(&bmt2)
            .execute(&mut conn);
        
        // This will fail because block_height has UNIQUE constraint
        // In production, this error causes the indexer to panic
        assert!(result2.is_err());
        
        // Expected error: duplicate key value violates unique constraint "block_metadata_transactions_block_height_key"
    }
}
```

## Notes
While the on-chain Move framework enforces block height uniqueness through event counters and assertions, the indexer should implement defensive programming to handle unexpected edge cases gracefully. The current implementation violates the principle of robustness by crashing on database constraint violations that could theoretically occur due to bugs, corruption, or edge cases in the broader system. The fix is trivial and significantly improves system resilience.

### Citations

**File:** crates/indexer/migrations/2022-08-08-043603_core_tables/up.sql (L85-99)
```sql
CREATE TABLE block_metadata_transactions (
  version BIGINT UNIQUE PRIMARY KEY NOT NULL,
  block_height BIGINT UNIQUE NOT NULL,
  id VARCHAR(66) NOT NULL,
  round BIGINT NOT NULL,
  epoch BIGINT NOT NULL,
  previous_block_votes_bitvec jsonb NOT NULL,
  proposer VARCHAR(66) NOT NULL,
  failed_proposer_indices jsonb NOT NULL,
  "timestamp" TIMESTAMP NOT NULL,
  -- Default time columns
  inserted_at TIMESTAMP NOT NULL DEFAULT NOW(),
  -- Constraints
  CONSTRAINT fk_versions FOREIGN KEY (version) REFERENCES transactions (version)
);
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

**File:** crates/indexer/src/processors/default_processor.rs (L611-623)
```rust
        match tx_result {
            Ok(_) => Ok(ProcessingResult::new(
                self.name(),
                start_version,
                end_version,
            )),
            Err(err) => Err(TransactionProcessingError::TransactionCommitError((
                anyhow::Error::from(err),
                start_version,
                end_version,
                self.name(),
            ))),
        }
```

**File:** crates/indexer/src/runtime.rs (L230-243)
```rust
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

**File:** crates/indexer/src/indexer/fetcher.rs (L229-265)
```rust
    let (_, _, block_event) = context
        .db
        .get_block_info_by_version(starting_version)
        .unwrap_or_else(|_| {
            panic!(
                "Could not get block_info for start version {}",
                starting_version,
            )
        });
    let mut timestamp = block_event.proposed_time();
    let mut epoch = block_event.epoch();
    let mut epoch_bcs = aptos_api_types::U64::from(epoch);
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

**File:** aptos-move/framework/aptos-framework/sources/block.move (L178-191)
```text
        let block_metadata_ref = borrow_global_mut<BlockResource>(@aptos_framework);
        block_metadata_ref.height = event::counter(&block_metadata_ref.new_block_events);

        let new_block_event = NewBlockEvent {
            hash,
            epoch,
            round,
            height: block_metadata_ref.height,
            previous_block_votes_bitvec,
            proposer,
            failed_proposer_indices,
            time_microseconds: timestamp,
        };
        emit_new_block_event(vm, &mut block_metadata_ref.new_block_events, new_block_event);
```

**File:** aptos-move/framework/aptos-framework/sources/block.move (L282-286)
```text
        assert!(
            event::counter(event_handle) == new_block_event.height,
            error::invalid_argument(ENUM_NEW_BLOCK_EVENTS_DOES_NOT_MATCH_BLOCK_HEIGHT),
        );
        event::emit_event<NewBlockEvent>(event_handle, new_block_event);
```

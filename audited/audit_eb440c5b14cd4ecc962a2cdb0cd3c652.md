# Audit Report

## Title
Indexer CurrentCollectionData State Rollback via User-Controlled String Bypass

## Summary
The Aptos indexer's `insert_current_collection_datas` function contains a critical flaw where user-controlled collection metadata (description, name, or URI) containing the substring "where" can bypass version-checking protection, allowing out-of-order transaction processing to permanently rollback collection state to outdated supply and metadata values.

## Finding Description

The vulnerability exists in the interaction between three components:

1. **Parallel Batch Processing**: The indexer processes transaction batches in parallel tasks [1](#0-0) 

2. **Version Check Bypass**: The `execute_with_better_error` function disables the WHERE clause protection if the query string contains "where" anywhere [2](#0-1) 

3. **User-Controlled Data**: Collection metadata (description, collection_name, metadata_uri) are user-controlled TEXT fields that get embedded in the SQL query string [3](#0-2) 

When `diesel::debug_query()` generates the SQL string, it includes the VALUES being inserted. If a collection description contains "where" (e.g., "Learn where to mint NFTs"), the substring check in `execute_with_better_error` matches, setting `additional_where_clause = None`, which disables the version protection: [4](#0-3) 

**Attack Scenario:**
1. User creates collection with description = "This is where my collection begins"
2. Transaction at version 200 updates collection supply to 500
3. Transaction at version 100 updates collection supply to 100
4. Due to parallel processing, version 200 completes first, writes supply=500
5. Version 100 completes second, the WHERE clause is bypassed due to "where" in description
6. Version 100's update succeeds, rolling back supply from 500 to 100 permanently

## Impact Explanation

This qualifies as **Medium Severity** per Aptos bug bounty criteria: "State inconsistencies requiring intervention."

The indexer is critical infrastructure that wallets, explorers, and marketplaces rely on for NFT collection data. Incorrect supply or metadata can cause:
- Trading platforms displaying wrong scarcity information
- Wallets showing incorrect collection details
- Users making financial decisions based on corrupted data
- Manual database intervention required to fix inconsistencies

While the on-chain blockchain state remains correct, the indexer database corruption affects the entire ecosystem's data availability layer.

## Likelihood Explanation

**HIGH Likelihood** - This will occur naturally without malicious intent:

1. Any collection with "where" in description/name/URI is vulnerable (common word)
2. Parallel batch processing is enabled by default [5](#0-4) 
3. Collections frequently receive multiple updates (minting increases supply)
4. Out-of-order completion is expected in parallel processing
5. The bug is deterministic - once triggered, corruption persists

The substring check is case-insensitive and applies to the entire query, making false positives extremely likely.

## Recommendation

Replace the broad substring check with a precise pattern match:

```rust
pub fn execute_with_better_error<U>(
    conn: &mut PgConnection,
    query: U,
    mut additional_where_clause: Option<&'static str>,
) -> QueryResult<usize>
where
    U: QueryFragment<Pg> + diesel::query_builder::QueryId,
{
    let original_query = diesel::debug_query::<diesel::pg::Pg, _>(&query).to_string();
    
    // Only disable WHERE clause for diesel's empty-check query
    if original_query.starts_with("SELECT") && original_query.contains("WHERE 1=0") {
        additional_where_clause = None;
    }
    
    let final_query = UpsertFilterLatestTransactionQuery {
        query,
        where_clause: additional_where_clause,
    };
    // ... rest of function
}
```

This prevents user-controlled data from disabling the version check while still handling diesel's empty-batch optimization.

## Proof of Concept

```sql
-- Simulate the vulnerability
BEGIN;

-- Initial state: collection at version 100
INSERT INTO current_collection_datas (
    collection_data_id_hash, creator_address, collection_name,
    description, metadata_uri, supply, maximum, maximum_mutable,
    uri_mutable, description_mutable, last_transaction_version,
    table_handle, inserted_at
) VALUES (
    'test_hash_123', '0xabc', 'Test Collection',
    'This is where my NFTs live', 'https://example.com', 100, 1000,
    false, false, false, 100, '0xhandle', NOW()
);

-- Simulate version 200 update (newer, should persist)
INSERT INTO current_collection_datas (
    collection_data_id_hash, creator_address, collection_name,
    description, metadata_uri, supply, maximum, maximum_mutable,
    uri_mutable, description_mutable, last_transaction_version,
    table_handle, inserted_at
) VALUES (
    'test_hash_123', '0xabc', 'Test Collection',
    'This is where my NFTs live', 'https://example.com', 500, 1000,
    false, false, false, 200, '0xhandle', NOW()
)
ON CONFLICT (collection_data_id_hash)
DO UPDATE SET
    supply = EXCLUDED.supply,
    last_transaction_version = EXCLUDED.last_transaction_version
WHERE current_collection_datas.last_transaction_version <= EXCLUDED.last_transaction_version;

-- Verify supply is now 500 at version 200
SELECT supply, last_transaction_version FROM current_collection_datas WHERE collection_data_id_hash = 'test_hash_123';
-- Expected: supply=500, version=200

-- Simulate version 100 update WITHOUT WHERE clause (bypassed due to "where" in description)
-- This simulates the bug where the WHERE clause is disabled
INSERT INTO current_collection_datas (
    collection_data_id_hash, creator_address, collection_name,
    description, metadata_uri, supply, maximum, maximum_mutable,
    uri_mutable, description_mutable, last_transaction_version,
    table_handle, inserted_at
) VALUES (
    'test_hash_123', '0xabc', 'Test Collection',
    'This is where my NFTs live', 'https://example.com', 100, 1000,
    false, false, false, 100, '0xhandle', NOW()
)
ON CONFLICT (collection_data_id_hash)
DO UPDATE SET
    supply = EXCLUDED.supply,
    last_transaction_version = EXCLUDED.last_transaction_version;
-- Note: No WHERE clause due to bug

-- Verify corruption: supply rolled back to 100 at version 100
SELECT supply, last_transaction_version FROM current_collection_datas WHERE collection_data_id_hash = 'test_hash_123';
-- Actual: supply=100, version=100 (CORRUPTED - should be 500 at version 200)

ROLLBACK;
```

### Citations

**File:** crates/indexer/src/runtime.rs (L111-112)
```rust
    let fetch_tasks = config.fetch_tasks.unwrap();
    let processor_tasks = config.processor_tasks.unwrap();
```

**File:** crates/indexer/src/runtime.rs (L211-215)
```rust
        for _ in 0..processor_tasks {
            let other_tailer = tailer.clone();
            let task = tokio::spawn(async move { other_tailer.process_next_batch().await });
            tasks.push(task);
        }
```

**File:** crates/indexer/src/database.rs (L72-77)
```rust
    let original_query = diesel::debug_query::<diesel::pg::Pg, _>(&query).to_string();
    // This is needed because if we don't insert any row, then diesel makes a call like this
    // SELECT 1 FROM TABLE WHERE 1=0
    if original_query.to_lowercase().contains("where") {
        additional_where_clause = None;
    }
```

**File:** crates/indexer/migrations/2022-09-20-055651_add_current_token_data/up.sql (L51-65)
```sql
CREATE TABLE current_collection_datas (
  -- sha256 of creator + collection_name
  collection_data_id_hash VARCHAR(64) UNIQUE PRIMARY KEY NOT NULL,
  creator_address VARCHAR(66) NOT NULL,
  collection_name VARCHAR(128) NOT NULL,
  description TEXT NOT NULL,
  metadata_uri VARCHAR(512) NOT NULL,
  supply NUMERIC NOT NULL,
  maximum NUMERIC NOT NULL,
  maximum_mutable BOOLEAN NOT NULL,
  uri_mutable BOOLEAN NOT NULL,
  description_mutable BOOLEAN NOT NULL,
  last_transaction_version BIGINT NOT NULL,
  inserted_at TIMESTAMP NOT NULL DEFAULT NOW()
);
```

**File:** crates/indexer/src/processors/token_processor.rs (L484-484)
```rust
            Some(" WHERE current_collection_datas.last_transaction_version <= excluded.last_transaction_version "),
```

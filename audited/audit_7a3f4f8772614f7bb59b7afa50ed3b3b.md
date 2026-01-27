# Audit Report

## Title
Retry Amplification in Token Indexer Causing Database Connection Exhaustion During Degradation

## Summary
The `get_collection_creator()` function in the token indexer implements a synchronous blocking retry mechanism that amplifies database load during degradation. When multiple parallel processing tasks encounter cache misses for collection creators, each triggers up to 5 sequential database queries while holding connections, leading to connection pool exhaustion and indexer failure.

## Finding Description

The indexer processes blockchain transactions in parallel using multiple concurrent tasks (default: 5 tasks). [1](#0-0) 

Each task processes token-related write set changes and may need to lookup collection creators from the database. [2](#0-1) 

When the creator address is not found in the cached `table_handle_to_owner` map, the code calls `get_collection_creator()` which implements a retry loop. [3](#0-2) 

The retry mechanism has critical flaws:

1. **Hardcoded retry count of 5**: [4](#0-3) 

2. **Blocking synchronous sleep**: The retry uses `std::thread::sleep` which blocks the thread for 500ms between attempts. [5](#0-4) 

3. **Connection held during retries**: Each task obtains a single database connection at the start of batch processing [6](#0-5)  and holds it throughout all retry attempts.

4. **Parallel amplification**: Multiple tasks run concurrently [7](#0-6) , each potentially executing multiple collection creator lookups per batch.

**Attack Scenario:**
- During database degradation (slow queries, high latency, intermittent failures)
- 5 parallel tasks processing token transactions
- Each task encounters N cache misses for collection creators in its batch
- Each cache miss triggers up to 5 sequential database queries
- Total query amplification: 5 tasks × N misses × 5 retries = 25N queries
- Each query holds a connection from the limited pool (r2d2 default: 10 connections)
- Tasks block for extended periods: 5 × (query_timeout + 500ms)
- Connection pool exhaustion occurs, preventing new operations
- Indexer processing stalls completely

## Impact Explanation

This qualifies as **Medium Severity** per Aptos bug bounty criteria for the following reasons:

1. **State inconsistencies requiring intervention**: The indexer falls behind or stops processing, causing token/NFT metadata to be unavailable or stale. This creates inconsistencies between on-chain state and indexed data that require manual intervention to resolve.

2. **Service availability impact**: While the indexer is not consensus-critical, it provides essential infrastructure for:
   - API queries for token/NFT data
   - Wallet applications displaying user assets
   - Marketplaces and dApps querying collection information
   - Analytics and monitoring systems

3. **Cascading failure pattern**: The retry amplification actively worsens database degradation rather than helping recovery, potentially causing complete indexer service failure.

4. **Resource exhaustion**: Connection pool exhaustion prevents legitimate operations from proceeding, constituting a denial-of-service condition on the indexer subsystem.

This does not reach High severity because:
- It affects the indexer, not validator nodes or consensus
- No funds are at risk
- The main chain continues operating normally

## Likelihood Explanation

This vulnerability has **HIGH likelihood** of occurring:

1. **Natural trigger conditions**: Database degradation is a common operational scenario caused by:
   - Hardware issues
   - Network latency
   - Query performance degradation under load
   - Connection limits being reached
   - Maintenance operations

2. **Common cache miss patterns**: Collection creator lookups require database access when:
   - New collections are created and not yet in the batch's cache
   - Transactions reference historical collections not in the batch's `table_handle_to_owner` map
   - Processing resumes after indexer restart with cold cache

3. **Default configuration amplifies impact**: The default of 5 parallel processor tasks maximizes the amplification effect.

4. **No circuit breaker**: The code lacks any mechanism to detect degraded database state and back off, instead retrying aggressively regardless of system health.

## Recommendation

Replace the synchronous blocking retry mechanism with an async-aware approach that includes:

1. **Exponential backoff** instead of fixed delays
2. **Async sleep** to avoid blocking threads
3. **Circuit breaker pattern** to detect sustained failures and skip retries
4. **Connection timeout configuration** separate from retry logic
5. **Metrics and logging** to detect retry storms

Example fix for `get_collection_creator()`:

```rust
pub fn get_collection_creator(
    conn: &mut PgPoolConnection,
    table_handle: &str,
) -> anyhow::Result<String> {
    // Single attempt, no retry amplification
    // Let the connection pool's own timeout handle transient failures
    match CurrentCollectionDataQuery::get_by_table_handle(conn, table_handle) {
        Ok(current_collection_data) => Ok(current_collection_data.creator_address),
        Err(e) => {
            aptos_logger::warn!(
                lookup_key = table_handle,
                error = ?e,
                "Failed to get collection creator"
            );
            Err(anyhow::anyhow!("Failed to get collection creator: {:?}", e))
        }
    }
}
```

Alternatively, implement proper async retry at a higher level with circuit breaking:
- Use tokio::time::sleep for non-blocking delays
- Implement circuit breaker to stop retrying during sustained failures
- Add metrics to track retry rates and success/failure patterns
- Consider caching collection creators across batches to reduce lookups

## Proof of Concept

To reproduce the vulnerability:

1. **Setup**: Configure indexer with default settings (5 processor tasks)

2. **Simulate database degradation**: 
   - Use a proxy to inject latency (e.g., toxiproxy) between indexer and PostgreSQL
   - Set latency to 10-15 seconds per query (approaching timeout)

3. **Generate token transactions**:
   - Create transactions with WriteTableItem changes for new collections
   - Ensure collection creators are NOT in the initial resource cache
   - Submit batches of 100+ such transactions

4. **Observe behavior**:
   - Monitor connection pool metrics via `GOT_CONNECTION` and `UNABLE_TO_GET_CONNECTION` counters [8](#0-7) 
   - Watch for tasks blocking in `get_collection_creator()` retry loops
   - Observe connection pool exhaustion as all connections are held by retrying tasks
   - Verify indexer processing stalls completely

Expected outcome: Within minutes of database degradation, all processor tasks become blocked in retry loops, the connection pool is exhausted, and the indexer stops making progress.

## Notes

This vulnerability is specific to the indexer subsystem and does not affect:
- Consensus protocol or validator operations
- Transaction execution or state commitment on the main chain
- Fund security or asset integrity

The issue represents a design flaw in error handling where retry logic intended to improve resilience actually amplifies failures during degraded conditions. The synchronous blocking nature of the retries in an otherwise async system (tokio-based) is particularly problematic.

### Citations

**File:** config/src/config/indexer_config.rs (L22-22)
```rust
pub const DEFAULT_PROCESSOR_TASKS: u8 = 5;
```

**File:** crates/indexer/src/models/token_models/tokens.rs (L123-129)
```rust
                        CollectionData::from_write_table_item(
                            write_table_item,
                            txn_version,
                            txn_timestamp,
                            table_handle_to_owner,
                            conn,
                        )
```

**File:** crates/indexer/src/models/token_models/collection_datas.rs (L23-23)
```rust
pub const QUERY_RETRIES: u32 = 5;
```

**File:** crates/indexer/src/models/token_models/collection_datas.rs (L109-119)
```rust
                None => match Self::get_collection_creator(conn, &table_handle) {
                    Ok(creator) => creator,
                    Err(_) => {
                        aptos_logger::error!(
                            transaction_version = txn_version,
                            lookup_key = &table_handle,
                            "Failed to get collection creator for table handle. You probably should backfill db."
                        );
                        return Ok(None);
                    },
                },
```

**File:** crates/indexer/src/models/token_models/collection_datas.rs (L168-183)
```rust
    pub fn get_collection_creator(
        conn: &mut PgPoolConnection,
        table_handle: &str,
    ) -> anyhow::Result<String> {
        let mut retried = 0;
        while retried < QUERY_RETRIES {
            retried += 1;
            match CurrentCollectionDataQuery::get_by_table_handle(conn, table_handle) {
                Ok(current_collection_data) => return Ok(current_collection_data.creator_address),
                Err(_) => {
                    std::thread::sleep(std::time::Duration::from_millis(QUERY_RETRY_DELAY_MS));
                },
            }
        }
        Err(anyhow::anyhow!("Failed to get collection creator"))
    }
```

**File:** crates/indexer/src/processors/token_processor.rs (L858-858)
```rust
        let mut conn = self.get_conn();
```

**File:** crates/indexer/src/runtime.rs (L210-215)
```rust
        let mut tasks = vec![];
        for _ in 0..processor_tasks {
            let other_tailer = tailer.clone();
            let task = tokio::spawn(async move { other_tailer.process_next_batch().await });
            tasks.push(task);
        }
```

**File:** crates/indexer/src/indexer/transaction_processor.rs (L45-63)
```rust
    fn get_conn(&self) -> PgPoolConnection {
        let pool = self.connection_pool();
        loop {
            match pool.get() {
                Ok(conn) => {
                    GOT_CONNECTION.inc();
                    return conn;
                },
                Err(err) => {
                    UNABLE_TO_GET_CONNECTION.inc();
                    aptos_logger::error!(
                        "Could not get DB connection from pool, will retry in {:?}. Err: {:?}",
                        pool.connection_timeout(),
                        err
                    );
                },
            };
        }
    }
```

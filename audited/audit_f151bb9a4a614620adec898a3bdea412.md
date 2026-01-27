# Audit Report

## Title
Indexer Concurrent Batch Processing Causes Missing Token Ownership Metadata Due to Cross-Batch Table Handle Resolution Failure

## Summary
The Aptos indexer's token processor implements concurrent batch processing where multiple transaction batches are processed in parallel. Each batch independently builds a `table_handle_to_owner` HashMap from only its own transactions. When table metadata (TokenStore resources) is created in one batch and referenced by table items in a concurrently-processed batch, the lookup fails, resulting in missing owner information in the token ownership records stored in the database.

## Finding Description

The vulnerability exists in the interaction between three components:

1. **Concurrent Batch Processing**: The indexer runtime spawns multiple tasks to process batches concurrently [1](#0-0) 

2. **Per-Batch HashMap Construction**: Each batch builds its own `table_handle_to_owner` HashMap scanning only transactions within that batch [2](#0-1) 

3. **Table Metadata Lookup**: When processing token ownerships, the code looks up table metadata from the batch-local HashMap [3](#0-2) 

**Attack Scenario:**
1. Transaction at version V creates a TokenStore resource (table metadata) for table handle X
2. Transaction at version V+500 writes a token to table handle X  
3. The fetcher creates two batches: Batch A (V to V+499) and Batch B (V+500 to V+999)
4. Both batches are dispatched to concurrent processor tasks
5. Batch B completes processing before Batch A
6. When Batch B processes the token write at V+500, it performs the lookup at line 88
7. The lookup returns `None` because Batch B's HashMap only scanned versions V+500 to V+999
8. The code logs a warning and stores `owner_address: None` in the database [4](#0-3) 

This violates the indexer's data integrity guarantee that later transactions should be able to reference metadata from earlier transactions.

## Impact Explanation

This issue causes **state inconsistencies in the indexer database** requiring intervention, qualifying as **Medium severity** per the Aptos bug bounty criteria. Specifically:

- Token ownership records are stored with `NULL` owner addresses even though the correct owner exists in earlier blockchain transactions
- The `current_token_ownerships` table may have missing or incomplete entries
- Applications querying the indexer API receive incorrect token ownership information
- The issue is non-deterministic and depends on batch processing timing

However, this is **NOT exploitable** by an attacker because:
- The race condition occurs naturally due to concurrent processing
- Attackers cannot control batch formation, processing order, or timing
- The indexer is an off-chain auxiliary service, not part of blockchain consensus
- No funds can be stolen and blockchain state remains correct

## Likelihood Explanation

**High likelihood of natural occurrence** when:
- The indexer is configured with `processor_tasks > 1` (concurrent processing enabled)
- Transaction batches contain both TokenStore resource creation and subsequent token operations
- System load causes variable processing speeds between concurrent tasks

**Zero likelihood of attacker exploitation** because:
- Attackers cannot influence how the fetcher divides transactions into batches
- Attackers cannot control the relative processing speed of concurrent tasks
- The race condition is timing-dependent and non-deterministic

## Recommendation

**Fix Approach 1: Accumulate Metadata Across Batches**
Maintain a shared, thread-safe cache of table metadata that persists across batch processing rounds:

```rust
// In TokenTransactionProcessor
struct TokenTransactionProcessor {
    connection_pool: PgDbPool,
    ans_contract_address: Option<String>,
    nft_points_contract: Option<String>,
    // Add shared metadata cache
    metadata_cache: Arc<RwLock<TableHandleToOwner>>,
}
```

Before processing each batch, query the cache and merge with batch-local metadata.

**Fix Approach 2: Sequential Metadata Resolution Phase**
Modify the runtime to process batches in two phases:
1. Phase 1: All batches extract table metadata and commit to a shared cache (sequential)
2. Phase 2: All batches process transactions using the complete metadata map (concurrent)

**Fix Approach 3: Database-Backed Metadata Resolution**
When table metadata is missing from the batch-local HashMap, query the `processor_status` table to check if earlier transactions have been processed, then query the database for the metadata rather than assuming it doesn't exist.

## Proof of Concept

```rust
// Test demonstrating the race condition
// File: crates/indexer/src/processors/token_processor_test.rs

#[tokio::test]
async fn test_concurrent_batch_metadata_race() {
    // Setup: Create test transactions
    let txn_v100 = create_token_store_resource_txn(100, "table_handle_1", "0xowner1");
    let txn_v600 = create_token_write_txn(600, "table_handle_1", "token_1");
    
    // Create two batches
    let batch_a = vec![txn_v100]; // versions 100-199
    let batch_b = vec![txn_v600]; // versions 600-699
    
    let processor = TokenTransactionProcessor::new(pool.clone(), None, None);
    
    // Process batch B before batch A completes
    let handle_b = tokio::spawn({
        let p = processor.clone();
        async move { p.process_transactions(batch_b, 600, 699).await }
    });
    
    // Small delay to ensure batch B starts first
    tokio::time::sleep(Duration::from_millis(10)).await;
    
    let handle_a = tokio::spawn({
        let p = processor.clone();
        async move { p.process_transactions(batch_a, 100, 199).await }
    });
    
    // Wait for both batches
    let (result_b, result_a) = tokio::join!(handle_b, handle_a);
    
    // Assert: Query database for token ownership at version 600
    let ownership = query_token_ownership(&mut conn, "token_1", 600);
    
    // BUG: owner_address will be NULL even though the correct owner exists
    assert!(ownership.owner_address.is_none(), "Race condition: missing owner");
    
    // Expected behavior: owner_address should be Some("0xowner1")
}
```

**Notes:**
- This is a data consistency bug in the indexer's concurrent processing logic
- The issue is **NOT exploitable** by attackers as they cannot control batch processing timing
- The blockchain's consensus and state remain unaffected
- Only the off-chain indexer's derived data is impacted
- The severity is Medium due to data inconsistency, but lacks exploitability for higher classification

### Citations

**File:** crates/indexer/src/runtime.rs (L210-219)
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
```

**File:** crates/indexer/src/models/token_models/tokens.rs (L350-373)
```rust
    pub fn get_table_handle_to_owner_from_transactions(
        transactions: &[APITransaction],
    ) -> TableHandleToOwner {
        let mut table_handle_to_owner: TableHandleToOwner = HashMap::new();
        // Do a first pass to get all the table metadata in the batch.
        for transaction in transactions {
            if let APITransaction::UserTransaction(user_txn) = transaction {
                let txn_version = user_txn.info.version.0 as i64;
                for wsc in &user_txn.info.changes {
                    if let APIWriteSetChange::WriteResource(write_resource) = wsc {
                        let maybe_map = TableMetadataForToken::get_table_handle_to_owner(
                            write_resource,
                            txn_version,
                        )
                        .unwrap();
                        if let Some(map) = maybe_map {
                            table_handle_to_owner.extend(map);
                        }
                    }
                }
            }
        }
        table_handle_to_owner
    }
```

**File:** crates/indexer/src/models/token_models/token_ownerships.rs (L88-94)
```rust
        let maybe_table_metadata = table_handle_to_owner.get(&table_handle);
        // Return early if table type is not tokenstore
        if let Some(tm) = maybe_table_metadata {
            if tm.table_type != "0x3::token::TokenStore" {
                return Ok(None);
            }
        }
```

**File:** crates/indexer/src/models/token_models/token_ownerships.rs (L115-122)
```rust
                aptos_logger::warn!(
                    transaction_version = txn_version,
                    table_handle = table_handle,
                    "Missing table handle metadata for TokenStore. {:?}",
                    table_handle_to_owner
                );
                (None, None, None)
            },
```

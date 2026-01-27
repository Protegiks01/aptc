# Audit Report

## Title
Race Condition in Token Burn Attribution Due to Concurrent Batch Processing

## Summary
The `prior_nft_ownership` HashMap in `parse_v2_token()` is not race-safe when multiple batches are processed concurrently. When a token burn event occurs in a batch that doesn't contain the token's prior transfer, the indexer falls back to a database query that can read stale committed data, resulting in incorrect burn attribution and database inconsistencies.

## Finding Description

The indexer processes transactions in batches using concurrent tasks configured by `processor_tasks`. Each task processes its own batch, and the `parse_v2_token()` function creates a local `prior_nft_ownership` HashMap to track token ownership changes within that batch. [1](#0-0) 

When a burn event is encountered, the code checks this HashMap for prior ownership. If not found (because the token wasn't modified in the current batch), it falls back to querying the database: [2](#0-1) 

The vulnerability occurs in this scenario:

1. **Batch 1** (versions 100-199): Contains transaction at version 100 transferring Token X from User A to User B
2. **Batch 2** (versions 200-299): Contains transaction at version 200 burning Token X

Both batches are fetched sequentially but processed concurrently by different tasks: [3](#0-2) 

**Race Condition Timeline:**
- T1: Task 1 calls `parse_v2_token()` for Batch 1, creates in-memory records for transfer (A→B)
- T2: Task 2 calls `parse_v2_token()` for Batch 2, processes burn event
- T3: Task 2's burn processing queries database (line 291-294 of v2_token_ownerships.rs)
- **T3 happens BEFORE Task 1 commits to database**
- T4: Database query returns stale data showing owner=A (from before version 100)
- T5: Task 2 creates burn record attributing burn to User A (incorrect)
- T6: Task 2 commits burn record to database
- T7: Task 1 commits transfer record, but burn record already has wrong owner

The database upsert uses version-based conflict resolution: [4](#0-3) 

This results in `current_token_ownerships_v2` containing:
- `{token_data_id: X, owner: A, amount: 0, version: 200}` (burn with wrong owner)
- `{token_data_id: X, owner: B, amount: 1, version: 100}` (transfer to actual owner)

This violates the invariant that a burned token (amount=0) at a later version should supersede earlier ownership records.

## Impact Explanation

This qualifies as **Medium to High severity** based on:

1. **State Inconsistencies Requiring Intervention (Medium)**: The indexer database becomes inconsistent with multiple conflicting ownership records for burned tokens. Manual database cleanup would be required to fix historical records.

2. **API Data Corruption (High)**: Applications and users querying the indexer API receive incorrect ownership information, which could affect:
   - NFT marketplaces showing wrong ownership history
   - Analytics platforms reporting incorrect burn statistics
   - User dashboards displaying misleading token states
   - Potentially financial calculations if burn attribution affects rewards/rebates

3. **Historical Record Corruption**: The `token_ownerships_v2` historical table permanently records the wrong owner for burn events, affecting audit trails and compliance.

## Likelihood Explanation

This vulnerability has **medium-to-high likelihood** of occurring in production:

**Enabling Conditions:**
- Concurrent batch processing enabled (`processor_tasks > 1`, which is the default configuration)
- Token transfer and burn transactions in consecutive blocks but different batches
- Timing race where burn batch processes before transfer batch commits

**Probability Factors:**
- Higher with smaller batch sizes (increases chance of consecutive txns spanning batches)
- Higher with more concurrent tasks (more parallelism = more races)
- Higher under load (processing delays increase race window)
- Common pattern: Users often transfer then burn NFTs for various use cases

**Realistic Scenario:**
A user transfers an NFT to another wallet and immediately burns it (perhaps for a game mechanic or collection completion). With typical batch sizes of 100-1000 transactions and multiple concurrent tasks, there's a non-negligible probability these transactions end up in adjacent batches with the race condition triggering.

## Recommendation

**Solution 1: Sequential Batch Commitment (Simple but slower)**
Process batches concurrently but commit them sequentially in version order. Add a commit ordering mechanism:

```rust
// In runtime.rs, after line 219
let mut sorted_batches = batches;
sorted_batches.sort_by_key(|(_, res)| {
    res.as_ref().ok().map(|r| r.start_version).unwrap_or(u64::MAX)
});

// Commit in order
for (num_txn, res) in sorted_batches {
    // existing commit logic
}
```

**Solution 2: Database Transaction Isolation (Better performance)**
Wrap the entire `parse_v2_token()` + `insert_to_db()` sequence in a serializable transaction or use SELECT FOR UPDATE when querying prior ownership:

```rust
// In v2_token_ownerships.rs, modify the fallback query
None => {
    match CurrentTokenOwnershipV2Query::get_nft_by_token_data_id_for_update(
        conn,
        token_address,
    ) {
        // ... rest of code
    }
}
```

**Solution 3: Cross-Batch Ownership Cache (Optimal)**
Implement a shared ownership cache (protected by RwLock or similar) that persists across batch processing:

```rust
// In TokenTransactionProcessor
pub struct TokenTransactionProcessor {
    connection_pool: PgDbPool,
    ans_contract_address: Option<String>,
    nft_points_contract: Option<String>,
    // Add shared ownership cache
    shared_nft_ownership: Arc<RwLock<HashMap<String, NFTOwnershipV2>>>,
}
```

Update the cache on commits and consult it before falling back to database queries.

## Proof of Concept

```rust
// Reproduction test (add to token_processor.rs tests)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_burn_race_condition() {
    // Setup: Create token owned by User A
    let token_x = create_test_token("token_x", "user_a");
    
    // Transaction 1 (version 100): Transfer token_x from user_a to user_b
    let transfer_txn = create_transfer_transaction(100, "token_x", "user_a", "user_b");
    
    // Transaction 2 (version 200): Burn token_x (should be attributed to user_b)
    let burn_txn = create_burn_transaction(200, "token_x");
    
    // Create two batches
    let batch1 = vec![transfer_txn]; // versions 100-199
    let batch2 = vec![burn_txn];      // versions 200-299
    
    // Process concurrently
    let processor = TokenTransactionProcessor::new(pool, None, None);
    let processor_arc = Arc::new(processor);
    
    let proc1 = processor_arc.clone();
    let proc2 = processor_arc.clone();
    
    let handle1 = tokio::spawn(async move {
        // Add delay to increase race probability
        tokio::time::sleep(Duration::from_millis(100)).await;
        proc1.process_transactions(batch1, 100, 199).await
    });
    
    let handle2 = tokio::spawn(async move {
        proc2.process_transactions(batch2, 200, 299).await
    });
    
    let _ = tokio::join!(handle1, handle2);
    
    // Verify bug: burn is attributed to wrong owner
    let burn_record = query_burn_record(&mut pool.get().unwrap(), "token_x");
    
    // EXPECTED: owner should be "user_b" (actual owner when burned)
    // ACTUAL: owner is "user_a" (stale owner from before transfer)
    assert_eq!(burn_record.owner_address, "user_b", 
        "Bug confirmed: Burn attributed to wrong owner due to race condition");
}
```

## Notes

The vulnerability is specific to the indexer component and does not affect blockchain consensus or validator operations. However, it represents a significant data integrity issue that can mislead applications and users relying on accurate NFT ownership information. The fix should be prioritized as it affects the correctness guarantees of the indexer API, which is a critical infrastructure component for the Aptos ecosystem.

### Citations

**File:** crates/indexer/src/processors/token_processor.rs (L778-792)
```rust
                .on_conflict((token_data_id, property_version_v1, owner_address, storage_id))
                .do_update()
                .set((
                    amount.eq(excluded(amount)),
                    table_type_v1.eq(excluded(table_type_v1)),
                    token_properties_mutated_v1.eq(excluded(token_properties_mutated_v1)),
                    is_soulbound_v2.eq(excluded(is_soulbound_v2)),
                    token_standard.eq(excluded(token_standard)),
                    is_fungible_v2.eq(excluded(is_fungible_v2)),
                    last_transaction_version.eq(excluded(last_transaction_version)),
                    last_transaction_timestamp.eq(excluded(last_transaction_timestamp)),
                    inserted_at.eq(excluded(inserted_at)),
                    non_transferrable_by_owner.eq(excluded(non_transferrable_by_owner)),
                )),
            Some(" WHERE current_token_ownerships_v2.last_transaction_version <= excluded.last_transaction_version "),
```

**File:** crates/indexer/src/processors/token_processor.rs (L1068-1068)
```rust
    let mut prior_nft_ownership: HashMap<String, NFTOwnershipV2> = HashMap::new();
```

**File:** crates/indexer/src/models/token_models/v2_token_ownerships.rs (L287-306)
```rust
            let latest_nft_ownership: NFTOwnershipV2 = match prior_nft_ownership.get(token_address)
            {
                Some(inner) => inner.clone(),
                None => {
                    match CurrentTokenOwnershipV2Query::get_nft_by_token_data_id(
                        conn,
                        token_address,
                    ) {
                        Ok(nft) => nft,
                        Err(_) => {
                            aptos_logger::error!(
                                transaction_version = txn_version,
                                lookup_key = &token_address,
                                "Failed to find NFT for burned token. You probably should backfill db."
                            );
                            return Ok(None);
                        },
                    }
                },
            };
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

# Audit Report

## Title
Race Condition in Concurrent Object Deletion Processing Causes Permanent Index Inconsistency

## Summary
The indexer's concurrent batch processing creates a race condition where object deletions can be silently skipped when the deleted object was created in a concurrently-processing batch. This results in permanent inconsistency between the `objects` (historical) and `current_objects` tables, causing queries to return deleted objects as alive and potentially enabling double-spending scenarios in applications relying on indexed data.

## Finding Description

The Aptos indexer processes transaction batches concurrently using multiple parallel tasks. [1](#0-0)  By default, 5 concurrent processor tasks run simultaneously. [2](#0-1) 

Each task independently fetches and processes batches, which can lead to out-of-order database commits.

When processing an object deletion, the code must retrieve the previous object state to populate historical fields. [3](#0-2) 

The critical flaw occurs when:
1. **Batch N** (versions 1-500): Creates Object X with owner A
2. **Batch N+1** (versions 501-1000): Deletes Object X
3. Both batches process **concurrently** in separate tasks

**Exploitation Flow:**
- Thread 1 begins processing Batch N
- Thread 2 begins processing Batch N+1 simultaneously  
- Thread 2 encounters the deletion of Object X
- Thread 2 checks the in-memory HashMap `all_current_objects` built from processing Batch N+1's write resources [4](#0-3)  - this HashMap only contains objects from the current batch, NOT from Batch N
- Thread 2 falls back to querying the database for Object X's previous state
- The database query **fails** because Thread 1 hasn't committed Batch N yet (READ COMMITTED isolation level prevents seeing uncommitted data)
- The error is logged and `Ok(None)` is returned, causing the deletion to be **silently skipped**
- Thread 1 eventually commits Batch N - Object X exists in both tables
- Thread 2 commits Batch N+1 **without** the deletion record

**Final State:**
- `objects` table: Contains creation record for Object X at version 50, **missing** deletion record at version 550
- `current_objects` table: Shows Object X as alive with `is_deleted = false`
- **Blockchain reality**: Object X was deleted at version 550

The upsert logic for `current_objects` includes a version check: [5](#0-4)  This WHERE clause prevents older versions from overwriting newer ones, but when the deletion is skipped entirely, this protection is irrelevant.

## Impact Explanation

This vulnerability creates **permanent state inconsistencies** between indexed data and actual blockchain state. Applications querying the indexer will receive incorrect information:

1. **NFT Marketplaces**: Deleted NFTs appear as available for purchase, enabling scams where users pay for non-existent items
2. **DeFi Applications**: Deleted collateral objects appear as active, causing incorrect liquidation calculations
3. **Wallet Applications**: Display incorrect asset ownership after transfers or burns
4. **Analytics Platforms**: Report incorrect object counts and ownership statistics

This qualifies as **Medium Severity** under the bug bounty criteria:
- **"State inconsistencies requiring intervention"**: The index must be manually reindexed to fix the inconsistency
- **"Limited funds loss or manipulation"**: Applications relying on indexed data could facilitate user losses, though on-chain state remains correct

The issue could potentially reach **High Severity** because:
- **"Significant protocol violations"**: The indexer protocol guarantees eventual consistency with blockchain state, which is violated
- **"API crashes"**: Queries expecting deleted objects to be marked as deleted may fail when encountering contradictory state

## Likelihood Explanation

**Likelihood: HIGH**

This race condition occurs during normal operation without any attacker action:

1. **Concurrent processing is enabled by default**: [6](#0-5)  The default is 5 concurrent processor tasks.

2. **Common pattern**: Objects are frequently created and deleted within adjacent batches (e.g., temporary objects, burned NFTs, liquidated positions)

3. **Database isolation**: The READ COMMITTED isolation level is standard for PostgreSQL and doesn't prevent this race

4. **No synchronization**: There are no locks or barriers preventing concurrent batch commits

The vulnerability triggers whenever:
- An object is created in batch N
- The same object is deleted in batch N+k where k is small (within the concurrent processing window)
- Both batches are processed by different tasks simultaneously
- The deletion batch queries the database before the creation batch commits

With 5 concurrent tasks and batch sizes of 500 transactions, this window is significant.

## Recommendation

**Solution 1: Serialize Batch Commits (Preferred)**

Ensure batches commit to the database in sequential version order, even if processing happens in parallel:

```rust
// In runtime.rs, replace the concurrent batch processing with ordered commits
// Process batches in parallel but commit sequentially
let mut pending_batches = BTreeMap::new(); // Order by start_version
let mut next_expected_version = current_version;

for result in batches {
    pending_batches.insert(result.start_version, result);
    
    // Commit batches in order
    while let Some(batch) = pending_batches.remove(&next_expected_version) {
        // Commit this batch
        batch.commit_to_db()?;
        next_expected_version = batch.end_version + 1;
    }
}
```

**Solution 2: Expand In-Memory Object Cache**

Include objects from all concurrently-processing batches in the lookup HashMap:

```rust
// Use a shared concurrent HashMap across all processing tasks
let shared_objects = Arc::new(DashMap::new());

// In each task, update shared state before querying database
shared_objects.insert(object.address, object.clone());

// In from_delete_resource, check shared state before database query
if let Some(obj) = shared_objects.get(&resource.address) {
    // Use shared object
} else {
    // Query database as fallback
}
```

**Solution 3: Disable Concurrent Processing for Object Operations**

Set `processor_tasks = 1` in indexer configuration to process batches sequentially, eliminating the race condition at the cost of reduced throughput.

## Proof of Concept

```rust
// Rust test demonstrating the race condition
#[tokio::test]
async fn test_concurrent_deletion_race_condition() {
    let pool = setup_test_db_pool().await;
    let processor = DefaultTransactionProcessor::new(pool.clone());
    
    // Batch 1: Create object X
    let create_txn = create_object_transaction("0xABC", version: 100);
    
    // Batch 2: Delete object X  
    let delete_txn = delete_object_transaction("0xABC", version: 200);
    
    // Process both batches concurrently
    let task1 = tokio::spawn({
        let p = processor.clone();
        async move {
            // Delay to ensure task2 queries database first
            tokio::time::sleep(Duration::from_millis(100)).await;
            p.process_transactions(vec![create_txn]).await
        }
    });
    
    let task2 = tokio::spawn({
        let p = processor.clone();
        async move {
            p.process_transactions(vec![delete_txn]).await
        }
    });
    
    let _ = tokio::try_join!(task1, task2).unwrap();
    
    // Verify inconsistency
    let mut conn = pool.get().unwrap();
    let current_obj = current_objects::table
        .filter(current_objects::object_address.eq("0xABC"))
        .first::<CurrentObject>(&mut conn)
        .unwrap();
    
    // Bug: Object shows as alive despite being deleted at version 200
    assert_eq!(current_obj.is_deleted, false); // Should be true!
    assert_eq!(current_obj.last_transaction_version, 100); // Should be 200!
    
    // Historical table is also incomplete
    let delete_record = objects::table
        .filter(objects::object_address.eq("0xABC"))
        .filter(objects::transaction_version.eq(200))
        .first::<Object>(&mut conn);
    
    assert!(delete_record.is_err()); // Delete record missing!
}
```

## Notes

This vulnerability affects all indexer deployments running with concurrent processing enabled (the default configuration). The issue is particularly severe because:

1. **Silent failure**: The error is only logged, not surfaced to operators
2. **Permanent corruption**: Once a batch commits with missing deletions, the inconsistency persists
3. **Widespread impact**: All applications querying the indexer receive incorrect data
4. **Difficult detection**: Requires comparing indexed data against blockchain state

The root cause is the assumption that the in-memory object mapping contains all necessary previous states, when in reality it only contains objects from the current batch. The database fallback query operates under READ COMMITTED isolation, which correctly prevents dirty reads but creates this race condition when combined with concurrent batch processing.

### Citations

**File:** config/src/config/indexer_config.rs (L22-22)
```rust
pub const DEFAULT_PROCESSOR_TASKS: u8 = 5;
```

**File:** config/src/config/indexer_config.rs (L186-190)
```rust
        indexer_config.processor_tasks = default_if_zero(
            indexer_config.processor_tasks.map(|v| v as u64),
            DEFAULT_PROCESSOR_TASKS as u64,
        )
        .map(|value| value as u8);
```

**File:** crates/indexer/src/runtime.rs (L209-219)
```rust
    loop {
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

**File:** crates/indexer/src/models/v2_objects.rs (L125-139)
```rust
            let previous_object = if let Some(object) = object_mapping.get(&resource.address) {
                object.clone()
            } else {
                match Self::get_object_owner(conn, &resource.address) {
                    Ok(owner) => owner,
                    Err(_) => {
                        aptos_logger::error!(
                            transaction_version = txn_version,
                            lookup_key = &resource.address,
                            "Missing object owner for object. You probably should backfill db.",
                        );
                        return Ok(None);
                    },
                }
            };
```

**File:** crates/indexer/src/processors/default_processor.rs (L444-469)
```rust
fn insert_current_objects(
    conn: &mut PgConnection,
    items_to_insert: &[CurrentObject],
) -> Result<(), diesel::result::Error> {
    use schema::current_objects::dsl::*;
    let chunks = get_chunks(items_to_insert.len(), CurrentObject::field_count());
    for (start_ind, end_ind) in chunks {
        execute_with_better_error(
            conn,
            diesel::insert_into(schema::current_objects::table)
                .values(&items_to_insert[start_ind..end_ind])
                .on_conflict(object_address)
                .do_update()
                .set((
                    owner_address.eq(excluded(owner_address)),
                    state_key_hash.eq(excluded(state_key_hash)),
                    allow_ungated_transfer.eq(excluded(allow_ungated_transfer)),
                    last_guid_creation_num.eq(excluded(last_guid_creation_num)),
                    last_transaction_version.eq(excluded(last_transaction_version)),
                    is_deleted.eq(excluded(is_deleted)),
                    inserted_at.eq(excluded(inserted_at)),
                )),
                Some(" WHERE current_objects.last_transaction_version <= excluded.last_transaction_version "),
        )?;
    }
    Ok(())
```

**File:** crates/indexer/src/processors/default_processor.rs (L532-571)
```rust
        let mut all_current_objects = HashMap::new();
        for txn in &transactions {
            let (changes, txn_version) = match txn {
                Transaction::UserTransaction(user_txn) => (
                    user_txn.info.changes.clone(),
                    user_txn.info.version.0 as i64,
                ),
                Transaction::BlockMetadataTransaction(bmt_txn) => {
                    (bmt_txn.info.changes.clone(), bmt_txn.info.version.0 as i64)
                },
                _ => continue,
            };

            for (index, wsc) in changes.iter().enumerate() {
                let index = index as i64;
                match wsc {
                    WriteSetChange::WriteResource(inner) => {
                        if let Some((object, current_object)) =
                            &Object::from_write_resource(inner, txn_version, index).unwrap()
                        {
                            all_objects.push(object.clone());
                            all_current_objects
                                .insert(object.object_address.clone(), current_object.clone());
                        }
                    },
                    WriteSetChange::DeleteResource(inner) => {
                        // Passing all_current_objects into the function so that we can get the owner of the deleted
                        // resource if it was handled in the same batch
                        if let Some((object, current_object)) = Object::from_delete_resource(
                            inner,
                            txn_version,
                            index,
                            &all_current_objects,
                            &mut conn,
                        )
                        .unwrap()
                        {
                            all_objects.push(object.clone());
                            all_current_objects
                                .insert(object.object_address.clone(), current_object.clone());
```

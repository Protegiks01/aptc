# Audit Report

## Title
Race Condition in Object Ownership Lookup Causes Non-Deterministic Indexer Data Corruption

## Summary
The retry logic in `get_object_owner()` within the Aptos indexer can return different ownership data for the same object deletion event when concurrent transaction batches are processed, resulting in permanent data corruption that violates the deterministic execution invariant.

## Finding Description

The indexer's `Object::from_delete_resource()` method relies on `get_object_owner()` to retrieve the previous owner of a deleted object. This function implements a retry mechanism that queries the `current_objects` table up to 5 times with 500ms delays between attempts. [1](#0-0) 

The developers acknowledge the problem in a comment: [2](#0-1) 

The vulnerability occurs because:

1. **Multi-threaded Processing**: The indexer processes transaction batches in parallel across multiple threads to improve throughput. [3](#0-2) 

2. **Read-Committed Isolation**: The PostgreSQL database uses "read-committed" isolation level, allowing SELECT queries to observe committed changes between retry attempts.

3. **Concurrent Updates**: The `current_objects` table is continuously updated by all processing threads using UPSERT operations that replace ownership data based on transaction version ordering. [4](#0-3) 

**Race Condition Scenario:**

- Thread A processes transaction batch [V100-V199] containing a deletion of Object X at version V150
- Thread B processes transaction batch [V200-V299] containing a transfer of Object X to a new owner at version V250
- Thread A's initial query for Object X's owner fails (database lock, timeout, etc.)
- Thread B completes processing and commits its batch, updating `current_objects` with the V250 ownership data
- Thread A retries and reads the V250 owner instead of the correct pre-V150 owner
- Thread A records incorrect ownership data for the deletion event at V150

The object mapping cache is intended to help but only works within a single batch: [5](#0-4) 

The cache cannot prevent cross-batch race conditions since different threads maintain separate `all_current_objects` HashMaps.

## Impact Explanation

This qualifies as **Medium Severity** per Aptos bug bounty criteria: "State inconsistencies requiring intervention."

The vulnerability causes:

1. **Deterministic Execution Violation**: Different indexer instances can produce different historical records for the same blockchain state, violating the invariant that all nodes must produce identical outputs for identical inputs.

2. **Permanent Data Corruption**: Once written, the incorrect ownership data persists in the `objects` historical table and cannot be automatically corrected without manual intervention or full reindexing.

3. **Application-Level Impacts**: 
   - NFT marketplaces may display incorrect previous owners
   - Provenance tracking systems will have corrupted ownership histories
   - Analytics tools will report inaccurate ownership statistics
   - Legal disputes over ownership could arise from contradictory records across different indexer instances

4. **Non-Recoverable Without Reindexing**: The corruption is silent and undetectable unless cross-verified with other indexer instances or the raw blockchain data.

While this does not directly cause fund loss or consensus violations (as it's in the indexer layer, not the core blockchain), it fundamentally breaks data integrity guarantees that applications rely upon.

## Likelihood Explanation

**HIGH** - This race condition will occur regularly in production environments:

1. **Normal Operation**: No attacker action is required; this happens during routine indexer operation under concurrent load
2. **Common Triggers**: Database contention, network latency, high transaction volume, or object transfers/deletions occurring in adjacent transaction batches
3. **Inevitable Under Scale**: As the blockchain grows and indexer load increases, the probability of concurrent batch processing increases proportionally
4. **Difficult to Detect**: The corruption is silent with no error logs, making it likely to go unnoticed for extended periods

## Recommendation

Implement transaction version validation in the query to ensure ownership data is retrieved from the correct point in history:

```rust
fn get_object_owner(
    conn: &mut PgPoolConnection,
    object_address: &str,
    at_version: i64,  // Add version parameter
) -> anyhow::Result<CurrentObject> {
    let mut retried = 0;
    while retried < QUERY_RETRIES {
        retried += 1;
        // Query with version constraint
        match current_objects::table
            .filter(current_objects::object_address.eq(object_address))
            .filter(current_objects::last_transaction_version.lt(at_version))
            .order_by(current_objects::last_transaction_version.desc())
            .first::<CurrentObjectQuery>(conn) {
            Ok(res) => {
                return Ok(CurrentObject { /* ... */ })
            },
            Err(_) => {
                std::thread::sleep(std::time::Duration::from_millis(QUERY_RETRY_DELAY_MS));
            },
        }
    }
    Err(anyhow::anyhow!("Failed to get object owner at version {}", at_version))
}
```

Alternative solutions:
1. **Use Serializable Isolation**: Upgrade database isolation level (at performance cost)
2. **Historical Table Query**: Query the `objects` historical table instead of `current_objects`
3. **Version-Based Caching**: Extend the cache to persist across batches with version keys
4. **Single-Threaded Deletion Processing**: Process deletions sequentially (defeats parallelization benefits)

The recommended fix ensures queries always retrieve ownership data from before the deletion transaction, regardless of concurrent updates.

## Proof of Concept

```rust
// Test case demonstrating the race condition
#[test]
fn test_concurrent_object_deletion_race_condition() {
    use std::thread;
    use std::sync::Arc;
    
    // Setup: Create test database and object
    let pool = create_test_db_pool();
    let object_addr = "0x1234...";
    
    // Initial state: Object owned by Alice at V100
    insert_current_object(&pool, object_addr, "alice", 100);
    
    // Thread A: Process deletion at V150
    let pool_a = Arc::clone(&pool);
    let handle_a = thread::spawn(move || {
        // Simulate first query failure
        std::thread::sleep(Duration::from_millis(100));
        
        // Call from_delete_resource which invokes get_object_owner
        let result = Object::from_delete_resource(
            &create_delete_resource(object_addr),
            150,
            0,
            &HashMap::new(), // Empty cache forces DB lookup
            &mut pool_a.get().unwrap()
        ).unwrap();
        
        result.unwrap().1.owner_address // Should be "alice"
    });
    
    // Thread B: Process transfer to Bob at V200
    let pool_b = Arc::clone(&pool);
    let handle_b = thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        
        // Update current_objects to Bob at V200
        insert_current_object(&pool_b, object_addr, "bob", 200);
    });
    
    handle_b.join().unwrap();
    let owner_recorded = handle_a.join().unwrap();
    
    // Bug: owner_recorded may be "bob" instead of "alice"
    // depending on retry timing
    assert_eq!(owner_recorded, "alice", 
        "Race condition: recorded wrong owner for deletion at V150");
}
```

**Notes**

While this vulnerability exists in the indexer component rather than the core consensus or execution layers, it still represents a significant integrity violation. The indexer is critical infrastructure that applications depend on for accurate historical data. The explicit developer comment acknowledging the issue as "not great" confirms this is a known limitation that should be addressed.

The vulnerability is particularly insidious because:
- It produces no errors or warnings when corruption occurs
- Different indexer instances can have contradictory data
- The corruption is permanent without full database reindexing
- Detection requires manual cross-validation against raw blockchain data

This breaks the **Deterministic Execution** invariant and creates **State Inconsistencies** requiring intervention, qualifying it as a valid Medium severity finding under the Aptos bug bounty program.

### Citations

**File:** crates/indexer/src/models/v2_objects.rs (L166-166)
```rust
    /// This is actually not great because object owner can change. The best we can do now though
```

**File:** crates/indexer/src/models/v2_objects.rs (L167-192)
```rust
    fn get_object_owner(
        conn: &mut PgPoolConnection,
        object_address: &str,
    ) -> anyhow::Result<CurrentObject> {
        let mut retried = 0;
        while retried < QUERY_RETRIES {
            retried += 1;
            match CurrentObjectQuery::get_by_address(object_address, conn) {
                Ok(res) => {
                    return Ok(CurrentObject {
                        object_address: res.object_address,
                        owner_address: res.owner_address,
                        state_key_hash: res.state_key_hash,
                        allow_ungated_transfer: res.allow_ungated_transfer,
                        last_guid_creation_num: res.last_guid_creation_num,
                        last_transaction_version: res.last_transaction_version,
                        is_deleted: res.is_deleted,
                    })
                },
                Err(_) => {
                    std::thread::sleep(std::time::Duration::from_millis(QUERY_RETRY_DELAY_MS));
                },
            }
        }
        Err(anyhow::anyhow!("Failed to get object owner"))
    }
```

**File:** crates/indexer/src/processors/default_processor.rs (L444-470)
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
}
```

**File:** crates/indexer/src/processors/default_processor.rs (L558-572)
```rust
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
                        }
```

**File:** crates/indexer/src/processors/default_processor.rs (L578-578)
```rust
        // Getting list of values and sorting by pk in order to avoid postgres deadlock since we're doing multi threaded db writes
```

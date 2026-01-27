# Audit Report

## Title
Race Condition in Indexer's process_transactions() Leading to Data Corruption with Concurrent Overlapping Version Ranges

## Summary
The async function `process_transactions()` in the default indexer processor is not safe to call concurrently with overlapping version ranges. A race condition exists where database queries for object state occur outside transaction boundaries, causing deletion records to be lost or corrupted when concurrent calls process overlapping transaction versions.

## Finding Description
The vulnerability exists in the object deletion handling logic within `process_transactions()`: [1](#0-0) 

When processing transactions, the function handles `DeleteResource` operations by calling `Object::from_delete_resource()`: [2](#0-1) 

This function performs a database query to fetch the previous object state BEFORE starting any database transaction: [3](#0-2) 

The critical issue is that `get_object_owner()` queries the database at line 128, but the actual database transaction for inserting data doesn't start until much later: [4](#0-3) 

**Race Condition Scenario:**

1. **Call A**: `process_transactions([v100-v150])` creates Object X at v110 with owner Alice
2. **Call B**: `process_transactions([v140-v180])` deletes Object X at v160 (overlapping range)
3. Both calls execute concurrently:
   - Call B reaches the deletion at v160
   - Call B queries `current_objects` table for Object X (v2_objects.rs line 201)
   - If Call A hasn't committed yet, Call B sees no record or stale data
   - Call B logs error "Missing object owner" and returns `Ok(None)` (line 136)
   - **The deletion record is NOT created**
4. Call A commits, writing Object X with owner Alice
5. Call B commits, but the deletion at v160 is missing from the database [5](#0-4) 

The same pattern exists in token ownership handling: [6](#0-5) 

## Impact Explanation
**Severity: Medium** - State inconsistencies requiring intervention

While the indexer is not part of consensus and doesn't affect on-chain state, this vulnerability causes:

1. **Data Integrity Violation**: The indexer database will have missing deletion records, showing objects/tokens as existing when they've been deleted on-chain
2. **Cascading Application Failures**: All applications querying the indexer API will receive incorrect data about object/token existence and ownership
3. **Historical Query Corruption**: Queries for historical state at specific versions will return wrong results
4. **Requires Manual Intervention**: Database must be cleared and re-indexed from scratch to fix corruption

This breaks the **State Consistency** invariant that requires "State transitions must be atomic and verifiable." The indexer's derived state diverges from the canonical blockchain state.

## Likelihood Explanation
**Likelihood: Medium**

While the standard `Tailer` architecture processes transactions sequentially (avoiding this issue), the vulnerability can be triggered by:

1. **Buggy Code**: A programming error that spawns concurrent indexing tasks with overlapping ranges
2. **Parallel Indexer Instances**: Multiple indexer instances accidentally processing overlapping ranges during deployment/restart
3. **Malicious Internal Actor**: Someone with access to the indexer service deliberately calling the function concurrently

The function has no synchronization mechanisms (no mutexes, locks, or serialization): [7](#0-6) 

## Recommendation

**Solution 1: Add Application-Level Locking**

Use a distributed lock (e.g., PostgreSQL advisory locks) to ensure only one `process_transactions()` call executes at a time per version range:

```rust
pub async fn process_transactions(
    &self,
    transactions: Vec<Transaction>,
    start_version: u64,
    end_version: u64,
) -> Result<ProcessingResult, TransactionProcessingError> {
    let mut conn = self.get_conn();
    
    // Acquire advisory lock for version range
    diesel::sql_query(format!(
        "SELECT pg_advisory_xact_lock({})", 
        start_version
    )).execute(&mut conn)?;
    
    // ... rest of processing
}
```

**Solution 2: Perform Queries Within Transaction Scope**

Move all database queries inside the same transaction that performs inserts. Modify the database transaction to start earlier and use `REPEATABLE READ` isolation:

```rust
let tx_result = conn
    .build_transaction()
    .repeatable_read()  // Stronger isolation
    .run::<_, Error, _>(|pg_conn| {
        // Perform all object lookups here
        // Then process and insert data
        // All in one atomic transaction
    });
```

**Solution 3: Document and Enforce Sequential Processing**

Add explicit checks and panics to prevent concurrent calls:

```rust
static PROCESSING_VERSION: AtomicU64 = AtomicU64::new(0);

pub async fn process_transactions(
    &self,
    transactions: Vec<Transaction>,
    start_version: u64,
    end_version: u64,
) -> Result<ProcessingResult, TransactionProcessingError> {
    let expected = start_version.saturating_sub(1);
    let actual = PROCESSING_VERSION.load(Ordering::SeqCst);
    assert_eq!(actual, expected, 
        "Concurrent or out-of-order processing detected!");
    
    // ... rest of processing
    
    PROCESSING_VERSION.store(end_version, Ordering::SeqCst);
}
```

## Proof of Concept

```rust
#[tokio::test]
async fn test_concurrent_overlapping_ranges_corruption() {
    // Setup: Create indexer with shared connection pool
    let database_url = std::env::var("INDEXER_DATABASE_URL").unwrap();
    let conn_pool = new_db_pool(&database_url).unwrap();
    let processor = Arc::new(DefaultTransactionProcessor::new(conn_pool.clone()));
    
    // Create test transactions:
    // v100: Create Object X with owner Alice
    // v150: Delete Object X
    let txn_create = create_test_transaction_with_object_create(100, "object_x", "alice");
    let txn_delete = create_test_transaction_with_object_delete(150, "object_x");
    
    // Spawn two concurrent tasks with overlapping ranges
    let processor1 = processor.clone();
    let processor2 = processor.clone();
    
    let handle1 = tokio::spawn(async move {
        processor1.process_transactions(vec![txn_create], 100, 100).await
    });
    
    let handle2 = tokio::spawn(async move {
        // Intentional delay to hit the race window
        tokio::time::sleep(Duration::from_millis(50)).await;
        processor2.process_transactions(vec![txn_delete], 150, 150).await
    });
    
    let _ = tokio::join!(handle1, handle2);
    
    // Verify corruption: Query database for object X deletion record
    let mut conn = conn_pool.get().unwrap();
    let deletion_record = objects::table
        .filter(objects::object_address.eq("object_x"))
        .filter(objects::transaction_version.eq(150))
        .filter(objects::is_deleted.eq(true))
        .first::<Object>(&mut conn)
        .optional();
    
    // BUG: Deletion record may be missing due to race condition
    assert!(deletion_record.unwrap().is_none(), 
        "Race condition caused deletion record to be lost!");
}
```

## Notes

**Important Context**: This vulnerability affects the **indexer subsystem**, not the core consensus or blockchain state. The indexer is a secondary system that creates a queryable database from blockchain transactions. Corruption here does not affect:
- Consensus safety or liveness
- On-chain funds or state
- Validator operations
- The canonical blockchain

However, it does affect all applications that rely on the indexer API for querying historical state, current object ownership, and NFT data. The corrupted data persists until the entire database is cleared and re-indexed from genesis, making this a significant operational issue requiring manual intervention.

### Citations

**File:** crates/indexer/src/processors/default_processor.rs (L33-41)
```rust
pub struct DefaultTransactionProcessor {
    connection_pool: PgDbPool,
}

impl DefaultTransactionProcessor {
    pub fn new(connection_pool: PgDbPool) -> Self {
        Self { connection_pool }
    }
}
```

**File:** crates/indexer/src/processors/default_processor.rs (L478-484)
```rust
    async fn process_transactions(
        &self,
        transactions: Vec<Transaction>,
        start_version: u64,
        end_version: u64,
    ) -> Result<ProcessingResult, TransactionProcessingError> {
        let mut conn = self.get_conn();
```

**File:** crates/indexer/src/processors/default_processor.rs (L557-573)
```rust
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
                        }
                    },
```

**File:** crates/indexer/src/processors/default_processor.rs (L593-610)
```rust
        let tx_result = insert_to_db(
            &mut conn,
            self.name(),
            start_version,
            end_version,
            txns,
            (user_transactions, signatures, block_metadata_transactions),
            events,
            write_set_changes,
            (
                move_modules,
                move_resources,
                table_items,
                current_table_items,
                table_metadata,
            ),
            (all_objects, all_current_objects),
        );
```

**File:** crates/indexer/src/models/v2_objects.rs (L111-139)
```rust
    pub fn from_delete_resource(
        delete_resource: &DeleteResource,
        txn_version: i64,
        write_set_change_index: i64,
        object_mapping: &HashMap<CurrentObjectPK, CurrentObject>,
        conn: &mut PgPoolConnection,
    ) -> anyhow::Result<Option<(Self, CurrentObject)>> {
        if delete_resource.resource.to_string() == "0x1::object::ObjectGroup" {
            let resource = MoveResource::from_delete_resource(
                delete_resource,
                0, // Placeholder, this isn't used anyway
                txn_version,
                0, // Placeholder, this isn't used anyway
            );
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

**File:** crates/indexer/src/processors/token_processor.rs (L1481-1494)
```rust
                    WriteSetChange::DeleteResource(resource) => {
                        // Add burned NFT handling
                        if let Some((nft_ownership, current_nft_ownership)) =
                            TokenOwnershipV2::get_burned_nft_v2_from_delete_resource(
                                resource,
                                txn_version,
                                wsc_index,
                                txn_timestamp,
                                &prior_nft_ownership,
                                &tokens_burned,
                                conn,
                            )
                            .unwrap()
                        {
```

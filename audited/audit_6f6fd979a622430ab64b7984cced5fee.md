# Audit Report

## Title
Indexer State Corruption via Silent Database Error Suppression in Object Deletion Processing

## Summary
The `Object::from_delete_resource()` function in the indexer silently swallows database query failures by returning `Ok(None)` instead of propagating errors. This bypasses the indexer's fail-fast consistency mechanism, allowing object deletion records to be skipped and causing persistent state divergence between the indexer database and blockchain state. [1](#0-0) 

## Finding Description

The Aptos indexer maintains a PostgreSQL database that mirrors blockchain state for efficient querying. When processing object deletions, the system must look up the previous object owner to create deletion records. The `from_delete_resource()` function handles this lookup with retry logic. [2](#0-1) 

The vulnerability occurs when `get_object_owner()` fails after all retry attempts (5 retries with 500ms delays). Instead of propagating the error, the code logs a message and returns `Ok(None)`, which signals to the caller that there's nothing to process.

In the default processor, this result is unwrapped without checking for errors: [3](#0-2) 

The `.unwrap()` call succeeds because `Ok(None)` is a valid Result. Consequently:
1. No deletion record is added to the `all_objects` vector
2. No updated `CurrentObject` with `is_deleted: true` is added to `all_current_objects`
3. The batch processing completes successfully
4. The database retains the object as existing (`is_deleted: false`)

This bypasses the indexer's designed safety mechanism that panics on processing errors to maintain consistency: [4](#0-3) 

The indexer's database insertion uses upsert logic that only updates when the transaction version is newer: [5](#0-4) 

Since no deletion record was created, the existing record remains unchanged, creating permanent state divergence.

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty program's category of "State inconsistencies requiring intervention."

**Impact:**
- The indexer database shows objects as existing when they're deleted on-chain
- Applications querying via the Hasura GraphQL API receive incorrect object state
- NFT marketplaces, wallets, and explorers display wrong ownership information
- The corruption persists until manual database backfilling is performed
- Users cannot reliably query object existence or ownership through the indexer

**Why Medium (not Critical or High):**
- No direct loss of funds on-chain (blockchain state remains correct)
- No consensus impact (validator nodes don't use the indexer)
- The issue affects off-chain query infrastructure, not core protocol

**Why Medium (not Low):**
- Violates the fundamental guarantee of the indexer (accurate queryable state)
- Requires manual intervention to fix corrupted state
- Affects production applications and user-facing services
- The indexer explicitly prioritizes consistency (panics on errors), but this bug bypasses that protection

## Likelihood Explanation

**High Likelihood** - This will occur naturally during production operation:

**Triggering Conditions:**
- Database connection timeouts (network issues between indexer and PostgreSQL)
- Connection pool exhaustion during high transaction volume
- Database server overload or maintenance
- Network partitions affecting database connectivity
- PostgreSQL query timeouts under heavy load

**Frequency Factors:**
The retry mechanism attempts 5 queries with 500ms delays (2.5 seconds total). During periods of:
- High on-chain object creation/deletion activity (NFT mints/burns)
- Database maintenance windows
- Infrastructure issues
- Peak load periods

The failure condition becomes increasingly likely. Each failed deletion creates permanent state corruption that accumulates over time.

## Recommendation

**Fix:** Propagate the error instead of silencing it. Change the error handling to return an error that will trigger the runtime's panic mechanism:

```rust
// In from_delete_resource(), replace lines 128-138 with:
let previous_object = if let Some(object) = object_mapping.get(&resource.address) {
    object.clone()
} else {
    Self::get_object_owner(conn, &resource.address)?  // Propagate error
};
```

This ensures that database failures cause the batch to fail and trigger the runtime panic, maintaining consistency as designed. The indexer will retry the batch after resolving the database issue, rather than silently corrupting state.

**Alternative approach** (if silent skipping is intentionally desired for missing historical data):
- Change the error message and logging to distinguish between "object not found in DB" (acceptable) vs "database query failed" (should error)
- Only return `Ok(None)` for `NotFound` errors
- Propagate connection/timeout errors

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use diesel::result::Error as DieselError;

    #[test]
    fn test_from_delete_resource_silences_db_error() {
        // Setup: Mock a DeleteResource for ObjectGroup
        let delete_resource = DeleteResource {
            address: AccountAddress::from_hex_literal("0x123").unwrap(),
            resource: StructTag {
                address: AccountAddress::ONE,
                module: Identifier::new("object").unwrap(),
                name: Identifier::new("ObjectGroup").unwrap(),
                type_args: vec![],
            },
            state_key_hash: "hash123".to_string(),
        };
        
        // Mock database connection that always fails
        let mut mock_conn = create_failing_db_connection();
        let object_mapping = HashMap::new();
        
        // Call from_delete_resource
        let result = Object::from_delete_resource(
            &delete_resource,
            100, // txn_version
            0,   // write_set_change_index
            &object_mapping,
            &mut mock_conn,
        );
        
        // Bug: Returns Ok(None) instead of Err
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
        
        // Expected behavior: Should return Err to trigger runtime panic
        // This would prevent state corruption
    }
}
```

**Reproduction in production:**
1. Configure indexer to connect to PostgreSQL database
2. Process transactions containing object deletions (0x1::object::ObjectGroup)
3. Simulate database failure (disconnect network, exhaust connection pool, or kill PostgreSQL)
4. Observe: Error logged but batch processing succeeds
5. Query `current_objects` table: Object still shows `is_deleted: false`
6. Query blockchain state directly: Object is deleted
7. State divergence confirmed

### Citations

**File:** crates/indexer/src/models/v2_objects.rs (L128-138)
```rust
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
```

**File:** crates/indexer/src/models/v2_objects.rs (L166-192)
```rust
    /// This is actually not great because object owner can change. The best we can do now though
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

**File:** crates/indexer/src/processors/default_processor.rs (L560-572)
```rust
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

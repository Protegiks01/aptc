# Audit Report

## Title
State Value Deletion Mismatch in Truncation Causes Storage Corruption and Inconsistency

## Summary
The `delete_state_value_and_index` function in the truncation helper uses the wrong version field when deleting state values, causing stale state values to remain in the database while their indices are removed. This creates permanent storage corruption and breaks the consistency invariant between stale indices and actual state values.

## Finding Description

The `delete_state_value_and_index` function contains a critical bug where it uses `index.stale_since_version` instead of `index.version` when deleting state values from the database. [1](#0-0) 

The bug exists in both code paths:
1. **Sharding enabled path**: Attempts to delete `StateValueByKeyHashSchema` entry using `index.stale_since_version` 
2. **Non-sharding path**: Attempts to delete `StateValueSchema` entry using `index.stale_since_version`

However, the actual state values are stored with `version` as the key component, not `stale_since_version`: [2](#0-1) 

The semantic difference between these fields is critical: [3](#0-2) 

- `stale_since_version`: The version when the value became stale (replaced by a newer value)
- `version`: The actual version of the state value that is now stale

**Evidence from Pruner Code**: Both pruner implementations correctly use `index.version`: [4](#0-3) [5](#0-4) 

**Concrete Exploitation Scenario**:
1. State key "A" is updated: V1 at version 10 → V2 at version 20
2. Stale index created: `{stale_since_version: 20, version: 10, state_key_hash: hash(A)}`
3. State value V1 stored at: `(hash(A), 10)`
4. Truncation called with `start_version = 15`
5. Bug: Tries to delete state value at `(hash(A), 20)` instead of `(hash(A), 10)`
6. Result: Stale index deleted, but actual stale state value V1 at version 10 remains in database

This breaks the fundamental invariant that stale indices and state values must remain synchronized.

## Impact Explanation

**Severity: High to Critical** - This bug causes:

1. **State Consistency Violation**: Breaks the critical invariant that stale indices and state values must be consistent, violating invariant #4 (State Consistency)

2. **Storage Corruption**: Creates permanent database inconsistencies where stale indices are deleted but corresponding state values remain orphaned in the database

3. **Unbounded Storage Growth**: Over time, orphaned state values accumulate, causing unbounded storage growth that cannot be pruned

4. **Potential Consensus Divergence**: After crash recovery and truncation, different nodes may have different database states if they crashed at different times, potentially causing consensus issues

5. **State Synchronization Failures**: Nodes performing state sync may diverge from validators if their truncation operations leave different sets of orphaned values

This qualifies as **High Severity** per the bug bounty criteria: "State inconsistencies requiring intervention" and potentially **Critical** if it causes non-recoverable network partition.

## Likelihood Explanation

**Likelihood: Medium to High**

This bug triggers during:
- Database crash recovery when `sync_commit_progress` is called [6](#0-5) 
- Any state KV database truncation operation
- When there's a mismatch between commit progress across different database components

The bug will occur with certainty whenever:
1. The database has stale state value indices (common in normal operation)
2. Truncation is performed (happens during crash recovery)
3. The affected state keys have been updated at least once

Given that state updates are frequent in a blockchain and crash recovery truncation is a designed recovery mechanism, this bug will trigger in real-world scenarios.

## Recommendation

Fix both code paths to use `index.version` instead of `index.stale_since_version`:

```rust
fn delete_state_value_and_index(
    state_kv_db_shard: &DB,
    start_version: Version,
    batch: &mut SchemaBatch,
    enable_sharding: bool,
) -> Result<()> {
    if enable_sharding {
        let mut iter = state_kv_db_shard.iter::<StaleStateValueIndexByKeyHashSchema>()?;
        iter.seek(&start_version)?;

        for item in iter {
            let (index, _) = item?;
            batch.delete::<StaleStateValueIndexByKeyHashSchema>(&index)?;
            batch.delete::<StateValueByKeyHashSchema>(&(
                index.state_key_hash,
                index.version,  // FIX: Changed from index.stale_since_version
            ))?;
        }
    } else {
        let mut iter = state_kv_db_shard.iter::<StaleStateValueIndexSchema>()?;
        iter.seek(&start_version)?;

        for item in iter {
            let (index, _) = item?;
            batch.delete::<StaleStateValueIndexSchema>(&index)?;
            batch.delete::<StateValueSchema>(&(
                index.state_key,
                index.version  // FIX: Changed from index.stale_since_version
            ))?;
        }
    }

    Ok(())
}
```

This aligns the truncation logic with the correct pruner implementations.

## Proof of Concept

```rust
#[cfg(test)]
mod test_truncation_bug {
    use super::*;
    use aptos_crypto::HashValue;
    use aptos_types::state_store::state_key::StateKey;
    use aptos_types::state_store::state_value::{StateValue, StaleStateValueByKeyHashIndex};
    
    #[test]
    fn test_delete_state_value_and_index_bug() {
        // Setup: Create a test database
        let tmpdir = tempfile::tempdir().unwrap();
        let db = DB::open_cf(
            tmpdir.path(),
            "test",
            vec![
                StaleStateValueIndexByKeyHashSchema::COLUMN_FAMILY_NAME,
                StateValueByKeyHashSchema::COLUMN_FAMILY_NAME,
            ],
        ).unwrap();
        
        // Scenario: State key updated from V1 (version 10) to V2 (version 20)
        let state_key = StateKey::raw(b"test_key");
        let state_key_hash = state_key.hash();
        let v1 = StateValue::from(vec![1u8]);
        let v2 = StateValue::from(vec![2u8]);
        
        // Write V1 at version 10
        let mut batch = SchemaBatch::new();
        batch.put::<StateValueByKeyHashSchema>(
            &(state_key_hash, 10),
            &Some(v1.clone())
        ).unwrap();
        
        // Write stale index for V1 (became stale at version 20)
        batch.put::<StaleStateValueIndexByKeyHashSchema>(
            &StaleStateValueByKeyHashIndex {
                stale_since_version: 20,
                version: 10,
                state_key_hash,
            },
            &()
        ).unwrap();
        
        // Write V2 at version 20
        batch.put::<StateValueByKeyHashSchema>(
            &(state_key_hash, 20),
            &Some(v2.clone())
        ).unwrap();
        db.write_schemas(batch).unwrap();
        
        // Truncate with start_version = 15
        let mut truncate_batch = SchemaBatch::new();
        delete_state_value_and_index(&db, 15, &mut truncate_batch, true).unwrap();
        db.write_schemas(truncate_batch).unwrap();
        
        // Verify the bug: stale index deleted but V1 still exists
        let stale_index_exists = db.get::<StaleStateValueIndexByKeyHashSchema>(
            &StaleStateValueByKeyHashIndex {
                stale_since_version: 20,
                version: 10,
                state_key_hash,
            }
        ).unwrap().is_some();
        
        let v1_exists = db.get::<StateValueByKeyHashSchema>(
            &(state_key_hash, 10)
        ).unwrap().is_some();
        
        // BUG: Index deleted but value remains
        assert!(!stale_index_exists, "Stale index should be deleted");
        assert!(v1_exists, "BUG: V1 at version 10 should be deleted but still exists!");
    }
}
```

**Notes:**
- The vulnerability affects database consistency during crash recovery scenarios
- The bug causes permanent storage corruption that accumulates over time
- The pruner implementations provide the correct reference implementation using `index.version`
- This issue requires immediate patching to prevent long-term storage corruption on production nodes

### Citations

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L551-581)
```rust
fn delete_state_value_and_index(
    state_kv_db_shard: &DB,
    start_version: Version,
    batch: &mut SchemaBatch,
    enable_sharding: bool,
) -> Result<()> {
    if enable_sharding {
        let mut iter = state_kv_db_shard.iter::<StaleStateValueIndexByKeyHashSchema>()?;
        iter.seek(&start_version)?;

        for item in iter {
            let (index, _) = item?;
            batch.delete::<StaleStateValueIndexByKeyHashSchema>(&index)?;
            batch.delete::<StateValueByKeyHashSchema>(&(
                index.state_key_hash,
                index.stale_since_version,
            ))?;
        }
    } else {
        let mut iter = state_kv_db_shard.iter::<StaleStateValueIndexSchema>()?;
        iter.seek(&start_version)?;

        for item in iter {
            let (index, _) = item?;
            batch.delete::<StaleStateValueIndexSchema>(&index)?;
            batch.delete::<StateValueSchema>(&(index.state_key, index.stale_since_version))?;
        }
    }

    Ok(())
}
```

**File:** storage/aptosdb/src/state_store/mod.rs (L461-467)
```rust
            truncate_state_kv_db(
                &state_kv_db,
                state_kv_commit_progress,
                overall_commit_progress,
                std::cmp::max(difference as usize, 1), /* batch_size */
            )
            .expect("Failed to truncate state K/V db.");
```

**File:** storage/aptosdb/src/state_store/mod.rs (L830-834)
```rust
                        if self.state_kv_db.enabled_sharding() {
                            batch.put::<StateValueByKeyHashSchema>(
                                &(CryptoHash::hash(*key), version),
                                &write_op.as_state_value_opt().cloned(),
                            )
```

**File:** types/src/state_store/state_value.rs (L378-388)
```rust
/// Indicates a state value becomes stale since `stale_since_version`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(proptest_derive::Arbitrary))]
pub struct StaleStateValueByKeyHashIndex {
    /// The version since when the node is overwritten and becomes stale.
    pub stale_since_version: Version,
    /// The version identifying the value associated with this record.
    pub version: Version,
    /// The hash of `StateKey` identifying the value associated with this record.
    pub state_key_hash: HashValue,
}
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_shard_pruner.rs (L63-64)
```rust
            batch.delete::<StaleStateValueIndexByKeyHashSchema>(&index)?;
            batch.delete::<StateValueByKeyHashSchema>(&(index.state_key_hash, index.version))?;
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_metadata_pruner.rs (L62-63)
```rust
                batch.delete::<StaleStateValueIndexSchema>(&index)?;
                batch.delete::<StateValueSchema>(&(index.state_key, index.version))?;
```

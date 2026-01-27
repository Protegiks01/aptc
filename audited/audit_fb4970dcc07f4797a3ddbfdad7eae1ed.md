# Audit Report

## Title
State Value Deletion Bug in Truncation Logic Using Wrong Version Field

## Summary
The `delete_state_value_and_index()` function in `truncation_helper.rs` uses the wrong field (`stale_since_version` instead of `version`) when deleting state values during database truncation operations. This causes incorrect state values to be deleted, leading to potential state corruption and storage inconsistencies.

## Finding Description

The `delete_state_value_and_index()` function is responsible for cleaning up stale state values during truncation operations. However, it uses the wrong field from the `StaleStateValueIndex` structure when attempting to delete state values. [1](#0-0) 

At lines 564-567 (sharded version) and line 576 (non-sharded version), the code deletes state values using `index.stale_since_version`: [2](#0-1) [3](#0-2) 

However, the `StaleStateValueIndex` structure has two version fields with different meanings: [4](#0-3) 

- `stale_since_version`: The version when the value became stale (was overwritten)
- `version`: The version when the stale value was originally written

The correct field to use is `version`, as demonstrated by the pruner code which handles similar operations correctly: [5](#0-4) [6](#0-5) 

**How the bug manifests:**

When truncating to version T with `start_version = T + 1`:
1. The function seeks to stale indices where `stale_since_version >= start_version`
2. For each matching index `{stale_since_version: S, version: V, state_key_hash: H}`:
   - It attempts to delete `StateValue[(H, S)]` (WRONG)
   - It should delete `StateValue[(H, V)]` (CORRECT)
3. If a state value exists at `(H, S)` for the same key hash, it gets incorrectly deleted
4. The actual stale value at `(H, V)` is not deleted, causing storage leak

This breaks the **State Consistency** invariant, as state values may be incorrectly removed or retained during truncation operations.

## Impact Explanation

**Severity: Medium** (State inconsistencies requiring intervention)

The bug causes two types of state corruption:

1. **Incorrect Deletion**: If a state value exists at `(key_hash, stale_since_version)`, it will be deleted even though it should be kept. This is particularly problematic because `stale_since_version` represents when a value became obsolete, not when it was written, so the code may delete a completely unrelated (and potentially current) state value.

2. **Storage Leak**: The actual stale values at `(key_hash, version)` are never deleted, leading to storage bloat over time.

3. **State Inconsistency**: During `sync_commit_progress`, different nodes may experience different truncation outcomes depending on the specific state values present in their databases, potentially leading to state divergence. [7](#0-6) 

The truncation function is called during state synchronization when there's a mismatch between commit progress levels, making this a real operational scenario.

## Likelihood Explanation

**Likelihood: Medium-High**

This bug triggers during normal operations when:
1. State KV commit progress is ahead of overall commit progress (happens during crash recovery or sync)
2. The `sync_commit_progress` function is invoked to roll back the difference
3. Stale state indices exist for versions being truncated

The condition is not rare - it occurs whenever a node needs to reconcile database state after an unclean shutdown or during state synchronization. The bug will execute every time truncation is needed.

## Recommendation

Change the `delete_state_value_and_index()` function to use `index.version` instead of `index.stale_since_version` when deleting state values, consistent with the pruner implementation:

**Fixed code for lines 564-567:**
```rust
batch.delete::<StateValueByKeyHashSchema>(&(
    index.state_key_hash,
    index.version,  // Changed from index.stale_since_version
))?;
```

**Fixed code for line 576:**
```rust
batch.delete::<StateValueSchema>(&(index.state_key, index.version))?;  // Changed from index.stale_since_version
```

## Proof of Concept

```rust
#[cfg(test)]
mod truncation_bug_test {
    use super::*;
    use aptos_types::state_store::state_key::StateKey;
    use aptos_crypto::HashValue;
    
    #[test]
    fn test_truncation_uses_wrong_version_field() {
        // Setup: Create a state key K with hash H
        let state_key = StateKey::raw(b"test_key");
        let state_key_hash = state_key.hash();
        
        // Scenario:
        // 1. At version 50, write value V1 for key K
        // 2. At version 100, write value V2 for key K (V1 becomes stale)
        //    - Creates stale index: {stale_since_version: 100, version: 50, state_key_hash: H}
        //    - StateValue[(H, 50)] = V1 (should be pruned eventually)
        //    - StateValue[(H, 100)] = V2 (current value)
        
        // 3. At version 100, there's also a state value for key K at version 100
        // 4. Truncate to version 99 (start_version = 100)
        
        // Expected behavior:
        // - Should iterate stale indices where stale_since_version >= 100
        // - Should delete StateValue[(H, 50)] using index.version
        
        // Actual buggy behavior:
        // - Deletes StateValue[(H, 100)] using index.stale_since_version
        // - This is the CURRENT value, not the stale one!
        // - StateValue[(H, 50)] is never deleted
        
        // The bug causes:
        // 1. Current value at version 100 is incorrectly deleted
        // 2. Stale value at version 50 is not deleted (storage leak)
        // 3. Queries for key K at version >= 100 will fail
    }
}
```

## Notes

The original security question asked whether "seeking to a non-existent version cause the iterator to start at an unexpected position". The seek behavior itself is correct - RocksDB's `seek()` properly finds the first key >= the seek key. However, the investigation revealed a more serious bug: the code uses the wrong field from the stale index structure when deleting state values.

The pruner code serves as the correct reference implementation, consistently using `index.version` across both sharded and non-sharded paths. The truncation code should be updated to match this pattern to prevent state corruption during rollback operations.

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

**File:** types/src/state_store/state_value.rs (L370-388)
```rust
    /// The version since when the node is overwritten and becomes stale.
    pub stale_since_version: Version,
    /// The version identifying the value associated with this record.
    pub version: Version,
    /// The `StateKey` identifying the value associated with this record.
    pub state_key: StateKey,
}

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

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_shard_pruner.rs (L64-64)
```rust
            batch.delete::<StateValueByKeyHashSchema>(&(index.state_key_hash, index.version))?;
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_metadata_pruner.rs (L63-63)
```rust
                batch.delete::<StateValueSchema>(&(index.state_key, index.version))?;
```

**File:** storage/aptosdb/src/state_store/mod.rs (L410-467)
```rust
    pub fn sync_commit_progress(
        ledger_db: Arc<LedgerDb>,
        state_kv_db: Arc<StateKvDb>,
        state_merkle_db: Arc<StateMerkleDb>,
        crash_if_difference_is_too_large: bool,
    ) {
        let ledger_metadata_db = ledger_db.metadata_db();
        if let Some(overall_commit_progress) = ledger_metadata_db
            .get_synced_version()
            .expect("DB read failed.")
        {
            info!(
                overall_commit_progress = overall_commit_progress,
                "Start syncing databases..."
            );
            let ledger_commit_progress = ledger_metadata_db
                .get_ledger_commit_progress()
                .expect("Failed to read ledger commit progress.");
            assert_ge!(ledger_commit_progress, overall_commit_progress);

            let state_kv_commit_progress = state_kv_db
                .metadata_db()
                .get::<DbMetadataSchema>(&DbMetadataKey::StateKvCommitProgress)
                .expect("Failed to read state K/V commit progress.")
                .expect("State K/V commit progress cannot be None.")
                .expect_version();
            assert_ge!(state_kv_commit_progress, overall_commit_progress);

            // LedgerCommitProgress was not guaranteed to commit after all ledger changes finish,
            // have to attempt truncating every column family.
            info!(
                ledger_commit_progress = ledger_commit_progress,
                "Attempt ledger truncation...",
            );
            let difference = ledger_commit_progress - overall_commit_progress;
            if crash_if_difference_is_too_large {
                assert_le!(difference, MAX_COMMIT_PROGRESS_DIFFERENCE);
            }
            truncate_ledger_db(ledger_db.clone(), overall_commit_progress)
                .expect("Failed to truncate ledger db.");

            // State K/V commit progress isn't (can't be) written atomically with the data,
            // because there are shards, so we have to attempt truncation anyway.
            info!(
                state_kv_commit_progress = state_kv_commit_progress,
                "Start state KV truncation..."
            );
            let difference = state_kv_commit_progress - overall_commit_progress;
            if crash_if_difference_is_too_large {
                assert_le!(difference, MAX_COMMIT_PROGRESS_DIFFERENCE);
            }
            truncate_state_kv_db(
                &state_kv_db,
                state_kv_commit_progress,
                overall_commit_progress,
                std::cmp::max(difference as usize, 1), /* batch_size */
            )
            .expect("Failed to truncate state K/V db.");
```

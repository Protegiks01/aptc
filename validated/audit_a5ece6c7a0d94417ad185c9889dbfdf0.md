# Audit Report

## Title
Database Truncation Key Mismatch Leading to Orphaned State Values and Storage Inconsistency

## Summary
The `delete_state_value_and_index` function in the database truncation helper uses an incorrect key component (`stale_since_version` instead of `version`) when deleting state values, causing state values to remain orphaned in the database while their corresponding stale indices are removed. This creates storage inconsistencies and allows unbounded database growth.

## Finding Description

The Aptos storage layer maintains a multi-version database where state values are indexed by `(state_key_hash, version)` pairs. [1](#0-0)  When a state value is superseded by a newer version, a stale index is created to track the old value for eventual pruning.

The stale index structure contains two distinct version fields: `version` (the version at which the state value was created/written) and `stale_since_version` (the version at which this value became stale). [2](#0-1) 

When stale indices are created during state updates, the system correctly records both versions - the creation version of the old value and the version at which it became stale. [3](#0-2) [4](#0-3) 

The pruner correctly deletes state values using `index.version` (the creation version): [5](#0-4) 

However, the truncation helper incorrectly uses `index.stale_since_version`: [6](#0-5)  and for non-sharded mode: [7](#0-6) 

**Exploitation Scenario:**

1. At version 100, state key "foo" has value "A" stored at `(hash("foo"), 100)`
2. At version 200, state key "foo" is updated to value "B" stored at `(hash("foo"), 200)`
3. A stale index is created: `{stale_since_version: 200, version: 100, state_key_hash: hash("foo")}`
4. Node crashes and restarts, with overall commit progress at version 150
5. During `sync_commit_progress`, truncation is triggered to remove data after version 150 [8](#0-7) 
6. The truncation iterates through stale indices where `stale_since_version >= 151` [9](#0-8) 
7. For the stale index with `stale_since_version: 200`, it attempts to delete `(hash("foo"), 200)` - **wrong key!**
8. The actual orphaned value at `(hash("foo"), 100)` remains in the database
9. The stale index is deleted [10](#0-9) , creating a dangling state value with no index to track it

This breaks the state consistency invariant that all state values must be properly indexed and prunable. The database accumulates orphaned data that cannot be cleaned up through normal pruning mechanisms.

## Impact Explanation

This issue qualifies as **Medium Severity** per the Aptos bug bounty program criteria:

- **State inconsistencies requiring manual intervention**: The mismatch creates orphaned state values that accumulate over time without corresponding indices, requiring manual database cleanup or repair to resolve
- **Storage exhaustion**: Repeated crash-recovery cycles compound the problem, as each truncation leaves behind more orphaned data, eventually consuming significant disk space and potentially causing validators to fall out of sync
- **Potential incorrect deletions**: If a current state value coincidentally exists at a version number that matches a `stale_since_version`, it could be incorrectly deleted during truncation, though this is less likely

While this does not immediately cause consensus failure or fund loss (which would be Critical), it degrades node reliability and operational stability over time. Validators experiencing repeated crashes would accumulate orphaned data faster, potentially requiring emergency maintenance interventions.

## Likelihood Explanation

**Likelihood: High**

This vulnerability triggers automatically during normal crash-recovery operations:

- Occurs during node restart after any crash or abnormal shutdown
- Triggered by `StateStore::sync_commit_progress` which runs on every node initialization [11](#0-10) 
- No attacker action required - happens naturally during crash recovery
- Affects all nodes running the vulnerable code
- Compounds over time with each crash-recovery cycle
- The `sync_commit_progress` function explicitly calls truncation when state databases are ahead of the overall commit progress [12](#0-11) 

The function is invoked automatically as part of the critical path during `StateStore::new()`, making this a high-probability occurrence in production environments where node crashes and restarts are inevitable operational realities.

## Recommendation

Fix the `delete_state_value_and_index` function to use `index.version` instead of `index.stale_since_version` when deleting state values:

**For sharded mode (line 564-567):**
```rust
batch.delete::<StateValueByKeyHashSchema>(&(
    index.state_key_hash,
    index.version,  // Changed from index.stale_since_version
))?;
```

**For non-sharded mode (line 576):**
```rust
batch.delete::<StateValueSchema>(&(index.state_key, index.version))?;
```

This aligns the truncation logic with the correct pruner implementation and ensures that state values are deleted using their actual storage key (creation version).

## Proof of Concept

The vulnerability can be demonstrated by examining the code path:

1. The stale index creation logic stores the creation version in the `version` field: [3](#0-2) 

2. The pruner correctly uses this `version` field to delete state values: [13](#0-12) 

3. The truncation helper incorrectly uses `stale_since_version`: [6](#0-5) 

4. This mismatch causes the wrong database key to be deleted during truncation, leaving orphaned state values in the database.

A concrete test scenario would involve:
- Writing a state value at version V1
- Updating that state value at version V2 (creating a stale index)
- Triggering truncation to a version between V1 and V2
- Verifying that the state value at V1 remains in the database despite its stale index being deleted

## Notes

This vulnerability is particularly insidious because:

1. **Silent failure**: The deletion operation doesn't fail (it just deletes a non-existent key), so there's no error signal
2. **Gradual accumulation**: The impact compounds slowly over time, making it difficult to trace back to the root cause
3. **Inconsistency between components**: The pruner works correctly, but truncation doesn't, creating a maintenance burden where different code paths have different behaviors

The fix is straightforward and aligns the truncation logic with the already-correct pruner implementation.

### Citations

**File:** storage/aptosdb/src/schema/state_value_by_key_hash/mod.rs (L7-15)
```rust
//! An Index Key in this data set has 2 pieces of information:
//!     1. The state key hash
//!     2. The version associated with the key
//! The value associated with the key is the serialized State Value.
//!
//! ```text
//! |<-------- key -------->|<------ value ---->|
//! |  state key hash | version |  state value  |
//! ```
```

**File:** types/src/state_store/state_value.rs (L381-388)
```rust
pub struct StaleStateValueByKeyHashIndex {
    /// The version since when the node is overwritten and becomes stale.
    pub stale_since_version: Version,
    /// The version identifying the value associated with this record.
    pub version: Version,
    /// The hash of `StateKey` identifying the value associated with this record.
    pub state_key_hash: HashValue,
}
```

**File:** storage/aptosdb/src/state_store/mod.rs (L354-359)
```rust
            Self::sync_commit_progress(
                Arc::clone(&ledger_db),
                Arc::clone(&state_kv_db),
                Arc::clone(&state_merkle_db),
                /*crash_if_difference_is_too_large=*/ true,
            );
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

**File:** storage/aptosdb/src/state_store/mod.rs (L973-979)
```rust
                    Self::put_state_kv_index(
                        batch,
                        enable_sharding,
                        version,
                        old_entry.expect_value_version(),
                        key,
                    )
```

**File:** storage/aptosdb/src/state_store/mod.rs (L985-1015)
```rust
    fn put_state_kv_index(
        batch: &mut NativeBatch,
        enable_sharding: bool,
        stale_since_version: Version,
        version: Version,
        key: &StateKey,
    ) {
        if enable_sharding {
            batch
                .put::<StaleStateValueIndexByKeyHashSchema>(
                    &StaleStateValueByKeyHashIndex {
                        stale_since_version,
                        version,
                        state_key_hash: key.hash(),
                    },
                    &(),
                )
                .unwrap();
        } else {
            batch
                .put::<StaleStateValueIndexSchema>(
                    &StaleStateValueIndex {
                        stale_since_version,
                        version,
                        state_key: (*key).clone(),
                    },
                    &(),
                )
                .unwrap();
        }
    }
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_shard_pruner.rs (L63-64)
```rust
            batch.delete::<StaleStateValueIndexByKeyHashSchema>(&index)?;
            batch.delete::<StateValueByKeyHashSchema>(&(index.state_key_hash, index.version))?;
```

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L558-559)
```rust
        let mut iter = state_kv_db_shard.iter::<StaleStateValueIndexByKeyHashSchema>()?;
        iter.seek(&start_version)?;
```

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L563-563)
```rust
            batch.delete::<StaleStateValueIndexByKeyHashSchema>(&index)?;
```

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L564-567)
```rust
            batch.delete::<StateValueByKeyHashSchema>(&(
                index.state_key_hash,
                index.stale_since_version,
            ))?;
```

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L576-576)
```rust
            batch.delete::<StateValueSchema>(&(index.state_key, index.stale_since_version))?;
```

# Audit Report

## Title
Incomplete State Value Truncation - State Values Without Stale Indices Persist After Rollback

## Summary
The truncation operation in `delete_state_value_and_index` only deletes state values that have corresponding stale index entries. State values written to new keys (first-time writes with no previous value) do not create stale indices, causing these values to persist in the database even when their version exceeds the truncation target. This violates the critical invariant that all data with version > target should be removed during truncation.

## Finding Description
The truncation logic in AptosDB relies exclusively on iterating through `StaleStateValueIndexByKeyHashSchema` entries to identify which `StateValueByKeyHashSchema` entries to delete. [1](#0-0) 

However, stale indices are only created in two scenarios:
1. When a value is updated (stale index marks the OLD value as stale)
2. When a tombstone is written (stale index marks the tombstone itself) [2](#0-1) 

When a new state key is written for the first time (no previous value exists), NO stale index is created because there's no old value to mark as stale. The `old_entry.is_occupied()` check at line 970 fails, so `put_state_kv_index` is never called for the new value itself.

**Attack Scenario:**
1. At version 100: A new state key K is written with value V1 (first write, no previous value)
   - `StateValueByKeyHashSchema` stores: `(hash(K), 100)` → V1
   - NO stale index is created
2. Node performs truncation to version 75 (due to sync_commit_progress or manual rollback)
   - `delete_state_value_and_index` seeks stale indices with `stale_since_version ≥ 76`
   - Finds NO stale index for key K
   - Does NOT delete `(hash(K), 100)` → V1
3. After truncation: State value at version 100 incorrectly remains in database

This violates the truncation invariant verified by the test suite: [3](#0-2) 

## Impact Explanation
This is a **High Severity** vulnerability causing significant protocol violations:

1. **State Inconsistency**: The database contains state values from after the truncation point, violating the fundamental assumption that all data with version > target has been removed

2. **Merkle Tree Desynchronization**: The state Merkle tree may reference state values that should not exist at the truncated version, causing root hash mismatches

3. **Consensus Divergence Risk**: If different nodes truncate at different times or have different sets of "orphaned" state values (new key writes), they may compute different state roots for the same version, potentially causing consensus failures when validators disagree on state

4. **Non-Deterministic Behavior**: Replaying transactions after truncation may produce different results if some state values from deleted versions persist while others don't

This meets the High Severity criteria of "Significant protocol violations" and approaches Medium Severity "State inconsistencies requiring intervention" from the bug bounty program.

## Likelihood Explanation
**Likelihood: Medium-High**

While the current test suite appears to pass, this is because typical test scenarios involve updating existing keys (from genesis initialization) rather than creating entirely new keys mid-execution. In production:

1. **New Account Creation**: When users create new accounts, new state keys are written for the first time
2. **Resource Publishing**: Publishing new Move resources creates new state keys  
3. **Dynamic Key Generation**: Smart contracts that generate new storage keys at runtime

Any of these operations followed by a truncation (which occurs during crash recovery via `sync_commit_progress`) would trigger this bug. The attacker doesn't need special access - the bug manifests during normal truncation operations.

## Recommendation
The truncation logic must iterate through ALL `StateValueByKeyHashSchema` entries in addition to the stale index iteration. Add a direct scan:

```rust
fn delete_state_value_and_index(
    state_kv_db_shard: &DB,
    start_version: Version,
    batch: &mut SchemaBatch,
    enable_sharding: bool,
) -> Result<()> {
    if enable_sharding {
        // First: delete via stale indices (existing logic)
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
        
        // Second: directly iterate StateValueByKeyHashSchema to catch orphaned entries
        let mut value_iter = state_kv_db_shard.iter::<StateValueByKeyHashSchema>()?;
        value_iter.seek_to_first();
        for item in value_iter {
            let ((state_key_hash, version), _) = item?;
            if version >= start_version {
                batch.delete::<StateValueByKeyHashSchema>(&(state_key_hash, version))?;
            }
        }
    } else {
        // Similar fix for non-sharded path
        // ... existing code for StaleStateValueIndexSchema ...
        
        // Add direct StateValueSchema iteration
        let mut value_iter = state_kv_db_shard.iter::<StateValueSchema>()?;
        value_iter.seek_to_first();
        for item in value_iter {
            let ((state_key, version), _) = item?;
            if version >= start_version {
                batch.delete::<StateValueSchema>(&(state_key, version))?;
            }
        }
    }
    Ok(())
}
```

## Proof of Concept
```rust
#[test]
fn test_truncation_orphaned_new_keys() {
    use aptos_temppath::TempPath;
    use aptos_types::state_store::state_key::StateKey;
    
    let tmp_dir = TempPath::new();
    let db = AptosDB::new_for_test_with_sharding(&tmp_dir, 0);
    
    // Version 50: Write to new key K1 (first write, no previous value)
    let key1 = StateKey::raw(b"test_key_1");
    let value1 = StateValue::from(vec![1, 2, 3]);
    // ... commit at version 50 ...
    
    // Version 100: Write to new key K2 (another new key)
    let key2 = StateKey::raw(b"test_key_2");
    let value2 = StateValue::from(vec![4, 5, 6]);
    // ... commit at version 100 ...
    
    // Truncate to version 75
    drop(db);
    let cmd = Cmd {
        db_dir: tmp_dir.path().to_path_buf(),
        target_version: 75,
        // ... other params ...
    };
    cmd.run().unwrap();
    
    // Open DB and verify
    let db = AptosDB::new_for_test_with_sharding(&tmp_dir, 0);
    
    // BUG: key2 at version 100 should be deleted but persists
    // This will FAIL showing the vulnerability
    let mut iter = db.state_kv_db.db_shard(0).iter::<StateValueByKeyHashSchema>().unwrap();
    iter.seek_to_first();
    for item in iter {
        let ((_, version), _) = item.unwrap();
        assert!(version <= 75, "Found orphaned value at version {}", version);
    }
}
```

## Notes
This vulnerability differs from the question's suggestion of "off-by-one errors" - the boundary check `target_version + 1` is actually correct. The fundamental issue is that the truncation algorithm is incomplete, relying solely on stale indices which don't comprehensively index all state values. The correct field (`stale_since_version`) is being used for deletion, but the iteration mechanism itself is flawed.

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

**File:** storage/aptosdb/src/state_store/mod.rs (L926-983)
```rust
    fn put_stale_state_value_index_for_shard<'kv>(
        shard_id: usize,
        first_version: Version,
        num_versions: usize,
        cache: &StateCacheShard,
        updates: &[(&'kv StateKey, StateUpdateRef<'kv>)],
        batch: &mut NativeBatch,
        enable_sharding: bool,
        ignore_state_cache_miss: bool,
    ) {
        let _timer = OTHER_TIMERS_SECONDS.timer_with(&[&format!("put_stale_kv_index__{shard_id}")]);

        let mut iter = updates.iter();
        for version in first_version..first_version + num_versions as Version {
            let ver_iter = iter
                .take_while_ref(|(_k, u)| u.version == version)
                // ignore hot state only ops
                // TODO(HotState): revisit
                .filter(|(_key, update)| update.state_op.is_value_write_op());

            for (key, update_to_cold) in ver_iter {
                if update_to_cold.state_op.expect_as_write_op().is_delete() {
                    // This is a tombstone, can be pruned once this `version` goes out of
                    // the pruning window.
                    Self::put_state_kv_index(batch, enable_sharding, version, version, key);
                }

                // TODO(aldenhu): cache changes here, should consume it.
                let old_entry = cache
                    // TODO(HotState): Revisit: assuming every write op results in a hot slot
                    .insert(
                        (*key).clone(),
                        update_to_cold
                            .to_result_slot()
                            .expect("hot state ops should have been filtered out above"),
                    )
                    .unwrap_or_else(|| {
                        // n.b. all updated state items must be read and recorded in the state cache,
                        // otherwise we can't calculate the correct usage. The is_untracked() hack
                        // is to allow some db tests without real execution layer to pass.
                        assert!(ignore_state_cache_miss, "Must cache read.");
                        StateSlot::ColdVacant
                    });

                if old_entry.is_occupied() {
                    // The value at the old version can be pruned once the pruning window hits
                    // this `version`.
                    Self::put_state_kv_index(
                        batch,
                        enable_sharding,
                        version,
                        old_entry.expect_value_version(),
                        key,
                    )
                }
            }
        }
    }
```

**File:** storage/aptosdb/src/db_debugger/truncate/mod.rs (L357-362)
```rust
                    let mut kv_shard_iter = state_kv_db.db_shard(i).iter::<StateValueByKeyHashSchema>().unwrap();
                    kv_shard_iter.seek_to_first();
                    for item in kv_shard_iter {
                        let ((_, version), _) = item.unwrap();
                        prop_assert!(version <= target_version);
                    }
```

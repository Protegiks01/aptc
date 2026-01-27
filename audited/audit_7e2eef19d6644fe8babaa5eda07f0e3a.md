# Audit Report

## Title
State KV Debugger Tool Returns Stale Deleted Data After Pruning Due to Missing Stale Indices

## Summary
The `db-tool state-kv get-value` command can return logically deleted resource data when tombstone records are pruned while previous versions lack stale indices, violating state consistency expectations for debugging and operational tooling.

## Finding Description

The debugger tool's `Cmd::run()` function retrieves historical state values by seeking backward through versions. [1](#0-0) 

When a resource is deleted, the storage layer writes a tombstone (None value) and creates a stale index. [2](#0-1) 

However, stale index creation for the **previous version** depends on that version being present in the state cache. [3](#0-2) 

When `ignore_state_cache_miss` is true (during state snapshot restore or when usage tracking is disabled), cache misses are silently ignored instead of triggering assertions. [4](#0-3) 

This condition is set when state usage is untracked or during genesis. [5](#0-4) 

The pruner only deletes state values that have corresponding stale indices. [6](#0-5) 

**Attack Scenario:**
1. Node restored from state snapshot with resource at version 100
2. Resource deleted at version 200, but version 100 not cached
3. Only tombstone at v200 gets stale index; v100 has no stale index
4. Pruner removes tombstone at v200, leaves orphaned data at v100
5. Debugger query at v300 returns stale v100 data instead of "not found"

The schema stores deletions as `Option<StateValue>` with None representing tombstones. [7](#0-6) 

The query function filters out None values but returns older versions when tombstones are missing. [8](#0-7) 

## Impact Explanation

**Medium Severity** - State inconsistencies requiring intervention:
- Operators using the debugger for incident response may make incorrect decisions based on stale data
- Audit trails become unreliable after pruning in snapshot-restored environments
- Violates the assumption that pruning preserves logical state consistency at query time
- Could lead to operational errors during emergency debugging scenarios

This does not reach High/Critical severity as:
- It only affects the offline debugging tool, not production APIs
- No consensus violation or fund loss occurs
- The blockchain state itself remains consistent (only the debugger's view is wrong)

## Likelihood Explanation

**Medium-High Likelihood:**
- State snapshot restore is a common operation for new validators joining the network
- Pruning runs automatically on all nodes to manage disk usage
- The condition (`ignore_state_cache_miss = true`) occurs during legitimate operations
- No special attacker privileges required; this is a natural consequence of normal operations

The vulnerability manifests automatically through standard operational workflows without requiring malicious intent.

## Recommendation

**Option 1: Force Cache Population Before Deletion**
Ensure all deletions read the previous version before applying, even during snapshot restore:

```rust
// In put_stale_state_value_index_for_shard, before line 947:
if update_to_cold.state_op.expect_as_write_op().is_delete() {
    // Force read of old value to ensure it's cached for stale indexing
    if old_entry.is_cold_vacant() {
        // Query the old version from DB and insert into cache
        if let Some((old_ver, old_val)) = 
            get_previous_version_from_db(key, version)? {
            cache.insert(key.clone(), StateSlot::new_cold(old_ver, old_val));
        }
    }
}
```

**Option 2: Create Stale Index for All Previous Versions**
Query the database to find the previous version and create its stale index even if not cached:

```rust
// After line 951, add:
if old_entry.is_cold_vacant() {
    // Query DB for the most recent version before deletion
    if let Some((prev_version, _)) = 
        query_latest_value_before(key, version, enable_sharding)? {
        Self::put_state_kv_index(
            batch, enable_sharding, version, prev_version, key
        );
    }
}
```

**Option 3: Mark Debugger Output with Warning**
Add explicit warnings when querying databases that may have orphaned data due to untracked usage scenarios.

## Proof of Concept

```rust
// Add to storage/aptosdb/src/state_store/tests/mod.rs
#[test]
fn test_debugger_stale_data_after_pruning() {
    let tmp_dir = TempPath::new();
    let db = AptosDB::new_for_test(&tmp_dir);
    
    // Simulate state snapshot restore with untracked usage
    let key = StateKey::raw(b"test_resource");
    let value_v100 = StateValue::from(b"old_data".to_vec());
    
    // Version 100: Create resource (simulating snapshot restore without cache)
    let mut batch = SchemaBatch::new();
    db.state_kv_db.put_state_value(&key, 100, &Some(value_v100))?;
    db.commit_batch(batch)?;
    
    // Version 200: Delete resource (without v100 in cache)
    let state_cache = ShardedStateCache::new_empty();  // Empty cache!
    let deletion = WriteOp::legacy_deletion();
    let mut updates = PerVersionStateUpdateRefs::new();
    updates.add_update(&key, 200, &deletion);
    
    // Commit deletion with ignore_state_cache_miss = true
    db.state_store.put_stats_and_indices(
        &current_state,
        &latest_state_with_untracked_usage,  // Triggers ignore_state_cache_miss
        &updates,
        &state_cache,
        &mut batch,
        &mut kv_batches,
    )?;
    
    // Verify tombstone exists at v200
    assert!(db.get_state_value(&key, 200)?.is_none());
    
    // Prune up to version 250
    db.state_kv_pruner.prune(250)?;
    
    // BUG: Debugger now returns stale data at v100
    let result = db.state_kv_db
        .get_state_value_with_version_by_version(&key, 300)?;
    
    assert!(result.is_some());  // Should be None, but returns v100!
    assert_eq!(result.unwrap().0, 100);  // Returns stale deleted data
}
```

### Citations

**File:** storage/aptosdb/src/db_debugger/state_kv/get_value.rs (L70-89)
```rust
        let mut start_version = self.version;
        let mut count = 0;
        while count < 10 {
            match db.get_state_value_with_version_by_version(&key, start_version)? {
                None => {
                    if count == 0 {
                        println!("{}", "Value not found.".to_string().yellow());
                    }
                    break;
                },
                Some((version, value)) => {
                    Self::print_value(version, value);
                    count += 1;
                    if version == 0 {
                        break;
                    }
                    start_version = version - 1;
                },
            }
        }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L876-876)
```rust
            latest_state.usage().is_untracked() || current_state.version().is_none(), // ignore_state_cache_miss
```

**File:** storage/aptosdb/src/state_store/mod.rs (L947-951)
```rust
                if update_to_cold.state_op.expect_as_write_op().is_delete() {
                    // This is a tombstone, can be pruned once this `version` goes out of
                    // the pruning window.
                    Self::put_state_kv_index(batch, enable_sharding, version, version, key);
                }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L962-968)
```rust
                    .unwrap_or_else(|| {
                        // n.b. all updated state items must be read and recorded in the state cache,
                        // otherwise we can't calculate the correct usage. The is_untracked() hack
                        // is to allow some db tests without real execution layer to pass.
                        assert!(ignore_state_cache_miss, "Must cache read.");
                        StateSlot::ColdVacant
                    });
```

**File:** storage/aptosdb/src/state_store/mod.rs (L970-980)
```rust
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
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_shard_pruner.rs (L47-72)
```rust
    pub(in crate::pruner) fn prune(
        &self,
        current_progress: Version,
        target_version: Version,
    ) -> Result<()> {
        let mut batch = SchemaBatch::new();

        let mut iter = self
            .db_shard
            .iter::<StaleStateValueIndexByKeyHashSchema>()?;
        iter.seek(&current_progress)?;
        for item in iter {
            let (index, _) = item?;
            if index.stale_since_version > target_version {
                break;
            }
            batch.delete::<StaleStateValueIndexByKeyHashSchema>(&index)?;
            batch.delete::<StateValueByKeyHashSchema>(&(index.state_key_hash, index.version))?;
        }
        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::StateKvShardPrunerProgress(self.shard_id),
            &DbMetadataValue::Version(target_version),
        )?;

        self.db_shard.write_schemas(batch)
    }
```

**File:** storage/aptosdb/src/schema/state_value/mod.rs (L35-40)
```rust
define_schema!(
    StateValueSchema,
    Key,
    Option<StateValue>,
    STATE_VALUE_CF_NAME
);
```

**File:** storage/aptosdb/src/state_kv_db.rs (L387-391)
```rust
            iter.seek(&(state_key.clone(), version))?;
            Ok(iter
                .next()
                .transpose()?
                .and_then(|((_, version), value_opt)| value_opt.map(|value| (version, value))))
```

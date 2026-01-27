# Audit Report

## Title
Unidirectional State Migration Validation Enables Undetected Data Loss During Storage Format Migration

## Summary
The `verify_state_kvs()` function in the database validation tooling only validates in one direction: it checks that entries in the new sharded storage format exist in the internal indexer, but fails to verify the reverse. This allows incomplete state migrations from `StateValueSchema` (non-sharded) to `StateValueByKeyHashSchema` (sharded) to pass validation despite missing data, potentially causing consensus divergence and state corruption.

## Finding Description
During migration from non-sharded to sharded storage (AIP-97), Aptos nodes must transition from `StateValueSchema` (which stores `(StateKey, Version) → StateValue`) to `StateValueByKeyHashSchema` (which stores `(HashValue, Version) → StateValue` where `HashValue` is the hash of the `StateKey`). [1](#0-0) [2](#0-1) 

The validation function builds a hash set of all state keys from the internal indexer and then iterates through the sharded database to check membership: [3](#0-2) 

The critical flaw is in `verify_state_kv()` which only checks one direction: [4](#0-3) 

This validates: "For each (hash, version) in StateValueByKeyHashSchema, does the hash exist in the internal indexer?"

It does NOT validate: "For each StateKey in the internal indexer, does the corresponding (hash, version) exist in StateValueByKeyHashSchema?"

**Attack/Failure Scenario:**
1. Node operator initiates migration from non-sharded to sharded storage per the AIP-97 migration guide [5](#0-4) 
2. During backup/restore migration, the process is interrupted (crash, disk full, network failure)
3. Only partial state is migrated to `StateValueByKeyHashSchema` - some StateKeys are missing
4. Internal indexer retains all original StateKeys
5. Operator runs validation via `verify_state_kvs()`
6. Validation iterates through incomplete sharded DB, checks each hash exists in indexer (they do)
7. Validation PASSES despite missing data
8. Node restarts and operates with incomplete state
9. Queries for missing StateKeys fail, leading to transaction execution failures
10. Different nodes may have different missing data → **consensus divergence**

During write operations, the sharding decision is made based on the `enabled_sharding()` flag at the time of writing: [6](#0-5) 

This lossy transformation from full StateKey to hash-only storage means once data is lost during migration, it cannot be recovered without re-syncing from genesis or a complete backup.

## Impact Explanation
This vulnerability meets **High Severity** criteria per the Aptos bug bounty program:

1. **State Inconsistencies Requiring Intervention**: Incomplete migrations create nodes with different state subsets, requiring manual intervention to identify and repair
2. **Potential Consensus Divergence**: If validators migrate at different times with different failures, they may commit to different state roots for identical blocks, violating the **Deterministic Execution** invariant (#1) and **State Consistency** invariant (#4)
3. **Data Availability Failures**: Missing state data causes transaction execution to fail when accessing deleted keys, leading to validator node slowdowns and potential API crashes

While not directly exploitable by an external attacker, this is a critical operational vulnerability that can manifest during the required migration process for all mainnet/testnet nodes.

## Likelihood Explanation
**Likelihood: High**

1. **Migration is Mandatory**: All mainnet and testnet nodes must migrate to sharded storage (enforced in config validation)
2. **Complex Operation**: Database migrations involving billions of state entries over hours/days have high failure probability
3. **Common Failure Modes**: Disk space exhaustion, memory pressure, network interruptions, process crashes all can cause partial migrations
4. **No Reverse Validation**: The validation tooling gives false confidence by passing validation on incomplete data
5. **Cascading Failures**: Once one node has incomplete state, it may propagate incorrect state commitments to other nodes

## Recommendation

Add bidirectional validation to `verify_state_kvs()`:

```rust
pub fn verify_state_kvs(
    db_root_path: &Path,
    internal_db: &DB,
    target_ledger_version: u64,
) -> Result<()> {
    println!("Validating db statekeys");
    let storage_dir = StorageDirPaths::from_path(db_root_path);
    let state_kv_db =
        StateKvDb::open_sharded(&storage_dir, RocksdbConfig::default(), None, None, false)?;

    // Build hash set from internal DB
    let mut all_internal_keys = HashSet::new();
    let mut internal_key_details = HashMap::new(); // NEW: Track full StateKey
    let mut iter = internal_db.iter::<StateKeysSchema>()?;
    iter.seek_to_first();
    for (key_ind, state_key_res) in iter.enumerate() {
        let state_key = state_key_res?.0;
        let state_key_hash = state_key.hash();
        all_internal_keys.insert(state_key_hash);
        internal_key_details.insert(state_key_hash, state_key.clone()); // NEW
        if key_ind % 10_000_000 == 0 {
            println!("Processed {} keys", key_ind);
        }
    }
    
    // EXISTING: Check sharded DB → internal DB
    let mut found_hashes = HashSet::new(); // NEW: Track what we found
    for shard_id in 0..16 {
        let shard = state_kv_db.db_shard(shard_id);
        verify_state_kv(shard, &all_internal_keys, &mut found_hashes, target_ledger_version)?;
    }
    
    // NEW: Check internal DB → sharded DB (reverse direction)
    let missing_in_sharded = all_internal_keys
        .difference(&found_hashes)
        .collect::<Vec<_>>();
    
    if !missing_in_sharded.is_empty() {
        println!("ERROR: {} StateKeys from internal DB missing in sharded DB", 
                 missing_in_sharded.len());
        for hash in missing_in_sharded.iter().take(100) {
            if let Some(key) = internal_key_details.get(hash) {
                println!("Missing StateKey: {:?} (hash: {:?})", key, hash);
            }
        }
        return Err(AptosDbError::Other(format!(
            "Migration validation failed: {} StateKeys missing in sharded DB",
            missing_in_sharded.len()
        )));
    }
    
    Ok(())
}

fn verify_state_kv(
    shard: &DB,
    all_internal_keys: &HashSet<HashValue>,
    found_hashes: &mut HashSet<HashValue>, // NEW parameter
    target_ledger_version: u64,
) -> Result<()> {
    let mut iter = shard.iter_with_opts::<StateValueByKeyHashSchema>(ReadOptions::default())?;
    iter.seek_to_first();
    let mut missing_keys = 0;
    
    for value in iter {
        let (state_key_hash, version) = value?.0;
        if version > target_ledger_version {
            continue;
        }
        
        found_hashes.insert(state_key_hash); // NEW: Track found hashes
        
        if !all_internal_keys.contains(&state_key_hash) {
            missing_keys += 1;
            println!("State key hash not found in internal db: {:?}, version: {}", 
                     state_key_hash, version);
        }
    }
    
    if missing_keys > 0 {
        return Err(AptosDbError::Other(format!(
            "Found {} hashes in sharded DB not present in internal indexer", 
            missing_keys
        )));
    }
    
    Ok(())
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod test_migration_validation {
    use super::*;
    use aptos_types::state_store::state_key::StateKey;
    use aptos_temppath::TempPath;
    
    #[test]
    fn test_unidirectional_validation_misses_incomplete_migration() {
        // Setup: Create state with 3 keys
        let tmp_dir = TempPath::new();
        let internal_db = create_internal_indexer_db(&tmp_dir);
        let state_kv_db = create_sharded_state_kv_db(&tmp_dir);
        
        // Populate internal indexer with 3 StateKeys
        let key1 = StateKey::raw(b"key1");
        let key2 = StateKey::raw(b"key2");
        let key3 = StateKey::raw(b"key3");
        
        write_to_internal_indexer(&internal_db, vec![key1.clone(), key2.clone(), key3.clone()]);
        
        // Simulate incomplete migration: only write key1 and key2 to sharded DB
        write_to_sharded_db(&state_kv_db, vec![
            (key1.hash(), 0, Some(StateValue::new_legacy(b"value1".to_vec()))),
            (key2.hash(), 0, Some(StateValue::new_legacy(b"value2".to_vec()))),
            // key3 missing - simulates migration failure
        ]);
        
        // Current validation passes despite missing key3
        let result = verify_state_kvs(&tmp_dir.path(), &internal_db, 0);
        
        // BUG: This should fail but passes
        assert!(result.is_ok(), "Current validation incorrectly passes with incomplete migration");
        
        // With fixed bidirectional validation, this would fail:
        // assert!(result.is_err(), "Fixed validation should detect missing key3");
    }
}
```

**Notes:**
- The validation bug creates a false sense of security during critical migration operations
- Operators may believe migration was successful when data was actually lost
- The issue compounds over time as lost data becomes harder to identify and repair
- Proper bidirectional validation would catch migration failures immediately, preventing state divergence

### Citations

**File:** storage/aptosdb/src/schema/state_value/mod.rs (L33-40)
```rust
type Key = (StateKey, Version);

define_schema!(
    StateValueSchema,
    Key,
    Option<StateValue>,
    STATE_VALUE_CF_NAME
);
```

**File:** storage/aptosdb/src/schema/state_value_by_key_hash/mod.rs (L28-35)
```rust
type Key = (HashValue, Version);

define_schema!(
    StateValueByKeyHashSchema,
    Key,
    Option<StateValue>,
    STATE_VALUE_BY_KEY_HASH_CF_NAME
);
```

**File:** storage/aptosdb/src/db_debugger/validation.rs (L124-145)
```rust
    //read all statekeys from internal db and store them in mem
    let mut all_internal_keys = HashSet::new();
    let mut iter = internal_db.iter::<StateKeysSchema>()?;
    iter.seek_to_first();
    for (key_ind, state_key_res) in iter.enumerate() {
        let state_key = state_key_res?.0;
        let state_key_hash = state_key.hash();
        all_internal_keys.insert(state_key_hash);
        if key_ind % 10_000_000 == 0 {
            println!("Processed {} keys", key_ind);
        }
    }
    println!(
        "Number of state keys in internal db: {}",
        all_internal_keys.len()
    );
    for shard_id in 0..16 {
        let shard = state_kv_db.db_shard(shard_id);
        println!("Validating state_kv for shard {}", shard_id);
        verify_state_kv(shard, &all_internal_keys, target_ledger_version)?;
    }
    Ok(())
```

**File:** storage/aptosdb/src/db_debugger/validation.rs (L157-191)
```rust
fn verify_state_kv(
    shard: &DB,
    all_internal_keys: &HashSet<HashValue>,
    target_ledger_version: u64,
) -> Result<()> {
    let read_opts = ReadOptions::default();
    let mut iter = shard.iter_with_opts::<StateValueByKeyHashSchema>(read_opts)?;
    // print a message every 10k keys
    let mut counter = 0;
    iter.seek_to_first();
    let mut missing_keys = 0;
    for value in iter {
        let (state_key_hash, version) = value?.0;
        if version > target_ledger_version {
            continue;
        }
        // check if the state key hash is present in the internal db
        if !all_internal_keys.contains(&state_key_hash) {
            missing_keys += 1;
            println!(
                "State key hash not found in internal db: {:?}, version: {}",
                state_key_hash, version
            );
        }
        counter += 1;
        if counter as usize % SAMPLE_RATE == 0 {
            println!(
                "Processed {} keys, the current sample is {} at version {}",
                counter, state_key_hash, version
            );
        }
    }
    println!("Number of missing keys: {}", missing_keys);
    Ok(())
}
```

**File:** config/src/config/storage_config.rs (L664-668)
```rust
            if (chain_id.is_testnet() || chain_id.is_mainnet())
                && config_yaml["rocksdb_configs"]["enable_storage_sharding"].as_bool() != Some(true)
            {
                panic!("Storage sharding (AIP-97) is not enabled in node config. Please follow the guide to migration your node, and set storage.rocksdb_configs.enable_storage_sharding to true explicitly in your node config. https://aptoslabs.notion.site/DB-Sharding-Migration-Public-Full-Nodes-1978b846eb7280b29f17ceee7d480730");
            }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L1030-1054)
```rust
    pub(crate) fn shard_state_value_batch(
        &self,
        sharded_batch: &mut ShardedStateKvSchemaBatch,
        values: &StateValueBatch,
        enable_sharding: bool,
    ) -> Result<()> {
        values.iter().for_each(|((key, version), value)| {
            let shard_id = key.get_shard_id();
            assert!(
                shard_id < NUM_STATE_SHARDS,
                "Invalid shard id: {}",
                shard_id
            );
            if enable_sharding {
                sharded_batch[shard_id]
                    .put::<StateValueByKeyHashSchema>(&(key.hash(), *version), value)
                    .expect("Inserting into sharded schema batch should never fail");
            } else {
                sharded_batch[shard_id]
                    .put::<StateValueSchema>(&(key.clone(), *version), value)
                    .expect("Inserting into sharded schema batch should never fail");
            }
        });
        Ok(())
    }
```

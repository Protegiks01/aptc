# Audit Report

## Title
Storage Leak via Orphaned Stale State Value Indices After enable_sharding Migration

## Summary
When a node migrates from `enable_storage_sharding=false` to `enable_storage_sharding=true` (as required by AIP-97 for mainnet/testnet), stale state value indices written under the old `StaleStateValueIndexSchema` in `ledger_db` become permanently orphaned. The pruning system only operates on the currently active schema, leaving old indices in `ledger_db` to accumulate indefinitely, causing unbounded storage growth.

## Finding Description

The Aptos storage system uses two mutually exclusive schemas for tracking stale state values that need pruning:

1. **StaleStateValueIndexSchema** - Uses full `StateKey`, stored in `STALE_STATE_VALUE_INDEX_CF_NAME` column family
2. **StaleStateValueIndexByKeyHashSchema** - Uses `state_key_hash`, stored in `STALE_STATE_VALUE_INDEX_BY_KEY_HASH_CF_NAME` column family

The schema selection is controlled by the `enable_storage_sharding` configuration flag: [1](#0-0) 

When sharding is **disabled**, the `StateKvDb` uses the `ledger_db` for both metadata and shard storage: [2](#0-1) 

The `ledger_db` contains only the old schema column family: [3](#0-2) 

When sharding is **enabled**, the system uses separate shard databases with the new schema: [4](#0-3) 

The pruning logic conditionally operates on only ONE schema at a time: [5](#0-4) 

**Vulnerability Sequence:**

1. Node runs with `enable_storage_sharding=false`
   - Indices written to `ledger_db::STALE_STATE_VALUE_INDEX_CF_NAME` using `StaleStateValueIndexSchema`
   - State values written to `ledger_db::STATE_VALUE_CF_NAME`
   - Pruner successfully operates on these indices

2. Node migrates to `enable_storage_sharding=true` (required for mainnet/testnet per AIP-97)
   - New separate `state_kv_metadata_db` and shard databases created
   - New indices written to `shard_db::STALE_STATE_VALUE_INDEX_BY_KEY_HASH_CF_NAME`
   - Pruner now only looks at the new schema in shard databases

3. **Old indices in `ledger_db` are orphaned:**
   - The `StateKvDb` structure no longer references `ledger_db` when sharding is enabled
   - Pruner has no code path to clean up old schema
   - Old indices accumulate indefinitely in `ledger_db`
   - No migration logic exists to clean up these orphaned indices

The configuration enforcement confirms this migration path is mandatory: [6](#0-5) 

## Impact Explanation

**Severity: Medium** - "State inconsistencies requiring intervention"

This vulnerability causes:

1. **Unbounded Storage Growth**: Every node that performs the AIP-97 migration accumulates orphaned stale state value indices in `ledger_db` that are never pruned. Over time, this leads to significant disk space waste.

2. **State Inconsistency**: The database contains stale indices in two different schemas across different database instances, but only one is actively maintained. This violates the state consistency invariant.

3. **Operational Impact**: Eventually, affected nodes may experience disk exhaustion, requiring manual intervention to clean up orphaned data or migrate to larger storage.

4. **Network-Wide Effect**: All mainnet and testnet nodes are required to enable sharding, meaning this affects the entire network, not just individual misconfigured nodes.

The impact does not reach Critical severity because:
- No consensus safety violations occur
- No loss of funds or validator rewards
- Network liveness is not immediately affected
- The issue manifests as gradual storage accumulation rather than immediate failure

However, it requires manual intervention to resolve and affects database integrity, qualifying as Medium severity.

## Likelihood Explanation

**Likelihood: High** (for mainnet/testnet nodes)

This vulnerability **will** occur for:
- All mainnet nodes performing AIP-97 migration (mandatory per config)
- All testnet nodes performing AIP-97 migration (mandatory per config)  
- Any node transitioning from non-sharded to sharded mode

The likelihood is extremely high because:

1. The migration is **mandatory** for production networks via config enforcement
2. No cleanup logic exists in the codebase
3. The vulnerability is triggered automatically by the configuration change, requiring no attacker action
4. Every node that existed before AIP-97 will experience this issue

The only nodes unaffected are:
- New nodes started with sharding already enabled (no pre-existing data)
- Development/test nodes that don't perform the migration

## Recommendation

Implement a migration function that cleans up orphaned indices from the old schema when transitioning to sharded mode. This should be executed during database initialization when sharding is detected as enabled but old schema indices exist.

**Recommended Fix Location:** `storage/aptosdb/src/state_kv_db.rs`

Add a migration check in the `open_sharded` function to clean up old indices:

```rust
pub(crate) fn open_sharded(...) -> Result<Self> {
    // ... existing open code ...
    
    let state_kv_db = Self { ... };
    
    if !readonly {
        // Cleanup orphaned indices from ledger_db after migration
        Self::cleanup_legacy_indices(&state_kv_db, ledger_db)?;
        
        if let Some(overall_kv_commit_progress) = get_state_kv_commit_progress(&state_kv_db)? {
            truncate_state_kv_db_shards(&state_kv_db, overall_kv_commit_progress)?;
        }
    }
    
    Ok(state_kv_db)
}

fn cleanup_legacy_indices(state_kv_db: &StateKvDb, ledger_db: Arc<DB>) -> Result<()> {
    // Iterate through all old schema indices in ledger_db
    // Delete them in batches
    // This should be idempotent and safe to run multiple times
}
```

Alternatively, document the migration process and provide a manual cleanup tool for node operators.

## Proof of Concept

The vulnerability can be demonstrated with the following sequence:

**Step 1: Start node with sharding disabled**
```rust
// Node config: enable_storage_sharding = false
// Write state updates, creating entries in:
// ledger_db::STALE_STATE_VALUE_INDEX_CF_NAME
```

**Step 2: Verify indices exist**
```rust
let mut iter = ledger_db.iter::<StaleStateValueIndexSchema>()?;
iter.seek_to_first();
let count_before = iter.count(); // Non-zero count
```

**Step 3: Restart with sharding enabled**
```rust
// Node config: enable_storage_sharding = true
// System creates new state_kv_metadata_db and shard databases
// StateKvDb no longer references ledger_db
```

**Step 4: Run pruner**
```rust
state_kv_pruner.prune(max_versions)?;
// Pruner only operates on StaleStateValueIndexByKeyHashSchema in shard_db
// Old indices in ledger_db remain untouched
```

**Step 5: Verify orphaned indices**
```rust
let mut iter = ledger_db.iter::<StaleStateValueIndexSchema>()?;
iter.seek_to_first();
let count_after = iter.count(); // Same as count_before - no pruning occurred
assert_eq!(count_before, count_after); // Demonstrates orphaned indices
```

**Expected Result:** Old indices in `ledger_db::STALE_STATE_VALUE_INDEX_CF_NAME` persist indefinitely, accumulating with each state update that occurred before migration, causing storage leak proportional to pre-migration blockchain history.

## Notes

This vulnerability is inherent to the AIP-97 migration design and affects all production nodes. The dual schema system was implemented to support both modes, but the migration path lacks proper cleanup logic. The impact compounds over time as more state updates occurred before migration, resulting in more orphaned indices. Node operators may need to manually clean up `ledger_db` or allocate significantly more storage than expected to accommodate both active and orphaned indices.

### Citations

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

**File:** storage/aptosdb/src/state_kv_db.rs (L62-70)
```rust
        let sharding = rocksdb_configs.enable_storage_sharding;
        if !sharding {
            info!("State K/V DB is not enabled!");
            return Ok(Self {
                state_kv_metadata_db: Arc::clone(&ledger_db),
                state_kv_db_shards: arr![Arc::clone(&ledger_db); 16],
                hot_state_kv_db_shards: None,
                enabled_sharding: false,
            });
```

**File:** storage/aptosdb/src/db_options.rs (L14-40)
```rust
pub(super) fn ledger_db_column_families() -> Vec<ColumnFamilyName> {
    vec![
        /* empty cf */ DEFAULT_COLUMN_FAMILY_NAME,
        BLOCK_BY_VERSION_CF_NAME,
        BLOCK_INFO_CF_NAME,
        EPOCH_BY_VERSION_CF_NAME,
        EVENT_ACCUMULATOR_CF_NAME,
        EVENT_BY_KEY_CF_NAME,
        EVENT_BY_VERSION_CF_NAME,
        EVENT_CF_NAME,
        LEDGER_INFO_CF_NAME,
        PERSISTED_AUXILIARY_INFO_CF_NAME,
        STALE_STATE_VALUE_INDEX_CF_NAME,
        STATE_VALUE_CF_NAME,
        TRANSACTION_CF_NAME,
        TRANSACTION_ACCUMULATOR_CF_NAME,
        TRANSACTION_ACCUMULATOR_HASH_CF_NAME,
        TRANSACTION_AUXILIARY_DATA_CF_NAME,
        ORDERED_TRANSACTION_BY_ACCOUNT_CF_NAME,
        TRANSACTION_SUMMARIES_BY_ACCOUNT_CF_NAME,
        TRANSACTION_BY_HASH_CF_NAME,
        TRANSACTION_INFO_CF_NAME,
        VERSION_DATA_CF_NAME,
        WRITE_SET_CF_NAME,
        DB_METADATA_CF_NAME,
    ]
}
```

**File:** storage/aptosdb/src/db_options.rs (L141-149)
```rust
pub(super) fn state_kv_db_new_key_column_families() -> Vec<ColumnFamilyName> {
    vec![
        /* empty cf */ DEFAULT_COLUMN_FAMILY_NAME,
        DB_METADATA_CF_NAME,
        STALE_STATE_VALUE_INDEX_BY_KEY_HASH_CF_NAME,
        STATE_VALUE_BY_KEY_HASH_CF_NAME,
        STATE_VALUE_INDEX_CF_NAME, // we still need this cf before deleting all the write callsites
    ]
}
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_metadata_pruner.rs (L35-65)
```rust
        if self.state_kv_db.enabled_sharding() {
            let num_shards = self.state_kv_db.num_shards();
            // NOTE: This can be done in parallel if it becomes the bottleneck.
            for shard_id in 0..num_shards {
                let mut iter = self
                    .state_kv_db
                    .db_shard(shard_id)
                    .iter::<StaleStateValueIndexByKeyHashSchema>()?;
                iter.seek(&current_progress)?;
                for item in iter {
                    let (index, _) = item?;
                    if index.stale_since_version > target_version {
                        break;
                    }
                }
            }
        } else {
            let mut iter = self
                .state_kv_db
                .metadata_db()
                .iter::<StaleStateValueIndexSchema>()?;
            iter.seek(&current_progress)?;
            for item in iter {
                let (index, _) = item?;
                if index.stale_since_version > target_version {
                    break;
                }
                batch.delete::<StaleStateValueIndexSchema>(&index)?;
                batch.delete::<StateValueSchema>(&(index.state_key, index.version))?;
            }
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

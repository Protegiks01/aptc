# Audit Report

## Title
State KV Pruner Data Leakage via Sharding Configuration Mismatch

## Summary
A configuration mismatch between the database's actual sharding state and the runtime configuration can cause the StateKvPruner to fail to prune data from sharded databases, leading to unbounded disk space growth and database inconsistencies.

## Finding Description
The StateKvPruner initializes its shard pruner components based on the `enabled_sharding()` value at initialization time, but does not validate whether this matches the actual database structure on disk. [1](#0-0) 

When a node is restarted with a different sharding configuration than what was used to create the database, a critical mismatch occurs:

**Scenario: Database created with sharding enabled, restarted with sharding disabled**

1. **Initial state (sharding enabled)**: Data is written to separate shard databases using `StaleStateValueIndexByKeyHashSchema` for tracking stale entries [2](#0-1) 

2. **After restart (sharding disabled)**: The `StateKvDb::new()` returns early without opening the shard databases, setting `enabled_sharding=false` and pointing all shards to ledger_db [3](#0-2) 

3. **StateKvPruner initialization**: Since `enabled_sharding()` returns false, the `shard_pruners` vector is initialized as empty [1](#0-0) 

4. **During pruning**: The metadata pruner checks `enabled_sharding()` at runtime and attempts to prune from `StaleStateValueIndexSchema` in ledger_db, but the actual stale data exists in `StaleStateValueIndexByKeyHashSchema` in the abandoned shard databases [4](#0-3) 

5. **Result**: The actual shard databases are never pruned because the `shard_pruners` vector is empty, causing indefinite accumulation of stale data.

The system lacks validation to detect this mismatch. The database metadata schema contains no flag to record the sharding mode used during creation [5](#0-4) 

## Impact Explanation
This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty criteria:

- **State inconsistencies requiring intervention**: The pruner's metadata indicates data has been pruned, but it remains on disk in the shard databases, creating a state inconsistency.
- **Disk space exhaustion**: Unpruned shard data will accumulate indefinitely, eventually filling the disk and causing node failure.
- **Database corruption**: The mismatch between metadata state and actual data state represents a form of database corruption.

While mainnet/testnet nodes have configuration validation that requires sharding to be enabled [6](#0-5) , devnet and test environments lack this protection, and the validation only checks the configuration value, not whether it matches the existing database structure.

## Likelihood Explanation
**Likelihood: Low to Medium**

This issue requires node operator error or intentional misconfiguration:
- An operator must manually change the `enable_storage_sharding` configuration
- Then restart the node without performing proper database migration
- Mainnet/testnet have config validation that would catch this (but only prevents disabling sharding, not initial mismatches)
- Devnet/localnet nodes are vulnerable

However, the lack of runtime validation means once this misconfiguration occurs, it silently degrades the system without immediate detection, making it a serious operational risk.

## Recommendation
Implement database structure validation on startup:

1. **Add a metadata key** to track the sharding mode used during database creation:
```rust
pub enum DbMetadataKey {
    // ... existing keys ...
    StateKvShardingEnabled, // NEW: tracks if DB was created with sharding
}
```

2. **Validate on database open** in `StateKvDb::new()`:
```rust
pub(crate) fn new(
    db_paths: &StorageDirPaths,
    rocksdb_configs: RocksdbConfigs,
    // ... other params ...
) -> Result<Self> {
    let sharding = rocksdb_configs.enable_storage_sharding;
    
    // Check if database already exists and validate sharding config
    if let Some(existing_sharding) = read_db_sharding_metadata(ledger_db)? {
        if existing_sharding != sharding {
            return Err(anyhow::anyhow!(
                "Sharding configuration mismatch: database was created with \
                 sharding={}, but current config has sharding={}. \
                 Database migration required.",
                existing_sharding, sharding
            ));
        }
    } else {
        // First time opening, record the sharding mode
        write_db_sharding_metadata(ledger_db, sharding)?;
    }
    // ... rest of initialization ...
}
```

3. **Provide migration tooling** to safely convert between sharding modes when intentionally changing configuration.

## Proof of Concept
```rust
// Reproduction steps (integration test):
// 1. Initialize AptosDB with enable_storage_sharding=true
// 2. Write state updates that create stale values
// 3. Run pruner - verify shard data is pruned correctly
// 4. Shutdown node
// 5. Restart AptosDB with enable_storage_sharding=false
// 6. Run pruner again
// 7. Observe: shard databases still contain unpruned data
// 8. Expected: System should either refuse to start or perform migration

#[test]
fn test_pruner_sharding_config_mismatch() {
    // Step 1: Create DB with sharding enabled
    let tmp_dir = TempPath::new();
    let mut config = NodeConfig::default();
    config.storage.rocksdb_configs.enable_storage_sharding = true;
    
    let db = AptosDB::open(
        &tmp_dir,
        false,
        NO_OP_STORAGE_PRUNER_CONFIG,
        config.storage.rocksdb_configs,
        false,
        BUFFERED_STATE_TARGET_ITEMS,
        MAX_NUM_NODES_PER_LRU_CACHE_SHARD,
    ).unwrap();
    
    // Step 2: Write data and create stale values
    // ... write state updates at versions 1, 2, 3 ...
    
    // Step 3: Enable pruning and prune to version 2
    // ... verify shard data exists ...
    db.prune_state_kv(2).unwrap();
    
    // Check shard databases have data
    let shard_path = tmp_dir.path().join("state_kv_db/shard_0");
    assert!(shard_path.exists());
    // ... verify stale data was pruned ...
    
    drop(db);
    
    // Step 4-5: Reopen with sharding disabled
    config.storage.rocksdb_configs.enable_storage_sharding = false;
    let db = AptosDB::open(
        &tmp_dir,
        false,
        NO_OP_STORAGE_PRUNER_CONFIG,
        config.storage.rocksdb_configs,
        false,
        BUFFERED_STATE_TARGET_ITEMS,
        MAX_NUM_NODES_PER_LRU_CACHE_SHARD,
    ).unwrap();
    
    // Step 6: Attempt pruning
    db.prune_state_kv(3).unwrap();
    
    // Step 7: Verify bug - shard data remains unpruned
    // Shard databases still exist with stale data
    assert!(shard_path.exists());
    // ... verify stale data at version 2 still exists in shards ...
    // This is the bug: pruner thought it pruned, but didn't touch shard DBs
}
```

## Notes
While this vulnerability primarily affects node operators who misconfigure their systems, it represents a **state consistency invariant violation** that could lead to node failures and operational issues. The lack of validation allows silent degradation that may not be detected until disk space is exhausted. The fix should include both validation to prevent the misconfiguration and clear error messages to guide operators toward proper migration procedures.

### Citations

**File:** storage/aptosdb/src/pruner/state_kv_pruner/mod.rs (L124-137)
```rust
        let shard_pruners = if state_kv_db.enabled_sharding() {
            let num_shards = state_kv_db.num_shards();
            let mut shard_pruners = Vec::with_capacity(num_shards);
            for shard_id in 0..num_shards {
                shard_pruners.push(StateKvShardPruner::new(
                    shard_id,
                    state_kv_db.db_shard_arc(shard_id),
                    metadata_progress,
                )?);
            }
            shard_pruners
        } else {
            Vec::new()
        };
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

**File:** storage/aptosdb/src/schema/db_metadata/mod.rs (L47-72)
```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(proptest_derive::Arbitrary))]
pub enum DbMetadataKey {
    LedgerPrunerProgress,
    StateMerklePrunerProgress,
    EpochEndingStateMerklePrunerProgress,
    StateKvPrunerProgress,
    StateSnapshotKvRestoreProgress(Version),
    LedgerCommitProgress,
    StateKvCommitProgress,
    OverallCommitProgress,
    StateKvShardCommitProgress(ShardId),
    StateMerkleCommitProgress,
    StateMerkleShardCommitProgress(ShardId),
    EventPrunerProgress,
    TransactionAccumulatorPrunerProgress,
    TransactionInfoPrunerProgress,
    TransactionPrunerProgress,
    WriteSetPrunerProgress,
    StateMerkleShardPrunerProgress(ShardId),
    EpochEndingStateMerkleShardPrunerProgress(ShardId),
    StateKvShardPrunerProgress(ShardId),
    StateMerkleShardRestoreProgress(ShardId, Version),
    TransactionAuxiliaryDataPrunerProgress,
    PersistedAuxiliaryInfoPrunerProgress,
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

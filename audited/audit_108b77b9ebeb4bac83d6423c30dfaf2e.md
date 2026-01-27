# Audit Report

## Title
Incomplete State Value Deletion Due to Sharding Configuration Mismatch During Database Truncation

## Summary
The `delete_state_value_and_index()` function uses a runtime `enable_sharding` flag to determine which database schemas to delete from, but this flag is not validated against the configuration used when data was originally written. This can cause incomplete data deletion during database truncation operations if the sharding configuration changes between writes and deletions.

## Finding Description

The vulnerability exists in the truncation logic where state values and their indices are deleted based on the current runtime configuration rather than metadata indicating which schema was used during writes. [1](#0-0) 

The function has two completely separate code paths:
- When `enable_sharding=true`: Deletes from `StaleStateValueIndexByKeyHashSchema` and `StateValueByKeyHashSchema`
- When `enable_sharding=false`: Deletes from `StaleStateValueIndexSchema` and `StateValueSchema`

The same conditional logic is used during writes: [2](#0-1) [3](#0-2) 

The `enable_sharding` flag comes from the runtime configuration and is NOT persisted in database metadata: [4](#0-3) 

The `DbMetadataKey` enum contains no field to track which sharding mode was used when data was written. The flag is set during database initialization: [5](#0-4) [6](#0-5) 

**Breaking Invariant:** This violates the **State Consistency** invariant - state transitions should be atomic and complete. When truncation occurs with a mismatched configuration, data remains in the database that the system believes has been deleted.

**Exploitation Scenario:**
1. Node operates with `enable_storage_sharding=false` (pre-AIP-97 or development environment)
2. State values written to `StateValueSchema` and `StaleStateValueIndexSchema`
3. Operator changes configuration to `enable_storage_sharding=true` (AIP-97 migration)
4. Node restarts with new configuration
5. Database truncation operation triggered (maintenance, repair, or rewind operation)
6. Truncation code uses `enabled_sharding()=true`, attempts deletion from `StateValueByKeyHashSchema` and `StaleStateValueIndexByKeyHashSchema`
7. Original data in `StateValueSchema` and `StaleStateValueIndexSchema` is NOT deleted
8. Storage bloat and data inconsistency results

## Impact Explanation

**Severity: Medium**

This issue qualifies as **Medium severity** under the Aptos bug bounty program criteria: "State inconsistencies requiring intervention."

The vulnerability can cause:
- **Storage bloat**: Undeletable stale data accumulates indefinitely
- **State inconsistencies**: System metadata indicates data is truncated but actual data persists
- **Operational failures**: Database maintenance operations incomplete
- **Potential consensus issues**: If different validators have different historical sharding configurations, they may have divergent storage states

However, this does NOT directly cause:
- Loss of funds
- Consensus safety violations (assuming all validators use identical configurations)
- Network partition

## Likelihood Explanation

**Likelihood: Medium to High** during AIP-97 migration period

The likelihood is significant because:

1. **AIP-97 Migration Reality**: All nodes must migrate from `enable_storage_sharding=false` to `true`, making this scenario inevitable during upgrade [7](#0-6) 

2. **No Validation**: No checks exist to prevent configuration changes: [8](#0-7) 

3. **Common Operations**: Database truncation occurs during normal maintenance, recovery, or debugging operations

4. **Test Coverage Gap**: Tests only verify single-configuration scenarios, not configuration transitions: [9](#0-8) 

## Recommendation

**Solution 1: Persist Sharding Configuration in Database Metadata**

Add a `DbMetadataKey::ShardingEnabled` field to store the sharding mode:

```rust
pub enum DbMetadataKey {
    // ... existing fields ...
    ShardingEnabled,
}
```

On first database initialization, persist the sharding mode. On subsequent opens, validate that the runtime configuration matches the persisted value, panicking if they differ.

**Solution 2: Dual-Schema Cleanup During Truncation**

Modify `delete_state_value_and_index()` to always clean both schema sets during truncation:

```rust
fn delete_state_value_and_index(
    state_kv_db_shard: &DB,
    start_version: Version,
    batch: &mut SchemaBatch,
    enable_sharding: bool,
) -> Result<()> {
    // Clean sharded schemas
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
    
    // ALSO clean non-sharded schemas (for migration safety)
    let mut iter = state_kv_db_shard.iter::<StaleStateValueIndexSchema>()?;
    iter.seek(&start_version)?;
    for item in iter {
        let (index, _) = item?;
        batch.delete::<StaleStateValueIndexSchema>(&index)?;
        batch.delete::<StateValueSchema>(&(index.state_key, index.stale_since_version))?;
    }
    
    Ok(())
}
```

**Recommended Approach**: Implement Solution 1 (metadata persistence with validation) as it prevents the root cause. Solution 2 is a temporary workaround that ensures cleanup but doesn't prevent the underlying configuration mismatch issue.

## Proof of Concept

```rust
#[cfg(test)]
mod configuration_mismatch_test {
    use super::*;
    use aptos_temppath::TempPath;
    use aptos_types::state_store::state_key::StateKey;
    
    #[test]
    fn test_truncation_with_sharding_config_mismatch() {
        // Step 1: Create DB with sharding DISABLED
        let tmp_dir = TempPath::new();
        let rocksdb_config_no_sharding = RocksdbConfigs {
            enable_storage_sharding: false,
            ..Default::default()
        };
        
        let db = AptosDB::new_for_test_with_config(&tmp_dir, rocksdb_config_no_sharding);
        
        // Step 2: Write some state values (goes to StateValueSchema)
        let test_key = StateKey::raw(b"test_key");
        let test_value = StateValue::from(b"test_value".to_vec());
        db.save_state_value(&test_key, 1, &test_value).unwrap();
        db.save_state_value(&test_key, 2, &test_value).unwrap();
        db.save_state_value(&test_key, 3, &test_value).unwrap();
        
        drop(db);
        
        // Step 3: Reopen DB with sharding ENABLED
        let rocksdb_config_sharding = RocksdbConfigs {
            enable_storage_sharding: true,
            ..Default::default()
        };
        
        let (ledger_db, _, state_merkle_db, state_kv_db) = AptosDB::open_dbs(
            &StorageDirPaths::from_path(&tmp_dir),
            rocksdb_config_sharding,
            None,
            None,
            false,
            0,
            false,
        ).unwrap();
        
        // Step 4: Perform truncation to version 1 (should delete versions 2 and 3)
        truncate_state_kv_db_single_shard(&state_kv_db, 0, 1).unwrap();
        
        // Step 5: Verify that data in StateValueSchema was NOT deleted
        // (because truncation used enable_sharding=true and only cleaned StateValueByKeyHashSchema)
        let mut iter = state_kv_db.metadata_db().iter::<StateValueSchema>().unwrap();
        iter.seek_to_first();
        
        let mut found_versions = Vec::new();
        for item in iter {
            let ((key, version), _) = item.unwrap();
            if key == test_key {
                found_versions.push(version);
            }
        }
        
        // BUG: Versions 2 and 3 should have been deleted but are still present
        assert_eq!(found_versions, vec![1, 2, 3], 
            "Incomplete deletion: old schema data not cleaned due to config mismatch");
    }
}
```

## Notes

This vulnerability is particularly concerning during the AIP-97 migration period where all Aptos nodes transition from non-sharded to sharded storage. While the configuration validation prevents mainnet/testnet nodes from running without sharding enabled, it does not prevent the transition scenario where historical data exists in non-sharded schemas while the current configuration expects sharded schemas.

The issue does not directly cause consensus divergence if all validators follow identical upgrade paths, but creates operational risks and storage inefficiencies that violate the state consistency guarantees expected from the storage layer.

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

**File:** storage/aptosdb/src/state_store/mod.rs (L830-840)
```rust
                        if self.state_kv_db.enabled_sharding() {
                            batch.put::<StateValueByKeyHashSchema>(
                                &(CryptoHash::hash(*key), version),
                                &write_op.as_state_value_opt().cloned(),
                            )
                        } else {
                            batch.put::<StateValueSchema>(
                                &((*key).clone(), version),
                                &write_op.as_state_value_opt().cloned(),
                            )
                        }
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

**File:** storage/aptosdb/src/state_kv_db.rs (L157-162)
```rust
        let state_kv_db = Self {
            state_kv_metadata_db,
            state_kv_db_shards,
            hot_state_kv_db_shards,
            enabled_sharding: true,
        };
```

**File:** storage/aptosdb/src/state_kv_db.rs (L277-279)
```rust
    pub(crate) fn enabled_sharding(&self) -> bool {
        self.enabled_sharding
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

**File:** storage/aptosdb/src/db_debugger/truncate/mod.rs (L302-331)
```rust
            if sharding_config.enable_storage_sharding {
                let mut iter = state_kv_db.metadata_db().iter::<StateValueByKeyHashSchema>().unwrap();
                iter.seek_to_first();
                for item in iter {
                    let ((_, version), _) = item.unwrap();
                    prop_assert!(version <= target_version);
                }

                let mut iter = state_kv_db.metadata_db().iter::<StaleStateValueIndexByKeyHashSchema>().unwrap();
                iter.seek_to_first();
                for item in iter {
                    let version = item.unwrap().0.stale_since_version;
                    prop_assert!(version <= target_version);
                }

            } else {
                let mut iter = state_kv_db.metadata_db().iter::<StateValueSchema>().unwrap();
                iter.seek_to_first();
                for item in iter {
                    let ((_, version), _) = item.unwrap();
                    prop_assert!(version <= target_version);
                }

                let mut iter = state_kv_db.metadata_db().iter::<StaleStateValueIndexSchema>().unwrap();
                iter.seek_to_first();
                for item in iter {
                    let version = item.unwrap().0.stale_since_version;
                    prop_assert!(version <= target_version);
                }
            }
```

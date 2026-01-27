# Audit Report

## Title
Version Skipping in Transaction Accumulator Pruning Due to Cross-Database Metadata Inconsistency

## Summary
When storage sharding is enabled (mandatory for mainnet/testnet), pruning progress metadata for different database components can become inconsistent during partial failures. The `get_or_initialize_subpruner_progress` function assumes that missing sub-pruner progress metadata means data has already been pruned up to the metadata pruner's progress, potentially causing versions to be permanently skipped from pruning.

## Finding Description

The Aptos storage system uses database sharding (AIP-97) where `ledger_metadata_db` and `transaction_accumulator_db` are **separate RocksDB instances**. [1](#0-0) 

During pruning, the `LedgerPruner` coordinates multiple sub-pruners that run in parallel: [2](#0-1) 

The critical flaw occurs when:

1. **Partial Failure During Pruning:** The `ledger_metadata_pruner` succeeds first, updating `LedgerPrunerProgress` in its database [3](#0-2) , but one or more sub-pruners fail before committing their progress.

2. **Progress Metadata Loss:** If the `transaction_accumulator_db` metadata becomes corrupted or is selectively restored from backup, the `TransactionAccumulatorPrunerProgress` entry may be missing.

3. **Incorrect Initialization:** On restart, `get_or_initialize_subpruner_progress` finds no progress metadata and **assumes** versions have been pruned: [4](#0-3) 

This function writes the `metadata_progress` directly to the sub-pruner's progress without verifying the data was actually pruned, then calls `prune(metadata_progress, metadata_progress)` which is a no-op.

4. **Permanent Version Skipping:** Versions that were never pruned from the transaction accumulator schemas are now marked as pruned and will **never be cleaned up** in future pruning operations.

The code explicitly acknowledges this data inconsistency risk with a TODO comment: [5](#0-4) 

Storage sharding is **enforced** for production networks: [6](#0-5) 

## Impact Explanation

**Medium Severity** - This qualifies as "State inconsistencies requiring intervention" per the bug bounty program:

- **Storage Bloat:** Unpruned `TransactionAccumulatorRootHashSchema` and `TransactionAccumulatorSchema` entries accumulate indefinitely, consuming disk space.
- **Cross-Database Inconsistency:** Different database shards have different version ranges, violating the State Consistency invariant.
- **Operational Impact:** Requires manual database intervention to identify and clean up skipped versions.
- **No Direct Fund Loss:** Does not directly enable theft or consensus violations.

## Likelihood Explanation

**Medium-Low Likelihood:**

**Prerequisites:**
1. Storage sharding must be enabled (mandatory for mainnet/testnet)
2. Partial pruning failure where metadata pruner succeeds but sub-pruner fails
3. Database metadata corruption or selective restoration affecting sub-pruner progress tracking

**Realistic Scenarios:**
- Filesystem corruption affecting specific database shards
- Partial backup restoration (e.g., restoring main data but not all metadata)
- Disk failures affecting individual shard directories
- Manual database operations during recovery procedures

The issue is **not directly exploitable by external attackers** but can occur through operational failures or infrastructure issues that are beyond normal attack vectors.

## Recommendation

**Immediate Fix:** Validate sub-pruner progress consistency during initialization rather than blindly trusting `metadata_progress`:

```rust
pub(crate) fn get_or_initialize_subpruner_progress(
    sub_db: &DB,
    progress_key: &DbMetadataKey,
    metadata_progress: Version,
    verify_fn: impl FnOnce(Version) -> Result<bool>, // Verify data actually pruned
) -> Result<Version> {
    Ok(
        if let Some(v) = sub_db.get::<DbMetadataSchema>(progress_key)? {
            v.expect_version()
        } else {
            // Don't assume data is pruned - verify or start from 0
            let safe_progress = if verify_fn(metadata_progress)? {
                metadata_progress
            } else {
                0 // Start from beginning if we can't verify
            };
            sub_db.put::<DbMetadataSchema>(
                progress_key,
                &DbMetadataValue::Version(safe_progress),
            )?;
            safe_progress
        },
    )
}
```

**Long-term Solutions:**
1. Implement atomic cross-database progress tracking using a coordinator
2. Add startup consistency checks to detect and repair metadata inconsistencies  
3. Store backup/forward checksums to detect partial corruptions
4. Implement the TODO to properly handle data inconsistency: [5](#0-4) 

## Proof of Concept

```rust
// Reproduction steps (requires database manipulation):
// 
// 1. Set up node with storage sharding enabled
// 2. Run pruning to version 1000, let metadata_pruner succeed
// 3. Force-kill transaction_accumulator_pruner before commit
// 4. Corrupt transaction_accumulator_db metadata file to remove progress key
// 5. Restart node
// 6. Observe TransactionAccumulatorPrunerProgress initialized to 1000
// 7. Verify versions 0-999 still exist in TransactionAccumulatorRootHashSchema
// 8. Observe these versions are never pruned in subsequent pruning operations
//
// Expected: Versions should be re-pruned or progress should be conservative
// Actual: Versions 0-999 are permanently skipped from pruning
```

**Notes:**
- This issue requires database-level corruption or inconsistency, not achievable through normal API calls
- The TODO comment indicates the development team is aware of potential data inconsistency issues in the sharded architecture
- Pruning the same versions multiple times is **safe** (idempotent deletes), but **skipping versions is problematic** for storage management
- The vulnerability primarily affects storage efficiency rather than consensus or fund security

### Citations

**File:** storage/aptosdb/src/ledger_db/mod.rs (L214-226)
```rust
            s.spawn(|_| {
                transaction_accumulator_db = Some(TransactionAccumulatorDb::new(Arc::new(
                    Self::open_rocksdb(
                        ledger_db_folder.join(TRANSACTION_ACCUMULATOR_DB_NAME),
                        TRANSACTION_ACCUMULATOR_DB_NAME,
                        &rocksdb_configs.ledger_db_config,
                        env,
                        block_cache,
                        readonly,
                    )
                    .unwrap(),
                )));
            });
```

**File:** storage/aptosdb/src/ledger_db/mod.rs (L281-281)
```rust
        // TODO(grao): Handle data inconsistency.
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/mod.rs (L75-76)
```rust
            self.ledger_metadata_pruner
                .prune(progress, current_batch_target_version)?;
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/mod.rs (L78-84)
```rust
            THREAD_MANAGER.get_background_pool().install(|| {
                self.sub_pruners.par_iter().try_for_each(|sub_pruner| {
                    sub_pruner
                        .prune(progress, current_batch_target_version)
                        .map_err(|err| anyhow!("{} failed to prune: {err}", sub_pruner.name()))
                })
            })?;
```

**File:** storage/aptosdb/src/pruner/pruner_utils.rs (L44-60)
```rust
pub(crate) fn get_or_initialize_subpruner_progress(
    sub_db: &DB,
    progress_key: &DbMetadataKey,
    metadata_progress: Version,
) -> Result<Version> {
    Ok(
        if let Some(v) = sub_db.get::<DbMetadataSchema>(progress_key)? {
            v.expect_version()
        } else {
            sub_db.put::<DbMetadataSchema>(
                progress_key,
                &DbMetadataValue::Version(metadata_progress),
            )?;
            metadata_progress
        },
    )
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

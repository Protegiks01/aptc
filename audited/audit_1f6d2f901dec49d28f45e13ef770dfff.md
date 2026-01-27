# Audit Report

## Title
State KV Shard Pruner Skips Historical Entries After Progress Initialization, Causing Unbounded Database Growth

## Summary
The `StateKvShardPruner::prune()` function uses RocksDB's `seek()` operation to position an iterator at `current_progress`. When a shard's pruner progress is uninitialized (due to crashes or data loss) and gets initialized to the metadata pruner's progress, the catch-up prune operation skips all stale entries with `stale_since_version < current_progress`, leaving them permanently unpruned. This causes unbounded database growth and eventual storage exhaustion.

## Finding Description

The vulnerability exists in the pruner initialization and seek logic: [1](#0-0) 

When `StateKvShardPruner::new()` is called, it uses `get_or_initialize_subpruner_progress()` to retrieve the shard's pruning progress. If no progress exists, it initializes the progress to `metadata_progress`: [2](#0-1) 

The catch-up prune is then called with `prune(progress, metadata_progress)`. When `progress == metadata_progress` (because it was just initialized), the prune operation seeks to that progress value: [3](#0-2) 

**Critical Issue:** RocksDB's `seek()` operation positions the iterator at the first key **greater than or equal to** the seek key. The schema uses `stale_since_version` as the primary component of the key: [4](#0-3) [5](#0-4) 

When seeking to version 100, if no entry exists with exactly `stale_since_version=100`, or after processing entries at version 100, the iterator moves to entries with `stale_since_version > 100`. All entries with `stale_since_version < 100` remain before the iterator position and are never visited.

**Attack Scenario:**
1. Node runs with sharding enabled, accumulating stale entries in shards
2. First pruning cycle: metadata pruner completes (progress=100), but node crashes before shard pruners persist their progress
3. On restart: shard has no progress recorded, gets initialized to metadata_progress=100
4. Catch-up prune: `prune(100, 100)` seeks to version 100, skipping all entries with `stale_since_version < 100`
5. Those entries remain in the database permanently, never to be pruned
6. Over time, repeated crashes during pruning accumulate more orphaned entries
7. Database grows unbounded, leading to storage exhaustion and node failure

The same vulnerability pattern exists in the state merkle pruner: [6](#0-5) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program for the following reasons:

1. **Validator Node Slowdowns**: As unpruned data accumulates, database operations become progressively slower, degrading node performance and potentially affecting consensus participation.

2. **Storage Exhaustion**: Unbounded database growth eventually leads to disk space exhaustion, causing node crashes and loss of availability. This affects network health as validators become unable to participate.

3. **State Inconsistencies**: Different nodes may have different amounts of orphaned data depending on their crash history, leading to inconsistent database sizes and performance characteristics across the network.

4. **Production Impact**: This affects all mainnet/testnet deployments where `enable_storage_sharding=true` is mandatory: [7](#0-6) 

The pruning system processes both metadata and shard pruners non-atomically: [8](#0-7) 

## Likelihood Explanation

**Likelihood: High**

This vulnerability will occur in production under realistic conditions:

1. **Node Crashes During Pruning**: Common causes include:
   - Power failures or hardware issues
   - OOM kills during heavy pruning operations
   - Manual restarts/updates during active pruning
   - Network issues causing node crashes

2. **Non-Atomic Progress Updates**: The metadata pruner and shard pruners write to separate RocksDB instances, creating a window for inconsistency during crashes.

3. **Accumulation Over Time**: Each crash during pruning potentially leaves more orphaned entries. Over months of operation, the cumulative effect becomes significant.

4. **No Self-Healing**: Once entries are skipped, there's no mechanism to detect or recover them. They remain permanently until manual intervention.

## Recommendation

**Fix: Always start catch-up prune from version 0 when shard progress is uninitialized**

Modify `get_or_initialize_subpruner_progress` to return 0 instead of `metadata_progress` when no progress exists, or modify the initialization to explicitly start from 0:

```rust
pub(in crate::pruner) fn new(
    shard_id: usize,
    db_shard: Arc<DB>,
    metadata_progress: Version,
) -> Result<Self> {
    let progress = get_or_initialize_subpruner_progress(
        &db_shard,
        &DbMetadataKey::StateKvShardPrunerProgress(shard_id),
        0,  // Changed from metadata_progress to 0
    )?;
    let myself = Self { shard_id, db_shard };

    info!(
        progress = progress,
        metadata_progress = metadata_progress,
        "Catching up state kv shard {shard_id}."
    );
    
    // This will now properly prune from 0 to metadata_progress on first initialization
    myself.prune(progress, metadata_progress)?;

    Ok(myself)
}
```

**Alternative Fix: Use seekForPrev or explicit backward iteration**

Instead of seeking forward and potentially skipping entries, seek to the start of the database when `current_progress == 0` or implement explicit backward scanning to verify no entries exist before `current_progress`.

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_temppath::TempPath;
    use aptos_types::state_store::state_value::StaleStateValueByKeyHashIndex;
    use aptos_crypto::HashValue;

    #[test]
    fn test_shard_pruner_skips_old_entries_after_init() {
        // Setup test database
        let tmpdir = TempPath::new();
        let db = Arc::new(DB::open(
            tmpdir.path(),
            "test_db",
            vec![StaleStateValueIndexByKeyHashSchema::column_family()],
            &RocksdbConfig::default(),
        ).unwrap());

        // Simulate existing stale entries before pruning started
        let mut batch = SchemaBatch::new();
        for version in &[10u64, 20, 30, 40, 50, 60, 70] {
            let index = StaleStateValueByKeyHashIndex {
                stale_since_version: *version,
                version: *version,
                state_key_hash: HashValue::random(),
            };
            batch.put::<StaleStateValueIndexByKeyHashSchema>(&index, &()).unwrap();
        }
        db.write_schemas(batch).unwrap();

        // Simulate scenario: metadata pruner has progress=50, shard has no progress
        // This happens after a crash where metadata pruner completed but shard didn't
        
        // Initialize shard pruner (will set progress to 50)
        let pruner = StateKvShardPruner::new(
            0,
            Arc::clone(&db),
            50,  // metadata_progress = 50
        ).unwrap();

        // Verify shard progress was set to 50
        let shard_progress = db
            .get::<DbMetadataSchema>(&DbMetadataKey::StateKvShardPrunerProgress(0))
            .unwrap()
            .unwrap()
            .expect_version();
        assert_eq!(shard_progress, 50);

        // Check that entries with stale_since_version < 50 still exist (BUG!)
        let mut iter = db.iter::<StaleStateValueIndexByKeyHashSchema>().unwrap();
        iter.seek_to_first();
        let mut found_versions = Vec::new();
        for item in iter {
            let (index, _) = item.unwrap();
            found_versions.push(index.stale_since_version);
        }
        
        // VULNERABILITY: Entries [10, 20, 30, 40] should have been pruned but still exist!
        assert!(found_versions.contains(&10));
        assert!(found_versions.contains(&20));
        assert!(found_versions.contains(&30));
        assert!(found_versions.contains(&40));
        
        // These entries will never be pruned in future runs because
        // seek(&50) will skip them
    }
}
```

## Notes

This vulnerability also affects `StateMerkleShardPruner` which uses the same initialization pattern and seek-based pruning logic. Both pruning systems should be fixed to ensure complete pruning of historical data during catch-up operations.

### Citations

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_shard_pruner.rs (L25-45)
```rust
    pub(in crate::pruner) fn new(
        shard_id: usize,
        db_shard: Arc<DB>,
        metadata_progress: Version,
    ) -> Result<Self> {
        let progress = get_or_initialize_subpruner_progress(
            &db_shard,
            &DbMetadataKey::StateKvShardPrunerProgress(shard_id),
            metadata_progress,
        )?;
        let myself = Self { shard_id, db_shard };

        info!(
            progress = progress,
            metadata_progress = metadata_progress,
            "Catching up state kv shard {shard_id}."
        );
        myself.prune(progress, metadata_progress)?;

        Ok(myself)
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

**File:** storage/aptosdb/src/schema/stale_state_value_index_by_key_hash/mod.rs (L13-19)
```rust
//! ```text
//! |<-------------------key------------------------>|
//! | stale_since_version | version | state_key_hash |
//! ```
//!
//! `stale_since_version` is serialized in big endian so that records in RocksDB will be in order of
//! its numeric value.
```

**File:** storage/aptosdb/src/schema/stale_state_value_index_by_key_hash/mod.rs (L76-80)
```rust
impl SeekKeyCodec<StaleStateValueIndexByKeyHashSchema> for Version {
    fn encode_seek_key(&self) -> Result<Vec<u8>> {
        Ok(self.to_be_bytes().to_vec())
    }
}
```

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/mod.rs (L191-217)
```rust
    pub(in crate::pruner::state_merkle_pruner) fn get_stale_node_indices(
        state_merkle_db_shard: &DB,
        start_version: Version,
        target_version: Version,
        limit: usize,
    ) -> Result<(Vec<StaleNodeIndex>, Option<Version>)> {
        let mut indices = Vec::new();
        let mut iter = state_merkle_db_shard.iter::<S>()?;
        iter.seek(&StaleNodeIndex {
            stale_since_version: start_version,
            node_key: NodeKey::new_empty_path(0),
        })?;

        let mut next_version = None;
        while indices.len() < limit {
            if let Some((index, _)) = iter.next().transpose()? {
                next_version = Some(index.stale_since_version);
                if index.stale_since_version <= target_version {
                    indices.push(index);
                    continue;
                }
            }
            break;
        }

        Ok((indices, next_version))
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

**File:** storage/aptosdb/src/pruner/state_kv_pruner/mod.rs (L64-78)
```rust
            self.metadata_pruner
                .prune(progress, current_batch_target_version)?;

            THREAD_MANAGER.get_background_pool().install(|| {
                self.shard_pruners.par_iter().try_for_each(|shard_pruner| {
                    shard_pruner
                        .prune(progress, current_batch_target_version)
                        .map_err(|err| {
                            anyhow!(
                                "Failed to prune state kv shard {}: {err}",
                                shard_pruner.shard_id(),
                            )
                        })
                })
            })?;
```

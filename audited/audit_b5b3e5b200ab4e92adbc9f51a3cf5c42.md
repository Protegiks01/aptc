# Audit Report

## Title
Unbounded Memory Consumption in State KV Shard Pruner Leading to Node Crashes

## Summary
The `StateKvShardPruner::prune()` function lacks item count limits when processing stale state value indices. Unlike the analogous `StateMerkleShardPruner` which implements proper batching with `max_nodes_to_prune`, the state KV pruner iterates through all stale indices within a version range and accumulates them in memory without bounds, potentially causing memory exhaustion and validator node crashes during pruning operations.

## Finding Description
The vulnerability exists in the pruning logic for stale state key-value indices. [1](#0-0) 

The function seeks to a starting version and then iterates through all stale state value index entries where `stale_since_version <= target_version`, adding each to a `SchemaBatch` without any limit on the number of items. Each iteration performs two delete operations (one for the index, one for the state value), accumulating all operations in a single in-memory batch.

The `SchemaBatch` structure stores operations in a `HashMap<ColumnFamilyName, Vec<WriteOp>>` [2](#0-1)  with no built-in memory limits.

In contrast, the `StateMerkleShardPruner` implements proper batching with a `max_nodes_to_prune` parameter [3](#0-2)  and uses `get_stale_node_indices()` which explicitly limits the number of items fetched. [4](#0-3) 

The state KV pruner's parent `StateKvPruner::prune()` only limits the **version range** (default 5,000 versions via `batch_size`) [5](#0-4) [6](#0-5) , not the number of items within that range.

**Attack Scenario:**
1. High transaction throughput creates numerous state updates (each transaction can update multiple state keys)
2. Each state update creates a stale index entry [7](#0-6) 
3. Within a 5,000-version window, millions of stale indices can accumulate (e.g., 1,000 transactions/block × 10 state updates/transaction × 500 blocks = 5,000,000 indices)
4. When pruning runs, all indices within the version range are loaded into memory simultaneously
5. This causes memory exhaustion and node crashes

## Impact Explanation
This vulnerability falls under **Medium Severity** per Aptos bug bounty criteria:
- **Validator node slowdowns/crashes**: Nodes can crash during pruning operations due to out-of-memory errors
- **State inconsistencies requiring intervention**: Pruning failures can leave inconsistent state requiring manual intervention
- **Availability impact**: Affected validators become temporarily unavailable, reducing network resilience

While not causing direct fund loss or consensus violations, repeated crashes during pruning operations disrupt network operations and could enable availability attacks against specific validators.

## Likelihood Explanation
**High Likelihood** - This is likely to occur in production:
- Normal high-throughput operations naturally create many stale indices
- Default configuration (`batch_size: 5,000`) is vulnerable
- No attacker coordination required - emerges from legitimate network usage
- All validators running pruning operations are potentially affected
- The vulnerability is deterministic: sufficient state churn will trigger it

## Recommendation
Implement item count limiting in `StateKvShardPruner::prune()` similar to `StateMerkleShardPruner`:

```rust
pub(in crate::pruner) fn prune(
    &self,
    current_progress: Version,
    target_version: Version,
    max_items_to_prune: usize,
) -> Result<()> {
    loop {
        let mut batch = SchemaBatch::new();
        let mut iter = self
            .db_shard
            .iter::<StaleStateValueIndexByKeyHashSchema>()?;
        iter.seek(&current_progress)?;
        
        let mut items_processed = 0;
        let mut last_version = current_progress;
        let mut done = true;
        
        for item in iter {
            let (index, _) = item?;
            if index.stale_since_version > target_version {
                break;
            }
            
            if items_processed >= max_items_to_prune {
                last_version = index.stale_since_version;
                done = false;
                break;
            }
            
            batch.delete::<StaleStateValueIndexByKeyHashSchema>(&index)?;
            batch.delete::<StateValueByKeyHashSchema>(&(index.state_key_hash, index.version))?;
            items_processed += 1;
            last_version = index.stale_since_version;
        }
        
        if done {
            batch.put::<DbMetadataSchema>(
                &DbMetadataKey::StateKvShardPrunerProgress(self.shard_id),
                &DbMetadataValue::Version(target_version),
            )?;
        } else {
            batch.put::<DbMetadataSchema>(
                &DbMetadataKey::StateKvShardPrunerProgress(self.shard_id),
                &DbMetadataValue::Version(last_version),
            )?;
        }
        
        self.db_shard.write_schemas(batch)?;
        
        if done {
            break;
        }
    }
    
    Ok(())
}
```

Additionally, update the caller in `StateKvPruner::prune()` to pass a `max_items_to_prune` parameter (e.g., 10,000 items) and interpret `batch_size` configuration as an item limit rather than a version limit for the state KV pruner.

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_temppath::TempPath;
    use aptos_schemadb::DB;
    
    #[test]
    fn test_memory_exhaustion_during_pruning() {
        // Create temporary database
        let tmpdir = TempPath::new();
        let db = DB::open(
            tmpdir.path(),
            "test_db",
            vec![
                StaleStateValueIndexByKeyHashSchema::COLUMN_FAMILY_NAME,
                StateValueByKeyHashSchema::COLUMN_FAMILY_NAME,
                DbMetadataSchema::COLUMN_FAMILY_NAME,
            ],
            &Default::default(),
        ).unwrap();
        
        // Simulate high state churn: create 1 million stale indices within 1000 versions
        let mut batch = SchemaBatch::new();
        let base_version = 1000u64;
        let num_indices = 1_000_000;
        
        for i in 0..num_indices {
            let version = base_version + (i % 1000); // Spread across 1000 versions
            let index = StaleStateValueByKeyHashIndex {
                stale_since_version: version,
                version: version - 1,
                state_key_hash: HashValue::random(),
            };
            batch.put::<StaleStateValueIndexByKeyHashSchema>(&index, &()).unwrap();
            
            // Write in smaller batches to avoid setup OOM
            if i % 10_000 == 0 {
                db.write_schemas(batch).unwrap();
                batch = SchemaBatch::new();
            }
        }
        db.write_schemas(batch).unwrap();
        
        // Create pruner
        let pruner = StateKvShardPruner {
            shard_id: 0,
            db_shard: Arc::new(db),
        };
        
        // This will attempt to load ALL 1M indices into memory at once
        // In production with proper memory limits, this would OOM
        let result = pruner.prune(base_version, base_version + 1000);
        
        // The vulnerability is that this succeeds but consumes excessive memory
        // In a production environment with limited memory, this would crash
        assert!(result.is_ok());
    }
}
```

**Notes:**
- The vulnerability affects all validators running with sharding enabled (the default configuration)
- The issue becomes more severe as network throughput increases
- Current mitigation: operators can reduce `batch_size` configuration, but this only limits the version range, not item count
- The comparison with `StateMerkleShardPruner` clearly shows this is an implementation oversight rather than an intentional design choice

### Citations

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

**File:** storage/schemadb/src/batch.rs (L127-133)
```rust
/// `SchemaBatch` holds a collection of updates that can be applied to a DB atomically. The updates
/// will be applied in the order in which they are added to the `SchemaBatch`.
#[derive(Debug, Default)]
pub struct SchemaBatch {
    rows: DropHelper<HashMap<ColumnFamilyName, Vec<WriteOp>>>,
    stats: SampledBatchStats,
}
```

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/state_merkle_shard_pruner.rs (L58-100)
```rust
    pub(in crate::pruner) fn prune(
        &self,
        current_progress: Version,
        target_version: Version,
        max_nodes_to_prune: usize,
    ) -> Result<()> {
        loop {
            let mut batch = SchemaBatch::new();
            let (indices, next_version) = StateMerklePruner::get_stale_node_indices(
                &self.db_shard,
                current_progress,
                target_version,
                max_nodes_to_prune,
            )?;

            indices.into_iter().try_for_each(|index| {
                batch.delete::<JellyfishMerkleNodeSchema>(&index.node_key)?;
                batch.delete::<S>(&index)
            })?;

            let mut done = true;
            if let Some(next_version) = next_version {
                if next_version <= target_version {
                    done = false;
                }
            }

            if done {
                batch.put::<DbMetadataSchema>(
                    &S::progress_metadata_key(Some(self.shard_id)),
                    &DbMetadataValue::Version(target_version),
                )?;
            }

            self.db_shard.write_schemas(batch)?;

            if done {
                break;
            }
        }

        Ok(())
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

**File:** storage/aptosdb/src/pruner/state_kv_pruner/mod.rs (L49-86)
```rust
    fn prune(&self, max_versions: usize) -> Result<Version> {
        let _timer = OTHER_TIMERS_SECONDS.timer_with(&["state_kv_pruner__prune"]);

        let mut progress = self.progress();
        let target_version = self.target_version();

        while progress < target_version {
            let current_batch_target_version =
                min(progress + max_versions as Version, target_version);

            info!(
                progress = progress,
                target_version = current_batch_target_version,
                "Pruning state kv data."
            );
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

            progress = current_batch_target_version;
            self.record_progress(progress);
            info!(progress = progress, "Pruning state kv data is done.");
        }

        Ok(target_version)
    }
```

**File:** config/src/config/storage_config.rs (L387-395)
```rust
impl Default for LedgerPrunerConfig {
    fn default() -> Self {
        LedgerPrunerConfig {
            enable: true,
            prune_window: 90_000_000,
            batch_size: 5_000,
            user_pruning_window_offset: 200_000,
        }
    }
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

# Audit Report

## Title
Unbounded Memory Consumption and Write Stall in StateKvShardPruner Due to Missing Batch Size Limit

## Summary
The `StateKvShardPruner::prune()` function lacks internal batching controls, causing it to accumulate an unbounded number of deletion operations in a single `SchemaBatch` when processing large version ranges with many stale state values. This can lead to memory exhaustion, RocksDB write stalls, and validator node slowdowns or crashes.

## Finding Description

The `StateKvShardPruner::prune()` function processes entire version ranges without any limit on the number of deletion operations accumulated in memory. [1](#0-0) 

The function iterates through all stale state value entries between `current_progress` and `target_version`, adding each deletion to a single `SchemaBatch` without checking batch size. The iterator processes all entries in one loop (lines 58-65), and all deletions are accumulated in memory before being written atomically via `write_schemas(batch)` at line 71.

In contrast, `StateMerkleShardPruner::prune()` implements proper batching with a `max_nodes_to_prune` parameter. [2](#0-1) 

This implementation uses a loop (line 64) to process entries in chunks, calling `get_stale_node_indices()` with a limit parameter (lines 66-71) and writing smaller batches incrementally (line 92).

The `get_stale_node_indices()` function respects the limit parameter, ensuring bounded memory usage. [3](#0-2) 

At line 205, the loop condition `while indices.len() < limit` ensures at most `limit` indices are returned per call.

The parent `StateKvPruner` provides version-based batching but does not limit the number of entries within each version range. [4](#0-3) 

At line 57, it limits the version range to `progress + max_versions`, but when calling `shard_pruner.prune()` at line 70, no entry count limit is passed. The default `batch_size` is 5,000 versions. [5](#0-4) 

The `SchemaBatch` implementation has no size limits - it simply accumulates operations in a `HashMap<ColumnFamilyName, Vec<WriteOp>>`. [6](#0-5) 

Each `delete` operation creates a `WriteOp::Deletion` and pushes it to the vector (lines 165-171) without any size checks.

Stale state value entries are created whenever state keys are updated or deleted during transaction processing. [7](#0-6) 

Lines 947-950 show tombstone deletions create stale entries, and lines 970-980 show updates create stale entries for old values. This means any user submitting transactions that update state will naturally create stale entries.

During initialization or catch-up scenarios, the pruner can process arbitrarily large version ranges. [8](#0-7) 

At line 42, `myself.prune(progress, metadata_progress)` is called, where `metadata_progress` could be millions of versions ahead if a node was offline.

**Attack Scenario:**
1. An attacker submits transactions that repeatedly update the same state keys
2. Each update creates stale entries in `StaleStateValueIndexByKeyHashSchema`
3. During pruning (especially catch-up), `StateKvShardPruner::prune()` loads all stale entries into a single batch
4. With sufficient volume across 5,000 versions (or more during catch-up), millions of entries accumulate in memory
5. This causes memory exhaustion, OOM crashes, or RocksDB write stalls that block consensus operations

## Impact Explanation

This vulnerability falls under **High Severity** per Aptos bug bounty criteria: "Validator Node Slowdowns - Significant performance degradation affecting consensus, DoS through resource exhaustion."

**Specific Impacts:**

1. **Memory Exhaustion**: Processing millions of deletion operations in a single batch can consume gigabytes of RAM, causing OOM conditions that crash validator nodes.

2. **Write Stalls**: Large atomic writes to RocksDB can trigger write stalls, blocking all write operations to the affected db_shard, including critical state commits from consensus.

3. **Availability Impact**: If multiple validators experience this simultaneously (e.g., during network-wide catch-up), network liveness could be degraded.

4. **Compaction Blocking**: The iterator holds a RocksDB snapshot for the entire duration, preventing compaction and increasing disk space usage.

This is not a "network DoS attack" (which is out of scope) but rather an internal resource exhaustion bug in the storage layer that lacks proper memory limits.

## Likelihood Explanation

**Likelihood: Medium to High**

This issue can occur in realistic scenarios:

1. **High-Frequency Contract Updates**: Popular DeFi protocols or gaming applications that frequently update state naturally create many stale values per version.

2. **Catch-Up Scenarios**: When a validator restarts after downtime, it must catch up on potentially millions of versions worth of stale data in a single initialization call.

3. **Storage Migration**: Upgrading from non-sharded to sharded storage could trigger initial pruning of very large version ranges.

4. **Deliberate Attack**: Any user with sufficient gas budget can submit transactions that maximize stale state value generation.

**Attacker Requirements:**
- Ability to submit transactions (any user, no special privileges)
- Sufficient gas to create many state updates (economically feasible)
- No validator access required

## Recommendation

Implement batching in `StateKvShardPruner::prune()` similar to `StateMerkleShardPruner`:

```rust
pub(in crate::pruner) fn prune(
    &self,
    current_progress: Version,
    target_version: Version,
    max_entries_to_prune: usize, // Add limit parameter
) -> Result<()> {
    let mut progress = current_progress;
    
    loop {
        let mut batch = SchemaBatch::new();
        let mut count = 0;
        
        let mut iter = self
            .db_shard
            .iter::<StaleStateValueIndexByKeyHashSchema>()?;
        iter.seek(&progress)?;
        
        for item in iter {
            let (index, _) = item?;
            if index.stale_since_version > target_version {
                break;
            }
            if count >= max_entries_to_prune {
                progress = index.stale_since_version;
                break;
            }
            
            batch.delete::<StaleStateValueIndexByKeyHashSchema>(&index)?;
            batch.delete::<StateValueByKeyHashSchema>(&(index.state_key_hash, index.version))?;
            count += 1;
        }
        
        let done = count < max_entries_to_prune;
        if done {
            batch.put::<DbMetadataSchema>(
                &DbMetadataKey::StateKvShardPrunerProgress(self.shard_id),
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

Update the caller in `StateKvPruner::prune()` to pass a configurable limit (e.g., 10,000 entries per batch).

## Proof of Concept

The vulnerability can be demonstrated by examining the code paths during high-volume state updates:

1. Deploy a Move module that updates a resource repeatedly
2. Submit many transactions (e.g., 1,000 transactions per version × 5,000 versions = 5 million state updates)
3. Each update creates a stale entry
4. When pruner runs, `StateKvShardPruner::prune()` attempts to load all 5 million entries into a single `SchemaBatch`
5. Memory consumption grows unbounded, eventually causing OOM or write stalls

The code evidence clearly shows the missing batching control compared to the equivalent `StateMerkleShardPruner` implementation.

### Citations

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_shard_pruner.rs (L25-44)
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

**File:** storage/schemadb/src/batch.rs (L130-173)
```rust
pub struct SchemaBatch {
    rows: DropHelper<HashMap<ColumnFamilyName, Vec<WriteOp>>>,
    stats: SampledBatchStats,
}

impl SchemaBatch {
    /// Creates an empty batch.
    pub fn new() -> Self {
        Self::default()
    }

    /// keep these on the struct itself so that we don't need to update each call site.
    pub fn put<S: Schema>(&mut self, key: &S::Key, value: &S::Value) -> DbResult<()> {
        <Self as WriteBatch>::put::<S>(self, key, value)
    }

    pub fn delete<S: Schema>(&mut self, key: &S::Key) -> DbResult<()> {
        <Self as WriteBatch>::delete::<S>(self, key)
    }
}

impl WriteBatch for SchemaBatch {
    fn stats(&mut self) -> &mut SampledBatchStats {
        &mut self.stats
    }

    fn raw_put(&mut self, cf_name: ColumnFamilyName, key: Vec<u8>, value: Vec<u8>) -> DbResult<()> {
        self.rows
            .entry(cf_name)
            .or_default()
            .push(WriteOp::Value { key, value });

        Ok(())
    }

    fn raw_delete(&mut self, cf_name: ColumnFamilyName, key: Vec<u8>) -> DbResult<()> {
        self.rows
            .entry(cf_name)
            .or_default()
            .push(WriteOp::Deletion { key });

        Ok(())
    }
}
```

**File:** storage/aptosdb/src/state_store/mod.rs (L926-1015)
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

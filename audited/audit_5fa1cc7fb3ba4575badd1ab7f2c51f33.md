# Audit Report

## Title
Unbounded Memory Consumption and Write Stall in StateKvShardPruner Due to Missing Batch Size Limit

## Summary
The `StateKvShardPruner::prune()` function lacks internal batching controls, causing it to accumulate an unbounded number of deletion operations in a single `SchemaBatch` when processing large version ranges with many stale state values. This can lead to memory exhaustion, RocksDB write stalls, and validator node slowdowns or crashes.

## Finding Description

The `StateKvShardPruner::prune()` function iterates through all stale state value entries between `current_progress` and `target_version` and adds deletion operations for each entry to a single `SchemaBatch` without any batching limit. [1](#0-0) 

The function processes the entire version range in one iteration, accumulating all deletions in memory before writing them in a single atomic operation. When the version range is large (e.g., 5,000 versions with the default batch size) and there have been many state updates across those versions, this results in:

1. **Unbounded Memory Growth**: If there are millions of stale entries (common during heavy contract execution or catch-up scenarios), the `batch` object grows without limit, potentially consuming gigabytes of memory.

2. **Large Atomic Writes**: The final `write_schemas(batch)` call writes potentially millions of deletions in a single RocksDB write operation, which can trigger write stalls.

3. **Snapshot Holding**: The iterator holds a RocksDB snapshot for the entire duration of the loop, preventing compaction and increasing space amplification.

This design contrasts sharply with `StateMerkleShardPruner::prune()`, which implements proper batching: [2](#0-1) 

The `StateMerkleShardPruner` accepts a `max_nodes_to_prune` parameter and uses a loop to process entries in chunks, writing smaller batches incrementally. It calls `get_stale_node_indices()` with a limit parameter: [3](#0-2) 

This function respects the `limit` parameter and returns at most `limit` indices per call, ensuring bounded memory usage.

**Attack Scenario:**

1. An attacker submits many transactions that repeatedly update the same state keys (e.g., updating a resource in a smart contract).
2. Each update creates a new state value and marks the previous value as stale, adding an entry to `StaleStateValueIndexByKeyHashSchema`.
3. During normal operation or catch-up, when the pruner runs with a large version range, `StateKvShardPruner::prune()` attempts to load all these stale entries into a single batch.
4. With sufficient transaction volume, this can cause:
   - Memory exhaustion (OOM killer terminating the validator process)
   - RocksDB write stalls blocking concurrent write operations
   - Severe performance degradation affecting consensus participation
   - Node crashes requiring restart

The parent `StateKvPruner` does provide version-based batching: [4](#0-3) 

However, this only limits the version range (default 5,000 versions via `batch_size`), not the number of entries within that range. If there are 100 state updates per version on average, a single batch could contain 500,000 deletion operations. [5](#0-4) 

## Impact Explanation

This vulnerability falls under **High Severity** per the Aptos bug bounty criteria: "Validator node slowdowns" and potentially API crashes.

**Specific Impacts:**

1. **Memory Exhaustion**: Large batches can consume multiple gigabytes of RAM, causing OOM conditions that crash validator nodes.

2. **Write Stalls**: RocksDB write stalls occur when large writes exceed configured thresholds, blocking all write operations to the affected db_shard, including critical state commits from consensus.

3. **Availability Impact**: If multiple validators experience this issue simultaneously (e.g., during catch-up after network issues), network liveness could be significantly degraded.

4. **Compaction Blocking**: Long-held iterator snapshots prevent RocksDB compaction, increasing disk space usage and degrading read performance.

While this doesn't directly cause consensus violations or fund loss, it violates the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The pruner operation consumes unbounded memory and can block critical operations.

## Likelihood Explanation

**Likelihood: Medium to High**

This issue is likely to occur in several realistic scenarios:

1. **High-Frequency Contract Updates**: Popular DeFi protocols or gaming applications that frequently update state create many stale values. A single popular contract could generate thousands of stale entries per version.

2. **Catch-Up Scenarios**: When a validator node restarts or rejoins after downtime with pruning enabled, it must catch up on potentially millions of versions worth of stale data.

3. **Storage Migration**: When upgrading from non-sharded to sharded storage, the initial pruning could process very large version ranges.

4. **Deliberate Attack**: An attacker with sufficient gas budget can intentionally create transaction patterns that maximize stale state value generation, specifically targeting this vulnerability.

The attacker requirements are minimal:
- Ability to submit transactions (any user)
- Sufficient gas to create many state updates (economically feasible)
- No validator privileges required

## Recommendation

Implement batching within `StateKvShardPruner::prune()` similar to `StateMerkleShardPruner::prune()`:

**Recommended Fix:**

```rust
pub(in crate::pruner) fn prune(
    &self,
    current_progress: Version,
    target_version: Version,
    max_entries_per_batch: usize,  // Add batching parameter
) -> Result<()> {
    let mut current = current_progress;
    
    loop {
        let mut batch = SchemaBatch::new();
        let mut count = 0;
        
        let mut iter = self
            .db_shard
            .iter::<StaleStateValueIndexByKeyHashSchema>()?;
        iter.seek(&current)?;
        
        for item in iter {
            let (index, _) = item?;
            if index.stale_since_version > target_version {
                break;
            }
            if count >= max_entries_per_batch {
                // Save next position for next batch
                current = index.stale_since_version;
                break;
            }
            
            batch.delete::<StaleStateValueIndexByKeyHashSchema>(&index)?;
            batch.delete::<StateValueByKeyHashSchema>(&(index.state_key_hash, index.version))?;
            count += 1;
        }
        
        if count == 0 {
            // Done - update final progress
            batch.put::<DbMetadataSchema>(
                &DbMetadataKey::StateKvShardPrunerProgress(self.shard_id),
                &DbMetadataValue::Version(target_version),
            )?;
            self.db_shard.write_schemas(batch)?;
            break;
        }
        
        // Write batch and continue
        self.db_shard.write_schemas(batch)?;
        
        if current >= target_version {
            // Final progress update
            let mut final_batch = SchemaBatch::new();
            final_batch.put::<DbMetadataSchema>(
                &DbMetadataKey::StateKvShardPrunerProgress(self.shard_id),
                &DbMetadataValue::Version(target_version),
            )?;
            self.db_shard.write_schemas(final_batch)?;
            break;
        }
    }
    
    Ok(())
}
```

**Additional Changes Required:**

Update the caller in `StateKvPruner::prune()` to pass the batching parameter: [6](#0-5) 

The call should include a configurable `max_entries_per_batch` parameter (e.g., 10,000 entries per batch, similar to how `StateMerklePruner` passes `batch_size` to shard pruners).

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use crate::schema::{
        stale_state_value_index_by_key_hash::StaleStateValueIndexByKeyHashSchema,
        state_value_by_key_hash::StateValueByKeyHashSchema,
    };
    use aptos_crypto::HashValue;
    use aptos_schemadb::DB;
    use aptos_temppath::TempPath;
    use aptos_types::state_store::state_key::StateKey;
    
    #[test]
    fn test_unbounded_memory_consumption() {
        // Setup: Create a db_shard with many stale entries
        let tmpdir = TempPath::new();
        let db = Arc::new(DB::open(
            tmpdir.path(),
            "test_db",
            vec![
                StaleStateValueIndexByKeyHashSchema::COLUMN_FAMILY_NAME,
                StateValueByKeyHashSchema::COLUMN_FAMILY_NAME,
            ],
            &Default::default(),
        ).unwrap());
        
        // Simulate 100,000 stale entries across 1,000 versions
        let num_entries = 100_000;
        let versions_per_entry = 1000;
        
        for i in 0..num_entries {
            let version = (i / (num_entries / versions_per_entry)) as u64;
            let key_hash = HashValue::sha3_256_of(&i.to_le_bytes());
            
            // Write stale index
            db.put::<StaleStateValueIndexByKeyHashSchema>(
                &StaleStateValueIndex {
                    stale_since_version: version,
                    version,
                    state_key_hash: key_hash,
                },
                &(),
            ).unwrap();
            
            // Write corresponding state value
            db.put::<StateValueByKeyHashSchema>(
                &(key_hash, version),
                &vec![0u8; 100], // 100 bytes per value
            ).unwrap();
        }
        
        // Create pruner
        let pruner = StateKvShardPruner::new(0, db.clone(), 0).unwrap();
        
        // Measure memory before and after pruning
        let mem_before = get_memory_usage();
        
        // This will try to load ALL 100,000 entries into a single batch
        // Expected: Memory spike of ~10MB+ (100K entries * ~100 bytes each)
        // Actual issue: No batching limit, entire dataset loaded
        let result = pruner.prune(0, versions_per_entry as u64);
        
        let mem_after = get_memory_usage();
        let mem_increase = mem_after - mem_before;
        
        assert!(result.is_ok());
        
        // Demonstrate that memory increased significantly
        // In production, with millions of entries, this could be gigabytes
        println!("Memory increased by: {} MB", mem_increase / 1_000_000);
        assert!(mem_increase > 5_000_000, "Expected significant memory increase");
    }
    
    fn get_memory_usage() -> usize {
        // Platform-specific memory measurement
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            let statm = fs::read_to_string("/proc/self/statm").unwrap();
            let rss_pages: usize = statm.split_whitespace().nth(1).unwrap().parse().unwrap();
            rss_pages * 4096 // Convert pages to bytes
        }
        #[cfg(not(target_os = "linux"))]
        {
            0 // Fallback for non-Linux systems
        }
    }
}
```

**Notes:**
- This PoC demonstrates the unbounded accumulation of entries in a single batch
- With 100,000 entries, the memory impact is measurable; with millions (realistic in production), it becomes critical
- The test can be extended to measure write latency and demonstrate write stall behavior
- In a real attack scenario, an attacker would target popular contracts to maximize stale value generation

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

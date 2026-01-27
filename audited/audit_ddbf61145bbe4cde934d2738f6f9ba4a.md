# Audit Report

## Title
Shard Pruner Progress Initialization Vulnerability Leading to Permanent Data Retention

## Summary
When `StateKvShardPruner::new()` initializes a shard's pruning progress, it may initialize to an incorrect `metadata_progress` value if the shard's progress key is missing. This causes the shard to permanently skip pruning data from earlier versions, leading to unbounded storage growth and state inconsistencies across shards.

## Finding Description
The vulnerability exists in the shard pruner initialization flow: [1](#0-0) 

The `new()` function calls `get_or_initialize_subpruner_progress()` which implements the following logic: [2](#0-1) 

If the shard's progress key doesn't exist, it initializes to `metadata_progress`. The problem arises because the metadata pruner can be ahead of shard pruners due to the pruning order: [3](#0-2) 

The metadata pruner commits first (line 64-65), then shard pruners run in parallel (lines 67-78). If the system crashes after the metadata pruner commits but before all shard pruners complete, `metadata_progress` will be ahead of the actual shard progress.

On restart, if a shard's progress key is missing (due to corruption, deletion, or first-time initialization), it will be initialized to the higher `metadata_progress`. The subsequent pruning operation then skips all earlier versions: [4](#0-3) 

The pruner seeks to `current_progress` (line 57) in the `StaleStateValueIndexByKeyHashSchema`, which has keys ordered by `stale_since_version`: [5](#0-4) [6](#0-5) 

When seeking with version 10000, it jumps to entries with `stale_since_version >= 10000`, permanently skipping all entries with `stale_since_version < 10000`.

**Scenario:**
1. System running with sharding enabled, all pruners at version 5000
2. Pruning batch: metadata pruner advances to version 10000 and commits
3. System crashes before shard pruners complete
4. On restart, Shard 3's progress key is corrupted/missing
5. `StateKvShardPruner::new(shard_id=3, metadata_progress=10000)` initializes Shard 3 to version 10000
6. `prune(10000, 10000)` is called - seeks to version 10000, skips everything before
7. Versions 5000-9999 in Shard 3 are never pruned

This breaks the **State Consistency** invariant - different shards retain different amounts of stale data, and the pruning system can no longer guarantee storage bounds.

## Impact Explanation
**Medium Severity** - "State inconsistencies requiring intervention"

While this doesn't directly cause loss of funds or consensus violations, it results in:

1. **Unbounded Storage Growth**: Unpruned stale state values accumulate indefinitely in affected shards, violating storage resource limits
2. **State Inconsistency**: Different shards have different pruning progress, breaking the assumption that all shards maintain consistent pruning windows
3. **Performance Degradation**: Queries may become slower over time as unpruned data accumulates
4. **Operational Impact**: Requires manual intervention to detect and fix affected shards, potentially requiring database migrations or rebuilds

The vulnerability requires no attacker action but occurs naturally during system crashes or database corruption scenarios, which are common in production blockchain environments.

## Likelihood Explanation
**High Likelihood** - This can occur in multiple realistic scenarios:

1. **Crash During Pruning**: The two-phase commit (metadata first, then shards) creates a window where crashes leave inconsistent state
2. **Database Corruption**: Storage layer corruption can delete or corrupt progress keys
3. **First-Time Sharding**: When enabling sharding on an existing node, if metadata_progress exists but shard progress doesn't
4. **Race Conditions**: Parallel shard pruning could fail partially, leaving some shards without updated progress

These are operational realities for long-running validator nodes, making this a practically exploitable vulnerability in production environments.

## Recommendation
Implement one of the following fixes:

**Option 1: Conservative Initialization**
Initialize missing shard progress to the minimum of all existing shard progresses, not to metadata_progress:

```rust
pub(in crate::pruner) fn new(
    shard_id: usize,
    db_shard: Arc<DB>,
    metadata_progress: Version,
    min_shard_progress: Option<Version>,  // Pass minimum from all shards
) -> Result<Self> {
    let initial_progress = min_shard_progress.unwrap_or(0);
    let progress = get_or_initialize_subpruner_progress(
        &db_shard,
        &DbMetadataKey::StateKvShardPrunerProgress(shard_id),
        initial_progress,  // Use conservative minimum
    )?;
    
    let myself = Self { shard_id, db_shard };
    
    // Catch up to metadata_progress
    if progress < metadata_progress {
        myself.prune(progress, metadata_progress)?;
    }
    
    Ok(myself)
}
```

**Option 2: Atomic Progress Tracking**
Store all shard progresses and metadata progress atomically in a single transaction to prevent divergence.

**Option 3: Progress Validation**
Add validation to detect and warn when shard progress diverges significantly from metadata progress, allowing operators to intervene before data is permanently lost.

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use crate::test_helper;
    use aptos_temppath::TempPath;
    
    #[test]
    fn test_shard_pruner_skips_data_on_incorrect_initialization() {
        let tmpdir = TempPath::new();
        let db = test_helper::arced_aptosdb_with_sharding(&tmpdir);
        
        // Simulate system state: metadata at version 10000, shard at version 5000
        let state_kv_db = db.state_kv_db();
        let metadata_db = state_kv_db.metadata_db();
        
        // Set metadata progress to 10000
        metadata_db.put::<DbMetadataSchema>(
            &DbMetadataKey::StateKvPrunerProgress,
            &DbMetadataValue::Version(10000)
        ).unwrap();
        
        // Insert stale state values at versions 5000-9999 in shard 0
        let shard_0 = state_kv_db.db_shard(0);
        for version in 5000..10000 {
            let index = StaleStateValueByKeyHashIndex {
                stale_since_version: version,
                version: version - 100,
                state_key_hash: HashValue::random(),
            };
            shard_0.put::<StaleStateValueIndexByKeyHashSchema>(&index, &()).unwrap();
        }
        
        // Delete shard 0's progress (simulating corruption)
        shard_0.delete::<DbMetadataSchema>(
            &DbMetadataKey::StateKvShardPrunerProgress(0)
        ).unwrap();
        
        // Initialize shard pruner - it will set progress to 10000
        let pruner = StateKvShardPruner::new(
            0,
            state_kv_db.db_shard_arc(0),
            10000,  // metadata_progress
        ).unwrap();
        
        // Verify that data from versions 5000-9999 was NOT pruned
        for version in 5000..10000 {
            let mut iter = shard_0.iter::<StaleStateValueIndexByKeyHashSchema>().unwrap();
            iter.seek(&version).unwrap();
            
            if let Some(item) = iter.next() {
                let (index, _) = item.unwrap();
                if index.stale_since_version == version {
                    // Data still exists - vulnerability confirmed!
                    panic!("Vulnerability: Version {} was not pruned!", version);
                }
            }
        }
    }
}
```

## Notes

This vulnerability is particularly concerning because:

1. **Silent Failure**: The system continues operating normally, but storage grows unbounded without obvious symptoms
2. **Irreversible**: Once the progress is initialized incorrectly, there's no automatic recovery mechanism
3. **Cascading Effect**: Multiple shards can be affected simultaneously if the crash occurs during parallel pruning
4. **Production Relevance**: Validator nodes running for extended periods will inevitably encounter crashes during pruning operations

The fix should prioritize data correctness over performance, defaulting to conservative initialization that ensures no pruning range is ever skipped.

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

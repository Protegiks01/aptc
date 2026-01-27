# Audit Report

## Title
State KV Shard Pruner Incorrectly Initializes Progress Leading to Permanent Data Retention

## Summary
The `StateKvShardPruner::new()` function initializes shard pruning progress to `metadata_progress` when no existing progress marker is found. This causes the initial catch-up prune operation to skip all historical stale data below `metadata_progress`, resulting in permanent storage bloat and potential disk exhaustion.

## Finding Description

The vulnerability exists in the initialization logic of the state KV shard pruner. When a shard has no existing `StateKvShardPrunerProgress` entry (due to database corruption, first-time initialization after metadata progress has advanced, or crash recovery), the pruner initializes the shard's progress to the current `metadata_progress` value. [1](#0-0) 

The critical flaw is in `get_or_initialize_subpruner_progress()`, which writes `metadata_progress` as the initial value when no progress exists: [2](#0-1) 

After initialization, `prune(progress, metadata_progress)` is called where both arguments equal `metadata_progress`. The prune function seeks to entries with `stale_since_version >= metadata_progress`: [3](#0-2) 

The `StaleStateValueIndexByKeyHashSchema` uses `stale_since_version` as the first component of its key, serialized in big-endian format for ordering: [4](#0-3) 

**Attack Scenario:**

1. Node operates normally with sharding enabled, metadata pruner progress advances to version N
2. Crash occurs after `StateKvMetadataPruner::prune()` updates `StateKvPrunerProgress = N` but before shard pruners complete
3. Database corruption or recovery causes loss of `StateKvShardPrunerProgress` entries for some shards
4. On restart, affected shards are initialized with progress = N
5. Initial `prune(N, N)` seeks to `stale_since_version >= N`, processing only entries where `stale_since_version == N`
6. All stale entries with `stale_since_version < N` are permanently skipped and never pruned

The metadata pruner updates progress before shard pruning completes: [5](#0-4) 

This creates a window where metadata progress can be ahead of shard progress, especially during the pruning loop: [6](#0-5) 

## Impact Explanation

This vulnerability causes **Medium severity** impact:

1. **Storage Bloat**: Unpruned stale state values accumulate indefinitely in affected shards, consuming disk space exponentially over time
2. **Disk Exhaustion**: Eventually leads to disk full conditions, causing node crashes and loss of availability
3. **Performance Degradation**: Database queries must traverse unpruned historical data, slowing read operations
4. **Operational Overhead**: Requires manual intervention to identify and remediate affected shards

While this doesn't directly cause fund loss or consensus violations, it creates **state inconsistencies requiring intervention** (Medium severity per bug bounty criteria). A node with full disk cannot process new blocks, effectively causing local liveness failure. If multiple validator nodes are affected simultaneously, this could impact network availability.

## Likelihood Explanation

**Medium likelihood** in production environments:

1. **Crash During Pruning**: The window between metadata pruner completion and shard pruner completion creates exposure during every pruning operation
2. **Database Corruption**: Hardware failures, filesystem issues, or improper shutdowns can corrupt metadata entries while preserving data entries
3. **Operational Errors**: Database restoration from backups may restore data but lose recent progress markers
4. **Migration Issues**: Nodes migrating from non-sharded to sharded configurations could encounter initialization inconsistencies

The vulnerability doesn't require attacker access but can be triggered through normal operational scenarios (crashes, hardware failures, migrations). Given the frequency of pruning operations in long-running validators, the cumulative probability over time is significant.

## Recommendation

Modify the initialization logic to never skip historical data:

1. **Check for existing data**: Before initializing progress, scan the shard for the oldest `stale_since_version` entry
2. **Initialize to minimum**: Set initial progress to `min(oldest_stale_version, metadata_progress)` or 0 if no data exists
3. **Log warnings**: Emit alerts when progress initialization detects gaps requiring large catch-up operations

Example fix in `state_kv_shard_pruner.rs`:

```rust
pub(in crate::pruner) fn new(
    shard_id: usize,
    db_shard: Arc<DB>,
    metadata_progress: Version,
) -> Result<Self> {
    let stored_progress = db_shard.get::<DbMetadataSchema>(
        &DbMetadataKey::StateKvShardPrunerProgress(shard_id)
    )?;
    
    let progress = if let Some(v) = stored_progress {
        v.expect_version()
    } else {
        // Check for actual data in shard before initializing
        let oldest_version = find_oldest_stale_version(&db_shard)?;
        let safe_progress = oldest_version.unwrap_or(metadata_progress).min(metadata_progress);
        
        if safe_progress < metadata_progress {
            warn!(
                shard_id = shard_id,
                safe_progress = safe_progress,
                metadata_progress = metadata_progress,
                "Shard progress missing, initializing to safe value to avoid data loss"
            );
        }
        
        db_shard.put::<DbMetadataSchema>(
            &DbMetadataKey::StateKvShardPrunerProgress(shard_id),
            &DbMetadataValue::Version(safe_progress),
        )?;
        safe_progress
    };
    
    // Continue with existing logic...
}
```

## Proof of Concept

```rust
#[test]
fn test_shard_pruner_initialization_skips_data() {
    // Setup: Create shard with stale data at versions 100-200
    let shard_db = create_test_shard();
    populate_stale_entries(&shard_db, 100, 200);
    
    // Simulate metadata pruner advancing to version 1000
    // without corresponding shard pruner progress
    let metadata_progress = 1000;
    
    // Create new shard pruner (simulating restart after crash)
    let shard_pruner = StateKvShardPruner::new(
        0,
        Arc::new(shard_db.clone()),
        metadata_progress,
    ).unwrap();
    
    // Verify: Stale entries from 100-200 still exist (not pruned)
    for version in 100..200 {
        let entries = get_stale_entries_at_version(&shard_db, version);
        assert!(!entries.is_empty(), 
            "Expected stale data at version {} to remain unpruned", version);
    }
    
    // Demonstrate: No future pruning will remove this data
    shard_pruner.prune(1000, 2000).unwrap();
    
    for version in 100..200 {
        let entries = get_stale_entries_at_version(&shard_db, version);
        assert!(!entries.is_empty(), 
            "Data at version {} permanently leaked after pruning to 2000", version);
    }
}
```

## Notes

This vulnerability demonstrates a critical gap in the catch-up logic for shard pruners. The assumption that `prune(metadata_progress, metadata_progress)` is safe breaks when the shard has never been pruned but contains data below `metadata_progress`. The fix must ensure that initialization never creates gaps in the pruning history, even in crash recovery or corruption scenarios.

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

**File:** storage/aptosdb/src/schema/stale_state_value_index_by_key_hash/mod.rs (L39-63)
```rust
impl KeyCodec<StaleStateValueIndexByKeyHashSchema> for StaleStateValueByKeyHashIndex {
    fn encode_key(&self) -> Result<Vec<u8>> {
        let mut encoded = vec![];
        encoded.write_u64::<BigEndian>(self.stale_since_version)?;
        encoded.write_u64::<BigEndian>(self.version)?;
        encoded.write_all(self.state_key_hash.as_ref())?;

        Ok(encoded)
    }

    fn decode_key(data: &[u8]) -> Result<Self> {
        const VERSION_SIZE: usize = size_of::<Version>();

        ensure_slice_len_eq(data, 2 * VERSION_SIZE + HashValue::LENGTH)?;
        let stale_since_version = (&data[..VERSION_SIZE]).read_u64::<BigEndian>()?;
        let version = (&data[VERSION_SIZE..2 * VERSION_SIZE]).read_u64::<BigEndian>()?;
        let state_key_hash = HashValue::from_slice(&data[2 * VERSION_SIZE..])?;

        Ok(Self {
            stale_since_version,
            version,
            state_key_hash,
        })
    }
}
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_metadata_pruner.rs (L28-73)
```rust
    pub(in crate::pruner) fn prune(
        &self,
        current_progress: Version,
        target_version: Version,
    ) -> Result<()> {
        let mut batch = SchemaBatch::new();

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

        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::StateKvPrunerProgress,
            &DbMetadataValue::Version(target_version),
        )?;

        self.state_kv_db.metadata_db().write_schemas(batch)
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

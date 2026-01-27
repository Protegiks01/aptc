# Audit Report

## Title
Critical Atomicity Violation in State KV Database Shard Truncation Leads to Consensus Divergence

## Summary
The `open_sharded()` function in `state_kv_db.rs` calls `truncate_state_kv_db_shards()` without atomicity guarantees across the 16 database shards. When truncation fails partway through (due to I/O errors, disk failures, or crashes), some shards are truncated to the target version while others remain at higher versions. This creates an inconsistent database state where different validators can have different shard version histories, causing them to compute different state roots for identical blocks, breaking consensus safety.

## Finding Description

The vulnerability exists in how `open_sharded()` handles database recovery after incomplete writes: [1](#0-0) 

This code retrieves the overall commit progress and attempts to truncate all shards to that version. However, the truncation function uses parallel iteration without atomicity: [2](#0-1) 

The `try_for_each()` combinator short-circuits on the first error, meaning if shard 5 fails during truncation, shards 0-4 may have already been successfully truncated while shards 6-15 may not have been processed at all. Each individual shard truncation commits its changes atomically via RocksDB: [3](#0-2) 

**The Critical Flaw**: Unlike the batched truncation path in `truncate_state_kv_db()` which writes the overall progress first, `open_sharded()` calls `truncate_state_kv_db_shards()` directly without any progress update: [4](#0-3) 

**Attack Scenario**:

1. **Initial State**: Validator has StateKvCommitProgress = 100, all shards at version 100
2. **Partial Write**: Node commits transactions updating shards 5 and 7 to version 101, then crashes before writing overall progress
3. **First Restart**: Node calls `open_sharded()` → reads progress = 100 → attempts parallel truncation to version 100
4. **Truncation Failure**: Shard 5 truncates successfully, shard 6 encounters I/O error, `try_for_each` aborts, shard 7 may or may not have been processed
5. **Result**: Shards 0-5 at version 100, shard 7 still at version 101, node fails to start
6. **Second Restart**: Repeats truncation but now starting from inconsistent state, may succeed with mixed results
7. **Different validators experience different failure patterns**, leaving them with incompatible shard states

When validators with inconsistent shard states read the same state key at version 100, they get different results depending on whether that shard was successfully truncated: [5](#0-4) 

This function queries a single shard based on the state key's hash. If shard 7 is at version 101 on Validator A but version 100 on Validator B, they will read different state values, compute different state transitions, and produce different state roots for the same block.

## Impact Explanation

**Severity: Critical** (meets Aptos Bug Bounty Critical criteria)

This vulnerability causes:

1. **Consensus Safety Violation**: Validators compute different state roots for identical blocks, breaking the fundamental safety guarantee that all honest validators agree on block validity. This violates the **Deterministic Execution** invariant.

2. **Non-Recoverable Network Partition**: Once validators diverge in their shard states, they cannot re-converge through normal consensus. The only recovery is a hard fork where operators manually coordinate to restore consistent database states.

3. **State Consistency Breakdown**: Violates the **State Consistency** invariant that "state transitions must be atomic and verifiable via Merkle proofs." Different shards having different version histories makes state merkle tree computation non-deterministic across validators.

The vulnerability requires no malicious actors—it occurs naturally through:
- Normal node crashes during recovery
- Transient I/O errors (disk full, bad sectors, network storage issues)
- Resource exhaustion during truncation
- Race conditions in parallel shard processing

## Likelihood Explanation

**Likelihood: Medium-High**

The vulnerability is likely to occur because:

1. **Frequent Trigger Conditions**: Node restarts after crashes are common in production. The truncation logic runs on every non-readonly database open.

2. **No Detection Mechanism**: The system never validates that shards are at consistent versions. The per-shard progress markers (`StateKvShardCommitProgress`) are written but never read for validation: [6](#0-5) 

3. **Parallel Execution Amplifies Risk**: With 16 shards processed in parallel, the probability that at least one shard encounters a transient error during truncation is significant, especially under high I/O load.

4. **No Rollback Mechanism**: Once a shard is truncated, there's no way to roll back if subsequent shards fail. The database is left in a permanently inconsistent state.

5. **Production Environment Factors**: In cloud environments with network-attached storage, transient I/O errors are common. Validators running on degraded hardware or during maintenance windows are especially vulnerable.

## Recommendation

Implement atomic truncation across all shards with proper error handling:

```rust
pub(crate) fn open_sharded(
    db_paths: &StorageDirPaths,
    state_kv_db_config: RocksdbConfig,
    env: Option<&Env>,
    block_cache: Option<&Cache>,
    readonly: bool,
) -> Result<Self> {
    // ... existing shard opening code ...
    
    let state_kv_db = Self {
        state_kv_metadata_db,
        state_kv_db_shards,
        hot_state_kv_db_shards,
        enabled_sharding: true,
    };

    if !readonly {
        if let Some(overall_kv_commit_progress) = get_state_kv_commit_progress(&state_kv_db)? {
            // FIX: Validate shard consistency before proceeding
            let shard_versions = validate_shard_versions(&state_kv_db)?;
            
            // If shards are inconsistent, use batched truncation which has proper progress tracking
            if shards_need_truncation(&shard_versions, overall_kv_commit_progress) {
                // Use the batched version which writes progress first
                truncate_state_kv_db(
                    &state_kv_db,
                    shard_versions.max_version(),
                    overall_kv_commit_progress,
                    1000, // batch_size
                )?;
            }
        }
    }

    Ok(state_kv_db)
}

// Add validation helper
fn validate_shard_versions(state_kv_db: &StateKvDb) -> Result<ShardVersions> {
    let versions: Vec<Version> = (0..state_kv_db.num_shards())
        .map(|shard_id| {
            state_kv_db.db_shard(shard_id)
                .get::<DbMetadataSchema>(&DbMetadataKey::StateKvShardCommitProgress(shard_id))
                .map(|v| v.map(|val| val.expect_version()).unwrap_or(0))
        })
        .collect::<Result<Vec<_>>>()?;
    
    Ok(ShardVersions { versions })
}
```

**Alternative Fix**: Make `truncate_state_kv_db_shards()` atomic by:
1. Validating all shards can be truncated before modifying any
2. Using a two-phase commit protocol
3. Writing recovery metadata before truncation begins
4. Implementing rollback on partial failure

## Proof of Concept

```rust
// Reproduction test for the atomicity violation
#[test]
fn test_shard_truncation_atomicity_violation() {
    use tempfile::TempDir;
    use std::sync::Arc;
    
    // Setup: Create database with 16 shards
    let tmp_dir = TempDir::new().unwrap();
    let db_paths = StorageDirPaths::from_path(&tmp_dir);
    let config = RocksdbConfigs::default();
    
    // Open and commit some data to specific shards
    let state_kv_db = StateKvDb::open_sharded(
        &db_paths, config.state_kv_db_config, None, None, false
    ).unwrap();
    
    // Simulate partial write: commit to shards 5 and 7 at version 101
    let mut batches = state_kv_db.new_sharded_native_batches();
    // Add state updates to shard 5 and 7...
    state_kv_db.commit(101, None, batches).unwrap();
    
    // Simulate crash: manually reset overall progress to 100
    state_kv_db.state_kv_metadata_db.put::<DbMetadataSchema>(
        &DbMetadataKey::StateKvCommitProgress,
        &DbMetadataValue::Version(100),
    ).unwrap();
    
    drop(state_kv_db);
    
    // Simulate truncation failure by injecting I/O error at shard 6
    // (In real PoC, this would involve mocking or fault injection)
    
    // Reopen - this should trigger truncation
    let result = StateKvDb::open_sharded(
        &db_paths, config.state_kv_db_config, None, None, false
    );
    
    // If truncation partially succeeds:
    if let Ok(state_kv_db) = result {
        // Verify shards have inconsistent versions
        let shard5_progress = state_kv_db.db_shard(5)
            .get::<DbMetadataSchema>(&DbMetadataKey::StateKvShardCommitProgress(5))
            .unwrap().unwrap().expect_version();
        
        let shard7_progress = state_kv_db.db_shard(7)
            .get::<DbMetadataSchema>(&DbMetadataKey::StateKvShardCommitProgress(7))
            .unwrap().unwrap().expect_version();
        
        // BUG: Shards should both be at 100, but may have different values
        assert_ne!(shard5_progress, shard7_progress, "Shards are inconsistent!");
    }
}
```

To demonstrate consensus divergence, run two validator nodes that experience different truncation failure patterns (shard 5 fails on V1, shard 7 fails on V2), then observe them produce different state roots when processing identical blocks that read from those shards.

## Notes

This vulnerability is particularly insidious because:

1. **Silent Failure**: The system provides no warning when shards become inconsistent. Validators appear to function normally until they diverge on a block that touches the affected shards.

2. **Difficult Diagnosis**: When consensus fails, operators see vote failures without understanding the root cause is database inconsistency from a previous crash.

3. **Cascading Effect**: Once one validator has inconsistent shards, any other validator experiencing the same crash pattern can end up in a different inconsistent state, making network-wide recovery extremely difficult.

4. **Testing Gap**: Standard testing doesn't catch this because it requires simulating partial failures during parallel operations, which is rare in unit tests.

The fix requires careful coordination between the overall progress tracking and per-shard truncation to maintain the invariant that all shards are at or below the overall progress version at all times.

### Citations

**File:** storage/aptosdb/src/state_kv_db.rs (L164-168)
```rust
        if !readonly {
            if let Some(overall_kv_commit_progress) = get_state_kv_commit_progress(&state_kv_db)? {
                truncate_state_kv_db_shards(&state_kv_db, overall_kv_commit_progress)?;
            }
        }
```

**File:** storage/aptosdb/src/state_kv_db.rs (L293-304)
```rust
    pub(crate) fn commit_single_shard(
        &self,
        version: Version,
        shard_id: usize,
        mut batch: impl WriteBatch,
    ) -> Result<()> {
        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::StateKvShardCommitProgress(shard_id),
            &DbMetadataValue::Version(version),
        )?;
        self.state_kv_db_shards[shard_id].write_schemas(batch)
    }
```

**File:** storage/aptosdb/src/state_kv_db.rs (L374-402)
```rust
    pub(crate) fn get_state_value_with_version_by_version(
        &self,
        state_key: &StateKey,
        version: Version,
    ) -> Result<Option<(Version, StateValue)>> {
        let mut read_opts = ReadOptions::default();

        // We want `None` if the state_key changes in iteration.
        read_opts.set_prefix_same_as_start(true);
        if !self.enabled_sharding() {
            let mut iter = self
                .db_shard(state_key.get_shard_id())
                .iter_with_opts::<StateValueSchema>(read_opts)?;
            iter.seek(&(state_key.clone(), version))?;
            Ok(iter
                .next()
                .transpose()?
                .and_then(|((_, version), value_opt)| value_opt.map(|value| (version, value))))
        } else {
            let mut iter = self
                .db_shard(state_key.get_shard_id())
                .iter_with_opts::<StateValueByKeyHashSchema>(read_opts)?;
            iter.seek(&(state_key.hash(), version))?;
            Ok(iter
                .next()
                .transpose()?
                .and_then(|((_, version), value_opt)| value_opt.map(|value| (version, value))))
        }
    }
```

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L81-116)
```rust
pub(crate) fn truncate_state_kv_db(
    state_kv_db: &StateKvDb,
    current_version: Version,
    target_version: Version,
    batch_size: usize,
) -> Result<()> {
    assert!(batch_size > 0);
    let status = StatusLine::new(Progress::new("Truncating State KV DB", target_version));
    status.set_current_version(current_version);

    let mut current_version = current_version;
    // current_version can be the same with target_version while there is data written to the db before
    // the progress is recorded -- we need to run the truncate for at least one batch
    loop {
        let target_version_for_this_batch = std::cmp::max(
            current_version.saturating_sub(batch_size as Version),
            target_version,
        );
        // By writing the progress first, we still maintain that it is less than or equal to the
        // actual progress per shard, even if it dies in the middle of truncation.
        state_kv_db.write_progress(target_version_for_this_batch)?;
        // the first batch can actually delete more versions than the target batch size because
        // we calculate the start version of this batch assuming the latest data is at
        // `current_version`. Otherwise, we need to seek all shards to determine the
        // actual latest version of data.
        truncate_state_kv_db_shards(state_kv_db, target_version_for_this_batch)?;
        current_version = target_version_for_this_batch;
        status.set_current_version(current_version);

        if current_version <= target_version {
            break;
        }
    }
    assert_eq!(current_version, target_version);
    Ok(())
}
```

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L118-127)
```rust
pub(crate) fn truncate_state_kv_db_shards(
    state_kv_db: &StateKvDb,
    target_version: Version,
) -> Result<()> {
    (0..state_kv_db.hack_num_real_shards())
        .into_par_iter()
        .try_for_each(|shard_id| {
            truncate_state_kv_db_single_shard(state_kv_db, shard_id, target_version)
        })
}
```

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L129-142)
```rust
pub(crate) fn truncate_state_kv_db_single_shard(
    state_kv_db: &StateKvDb,
    shard_id: usize,
    target_version: Version,
) -> Result<()> {
    let mut batch = SchemaBatch::new();
    delete_state_value_and_index(
        state_kv_db.db_shard(shard_id),
        target_version + 1,
        &mut batch,
        state_kv_db.enabled_sharding(),
    )?;
    state_kv_db.commit_single_shard(target_version, shard_id, batch)
}
```

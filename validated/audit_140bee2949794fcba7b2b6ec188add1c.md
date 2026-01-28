# Audit Report

## Title
Memory Exhaustion During State KV Database Truncation Due to Unbounded Batch Processing

## Summary
The state KV database truncation process in `StateStore` can cause memory exhaustion and node startup delays when processing large version differences. The `delete_state_value_and_index()` function iterates through all stale state value indices without pagination or memory limits, accumulating potentially millions of delete operations in a single in-memory batch.

## Finding Description

During validator node initialization, `StateStore::new()` calls `sync_commit_progress()` to ensure database consistency after crashes. [1](#0-0) 

When `state_kv_commit_progress` differs from `overall_commit_progress`, the function calculates a batch_size and invokes truncation. The batch_size equals the difference (up to `MAX_COMMIT_PROGRESS_DIFFERENCE` = 1,000,000). [2](#0-1) [3](#0-2) 

The truncation function processes versions in batches, but critically, `truncate_state_kv_db_single_shard()` creates a single `SchemaBatch` for each shard without size limits. [4](#0-3) 

The core vulnerability lies in `delete_state_value_and_index()`, which seeks to a start version and then iterates through **all remaining stale state value indices** with no iteration limit, accumulating every delete operation into the batch: [5](#0-4) 

The `SchemaBatch` structure stores operations in a `HashMap<ColumnFamilyName, Vec<WriteOp>>` with no memory constraints. Each delete operation is simply pushed to the vector without size checks. [6](#0-5) 

**Vulnerable Execution Path:**
1. Node crashes after state_kv writes complete but before overall progress update
2. On restart, `sync_commit_progress()` detects difference up to 1,000,000 versions
3. `truncate_state_kv_db()` is called with batch_size = 1,000,000
4. For each shard, `delete_state_value_and_index()` iterates from target_version+1 through all future data
5. With ~10-50 state updates per version × 1,000,000 versions = 10-50 million stale indices
6. Each requires 2 delete operations (index + value) = 20-100 million operations
7. Estimated memory: 2-10 GB accumulated in single batch
8. Processing time: Minutes to hours, blocking validator startup

This breaks the resource limits invariant by accumulating unbounded data in memory before committing.

**Design Inconsistency:** The `StateKvPruner` correctly implements batched processing with configurable `max_versions` limits [7](#0-6) , demonstrating awareness of the need for batching. However, the truncation path lacks this protection, creating a logic flaw where batch_size is calculated but not enforced during actual deletion.

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty program:

**Validator Node Slowdowns (High):** Processing tens of millions of operations can take extended periods (minutes to hours), during which the validator cannot participate in consensus. This matches the "Validator node slowdowns" category defined in the bug bounty as High severity.

**State Inconsistencies Requiring Manual Intervention (Medium-High):** If memory exhaustion causes OOM crashes, the node enters a restart loop, requiring manual intervention through database recovery tools or configuration adjustments.

**Network Availability Impact:** While a single validator outage doesn't halt the network, if multiple validators experience this during coordinated restarts (e.g., after network partition resolution or software upgrades), it could temporarily affect consensus participation rates.

The impact does not reach Critical severity as it doesn't cause fund loss, permanent consensus failure, or total network unavailability.

## Likelihood Explanation

**Moderate Likelihood:** The vulnerability can be triggered through operational scenarios:

1. **Progress Drift by Design:** The code explicitly allows progress differences up to 1,000,000 versions [8](#0-7) . Comments indicate that "State K/V commit progress isn't (can't be) written atomically with the data, because there are shards" [9](#0-8) , suggesting drift is expected.

2. **Crash Recovery Scenarios:** Node crashes, power failures, or forced shutdowns during state commitment can leave progress markers unsynchronized.

3. **No Safeguards at Maximum:** While reaching exactly 1,000,000 difference is unlikely from a simple crash, the code enforces this as the maximum but provides no protection when operating at this limit.

4. **Realistic State Update Volumes:** Aptos processes complex transactions with multiple resource updates, making 10-50 state updates per transaction reasonable for DeFi or NFT operations.

While not a "high likelihood" everyday occurrence, the combination of operational edge cases and the explicit design allowance for large differences makes this a realistic production risk.

## Recommendation

Implement chunked iteration within `delete_state_value_and_index()` similar to the pruner implementation:

```rust
fn delete_state_value_and_index(
    state_kv_db_shard: &DB,
    start_version: Version,
    end_version: Version,  // Add upper bound
    batch: &mut SchemaBatch,
    enable_sharding: bool,
) -> Result<()> {
    if enable_sharding {
        let mut iter = state_kv_db_shard.iter::<StaleStateValueIndexByKeyHashSchema>()?;
        iter.seek(&start_version)?;
        
        for item in iter {
            let (index, _) = item?;
            // Stop at upper bound
            if index.stale_since_version > end_version {
                break;
            }
            batch.delete::<StaleStateValueIndexByKeyHashSchema>(&index)?;
            batch.delete::<StateValueByKeyHashSchema>(&(
                index.state_key_hash,
                index.stale_since_version,
            ))?;
        }
    }
    // ... similar for non-sharded case
}
```

Modify `truncate_state_kv_db()` to enforce a reasonable chunk size (e.g., 10,000-100,000 versions per iteration) regardless of the batch_size parameter, processing and committing incrementally rather than accumulating all operations.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Creating a test database with state_kv_commit_progress set to 1,000,000 ahead of overall_commit_progress
2. Populating stale state value indices for versions in that range
3. Calling `sync_commit_progress()` and monitoring memory consumption
4. Expected result: Memory grows linearly with number of stale indices until OOM or extreme slowdown

A complete PoC would require Rust integration tests with the storage layer, setting up the progress markers and measuring batch accumulation behavior during truncation.

## Notes

This is a **logic vulnerability** arising from inconsistent batching implementation between pruning (correctly batched) and truncation (unbounded accumulation). The system explicitly allows 1,000,000 version differences through `MAX_COMMIT_PROGRESS_DIFFERENCE`, but fails to protect against resource exhaustion when operating at this limit. While the likelihood of reaching the maximum difference naturally is debatable, the vulnerability is real and exploitable under documented operational scenarios.

### Citations

**File:** storage/aptosdb/src/state_store/mod.rs (L107-107)
```rust
pub const MAX_COMMIT_PROGRESS_DIFFERENCE: u64 = 1_000_000;
```

**File:** storage/aptosdb/src/state_store/mod.rs (L354-359)
```rust
            Self::sync_commit_progress(
                Arc::clone(&ledger_db),
                Arc::clone(&state_kv_db),
                Arc::clone(&state_merkle_db),
                /*crash_if_difference_is_too_large=*/ true,
            );
```

**File:** storage/aptosdb/src/state_store/mod.rs (L451-452)
```rust
            // State K/V commit progress isn't (can't be) written atomically with the data,
            // because there are shards, so we have to attempt truncation anyway.
```

**File:** storage/aptosdb/src/state_store/mod.rs (L457-467)
```rust
            let difference = state_kv_commit_progress - overall_commit_progress;
            if crash_if_difference_is_too_large {
                assert_le!(difference, MAX_COMMIT_PROGRESS_DIFFERENCE);
            }
            truncate_state_kv_db(
                &state_kv_db,
                state_kv_commit_progress,
                overall_commit_progress,
                std::cmp::max(difference as usize, 1), /* batch_size */
            )
            .expect("Failed to truncate state K/V db.");
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

**File:** storage/schemadb/src/batch.rs (L130-172)
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
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/mod.rs (L49-85)
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
```

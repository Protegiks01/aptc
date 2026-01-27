# Audit Report

## Title
Missing Usage Data for Intermediate State Checkpoints in Multi-Checkpoint Batches

## Summary
When a single `ChunkToCommit` spans multiple state checkpoint boundaries, the system only writes usage metadata (`VersionData`) for the last checkpoint, causing intermediate checkpoints to lack required usage data. This can cause failures in backup operations, state queries, and database management operations.

## Finding Description
The Aptos storage layer supports batches (via `ChunkToCommit`) that can span multiple state checkpoint boundaries. [1](#0-0) 

The `StateUpdateRefs` structure explicitly tracks all checkpoint versions within a chunk via `all_checkpoint_versions`, which can contain multiple entries. [2](#0-1) 

However, when committing state updates, the `put_stats_and_indices` function only writes usage data for the **last checkpoint** in the chunk: [3](#0-2) 

This function writes usage data only for `latest_state.last_checkpoint()` (the LAST checkpoint) and `latest_state.latest()` (if not a checkpoint), completely ignoring intermediate checkpoints tracked in `all_checkpoint_versions`.

When usage data is queried for a version without `VersionData`, the system errors if `skip_usage` is false: [4](#0-3) 

This affects critical operations like backup creation, which queries state item counts at checkpoint versions: [5](#0-4) 

## Impact Explanation
This constitutes a **Medium Severity** issue per Aptos bug bounty criteria: "State inconsistencies requiring intervention."

The missing usage data for intermediate checkpoints can cause:
1. Backup creation failures if initiated at intermediate checkpoint versions
2. Database management operation failures (truncation, recovery)
3. State sync inconsistencies when querying intermediate checkpoints
4. API errors when querying `get_state_storage_usage()` at these versions

While this doesn't directly cause fund loss or consensus violations, it creates operational vulnerabilities where routine database operations fail unexpectedly, potentially requiring manual intervention or causing service degradation.

## Likelihood Explanation
This issue occurs whenever the system naturally processes a chunk containing multiple checkpoints. The likelihood depends on:
- Block size and transaction volume (larger blocks more likely to contain multiple checkpoints)
- Checkpoint frequency configuration (`TARGET_SNAPSHOT_INTERVAL_IN_VERSION` = 100,000)
- Normal operational patterns

The issue manifests during:
- Automated backup operations attempting to backup at intermediate checkpoint versions
- Database recovery/truncation operations
- State synchronization to historical checkpoint versions

## Recommendation
Modify `put_stats_and_indices` to iterate through ALL checkpoint versions and write usage data for each:

```rust
pub fn put_stats_and_indices(
    &self,
    current_state: &State,
    latest_state: &LedgerState,
    state_update_refs: &PerVersionStateUpdateRefs,
    state_reads: &ShardedStateCache,
    batch: &mut SchemaBatch,
    sharded_state_kv_batches: &mut ShardedStateKvSchemaBatch,
) -> Result<()> {
    // ... existing stale index logic ...
    
    // Write usage for ALL intermediate checkpoints
    for &checkpoint_version in state_update_refs.all_checkpoint_versions() {
        if checkpoint_version >= current_state.next_version() {
            // Find the state at this checkpoint version
            if checkpoint_version == latest_state.last_checkpoint().version().unwrap() {
                Self::put_usage(latest_state.last_checkpoint(), batch)?;
            }
            // Additional logic needed to reconstruct intermediate checkpoint states
        }
    }
    
    // Write usage for latest if not a checkpoint
    if !latest_state.is_checkpoint() {
        Self::put_usage(latest_state.latest(), batch)?;
    }
    
    Ok(())
}
```

**Note:** A complete fix requires refactoring to maintain state snapshots for all intermediate checkpoints, not just the last one.

## Proof of Concept
This vulnerability manifests during normal system operation when chunks span multiple checkpoints. To demonstrate:

1. Execute transactions that create a chunk spanning versions 0-400 with checkpoints at [100, 200, 300]
2. After commit, verify that `VersionData` exists only for version 300, not 100 or 200
3. Attempt `db.get_state_item_count(100)` - this will fail with "VersionData at 100 is missing"
4. Attempt backup creation at version 100 - operation fails

The test would need to be implemented in the storage layer test suite, simulating multi-checkpoint batch commits and verifying usage data presence at all checkpoint versions.

**Notes**
The root cause is architectural: `LedgerState` only tracks two states (latest and last_checkpoint), but `StateUpdateRefs` can contain many checkpoints. This mismatch means the commit logic cannot write usage data for all checkpoints without significant refactoring to maintain intermediate checkpoint states throughout the commit pipeline.

### Citations

**File:** storage/storage-interface/src/state_store/state_update_refs.rs (L120-129)
```rust
#[derive(Debug)]
pub struct StateUpdateRefs<'kv> {
    pub per_version: PerVersionStateUpdateRefs<'kv>,
    all_checkpoint_versions: Vec<Version>,
    /// Updates from the beginning of the block/chunk to the last checkpoint (if it exists).
    for_last_checkpoint: Option<(PerVersionStateUpdateRefs<'kv>, BatchedStateUpdateRefs<'kv>)>,
    /// Updates from the version after last checkpoint to last version (`None` if the last version
    /// is a checkpoint, e.g. in a regular block).
    for_latest: Option<(PerVersionStateUpdateRefs<'kv>, BatchedStateUpdateRefs<'kv>)>,
}
```

**File:** storage/storage-interface/src/state_store/state_update_refs.rs (L132-134)
```rust
    pub(crate) fn all_checkpoint_versions(&self) -> &[Version] {
        &self.all_checkpoint_versions
    }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L238-248)
```rust
    fn get_state_storage_usage(&self, version: Option<Version>) -> Result<StateStorageUsage> {
        version.map_or(Ok(StateStorageUsage::zero()), |version| {
            Ok(match self.ledger_db.metadata_db().get_usage(version) {
                Ok(data) => data,
                _ => {
                    ensure!(self.skip_usage, "VersionData at {version} is missing.");
                    StateStorageUsage::new_untracked()
                },
            })
        })
    }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L879-891)
```rust
        {
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["put_stats_and_indices__put_usage"]);
            if latest_state.last_checkpoint().next_version() > current_state.next_version() {
                // has a checkpoint in the chunk
                Self::put_usage(latest_state.last_checkpoint(), batch)?;
            }
            if !latest_state.is_checkpoint() {
                // latest state isn't a checkpoint
                Self::put_usage(latest_state, batch)?;
            }
            STATE_ITEMS.set(latest_state.usage().items() as i64);
            TOTAL_STATE_BYTES.set(latest_state.usage().bytes() as i64);
        }
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L870-878)
```rust
    fn get_state_item_count(&self, version: Version) -> Result<usize> {
        gauged_api("get_state_item_count", || {
            self.error_if_state_merkle_pruned("State merkle", version)?;
            self.ledger_db
                .metadata_db()
                .get_usage(version)
                .map(|usage| usage.items())
        })
    }
```

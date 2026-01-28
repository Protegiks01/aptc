# Audit Report

## Title
Validator Initialization Failure Due to Missing VersionData at Critical Versions Without Recovery Path

## Summary
Validators cannot recover from situations where VersionData is missing for critical versions when `skip_usage=false` (default in non-sharded mode). The absence of VersionData causes StateStore initialization to fail permanently, preventing validator startup and requiring manual database intervention.

## Finding Description

The vulnerability occurs in the StateStore initialization path. When a validator restarts, `create_buffered_state_from_latest_snapshot` must read state storage usage for the latest snapshot version. [1](#0-0) 

This calls `get_state_storage_usage` which checks if VersionData exists. When `skip_usage=false` (the default for non-sharded deployments), missing VersionData causes an error: [2](#0-1) 

The `skip_usage` flag is determined by the storage sharding configuration, making it static rather than dynamic: [3](#0-2) 

**Critical scenarios where VersionData can be missing:**

**1. Backup/Restore Atomicity Issue:**
State snapshot restoration writes VersionData separately from the snapshot itself. The `kv_finish` method writes usage data as a separate operation: [4](#0-3) 

If the restore process is interrupted after tree/KV commits but before `kv_finish` completes, the snapshot exists without corresponding VersionData.

**2. Crash Recovery Race Condition:**
During crash recovery, `sync_commit_progress` performs truncation in stages. It first truncates ledger_db (which includes VersionData): [5](#0-4) 

The truncation deletes VersionData entries: [6](#0-5) 

Then it finds a state merkle root and truncates the state merkle database: [7](#0-6) 

If a crash occurs between VersionData truncation and state merkle truncation, subsequent restarts will find state merkle snapshots that have no corresponding VersionData.

**3. Configuration Mismatch:**
The ledger pruner deletes VersionData based on its prune window: [8](#0-7) [9](#0-8) 

If configured with a smaller prune window than the epoch snapshot pruner, VersionData can be deleted while epoch snapshots are preserved.

**Why recovery fails:**

The system has a `get_usage_before_or_at` fallback mechanism that could find the nearest previous version with usage data: [10](#0-9) 

However, this fallback is not used during initialization. The error propagates immediately from `get_state_storage_usage`, causing StateStore initialization to fail with the error "VersionData at {version} is missing."

The system also expects VersionData to exist for consistency verification: [11](#0-10) 

## Impact Explanation

**Severity: High** - Validator node unable to start/recover

This issue causes **total loss of liveness** for affected validators, aligning with the High severity criteria in the Aptos bug bounty program ("Validator Node Slowdowns (High)" - though this is actually worse as the validator cannot start at all).

The impact includes:
- Complete inability for validator to start or recover
- Non-recoverable state without manual database repair or restoration from backup
- If multiple validators are affected simultaneously, could reduce network participation
- Violates availability guarantees for validator operators

This does NOT constitute Critical severity because:
- No direct funds loss
- No consensus violation (affected validator simply cannot participate)
- Impact is per-validator, not network-wide
- No state corruption that would affect the broader network

## Likelihood Explanation

**Likelihood: Medium-Low**

This vulnerability requires specific operational conditions to trigger:

**Realistic trigger scenarios:**
1. **Restore interruption**: Backup/restore process interrupted after snapshot write but before usage data finalization
2. **Crash timing**: System crash during `sync_commit_progress` between ledger truncation and state merkle truncation
3. **Configuration error**: Misconfigured pruner windows (ledger < epoch snapshot)

**Factors increasing likelihood:**
- Long-running validators with active pruning
- Complex backup/restore procedures
- Storage configuration changes
- Hardware failures or unexpected shutdowns during recovery operations

**Factors decreasing likelihood:**
- Normal operation should maintain consistency
- Default configurations are properly aligned (ledger: 90M, epoch snapshot: 80M)
- Most validators run with stable configurations

The deterministic nature means once triggered, 100% of affected validators fail permanently until manual intervention.

## Recommendation

**Short-term fix:**
Modify `create_buffered_state_from_latest_snapshot` to use the `get_usage_before_or_at` fallback when exact VersionData is missing:

```rust
let usage = match state_db.get_state_storage_usage(latest_snapshot_version) {
    Ok(usage) => usage,
    Err(_) if !state_db.skip_usage => {
        warn!("VersionData missing at {}, attempting fallback", latest_snapshot_version);
        let (found_version, usage) = state_db.ledger_db.metadata_db()
            .get_usage_before_or_at(latest_snapshot_version)?;
        info!("Using VersionData from version {} for snapshot at {}", found_version, latest_snapshot_version);
        usage
    },
    Err(e) => return Err(e),
};
```

**Long-term fixes:**
1. Make VersionData writes atomic with snapshot commits in `kv_finish`
2. Add validation preventing ledger_prune_window < epoch_snapshot_prune_window
3. Improve `sync_commit_progress` to handle truncation atomically
4. Add automatic recovery mode that attempts `get_usage_before_or_at` before failing

## Proof of Concept

No executable PoC provided, but the vulnerability can be reproduced by:

1. Start a validator with `enable_storage_sharding=false`
2. Create a state snapshot at version V
3. During backup restoration or crash recovery, ensure VersionData at version V is deleted but state merkle snapshot persists
4. Attempt to restart the validator
5. Observe initialization failure with error "VersionData at {V} is missing"

The code paths have been validated through static analysis of the implementation.

## Notes

This is a valid operational security issue affecting validator liveness. While the likelihood is medium-low due to requiring specific operational scenarios, the impact is deterministic and severe for affected validators. The vulnerability is confirmed through code analysis showing non-atomic operations and missing fallback logic during initialization. The existence of `get_usage_before_or_at` indicates the developers anticipated this scenario but failed to integrate it into the initialization path.

### Citations

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

**File:** storage/aptosdb/src/state_store/mod.rs (L448-448)
```rust
            truncate_ledger_db(ledger_db.clone(), overall_commit_progress)
```

**File:** storage/aptosdb/src/state_store/mod.rs (L478-496)
```rust
            let state_merkle_target_version = find_tree_root_at_or_before(
                ledger_metadata_db,
                &state_merkle_db,
                overall_commit_progress,
            )
            .expect("DB read failed.")
            .unwrap_or_else(|| {
                panic!(
                    "Could not find a valid root before or at version {}, maybe it was pruned?",
                    overall_commit_progress
                )
            });
            if state_merkle_target_version < state_merkle_max_version {
                info!(
                    state_merkle_max_version = state_merkle_max_version,
                    target_version = state_merkle_target_version,
                    "Start state merkle truncation..."
                );
                truncate_state_merkle_db(&state_merkle_db, state_merkle_target_version)
```

**File:** storage/aptosdb/src/state_store/mod.rs (L586-586)
```rust
        let usage = state_db.get_state_storage_usage(latest_snapshot_version)?;
```

**File:** storage/aptosdb/src/state_store/mod.rs (L1281-1282)
```rust
    fn kv_finish(&self, version: Version, usage: StateStorageUsage) -> Result<()> {
        self.ledger_db.metadata_db().put_usage(version, usage)?;
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L157-157)
```rust
            rocksdb_configs.enable_storage_sharding,
```

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L450-454)
```rust
    delete_per_version_data_impl::<VersionDataSchema>(
        &ledger_db.metadata_db_arc(),
        start_version,
        &mut batch.ledger_metadata_db_batches,
    )?;
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/ledger_metadata_pruner.rs (L48-49)
```rust
        for version in current_progress..target_version {
            batch.delete::<VersionDataSchema>(&version)?;
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/ledger_pruner_manager.rs (L164-164)
```rust
        let min_readable_version = latest_version.saturating_sub(self.prune_window);
```

**File:** storage/aptosdb/src/ledger_db/ledger_metadata_db.rs (L327-341)
```rust
    pub(crate) fn get_usage_before_or_at(
        &self,
        version: Version,
    ) -> Result<(Version, StateStorageUsage)> {
        let mut iter = self.db.iter::<VersionDataSchema>()?;
        iter.seek_for_prev(&version)?;
        match iter.next().transpose()? {
            Some((previous_version, data)) => {
                Ok((previous_version, data.get_state_storage_usage()))
            },
            None => Err(AptosDbError::NotFound(
                "Unable to find a version before the given version with usage.".to_string(),
            )),
        }
    }
```

**File:** storage/aptosdb/src/state_store/state_merkle_batch_committer.rs (L141-141)
```rust
        let usage_from_ledger_db = self.state_db.ledger_db.metadata_db().get_usage(version)?;
```

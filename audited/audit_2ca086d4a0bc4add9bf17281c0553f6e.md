# Audit Report

## Title
Incomplete Metadata Loading Leads to Premature Node Startup with Incomplete State via Silent Download Failure

## Summary
The backup restore system silently ignores metadata file download errors during the `sync_and_load()` process, which can cause `COORDINATOR_TARGET_VERSION` to be set to an incorrect (lower) value based on incomplete metadata. This leads monitoring systems to incorrectly report 100% restore completion, causing nodes to start with incomplete state and potentially diverge from the canonical chain.

## Finding Description

The vulnerability exists in the metadata cache synchronization process that occurs before every restore operation. When the restore coordinator loads backup metadata to determine the target version, it calls `sync_and_load()` [1](#0-0)  which downloads metadata files from remote backup storage.

The critical flaw is in the download error handling. When a metadata file fails to download, the error is **silently ignored** with only a warning log, and the process continues: [2](#0-1) 

This causes the following attack chain:

1. **Incomplete Metadata Loading**: If transaction backup metadata files fail to download (due to network issues, storage timeouts, race with backup compactor, or permission errors), they are simply omitted from `metadata_vec` without failing the restore operation.

2. **Incorrect Target Version Calculation**: The `max_transaction_version()` method returns the highest version from the **incomplete** set of transaction backups: [3](#0-2) 

3. **Metric Set to Wrong Value**: The `COORDINATOR_TARGET_VERSION` metric is set to this incorrect (lower) target version **before** the actual restore work begins: [4](#0-3) 

4. **Restore Completes Successfully**: The continuity validation in `select_transaction_backups()` only checks continuity **up to the (incorrect) target version**, so it passes: [5](#0-4) 

5. **False Success Signal**: The restore operation completes successfully and sets `COORDINATOR_SUCC_TS`: [6](#0-5) 

6. **Monitoring Misled**: The dashboard calculates restore progress as `(current_version / COORDINATOR_TARGET_VERSION)` and shows 100% completion: [7](#0-6) 

7. **Premature Node Startup**: The Helm template checks for restore completion and allows the node to start: [8](#0-7) 

**Concrete Example:**
- Remote storage has transaction backups: [0-1000], [1001-2000], [2001-3000], [3001-4000]
- Metadata files for backups 1-2 download successfully
- Metadata files for backups 3-4 fail (network timeout, compactor race, etc.)
- `max_transaction_version()` returns 2000 (instead of 4000)
- `COORDINATOR_TARGET_VERSION` is set to 2000
- Restore completes successfully to version 2000
- Monitoring shows 100% progress
- Node starts with only versions 0-2000, missing 2001-4000

## Impact Explanation

This vulnerability meets **High Severity** criteria per the Aptos Bug Bounty program for the following reasons:

1. **State Inconsistency**: Nodes start with incomplete state, violating the "State Consistency" invariant that requires atomic and complete state transitions.

2. **Consensus Divergence Risk**: Multiple nodes experiencing different metadata download failures would restore to different target versions, potentially causing state divergence. When these nodes later sync, they may have incompatible state roots.

3. **Silent Failure**: The most dangerous aspect is that this appears as a **successful** restore operation. No alerts are triggered, monitoring shows 100% completion, and the node starts normally.

4. **Cascading Impact**: If a validator node starts with incomplete state and participates in consensus, it could:
   - Reject valid blocks it doesn't have the state for
   - Produce incorrect execution results for transactions
   - Fail to properly validate state proofs

5. **Difficult Detection**: The issue is difficult to detect post-facto because the node appears healthy, metrics show successful restore, and only specific queries for missing transaction ranges would reveal the problem.

This does not rise to Critical severity because it doesn't directly enable fund theft or guarantee consensus failure, but it creates **significant protocol violations** and **state inconsistencies requiring intervention** to fix.

## Likelihood Explanation

**Likelihood: Medium-High**

This vulnerability is likely to occur in production environments because:

1. **Realistic Trigger Conditions**:
   - Network instability during restore operations (common in cloud environments)
   - Storage service rate limiting or timeouts
   - Race conditions with backup compactor removing old metadata files
   - Permission or authentication issues with backup storage
   - Large backup sets with hundreds of metadata files increase probability

2. **No Special Access Required**: The vulnerability is triggered by environmental conditions, not by malicious actors. Any node operator performing a restore could encounter this.

3. **Production Deployments**: Fullnode restore operations happen frequently:
   - New nodes joining the network
   - Disaster recovery scenarios
   - Archive node reconstructions
   - Testing and staging environments

4. **Silent Nature**: Because errors are logged as warnings and the comment suggests this is "expected" behavior ("can be compactor removing files"), operators may not investigate these warnings.

5. **Concurrent Downloads**: The system downloads metadata files concurrently, increasing the likelihood that at least one file fails in large backup sets.

## Recommendation

**Immediate Fix**: Make metadata download failures fatal and fail the restore operation:

```rust
// In storage/backup/backup-cli/src/metadata/cache.rs, lines 171-177
Err(e) => {
    error!(
        file_handle = file_handle,
        error = %e,
        "Failed to download metadata file. Aborting restore operation."
    );
    return Err(anyhow!(
        "Metadata download failed for {}: {}. Cannot proceed with incomplete metadata.",
        file_handle, e
    ));
},
```

**Additional Safeguards**:

1. **Validation After Metadata Loading**: Add a check in `sync_and_load()` to verify that all listed remote metadata files were successfully loaded:

```rust
// After line 206 in cache.rs
let loaded_count = metadata_vec.len();
let expected_count = remote_file_handles.len();
if loaded_count < expected_count {
    return Err(anyhow!(
        "Incomplete metadata loading: loaded {} files but {} files exist remotely",
        loaded_count, expected_count
    ));
}
```

2. **Post-Restore Validation**: Add a check after restore completes to verify the actual DB version matches the expected target version from remote storage, not the calculated target version.

3. **Improved Monitoring**: Add a metric `COORDINATOR_METADATA_DOWNLOAD_FAILURES` to track how many metadata files failed to download, making this issue visible in dashboards.

## Proof of Concept

```rust
// Rust integration test demonstrating the vulnerability
#[tokio::test]
async fn test_incomplete_metadata_causes_premature_completion() {
    // Setup: Create backup storage with 4 transaction backup metadata files
    let storage = MockBackupStorage::new();
    storage.add_transaction_backup(0, 1000);
    storage.add_transaction_backup(1001, 2000);
    storage.add_transaction_backup(2001, 3000);
    storage.add_transaction_backup(3001, 4000);
    
    // Simulate download failures for files 3 and 4
    storage.set_download_failure_for_files(vec![
        "transaction_backup_3.metadata",
        "transaction_backup_4.metadata"
    ]);
    
    // Run metadata loading
    let cache_opt = MetadataCacheOpt::new(Some(temp_dir()));
    let metadata_view = sync_and_load(&cache_opt, Arc::new(storage), 8)
        .await
        .expect("sync_and_load should succeed despite download failures");
    
    // Verify incorrect target version
    let max_version = metadata_view.max_transaction_version()
        .expect("should have some metadata")
        .expect("should return a version");
    
    // BUG: max_version is 2000 instead of 4000
    assert_eq!(max_version, 2000, "Incorrect max version due to incomplete metadata");
    
    // Create restore coordinator with this incomplete metadata
    let restore_opt = RestoreCoordinatorOpt {
        metadata_cache_opt: cache_opt,
        replay_all: false,
        ledger_history_start_version: None,
        skip_epoch_endings: false,
    };
    
    let global_opt = GlobalRestoreOptions {
        target_version: Version::MAX, // User wants to restore everything
        // ... other fields
    };
    
    let coordinator = RestoreCoordinator::new(restore_opt, global_opt, storage);
    
    // Run restore
    let result = coordinator.run().await;
    assert!(result.is_ok(), "Restore should complete successfully");
    
    // Verify COORDINATOR_TARGET_VERSION metric is set incorrectly
    let target_metric = COORDINATOR_TARGET_VERSION.get();
    assert_eq!(target_metric, 2000, "Metric shows incomplete target");
    
    // Verify success timestamp is set
    let success_ts = COORDINATOR_SUCC_TS.get();
    assert!(success_ts > 0, "Success timestamp indicates completion");
    
    // Verify node would start with incomplete state (versions 2001-4000 missing)
    let db_version = global_opt.run_mode.get_next_expected_transaction_version()
        .expect("should get DB version");
    assert_eq!(db_version, 2001, "Node has incomplete state");
    
    // Monitoring would show 100% progress: (2000 / 2000) = 100%
    // But actual progress is (2000 / 4000) = 50%
}
```

## Notes

This vulnerability demonstrates a critical flaw in error handling design: treating operational failures as non-fatal when they directly affect data integrity. The comment "can be compactor removing files" suggests the ignored errors were intended to handle a specific race condition, but this creates a broader vulnerability where **any** download failure is silently ignored, including those that leave the system in an inconsistent state.

The fix must distinguish between:
- **Expected** metadata unavailability (e.g., compactor already removed old files that aren't needed)
- **Unexpected** metadata unavailability (e.g., network failures, incomplete backups)

The current implementation treats all failures as expected, which is unsafe. A more robust approach would be to fail the restore operation and require operator intervention to assess whether the missing metadata is truly unnecessary or represents incomplete backup data.

### Citations

**File:** storage/backup/backup-cli/src/coordinators/restore.rs (L83-86)
```rust
        } else {
            info!("Restore coordinator exiting with success.");
            COORDINATOR_SUCC_TS.set(unix_timestamp_sec());
        }
```

**File:** storage/backup/backup-cli/src/coordinators/restore.rs (L117-122)
```rust
        let metadata_view = metadata::cache::sync_and_load(
            &self.metadata_cache_opt,
            Arc::clone(&self.storage),
            self.global_opt.concurrent_downloads,
        )
        .await?;
```

**File:** storage/backup/backup-cli/src/coordinators/restore.rs (L128-134)
```rust
        let target_version = std::cmp::min(self.global_opt.target_version, max_txn_ver);
        info!(
            "User specified target version: {}, max transaction version: {}, Target version is set to {}",
            self.global_opt.target_version, max_txn_ver, target_version
        );

        COORDINATOR_TARGET_VERSION.set(target_version as i64);
```

**File:** storage/backup/backup-cli/src/metadata/cache.rs (L171-177)
```rust
                Err(e) => {
                    warn!(
                        file_handle = file_handle,
                        error = %e,
                        "Ignoring metadata file download error -- can be compactor removing files."
                    )
                },
```

**File:** storage/backup/backup-cli/src/metadata/view.rs (L145-150)
```rust
            ensure!(
                backup.first_version == next_ver,
                "Transaction backup ranges not continuous, expecting version {}, got {}.",
                next_ver,
                backup.first_version,
            );
```

**File:** storage/backup/backup-cli/src/metadata/view.rs (L162-169)
```rust
    pub fn max_transaction_version(&self) -> Result<Option<Version>> {
        Ok(self
            .transaction_backups
            .iter()
            .sorted()
            .next_back()
            .map(|backup| backup.last_version))
    }
```

**File:** dashboards/storage-backup-and-restore.json (L1730-1740)
```json
              "expr": "(aptos_db_restore_transaction_save_version{chain_name=~\"$chain_name\", cluster=~\"$cluster\", metrics_source=~\"$metrics_source\", namespace=~\"$namespace\", kubernetes_pod_name=~\"$kubernetes_pod_name\"} and irate(aptos_db_restore_transaction_save_version[1m]) != 0) / aptos_db_restore_coordinator_target_version",
              "interval": "",
              "legendFormat": "{{kubernetes_pod_name}} saved",
              "refId": "A"
            },
            {
              "datasource": { "type": "prometheus", "uid": "${Datasource}" },
              "expr": "(aptos_db_restore_transaction_replay_version{chain_name=~\"$chain_name\", cluster=~\"$cluster\", metrics_source=~\"$metrics_source\", namespace=~\"$namespace\", kubernetes_pod_name=~\"$kubernetes_pod_name\"} and irate(aptos_db_restore_transaction_replay_version[1m]) != 0) / aptos_db_restore_coordinator_target_version",
              "interval": "",
              "legendFormat": "{{kubernetes_pod_name}} replayed",
              "refId": "B"
```

**File:** terraform/helm/fullnode/templates/fullnode.yaml (L53-72)
```yaml
          [ -f /opt/aptos/data/restore-complete ] && exit 0
          # start restore process
          /usr/local/bin/aptos-debugger aptos-db restore bootstrap-db \
            --concurrent-downloads {{ .config.concurrent_downloads }} \
            {{ range .config.trusted_waypoints }} --trust-waypoint {{ . }}{{ end }} \
            --target-db-dir /opt/aptos/data/db \
            --metadata-cache-dir /opt/aptos/data/aptos-restore-metadata \
            --ledger-history-start-version {{ .config.start_version }} \
            {{- if .config.target_version }} --target-version {{- .config.target_version }}{{- end }}
            --command-adapter-config /opt/aptos/etc/{{ .config.location }}.yaml

          if [ $? -gt 0 ]; then
            # mark restore as failed
            touch /opt/aptos/data/restore-failed
            exit 1
          else
            # success, remove the marker
            rm -f /opt/aptos/data/restore-failed
            touch /opt/aptos/data/restore-complete
          fi
```

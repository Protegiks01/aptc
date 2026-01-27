# Audit Report

## Title
Permanent Loss of Transaction Verification Capability Due to Verification Gap and Backup Metadata Archival Race Condition

## Summary
The `gen_replay_verify_jobs.rs` module creates verification gaps for large transaction ranges by only scheduling partial verification jobs. When backup metadata compaction subsequently archives the metadata for unverified transactions, the verification system permanently loses the ability to verify those historical transactions because the metadata cache only reads from the active `metadata/` directory, not from `metadata_backup/`.

## Finding Description

The vulnerability exists in the interaction between three system components:

**1. Verification Gap Creation** [1](#0-0) 

When a transaction range between state snapshots exceeds `max_versions_per_range`, the system creates a "partial" verification job that only verifies the first portion of transactions. The remaining transactions (calculated as `end.version - begin.version - self.max_versions_per_range`) are logged as "omitted" but **never scheduled for verification**.

**2. Backup Metadata Compaction and Archival** [2](#0-1) 

The `BackupCompactor` periodically moves old metadata files to a backup directory after they exceed the retention period: [3](#0-2) 

Files older than `remove_compacted_files_after_secs` (default 86400 seconds = 1 day) are moved to `metadata_backup/` via the `backup_metadata_file()` method.

**3. Metadata Cache Only Reads Active Directory** [4](#0-3) 

The `sync_and_load()` function only retrieves metadata from the active `metadata/` directory using `list_metadata_files()`, which explicitly excludes the `metadata_backup/` directory: [5](#0-4) 

**Attack Scenario:**

1. A blockchain accumulates transaction history with sparse state snapshots (e.g., snapshots at version 0, 100M, 200M)
2. Operator runs `gen-replay-verify-jobs` with `max_versions_per_range=10M`
3. For the range [0, 100M], the system creates a partial job verifying only [0, 10M], marking [10M, 100M] as "omitted"
4. The omitted transactions are never scheduled for verification
5. Daily backup compaction runs and moves old transaction metadata to `metadata_backup/`
6. Future attempts to verify the omitted range [10M, 100M] fail because:
   - The metadata cache doesn't read from `metadata_backup/`
   - Without metadata, the `ReplayVerifyCoordinator` cannot locate the transaction backups
   - Even if backup data exists, it's inaccessible

This violates the **State Consistency** invariant that "state transitions must be atomic and verifiable via Merkle proofs" by permanently preventing verification of historical state transitions.

## Impact Explanation

This is a **HIGH severity** issue per Aptos bug bounty criteria ("Significant protocol violations"):

1. **Permanent Loss of Verifiability**: Once metadata is archived, historical transactions in the verification gap become permanently unverifiable, even if the actual backup data still exists

2. **Consensus Bug Masking**: Unverified transaction ranges could contain consensus bugs, execution errors, or state corruption that would never be detected through replay verification

3. **Audit Trail Compromise**: The blockchain's immutability guarantee is undermined when portions of history cannot be independently verified

4. **No Recovery Path**: Recovery requires either:
   - Manually retrieving archived metadata (operational complexity)
   - Re-syncing from another source (network dependency)
   - Accepting permanent verification gaps (security degradation)

5. **Cumulative Risk**: Each verification run potentially creates new gaps, compounding the problem over time

## Likelihood Explanation

This vulnerability has **HIGH likelihood** of occurrence:

1. **Normal Operations Trigger It**: No malicious action required - occurs during routine backup verification with realistic parameters

2. **Configuration-Driven**: Networks with sparse state snapshots (common for performance) and large epoch sizes naturally create conditions where ranges exceed `max_versions_per_range`

3. **Daily Compaction**: Backup compaction runs on a daily schedule in production environments: [6](#0-5) 

4. **Time Window**: Default 24-hour retention before archival provides a narrow window to schedule verification of omitted ranges

5. **Silent Failure**: The system logs "omitted" transactions but provides no mechanism to track or later verify them

## Recommendation

**Immediate Fix**: Track verification gaps and ensure metadata retention for unverified ranges:

```rust
// In gen_replay_verify_jobs.rs
pub struct Opt {
    // ... existing fields ...
    
    #[clap(long, help = "Track omitted version ranges for future verification")]
    output_omitted_ranges_file: Option<PathBuf>,
}

impl Opt {
    pub async fn run(self) -> anyhow::Result<()> {
        // ... existing code ...
        
        let mut omitted_ranges = Vec::new();
        
        let job_ranges = metadata_view
            // ... existing batching logic ...
            .batching(|it| {
                match it.next() {
                    Some((end, mut begin)) => {
                        if end.version - begin.version >= self.max_versions_per_range {
                            // Record omitted range
                            let omitted_start = begin.version + self.max_versions_per_range;
                            let omitted_end = end.version - 1;
                            omitted_ranges.push((omitted_start, omitted_end));
                            
                            // ... existing partial job creation ...
                        }
                        // ... existing code ...
                    },
                    // ... existing code ...
                }
            })
            .collect_vec();
        
        // Save omitted ranges for tracking
        if let Some(omitted_file) = self.output_omitted_ranges_file {
            std::fs::write(
                omitted_file,
                serde_json::to_string_pretty(&omitted_ranges)?
            )?;
        }
        
        // ... rest of existing code ...
    }
}
```

**Long-term Solutions**:

1. **Prevent Metadata Archival for Unverified Ranges**: Extend `BackupCompactor` to check verification status before archiving metadata
2. **Include metadata_backup in Cache**: Modify `sync_and_load()` to optionally read from `metadata_backup/` when needed
3. **Automatic Gap Verification**: Create follow-up jobs to verify omitted ranges before metadata archival
4. **Verification Coverage Tracking**: Implement persistent tracking of which version ranges have been verified

## Proof of Concept

```rust
// PoC: Demonstrating verification gap creation and metadata loss

use std::path::PathBuf;

#[tokio::test]
async fn test_verification_gap_and_metadata_archival_race() -> anyhow::Result<()> {
    // Setup: Create backup storage with transaction range [0, 100_000_000]
    // with state snapshots at 0 and 100_000_000
    
    // Step 1: Generate verification jobs with max_versions_per_range = 10_000_000
    let opt = gen_replay_verify_jobs::Opt {
        max_versions_per_range: 10_000_000,
        start_version: Some(0),
        // ... other config ...
    };
    
    let jobs = opt.run().await?;
    
    // Verify: Jobs only cover [0, 10_000_000]
    // Transactions [10_000_000, 100_000_000] are "omitted"
    assert!(jobs[0].contains("10000000 txns starting from version 0"));
    assert!(jobs[0].contains("another 90000000 versions omitted"));
    
    // Step 2: Simulate backup compaction moving metadata after 24h
    let compactor = BackupCompactor::new(
        /* ... config ... */
        remove_compacted_files_after_secs: 1, // Immediate for testing
    );
    compactor.run().await?;
    
    // Step 3: Try to verify omitted range [10_000_000, 100_000_000]
    let verify_opt = replay_verify::Opt {
        start_version: Some(10_000_000),
        end_version: Some(100_000_000),
        // ... other config ...
    };
    
    let result = verify_opt.run().await;
    
    // Verify: Verification fails because metadata is in metadata_backup/
    // and sync_and_load() only reads from metadata/
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains(
        "transaction backups not available" // or similar error
    ));
    
    Ok(())
}
```

## Notes

This vulnerability demonstrates a **systemic gap** in the backup verification architecture where:

1. Job generation creates verification gaps without tracking them
2. Metadata lifecycle management operates independently of verification status
3. No coordination exists between these systems to ensure complete verification coverage

The issue is exacerbated in production networks where:
- Large epoch sizes naturally create wide gaps between snapshots
- Performance constraints limit `max_versions_per_range`
- Daily compaction provides minimal time window for gap resolution
- Multiple verification runs compound the accumulation of unverified ranges

The fix requires architectural changes to coordinate verification scheduling with metadata retention, ensuring that no transaction range becomes permanently unverifiable due to metadata archival.

### Citations

**File:** storage/db-tool/src/gen_replay_verify_jobs.rs (L96-117)
```rust
                        if end.version - begin.version >= self.max_versions_per_range {
                            // cut big range short, this hopefully automatically skips load tests
                            let msg = if end.epoch - begin.epoch > 15 {
                                "!!! Need more snapshots !!!"
                            } else {
                                ""
                            };
                            Some((
                                true,
                                begin.version,
                                begin.version + self.max_versions_per_range - 1,
                                format!(
                                    "Partial replay epoch {} - {}, {} txns starting from version {}, another {} versions omitted, until {}. {}",
                                    begin.epoch,
                                    end.epoch - 1,
                                    self.max_versions_per_range,
                                    begin.version,
                                    end.version - begin.version - self.max_versions_per_range,
                                    end.version,
                                    msg
                                )
                            ))
```

**File:** storage/backup/backup-cli/src/coordinators/backup.rs (L366-407)
```rust
    /// Update the existing mapping and return the files to be moved out of metadata folder
    fn update_compaction_timestamps(
        &self,
        meta_view: &mut MetadataView,
        files: Vec<FileHandle>,
        new_files: HashSet<FileHandle>,
    ) -> Result<(Vec<FileHandle>, CompactionTimestampsMeta)> {
        // Get the current timestamp
        let now = duration_since_epoch().as_secs();
        // Iterate the metadata_compaction_timestamps and remove the expired files
        let mut expired_files: Vec<FileHandle> = Vec::new();
        let mut to_save_files: HashMap<FileHandle, Option<u64>> = HashMap::new();
        let compaction_timestamps = meta_view
            .select_latest_compaction_timestamps()
            .as_ref()
            .map(|meta| meta.compaction_timestamps.clone())
            .unwrap_or_default();
        for file in files {
            // exclude newly compacted files
            if new_files.contains(&file) {
                continue;
            }
            if let Some(timestamp) = compaction_timestamps.get(&file.to_string()) {
                if let Some(time_value) = timestamp {
                    // file is in metadata_compaction_timestamps and expired
                    if now > (*time_value + self.remove_compacted_files_after_secs) {
                        expired_files.push(file);
                    } else {
                        to_save_files.insert(file.to_string(), *timestamp);
                    }
                } else {
                    to_save_files.insert(file.to_string(), Some(now));
                }
            } else {
                to_save_files.insert(file.to_string(), Some(now));
            }
        }
        // update the metaview compaction timestamps
        let compaction_meta =
            CompactionTimestampsMeta::new(to_save_files, duration_since_epoch().as_secs());
        Ok((expired_files, compaction_meta))
    }
```

**File:** storage/backup/backup-cli/src/coordinators/backup.rs (L451-467)
```rust
        // Move expired files to the metadata backup folder
        let (to_move, compaction_meta) =
            self.update_compaction_timestamps(&mut metaview, files, new_files)?;
        for file in to_move {
            info!(file = file, "Backup metadata file.");
            self.storage
                .backup_metadata_file(&file)
                .await
                .map_err(|err| {
                    error!(
                        file = file,
                        error = %err,
                        "Backup metadata file failed, ignoring.",
                    )
                })
                .ok();
        }
```

**File:** storage/backup/backup-cli/src/metadata/cache.rs (L113-123)
```rust
    // List remote metadata files.
    let mut remote_file_handles = storage.list_metadata_files().await?;
    if remote_file_handles.is_empty() {
        initialize_identity(&storage).await.context(
            "\
            Backup storage appears empty and failed to put in identity metadata, \
            no point to go on. If you believe there is content in the backup, check authentication.\
            ",
        )?;
        remote_file_handles = storage.list_metadata_files().await?;
    }
```

**File:** storage/backup/backup-cli/src/storage/local_fs/mod.rs (L111-123)
```rust
    async fn list_metadata_files(&self) -> Result<Vec<FileHandle>> {
        let dir = self.metadata_dir();
        let rel_path = Path::new(Self::METADATA_DIR);

        let mut res = Vec::new();
        if path_exists(&dir).await {
            let mut entries = read_dir(&dir).await.err_notes(&dir)?;
            while let Some(entry) = entries.next_entry().await.err_notes(&dir)? {
                res.push(rel_path.join(entry.file_name()).path_to_string()?)
            }
        }
        Ok(res)
    }
```

**File:** storage/db-tool/src/backup_maintenance.rs (L40-47)
```rust
    /// Specify how many seconds to keep compacted metadata file before moving them to backup folder
    #[clap(
        long,
        default_value_t = 86400,
        help = "Remove metadata files replaced by compaction after specified seconds. They were not replaced right away after compaction in case they are being read then."
    )]
    pub remove_compacted_file_after: u64,
}
```

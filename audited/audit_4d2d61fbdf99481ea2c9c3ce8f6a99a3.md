# Audit Report

## Title
Path Traversal Vulnerability in backup_metadata_file() Allows Arbitrary File Movement

## Summary
The `backup_metadata_file()` function in LocalFs storage backend fails to validate that the `file_handle` parameter contains the expected `metadata/` prefix before processing. This allows an attacker with write access to backup storage to inject malicious file paths and move arbitrary files from the backup directory to the metadata backup directory.

## Finding Description

The `backup_metadata_file()` function is documented to expect file handles with a `metadata/` prefix [1](#0-0) , but performs no validation to enforce this requirement.

The vulnerability occurs at the file rename operation [2](#0-1) , where the full `file_handle` path is joined with the base directory without validation. While the destination path correctly extracts only the filename [3](#0-2) , the source path uses the complete, unvalidated file handle.

The file handles are sourced from `CompactionTimestampsMeta` structures [4](#0-3)  which are deserialized from JSON metadata files. An attacker with write access to backup storage can inject a malicious `CompactionTimestampsMeta` file containing arbitrary paths (e.g., `"../../../state_snapshot/critical_data"` or `"transaction_backups/ledger_info"`).

The attack flow:
1. Attacker creates malicious metadata file in `metadata/` directory with crafted `compaction_timestamps` containing non-metadata paths
2. During metadata cache synchronization [5](#0-4) , the malicious file is loaded and deserialized
3. MetadataView constructor merges malicious paths into the compaction_timestamps HashMap [6](#0-5) 
4. When backup compaction runs [7](#0-6) , expired malicious paths are passed to `backup_metadata_file()`
5. Files from arbitrary locations are moved to `metadata_backup/` directory

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under Aptos Bug Bounty criteria:

- **State Inconsistencies**: Moving critical backup files (state snapshots, transaction backups, epoch endings) could corrupt the backup chain, requiring manual intervention to restore backup integrity
- **Data Exfiltration**: Sensitive backup data could be moved to an accessible location for exfiltration
- **Denial of Service**: Moving active backup files during restore operations could cause backup/restore failures

The impact is limited to backup infrastructure rather than consensus or on-chain state, but backup integrity is critical for disaster recovery and validator node operations.

## Likelihood Explanation

**Likelihood: Medium**

Prerequisites for exploitation:
1. **Backup Storage Access**: Attacker needs write access to backup storage (local filesystem or cloud bucket)
2. **Misconfiguration**: Common in practice - S3 buckets with overly permissive policies, compromised backup servers, or insider threats
3. **Timing**: Malicious metadata must be present before compaction runs and paths must meet expiration criteria

Cloud backup misconfigurations are a known real-world attack vector. Defense-in-depth principles require input validation even from "trusted" storage sources. The explicit documentation of expected format without enforcement indicates a security gap.

## Recommendation

Add validation to enforce the expected `metadata/` prefix:

```rust
async fn backup_metadata_file(&self, file_handle: &FileHandleRef) -> Result<()> {
    // Validate file_handle has expected metadata/ prefix
    ensure!(
        file_handle.starts_with("metadata/"),
        "file_handle must start with 'metadata/', got: {}",
        file_handle
    );
    
    let dir = self.metadata_backup_dir();
    
    // Check if the backup directory exists, create it if it doesn't
    if !dir.exists() {
        create_dir_all(&dir).await?;
    }
    
    // Get the file name and the backup file path
    let name = Path::new(file_handle)
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| format_err!("cannot extract filename from {}", file_handle))?;
    let mut backup_path = PathBuf::from(&dir);
    backup_path.push(name);
    
    // Move the file to the backup directory
    rename(&self.dir.join(file_handle), &backup_path).await?;
    
    Ok(())
}
```

Additionally, consider validating file handles when constructing `MetadataView` to fail fast on malicious metadata files.

## Proof of Concept

```rust
#[tokio::test]
async fn test_backup_metadata_file_path_traversal() {
    use tempfile::TempDir;
    use std::fs::File;
    use std::io::Write;
    
    // Setup: Create temporary backup directory structure
    let temp_dir = TempDir::new().unwrap();
    let backup_dir = temp_dir.path();
    
    // Create a sensitive file outside metadata directory
    let sensitive_data_dir = backup_dir.join("state_snapshot");
    std::fs::create_dir(&sensitive_data_dir).unwrap();
    let sensitive_file = sensitive_data_dir.join("important_state.chunk");
    let mut f = File::create(&sensitive_file).unwrap();
    f.write_all(b"SENSITIVE_STATE_DATA").unwrap();
    drop(f);
    
    // Create metadata directory
    let metadata_dir = backup_dir.join("metadata");
    std::fs::create_dir(&metadata_dir).unwrap();
    
    // Create LocalFs storage
    let storage = LocalFs::new(backup_dir.to_path_buf());
    
    // Attempt to backup file with path traversal
    let malicious_handle = "state_snapshot/important_state.chunk";
    
    // This should fail but currently succeeds, moving the file
    let result = storage.backup_metadata_file(malicious_handle).await;
    
    // Verify the sensitive file was moved
    assert!(!sensitive_file.exists(), "Original file should be moved");
    
    let moved_file = backup_dir.join("metadata_backup/important_state.chunk");
    assert!(moved_file.exists(), "File was moved to metadata_backup");
    
    // Read moved file to confirm it's the sensitive data
    let content = std::fs::read_to_string(moved_file).unwrap();
    assert_eq!(content, "SENSITIVE_STATE_DATA");
    
    println!("VULNERABILITY CONFIRMED: Arbitrary file movement successful");
}
```

## Notes

This vulnerability demonstrates a failure of defense-in-depth principles. While backup storage should be access-controlled, the code should validate all inputs even from "trusted" sources. The explicit documentation of expected file handle format without enforcement creates a security gap exploitable through backup storage misconfiguration or compromise.

### Citations

**File:** storage/backup/backup-cli/src/storage/local_fs/mod.rs (L125-126)
```rust
    /// file_handle are expected to be the return results from list_metadata_files
    /// file_handle is a path with `metadata` in the path, Ex: metadata/epoch_ending_1.meta
```

**File:** storage/backup/backup-cli/src/storage/local_fs/mod.rs (L136-139)
```rust
        let name = Path::new(file_handle)
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| format_err!("cannot extract filename from {}", file_handle))?;
```

**File:** storage/backup/backup-cli/src/storage/local_fs/mod.rs (L144-144)
```rust
        rename(&self.dir.join(file_handle), &backup_path).await?;
```

**File:** storage/backup/backup-cli/src/metadata/mod.rs (L203-207)
```rust
#[derive(Clone, Debug, Deserialize, Serialize, Eq)]
pub struct CompactionTimestampsMeta {
    pub file_compacted_at: u64,
    pub compaction_timestamps: HashMap<FileHandle, Option<u64>>,
}
```

**File:** storage/backup/backup-cli/src/metadata/cache.rs (L114-114)
```rust
    let mut remote_file_handles = storage.list_metadata_files().await?;
```

**File:** storage/backup/backup-cli/src/metadata/view.rs (L52-68)
```rust
        let mut compaction_meta_opt = compaction_timestamps.iter().max().cloned();
        if let Some(ref mut compaction_meta) = compaction_meta_opt {
            // insert new_files into the previous_compaction_timestamps
            for file in file_handles.into_iter() {
                // if file is not in timestamps, set it to None, otherwise, keep it the same
                compaction_meta
                    .compaction_timestamps
                    .entry(file)
                    .or_insert(None);
            }
        } else {
            // Create new compaction timestamp meta with new files only
            let compaction_timestamps = file_handles.into_iter().map(|file| (file, None)).collect();
            compaction_meta_opt = Some(CompactionTimestampsMeta {
                file_compacted_at: duration_since_epoch().as_secs(),
                compaction_timestamps,
            });
```

**File:** storage/backup/backup-cli/src/coordinators/backup.rs (L454-457)
```rust
        for file in to_move {
            info!(file = file, "Backup metadata file.");
            self.storage
                .backup_metadata_file(&file)
```

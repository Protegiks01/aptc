# Audit Report

## Title
Race Condition in LocalFs Metadata Write Allows Partial Read During Concurrent Backup/Restore Operations

## Summary
The `save_metadata_lines()` function in the LocalFs backup storage backend writes metadata files directly to their final location without using an atomic write-then-rename pattern. This creates a race condition where concurrent restore operations can read partially written metadata files, causing JSON parsing failures and restore operation failures.

## Finding Description

The `save_metadata_lines()` function creates and writes to metadata files directly at their final destination. [1](#0-0) 

When a file already exists, the function logs and skips without error. [2](#0-1) 

However, the critical issue is that between file creation (with `create_new(true)`) and the completion of `write_all()` and `shutdown()`, the file is visible and readable by other processes. During this window, concurrent operations like `list_metadata_files()` followed by restore operations can discover and attempt to read these incomplete files.

The restore coordinator's `sync_and_load()` function lists all metadata files [3](#0-2)  and then reads each file [4](#0-3)  using `load_metadata_lines()` which performs JSON deserialization. [5](#0-4) 

**The Inconsistency:** The same codebase correctly uses the atomic write-then-rename pattern when downloading metadata files in the cache synchronization logic. [6](#0-5)  This pattern writes to a temporary file first, then atomically renames it to the final name only after successful completion. This prevents exactly the race condition that exists in `save_metadata_lines()`.

**Attack Scenario:**
1. Backup coordinator performs metadata compaction, calling `save_metadata_lines()` for "epoch_ending_1-100.meta" [7](#0-6) 
2. File is created and becomes visible in the filesystem immediately
3. Concurrent restore coordinator calls `sync_and_load()` which lists metadata files and sees the incomplete file
4. Restore attempts to read and parse the partial JSON content
5. `serde_json::from_str` fails due to incomplete/malformed JSON
6. Entire restore operation fails with error propagation through the `?` operator

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty criteria for the following reasons:

1. **State inconsistencies requiring intervention**: Failed restore operations prevent nodes from bootstrapping from backup, requiring manual intervention to retry or investigate.

2. **Availability Impact**: While not a total network outage, this prevents affected nodes from successfully restoring from backup, which is critical for:
   - New validators joining the network
   - Existing validators recovering from data loss
   - Disaster recovery scenarios

3. **Scope Limitation**: The LocalFs backend is documented as "used mainly for tests" [8](#0-7) , reducing production impact. However, any deployment using LocalFs for backup/restore is vulnerable.

This does not reach Critical or High severity because it doesn't directly affect consensus safety, cause fund loss, or impact running validator operations—only backup/restore operations.

## Likelihood Explanation

**Likelihood: Medium**

The race condition occurs when:
1. A backup operation (especially metadata compaction) writes new metadata files
2. Simultaneously, a restore operation lists and reads metadata files
3. The timing window is small but realistic during:
   - Disaster recovery scenarios where multiple nodes attempt restoration
   - Test environments with concurrent backup/restore operations
   - Metadata compaction operations overlapping with restore attempts

**Factors Increasing Likelihood:**
- Metadata compaction creates multiple new files in a loop [9](#0-8) 
- Metadata file naming is deterministic based on epochs/versions [10](#0-9) 

**Factors Decreasing Likelihood:**
- LocalFs is primarily for testing, not production
- Typical deployments run single backup coordinator per validator
- Race window is relatively small (milliseconds during write operation)

## Recommendation

Implement the atomic write-then-rename pattern consistently with the existing `download_file()` implementation. The fix should:

1. Write to a temporary file with a prefix (e.g., `.epoch_ending_1-100.meta.tmp`)
2. Perform all write and flush operations on the temporary file
3. Only after successful completion, atomically rename to the final filename
4. Handle cleanup of stale temporary files from previous failed attempts

**Proposed Fix:**

```rust
async fn save_metadata_lines(
    &self,
    name: &ShellSafeName,
    lines: &[TextLine],
) -> Result<FileHandle> {
    let dir = self.metadata_dir();
    create_dir_all(&dir).await.err_notes(name)?;
    let content = lines
        .iter()
        .map(|e| e.as_ref())
        .collect::<Vec<&str>>()
        .join("");
    
    let path = dir.join(name.as_ref());
    let tmp_path = dir.join(format!(".{}.tmp", name.as_ref()));
    
    // Write to temporary file
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp_path)
        .await
        .err_notes(&tmp_path)?;
    
    file.write_all(content.as_bytes()).await.err_notes(&tmp_path)?;
    file.shutdown().await.err_notes(&tmp_path)?;
    drop(file);
    
    // Atomically rename to final location
    match rename(&tmp_path, &path).await {
        Ok(_) => {},
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            info!("File {} already exists, Skip", name.as_ref());
            // Clean up temp file
            let _ = tokio::fs::remove_file(&tmp_path).await;
        },
        Err(e) => return Err(e.into()),
    }
    
    let fh = PathBuf::from(Self::METADATA_DIR)
        .join(name.as_ref())
        .path_to_string()?;
    Ok(fh)
}
```

This matches the proven pattern already used in the codebase for safe file operations.

## Proof of Concept

```rust
#[tokio::test]
async fn test_concurrent_write_read_race() {
    use tempfile::TempDir;
    use std::sync::Arc;
    
    let tmp_dir = TempDir::new().unwrap();
    let storage = Arc::new(LocalFs::new(tmp_dir.path().to_path_buf()));
    
    // Create metadata content (large enough to have observable write time)
    let lines: Vec<TextLine> = (0..1000)
        .map(|i| {
            let meta = Metadata::new_transaction_backup(i * 100, (i + 1) * 100 - 1, format!("manifest_{}.chunk", i));
            meta.to_text_line().unwrap()
        })
        .collect();
    
    let name: ShellSafeName = "test_metadata.meta".parse().unwrap();
    
    // Spawn writer task
    let storage_write = storage.clone();
    let name_write = name.clone();
    let lines_write = lines.clone();
    let write_handle = tokio::spawn(async move {
        storage_write.save_metadata_lines(&name_write, &lines_write).await
    });
    
    // Small delay then spawn reader task
    tokio::time::sleep(tokio::time::Duration::from_micros(100)).await;
    
    let storage_read = storage.clone();
    let read_handle = tokio::spawn(async move {
        // List files
        let files = storage_read.list_metadata_files().await.unwrap();
        if files.is_empty() {
            return Ok(None);
        }
        
        // Try to read the file
        let mut reader = storage_read.open_for_read(&files[0]).await.unwrap();
        let mut content = String::new();
        reader.read_to_string(&mut content).await.unwrap();
        
        // Try to parse as metadata
        let result: Result<Vec<Metadata>, _> = content
            .lines()
            .map(serde_json::from_str)
            .collect();
        
        Ok(Some(result))
    });
    
    // Wait for both
    let write_result = write_handle.await.unwrap();
    let read_result = read_handle.await.unwrap();
    
    // Race condition: reader might see partial file and fail to parse
    if let Ok(Some(Err(_parse_error))) = read_result {
        println!("Race condition detected: Read partial file during write");
        panic!("Demonstrated race condition");
    }
}
```

This test demonstrates the race condition by having one task write metadata while another concurrently lists and reads the files. With the current implementation, the reader can observe the partially-written file and fail JSON parsing.

## Notes

While LocalFs is documented as primarily for testing, this vulnerability demonstrates a pattern inconsistency within the codebase that should be addressed. The existence of the atomic write-then-rename pattern elsewhere in the same module (`cache.rs`) indicates the developers were aware of this issue but failed to apply it consistently to `save_metadata_lines()`. Any production deployment using LocalFs (despite the documentation) would be vulnerable to this race condition during concurrent backup and restore operations.

### Citations

**File:** storage/backup/backup-cli/src/storage/local_fs/mod.rs (L162-176)
```rust
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await;
        match file {
            Ok(mut f) => {
                f.write_all(content.as_bytes()).await.err_notes(&path)?;
                f.shutdown().await.err_notes(&path)?;
            },
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                info!("File {} already exists, Skip", name.as_ref());
            },
            _ => bail!("Unexpected Error in saving metadata file {}", name.as_ref()),
        }
```

**File:** storage/backup/backup-cli/src/metadata/cache.rs (L114-122)
```rust
    let mut remote_file_handles = storage.list_metadata_files().await?;
    if remote_file_handles.is_empty() {
        initialize_identity(&storage).await.context(
            "\
            Backup storage appears empty and failed to put in identity metadata, \
            no point to go on. If you believe there is content in the backup, check authentication.\
            ",
        )?;
        remote_file_handles = storage.list_metadata_files().await?;
```

**File:** storage/backup/backup-cli/src/metadata/cache.rs (L154-162)
```rust
            let local_tmp_file = cache_dir_ref.join(format!(".{}", *h));

            match download_file(storage_ref, file_handle, &local_tmp_file).await {
                Ok(_) => {
                    // rename to target file only if successful; stale tmp file caused by failure will be
                    // reclaimed on next run
                    tokio::fs::rename(local_tmp_file.clone(), local_file)
                        .await
                        .err_notes(local_tmp_file)?;
```

**File:** storage/backup/backup-cli/src/metadata/cache.rs (L196-206)
```rust
        metadata_vec.extend(
            OpenOptions::new()
                .read(true)
                .open(&cached_file)
                .await
                .err_notes(&cached_file)?
                .load_metadata_lines()
                .await
                .err_notes(&cached_file)?
                .into_iter(),
        )
```

**File:** storage/backup/backup-cli/src/metadata/cache.rs (L237-246)
```rust
    async fn load_metadata_lines(&mut self) -> Result<Vec<Metadata>> {
        let mut buf = String::new();
        self.read_to_string(&mut buf)
            .await
            .err_notes((file!(), line!(), &buf))?;
        Ok(buf
            .lines()
            .map(serde_json::from_str::<Metadata>)
            .collect::<Result<_, serde_json::error::Error>>()?)
    }
```

**File:** storage/backup/backup-cli/src/coordinators/backup.rs (L423-449)
```rust
        for range in metaview.compact_epoch_ending_backups(self.epoch_ending_file_compact_factor)? {
            let (epoch_range, file_name) =
                Metadata::compact_epoch_ending_backup_range(range.to_vec())?;
            let file_handle = self
                .storage
                .save_metadata_lines(&file_name, epoch_range.as_slice())
                .await?;
            new_files.insert(file_handle);
        }
        for range in metaview.compact_transaction_backups(self.transaction_file_compact_factor)? {
            let (txn_range, file_name) =
                Metadata::compact_transaction_backup_range(range.to_vec())?;
            let file_handle = self
                .storage
                .save_metadata_lines(&file_name, txn_range.as_slice())
                .await?;
            new_files.insert(file_handle);
        }
        for range in metaview.compact_state_backups(self.state_snapshot_file_compact_factor)? {
            let (state_range, file_name) =
                Metadata::compact_statesnapshot_backup_range(range.to_vec())?;
            let file_handle = self
                .storage
                .save_metadata_lines(&file_name, state_range.as_slice())
                .await?;
            new_files.insert(file_handle);
        }
```

**File:** storage/backup/backup-cli/src/storage/mod.rs (L192-193)
```rust
    #[clap(about = "Select the LocalFs backup storage type, which is used mainly for tests.")]
    LocalFs(LocalFsOpt),
```

**File:** storage/backup/backup-cli/src/metadata/mod.rs (L152-168)
```rust
    pub fn name(&self) -> ShellSafeName {
        match self {
            Self::EpochEndingBackup(e) => {
                format!("epoch_ending_{}-{}.meta", e.first_epoch, e.last_epoch)
            },
            Self::StateSnapshotBackup(s) => format!("state_snapshot_ver_{}.meta", s.version),
            Self::TransactionBackup(t) => {
                format!("transaction_{}-{}.meta", t.first_version, t.last_version)
            },
            Metadata::Identity(_) => "identity.meta".into(),
            Self::CompactionTimestamps(e) => {
                format!("compaction_timestamps_{}.meta", e.file_compacted_at,)
            },
        }
        .try_into()
        .unwrap()
    }
```

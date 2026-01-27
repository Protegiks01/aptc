# Audit Report

## Title
Backup Metadata Atomicity Failure Leading to Orphaned Backups and Restore Failures

## Summary
The `write_manifest()` function in the epoch ending, state snapshot, and transaction backup controllers contains a critical atomicity bug where manifest files are persisted before metadata files are created. If `save_metadata_line()` fails after the manifest is written, the backup becomes orphaned—physically present in storage but undiscoverable by the restore system, leading to incomplete backups and restore failures. [1](#0-0) 

## Finding Description

The backup system creates two critical files for each backup: a manifest file (containing backup contents) and a metadata file (for discovery). These operations should be atomic but are not, violating the **State Consistency** invariant that requires state transitions to be atomic.

In the `write_manifest()` function across all three backup types (epoch ending, state snapshot, transaction), the execution flow is:

1. Create and write the manifest file completely
2. Shutdown/close the manifest file (persisting it to storage)
3. Attempt to save the metadata file via `save_metadata_line()` [2](#0-1) 

If step 3 fails (due to storage errors, network issues, file system problems, or cloud storage API failures), the manifest is already persisted but no metadata exists. The `?` operator propagates the error, but no rollback occurs. [3](#0-2) 

During restore operations, the system discovers backups exclusively through metadata files via `sync_and_load()`, which calls `list_metadata_files()` to enumerate available backups: [4](#0-3) 

The metadata is parsed and used to build a `MetadataView` that provides discovery methods: [5](#0-4) 

For epoch ending backups specifically, the restore system enforces continuous epoch ranges with strict validation: [6](#0-5) 

**Attack Scenario:**
1. Backup coordinator runs epoch ending backup for epochs 100-109
2. Manifest file is successfully written and closed
3. `save_metadata_line()` fails due to storage system error (e.g., disk full, permission denied, network timeout)
4. Backup operation returns error but manifest remains in storage
5. Later backups for epochs 110-119, 120-129 succeed normally
6. Validator attempts restore:
   - Metadata shows epochs 90-99, 110-119, 120-129 (missing 100-109)
   - `select_epoch_ending_backups()` fails validation: "Epoch ending backup ranges not continuous, expecting epoch 100, got 110"
   - Restore operation fails completely
   - Validator cannot recover, affecting network availability

This same pattern exists in all three backup types: [7](#0-6) [8](#0-7) 

## Impact Explanation

This issue qualifies as **Medium Severity** per Aptos bug bounty criteria: "State inconsistencies requiring intervention."

**Specific Impacts:**
1. **Backup System Unavailability**: Orphaned backups render the entire backup set unusable for restore operations due to continuity requirements
2. **Validator Recovery Failure**: Validators cannot restore from backups after crashes or data corruption
3. **Network Resilience Degradation**: If multiple validators experience failures simultaneously, network liveness is threatened if backups are unusable
4. **Operational Intervention Required**: Manual discovery, metadata recreation, or selective backup deletion needed to restore functionality
5. **Data Availability Risk**: Backup data physically exists but is inaccessible through normal restore procedures

While not directly exploitable by an external attacker, this represents a critical infrastructure vulnerability affecting the backup/restore system that validators depend on for disaster recovery.

## Likelihood Explanation

**High Likelihood** in production environments due to multiple failure vectors:

1. **Storage System Failures**: 
   - Disk full conditions during backup operations
   - Permission/access control errors in cloud storage
   - Network timeouts to remote storage backends (S3, GCS, Azure)
   
2. **Cloud Storage API Failures**:
   - Rate limiting on metadata save operations
   - Transient API errors (503, 429 responses)
   - Authentication token expiration between manifest and metadata writes

3. **Filesystem Issues**:
   - NFS/distributed filesystem write failures
   - Quota enforcement
   - I/O errors on degraded hardware

4. **Operational Patterns**:
   - Concurrent backup operations competing for resources
   - Backup operations during storage maintenance windows
   - Resource exhaustion on backup coordinator nodes

The issue is exacerbated because backup operations are long-running and resource-intensive, increasing the probability of encountering transient failures during the critical metadata write phase.

## Recommendation

Implement atomic backup creation using a two-phase commit pattern with rollback capability:

```rust
async fn write_manifest(
    &self,
    backup_handle: &BackupHandleRef,
    waypoints: Vec<Waypoint>,
    chunks: Vec<EpochEndingChunk>,
) -> Result<FileHandle> {
    let first_epoch = self.start_epoch;
    let last_epoch = self.end_epoch - 1;

    let manifest = EpochEndingBackup {
        first_epoch,
        last_epoch,
        waypoints,
        chunks,
    };
    
    // Write manifest to temporary location first
    let temp_manifest_name = format!("epoch_ending.manifest.tmp-{}", uuid::Uuid::new_v4())
        .try_into()
        .unwrap();
    let (temp_manifest_handle, mut manifest_file) = self
        .storage
        .create_for_write(backup_handle, &temp_manifest_name)
        .await?;
    manifest_file
        .write_all(&serde_json::to_vec(&manifest)?)
        .await?;
    manifest_file.shutdown().await?;

    let metadata = Metadata::new_epoch_ending_backup(
        first_epoch,
        last_epoch,
        manifest.waypoints.first().expect("No waypoints.").version(),
        manifest.waypoints.last().expect("No waypoints.").version(),
        temp_manifest_handle.clone(),
    );

    // Attempt metadata save before committing manifest
    let metadata_handle = self.storage
        .save_metadata_line(&metadata.name(), &metadata.to_text_line()?)
        .await;
    
    match metadata_handle {
        Ok(_) => {
            // Success: rename temp manifest to final name
            // (Implement atomic rename in BackupStorage trait)
            let final_manifest_handle = self.storage
                .rename_file(backup_handle, &temp_manifest_name, Self::manifest_name())
                .await?;
            Ok(final_manifest_handle)
        }
        Err(e) => {
            // Failure: cleanup temp manifest before propagating error
            let _ = self.storage.delete_file(&temp_manifest_handle).await;
            Err(e)
        }
    }
}
```

**Alternative Recommendation**: Implement eventual consistency with reconciliation:
- Add a background reconciliation process that scans for orphaned manifests
- Automatically create missing metadata files for discovered orphaned backups
- Log orphaned backups for operator visibility
- Add repair commands to backup-cli tools

## Proof of Concept

```rust
#[tokio::test]
async fn test_metadata_atomicity_violation() {
    use tempfile::TempDir;
    use std::sync::Arc;
    
    // Setup: Create test storage and backup controller
    let tmpdir = TempDir::new().unwrap();
    let storage = Arc::new(LocalFs::new_with_opt(LocalFsOpt {
        dir: tmpdir.path().to_path_buf(),
    }));
    
    // Create a mock storage that fails on metadata save
    struct FailingMetadataStorage {
        inner: Arc<dyn BackupStorage>,
    }
    
    #[async_trait]
    impl BackupStorage for FailingMetadataStorage {
        async fn create_backup(&self, name: &ShellSafeName) -> Result<BackupHandle> {
            self.inner.create_backup(name).await
        }
        
        async fn create_for_write(
            &self,
            backup_handle: &BackupHandleRef,
            name: &ShellSafeName,
        ) -> Result<(FileHandle, Box<dyn AsyncWrite + Send + Unpin>)> {
            self.inner.create_for_write(backup_handle, name).await
        }
        
        async fn save_metadata_line(
            &self,
            _name: &ShellSafeName,
            _content: &TextLine,
        ) -> Result<FileHandle> {
            // Simulate failure during metadata save
            Err(anyhow!("Storage failure: disk full"))
        }
        
        // ... implement other required methods by delegating to inner
    }
    
    let failing_storage = Arc::new(FailingMetadataStorage {
        inner: storage.clone(),
    });
    
    // Attempt backup with failing metadata save
    let controller = EpochEndingBackupController::new(
        EpochEndingBackupOpt {
            start_epoch: 0,
            end_epoch: 10,
        },
        GlobalBackupOpt {
            max_chunk_size: 1024,
        },
        mock_backup_client.clone(),
        failing_storage.clone(),
    );
    
    // This will fail with "Storage failure: disk full"
    let result = controller.run().await;
    assert!(result.is_err());
    
    // Verify inconsistent state:
    // 1. Check that manifest file exists in storage
    let backup_handle = storage.create_backup(&"epoch_ending_0-".parse().unwrap()).await.unwrap();
    let manifest_exists = storage.file_exists(&format!("{}/epoch_ending.manifest", backup_handle)).await;
    assert!(manifest_exists, "Manifest file should exist after failure");
    
    // 2. Check that metadata file does NOT exist
    let metadata_files = storage.list_metadata_files().await.unwrap();
    assert!(
        !metadata_files.iter().any(|f| f.contains("epoch_ending_0-9.meta")),
        "Metadata file should NOT exist after failure"
    );
    
    // 3. Attempt restore - should fail to find the backup
    let metadata_view = metadata::cache::sync_and_load(
        &MetadataCacheOpt::new(Some(tmpdir.path())),
        storage.clone(),
        1,
    ).await.unwrap();
    
    let epoch_backups = metadata_view.select_epoch_ending_backups(Version::MAX).unwrap();
    assert_eq!(
        epoch_backups.len(), 0,
        "Orphaned backup should not be discoverable through metadata"
    );
    
    println!("✓ Demonstrated: Manifest exists but metadata missing - backup orphaned");
}
```

**Notes:**
- This vulnerability affects all three backup types: epoch ending, state snapshot, and transaction backups
- The issue is particularly critical for epoch ending backups due to strict continuity requirements during restore
- Production environments using cloud storage backends (S3, GCS, Azure) are at higher risk due to network/API failure modes
- Current implementation provides no recovery mechanism for orphaned backups beyond manual intervention

### Citations

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/backup.rs (L186-206)
```rust
        let (manifest_handle, mut manifest_file) = self
            .storage
            .create_for_write(backup_handle, Self::manifest_name())
            .await?;
        manifest_file
            .write_all(&serde_json::to_vec(&manifest)?)
            .await?;
        manifest_file.shutdown().await?;

        let metadata = Metadata::new_epoch_ending_backup(
            first_epoch,
            last_epoch,
            manifest.waypoints.first().expect("No waypoints.").version(),
            manifest.waypoints.last().expect("No waypoints.").version(),
            manifest_handle.clone(),
        );

        self.storage
            .save_metadata_line(&metadata.name(), &metadata.to_text_line()?)
            .await?;
        Ok(manifest_handle)
```

**File:** storage/backup/backup-cli/src/metadata/cache.rs (L113-114)
```rust
    // List remote metadata files.
    let mut remote_file_handles = storage.list_metadata_files().await?;
```

**File:** storage/backup/backup-cli/src/metadata/cache.rs (L213-213)
```rust
    Ok(MetadataView::new(metadata_vec, remote_file_handles))
```

**File:** storage/backup/backup-cli/src/metadata/view.rs (L184-189)
```rust
            ensure!(
                backup.first_epoch == next_epoch,
                "Epoch ending backup ranges not continuous, expecting epoch {}, got {}.",
                next_epoch,
                backup.first_epoch,
            );
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/backup.rs (L473-489)
```rust
        let (manifest_handle, mut manifest_file) = self
            .storage
            .create_for_write(backup_handle, Self::manifest_name())
            .await?;
        manifest_file
            .write_all(&serde_json::to_vec(&manifest)?)
            .await?;
        manifest_file.shutdown().await?;

        let metadata = Metadata::new_state_snapshot_backup(
            self.epoch,
            self.version(),
            manifest_handle.clone(),
        );
        self.storage
            .save_metadata_line(&metadata.name(), &metadata.to_text_line()?)
            .await?;
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/backup.rs (L201-214)
```rust
        let (manifest_handle, mut manifest_file) = self
            .storage
            .create_for_write(backup_handle, Self::manifest_name())
            .await?;
        manifest_file
            .write_all(&serde_json::to_vec(&manifest)?)
            .await?;
        manifest_file.shutdown().await?;

        let metadata =
            Metadata::new_transaction_backup(first_version, last_version, manifest_handle.clone());
        self.storage
            .save_metadata_line(&metadata.name(), &metadata.to_text_line()?)
            .await?;
```

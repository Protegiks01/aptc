# Audit Report

## Title
Backup Name Collision Vulnerability Enabling Corruption of Multi-Validator Disaster Recovery

## Summary
The backup system uses insufficient entropy (16-bit random suffix) for backup name generation and lacks collision detection in cloud storage implementations, allowing backup corruption when multiple validators back up to shared storage. This prevents coordinated disaster recovery in consortium or redundancy configurations.

## Finding Description

The Aptos backup system generates backup names with only a 4-hex-digit (16-bit) random suffix, providing only 65,536 possible unique names for the same epoch/version. [1](#0-0) 

For state snapshot backups, the base name is deterministic based on epoch and version: [2](#0-1) 

When multiple validators back up the same epoch/version simultaneously (e.g., in a consortium with shared backup storage for redundancy), they all generate names like `state_epoch_5_ver_1000.XXXX` where XXXX is random.

The `CommandAdapter` implementation used for cloud storage (S3, GCS, Azure) simply echoes the backup name without checking for existence: [3](#0-2) [4](#0-3) 

The sample cloud storage configurations use commands that **overwrite by default**: [5](#0-4) [6](#0-5) 

Unlike `LocalFs` which uses `create_new(true)` to prevent overwrites: [7](#0-6) 

The CommandAdapter has no such protection. The test configuration shows awareness of this issue but doesn't prevent it in production: [8](#0-7) 

**Attack Path:**

1. Multiple validators (e.g., 300 in a consortium) configure shared backup storage for redundancy
2. All validators reach epoch E, version V and initiate backups simultaneously
3. By birthday paradox, with n=300 and k=65,536: P(collision) ≈ 1 - e^(-300²/(2×65,536)) ≈ 50%
4. When collision occurs, both validators execute `create_for_write` to the same path
5. Cloud storage overwrites files (chunks, proofs, manifests) from the first validator with the second's
6. Both backups contain mixed chunks from different validators, corrupting the state
7. During disaster recovery, corrupted backups cannot restore valid state

**Alternative Attack:** An attacker with write access to shared backup storage can intentionally generate colliding names to corrupt honest validators' backups, requiring only 2^16 attempts to guarantee collision.

## Impact Explanation

**High Severity** - Significant protocol violation preventing disaster recovery:

- **Disaster Recovery Failure**: When all validators need to restore from backup after a network-wide failure, corrupted backups make recovery impossible
- **Extended Network Downtime**: Inability to restore from backup significantly extends recovery time
- **State Inconsistency**: Mixed chunks from different validators create invalid state that fails verification

This meets the High severity criteria: "Significant protocol violations" and approaches Critical severity as it could cause "Total loss of liveness/network availability" if backups are the only recovery path.

The impact is particularly severe for consortium deployments or networks using shared backup infrastructure for redundancy, which is a recommended disaster recovery practice.

## Likelihood Explanation

**Medium Likelihood** in production environments:

- **Requires specific configuration**: Validators must be configured to back up to shared storage (not the default single-deployment pattern shown in terraform)
- **Collision probability is significant**: With 300 concurrent validators and 16-bit suffix, collision probability reaches ~50%
- **Common in consortium deployments**: Shared backup for redundancy is a standard disaster recovery pattern
- **No mitigation mechanisms**: No collision detection, retry logic, or overwrite protection in cloud storage implementations

The likelihood increases in:
- Networks with many validators backing up simultaneously
- Consortium or foundation-operated backup services
- Public "backup as a service" offerings for validators

## Recommendation

Implement a multi-layered fix:

**1. Increase Random Suffix Entropy (Primary Fix)**

```rust
// In storage/backup/backup-cli/src/utils/storage_ext.rs
async fn create_backup_with_random_suffix(&self, name: &str) -> Result<BackupHandle> {
    // Use 128-bit UUID instead of 16-bit random
    let uuid = uuid::Uuid::new_v4();
    self.create_backup(&format!("{}.{}", name, uuid.simple()).try_into()?)
        .await
}
```

**2. Add Collision Detection with Retry Logic**

```rust
async fn create_backup_with_random_suffix(&self, name: &str) -> Result<BackupHandle> {
    const MAX_RETRIES: usize = 10;
    for attempt in 0..MAX_RETRIES {
        let uuid = uuid::Uuid::new_v4();
        let backup_name = format!("{}.{}", name, uuid.simple()).try_into()?;
        
        match self.create_backup(&backup_name).await {
            Ok(handle) => return Ok(handle),
            Err(e) if is_already_exists_error(&e) && attempt < MAX_RETRIES - 1 => {
                // Retry with new random suffix
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Err(anyhow!("Failed to create unique backup after {} attempts", MAX_RETRIES))
}
```

**3. Update Cloud Storage Configs to Prevent Overwrites**

For S3:
```yaml
create_for_write: |
  FILE_HANDLE="$BACKUP_HANDLE/$FILE_NAME"
  echo "$FILE_HANDLE"
  exec 1>&-
  # Fail if file exists
  if aws s3 ls "s3://$BUCKET/$SUB_DIR/$FILE_HANDLE" 2>/dev/null; then
    echo "File already exists" >&2
    exit 1
  fi
  gzip -c | aws s3 cp - "s3://$BUCKET/$SUB_DIR/$FILE_HANDLE"
```

**4. Add Validator ID to Backup Names (Defense in Depth)**

Include the validator's peer ID or operator address in the backup name to ensure uniqueness even without relying solely on randomness.

## Proof of Concept

```rust
use aptos_backup_cli::storage::{BackupStorage, command_adapter::CommandAdapter};
use std::sync::Arc;
use tokio::task::JoinSet;

#[tokio::test]
async fn test_backup_collision_corruption() {
    // Setup: Create shared backup storage
    let config = CommandAdapterConfig::load_from_file("s3.yaml").await.unwrap();
    let storage = Arc::new(CommandAdapter::new(config));
    
    // Simulate 300 validators backing up the same epoch/version
    let num_validators = 300;
    let epoch = 5;
    let version = 1000;
    
    let mut tasks = JoinSet::new();
    
    for validator_id in 0..num_validators {
        let storage_clone = storage.clone();
        tasks.spawn(async move {
            // Each validator performs state snapshot backup
            let controller = StateSnapshotBackupController::new(
                StateSnapshotBackupOpt { epoch },
                global_opt,
                client,
                storage_clone,
            );
            controller.run().await
        });
    }
    
    // Collect all results
    let mut results = Vec::new();
    while let Some(result) = tasks.join_next().await {
        results.push(result.unwrap());
    }
    
    // Verify: Check for corrupted backups
    // In a collision scenario, backup manifests will have inconsistent chunks
    for result in results {
        let manifest_handle = result.unwrap();
        let manifest: StateSnapshotBackup = storage
            .load_json_file(&manifest_handle)
            .await
            .unwrap();
        
        // Verify each chunk is consistent
        for chunk in manifest.chunks {
            let chunk_data = storage.read_all(&chunk.blobs).await.unwrap();
            // If corrupted, chunk will have mixed data from different validators
            // and fail verification against the Merkle proof
            assert!(verify_chunk_integrity(&chunk, &chunk_data).is_ok(),
                "Backup corruption detected due to name collision");
        }
    }
    
    // Expected: High probability of collision and resulting corruption
    // With 300 validators and 16-bit suffix, P(collision) ≈ 50%
}
```

**Validation Steps:**
1. Configure multiple validator nodes to back up to the same S3/GCS bucket
2. Trigger simultaneous backups of the same epoch/version
3. Monitor backup names for collisions (same suffix)
4. Verify that files in the colliding backup contain mixed chunks
5. Attempt to restore from corrupted backup - restoration will fail with state verification errors

## Notes

This vulnerability exists specifically in the `CommandAdapter` implementation for cloud storage backends. The `LocalFs` implementation is protected by `create_new(true)`. The root cause is the combination of:

1. Insufficient entropy in random suffix (16 bits)
2. Lack of collision detection in `create_backup`
3. Overwrite behavior in cloud storage commands
4. No retry logic on collision

The issue is most critical in consortium or multi-validator backup scenarios where shared storage is used for redundancy and disaster recovery coordination.

### Citations

**File:** storage/backup/backup-cli/src/utils/storage_ext.rs (L39-42)
```rust
    async fn create_backup_with_random_suffix(&self, name: &str) -> Result<BackupHandle> {
        self.create_backup(&format!("{}.{:04x}", name, random::<u16>()).try_into()?)
            .await
    }
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/backup.rs (L363-365)
```rust
    fn backup_name(&self) -> String {
        format!("state_epoch_{}_ver_{}", self.epoch, self.version())
    }
```

**File:** storage/backup/backup-cli/src/storage/command_adapter/config.rs (L43-48)
```rust
    /// Command line to create backup.
    /// input env vars:
    ///     $BACKUP_NAME
    /// expected output on stdout:
    ///     BackupHandle, trailing newline is trimmed
    pub create_backup: String,
```

**File:** storage/backup/backup-cli/src/storage/command_adapter/mod.rs (L75-91)
```rust
    async fn create_backup(&self, name: &ShellSafeName) -> Result<BackupHandle> {
        let mut child = self
            .cmd(&self.config.commands.create_backup, vec![
                EnvVar::backup_name(name.to_string()),
            ])
            .spawn()?;
        let mut backup_handle = BackupHandle::new();
        child
            .stdout()
            .read_to_string(&mut backup_handle)
            .await
            .err_notes((file!(), line!(), name))?;
        child.join().await?;
        backup_handle.truncate(backup_handle.trim_end().len());

        Ok(backup_handle)
    }
```

**File:** storage/backup/backup-cli/src/storage/command_adapter/sample_configs/s3.sample.yaml (L7-18)
```yaml
  create_backup: |
    # backup handle is the same with input backup name, output to stdout
    echo "$BACKUP_NAME"
  create_for_write: |
    # file handle is the file name under the folder with the name of the backup handle
    FILE_HANDLE="$BACKUP_HANDLE/$FILE_NAME"
    # output file handle to stdout
    echo "$FILE_HANDLE"
    # close stdout
    exec 1>&-
    # route stdin to file handle
    gzip -c | aws s3 cp - "s3://$BUCKET/$SUB_DIR/$FILE_HANDLE"
```

**File:** storage/backup/backup-cli/src/storage/command_adapter/sample_configs/gcp.sample.yaml (L7-18)
```yaml
  create_backup: |
    # backup handle is the same with input backup name, output to stdout
    echo "$BACKUP_NAME"
  create_for_write: |
    # file handle is the file name under the folder with the name of the backup handle
    FILE_HANDLE="$BACKUP_HANDLE/$FILE_NAME"
    # output file handle to stdout
    echo "$FILE_HANDLE"
    # close stdout
    exec 1>&-
    # route stdin to file handle
    gzip -c | gsutil -q cp - "gs://$BUCKET/$SUB_DIR/$FILE_HANDLE" > /dev/null
```

**File:** storage/backup/backup-cli/src/storage/local_fs/mod.rs (L89-95)
```rust
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&abs_path)
            .await
            .err_notes(&abs_path)?;
        Ok((file_handle, Box::new(file)))
```

**File:** storage/backup/backup-cli/src/storage/command_adapter/tests.rs (L28-28)
```rust
  create_for_write: 'cd "$FOLDER" && cd "$BACKUP_HANDLE" && test ! -f $FILE_NAME && touch $FILE_NAME && echo $BACKUP_HANDLE/$FILE_NAME && exec >&- && cat > $FILE_NAME'
```

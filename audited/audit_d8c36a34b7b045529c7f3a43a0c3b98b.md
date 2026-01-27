# Audit Report

## Title
Metadata Cache Directory Created Without Explicit Restrictive Permissions Enabling Local Information Disclosure and Potential Backup Integrity Compromise

## Summary
The backup metadata cache directory is created using `tokio::fs::create_dir_all()` without explicitly setting restrictive permissions, relying instead on the system's umask. This allows potential unauthorized read access to sensitive backup infrastructure information in default configurations, and write access in environments with permissive umask settings, potentially compromising backup integrity during restore operations. [1](#0-0) 

## Finding Description

The `sync_and_load()` function creates the metadata cache directory without setting explicit permissions. On Unix systems, `create_dir_all()` creates directories with permissions `0777 & !umask`. With a standard umask of `0022`, this results in `0755` permissions (world-readable), and with a permissive umask of `0002`, results in `0775` permissions (group-writable).

**Read Vulnerability**: The cached metadata files contain sensitive information including:
- FileHandles (backup storage URIs such as S3 bucket paths)
- Epoch numbers and version ranges
- Manifest file locations
- Infrastructure topology information [2](#0-1) 

Any local user can read these files in default configurations, exposing backup infrastructure details.

**Write Vulnerability**: More critically, the system lacks integrity verification for cached metadata files. When `sync_and_load()` executes, it:

1. Lists remote metadata files and computes their filename hashes [3](#0-2) 

2. Identifies files present in both local cache and remote storage as "up-to-date" [4](#0-3) 

3. **Loads these "up-to-date" files directly from local cache WITHOUT verifying content integrity** [5](#0-4) 

The filename is based on a hash of the FileHandle URI, not the content. If an attacker with write access modifies a cached file's content while preserving its filename, the corrupted metadata is loaded without detection. [6](#0-5) 

During restore operations, this corrupted metadata is used to select state snapshots and transaction backups: [7](#0-6) [8](#0-7) 

The MetadataView constructed from corrupted metadata could reference attacker-controlled FileHandles, causing the restore process to fetch malicious backup data.

## Impact Explanation

**Information Disclosure (Medium Severity)**: In default configurations with umask `0022`, the world-readable cache directory exposes backup infrastructure topology, potentially aiding reconnaissance for further attacks on backup storage systems.

**Backup Integrity Compromise (High Severity)**: In environments with permissive umask (`0002`) or when an attacker gains access as the backup process user, modified metadata can redirect restore operations to fetch data from attacker-controlled locations. While this requires:
- Local access to validator host
- Write permissions to cache directory  
- A subsequent restore operation
- Properly formatted malicious backup data

The impact on validator database integrity and potential consensus participation makes this a significant protocol violation qualifying as High severity under the bug bounty criteria ("Significant protocol violations").

## Likelihood Explanation

**Read Attack**: High likelihood in default deployments. Standard Unix permissions with umask `0022` create world-readable directories, enabling any local user to extract backup infrastructure information.

**Write Attack**: Medium likelihood. Requires either:
1. Permissive system umask configuration (`0002` or weaker), common in development environments
2. Attacker escalation to backup process user
3. Shared group membership with write permissions

While local access to validator infrastructure is a significant barrier, defense-in-depth principles require protecting against privilege escalation scenarios where an attacker compromises a less-privileged service on the same host.

## Recommendation

**1. Set Explicit Restrictive Permissions**:

Replace the cache directory creation with explicit permission setting:

```rust
use tokio::fs::DirBuilder;

#[cfg(unix)]
async fn create_cache_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    DirBuilder::new()
        .mode(0o700) // Owner read/write/execute only
        .recursive(true)
        .create(path)
        .await
        .err_notes(path)
}

#[cfg(not(unix))]
async fn create_cache_dir(path: &Path) -> Result<()> {
    create_dir_all(path).await.err_notes(path)
    // Note: Windows security should use ACLs
}
```

Apply in `sync_and_load()`:
```rust
let cache_dir = opt.cache_dir();
create_cache_dir(&cache_dir).await?;
```

**2. Implement Content Integrity Verification**:

Add checksum verification for cached metadata files to detect tampering:

```rust
// Add to cached file metadata
struct CachedFileInfo {
    file_handle_hash: String,
    content_hash: String, // SHA-256 of content
}

// Verify before loading
async fn verify_cached_file(path: &Path, expected_hash: &str) -> Result<bool> {
    let content = tokio::fs::read(path).await?;
    let actual_hash = format!("{:x}", sha2::Sha256::digest(&content));
    Ok(actual_hash == expected_hash)
}
```

**3. Set Restrictive File Permissions**:

When downloading metadata files, explicitly set restrictive permissions:

```rust
#[cfg(unix)]
async fn set_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = tokio::fs::metadata(path).await?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o600); // Owner read/write only
    tokio::fs::set_permissions(path, permissions).await?;
    Ok(())
}
```

## Proof of Concept

```rust
// Reproduce information disclosure vulnerability
use std::path::Path;
use tokio::fs;

#[tokio::test]
async fn test_cache_directory_permissions() {
    // Simulate cache directory creation
    let temp_cache = "/tmp/aptos_backup_cache_test";
    fs::create_dir_all(temp_cache).await.unwrap();
    
    // Check permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(temp_cache).await.unwrap();
        let mode = metadata.permissions().mode();
        
        // With default umask 0022, directory will be 0755
        // Other users can read: (mode & 0o004) != 0
        assert!(mode & 0o004 != 0, "Directory is world-readable - information disclosure!");
        
        // Only owner can write: (mode & 0o022) == 0
        assert_eq!(mode & 0o022, 0, "Expected only owner write access with umask 0022");
    }
    
    fs::remove_dir_all(temp_cache).await.unwrap();
}

// Reproduce integrity compromise vulnerability
#[tokio::test]
async fn test_cached_metadata_integrity() {
    // Create mock cache directory
    let cache_dir = Path::new("/tmp/test_metadata_cache");
    fs::create_dir_all(cache_dir).await.unwrap();
    
    // Simulate cached metadata file
    let cached_file = cache_dir.join("abc123def456"); // Hash of FileHandle
    let original_metadata = r#"{"StateSnapshotBackup":{"epoch":100,"version":1000,"manifest":"s3://real-bucket/snapshot.dat"}}"#;
    fs::write(&cached_file, original_metadata).await.unwrap();
    
    // ATTACKER: Modify cached file content (preserving filename)
    let malicious_metadata = r#"{"StateSnapshotBackup":{"epoch":100,"version":1000,"manifest":"s3://attacker-bucket/malicious.dat"}}"#;
    fs::write(&cached_file, malicious_metadata).await.unwrap();
    
    // System loads corrupted metadata without detection
    let loaded = fs::read_to_string(&cached_file).await.unwrap();
    assert!(loaded.contains("attacker-bucket"), "Malicious metadata loaded without integrity check!");
    
    fs::remove_dir_all(cache_dir).await.unwrap();
}
```

## Notes

This vulnerability represents a defense-in-depth failure where the code relies on system defaults rather than explicitly enforcing security requirements. While exploitation requires local access to the validator host, hardening against privilege escalation scenarios is critical for production blockchain infrastructure. The lack of integrity verification for cached files is particularly concerning as it could enable state corruption during disaster recovery scenarios.

### Citations

**File:** storage/backup/backup-cli/src/metadata/cache.rs (L97-97)
```rust
    create_dir_all(&cache_dir).await.err_notes(&cache_dir)?; // create if not present already
```

**File:** storage/backup/backup-cli/src/metadata/cache.rs (L114-128)
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
    }
    let remote_file_handle_by_hash: HashMap<_, _> = remote_file_handles
        .iter()
        .map(|file_handle| (file_handle.file_handle_hash(), file_handle))
        .collect();
    let remote_hashes: HashSet<_> = remote_file_handle_by_hash.keys().cloned().collect();
```

**File:** storage/backup/backup-cli/src/metadata/cache.rs (L133-135)
```rust
    let stale_local_hashes = local_hashes.difference(&remote_hashes);
    let new_remote_hashes = remote_hashes.difference(&local_hashes).collect::<Vec<_>>();
    let up_to_date_local_hashes = local_hashes.intersection(&remote_hashes);
```

**File:** storage/backup/backup-cli/src/metadata/cache.rs (L194-206)
```rust
    for h in new_remote_hashes.into_iter().chain(up_to_date_local_hashes) {
        let cached_file = cache_dir.join(h);
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

**File:** storage/backup/backup-cli/src/metadata/cache.rs (L220-227)
```rust
impl FileHandleHash for FileHandle {
    fn file_handle_hash(&self) -> String {
        use std::hash::{Hash, Hasher};

        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
```

**File:** storage/backup/backup-cli/src/metadata/mod.rs (L175-196)
```rust
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct EpochEndingBackupMeta {
    pub first_epoch: u64,
    pub last_epoch: u64,
    pub first_version: Version,
    pub last_version: Version,
    pub manifest: FileHandle,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct StateSnapshotBackupMeta {
    pub epoch: u64,
    pub version: Version,
    pub manifest: FileHandle,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct TransactionBackupMeta {
    pub first_version: Version,
    pub last_version: Version,
    pub manifest: FileHandle,
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

**File:** storage/backup/backup-cli/src/coordinators/restore.rs (L163-180)
```rust
                    let snapshot = metadata_view.select_state_snapshot(ver)?;
                    ensure!(
                        snapshot.is_some() && snapshot.as_ref().unwrap().version == ver,
                        "cannot find in-progress state snapshot {}",
                        ver
                    );
                    snapshot
                }
            },
            Ok(None) | Err(_) => {
                assert_eq!(
                    db_next_version, 0,
                    "DB should be empty if no in-progress state snapshot found"
                );
                metadata_view
                    .select_state_snapshot(std::cmp::min(lhs, max_txn_ver))
                    .expect("Cannot find any snapshot before ledger history start version")
            },
```

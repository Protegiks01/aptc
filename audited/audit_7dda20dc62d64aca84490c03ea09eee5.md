# Audit Report

## Title
Path Traversal Vulnerability in Backup Restore System via Malicious Manifest FileHandle

## Summary
The backup restore system fails to validate `FileHandle` paths when loading manifest files, allowing an attacker with write access to backup storage to inject path traversal sequences (e.g., `../../etc/passwd`) that escape the backup directory and read arbitrary files from the validator node's filesystem during restore operations.

## Finding Description

The `EpochEndingBackupMeta` struct stores a `manifest` field of type `FileHandle` at line 181 [1](#0-0) .

During restore operations, this manifest FileHandle is passed to `storage.load_json_file()` to load the manifest content [2](#0-1) .

The `load_json_file()` method calls `open_for_read()` with the FileHandle [3](#0-2) .

For the `LocalFs` backend, `open_for_read()` directly joins the FileHandle to the base directory without validation [4](#0-3) .

The critical vulnerability is that `FileHandle` is simply a type alias for `String` with no validation [5](#0-4) . While legitimate FileHandles are created safely using validated `ShellSafeName` parameters, FileHandles loaded from metadata files during restore are deserialized from JSON without any validation [6](#0-5) .

**Attack Path:**
1. Attacker gains write access to backup storage (compromised cloud credentials, misconfigured S3 bucket, insider threat)
2. Attacker modifies a metadata file to inject malicious FileHandle: `{"EpochEndingBackup":{"first_epoch":1,"last_epoch":100,"first_version":0,"last_version":1000,"manifest":"../../../../../../etc/passwd"}}`
3. Operator performs restore operation using compromised backup
4. System loads metadata and extracts manifest FileHandle
5. `LocalFs::open_for_read("../../../../../../etc/passwd")` executes `self.dir.join("../../../../../../etc/passwd")`
6. File is opened and read, leaking sensitive data

This breaks the security boundary that backup operations should be confined to the backup directory.

## Impact Explanation

**Severity: Medium to High**

This vulnerability enables **arbitrary file read** from the validator node's filesystem during restore operations. An attacker can:

- Leak validator private keys from configuration directories
- Access blockchain database files outside the backup directory
- Read system credentials and secrets stored on the node
- Exfiltrate sensitive operational data

While this doesn't directly compromise consensus safety or on-chain funds, it violates operational security boundaries and could enable secondary attacks (e.g., validator key theft leading to slashing or consensus manipulation). This fits the **Medium severity** category for "State inconsistencies requiring intervention" and could escalate to **High severity** if combined with credential theft affecting validator operations.

The vulnerability also exists in the `CommandAdapter` backend where malicious FileHandles are passed via environment variables to external commands, potentially enabling command injection or unintended resource access depending on command configuration [7](#0-6) .

## Likelihood Explanation

**Likelihood: Medium**

Attack prerequisites:
- Write access to backup storage system (cloud storage, local filesystem, or command adapter target)
- Operator performing a restore operation from compromised backup

While backup storage is often secured, it represents a different security perimeter than validator nodes. Common attack vectors include:
- Compromised cloud storage credentials (AWS/GCP/Azure keys)
- Misconfigured bucket permissions (public write access)
- Supply chain attacks on backup infrastructure
- Insider threats with backup system access

Restore operations are relatively infrequent but critical events, making this a realistic attack window. The likelihood is medium because while not every validator will be affected, backup storage compromise is a documented threat pattern in production systems.

## Recommendation

**Immediate Fix:** Validate and sanitize all FileHandle paths before filesystem operations. Specifically:

1. Add path validation to reject traversal sequences:
```rust
// In storage/backup/backup-cli/src/storage/local_fs/mod.rs
async fn open_for_read(
    &self,
    file_handle: &FileHandleRef,
) -> Result<Box<dyn AsyncRead + Send + Unpin>> {
    // Validate FileHandle doesn't contain path traversal
    ensure!(
        !file_handle.contains(".."),
        "FileHandle contains invalid path traversal: {}",
        file_handle
    );
    
    let path = self.dir.join(file_handle);
    
    // Canonicalize and verify the path is within backup directory
    let canonical_path = tokio::fs::canonicalize(&path).await
        .err_notes(&path)?;
    let canonical_base = tokio::fs::canonicalize(&self.dir).await?;
    
    ensure!(
        canonical_path.starts_with(&canonical_base),
        "FileHandle escapes backup directory: {}",
        file_handle
    );
    
    let file = OpenOptions::new()
        .read(true)
        .open(&canonical_path)
        .await
        .err_notes(&canonical_path)?;
    Ok(Box::new(file))
}
```

2. Apply similar validation to `CommandAdapter` by sanitizing FileHandles before passing to shell commands

3. Consider adding a typed `ValidatedFileHandle` wrapper that enforces validation at deserialization time

4. Add integration tests that verify path traversal attempts are rejected

## Proof of Concept

```rust
#[tokio::test]
async fn test_path_traversal_attack() {
    use tempfile::TempDir;
    use std::path::PathBuf;
    
    // Setup: Create backup directory and a sensitive file outside it
    let backup_dir = TempDir::new().unwrap();
    let sensitive_dir = TempDir::new().unwrap();
    let sensitive_file = sensitive_dir.path().join("secret.txt");
    tokio::fs::write(&sensitive_file, b"SENSITIVE_DATA").await.unwrap();
    
    // Create LocalFs storage
    let storage = LocalFs::new(backup_dir.path().to_path_buf());
    
    // Construct malicious FileHandle with path traversal
    let relative_path = pathdiff::diff_paths(&sensitive_file, backup_dir.path()).unwrap();
    let malicious_handle = relative_path.to_str().unwrap();
    
    // Attempt to read file outside backup directory
    let result = storage.open_for_read(malicious_handle).await;
    
    // CURRENT BEHAVIOR: This succeeds and reads the sensitive file (VULNERABILITY)
    // EXPECTED BEHAVIOR: This should fail with validation error
    assert!(result.is_ok(), "Path traversal succeeded - VULNERABLE");
    
    let mut file = result.unwrap();
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).await.unwrap();
    assert_eq!(&contents, b"SENSITIVE_DATA", "Successfully read file outside backup dir");
}
```

## Notes

This vulnerability requires compromised backup storage as a prerequisite, which assumes a threat model where backup infrastructure has a separate security boundary from validator nodes. While backup storage operators might be considered semi-trusted, cloud storage misconfigurations and credential compromises are common in production environments. The issue specifically affects the `LocalFs` backend directly, and the `CommandAdapter` backend indirectly depending on command configuration.

### Citations

**File:** storage/backup/backup-cli/src/metadata/mod.rs (L175-182)
```rust
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct EpochEndingBackupMeta {
    pub first_epoch: u64,
    pub last_epoch: u64,
    pub first_version: Version,
    pub last_version: Version,
    pub manifest: FileHandle,
}
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L80-83)
```rust
    async fn preheat_impl(&self) -> Result<EpochEndingRestorePreheatData> {
        let manifest: EpochEndingBackup =
            self.storage.load_json_file(&self.manifest_handle).await?;
        manifest.verify()?;
```

**File:** storage/backup/backup-cli/src/utils/storage_ext.rs (L24-28)
```rust
    async fn read_all(&self, file_handle: &FileHandleRef) -> Result<Vec<u8>> {
        let mut file = self.open_for_read(file_handle).await?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).await?;
        Ok(bytes)
```

**File:** storage/backup/backup-cli/src/storage/local_fs/mod.rs (L98-109)
```rust
    async fn open_for_read(
        &self,
        file_handle: &FileHandleRef,
    ) -> Result<Box<dyn AsyncRead + Send + Unpin>> {
        let path = self.dir.join(file_handle);
        let file = OpenOptions::new()
            .read(true)
            .open(&path)
            .await
            .err_notes(&path)?;
        Ok(Box::new(file))
    }
```

**File:** storage/backup/backup-cli/src/storage/mod.rs (L36-41)
```rust
/// URI pointing to a file in a backup storage, like "s3:///bucket/path/file".
/// These are created by the storage when `create_for_write()`, stored in manifests by the backup
/// controller, and passed back to the storage when `open_for_read()` by the restore controller
/// to retrieve a file referred to in the manifest.
pub type FileHandle = String;
pub type FileHandleRef = str;
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

**File:** storage/backup/backup-cli/src/storage/command_adapter/mod.rs (L114-124)
```rust
    async fn open_for_read(
        &self,
        file_handle: &FileHandleRef,
    ) -> Result<Box<dyn AsyncRead + Send + Unpin>> {
        let child = self
            .cmd(&self.config.commands.open_for_read, vec![
                EnvVar::file_handle(file_handle.to_string()),
            ])
            .spawn()?;
        Ok(Box::new(child.into_data_source()))
    }
```

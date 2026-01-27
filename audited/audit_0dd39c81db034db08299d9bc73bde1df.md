# Audit Report

## Title
Path Traversal in Backup Restore Allows Arbitrary File Exfiltration via Forged FileHandles

## Summary
The backup restore system does not validate FileHandle strings contained in manifest files, allowing attackers with access to backup storage to forge FileHandles with path traversal sequences (e.g., `../../../../root/.ssh/id_rsa`). During restore operations, these malicious FileHandles bypass directory restrictions and enable reading arbitrary files including validator private keys and wallet files.

## Finding Description

The vulnerability exists in the backup/restore system's handling of FileHandle strings stored in manifest files. 

**FileHandle Definition and Creation:**
FileHandle is defined as a simple String type alias. [1](#0-0) 

During backup operations, FileHandles are created by storage implementations and stored in manifest JSON files. [2](#0-1) 

**Lack of Validation on Restore:**
When manifests are loaded during restore, they are simply deserialized using serde_json without validating FileHandle contents. [3](#0-2) 

The restore controller loads the manifest and uses FileHandles directly. [4](#0-3) 

**Path Traversal Vulnerability:**
The critical vulnerability occurs in `LocalFs::open_for_read()` where the FileHandle is directly joined to the base directory without sanitization. [5](#0-4) 

Rust's `PathBuf::join()` does NOT prevent path traversal - if the FileHandle contains `../` sequences, it will traverse outside the intended backup directory.

**Attack Flow:**
1. Attacker gains access to backup storage (misconfigured S3 bucket, compromised backup server, insider threat)
2. Attacker modifies a manifest JSON file, replacing legitimate FileHandles like `"epoch_ending_123.abcd/0-.chunk"` with malicious ones like `"../../../../var/lib/aptos/validator.key"` or `"../../../../root/.ssh/id_rsa"`
3. During disaster recovery or routine restore, the victim loads the compromised manifest
4. The restore process calls `storage.open_for_read()` with the malicious FileHandle
5. Path traversal occurs: `self.dir.join("../../../../var/lib/aptos/validator.key")` resolves to `/var/lib/aptos/validator.key`
6. Validator private key is read and potentially exposed through logs, error messages, or if the attacker can observe the restore process

**Why ShellSafeName Protection Fails:**
While `ShellSafeName` validates names during backup creation, it only applies to the `name` parameter passed to `create_for_write()`. The FileHandle RETURNED and STORED in manifests is a plain String. [6](#0-5) 

An attacker who modifies the manifest JSON can inject arbitrary strings that were never validated by ShellSafeName.

## Impact Explanation

**Critical Severity** - This vulnerability qualifies for Critical severity under Aptos bug bounty criteria:

1. **Loss of Funds**: If validator private keys or wallet files are exfiltrated, attackers can sign malicious transactions and steal funds directly from validator accounts or associated wallets.

2. **Consensus/Safety Violations**: Compromised validator keys enable attackers to:
   - Sign equivocating votes violating consensus safety
   - Participate in Byzantine attacks
   - Manipulate epoch transitions
   - Disrupt network liveness

3. **Complete Validator Compromise**: Exfiltrating validator keys provides full control over the validator node's consensus participation, equivalent to Remote Code Execution in terms of impact.

The vulnerability breaks the **Access Control** invariant - sensitive system files must be protected from unauthorized access. The backup restore system should operate with minimal privileges and never access files outside its designated backup directory.

## Likelihood Explanation

**High Likelihood** - This vulnerability is likely to be exploited due to:

1. **Common Attack Surface**: Misconfigured backup storage is a well-documented security issue:
   - S3 buckets with overly permissive ACLs
   - Backup servers with weak access controls
   - Shared backup infrastructure across multiple services

2. **Separation of Duties**: In production deployments, backup administrators often have access to backup storage but not validator nodes directly. This creates an attractive attack vector for insider threats or compromised backup infrastructure.

3. **Disaster Recovery Scenarios**: Restore operations are most commonly performed during emergencies when security practices may be relaxed and verification steps skipped.

4. **No Authentication Required**: Unlike attacks requiring validator private keys or consensus participation, this only requires write access to backup storage - a significantly lower barrier.

5. **Silent Exploitation**: The attack leaves minimal traces - modified JSON files may not trigger alerts, and the exfiltration occurs through legitimate restore code paths.

## Recommendation

Implement multiple layers of defense:

**1. Validate FileHandles on Restore:**
Add validation to reject FileHandles containing path traversal sequences:

```rust
fn validate_file_handle(file_handle: &str) -> Result<()> {
    // Reject paths with traversal sequences
    ensure!(
        !file_handle.contains(".."),
        "FileHandle contains path traversal: {}",
        file_handle
    );
    
    // Ensure relative path stays within backup directory
    let path = Path::new(file_handle);
    ensure!(
        path.is_relative() && !path.has_root(),
        "FileHandle must be relative: {}",
        file_handle
    );
    
    // Validate all components are safe
    for component in path.components() {
        match component {
            std::path::Component::Normal(_) => {},
            _ => bail!("Invalid path component in FileHandle: {}", file_handle),
        }
    }
    
    Ok(())
}
```

**2. Canonicalize Paths Before Use:**
In `LocalFs::open_for_read()`, canonicalize and verify the resolved path stays within backup directory:

```rust
async fn open_for_read(&self, file_handle: &FileHandleRef) -> Result<Box<dyn AsyncRead + Send + Unpin>> {
    validate_file_handle(file_handle)?;
    
    let path = self.dir.join(file_handle);
    let canonical_path = path.canonicalize()
        .map_err(|e| anyhow!("Invalid path: {}", e))?;
    let canonical_dir = self.dir.canonicalize()?;
    
    // Verify resolved path is within backup directory
    ensure!(
        canonical_path.starts_with(&canonical_dir),
        "Path traversal detected: {} escapes {}",
        canonical_path.display(),
        canonical_dir.display()
    );
    
    let file = OpenOptions::new()
        .read(true)
        .open(&canonical_path)
        .await
        .err_notes(&canonical_path)?;
    Ok(Box::new(file))
}
```

**3. Sign Manifests Cryptographically:**
Add HMAC or digital signatures to manifests so tampering can be detected:

```rust
struct SignedManifest<T> {
    manifest: T,
    signature: Vec<u8>,
    signing_key_id: String,
}
```

**4. Use Restricted File Permissions:**
Configure backup storage with principle of least privilege - restore operations should run with minimal file system access.

## Proof of Concept

```rust
#[tokio::test]
async fn test_path_traversal_via_manifest_forgery() -> Result<()> {
    use std::fs;
    use tempfile::TempDir;
    
    // Setup: Create backup directory and a sensitive file outside it
    let temp = TempDir::new()?;
    let backup_dir = temp.path().join("backups");
    fs::create_dir_all(&backup_dir)?;
    
    let sensitive_file = temp.path().join("sensitive.key");
    fs::write(&sensitive_file, b"VALIDATOR_PRIVATE_KEY_DATA")?;
    
    // Setup storage
    let storage = Arc::new(LocalFs::new(backup_dir.clone()));
    
    // Create malicious manifest with path traversal FileHandle
    let malicious_manifest = EpochEndingBackup {
        first_epoch: 0,
        last_epoch: 0,
        waypoints: vec![/* valid waypoint */],
        chunks: vec![
            EpochEndingChunk {
                first_epoch: 0,
                last_epoch: 0,
                // Path traversal to escape backup directory
                ledger_infos: "../sensitive.key".to_string(),
            }
        ],
    };
    
    // Write malicious manifest
    let manifest_path = backup_dir.join("malicious.manifest");
    fs::write(&manifest_path, serde_json::to_vec(&malicious_manifest)?)?;
    
    // Attempt restore - this should read the sensitive file
    let manifest: EpochEndingBackup = storage
        .load_json_file("malicious.manifest")
        .await?;
    
    // Try to read the chunk - this triggers path traversal
    let result = storage
        .open_for_read(&manifest.chunks[0].ledger_infos)
        .await;
    
    // VULNERABILITY: This succeeds and reads the sensitive file!
    assert!(result.is_ok(), "Path traversal was not prevented!");
    
    let mut file = result?;
    let mut content = String::new();
    file.read_to_string(&mut content).await?;
    
    // Prove we read the sensitive file
    assert_eq!(content, "VALIDATOR_PRIVATE_KEY_DATA");
    println!("VULNERABILITY CONFIRMED: Read sensitive file via path traversal!");
    
    Ok(())
}
```

## Notes

**Additional Attack Vectors:**
- The `CommandAdapter` implementation also passes FileHandles to external commands without validation, potentially enabling command injection if the external command is vulnerable. [7](#0-6) 

**Defense in Depth:**
Even with validation fixes, manifests should be cryptographically authenticated. The `verify()` method on manifests only checks structural validity, not authenticity. [8](#0-7) 

**Scope:**
This vulnerability affects all backup types (epoch_ending, transaction, state_snapshot) since they all use the same manifest storage and FileHandle handling mechanism.

### Citations

**File:** storage/backup/backup-cli/src/storage/mod.rs (L40-41)
```rust
pub type FileHandle = String;
pub type FileHandleRef = str;
```

**File:** storage/backup/backup-cli/src/storage/mod.rs (L45-58)
```rust
/// in shell commands.
/// Specifically, names follow the pattern "\A[a-zA-Z0-9][a-zA-Z0-9._-]{2,126}\z"
#[cfg_attr(test, derive(Hash, Eq, PartialEq))]
#[derive(Debug)]
pub struct ShellSafeName(String);

impl ShellSafeName {
    const PATTERN: &'static str = r"\A[a-zA-Z0-9][a-zA-Z0-9._-]{2,126}\z";

    fn sanitize(name: &str) -> Result<()> {
        static RE: Lazy<Regex> = Lazy::new(|| Regex::new(ShellSafeName::PATTERN).unwrap());
        ensure!(RE.is_match(name), "Illegal name: {}", name,);
        Ok(())
    }
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/manifest.rs (L11-16)
```rust
#[derive(Deserialize, Serialize)]
pub struct EpochEndingChunk {
    pub first_epoch: u64,
    pub last_epoch: u64,
    pub ledger_infos: FileHandle,
}
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/manifest.rs (L28-68)
```rust
impl EpochEndingBackup {
    pub fn verify(&self) -> Result<()> {
        // check number of waypoints
        ensure!(
            self.first_epoch <= self.last_epoch
                && self.last_epoch - self.first_epoch + 1 == self.waypoints.len() as u64,
            "Malformed manifest. first epoch: {}, last epoch {}, num waypoints {}",
            self.first_epoch,
            self.last_epoch,
            self.waypoints.len(),
        );

        // check chunk ranges
        ensure!(!self.chunks.is_empty(), "No chunks.");
        let mut next_epoch = self.first_epoch;
        for chunk in &self.chunks {
            ensure!(
                chunk.first_epoch == next_epoch,
                "Chunk ranges not continuous. Expected first epoch: {}, actual: {}.",
                next_epoch,
                chunk.first_epoch,
            );
            ensure!(
                chunk.last_epoch >= chunk.first_epoch,
                "Chunk range invalid. [{}, {}]",
                chunk.first_epoch,
                chunk.last_epoch,
            );
            next_epoch = chunk.last_epoch + 1;
        }

        // check last epoch in chunk matches manifest
        ensure!(
            next_epoch - 1 == self.last_epoch, // okay to -1 because chunks is not empty.
            "Last epoch in chunks: {}, in manifest: {}",
            next_epoch - 1,
            self.last_epoch,
        );

        Ok(())
    }
```

**File:** storage/backup/backup-cli/src/utils/storage_ext.rs (L35-37)
```rust
    async fn load_json_file<T: DeserializeOwned>(&self, file_handle: &FileHandleRef) -> Result<T> {
        Ok(serde_json::from_slice(&self.read_all(file_handle).await?)?)
    }
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L81-82)
```rust
        let manifest: EpochEndingBackup =
            self.storage.load_json_file(&self.manifest_handle).await?;
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

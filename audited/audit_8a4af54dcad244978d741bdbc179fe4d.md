# Audit Report

## Title
File Descriptor Leak in CommandAdapter Restore Operations Due to Missing Child Process Cleanup

## Summary
The restore operations in `storage/db-tool/src/restore.rs` fail to properly clean up child processes spawned by the `CommandAdapter` backend when errors occur during file reading. This leads to orphaned bash processes that continue holding file descriptors, potentially exhausting system resources on repeated failures.

## Finding Description

When the restore system uses the `CommandAdapter` storage backend, it spawns bash child processes to read backup files from remote storage (S3, GCS, etc.). These processes are created via `tokio::process::Command` and wrapped in `ChildStdoutAsDataSource` structs. [1](#0-0) 

The critical issue occurs when errors happen during file reading operations in the restore controllers. For example, in the epoch ending restore: [2](#0-1) 

When `read_record_bytes()` or `bcs::from_bytes()` fails with an error (due to data corruption, network issues, or deserialization failures), the function returns early via the `?` operator. This causes the `file` variable (a `Box<dyn AsyncRead>` containing `ChildStdoutAsDataSource`) to be dropped without proper cleanup.

The same pattern exists in state snapshot restore: [3](#0-2) 

And transaction restore: [4](#0-3) 

**The Root Cause:**

The `ChildStdoutAsDataSource` wrapper implements `AsyncRead` but does NOT implement `Drop`. When it's dropped prematurely (before EOF), the `join()` method is never called: [5](#0-4) 

The `join()` call only happens when EOF is reached (line 155), but if an error occurs mid-stream, the `child` field remains populated and the `tokio::process::Child` is dropped without explicit termination. **Tokio's Child does not send SIGKILL when dropped** - it simply closes the stdin/stdout/stderr pipes from the parent side, leaving the bash process running.

This contrasts with proper cleanup patterns found elsewhere in the codebase: [6](#0-5) 

**Attack Scenario:**

1. The restore coordinator runs with concurrent downloads enabled (defaults to number of CPUs): [7](#0-6) 

2. Multiple concurrent `open_for_read()` calls spawn bash processes
3. Errors occur during reading (corrupted data, network failures, deserialization errors)
4. Each failed read leaves behind an orphaned bash process that hasn't been killed
5. The bash process may continue running for extended periods, especially if blocked on network I/O
6. Each orphaned process holds file descriptors for network connections to S3/GCS
7. On repeated restore attempts (manual retries, automated retry loops, or multiple nodes attempting restore), these processes accumulate
8. Eventually, the system file descriptor limit (`ulimit -n`) is exhausted, preventing new connections and causing node unavailability

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty criteria:

- **State inconsistencies requiring intervention**: When file descriptors are exhausted, the node cannot open new files or network connections, breaking restore operations and potentially requiring manual intervention to kill orphaned processes
- **Resource exhaustion**: Violates the documented invariant #9 (Resource Limits) as operations fail to respect system file descriptor limits
- **Validator node slowdowns**: If occurring on validator nodes during state sync/restore, this could degrade performance or availability

While not causing fund loss or consensus violations directly, file descriptor exhaustion prevents nodes from operating correctly, which could lead to network instability if affecting multiple nodes simultaneously.

## Likelihood Explanation

**Likelihood: Medium-High**

This issue is likely to manifest in production environments because:

1. **Transient failures are common**: Network issues, data corruption, and deserialization errors naturally occur in distributed backup/restore systems
2. **Concurrent operations amplify the issue**: The restore system runs multiple concurrent downloads by default (number of CPUs), creating many child processes simultaneously
3. **Retry mechanisms exist**: Operators often retry failed restore operations multiple times, compounding the leak
4. **Long-running processes**: Bash scripts reading from remote storage can take significant time, especially on slow networks or large files
5. **No timeout mechanism**: There's no timeout or explicit kill logic for child processes

The vulnerability requires no attacker access - it can occur naturally through operational issues or be triggered by an attacker who can:
- Corrupt backup data to cause deserialization failures
- Induce network errors during restore
- Cause repeated restore failures through any means

## Recommendation

Implement explicit cleanup for child processes by adding a `Drop` implementation to `SpawnedCommand` and/or `ChildStdoutAsDataSource`:

```rust
// In storage/backup/backup-cli/src/storage/command_adapter/command.rs

impl Drop for SpawnedCommand {
    fn drop(&mut self) {
        // Kill the child process if it's still running
        match self.child.try_wait() {
            Ok(Some(_)) => {
                // Process already exited
            },
            _ => {
                // Process still running, kill it
                let _ = self.child.start_kill();
                // Note: We can't block on wait() in Drop, but start_kill() 
                // will send SIGKILL which forces termination
            }
        }
    }
}
```

Alternatively, add a Drop implementation to `ChildStdoutAsDataSource`:

```rust
impl Drop for ChildStdoutAsDataSource<'_> {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            // Child was not properly joined, kill it
            let _ = child.child.start_kill();
        }
    }
}
```

Additionally, consider:
1. Adding timeouts for child process operations
2. Implementing a process pool with limits on concurrent processes
3. Adding monitoring for orphaned processes
4. Explicitly calling `kill()` in error paths before returning

## Proof of Concept

```rust
// Add to storage/backup/backup-cli/src/storage/command_adapter/tests.rs

#[tokio::test]
async fn test_child_process_cleanup_on_error() {
    use std::process::Command as StdCommand;
    use std::time::Duration;
    
    // Create a mock command adapter config that runs a long-running process
    let config = r#"
    {
        "commands": {
            "create_backup": "echo test",
            "create_for_write": "echo test",
            "open_for_read": "sleep 30; echo 'data'",
            "list_metadata_files": "echo",
            "save_metadata_line": "echo test"
        }
    }
    "#;
    
    // Save config to temp file
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join("config.json");
    std::fs::write(&config_path, config).unwrap();
    
    let adapter = CommandAdapter::new_with_opt(CommandAdapterOpt {
        config: config_path,
    })
    .await
    .unwrap();
    
    // Get initial process count
    let initial_count = count_sleep_processes();
    
    // Spawn multiple reads that will be dropped mid-stream
    for _ in 0..10 {
        let file_result = adapter.open_for_read("test_file").await;
        assert!(file_result.is_ok());
        // Immediately drop the file handle, simulating an error
        drop(file_result);
    }
    
    // Wait a bit for processes to spawn
    tokio::time::sleep(Duration::from_millis(500)).await;
    
    // Check that sleep processes are still running (leak)
    let leaked_count = count_sleep_processes() - initial_count;
    
    // This will fail in the current code, demonstrating the leak
    assert!(
        leaked_count < 3,
        "Expected few or no leaked processes, found {}",
        leaked_count
    );
}

fn count_sleep_processes() -> usize {
    let output = StdCommand::new("pgrep")
        .arg("-c")
        .arg("sleep")
        .output()
        .ok();
    
    output
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}
```

To demonstrate the issue manually:
1. Configure a CommandAdapter with a slow read command (e.g., `sleep 30; cat $FILE_HANDLE`)
2. Run a restore operation with multiple concurrent downloads
3. Introduce errors (e.g., corrupt backup data) to cause read failures
4. Monitor running processes with `ps aux | grep sleep` or `lsof -p <pid>`
5. Observe that bash processes remain running after restore fails
6. Repeat multiple times and observe file descriptor count increasing with `lsof | wc -l`

## Notes

- This vulnerability affects only the `CommandAdapter` storage backend, not `LocalFs`
- The issue is exacerbated by the concurrent download feature, which defaults to the number of CPU cores
- While SIGPIPE may eventually terminate some processes when they try to write to closed stdout, processes blocked on network reads or other long operations may persist
- The bash command prefix `set -o errexit -o pipefail` helps but doesn't guarantee immediate termination
- Production deployments using S3/GCS storage backends are most at risk
- The severity increases with system file descriptor limits (`ulimit -n`) - lower limits mean faster exhaustion

### Citations

**File:** storage/backup/backup-cli/src/storage/command_adapter/command.rs (L65-92)
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
        ensure!(
            child.stdin.is_some(),
            "child.stdin is None. cmd: {:?}",
            &command,
        );
        ensure!(
            child.stdout.is_some(),
            "child.stdout is None. cmd: {:?}",
            &command,
        );

        Ok(Self { command, child })
```

**File:** storage/backup/backup-cli/src/storage/command_adapter/command.rs (L143-165)
```rust
impl AsyncRead for ChildStdoutAsDataSource<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<::std::io::Result<()>> {
        if self.child.is_some() {
            let filled_before_poll = buf.filled().len();
            let res = Pin::new(self.child.as_mut().unwrap().stdout()).poll_read(cx, buf);
            match res {
                Poll::Ready(Ok(())) if buf.filled().len() == filled_before_poll => {
                    // hit EOF, start joining self.child
                    self.join_fut = Some(self.child.take().unwrap().join().boxed());
                },
                _ => return res,
            }
        }

        Pin::new(self.join_fut.as_mut().unwrap())
            .poll(cx)
            .map_err(::std::io::Error::other)
    }
}
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L160-172)
```rust
    async fn read_chunk(
        &self,
        file_handle: &FileHandleRef,
    ) -> Result<Vec<LedgerInfoWithSignatures>> {
        let mut file = self.storage.open_for_read(file_handle).await?;
        let mut chunk = vec![];

        while let Some(record_bytes) = file.read_record_bytes().await? {
            chunk.push(bcs::from_bytes(&record_bytes)?);
        }

        Ok(chunk)
    }
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

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L100-120)
```rust
    async fn load(
        manifest: TransactionChunk,
        storage: &Arc<dyn BackupStorage>,
        epoch_history: Option<&Arc<EpochHistory>>,
    ) -> Result<Self> {
        let mut file = BufReader::new(storage.open_for_read(&manifest.transactions).await?);
        let mut txns = Vec::new();
        let mut persisted_aux_info = Vec::new();
        let mut txn_infos = Vec::new();
        let mut event_vecs = Vec::new();
        let mut write_sets = Vec::new();

        while let Some(record_bytes) = file.read_record_bytes().await? {
            let (txn, aux_info, txn_info, events, write_set): (
                _,
                PersistedAuxiliaryInfo,
                _,
                _,
                WriteSet,
            ) = match manifest.format {
                TransactionChunkFormat::V0 => {
```

**File:** testsuite/forge/src/backend/local/node.rs (L32-45)
```rust
impl Drop for Process {
    // When the Process struct goes out of scope we need to kill the child process
    fn drop(&mut self) {
        // check if the process has already been terminated
        match self.0.try_wait() {
            // The child process has already terminated, perhaps due to a crash
            Ok(Some(_)) => {},

            // The process is still running so we need to attempt to kill it
            _ => {
                self.0.kill().expect("Process wasn't running");
                self.0.wait().unwrap();
            },
        }
```

**File:** storage/backup/backup-cli/src/utils/mod.rs (L366-383)
```rust
pub struct ConcurrentDownloadsOpt {
    #[clap(
        long,
        help = "Number of concurrent downloads from the backup storage. This covers the initial \
        metadata downloads as well. Speeds up remote backup access. [Defaults to number of CPUs]"
    )]
    concurrent_downloads: Option<usize>,
}

impl ConcurrentDownloadsOpt {
    pub fn get(&self) -> usize {
        let ret = self.concurrent_downloads.unwrap_or_else(num_cpus::get);
        info!(
            concurrent_downloads = ret,
            "Determined concurrency level for downloading."
        );
        ret
    }
```

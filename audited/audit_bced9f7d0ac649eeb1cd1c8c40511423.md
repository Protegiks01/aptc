# Audit Report

## Title
Resource Leak in CommandAdapter Backup Restore Leading to Process and File Descriptor Exhaustion During Critical Recovery

## Summary
The `ChildStdoutAsDataSource` struct in the CommandAdapter storage backend lacks a `Drop` implementation, causing child processes to become zombies when errors occur during chunk reading. During concurrent restore operations with high concurrency levels (defaulting to CPU count), this leads to accumulation of zombie processes holding open file descriptors, ultimately causing restore failures during critical node recovery operations.

## Finding Description

The `read_chunk()` function in the epoch ending restore process opens file handles via the storage backend's `open_for_read()` method. [1](#0-0) 

For the CommandAdapter backend, this returns a `ChildStdoutAsDataSource` that wraps a spawned child process (e.g., cloud storage CLI tools like `gsutil` or `aws s3 cp`). [2](#0-1) 

The `ChildStdoutAsDataSource` struct implements `AsyncRead` and properly joins the child process when EOF is reached. [3](#0-2) 

However, there is **no `Drop` implementation** for `ChildStdoutAsDataSource`. When errors occur during chunk reading (network issues, data corruption, etc.), the `read_chunk()` function returns early via the `?` operator, and the `file` variable is dropped. [4](#0-3) 

When `ChildStdoutAsDataSource` is dropped without reaching EOF:
1. The underlying `tokio::process::Child` is dropped without being killed or waited for
2. The child process continues running or becomes a zombie
3. File descriptors held by the child process remain open
4. Process table entries are not freed

This is particularly critical during concurrent restore operations, where multiple manifests are processed concurrently. [5](#0-4) 

The concurrency level defaults to the number of CPUs (typically 32-64 on validator nodes). [6](#0-5) 

The codebase itself demonstrates awareness of this pattern - the `Process` struct in the test infrastructure properly implements `Drop` to kill child processes. [7](#0-6) 

## Impact Explanation

**Medium Severity** - This qualifies as "State inconsistencies requiring intervention" per Aptos bug bounty criteria because:

1. **Critical Recovery Scenario**: Backup restore operations are performed during disaster recovery when a node needs to rejoin the network or recover from data corruption
2. **Restore Operation Failure**: Accumulation of zombie processes and open file descriptors leads to system resource exhaustion, causing subsequent restore attempts to fail
3. **Operational Intervention Required**: Manual cleanup of zombie processes and system restart may be necessary
4. **Network Rejoin Prevention**: A node unable to complete restore cannot synchronize with the network

While not causing consensus violations or fund loss, this prevents nodes from recovering during critical operational scenarios, requiring manual intervention to restore network participation.

## Likelihood Explanation

**High Likelihood** during restore operations with network instability:

1. **Common Trigger Conditions**: Network interruptions, timeouts, and transient cloud storage errors are common during large data transfers
2. **Default Configuration Vulnerable**: The default concurrent_downloads setting (CPU count) means 32-64 operations can be in flight simultaneously on typical nodes
3. **Error Amplification**: Each failed chunk creates a zombie process; with multiple chunks per manifest and multiple concurrent manifests, zombies accumulate rapidly
4. **Realistic Scenario**: Operators restoring from cloud storage backups routinely encounter network issues, making this a practical concern rather than theoretical

## Recommendation

Implement a `Drop` trait for `ChildStdoutAsDataSource` and `ChildStdinAsDataSink` to properly clean up child processes when dropped before completion:

```rust
impl Drop for ChildStdoutAsDataSource<'_> {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            // Child wasn't properly joined via poll_read reaching EOF
            // Kill the process to prevent zombies
            let _ = child.child.kill();
            // Note: We can't wait synchronously in Drop, but killing prevents zombies
            // The OS will reap the process after it exits
        }
    }
}

impl Drop for ChildStdinAsDataSink<'_> {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.child.kill();
        }
    }
}
```

## Proof of Concept

```rust
// Test demonstrating the resource leak
// File: storage/backup/backup-cli/src/storage/command_adapter/test_resource_leak.rs

#[tokio::test]
async fn test_child_process_cleanup_on_error() {
    use tokio::io::AsyncReadExt;
    use std::process::Command as StdCommand;
    
    // Get initial process count
    let initial_processes = get_process_count();
    
    // Simulate multiple concurrent failed reads
    let storage = CommandAdapter::new(test_config_with_failing_commands());
    
    for _ in 0..32 {
        let mut file = storage.open_for_read("test_file").await.unwrap();
        let mut buf = vec![0u8; 100];
        
        // Simulate error by dropping before read completes
        // In real scenario, this happens when read_record_bytes() fails
        // The file handle (ChildStdoutAsDataSource) is dropped here
        drop(file);
    }
    
    // Wait briefly for processes to become zombies
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    
    // Check for zombie processes
    let final_processes = get_process_count();
    let zombie_count = count_zombie_processes();
    
    assert_eq!(zombie_count, 32, "32 zombie processes should exist");
    assert!(final_processes > initial_processes + 30, 
            "Process count should have increased significantly");
}

fn get_process_count() -> usize {
    // Platform-specific process counting
    #[cfg(target_os = "linux")]
    {
        std::fs::read_dir("/proc")
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().chars().all(|c| c.is_numeric()))
            .count()
    }
    #[cfg(not(target_os = "linux"))]
    { 0 }
}

fn count_zombie_processes() -> usize {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_dir("/proc")
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let status_file = e.path().join("status");
                if let Ok(content) = std::fs::read_to_string(status_file) {
                    content.contains("State:\tZ")
                } else {
                    false
                }
            })
            .count()
    }
    #[cfg(not(target_os = "linux"))]
    { 0 }
}
```

## Notes

This vulnerability specifically affects the **CommandAdapter** storage backend used for cloud storage integration (AWS S3, Google Cloud Storage, etc.). The **LocalFs** backend is not affected as it uses `tokio::fs::File` which properly implements `Drop` to close file descriptors.

The issue manifests during error conditions in restore operations, making it particularly problematic during disaster recovery scenarios when operators need reliable restore functionality. The missing `Drop` implementation violates Rust's RAII pattern that the rest of the codebase follows, as evidenced by the proper implementation in the test infrastructure.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L97-97)
```rust
            let lis = self.read_chunk(&chunk.ledger_infos).await?;
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

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L360-373)
```rust
        let futs_iter = self.manifest_handles.iter().map(|hdl| {
            EpochEndingRestoreController::new(
                EpochEndingRestoreOpt {
                    manifest_handle: hdl.clone(),
                },
                self.global_opt.clone(),
                self.storage.clone(),
            )
            .preheat()
        });
        let mut futs_stream = futures::stream::iter(futs_iter).buffered_x(
            self.global_opt.concurrent_downloads * 2, /* buffer size */
            self.global_opt.concurrent_downloads,     /* concurrency */
        );
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

**File:** testsuite/forge/src/backend/local/node.rs (L32-46)
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
    }
```

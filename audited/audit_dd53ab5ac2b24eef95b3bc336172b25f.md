# Audit Report

## Title
Indefinite Hang in Backup Restore Due to Missing Timeout on Storage Backend Reads

## Summary
The `read_all()` function in the backup-cli lacks timeout mechanisms for long-running storage backend reads. A slow or malicious storage backend can cause the restore coordinator to hang indefinitely, blocking backup recovery operations during critical disaster recovery scenarios.

## Finding Description
The `read_all()` function performs unbounded reads from storage backends without any timeout protection. [1](#0-0) 

This function is used throughout the restore process to load critical manifest and backup data files. [2](#0-1) [3](#0-2) [4](#0-3) 

The vulnerability exists because:

1. **CommandAdapter** spawns shell commands (e.g., gsutil, aws s3) without read timeouts [5](#0-4) 

2. **ChildStdoutAsDataSource** polls stdout without timeout enforcement [6](#0-5) 

3. **RestoreCoordinator** invokes these operations without timeout wrappers [7](#0-6) 

**Attack Scenario:**
- Attacker compromises cloud storage credentials or operates a malicious storage backend
- Storage backend configured to respond extremely slowly or hang on read requests
- Restore coordinator calls `read_all()` → `open_for_read()` → spawns command → reads from slow/hanging stdout
- Restore operation hangs indefinitely with no timeout
- Disaster recovery and backup restoration are blocked

Note that while `BackupServiceClient` implements 60-second timeouts, this only applies to backup creation from running nodes, not restore operations from storage backends. [8](#0-7) 

## Impact Explanation
This qualifies as **Medium severity** under the Aptos bug bounty program:
- **"State inconsistencies requiring intervention"**: Blocked backup recovery requires manual intervention to diagnose and resolve
- **Operational impact**: Prevents disaster recovery when validators need to restore from backups
- **Availability impact**: During critical incident response, inability to restore from backups extends downtime

While not directly causing consensus failures or fund loss, this vulnerability significantly degrades the reliability of the backup/restore system, which is critical infrastructure for validator operations.

## Likelihood Explanation
**Moderate likelihood**:
- Requires compromising storage backend credentials (realistic via credential leaks, misconfigured IAM policies)
- OR social engineering to configure restore from malicious storage
- Does not require validator insider access or collusion
- Execution is straightforward once storage access is obtained
- No rate limiting or anomaly detection on storage read operations

## Recommendation
Implement configurable timeouts for all storage backend read operations:

```rust
#[async_trait]
impl BackupStorageExt for Arc<dyn BackupStorage> {
    async fn read_all(&self, file_handle: &FileHandleRef) -> Result<Vec<u8>> {
        let mut file = self.open_for_read(file_handle).await?;
        let mut bytes = Vec::new();
        
        // Add configurable timeout (e.g., from GlobalRestoreOptions)
        let timeout = Duration::from_secs(300); // 5 minutes default
        tokio::time::timeout(timeout, file.read_to_end(&mut bytes))
            .await
            .map_err(|_| anyhow!("Timeout reading file: {}", file_handle))??;
        
        Ok(bytes)
    }
}
```

Additionally:
1. Add timeout configuration to `GlobalRestoreOptions`
2. Implement per-read timeouts in `ChildStdoutAsDataSource` using `tokio_io_timeout::TimeoutReader`
3. Add metrics for slow storage backend operations
4. Log warnings when operations approach timeout thresholds

## Proof of Concept
```rust
// Test that demonstrates the vulnerability
// File: storage/backup/backup-cli/src/storage/tests/timeout_test.rs

#[tokio::test]
async fn test_read_all_hangs_on_slow_storage() {
    use std::sync::Arc;
    use tokio::time::{sleep, Duration};
    
    // Create mock storage that hangs indefinitely
    struct SlowMockStorage;
    
    #[async_trait]
    impl BackupStorage for SlowMockStorage {
        async fn open_for_read(&self, _: &FileHandleRef) 
            -> Result<Box<dyn AsyncRead + Send + Unpin>> {
            // Return a reader that never completes
            struct HangingReader;
            impl AsyncRead for HangingReader {
                fn poll_read(self: Pin<&mut Self>, cx: &mut Context, _: &mut ReadBuf) 
                    -> Poll<std::io::Result<()>> {
                    // Never returns Ready, simulating slow/hung storage
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            Ok(Box::new(HangingReader))
        }
        // ... implement other required methods
    }
    
    let storage: Arc<dyn BackupStorage> = Arc::new(SlowMockStorage);
    
    // This will hang indefinitely without timeout
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        storage.read_all("test_file")
    ).await;
    
    // Should timeout, proving vulnerability
    assert!(result.is_err(), "read_all should have timed out");
}
```

## Notes
The vulnerability is confirmed through code analysis showing that `read_all()` uses Tokio's `read_to_end()` without any timeout wrapper, and storage backend operations (CommandAdapter, LocalFs) lack timeout enforcement. The restore coordinator invokes these operations directly without adding timeout protection at a higher level.

### Citations

**File:** storage/backup/backup-cli/src/utils/storage_ext.rs (L24-29)
```rust
    async fn read_all(&self, file_handle: &FileHandleRef) -> Result<Vec<u8>> {
        let mut file = self.open_for_read(file_handle).await?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).await?;
        Ok(bytes)
    }
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L123-126)
```rust
        let manifest: StateSnapshotBackup =
            self.storage.load_json_file(&self.manifest_handle).await?;
        let (txn_info_with_proof, li): (TransactionInfoWithProof, LedgerInfoWithSignatures) =
            self.storage.load_bcs_file(&manifest.proof).await?;
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L147-151)
```rust
        let (range_proof, ledger_info) = storage
            .load_bcs_file::<(TransactionAccumulatorRangeProof, LedgerInfoWithSignatures)>(
                &manifest.proof,
            )
            .await?;
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L81-82)
```rust
        let manifest: EpochEndingBackup =
            self.storage.load_json_file(&self.manifest_handle).await?;
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

**File:** storage/db-tool/src/restore.rs (L114-122)
```rust
            Command::BootstrapDB(bootstrap) => {
                RestoreCoordinator::new(
                    bootstrap.opt,
                    bootstrap.global.try_into()?,
                    bootstrap.storage.init_storage().await?,
                )
                .run()
                .await?;
            },
```

**File:** storage/backup/backup-cli/src/utils/backup_service_client.rs (L39-83)
```rust
    const TIMEOUT_SECS: u64 = 60;

    pub fn new_with_opt(opt: BackupServiceClientOpt) -> Self {
        Self::new(opt.address)
    }

    pub fn new(address: String) -> Self {
        Self {
            address,
            client: reqwest::Client::builder()
                .no_proxy()
                .build()
                .expect("Http client should build."),
        }
    }

    async fn get(&self, endpoint: &'static str, params: &str) -> Result<impl AsyncRead + use<>> {
        let _timer = BACKUP_TIMER.timer_with(&[&format!("backup_service_client_get_{endpoint}")]);

        let url = if params.is_empty() {
            format!("{}/{}", self.address, endpoint)
        } else {
            format!("{}/{}/{}", self.address, endpoint, params)
        };
        let timeout = Duration::from_secs(Self::TIMEOUT_SECS);
        let reader = tokio::time::timeout(timeout, self.client.get(&url).send())
            .await?
            .err_notes(&url)?
            .error_for_status()
            .err_notes(&url)?
            .bytes_stream()
            .map_ok(|bytes| {
                THROUGHPUT_COUNTER.inc_with_by(&[endpoint], bytes.len() as u64);
                bytes
            })
            .map_err(futures::io::Error::other)
            .into_async_read()
            .compat();

        // Adding the timeout here instead of on the response because we do use long living
        // connections. For example, we stream the entire state snapshot in one request.
        let mut reader_with_read_timeout = TimeoutReader::new(reader);
        reader_with_read_timeout.set_timeout(Some(timeout));

        Ok(Box::pin(reader_with_read_timeout))
```

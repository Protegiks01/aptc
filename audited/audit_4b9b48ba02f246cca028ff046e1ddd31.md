# Audit Report

## Title
Missing Timeout Handling in Database Restore Operations Can Cause Indefinite Validator Initialization Hangs

## Summary
The database restore operations in `storage/db-tool/src/restore.rs` and related coordinator files lack timeout handling on async network operations, allowing indefinite hangs during validator initialization when backup storage is slow or unresponsive.

## Finding Description

The `Command::run()` function in the restore tool performs multiple async operations without any timeout protection: [1](#0-0) 

These operations include:
1. **Storage initialization** - reads configuration files and initializes backup storage connections
2. **Metadata synchronization** - lists and downloads metadata files from remote storage
3. **State snapshot restoration** - downloads and processes large state snapshot files
4. **Transaction restoration** - downloads and replays transaction history
5. **Epoch ending restoration** - downloads epoch proofs and ledger infos

All these operations involve network I/O through the `BackupStorage` trait, which can use `CommandAdapter` to spawn shell commands that interact with remote storage (S3, GCS, etc.): [2](#0-1) 

The `RestoreCoordinator::run_impl()` performs extensive network operations without timeouts: [3](#0-2) 

The metadata sync operation lists remote files and downloads them concurrently: [4](#0-3) 

State snapshot and transaction restore controllers perform similar unbounded operations: [5](#0-4) [6](#0-5) 

The `BootstrapDb` CLI command, used for validator initialization, directly awaits these operations: [7](#0-6) 

**Hang Scenarios:**
1. Remote backup storage (S3/GCS) experiencing high latency or timeouts
2. DNS resolution failures for storage endpoints
3. TCP connection hangs without FIN/RST packets
4. Shell commands in `CommandAdapter` blocking indefinitely
5. Malicious backup storage serving data at extremely slow rates
6. Network middleware (proxies, firewalls) dropping packets silently

## Impact Explanation

This issue qualifies as **High Severity** under the Aptos bug bounty program criteria for "Validator node slowdowns" or potentially **Medium Severity** for "State inconsistencies requiring intervention."

**Validator Initialization Failure:**
- Validators use the `BootstrapDb` command to restore their database from backup before starting
- In Kubernetes deployments, this runs as an init container that must complete before the validator pod starts
- An indefinite hang prevents the validator from ever initializing and joining the network
- Operators must manually intervene to kill the process and investigate

**Network Liveness Impact:**
- If multiple validators attempt to bootstrap simultaneously during a network incident and all hang, network liveness is reduced
- New validators cannot join the validator set
- Existing validators cannot recover from disk failures

**Comparison with Existing Timeout Handling:**
The codebase demonstrates awareness of timeout requirements in `backup_service_client.rs`: [8](#0-7) 

This shows timeouts are used elsewhere but were not applied to restore operations.

## Likelihood Explanation

**High Likelihood** - This will occur in production environments:

1. **Network failures are common** - Validators operate in diverse network environments with varying connectivity quality
2. **Cloud storage outages happen** - AWS S3, Google Cloud Storage experience periodic degradations
3. **Operator error is frequent** - Misconfigured backup storage URLs, incorrect credentials, firewall rules
4. **No automatic recovery** - Without timeouts, the process never fails gracefully, requiring manual intervention
5. **Critical path operation** - This affects validator initialization, a mandatory step for node operation

The issue is particularly problematic because:
- No progress indication after initial logs
- No maximum wait time configured
- No automatic retry with backoff
- Operators cannot distinguish between "slow but progressing" vs "completely hung"

## Recommendation

Add comprehensive timeout handling to all async network operations in the restore flow:

**1. Add global timeout configuration:**
```rust
// In GlobalRestoreOpt
#[clap(
    long,
    default_value = "3600",
    help = "Timeout in seconds for individual backup storage operations"
)]
pub operation_timeout_secs: u64,

#[clap(
    long, 
    default_value = "86400",
    help = "Total timeout in seconds for the entire restore operation"
)]
pub total_timeout_secs: u64,
```

**2. Wrap all storage operations with timeouts:**
```rust
use tokio::time::{timeout, Duration};

// In Command::run()
let storage = timeout(
    Duration::from_secs(300),
    storage.init_storage()
).await
    .map_err(|_| anyhow!("Storage initialization timed out after 300s"))??;

// In RestoreCoordinator
let result = timeout(
    Duration::from_secs(self.global_opt.total_timeout_secs),
    self.run_impl()
).await
    .map_err(|_| anyhow!("Restore operation timed out"))?;
```

**3. Add per-file operation timeouts:**
```rust
// In storage operations
async fn open_for_read_with_timeout(
    &self,
    file_handle: &FileHandle,
    timeout_secs: u64,
) -> Result<Box<dyn AsyncRead + Send + Unpin>> {
    timeout(
        Duration::from_secs(timeout_secs),
        self.open_for_read(file_handle)
    ).await
        .map_err(|_| anyhow!("File read timed out: {}", file_handle))?
}
```

**4. Add progress monitoring and heartbeats:**
```rust
// Track last progress timestamp
let last_progress = Arc::new(Mutex::new(Instant::now()));

// Update on each chunk/file processed
// Check periodically and fail if no progress for too long
```

## Proof of Concept

```rust
// File: storage/backup/backup-cli/src/storage/mock_hanging_storage.rs
use crate::storage::{BackupStorage, FileHandle, BackupHandle, ShellSafeName, TextLine};
use async_trait::async_trait;
use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};

/// Mock storage that hangs on operations to demonstrate the timeout issue
pub struct HangingMockStorage;

#[async_trait]
impl BackupStorage for HangingMockStorage {
    async fn create_backup(&self, _name: &ShellSafeName) -> Result<BackupHandle> {
        // Simulate indefinite hang
        tokio::time::sleep(tokio::time::Duration::from_secs(u64::MAX)).await;
        unreachable!()
    }

    async fn open_for_read(
        &self,
        _file_handle: &FileHandle,
    ) -> Result<Box<dyn AsyncRead + Send + Unpin>> {
        // Simulate network read hang
        tokio::time::sleep(tokio::time::Duration::from_secs(u64::MAX)).await;
        unreachable!()
    }

    async fn list_metadata_files(&self) -> Result<Vec<FileHandle>> {
        // Simulate hanging DNS resolution or slow API response
        tokio::time::sleep(tokio::time::Duration::from_secs(u64::MAX)).await;
        unreachable!()
    }

    // ... implement other methods similarly
}

// Test demonstrating the hang
#[tokio::test]
async fn test_restore_hangs_without_timeout() {
    use std::time::Duration;
    
    let storage = Arc::new(HangingMockStorage);
    let restore_coordinator = RestoreCoordinator::new(
        RestoreCoordinatorOpt::default(),
        GlobalRestoreOptions::default(),
        storage,
    );
    
    // This will hang indefinitely without timeout
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        restore_coordinator.run()
    ).await;
    
    // Expect timeout, demonstrating the vulnerability
    assert!(result.is_err(), "Restore should have timed out but didn't");
}
```

## Notes

This vulnerability represents a violation of the **Resource Limits** invariant (#9): "All operations must respect gas, storage, and computational limits" - extended to include time limits. The restore operation is a critical initialization path that should have bounded execution time to ensure validators can recover from failures reliably.

The fix should be applied across all async operations in the backup/restore subsystem to ensure consistent timeout behavior throughout the initialization flow.

### Citations

**File:** storage/db-tool/src/restore.rs (L66-127)
```rust
    pub async fn run(self) -> Result<()> {
        match self {
            Command::Oneoff(oneoff) => {
                match oneoff {
                    Oneoff::EpochEnding {
                        storage,
                        opt,
                        global,
                    } => {
                        EpochEndingRestoreController::new(
                            opt,
                            global.try_into()?,
                            storage.init_storage().await?,
                        )
                        .run(None)
                        .await?;
                    },
                    Oneoff::StateSnapshot {
                        storage,
                        opt,
                        global,
                    } => {
                        StateSnapshotRestoreController::new(
                            opt,
                            global.try_into()?,
                            storage.init_storage().await?,
                            None, /* epoch_history */
                        )
                        .run()
                        .await?;
                    },
                    Oneoff::Transaction {
                        storage,
                        opt,
                        global,
                    } => {
                        TransactionRestoreController::new(
                            opt,
                            global.try_into()?,
                            storage.init_storage().await?,
                            None, /* epoch_history */
                            VerifyExecutionMode::NoVerify,
                        )
                        .run()
                        .await?;
                    },
                }
            },
            Command::BootstrapDB(bootstrap) => {
                RestoreCoordinator::new(
                    bootstrap.opt,
                    bootstrap.global.try_into()?,
                    bootstrap.storage.init_storage().await?,
                )
                .run()
                .await?;
            },
        }

        Ok(())
    }
}
```

**File:** storage/backup/backup-cli/src/coordinators/restore.rs (L71-89)
```rust
    pub async fn run(self) -> Result<()> {
        info!("Restore coordinator started.");
        COORDINATOR_START_TS.set(unix_timestamp_sec());

        let ret = self.run_impl().await;

        if let Err(e) = &ret {
            error!(
                error = ?e,
                "Restore coordinator failed."
            );
            COORDINATOR_FAIL_TS.set(unix_timestamp_sec());
        } else {
            info!("Restore coordinator exiting with success.");
            COORDINATOR_SUCC_TS.set(unix_timestamp_sec());
        }

        ret
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

**File:** storage/backup/backup-cli/src/metadata/cache.rs (L90-122)
```rust
pub async fn sync_and_load(
    opt: &MetadataCacheOpt,
    storage: Arc<dyn BackupStorage>,
    concurrent_downloads: usize,
) -> Result<MetadataView> {
    let timer = Instant::now();
    let cache_dir = opt.cache_dir();
    create_dir_all(&cache_dir).await.err_notes(&cache_dir)?; // create if not present already

    // List cached metadata files.
    let dir = read_dir(&cache_dir).await.err_notes(&cache_dir)?;
    let local_hashes_vec: Vec<String> = ReadDirStream::new(dir)
        .filter_map(|entry| match entry {
            Ok(e) => {
                let path = e.path();
                let file_name = path.file_name()?.to_str()?;
                Some(file_name.to_string())
            },
            Err(_) => None,
        })
        .collect()
        .await;
    let local_hashes: HashSet<_> = local_hashes_vec.into_iter().collect();
    // List remote metadata files.
    let mut remote_file_handles = storage.list_metadata_files().await?;
    if remote_file_handles.is_empty() {
        initialize_identity(&storage).await.context(
            "\
            Backup storage appears empty and failed to put in identity metadata, \
            no point to go on. If you believe there is content in the backup, check authentication.\
            ",
        )?;
        remote_file_handles = storage.list_metadata_files().await?;
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L113-127)
```rust
    async fn run_impl(self) -> Result<()> {
        if self.version > self.target_version {
            warn!(
                "Trying to restore state snapshot to version {}, which is newer than the target version {}, skipping.",
                self.version,
                self.target_version,
            );
            return Ok(());
        }

        let manifest: StateSnapshotBackup =
            self.storage.load_json_file(&self.manifest_handle).await?;
        let (txn_info_with_proof, li): (TransactionInfoWithProof, LedgerInfoWithSignatures) =
            self.storage.load_bcs_file(&manifest.proof).await?;
        txn_info_with_proof.verify(li.ledger_info(), manifest.version)?;
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L100-112)
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
```

**File:** crates/aptos/src/node/mod.rs (L1342-1356)
```rust
    async fn execute(self) -> CliTypedResult<()> {
        let storage = self.storage.init_storage().await?;
        // hack: get around this error, related to use of `async_trait`:
        //   error: higher-ranked lifetime error
        //   ...
        //   = note: could not prove for<'r, 's> Pin<Box<impl futures::Future<Output = std::result::Result<(), CliError>>>>: CoerceUnsized<Pin<Box<(dyn futures::Future<Output = std::result::Result<(), CliError>> + std::marker::Send + 's)>>>
        tokio::task::spawn_blocking(|| {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime
                .block_on(RestoreCoordinator::new(self.opt, self.global.try_into()?, storage).run())
        })
        .await
        .unwrap()?;
        Ok(())
    }
```

**File:** storage/backup/backup-cli/src/utils/backup_service_client.rs (L63-84)
```rust
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
    }
```

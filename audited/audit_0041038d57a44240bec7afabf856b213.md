# Audit Report

## Title
Lack of Application-Level Locking Mechanism for Concurrent Database Restore Operations

## Summary
The database restore functionality in `storage/db-tool/src/restore.rs` relies solely on RocksDB's internal file locking to prevent concurrent restore operations. There is no application-level locking mechanism, advisory lock file, or explicit check to prevent multiple restore processes from running simultaneously against the same database directory. This creates a risk of database corruption in scenarios where RocksDB's file locking fails or is bypassed.

## Finding Description
The `Command::run()` function in the restore module initiates database restoration by opening the target database via `AptosDB::open_kv_only()` in write mode. [1](#0-0) 

The database opening occurs during the conversion of `GlobalRestoreOpt` to `GlobalRestoreOptions`, where `AptosDB::open_kv_only()` is called with `readonly=false`. [2](#0-1) 

The only protection against concurrent database access is RocksDB's internal file locking mechanism, which creates a LOCK file in the database directory. [3](#0-2) 

RocksDB errors (including lock acquisition failures) are converted to generic `AptosDbError::OtherRocksDbError` and propagated up the call stack. [4](#0-3) 

However, RocksDB file locking can fail in several scenarios:
1. **Network File Systems**: File locks may not work correctly on NFS or CIFS, which are common in cloud/container deployments for persistent storage
2. **Stale lock files**: Process crashes may leave stale LOCK files that don't properly prevent concurrent access
3. **Manual intervention**: Operators might delete LOCK files during troubleshooting, inadvertently allowing concurrent access
4. **Container orchestration**: Kubernetes pod restarts or volume remounts may not properly preserve lock state

The code even acknowledges the importance of preventing concurrent restores with a comment stating "This tool only guarantees resume from previous in-progress restore." [5](#0-4)  However, no actual enforcement mechanism exists beyond RocksDB's file lock.

If two restore operations run concurrently against the same database:
- Both processes write to the same RocksDB column families simultaneously
- Write-ahead logs (WAL) and SSTable files can become corrupted
- Merkle tree state and key-value state can become inconsistent
- The resulting database may contain partial data from both restore operations

## Impact Explanation
This is a **High Severity** vulnerability according to Aptos bug bounty criteria because it can cause:

1. **State inconsistencies requiring intervention**: Concurrent restores can corrupt the database, requiring manual recovery or restoration from a different backup
2. **Validator node operational issues**: A corrupted database after restore could cause validator nodes to crash, fail consensus participation, or serve incorrect state data
3. **Potential consensus divergence**: If different validators restore to slightly different states due to corruption, this could cause consensus failures

While not directly causing fund loss, database corruption during restore operations represents a significant operational risk that violates the "State Consistency" invariant (State transitions must be atomic and verifiable via Merkle proofs).

## Likelihood Explanation
The likelihood is **Medium to High** because:

1. **Common operational scenarios**: Database restores are frequent operations for:
   - New validator node setup
   - Disaster recovery
   - Node migration
   - Testing and validation

2. **Realistic failure modes**: NFS file locking issues are well-documented in distributed systems. Many blockchain deployments use network storage for cost and flexibility reasons.

3. **Automation risks**: Kubernetes CronJobs, automated backup/restore scripts, or CI/CD pipelines might accidentally trigger concurrent restores due to timing issues or misconfiguration.

4. **Human error**: Operators troubleshooting a stuck restore might manually delete the LOCK file or start a second restore process without realizing the first is still running.

## Recommendation
Implement a defense-in-depth approach with multiple layers of protection:

1. **Add an application-level advisory lock file** before attempting to open the database:
   - Create a `.aptos-restore.lock` file in the target database directory
   - Use exclusive file locking (similar to the existing `FileLock` implementation) [6](#0-5) 
   - Check for this lock file before starting any restore operation
   - Provide clear error messages when a restore is already in progress

2. **Add explicit validation** in `GlobalRestoreOpt::try_from()`:
   ```rust
   // Before opening the database, check for an existing restore lock
   let lock_file_path = db_dir.join(".aptos-restore.lock");
   let _restore_lock = FileLock::lock_exclusive(&lock_file_path)
       .context("Another restore operation is already in progress for this database directory")?;
   ```

3. **Improve error handling** to distinguish lock acquisition failures from other database errors and provide actionable guidance to operators.

4. **Add logging** to track when restore operations start and complete, making it easier to detect concurrent operations.

## Proof of Concept
```rust
// Simulated concurrent restore test (conceptual - requires actual test infrastructure)
#[tokio::test]
async fn test_concurrent_restore_prevention() {
    let db_dir = TempPath::new();
    
    // Create two GlobalRestoreOpt instances pointing to the same directory
    let opt1 = GlobalRestoreOpt {
        db_dir: Some(db_dir.path().to_path_buf()),
        target_version: Some(1000),
        ..Default::default()
    };
    
    let opt2 = GlobalRestoreOpt {
        db_dir: Some(db_dir.path().to_path_buf()),
        target_version: Some(2000),
        ..Default::default()
    };
    
    // Spawn two concurrent restore attempts
    let handle1 = tokio::spawn(async move {
        let restore_options: GlobalRestoreOptions = opt1.try_into()?;
        // First restore should succeed
        Ok::<_, anyhow::Error>(())
    });
    
    let handle2 = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let restore_options: GlobalRestoreOptions = opt2.try_into()?;
        // Second restore should fail with lock error
        Ok::<_, anyhow::Error>(())
    });
    
    // On systems with proper RocksDB locking, handle2 should fail
    // On NFS or with stale locks, both might succeed, causing corruption
    let (result1, result2) = tokio::join!(handle1, handle2);
    
    // EXPECTED: result2 should be Err (lock held)
    // ACTUAL (on NFS): both might succeed, corrupting database
}
```

**Notes**
The absence of application-level locking for concurrent restore prevention represents a significant gap in the defense-in-depth strategy for a critical blockchain operation. While RocksDB's file locking provides baseline protection, it is insufficient for production blockchain deployments that may use network file systems, container orchestration, or face operational errors. The restore operation's criticality (as acknowledged by the code comments) warrants explicit, application-level concurrency control beyond relying solely on database engine internals.

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

**File:** storage/backup/backup-cli/src/utils/mod.rs (L305-315)
```rust
            let restore_handler = Arc::new(AptosDB::open_kv_only(
                StorageDirPaths::from_path(db_dir),
                false,                       /* read_only */
                NO_OP_STORAGE_PRUNER_CONFIG, /* pruner config */
                opt.rocksdb_opt.clone().into(),
                false, /* indexer */
                BUFFERED_STATE_TARGET_ITEMS,
                DEFAULT_MAX_NUM_NODES_PER_LRU_CACHE_SHARD,
                internal_indexer_db,
            )?)
            .get_restore_handler();
```

**File:** storage/schemadb/src/lib.rs (L141-193)
```rust
    fn open_cf_impl(
        db_opts: &Options,
        path: impl AsRef<Path>,
        name: &str,
        cfds: Vec<ColumnFamilyDescriptor>,
        open_mode: OpenMode,
    ) -> DbResult<DB> {
        // ignore error, since it'll fail to list cfs on the first open
        let existing_cfs: HashSet<String> = rocksdb::DB::list_cf(db_opts, path.de_unc())
            .unwrap_or_default()
            .into_iter()
            .collect();
        let requested_cfs: HashSet<String> =
            cfds.iter().map(|cfd| cfd.name().to_string()).collect();
        let missing_cfs: HashSet<&str> = requested_cfs
            .difference(&existing_cfs)
            .map(|cf| {
                warn!("Missing CF: {}", cf);
                cf.as_ref()
            })
            .collect();
        let unrecognized_cfs = existing_cfs.difference(&requested_cfs);

        let all_cfds = cfds
            .into_iter()
            .chain(unrecognized_cfs.map(Self::cfd_for_unrecognized_cf));

        let inner = {
            use rocksdb::DB;
            use OpenMode::*;

            match open_mode {
                ReadWrite => DB::open_cf_descriptors(db_opts, path.de_unc(), all_cfds),
                ReadOnly => {
                    DB::open_cf_descriptors_read_only(
                        db_opts,
                        path.de_unc(),
                        all_cfds.filter(|cfd| !missing_cfs.contains(cfd.name())),
                        false, /* error_if_log_file_exist */
                    )
                },
                Secondary(secondary_path) => DB::open_cf_descriptors_as_secondary(
                    db_opts,
                    path.de_unc(),
                    secondary_path,
                    all_cfds,
                ),
            }
        }
        .into_db_res()?;

        Ok(Self::log_construct(name, open_mode, inner))
    }
```

**File:** storage/schemadb/src/lib.rs (L389-408)
```rust
fn to_db_err(rocksdb_err: rocksdb::Error) -> AptosDbError {
    match rocksdb_err.kind() {
        ErrorKind::Incomplete => AptosDbError::RocksDbIncompleteResult(rocksdb_err.to_string()),
        ErrorKind::NotFound
        | ErrorKind::Corruption
        | ErrorKind::NotSupported
        | ErrorKind::InvalidArgument
        | ErrorKind::IOError
        | ErrorKind::MergeInProgress
        | ErrorKind::ShutdownInProgress
        | ErrorKind::TimedOut
        | ErrorKind::Aborted
        | ErrorKind::Busy
        | ErrorKind::Expired
        | ErrorKind::TryAgain
        | ErrorKind::CompactionTooLarge
        | ErrorKind::ColumnFamilyDropped
        | ErrorKind::Unknown => AptosDbError::OtherRocksDbError(rocksdb_err.to_string()),
    }
}
```

**File:** storage/backup/backup-cli/src/coordinators/restore.rs (L114-115)
```rust
        info!("This tool only guarantees resume from previous in-progress restore. \
        If you want to restore a new DB, please either specify a new target db dir or delete previous in-progress DB in the target db dir.");
```

**File:** third_party/move/tools/move-package-cache/src/file_lock.rs (L1-100)
```rust
// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use fs2::FileExt;
use futures::FutureExt;
use std::{
    fs::{self, File},
    mem,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{pin, select, task};

/// A file-based lock to ensure exclusive access to certain resources.
///
/// This is used by the package cache to ensure only one process can mutate a cached repo, checkout,
/// or on-chain package at a time.
pub struct FileLock {
    file: Option<File>,
    path: PathBuf,
}

impl FileLock {
    /// Attempts to acquire an exclusive `FileLock`, with an optional alert callback.
    ///
    /// If the lock cannot be acquired within `alert_timeout`, the `alert_on_wait` callback
    /// is executed to notify the caller.
    pub async fn lock_with_alert_on_wait<P, F>(
        lock_path: P,
        alert_timeout: Duration,
        alert_on_wait: F,
    ) -> Result<Self>
    where
        P: AsRef<Path>,
        F: FnOnce(),
    {
        let lock_path = lock_path.as_ref().to_owned();

        let lock_fut = {
            let lock_path = lock_path.clone();

            task::spawn_blocking(move || -> Result<File> {
                let lock_file = File::create(&lock_path)?;
                lock_file.lock_exclusive()?;
                Ok(lock_file)
            })
        };

        let timeout = tokio::time::sleep(alert_timeout).fuse();

        pin!(lock_fut, timeout);

        let lock_file = select! {
            _ = &mut timeout => {
                alert_on_wait();
                lock_fut.await??
            },
            res = &mut lock_fut => res??,
        };

        Ok(Self {
            file: Some(lock_file),
            path: lock_path,
        })
    }
}

impl Drop for FileLock {
    /// Automatically releases the lock and removes the lock file when dropped.
    /// This makes the lock easy to use -- exclusive access is guaranteed as long as the lock is alive.
    fn drop(&mut self) {
        let file = self.file.take().expect("this should always succeed");
        mem::drop(file);
        _ = fs::remove_file(&self.path); // Best effort
    }
}


```

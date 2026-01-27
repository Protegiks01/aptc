# Audit Report

## Title
Backup Metadata Cache Poisoning: Missing Cryptographic Verification Enables Silent Backup Data Loss

## Summary
The backup metadata cache in `cache::sync_and_load()` lacks cryptographic verification (signatures, checksums, or HMACs), allowing an attacker with write access to the backup storage to inject malicious metadata files. This causes the `BackupCoordinator` to make incorrect backup decisions, skipping critical blockchain data and creating incomplete backups that cannot be used for disaster recovery. [1](#0-0) 

## Finding Description

The backup system uses metadata files (`.meta` files) stored in the backup storage to track which epochs, transactions, and state snapshots have been backed up. These metadata files are deserialized from JSON without any cryptographic verification.

**Attack Flow:**

1. **Metadata Download Without Verification**: The `sync_and_load()` function downloads metadata files from backup storage and deserializes them using `serde_json` with no authentication: [2](#0-1) 

The function specifically at lines 236-246 loads metadata from JSON with no verification: [3](#0-2) 

2. **Trusted Metadata Used for Backup Decisions**: The `BackupCoordinator` uses the metadata to determine where to start backing up: [4](#0-3) 

The coordinator trusts `backup_state.latest_epoch_ending_epoch`, `backup_state.latest_state_snapshot_epoch`, and `backup_state.latest_transaction_version` to initialize backup work streams.

3. **Attack Execution**: An attacker who compromises backup storage credentials (S3/GCS/Azure IAM) creates malicious metadata files claiming newer epochs/versions are already backed up: [5](#0-4) 

For example, creating `epoch_ending_5000-6000.meta` with:
```json
{"EpochEndingBackup":{"first_epoch":5000,"last_epoch":6000,"first_version":X,"last_version":Y,"manifest":"fake://handle"}}
```

4. **Silent Data Loss**: The coordinator skips backing up epochs 1-6000, creating gaps in the backup. When disaster recovery is needed, the backup is incomplete. [6](#0-5) 

The `backup_epoch_endings` function uses the poisoned `last_epoch_ending_epoch_in_backup` value to determine which epochs to back up next, skipping all previous epochs.

**Broken Invariants:**

This vulnerability breaks the implicit invariant that backup metadata accurately reflects backed-up blockchain state and that backups are a reliable source of truth for disaster recovery.

## Impact Explanation

**High Severity** - This vulnerability meets the "Significant protocol violations" criteria because:

1. **Backup Integrity Compromise**: The backup system is critical infrastructure for node operators. Poisoned metadata causes silent failures where backups appear complete but are actually missing critical data.

2. **Disaster Recovery Failure**: In a node failure scenario requiring restoration from backup:
   - The incomplete backup cannot restore the full blockchain state
   - Network availability is compromised if multiple nodes rely on the same poisoned backup
   - May require expensive full resync from genesis or other nodes

3. **Silent Attack**: The coordinator continues running without errors, making the attack undetectable until restoration is attempted.

4. **Cascading Impact**: If the poisoned backup is used as a source for other nodes or for verification, the corruption spreads.

While this doesn't directly cause fund theft or consensus violations, it compromises the availability and recoverability of the network, which is categorized as High severity in the bug bounty program.

## Likelihood Explanation

**Medium-High Likelihood:**

**Prerequisites:**
- Attacker must compromise backup storage credentials (S3/GCS/Azure IAM)
- This is realistic as cloud credentials are commonly targeted and sometimes misconfigured

**Complexity:**
- Low - Creating malicious JSON metadata files is trivial
- The attack is silent and difficult to detect
- No cryptographic skills required

**Real-World Scenarios:**
- Compromised cloud service credentials
- Insider threat from personnel with backup storage access
- Supply chain attacks on backup infrastructure
- Misconfigured IAM policies granting excessive permissions

## Recommendation

Implement cryptographic verification of metadata files using either:

**Option 1: HMAC-based Verification**
Add an HMAC to each metadata file using a secret key known only to the legitimate backup coordinator:

```rust
// In Metadata impl
pub fn to_authenticated_text_line(&self, hmac_key: &[u8]) -> Result<TextLine> {
    let json = serde_json::to_string(self)?;
    let mut mac = HmacSha256::new_from_slice(hmac_key)?;
    mac.update(json.as_bytes());
    let tag = mac.finalize().into_bytes();
    let authenticated = format!("{}|{}", json, hex::encode(tag));
    TextLine::new(&authenticated)
}

pub fn verify_and_parse(line: &str, hmac_key: &[u8]) -> Result<Self> {
    let parts: Vec<_> = line.split('|').collect();
    ensure!(parts.len() == 2, "Invalid authenticated metadata format");
    
    let mut mac = HmacSha256::new_from_slice(hmac_key)?;
    mac.update(parts[0].as_bytes());
    mac.verify_from_slice(&hex::decode(parts[1])?)?;
    
    Ok(serde_json::from_str(parts[0])?)
}
```

**Option 2: Digital Signatures**
Sign metadata files with the backup coordinator's private key and verify with the public key during loading.

**Additional Mitigations:**
1. Enable versioning on backup storage buckets to detect unauthorized modifications
2. Monitor backup storage for unexpected metadata file changes
3. Implement integrity checks comparing local node state with backup metadata periodically
4. Add alerting when backup storage state jumps unexpectedly

## Proof of Concept

```rust
// File: storage/backup/backup-cli/tests/metadata_poisoning_test.rs
use aptos_backup_cli::metadata::{Metadata, EpochEndingBackupMeta};
use aptos_backup_cli::metadata::cache::{MetadataCacheOpt, sync_and_load};
use aptos_backup_cli::storage::{BackupStorage, local_fs::LocalFs};
use aptos_temppath::TempPath;
use std::sync::Arc;

#[tokio::test]
async fn test_metadata_poisoning_attack() {
    // Setup: Create legitimate backup storage
    let backup_dir = TempPath::new();
    let storage = Arc::new(LocalFs::new(backup_dir.path()));
    
    // Attacker: Create malicious metadata claiming epoch 5000 is backed up
    let malicious_meta = Metadata::new_epoch_ending_backup(
        5000, 6000, 100000, 200000,
        "fake://nonexistent/manifest".to_string()
    );
    
    // Inject poisoned metadata into storage
    storage.save_metadata_line(
        &"epoch_ending_5000-6000.meta".parse().unwrap(),
        &malicious_meta.to_text_line().unwrap()
    ).await.unwrap();
    
    // Victim: Load metadata cache
    let cache_dir = TempPath::new();
    let cache_opt = MetadataCacheOpt::new(Some(cache_dir.path()));
    let view = sync_and_load(&cache_opt, storage, 1).await.unwrap();
    
    // Verify: The poisoned metadata affects backup state
    let backup_state = view.get_storage_state().unwrap();
    
    // VULNERABILITY: The coordinator will start backing up from epoch 6001,
    // skipping epochs 0-6000 which were never actually backed up!
    assert_eq!(backup_state.latest_epoch_ending_epoch, Some(6000));
    
    println!("ATTACK SUCCESSFUL: Backup coordinator will skip epochs 0-6000");
    println!("Backup state reports: {:?}", backup_state);
    
    // When disaster recovery is needed, the backup will be incomplete
    // and restoration will fail, causing potential network outage.
}

// Demonstration of impact on BackupCoordinator
#[tokio::test] 
async fn test_coordinator_skips_epochs() {
    // This test would show that BackupCoordinator.backup_epoch_endings()
    // uses the poisoned last_epoch_ending_epoch_in_backup value
    // and skips backing up the missing epochs.
    // Full implementation omitted for brevity but follows from:
    // storage/backup/backup-cli/src/coordinators/backup.rs lines 199-235
}
```

**To verify this vulnerability:**
1. Set up a backup coordinator with cloud storage
2. Manually inject a malicious `.meta` file with inflated epoch numbers
3. Observe that the coordinator skips backing up the claimed epochs
4. Attempt restoration and observe incomplete backup

**Notes**

This vulnerability requires the attacker to have write access to the backup storage, which is a significant but realistic prerequisite given the prevalence of cloud credential compromises. The lack of any cryptographic verification of metadata is a fundamental security gap in the backup system's design. While the actual backup data (manifests with waypoints and signatures) is verified during restoration, the metadata that tells the coordinator *which backups exist* has no protection, creating a critical weakness in the disaster recovery infrastructure.

### Citations

**File:** storage/db-tool/src/backup.rs (L227-235)
```rust
                OneShotQueryType::BackupStorageState(opt) => {
                    let view = cache::sync_and_load(
                        &opt.metadata_cache,
                        opt.storage.init_storage().await?,
                        opt.concurrent_downloads.get(),
                    )
                    .await?;
                    println!("{}", view.get_storage_state()?)
                },
```

**File:** storage/backup/backup-cli/src/metadata/cache.rs (L90-214)
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
    }
    let remote_file_handle_by_hash: HashMap<_, _> = remote_file_handles
        .iter()
        .map(|file_handle| (file_handle.file_handle_hash(), file_handle))
        .collect();
    let remote_hashes: HashSet<_> = remote_file_handle_by_hash.keys().cloned().collect();
    info!("Metadata files listed.");
    NUM_META_FILES.set(remote_hashes.len() as i64);

    // Sync local cache with remote metadata files.
    let stale_local_hashes = local_hashes.difference(&remote_hashes);
    let new_remote_hashes = remote_hashes.difference(&local_hashes).collect::<Vec<_>>();
    let up_to_date_local_hashes = local_hashes.intersection(&remote_hashes);

    for h in stale_local_hashes {
        let file = cache_dir.join(h);
        remove_file(&file).await.err_notes(&file)?;
        info!(file_name = h, "Deleted stale metadata file in cache.");
    }

    let num_new_files = new_remote_hashes.len();
    NUM_META_MISS.set(num_new_files as i64);
    NUM_META_DOWNLOAD.set(0);
    let futs = new_remote_hashes.iter().enumerate().map(|(i, h)| {
        let fh_by_h_ref = &remote_file_handle_by_hash;
        let storage_ref = storage.as_ref();
        let cache_dir_ref = &cache_dir;

        async move {
            let file_handle = fh_by_h_ref.get(*h).expect("In map.");
            let local_file = cache_dir_ref.join(*h);
            let local_tmp_file = cache_dir_ref.join(format!(".{}", *h));

            match download_file(storage_ref, file_handle, &local_tmp_file).await {
                Ok(_) => {
                    // rename to target file only if successful; stale tmp file caused by failure will be
                    // reclaimed on next run
                    tokio::fs::rename(local_tmp_file.clone(), local_file)
                        .await
                        .err_notes(local_tmp_file)?;
                    info!(
                        file_handle = file_handle,
                        processed = i + 1,
                        total = num_new_files,
                        "Metadata file downloaded."
                    );
                    NUM_META_DOWNLOAD.inc();
                },
                Err(e) => {
                    warn!(
                        file_handle = file_handle,
                        error = %e,
                        "Ignoring metadata file download error -- can be compactor removing files."
                    )
                },
            }

            Ok(())
        }
    });
    futures::stream::iter(futs)
        .buffered_x(
            concurrent_downloads * 2, /* buffer size */
            concurrent_downloads,     /* concurrency */
        )
        .collect::<Result<Vec<_>>>()
        .await?;

    info!("Loading all metadata files to memory.");
    // Load metadata from synced cache files.
    let mut metadata_vec = Vec::new();
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
    }
    info!(
        total_time = timer.elapsed().as_secs(),
        "Metadata cache loaded.",
    );

    Ok(MetadataView::new(metadata_vec, remote_file_handles))
}
```

**File:** storage/backup/backup-cli/src/metadata/cache.rs (L236-246)
```rust
impl<R: AsyncRead + Send + Unpin> LoadMetadataLines for R {
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

**File:** storage/backup/backup-cli/src/coordinators/backup.rs (L114-159)
```rust
    pub async fn run(&self) -> Result<()> {
        // Connect to both the local node and the backup storage.
        let backup_state = metadata::cache::sync_and_load(
            &self.metadata_cache_opt,
            Arc::clone(&self.storage),
            self.concurrent_downloads,
        )
        .await?
        .get_storage_state()?;

        // On new DbState retrieved:
        // `watch_db_state` informs `backup_epoch_endings` via channel 1,
        // and the latter informs the other backup type workers via channel 2, after epoch
        // ending is properly backed up, if necessary. This way, the epoch ending LedgerInfo needed
        // for proof verification is always available in the same backup storage.
        let (tx1, rx1) = watch::channel::<Option<DbState>>(None);
        let (tx2, rx2) = watch::channel::<Option<DbState>>(None);

        // Schedule work streams.
        let watch_db_state = IntervalStream::new(interval(Duration::from_secs(1)))
            .then(|_| self.try_refresh_db_state(&tx1))
            .boxed_local();

        let backup_epoch_endings = self
            .backup_work_stream(
                backup_state.latest_epoch_ending_epoch,
                &rx1,
                |slf, last_epoch, db_state| {
                    Self::backup_epoch_endings(slf, last_epoch, db_state, &tx2)
                },
            )
            .boxed_local();
        let backup_state_snapshots = self
            .backup_work_stream(
                backup_state.latest_state_snapshot_epoch,
                &rx2,
                Self::backup_state_snapshot,
            )
            .boxed_local();
        let backup_transactions = self
            .backup_work_stream(
                backup_state.latest_transaction_version,
                &rx2,
                Self::backup_transactions,
            )
            .boxed_local();
```

**File:** storage/backup/backup-cli/src/coordinators/backup.rs (L199-235)
```rust
    async fn backup_epoch_endings(
        &self,
        mut last_epoch_ending_epoch_in_backup: Option<u64>,
        db_state: DbState,
        downstream_db_state_broadcaster: &watch::Sender<Option<DbState>>,
    ) -> Result<Option<u64>> {
        loop {
            if let Some(epoch) = last_epoch_ending_epoch_in_backup {
                EPOCH_ENDING_EPOCH.set(epoch as i64);
            }
            let (first, last) = get_batch_range(last_epoch_ending_epoch_in_backup, 1);

            if db_state.epoch <= last {
                // "<=" because `db_state.epoch` hasn't ended yet, wait for the next db_state update
                break;
            }

            EpochEndingBackupController::new(
                EpochEndingBackupOpt {
                    start_epoch: first,
                    end_epoch: last + 1,
                },
                self.global_opt.clone(),
                Arc::clone(&self.client),
                Arc::clone(&self.storage),
            )
            .run()
            .await?;
            last_epoch_ending_epoch_in_backup = Some(last)
        }

        downstream_db_state_broadcaster
            .send(Some(db_state))
            .map_err(|e| anyhow!("Receivers should not be cancelled: {}", e))
            .unwrap();
        Ok(last_epoch_ending_epoch_in_backup)
    }
```

**File:** storage/backup/backup-cli/src/metadata/mod.rs (L14-22)
```rust
#[derive(Deserialize, Serialize)]
#[allow(clippy::enum_variant_names)] // to introduce: BackupperId, etc
pub(crate) enum Metadata {
    EpochEndingBackup(EpochEndingBackupMeta),
    StateSnapshotBackup(StateSnapshotBackupMeta),
    TransactionBackup(TransactionBackupMeta),
    Identity(IdentityMeta),
    CompactionTimestamps(CompactionTimestampsMeta),
}
```

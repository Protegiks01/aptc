# Audit Report

## Title
TOCTOU Vulnerability in Backup Restore: Version Mismatch Allows Rollback Attack via Manifest Swap

## Summary
A Time-of-Check to Time-of-Use (TOCTOU) vulnerability exists in the backup restoration process where metadata is synced and cached separately from manifest loading. An attacker with write access to the backup storage backend can swap manifest files between metadata sync and manifest usage, causing nodes to restore state from an older version while believing they are restoring a newer version. This bypasses cryptographic verification because all data is legitimately signed—just from the wrong blockchain version.

## Finding Description
The vulnerability exists in the state snapshot restoration workflow across multiple files: [1](#0-0) 

During verification/restoration, the coordinator first syncs metadata which contains `StateSnapshotBackupMeta` entries with version numbers and manifest file handles. This metadata is cached locally. [2](#0-1) 

The metadata sync process downloads metadata files but does **not** cryptographically verify their integrity—only caches them by hash for deduplication purposes. [3](#0-2) 

Later, when restoration begins, the manifest is loaded from remote storage using the file handle from cached metadata: [4](#0-3) 

The critical issue is at line 86: `self.version` is set from metadata (e.g., V100), but the manifest is loaded fresh from storage at line 123-124: [5](#0-4) 

**There is NO validation that `manifest.version == self.version`**. The proof verification at line 127 uses `manifest.version`, not `self.version`. When creating the restore receiver at line 142, it uses `self.version` (from metadata) but `manifest.root_hash` (from the potentially swapped manifest).

**Attack Scenario:**
1. Legitimate metadata is synced indicating version V100 with manifest handle M100
2. Attacker with storage backend write access swaps manifest file M100 with legitimate manifest M90 (from version 90)
3. When M100 is loaded, the system gets M90 manifest with `version=90` and `root_hash=V90_ROOT_HASH`
4. Proof verification passes because M90 has valid signatures for version 90
5. State receiver is created with `version=V100` (from metadata) and `expected_root_hash=V90_ROOT_HASH` (from swapped manifest)
6. Jellyfish Merkle tree nodes are tagged with version V100 but contain V90 state data [6](#0-5) [7](#0-6) 

The tree restoration uses the version parameter to tag nodes, meaning V90 state will be stored as V100 state in the database.

## Impact Explanation
This vulnerability qualifies as **HIGH severity** per Aptos bug bounty criteria:

1. **State Inconsistencies**: Nodes restoring from swapped backups will have different state versions than expected, causing database corruption where state data doesn't match version tags.

2. **Rollback Attack Vector**: An attacker can force nodes to restore older state (e.g., V90) while believing it's newer state (e.g., V100), effectively rolling back blockchain state. This violates the **State Consistency** and **Deterministic Execution** invariants.

3. **Consensus Impact**: If different nodes are tricked into restoring different versions during recovery, they will have divergent state, potentially causing consensus failures or chain splits when they rejoin the network.

4. **Protocol Violation**: The vulnerability allows bypassing the intended backup integrity model where metadata should accurately describe the backup contents.

While not reaching Critical severity (no direct fund loss or immediate consensus break), it enables significant state manipulation attacks during node recovery operations.

## Likelihood Explanation
**Likelihood: MEDIUM**

Requirements for exploitation:
- **Storage Backend Access**: Attacker needs write access to the backup storage backend (S3, GCS, local filesystem, etc.). This is external to the blockchain but may be accessible to cloud infrastructure attackers, malicious storage administrators, or compromised backup systems.
- **Timing Window**: Attack must occur between metadata sync (step 1) and manifest loading (step 3), which could be seconds to minutes depending on network latency.
- **Legitimate Backup Availability**: Attacker needs access to legitimate older backups with valid signatures.

The attack is realistic because:
1. Backup storage is often a separate security domain from validator nodes
2. The TOCTOU window is significant (metadata is cached, manifests loaded later)
3. All validation passes because swapped data is legitimately signed
4. No alerts or warnings would trigger since all cryptographic checks succeed

## Recommendation
Add explicit version validation to ensure manifest version matches metadata version:

**In `storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs`**, after loading the manifest (line 124), add:

```rust
let manifest: StateSnapshotBackup =
    self.storage.load_json_file(&self.manifest_handle).await?;

// SECURITY: Validate manifest version matches expected version from metadata
ensure!(
    manifest.version == self.version,
    "Manifest version mismatch: expected {} from metadata, got {} from manifest. \
    Possible TOCTOU attack or storage corruption.",
    self.version,
    manifest.version,
);

let (txn_info_with_proof, li): (TransactionInfoWithProof, LedgerInfoWithSignatures) =
    self.storage.load_bcs_file(&manifest.proof).await?;
```

Similarly, add epoch validation:
```rust
ensure!(
    manifest.epoch == backup_meta.epoch,
    "Manifest epoch mismatch: expected {} from metadata, got {} from manifest.",
    backup_meta.epoch,
    manifest.epoch,
);
```

**Additional hardening:** Consider cryptographically signing metadata files or including manifest hashes in metadata entries to prevent metadata tampering.

## Proof of Concept

```rust
// Proof of Concept demonstrating the TOCTOU vulnerability
// This test simulates an attacker swapping manifest files between metadata sync and restore

#[tokio::test]
async fn test_toctou_manifest_swap_vulnerability() {
    use std::sync::Arc;
    use tempfile::TempDir;
    
    // Setup: Create legitimate backups for V90 and V100
    let storage_dir = TempDir::new().unwrap();
    let storage = Arc::new(LocalStorage::new(storage_dir.path()));
    
    // Create legitimate V100 backup metadata
    let v100_meta = StateSnapshotBackupMeta {
        epoch: 10,
        version: 100,
        manifest: FileHandle::new("state_snapshot_100.manifest"),
    };
    
    // Create legitimate V90 manifest with valid proofs
    let v90_manifest = create_legitimate_backup(90, valid_v90_proof());
    
    // Store V100 metadata
    let metadata = Metadata::new_state_snapshot_backup(
        v100_meta.epoch,
        v100_meta.version,
        v100_meta.manifest.clone(),
    );
    storage.save_metadata_line(&metadata.name(), &metadata.to_text_line().unwrap()).await.unwrap();
    
    // Step 1: Metadata sync (Time-of-Check)
    let metadata_view = sync_and_load(&MetadataCacheOpt::default(), storage.clone(), 1).await.unwrap();
    let selected_backup = metadata_view.select_state_snapshot(100).unwrap().unwrap();
    
    // ATTACK: Between metadata sync and manifest load, swap V100 manifest with V90 manifest
    storage.save_json_file(
        &selected_backup.manifest,
        &v90_manifest  // Attacker swaps in V90 manifest
    ).await.unwrap();
    
    // Step 2: Create restore controller with V100 expectation
    let controller = StateSnapshotRestoreController::new(
        StateSnapshotRestoreOpt {
            manifest_handle: selected_backup.manifest,
            version: 100,  // Expects V100 from metadata
            validate_modules: false,
            restore_mode: StateSnapshotRestoreMode::Default,
        },
        global_opts,
        storage.clone(),
        None,
    );
    
    // Step 3: Run restore (Time-of-Use)
    let result = controller.run().await;
    
    // BUG: Restore succeeds but database now has V90 state tagged as V100
    assert!(result.is_ok());  // No error because V90 proofs are valid!
    
    // Verify the vulnerability: database thinks it has V100 but actually has V90 state
    let db_state_version = db.get_latest_version().unwrap();
    assert_eq!(db_state_version, 100);  // DB thinks it's V100
    
    let actual_root_hash = db.get_state_root_hash(100).unwrap();
    assert_eq!(actual_root_hash, v90_manifest.root_hash);  // But has V90 root hash!
    
    // This is a successful TOCTOU attack causing version mismatch
}
```

**Notes**
- The vulnerability exists because metadata files are not cryptographically bound to the manifest files they reference
- The proof verification system validates that data is legitimate and properly signed, but not that it matches the expected version from metadata
- Similar TOCTOU issues may exist in transaction backup and epoch ending backup restoration flows, though state snapshot restoration is the most critical
- The attack requires external storage backend access, making it a "storage layer" vulnerability rather than a pure blockchain protocol vulnerability
- Defense in depth would include: version validation (primary fix), manifest hash inclusion in metadata, cryptographic binding between metadata and manifests, and storage backend access controls

### Citations

**File:** storage/backup/backup-cli/src/coordinators/verify.rs (L85-96)
```rust
        let metadata_view = metadata::cache::sync_and_load(
            &self.metadata_cache_opt,
            Arc::clone(&self.storage),
            self.concurrent_downloads,
        )
        .await?;
        let ver_max = Version::MAX;
        let state_snapshot =
            metadata_view.select_state_snapshot(self.state_snapshot_before_version)?;
        let transactions =
            metadata_view.select_transaction_backups(self.start_version, self.end_version)?;
        let epoch_endings = metadata_view.select_epoch_ending_backups(ver_max)?;
```

**File:** storage/backup/backup-cli/src/metadata/cache.rs (L89-214)
```rust
/// Sync local cache folder with remote storage, and load all metadata entries from the cache.
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

**File:** storage/backup/backup-cli/src/metadata/mod.rs (L184-189)
```rust
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct StateSnapshotBackupMeta {
    pub epoch: u64,
    pub version: Version,
    pub manifest: FileHandle,
}
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L76-94)
```rust
impl StateSnapshotRestoreController {
    pub fn new(
        opt: StateSnapshotRestoreOpt,
        global_opt: GlobalRestoreOptions,
        storage: Arc<dyn BackupStorage>,
        epoch_history: Option<Arc<EpochHistory>>,
    ) -> Self {
        Self {
            storage,
            run_mode: global_opt.run_mode,
            version: opt.version,
            manifest_handle: opt.manifest_handle,
            target_version: global_opt.target_version,
            epoch_history,
            concurrent_downloads: global_opt.concurrent_downloads,
            validate_modules: opt.validate_modules,
            restore_mode: opt.restore_mode,
        }
    }
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L113-145)
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
        let state_root_hash = txn_info_with_proof
            .transaction_info()
            .ensure_state_checkpoint_hash()?;
        ensure!(
            state_root_hash == manifest.root_hash,
            "Root hash mismatch with that in proof. root hash: {}, expected: {}",
            manifest.root_hash,
            state_root_hash,
        );
        if let Some(epoch_history) = self.epoch_history.as_ref() {
            epoch_history.verify_ledger_info(&li)?;
        }

        let receiver = Arc::new(Mutex::new(Some(self.run_mode.get_state_restore_receiver(
            self.version,
            manifest.root_hash,
            self.restore_mode,
        )?)));
```

**File:** storage/aptosdb/src/state_restore/mod.rs (L180-194)
```rust
        restore_mode: StateSnapshotRestoreMode,
    ) -> Result<Self> {
        Ok(Self {
            tree_restore: Arc::new(Mutex::new(Some(JellyfishMerkleRestore::new_overwrite(
                Arc::clone(tree_store),
                version,
                expected_root_hash,
            )?))),
            kv_restore: Arc::new(Mutex::new(Some(StateValueRestore::new(
                Arc::clone(value_store),
                version,
            )))),
            restore_mode,
        })
    }
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L237-251)
```rust
    pub fn new_overwrite<D: 'static + TreeWriter<K>>(
        store: Arc<D>,
        version: Version,
        expected_root_hash: HashValue,
    ) -> Result<Self> {
        Ok(Self {
            store,
            version,
            partial_nodes: vec![InternalInfo::new_empty(NodeKey::new_empty_path(version))],
            frozen_nodes: HashMap::new(),
            previous_leaf: None,
            num_keys_received: 0,
            expected_root_hash,
            finished: false,
            async_commit: false,
```

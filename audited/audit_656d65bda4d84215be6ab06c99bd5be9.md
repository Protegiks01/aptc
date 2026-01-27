# Audit Report

## Title
State Snapshot Metadata Manifest Redirection Enables Consensus-Breaking State Corruption

## Summary
The `StateSnapshotBackupMeta` struct stores version and epoch metadata separately from the actual snapshot manifest, with no cryptographic binding or validation. An attacker with backup storage write access can modify metadata to redirect the manifest FileHandle to a different snapshot, causing the restore process to load state from version V2 while the database believes it's restoring version V1. This breaks deterministic execution and can cause permanent consensus violations across nodes.

## Finding Description

The vulnerability exists in the backup/restore architecture where metadata and manifest data are stored separately without integrity validation.

**Vulnerable Structure:** [1](#0-0) 

The `StateSnapshotBackupMeta` contains three public fields: `epoch`, `version`, and `manifest`. The `manifest` field is simply a `FileHandle` (String URI) with no cryptographic binding to the version/epoch values. [2](#0-1) 

**Attack Vector:**

During backup creation, metadata is saved separately from the manifest: [3](#0-2) 

An attacker with write access to backup storage can:
1. Modify a metadata file (which is plain JSON)
2. Change the `manifest` FileHandle to point to a different snapshot
3. Keep the `version` and `epoch` fields unchanged to avoid detection

**Critical Flaw in Restore Logic:**

During restore, the controller loads the manifest but never validates that its version/epoch match the metadata: [4](#0-3) 

The code uses `self.version` (from metadata) to initialize the state restore receiver, but `manifest.root_hash` (from the potentially different manifest). The proof verification at line 127 uses `manifest.version`, not `self.version`, so it passes even when they differ.

**State Corruption Mechanism:** [5](#0-4) [6](#0-5) 

The `StateSnapshotRestore` is initialized with `version` from metadata but `expected_root_hash` from the manifest. This causes the Jellyfish Merkle tree to be reconstructed with the wrong version tag, and all state KV pairs are written with the wrong version, leading to catastrophic state corruption.

**No Integrity Protection:**

There is no cryptographic signature or hash verification binding the metadata to the manifest contents. Metadata files are stored as plain JSON/text with no integrity protection: [7](#0-6) 

## Impact Explanation

**Severity: CRITICAL** (Consensus/Safety Violations - up to $1,000,000)

This vulnerability breaks the fundamental "Deterministic Execution" invariant: all validators must produce identical state roots for identical blocks. When nodes restore from manipulated backups:

1. **State Version Mismatch**: Database is tagged with version V1 but contains state from version V2
2. **Transaction Replay Corruption**: Subsequent transactions replay from the wrong base state
3. **Consensus Divergence**: Different nodes can end up with different state roots for the same block height
4. **Non-Recoverable Split**: This creates a permanent chain split requiring a hard fork to resolve

The attack is particularly dangerous because:
- It affects disaster recovery scenarios when backups are critical
- Multiple nodes could restore from the same compromised backup
- The corruption is silent and may not be detected until consensus failures occur
- No on-chain mechanism can detect or prevent this

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

**Attacker Requirements:**
- Write access to backup storage (S3/GCS/Azure buckets)
- OR ability to MITM/intercept backup downloads during disaster recovery

**Realistic Scenarios:**
1. **Compromised Cloud Credentials**: Attacker gains access to backup storage IAM keys
2. **Malicious Insider**: Backup administrator with write access
3. **Supply Chain Attack**: Compromised backup automation tools
4. **Disaster Recovery Window**: During network incidents when operators hastily download backups

The attack is relatively simple to execute (just modify a JSON file), doesn't require deep protocol knowledge, and would likely succeed undetected since there's no validation. Given the high-value target (blockchain infrastructure) and potential for backup storage credential compromise, this represents a realistic threat.

## Recommendation

Add mandatory validation that manifest contents match metadata fields:

```rust
// In StateSnapshotRestoreController::run_impl()
async fn run_impl(self) -> Result<()> {
    if self.version > self.target_version {
        warn!("...");
        return Ok(());
    }

    let manifest: StateSnapshotBackup =
        self.storage.load_json_file(&self.manifest_handle).await?;
    
    // ADD VALIDATION HERE
    ensure!(
        manifest.version == self.version,
        "Manifest version {} does not match metadata version {}. Possible manifest redirect attack.",
        manifest.version,
        self.version
    );
    
    ensure!(
        manifest.epoch == self.epoch,
        "Manifest epoch {} does not match metadata epoch {}. Possible manifest redirect attack.",
        manifest.epoch,
        self.epoch
    );
    
    let (txn_info_with_proof, li): (TransactionInfoWithProof, LedgerInfoWithSignatures) =
        self.storage.load_bcs_file(&manifest.proof).await?;
    // ... rest of verification
}
```

**Additional Hardening:**
1. Add cryptographic signatures to metadata files
2. Include manifest content hash in metadata
3. Implement backup storage access logging and monitoring
4. Add integrity checks during metadata cache synchronization

## Proof of Concept

```rust
// Reproduction steps demonstrating the vulnerability

use storage::backup::backup_cli::metadata::{Metadata, StateSnapshotBackupMeta};
use storage::backup::backup_cli::backup_types::state_snapshot::manifest::StateSnapshotBackup;

// 1. Create legitimate backup metadata for version 100
let legitimate_metadata = StateSnapshotBackupMeta {
    epoch: 5,
    version: 100,
    manifest: "s3://bucket/snapshot_v100.manifest".to_string(),
};

// 2. Attacker modifies metadata to redirect manifest
let malicious_metadata = StateSnapshotBackupMeta {
    epoch: 5,      // Keep same to avoid detection
    version: 100,  // Keep same to avoid detection
    manifest: "s3://bucket/snapshot_v200.manifest".to_string(), // REDIRECTED!
};

// 3. Serialize malicious metadata (no signature prevents this)
let malicious_json = serde_json::to_string(&Metadata::StateSnapshotBackup(malicious_metadata))?;
// Attacker writes this to backup storage, replacing legitimate metadata

// 4. During restore:
// - StateSnapshotRestoreController is created with version=100
// - Manifest from v200 is loaded (has version=200, different root_hash)
// - No validation compares manifest.version with metadata.version
// - StateSnapshotRestore::new() is called with version=100, root_hash=H200
// - Database is corrupted: thinks it's at v100 but has state from v200

// 5. Result: Consensus violation when nodes have different states
// Node A (restored from legitimate backup): state_root_100 = H100
// Node B (restored from malicious backup): state_root_100 = H200
// → Chain split, requires hard fork
```

To test this vulnerability:
1. Create two state snapshots at different versions
2. Create metadata pointing to snapshot A
3. Manually modify metadata to point to snapshot B's manifest
4. Run restore using the modified metadata
5. Observe that DB version tags don't match actual state content
6. Verify that subsequent transaction replay produces different state roots than expected

## Notes

This vulnerability requires backup storage write access, which may be considered a "privileged" position. However, backup storage credentials are typically separate from validator keys and are often managed by DevOps teams rather than being secured at the same level as consensus keys. The Aptos bug bounty program should clarify whether backup infrastructure compromise is in scope, as it represents a realistic attack vector during disaster recovery scenarios.

### Citations

**File:** storage/backup/backup-cli/src/metadata/mod.rs (L170-172)
```rust
    pub fn to_text_line(&self) -> Result<TextLine> {
        TextLine::new(&serde_json::to_string(self)?)
    }
```

**File:** storage/backup/backup-cli/src/metadata/mod.rs (L185-189)
```rust
pub struct StateSnapshotBackupMeta {
    pub epoch: u64,
    pub version: Version,
    pub manifest: FileHandle,
}
```

**File:** storage/backup/backup-cli/src/storage/mod.rs (L36-41)
```rust
/// URI pointing to a file in a backup storage, like "s3:///bucket/path/file".
/// These are created by the storage when `create_for_write()`, stored in manifests by the backup
/// controller, and passed back to the storage when `open_for_read()` by the restore controller
/// to retrieve a file referred to in the manifest.
pub type FileHandle = String;
pub type FileHandleRef = str;
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/backup.rs (L482-489)
```rust
        let metadata = Metadata::new_state_snapshot_backup(
            self.epoch,
            self.version(),
            manifest_handle.clone(),
        );
        self.storage
            .save_metadata_line(&metadata.name(), &metadata.to_text_line()?)
            .await?;
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L123-145)
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
        if let Some(epoch_history) = self.epoch_history.as_ref() {
            epoch_history.verify_ledger_info(&li)?;
        }

        let receiver = Arc::new(Mutex::new(Some(self.run_mode.get_state_restore_receiver(
            self.version,
            manifest.root_hash,
            self.restore_mode,
        )?)));
```

**File:** storage/aptosdb/src/backup/restore_handler.rs (L41-55)
```rust
    pub fn get_state_restore_receiver(
        &self,
        version: Version,
        expected_root_hash: HashValue,
        restore_mode: StateSnapshotRestoreMode,
    ) -> Result<StateSnapshotRestore<StateKey, StateValue>> {
        StateSnapshotRestore::new(
            &self.state_store.state_merkle_db,
            &self.state_store,
            version,
            expected_root_hash,
            true, /* async_commit */
            restore_mode,
        )
    }
```

**File:** storage/aptosdb/src/state_restore/mod.rs (L152-173)
```rust
    pub fn new<T: 'static + TreeReader<K> + TreeWriter<K>, S: 'static + StateValueWriter<K, V>>(
        tree_store: &Arc<T>,
        value_store: &Arc<S>,
        version: Version,
        expected_root_hash: HashValue,
        async_commit: bool,
        restore_mode: StateSnapshotRestoreMode,
    ) -> Result<Self> {
        Ok(Self {
            tree_restore: Arc::new(Mutex::new(Some(JellyfishMerkleRestore::new(
                Arc::clone(tree_store),
                version,
                expected_root_hash,
                async_commit,
            )?))),
            kv_restore: Arc::new(Mutex::new(Some(StateValueRestore::new(
                Arc::clone(value_store),
                version,
            )))),
            restore_mode,
        })
    }
```

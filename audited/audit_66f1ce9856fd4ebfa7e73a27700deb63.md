# Audit Report

## Title
Backup Restore Target Version Manipulation via Compromised Metadata Allows Incomplete State Restoration

## Summary
The restore coordinator determines the target version for blockchain restoration based solely on metadata files from the backup source, without cross-validation against actual backup manifests. A compromised backup source can provide metadata claiming an artificially low `last_version`, causing the restore to complete "successfully" with incomplete blockchain state. The node will believe it has fully restored while missing potentially millions of transactions.

## Finding Description

The vulnerability exists in the restore coordinator's target version calculation logic. When a node operator initiates a database restore (typically without specifying `--target-version`, which defaults to `Version::MAX` to restore everything available), the coordinator calculates the actual target version as follows: [1](#0-0) 

The `max_transaction_version()` method retrieves the `last_version` field from `TransactionBackupMeta` entries in metadata files: [2](#0-1) 

These metadata files are downloaded from the backup storage without cryptographic verification: [3](#0-2) 

**Critical Flaw:** The `TransactionBackupMeta.last_version` in metadata files is never validated against the actual `TransactionBackup.last_version` in the backup manifests they reference. During restoration, transaction chunks are filtered based on the artificially low target version: [4](#0-3) 

**Attack Path:**
1. Attacker compromises backup storage (cloud breach, insider access, MITM)
2. Attacker modifies metadata files to contain `TransactionBackupMeta` with `last_version = 100,000` while real chain is at version 1,000,000
3. Operator initiates restore without explicit `--target-version` (expects full restore)
4. Coordinator calculates `target_version = min(Version::MAX, 100,000) = 100,000`
5. `COORDINATOR_TARGET_VERSION` metric is set to 100,000
6. Restore processes only up to version 100,000 and marks as successful
7. Node starts with 900,000 versions missing, believing it's fully restored

**Missing Validation:** A function `get_actual_target_version()` exists that would warn about this scenario, but it's marked as dead code and never called: [5](#0-4) 

## Impact Explanation

**Severity: HIGH** per Aptos bug bounty criteria - "Significant protocol violations"

The vulnerability breaks the **State Consistency** invariant. A successfully restored node will:
- Have incomplete blockchain state (missing transactions, events, state changes)
- Return incorrect/outdated results for state queries
- Fail to properly validate new transactions that depend on missing state
- Be unable to participate correctly in consensus if used as a validator
- Potentially produce different state roots than honest nodes, causing consensus issues

This affects any node operator performing backup restoration, including:
- New validator nodes bootstrapping from backup
- Fullnode operators recovering from failures
- Archive nodes restoring historical data

The impact is significant because the restore completes with success status, providing no indication that the restored state is incomplete. Operators have no way to detect this without manual verification against the network.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH** in environments with compromised backup infrastructure

This attack requires:
- Compromised backup storage (cloud storage breach, insider threat, or MITM attack)
- Operator performing restore without explicit low `--target-version`
- No out-of-band verification of blockchain completeness

Factors increasing likelihood:
- Backup storage is often third-party cloud services (AWS S3, GCS) vulnerable to breaches
- Metadata files are plain JSON without signatures or integrity checks
- Common operational practice is to restore to latest available version
- No warning is raised when metadata indicates lower version than expected

Factors decreasing likelihood:
- Requires compromise of backup infrastructure
- Restored node will eventually detect state inconsistency when syncing with network (but damage already done)
- Sophisticated operators may verify blockchain version before deployment

## Recommendation

**Immediate Fix:** Add validation that compares metadata claims against actual backup manifests and user expectations:

```rust
// In RestoreCoordinator::run_impl(), after line 212:
let actual_max_version = transaction_backups
    .last()
    .map(|b| b.last_version)
    .ok_or_else(|| anyhow!("No transaction backup found."))?;

// Validate metadata matches manifest
for backup_meta in &transaction_backups {
    let manifest = self.storage
        .load_json_file::<TransactionBackup>(&backup_meta.manifest)
        .await?;
    ensure!(
        manifest.last_version == backup_meta.last_version,
        "Metadata mismatch: TransactionBackupMeta claims last_version={}, but actual manifest has last_version={}",
        backup_meta.last_version,
        manifest.last_version
    );
}

// Warn if restored version is significantly lower than user expectation
if self.global_opt.target_version == Version::MAX && actual_max_version < expected_network_version {
    warn!(
        "WARNING: Restore will only reach version {} but network may be at higher version. \
        Verify backup completeness before deployment.",
        actual_max_version
    );
}

// After restore completes, validate final version
let final_version = self.global_opt.run_mode.get_next_expected_transaction_version()? - 1;
ensure!(
    final_version >= target_version,
    "Restore completed at version {} but target was {}",
    final_version,
    target_version
);
```

**Long-term Solutions:**
1. Sign metadata files with validator keys to prevent tampering
2. Include blockchain version in trusted waypoints for validation
3. Add post-restore verification step that checks against network peers
4. Implement metadata integrity checks using merkle roots

## Proof of Concept

```rust
// File: storage/backup/backup-cli/tests/integration_test_restore_manipulation.rs
use aptos_backup_cli::{
    metadata::{Metadata, TransactionBackupMeta},
    storage::{local_fs::LocalFs, BackupStorage},
};
use aptos_temppath::TempPath;
use std::sync::Arc;

#[tokio::test]
async fn test_compromised_metadata_causes_incomplete_restore() {
    // Setup: Create backup storage with manipulated metadata
    let backup_dir = TempPath::new();
    let storage = Arc::new(LocalFs::new(backup_dir.path().to_path_buf()));
    
    // Attacker creates fake metadata claiming only version 0-999 exists
    let fake_metadata = Metadata::new_transaction_backup(
        0,  // first_version
        999, // last_version (ARTIFICIALLY LOW)
        "fake_manifest.json".parse().unwrap(),
    );
    
    // Save fake metadata
    storage.save_metadata_line(
        &fake_metadata.name(),
        &fake_metadata.to_text_line().unwrap(),
    ).await.unwrap();
    
    // In reality, backup contains transactions 0-99999
    // Create actual backup manifest with correct version
    let real_manifest = TransactionBackup {
        first_version: 0,
        last_version: 99999, // ACTUAL DATA
        chunks: vec![/* ... */],
    };
    
    // Operator runs restore expecting full restore (no --target-version)
    let restore_opt = GlobalRestoreOpt {
        target_version: None, // Defaults to Version::MAX
        // ... other opts
    };
    
    let coordinator = RestoreCoordinator::new(
        RestoreCoordinatorOpt::default(),
        restore_opt.try_into().unwrap(),
        storage,
    );
    
    // Execute restore
    coordinator.run().await.unwrap();
    
    // VULNERABILITY: Restore succeeds but only restores to version 999
    // Expected: Should restore to version 99999 or raise error
    // Actual: Silently completes at version 999
    
    let restored_version = /* check DB version */;
    assert_eq!(restored_version, 999); // WRONG! Should be 99999
    // Node operator believes restore is complete but 99000 versions are missing
}
```

**Notes:**
- This vulnerability requires compromise of backup storage infrastructure, which while not trivial, is within the threat model given cloud storage breaches and insider threats
- The issue is particularly dangerous because it fails silently - the restore completes with success status
- The dead code `get_actual_target_version()` function suggests this scenario was previously considered but the validation was never implemented
- Post-restore state sync will eventually detect the discrepancy, but by then the node may have already been deployed and caused operational issues

### Citations

**File:** storage/backup/backup-cli/src/coordinators/restore.rs (L125-134)
```rust
        let max_txn_ver = metadata_view
            .max_transaction_version()?
            .ok_or_else(|| anyhow!("No transaction backup found."))?;
        let target_version = std::cmp::min(self.global_opt.target_version, max_txn_ver);
        info!(
            "User specified target version: {}, max transaction version: {}, Target version is set to {}",
            self.global_opt.target_version, max_txn_ver, target_version
        );

        COORDINATOR_TARGET_VERSION.set(target_version as i64);
```

**File:** storage/backup/backup-cli/src/coordinators/restore.rs (L388-406)
```rust
    #[allow(dead_code)]
    fn get_actual_target_version(
        &self,
        transaction_backups: &[TransactionBackupMeta],
    ) -> Result<Version> {
        if let Some(b) = transaction_backups.last() {
            if b.last_version > self.target_version() {
                Ok(self.target_version())
            } else {
                warn!(
                    "Can't find transaction backup containing the target version, \
                    will restore as much as possible"
                );
                Ok(b.last_version)
            }
        } else {
            bail!("No transaction backup found.")
        }
    }
```

**File:** storage/backup/backup-cli/src/metadata/view.rs (L162-169)
```rust
    pub fn max_transaction_version(&self) -> Result<Option<Version>> {
        Ok(self
            .transaction_backups
            .iter()
            .sorted()
            .next_back()
            .map(|backup| backup.last_version))
    }
```

**File:** storage/backup/backup-cli/src/metadata/cache.rs (L114-128)
```rust
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
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L360-362)
```rust
            .try_filter(move |c| {
                future::ready(c.first_version <= target_version && c.last_version >= first_version)
            })
```

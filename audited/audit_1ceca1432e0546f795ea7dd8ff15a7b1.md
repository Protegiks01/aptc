# Audit Report

## Title
Missing Transaction Coverage Validation in ReplayVerifyCoordinator Leads to Silent Partial Verification

## Summary
The `ReplayVerifyCoordinator` in `replay_verify.rs` does not validate that the selected transaction backups actually cover the full range up to `end_version`, allowing replay verification to complete successfully even when processing only a subset of the requested transaction range. This creates a silent partial verification scenario where operators believe a node has been verified to a specific version when it has not.

## Finding Description

The `ReplayVerifyCoordinator::run_impl()` method calls `select_transaction_backups()` to retrieve transaction backups for verification [1](#0-0) , but never validates that the returned backups actually reach `self.end_version`.

The `select_transaction_backups()` method in `MetadataView` only validates continuity of backup ranges (ensuring no gaps exist) [2](#0-1) , but does not validate that the backups extend to the requested `target_version`. It simply breaks early if a backup's `first_version > target_version` [3](#0-2)  and returns whatever backups were collected up to that point [4](#0-3) .

This differs from the `RestoreCoordinator`, which properly validates coverage by computing the actual maximum transaction version available in backups and adjusting the target accordingly [5](#0-4) .

**Attack Scenario:**
1. Backup storage contains transactions from version 0 to 500,000 (due to corruption, incomplete sync, or malicious tampering)
2. Operator initiates replay verification with `start_version=0` and `end_version=1,000,000`
3. `select_transaction_backups(0, 1000000)` returns backups covering only [0, 500,000] without error
4. `TransactionRestoreBatchController` processes these transactions successfully
5. Verification completes with success status, despite only verifying 500,000 out of 1,000,000 transactions
6. Operator believes the node state is verified up to version 1,000,000 when it's actually only verified to 500,000

The final error check only validates execution consistency [6](#0-5) , not coverage completeness.

## Impact Explanation

This vulnerability qualifies as **Medium severity** under the Aptos bug bounty program for the following reasons:

**"State inconsistencies requiring intervention"** - The node's actual verified state (version 500,000) diverges from the operator's belief (version 1,000,000), creating a state inconsistency that requires manual investigation and intervention to detect and correct.

**Operational Risk** - Silent failures in backup/restore operations undermine trust in the disaster recovery infrastructure. Operators may unknowingly deploy nodes with incomplete verification, leading to:
- Nodes participating in consensus with unverified state
- False confidence in backup system integrity
- Potential cascading failures if multiple nodes rely on the same corrupted backups

**Not Critical/High because:**
- Does not directly cause loss of funds or theft
- Does not break consensus safety (nodes still execute deterministically)
- Does not cause network partition or liveness failure
- Requires pre-existing backup storage corruption or manipulation
- Impact is on operational integrity, not core protocol security

## Likelihood Explanation

**Likelihood: Medium**

This issue can occur in several realistic scenarios:

1. **Backup Storage Corruption** - Storage system failures, bit rot, or incomplete backups due to network interruptions during backup creation
2. **Operational Errors** - Misconfigured backup retention policies causing premature deletion of recent transaction backups
3. **Malicious Backup Provider** - Compromised backup storage serving incomplete data
4. **Network Partitions** - Interrupted backup downloads leaving incomplete local caches

The vulnerability is exploitable without any special privileges - it only requires the backup storage to contain incomplete transaction data, which can happen through various operational failures or attacks.

However, it requires:
- Backup data to be incomplete (not the normal operational case)
- Operator to request verification beyond available data
- No manual verification of completion (operators typically don't check version ranges)

## Recommendation

Add validation to ensure selected transaction backups reach the requested `end_version`, similar to how `RestoreCoordinator` handles this case.

**Proposed Fix for `replay_verify.rs`:**

```rust
async fn run_impl(self) -> Result<(), ReplayError> {
    // ... existing code ...
    
    let metadata_view = metadata::cache::sync_and_load(
        &self.metadata_cache_opt,
        Arc::clone(&self.storage),
        self.concurrent_downloads,
    )
    .await?;
    
    // Add validation for maximum available transaction version
    let max_txn_ver = metadata_view
        .max_transaction_version()?
        .ok_or_else(|| ReplayError::OtherError("No transaction backup found.".to_string()))?;
    
    if self.end_version > max_txn_ver {
        return Err(ReplayError::OtherError(format!(
            "Requested end_version {} exceeds maximum available transaction version {} in backups. \
            Cannot complete replay verification to requested version.",
            self.end_version,
            max_txn_ver
        )));
    }
    
    // ... rest of existing code ...
}
```

This ensures that replay verification fails explicitly if the requested `end_version` cannot be satisfied by available backup data, preventing silent partial verification.

## Proof of Concept

```rust
#[tokio::test]
async fn test_replay_verify_incomplete_backups() {
    use tempfile::TempDir;
    
    // Setup: Create backup storage with transactions 0-500
    let backup_dir = TempDir::new().unwrap();
    let storage = Arc::new(LocalFs::new(backup_dir.path().to_path_buf()));
    
    // Create mock transaction backups covering only versions 0-500
    let backup_meta = TransactionBackupMeta {
        first_version: 0,
        last_version: 500,
        manifest: FileHandle::new("txn_0_500.manifest"),
    };
    
    // Create metadata view with limited backup data
    let metadata = vec![Metadata::TransactionBackup(backup_meta)];
    let metadata_view = MetadataView::new(metadata, vec![]);
    
    // Create ReplayVerifyCoordinator requesting verification to version 1000
    let coordinator = ReplayVerifyCoordinator::new(
        storage,
        MetadataCacheOpt::default(),
        TrustedWaypointOpt::default(),
        4, // concurrent_downloads
        4, // replay_concurrency
        restore_handler,
        0,    // start_version
        1000, // end_version - EXCEEDS AVAILABLE DATA
        false,
        VerifyExecutionMode::verify_all(),
    ).unwrap();
    
    // Execute replay verification
    let result = coordinator.run().await;
    
    // VULNERABILITY: This should fail with an error indicating incomplete data,
    // but instead succeeds after processing only versions 0-500
    assert!(result.is_ok(), "Expected success due to missing validation");
    
    // Verify that only partial data was processed
    let actual_version = restore_handler.get_latest_version().unwrap();
    assert_eq!(actual_version, 500, "Only processed up to version 500");
    assert_ne!(actual_version, 1000, "Did not reach requested end_version 1000");
    
    // IMPACT: Operator believes verification completed to v1000, but it only reached v500
    println!("VULNERABILITY CONFIRMED: Replay completed to version {} instead of requested {}", 
             actual_version, 1000);
}
```

**Expected Behavior:** The test should demonstrate that `ReplayVerifyCoordinator` returns success even though it only processed 500 transactions instead of the requested 1000, confirming the silent partial verification vulnerability.

**Notes**

The `RestoreCoordinator` already implements the correct validation pattern by using `max_transaction_version()` to compute the actual achievable target [7](#0-6) . This same validation should be applied to `ReplayVerifyCoordinator` to ensure consistency across all backup/restore operations and prevent silent partial verification failures.

This vulnerability specifically affects the replay verification path, which is used for validating backup integrity and disaster recovery testing. While it doesn't directly compromise consensus or cause fund loss, it undermines the reliability of the backup/restore infrastructure by allowing undetected partial verifications that could lead to operational failures during actual disaster recovery scenarios.

### Citations

**File:** storage/backup/backup-cli/src/coordinators/replay_verify.rs (L159-164)
```rust
        let transactions = metadata_view.select_transaction_backups(
            // transaction info at the snapshot must be restored otherwise the db will be confused
            // about the latest version after snapshot is restored.
            next_txn_version.saturating_sub(1),
            self.end_version,
        )?;
```

**File:** storage/backup/backup-cli/src/coordinators/replay_verify.rs (L207-211)
```rust
        if self.verify_execution_mode.seen_error() {
            Err(ReplayError::TxnMismatch)
        } else {
            Ok(())
        }
```

**File:** storage/backup/backup-cli/src/metadata/view.rs (L142-144)
```rust
            if backup.first_version > target_version {
                break;
            }
```

**File:** storage/backup/backup-cli/src/metadata/view.rs (L145-150)
```rust
            ensure!(
                backup.first_version == next_ver,
                "Transaction backup ranges not continuous, expecting version {}, got {}.",
                next_ver,
                backup.first_version,
            );
```

**File:** storage/backup/backup-cli/src/metadata/view.rs (L159-159)
```rust
        Ok(res)
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

**File:** storage/backup/backup-cli/src/coordinators/restore.rs (L125-132)
```rust
        let max_txn_ver = metadata_view
            .max_transaction_version()?
            .ok_or_else(|| anyhow!("No transaction backup found."))?;
        let target_version = std::cmp::min(self.global_opt.target_version, max_txn_ver);
        info!(
            "User specified target version: {}, max transaction version: {}, Target version is set to {}",
            self.global_opt.target_version, max_txn_ver, target_version
        );
```

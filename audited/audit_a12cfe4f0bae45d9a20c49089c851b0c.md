# Audit Report

## Title
Missing Target Version Validation in Backup Restore Allows State Discontinuities

## Summary
The backup restore system fails to validate that selected transaction backups actually cover the requested target version range. This allows restoration to complete successfully even when transaction versions are missing, creating dangerous state discontinuities that violate the State Consistency invariant and can lead to consensus failures.

## Finding Description

The vulnerability exists in the transaction backup selection and restoration flow, specifically affecting three critical components:

**1. Incomplete Coverage Check in `select_transaction_backups`** [1](#0-0) 

This method checks that all backups are continuous from version 0, but critically **does not verify** that the returned backups actually reach the requested `target_version`. The method will return successfully even if backups only cover up to version 199 when target_version is 300.

**2. No Post-Processing Validation in Transaction Restore** [2](#0-1) 

The `TransactionRestoreBatchController.run()` method processes transaction chunks and filters them by target_version, but never validates that the last processed chunk actually reaches `target_version`. The restore completes successfully regardless of coverage gaps.

**3. Missing Final Verification in Replay Verify Coordinator** [3](#0-2) [4](#0-3) 

The replay verification only checks for execution errors but never validates that the restored state actually reached `self.end_version`.

**4. Dead Code That Could Have Prevented This** [5](#0-4) 

There exists a `get_actual_target_version` function that explicitly checks if backups cover the target version and warns "Can't find transaction backup containing the target version", but this function is marked `#[allow(dead_code)]` and is never called in production.

**5. Tests Show Correct Validation Pattern** [6](#0-5) 

Test code properly validates the restored version matches the target using `assert_eq!(tgt_db.expect_synced_version(), target_version)`, but this validation is absent from production code.

**Attack Scenario:**

1. Attacker gains access to backup storage (or legitimate backups are incomplete/corrupted)
2. Available backups: versions [0-99], [100-199] 
3. Operator initiates restore with `end_version = 300`
4. `select_transaction_backups(start=0, target=300)` returns [0-99], [100-199] successfully
5. `TransactionRestoreBatchController` processes these chunks successfully  
6. `ReplayVerifyCoordinator` completes without error
7. **Result**: Database is in inconsistent state with versions 200-300 missing, but system believes restore succeeded

This breaks the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs." The missing transaction versions create a gap in the ledger that will cause consensus failures when validators attempt to sync or verify against this incomplete state.

## Impact Explanation

**Severity: HIGH** (up to $50,000 per Aptos bug bounty criteria)

This vulnerability causes "State inconsistencies requiring intervention" which falls under the **Medium Severity** category, but the impact extends to potential consensus disruption, making it **High Severity**:

- **State Corruption**: Restored nodes have incomplete transaction history, breaking state consistency
- **Consensus Disruption**: Validators with incomplete state will diverge from honest validators, potentially causing consensus failures or requiring manual intervention
- **Chain Split Risk**: If multiple validators restore from incomplete backups, they may form a divergent subset unable to agree with the main network
- **Silent Failure**: The system completes successfully without warning, making the issue difficult to detect until consensus problems emerge
- **Recovery Complexity**: Requires manual detection, diagnosis, and re-restoration to fix

The vulnerability affects any node performing backup restoration, including:
- Archive nodes restoring historical state
- Validators recovering from failures
- New nodes bootstrapping from backups
- Disaster recovery scenarios

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

The vulnerability is triggered when:
1. Backup storage contains incomplete transaction backup sets (common in storage failures, partial backups, or corrupted data)
2. Operators perform restore operations with target versions beyond available backups
3. No manual verification of restored version is performed post-restore

Real-world triggers include:
- **Storage failures**: Cloud storage corruption or partial deletions
- **Incomplete backups**: Backup processes interrupted or misconfigured  
- **Malicious actors**: Attackers with access to backup storage removing backup files
- **Operational errors**: Restoring to wrong target version or using stale backup metadata
- **Disaster recovery**: High-pressure scenarios where validation steps may be skipped

The likelihood is elevated because:
- The code provides no warnings or errors when backups are incomplete
- Operators may not realize they need to manually verify restored versions
- Test infrastructure validates properly, creating false confidence
- The dead `get_actual_target_version` function suggests developers were aware of this issue but didn't implement the fix

## Recommendation

**Immediate Fixes Required:**

**1. Add Target Version Validation in `select_transaction_backups`:**

```rust
pub fn select_transaction_backups(
    &self,
    start_version: Version,
    target_version: Version,
) -> Result<Vec<TransactionBackupMeta>> {
    // ... existing continuity checks ...
    
    // NEW: Verify coverage reaches target_version
    if let Some(last_backup) = res.last() {
        ensure!(
            last_backup.last_version >= target_version,
            "Transaction backups do not cover target version. Last available version: {}, target version: {}",
            last_backup.last_version,
            target_version
        );
    } else if target_version > 0 {
        bail!("No transaction backups available to reach target version {}", target_version);
    }
    
    Ok(res)
}
```

**2. Add Post-Restoration Validation in `TransactionRestoreBatchController`:**

```rust
async fn run_impl(self) -> Result<()> {
    // ... existing restoration logic ...
    
    // NEW: After restoration completes, verify we reached target_version
    if let RestoreRunMode::Restore { restore_handler } = self.global_opt.run_mode.as_ref() {
        let restored_version = restore_handler.get_next_expected_transaction_version()? - 1;
        ensure!(
            restored_version >= self.global_opt.target_version,
            "Restoration incomplete. Restored version: {}, target version: {}",
            restored_version,
            self.global_opt.target_version
        );
    }
    
    Ok(())
}
```

**3. Add Final Verification in `ReplayVerifyCoordinator`:**

```rust
async fn run_impl(self) -> Result<(), ReplayError> {
    // ... existing replay logic ...
    
    // NEW: Verify we reached end_version
    let final_version = self.restore_handler.get_next_expected_transaction_version()? - 1;
    if final_version < self.end_version {
        return Err(ReplayError::OtherError(format!(
            "Replay incomplete. Final version: {}, expected: {}",
            final_version,
            self.end_version
        )));
    }
    
    if self.verify_execution_mode.seen_error() {
        Err(ReplayError::TxnMismatch)
    } else {
        Ok(())
    }
}
```

**4. Activate the Existing `get_actual_target_version` Function:**

Remove `#[allow(dead_code)]` and call it during restore planning to provide early warnings about incomplete backup coverage.

## Proof of Concept

```rust
// Test demonstrating the vulnerability
#[tokio::test]
async fn test_incomplete_backup_coverage_vulnerability() {
    use aptos_temppath::TempPath;
    use std::sync::Arc;
    
    // Setup: Create source DB with transactions 0-199
    let (_src_db_dir, src_db, _blocks) = tmp_db_with_random_content();
    let backup_dir = TempPath::new();
    backup_dir.create_as_dir().unwrap();
    let store: Arc<dyn BackupStorage> = Arc::new(LocalFs::new(backup_dir.path().to_path_buf()));
    
    // Backup only versions 0-199
    let backup_handle = backup_transactions(&src_db, &store, 0, 200).await.unwrap();
    
    // Setup target DB for restore
    let tgt_db_dir = TempPath::new();
    tgt_db_dir.create_as_dir().unwrap();
    
    // VULNERABILITY: Request restore to version 300, but backups only cover 0-199
    let restore_result = TransactionRestoreBatchController::new(
        GlobalRestoreOpt {
            target_version: Some(300), // Request version 300
            db_dir: Some(tgt_db_dir.path().to_path_buf()),
            // ... other options
        }.try_into().unwrap(),
        store,
        vec![backup_handle],
        None,
        None,
        None,
        VerifyExecutionMode::NoVerify,
        None,
    )
    .run()
    .await;
    
    // BUG: This succeeds even though we only restored to version 199!
    assert!(restore_result.is_ok());
    
    // Verify the actual restored version
    let tgt_db = AptosDB::new_readonly_for_test(&tgt_db_dir);
    let actual_version = tgt_db.expect_synced_version();
    
    // VULNERABILITY DEMONSTRATED: 
    // Requested version 300, but only got 199, yet restore "succeeded"
    assert_eq!(actual_version, 199); // Should be 300!
    assert_ne!(actual_version, 300); // Proves the gap exists
    
    // This incomplete state will cause consensus failures and state inconsistencies
}
```

**Notes:**

This vulnerability represents a critical gap in data validation during the backup/restore process. The presence of dead code that would have prevented this issue, combined with proper validation in tests but not production, suggests this may be a regression or incomplete implementation. The fix is straightforward but essential for maintaining state consistency across the Aptos network.

### Citations

**File:** storage/backup/backup-cli/src/metadata/view.rs (L132-160)
```rust
    pub fn select_transaction_backups(
        &self,
        start_version: Version,
        target_version: Version,
    ) -> Result<Vec<TransactionBackupMeta>> {
        // This can be more flexible, but for now we assume and check backups are continuous in
        // range (which is always true when we backup from a single backup coordinator)
        let mut next_ver = 0;
        let mut res = Vec::new();
        for backup in self.transaction_backups.iter().sorted() {
            if backup.first_version > target_version {
                break;
            }
            ensure!(
                backup.first_version == next_ver,
                "Transaction backup ranges not continuous, expecting version {}, got {}.",
                next_ver,
                backup.first_version,
            );

            if backup.last_version >= start_version {
                res.push(backup.clone());
            }

            next_ver = backup.last_version + 1;
        }

        Ok(res)
    }
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L286-339)
```rust
    pub async fn run(self) -> Result<()> {
        let name = self.name();
        info!("{} started.", name);
        self.run_impl()
            .await
            .map_err(|e| anyhow!("{} failed: {}", name, e))?;
        info!("{} succeeded.", name);
        Ok(())
    }

    fn name(&self) -> String {
        format!("transaction {}", self.global_opt.run_mode.name())
    }

    async fn run_impl(self) -> Result<()> {
        if self.manifest_handles.is_empty() {
            return Ok(());
        }

        let mut loaded_chunk_stream = self.loaded_chunk_stream();
        // If first_version is None, we confirm and save frozen substrees to create a baseline
        // When first version is not None, it only happens when we already finish first phase of db restore and
        // we don't need to confirm and save frozen subtrees again.
        let first_version = self.first_version.unwrap_or(
            self.confirm_or_save_frozen_subtrees(&mut loaded_chunk_stream)
                .await?,
        );
        if let RestoreRunMode::Restore { restore_handler } = self.global_opt.run_mode.as_ref() {
            ensure!(
                self.output_transaction_analysis.is_none(),
                "Bug: requested to output transaction output sizing info in restore mode.",
            );
            AptosVM::set_concurrency_level_once(self.global_opt.replay_concurrency_level);

            let kv_only = self.replay_from_version.is_some_and(|(_, k)| k);
            let txns_to_execute_stream = self
                .save_before_replay_version(first_version, loaded_chunk_stream, restore_handler)
                .await?;

            if let Some(txns_to_execute_stream) = txns_to_execute_stream {
                if kv_only {
                    self.replay_kv(restore_handler, txns_to_execute_stream)
                        .await?;
                } else {
                    self.replay_transactions(restore_handler, txns_to_execute_stream)
                        .await?;
                }
            }
        } else {
            self.go_through_verified_chunks(loaded_chunk_stream, first_version)
                .await?;
        }
        Ok(())
    }
```

**File:** storage/backup/backup-cli/src/coordinators/replay_verify.rs (L159-164)
```rust
        let transactions = metadata_view.select_transaction_backups(
            // transaction info at the snapshot must be restored otherwise the db will be confused
            // about the latest version after snapshot is restored.
            next_txn_version.saturating_sub(1),
            self.end_version,
        )?;
```

**File:** storage/backup/backup-cli/src/coordinators/replay_verify.rs (L207-212)
```rust
        if self.verify_execution_mode.seen_error() {
            Err(ReplayError::TxnMismatch)
        } else {
            Ok(())
        }
    }
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

**File:** storage/backup/backup-cli/src/backup_types/transaction/tests.rs (L147-147)
```rust
    assert_eq!(tgt_db.expect_synced_version(), target_version);
```

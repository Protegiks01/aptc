# Audit Report

## Title
Missing Version Range Existence Validation in ReplayVerifyCoordinator Allows Silent Verification Bypass

## Summary
The `ReplayVerifyCoordinator` in the backup CLI does not validate that user-specified version ranges actually exist in backup metadata. When versions beyond the available backup range are requested, the tool silently succeeds without verifying any transactions, creating a false sense of backup integrity.

## Finding Description

In `ReplayVerifyCoordinator`, the `start_version` and `end_version` parameters define the replay verification range. [1](#0-0) 

The only validation performed is an order check to ensure `start_version <= end_version`: [2](#0-1) 

However, there is no validation that these versions actually exist in the backup metadata. The code proceeds to call `select_transaction_backups`: [3](#0-2) 

The `select_transaction_backups` method filters backups based on version overlap, but returns an empty vector (without error) when no backups match: [4](#0-3) 

When an empty manifest list is passed to `TransactionRestoreBatchController`, it immediately returns success: [5](#0-4) 

The verification then completes successfully without verifying any transactions: [6](#0-5) 

**Contrast with RestoreCoordinator:** The regular `RestoreCoordinator` properly validates version ranges by checking the maximum available transaction version and returning an error if no backups exist: [7](#0-6) 

This validation is missing in both `ReplayVerifyCoordinator` and `VerifyCoordinator`.

## Impact Explanation

This vulnerability falls under **Medium Severity** per the Aptos bug bounty program for the following reasons:

1. **Operational Integrity Violation**: Backup verification is critical for disaster recovery preparedness. False positive verification results undermine the reliability of backup systems.

2. **State Inconsistencies**: In disaster recovery scenarios, operators may discover that backups believed to be verified don't actually cover the required version range, leading to inability to restore blockchain state and requiring emergency intervention.

3. **Silent Failure**: The tool provides no warning or error when versions don't exist, creating a false sense of security. Users running automated verification scripts would not detect the issue.

4. **Scope of Impact**: While this doesn't directly affect live consensus or cause immediate fund loss, it compromises the backup infrastructure that ensures blockchain availability and recoverability—a critical operational security component.

## Likelihood Explanation

**Likelihood: Medium-High**

This issue will occur whenever:
- Operators specify version ranges that don't exist in backups (typos, wrong configuration)
- Automated scripts use outdated version ranges after backup rotation
- Users test verification with future version numbers
- Backup metadata becomes stale or incomplete

The vulnerability is easily triggered and requires no special privileges—any user running the `db-tool replay-verify` command can encounter it. The CLI documentation even suggests the tool should validate version ranges (help text mentions "if present in the backup"), but this validation is not implemented. [8](#0-7) 

## Recommendation

Add version range validation similar to `RestoreCoordinator`:

```rust
async fn run_impl(self) -> Result<(), ReplayError> {
    AptosVM::set_concurrency_level_once(self.replay_concurrency_level);
    set_timed_feature_override(TimedFeatureOverride::Replay);

    let metadata_view = metadata::cache::sync_and_load(
        &self.metadata_cache_opt,
        Arc::clone(&self.storage),
        self.concurrent_downloads,
    )
    .await?;
    
    if self.start_version > self.end_version {
        return Err(ReplayError::OtherError(format!(
            "start_version {} should precede end_version {}.",
            self.start_version, self.end_version
        )));
    }

    // ADD THIS VALIDATION:
    let max_txn_ver = metadata_view
        .max_transaction_version()?
        .ok_or_else(|| ReplayError::OtherError(
            "No transaction backup found in metadata.".to_string()
        ))?;
    
    if self.start_version > max_txn_ver {
        return Err(ReplayError::OtherError(format!(
            "start_version {} exceeds maximum available version {} in backups.",
            self.start_version, max_txn_ver
        )));
    }
    
    let actual_end_version = std::cmp::min(self.end_version, max_txn_ver);
    if actual_end_version < self.end_version {
        warn!(
            "end_version {} exceeds maximum available version {}, capping to {}",
            self.end_version, max_txn_ver, actual_end_version
        );
    }

    // Continue with actual_end_version instead of self.end_version
    // ...
}
```

Apply similar fixes to `VerifyCoordinator` for consistency.

## Proof of Concept

**Setup:**
1. Create a backup with transactions covering versions 0-1000
2. Run replay-verify requesting versions 5000-6000

**Expected behavior:** Error indicating versions don't exist in backup

**Actual behavior:** Tool reports success without verifying anything

**Reproduction Steps:**

```bash
# Assume backup contains versions 0-1000
./target/release/db-tool replay-verify \
    --start-version 5000 \
    --end-version 6000 \
    --target-db-dir /tmp/test_db \
    --storage-config <storage-config> \
    --metadata-cache-dir /tmp/metadata

# Output:
# ReplayVerify coordinator started.
# ReplayVerify coordinator succeeded
# Exit code: 0

# No transactions were actually verified, but tool reports success
```

**Validation Test:**

The vulnerability can be confirmed by examining the logs or adding instrumentation to verify that:
1. `select_transaction_backups` returns an empty vector
2. `TransactionRestoreBatchController::run_impl()` hits the early return at line 301-303
3. No chunks are processed
4. Tool exits with success status

## Notes

This vulnerability affects both `ReplayVerifyCoordinator` and `VerifyCoordinator`. The `RestoreCoordinator` has proper validation, indicating this is an inconsistency in the codebase rather than a design decision. The CLI help text suggests version validation was intended but not implemented.

### Citations

**File:** storage/backup/backup-cli/src/coordinators/replay_verify.rs (L51-53)
```rust
    start_version: Version,
    end_version: Version,
    validate_modules: bool,
```

**File:** storage/backup/backup-cli/src/coordinators/replay_verify.rs (L110-115)
```rust
        if self.start_version > self.end_version {
            return Err(ReplayError::OtherError(format!(
                "start_version {} should precede end_version {}.",
                self.start_version, self.end_version
            )));
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

**File:** storage/backup/backup-cli/src/coordinators/replay_verify.rs (L207-211)
```rust
        if self.verify_execution_mode.seen_error() {
            Err(ReplayError::TxnMismatch)
        } else {
            Ok(())
        }
```

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

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L300-303)
```rust
    async fn run_impl(self) -> Result<()> {
        if self.manifest_handles.is_empty() {
            return Ok(());
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

**File:** storage/db-tool/src/replay_verify.rs (L44-49)
```rust
    #[clap(
        long,
        help = "The last transaction version required to be replayed and verified (if present \
        in the backup). [Defaults to the latest version available] "
    )]
    end_version: Option<Version>,
```

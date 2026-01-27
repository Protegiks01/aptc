# Audit Report

## Title
Integer Overflow in Backup Metadata Processing Causes Backup Coordinator Failure

## Summary
The `get_storage_state()` function computes maximum values from backup metadata without validating against `u64::MAX` or `Version::MAX`. When malformed metadata entries contain these maximum values, subsequent arithmetic operations in the backup coordinator overflow, causing the backup system to attempt re-backing up already processed versions starting from version 0, leading to backup operation failures or data loss.

## Finding Description

The vulnerability exists in the backup metadata processing chain: [1](#0-0) 

The `get_storage_state()` function uses `.max()` on iterators to find the latest backup versions without validating the values. When backup metadata is loaded via JSON deserialization, no bounds checking occurs: [2](#0-1) 

If a malicious or corrupted metadata file contains `last_version: u64::MAX` or `last_epoch: u64::MAX`, this value propagates through the backup coordinator. The critical failure occurs in `get_batch_range()`: [3](#0-2) 

With `last_in_backup = Some(u64::MAX)`:
- `first = u64::MAX + 1` wraps to `0` in release mode
- `batch = u64::MAX / batch_size + 1` produces a large value
- `last = batch * batch_size` overflows to a small value

This causes the backup coordinator to incorrectly attempt backing up versions starting from 0: [4](#0-3) 

The same overflow issue affects metadata compaction operations: [5](#0-4) 

**Attack Vector:**
1. Attacker gains write access to backup storage (compromised credentials or misconfigured IAM)
2. Attacker uploads malicious metadata file: `{"TransactionBackup":{"first_version":3000,"last_version":18446744073709551615,"manifest":"<handle>"}}`
3. Backup coordinator loads metadata via `sync_and_load()`
4. `get_storage_state()` returns `latest_transaction_version: Some(u64::MAX)`
5. Next backup cycle calls `get_batch_range(Some(u64::MAX), batch_size)` 
6. Integer overflow produces `first=0, last=~8000`, causing re-backup attempts of old versions
7. Backup operations fail or corrupt existing backup history
8. New transactions after actual latest version never get backed up

## Impact Explanation

**Severity: Medium** per bug bounty criteria ("State inconsistencies requiring intervention")

While this vulnerability does NOT directly affect the live blockchain consensus, it creates critical operational risks:

1. **Backup System Denial of Service**: Malformed metadata causes the backup coordinator to enter an invalid state where it cannot progress beyond attempting to re-backup version 0
2. **Data Loss Risk**: If the corrupted backup coordinator overwrites valid backups or fails to backup new data, disaster recovery becomes impossible
3. **Restore Failures**: The continuity validation in `select_transaction_backups()` may accept the malformed metadata, causing incomplete restores: [6](#0-5) 

After processing `last_version = u64::MAX`, `next_ver` overflows to 0, potentially breaking continuity checks for subsequent operations.

## Likelihood Explanation

**Likelihood: Low-Medium**

**Prerequisites:**
- Attacker must compromise backup storage credentials (S3/GCS/Azure IAM)
- Backup storage typically has restricted write access, but misconfigurations occur
- Once access is gained, exploitation is trivial (upload single JSON file)

**Mitigating Factors:**
- Backup storage is typically protected by strong IAM policies
- Most deployments use read-only credentials for backup consumers
- Monitoring systems may detect unusual metadata files

**Aggravating Factors:**
- No validation of metadata values during deserialization
- Integer overflow wraps silently in Rust release builds
- Backup coordinator automatically loads all metadata files without verification
- A single malformed file affects all backup operations globally

## Recommendation

Add validation during metadata deserialization and before arithmetic operations:

```rust
// In metadata/mod.rs - add validation method
impl TransactionBackupMeta {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.first_version <= self.last_version,
            "Invalid version range: first_version {} > last_version {}",
            self.first_version, self.last_version
        );
        ensure!(
            self.last_version < Version::MAX,
            "Invalid last_version: {} (must be < Version::MAX)",
            self.last_version
        );
        Ok(())
    }
}

// In coordinators/backup.rs - add overflow protection
fn get_batch_range(last_in_backup: Option<u64>, batch_size: usize) -> (u64, u64) {
    last_in_backup.map_or((0, 0), |n| {
        // Protect against overflow when n is near u64::MAX
        ensure!(n < u64::MAX - batch_size as u64, 
            "Cannot compute next batch: last_in_backup {} too close to u64::MAX", n);
        
        let first = n.checked_add(1).expect("overflow computing first");
        let batch = n / batch_size as u64 + 1;
        let last = batch.checked_mul(batch_size as u64).expect("overflow computing last");
        (first, last)
    })
}

// In cache.rs - validate metadata after loading
async fn load_metadata_lines(&mut self) -> Result<Vec<Metadata>> {
    let mut buf = String::new();
    self.read_to_string(&mut buf).await.err_notes((file!(), line!(), &buf))?;
    
    let metadata: Vec<Metadata> = buf
        .lines()
        .map(serde_json::from_str::<Metadata>)
        .collect::<Result<_, serde_json::error::Error>>()?;
    
    // Validate each metadata entry
    for meta in &metadata {
        match meta {
            Metadata::TransactionBackup(t) => t.validate()?,
            Metadata::EpochEndingBackup(e) => {
                ensure!(e.last_epoch < u64::MAX, "Invalid last_epoch");
            },
            _ => {},
        }
    }
    
    Ok(metadata)
}
```

## Proof of Concept

```rust
// Test demonstrating the overflow vulnerability
#[test]
fn test_max_value_overflow_in_get_batch_range() {
    use crate::coordinators::backup::get_batch_range;
    
    // Normal case
    let (first, last) = get_batch_range(Some(1000), 100);
    assert_eq!(first, 1001);
    assert_eq!(last, 1100);
    
    // Malicious case with u64::MAX
    let (first, last) = get_batch_range(Some(u64::MAX), 10000);
    
    // Due to overflow: first = u64::MAX + 1 = 0
    assert_eq!(first, 0); // VULNERABILITY: wraps to 0
    
    // Due to overflow in multiplication: last wraps to small value
    // This causes backup coordinator to try backing up [0, ~8384] 
    // instead of continuing from u64::MAX
    assert!(last < 10000); // VULNERABILITY: incorrect range
    
    println!("Overflow occurred: first={}, last={}", first, last);
    // This would cause the backup coordinator to fail or corrupt backups
}

#[test]  
fn test_malformed_metadata_propagation() {
    use crate::metadata::{Metadata, TransactionBackupMeta};
    use crate::storage::FileHandle;
    
    // Simulate malicious metadata with MAX value
    let malicious_meta = TransactionBackupMeta {
        first_version: 0,
        last_version: u64::MAX, // Malicious value
        manifest: FileHandle::from("s3://bucket/manifest.json"),
    };
    
    // This should fail validation but currently doesn't
    let metadata = Metadata::TransactionBackup(malicious_meta);
    let json = serde_json::to_string(&metadata).unwrap();
    
    // Deserialization succeeds without validation
    let loaded: Metadata = serde_json::from_str(&json).unwrap();
    
    if let Metadata::TransactionBackup(t) = loaded {
        assert_eq!(t.last_version, u64::MAX); // VULNERABILITY: no validation
    }
}
```

## Notes

This vulnerability is isolated to the backup/restore subsystem and does not directly affect consensus, transaction execution, or live blockchain state. However, it creates significant operational risk by potentially corrupting the disaster recovery infrastructure. The issue requires backup storage compromise as a prerequisite, which elevates the attack complexity but does not eliminate the risk given the critical importance of backup integrity for blockchain operations.

### Citations

**File:** storage/backup/backup-cli/src/metadata/view.rs (L80-94)
```rust
    pub fn get_storage_state(&self) -> Result<BackupStorageState> {
        let latest_epoch_ending_epoch =
            self.epoch_ending_backups.iter().map(|e| e.last_epoch).max();
        let latest_state_snapshot = self.select_state_snapshot(Version::MAX)?;
        let (latest_state_snapshot_epoch, latest_state_snapshot_version) =
            match latest_state_snapshot {
                Some(snapshot) => (Some(snapshot.epoch), Some(snapshot.version)),
                None => (None, None),
            };
        let latest_transaction_version = self
            .transaction_backups
            .iter()
            .map(|t| t.last_version)
            .max();

```

**File:** storage/backup/backup-cli/src/metadata/view.rs (L145-156)
```rust
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
```

**File:** storage/backup/backup-cli/src/metadata/cache.rs (L237-246)
```rust
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

**File:** storage/backup/backup-cli/src/coordinators/backup.rs (L269-291)
```rust
    async fn backup_transactions(
        &self,
        mut last_transaction_version_in_backup: Option<Version>,
        db_state: DbState,
    ) -> Result<Option<u64>> {
        loop {
            if let Some(version) = last_transaction_version_in_backup {
                TRANSACTION_VERSION.set(version as i64);
            }
            let (first, last) = get_batch_range(
                last_transaction_version_in_backup,
                self.transaction_batch_size,
            );

            if db_state.committed_version < last {
                // wait for the next db_state update
                return Ok(last_transaction_version_in_backup);
            }

            TransactionBackupController::new(
                TransactionBackupOpt {
                    start_version: first,
                    num_transactions: (last + 1 - first) as usize,
```

**File:** storage/backup/backup-cli/src/coordinators/backup.rs (L490-499)
```rust
fn get_batch_range(last_in_backup: Option<u64>, batch_size: usize) -> (u64, u64) {
    // say, 7 is already in backup, and we target batches of size 10, we will return (8, 10) in this
    // case, so 8, 9, 10 will be in this batch, and next time the backup worker will pass in 10,
    // and we will return (11, 20). The transaction 0 will be in it's own batch.
    last_in_backup.map_or((0, 0), |n| {
        let first = n + 1;
        let batch = n / batch_size as u64 + 1;
        let last = batch * batch_size as u64;
        (first, last)
    })
```

**File:** storage/backup/backup-cli/src/metadata/mod.rs (L125-135)
```rust
        let mut next_version = backup_meta.last_version + 1;
        let mut res: Vec<TextLine> = Vec::new();
        res.push(Metadata::TransactionBackup(backup_meta).to_text_line()?);
        for backup in backup_metas.iter().skip(1) {
            ensure!(
                next_version == backup.first_version,
                "txn backup ranges is not continuous expecting version {}, got {}.",
                next_version,
                backup.first_version,
            );
            next_version = backup.last_version + 1;
```

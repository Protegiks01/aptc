# Audit Report

## Title
Incomplete Epoch History Bypasses Cryptographic Verification in Backup Restoration

## Summary
The backup restoration system allows state snapshots and transactions from epochs beyond the restored epoch history to bypass cryptographic signature verification, potentially enabling restoration of data from incompatible blockchain states and causing consensus splits.

## Finding Description

The vulnerability exists in the epoch verification logic during backup restoration. When `MetadataView::new()` accepts backup metadata, it performs no validation that transaction backups, state snapshots, and epoch ending backups are aligned or complete. [1](#0-0) 

During restoration, if epoch ending backups are incomplete (e.g., only containing epochs 0-5), the `EpochHistory` will only have data for those epochs. When the system attempts to verify a state snapshot or transactions from a much later epoch (e.g., epoch 100), the verification function has a critical bypass: [2](#0-1) 

At line 279, if `epoch > self.epoch_endings.len()`, the function immediately returns `Ok()` with only a warning, **completely bypassing** the cryptographic signature verification that would normally occur at lines 289-310. This means:

1. A state snapshot from epoch 100 with incomplete epoch history (only epochs 0-5) will be accepted without verifying its signatures
2. Transactions from epochs 101-150 will similarly bypass verification
3. An attacker controlling backup metadata can provide:
   - Minimal epoch ending backups (epochs 0-N)
   - State snapshots from epoch M >> N (from a different chain/fork)
   - Transaction backups from epochs > M (from yet another source)

The restoration process selects backups based purely on version ranges without cross-validation: [3](#0-2) 

This violates the **Cryptographic Correctness** invariant - BLS signatures must be verified but are skipped. It also violates **State Consistency** - state transitions must be verifiable via proofs, but incomplete epoch history prevents verification.

## Impact Explanation

This is a **Critical Severity** vulnerability qualifying for up to $1,000,000 under Aptos bug bounty criteria:

1. **Consensus/Safety Violations**: Nodes restored from maliciously crafted backups will have incompatible state, causing consensus splits and potential chain forks
2. **State Consistency Breach**: Restored nodes may have state from different blockchain forks, breaking deterministic execution guarantees
3. **Network Partition Risk**: Validators restored with misaligned state will reject valid blocks and could require hard fork to recover

The comment at line 284-285 acknowledges this: "node won't be able to start if this data is malicious" - but this protection is not implemented at restoration time, only hoped for at node startup.

## Likelihood Explanation

**HIGH likelihood** - The attack requires:
1. Access to upload malicious metadata to backup storage (cloud bucket, shared storage)
2. Ability to reference existing backup files or create fake backup manifests
3. Target node operator initiating restoration from the compromised backup location

This is realistic because:
- Backup storage is often less secured than production systems
- Many operators use shared backup infrastructure
- Metadata files are JSON/plain text, easily modified
- No authentication/integrity checks on metadata files themselves

## Recommendation

Add mandatory cross-validation in `MetadataView::new()` to ensure epoch alignment:

```rust
pub(crate) fn new(metadata_vec: Vec<Metadata>, file_handles: Vec<FileHandle>) -> Result<Self> {
    // ... existing code for sorting and deduping ...
    
    // Validate epoch alignment
    if !state_snapshot_backups.is_empty() && !epoch_ending_backups.is_empty() {
        for snapshot in &state_snapshot_backups {
            // Find epoch ending that covers this snapshot's version
            let epoch_at_version = epoch_ending_backups
                .iter()
                .find(|e| e.first_version <= snapshot.version && snapshot.version <= e.last_version)
                .ok_or_else(|| anyhow!(
                    "No epoch ending found for state snapshot at version {} (claimed epoch {})",
                    snapshot.version, snapshot.epoch
                ))?;
            
            ensure!(
                epoch_at_version.first_epoch <= snapshot.epoch && 
                snapshot.epoch <= epoch_at_version.last_epoch,
                "State snapshot epoch {} doesn't align with epoch ending at version {}",
                snapshot.epoch, snapshot.version
            );
        }
    }
    
    // Ensure epoch history is complete up to target version
    if let Some(max_snapshot_epoch) = state_snapshot_backups.iter().map(|s| s.epoch).max() {
        if let Some(max_epoch_ending) = epoch_ending_backups.iter().map(|e| e.last_epoch).max() {
            ensure!(
                max_epoch_ending >= max_snapshot_epoch,
                "Incomplete epoch history: snapshots go up to epoch {}, but epoch endings only cover up to epoch {}",
                max_snapshot_epoch, max_epoch_ending
            );
        }
    }
    
    Ok(Self { /* ... */ })
}
```

Additionally, remove the bypass in `verify_ledger_info` - make incomplete epoch history a hard error:

```rust
pub fn verify_ledger_info(&self, li_with_sigs: &LedgerInfoWithSignatures) -> Result<()> {
    let epoch = li_with_sigs.ledger_info().epoch();
    ensure!(!self.epoch_endings.is_empty(), "Empty epoch history.");
    ensure!(
        epoch <= self.epoch_endings.len() as u64,
        "Epoch {} is beyond epoch history coverage (max epoch {}). Cannot verify signature.",
        epoch, self.epoch_endings.len() - 1
    );
    // ... rest of verification ...
}
```

## Proof of Concept

Create malicious metadata files:

```json
// epoch_ending_0-5.meta
{"EpochEndingBackup":{"first_epoch":0,"last_epoch":5,"first_version":0,"last_version":500,"manifest":"epoch_0-5.manifest"}}

// state_snapshot_ver_10000.meta (from different chain, epoch 100)
{"StateSnapshotBackup":{"epoch":100,"version":10000,"manifest":"snapshot_10000.manifest"}}

// transaction_10001-20000.meta
{"TransactionBackup":{"first_version":10001,"last_version":20000,"manifest":"txn_10001-20000.manifest"}}
```

Run restoration:
```bash
aptos-db-tool restore bootstrap-db \
    --metadata-cache-dir ./malicious_metadata \
    --target-version 20000
```

Expected behavior: Restoration succeeds with warnings, creating inconsistent state
Actual secure behavior: Should fail with "Incomplete epoch history" error

**Notes**

The vulnerability exists because the system relies on "defense in depth" - assuming that if initial chunks are verified, later chunks are safe. However, when an attacker controls metadata selection, they can provide minimal verified initial data (epochs 0-5) and append unverified data from incompatible sources. The TODO comment acknowledges this needs fixing "from upper level" but no such fix exists in `MetadataView::new()` or the restore coordinator.

### Citations

**File:** storage/backup/backup-cli/src/metadata/view.rs (L29-78)
```rust
    pub(crate) fn new(metadata_vec: Vec<Metadata>, file_handles: Vec<FileHandle>) -> Self {
        let mut epoch_ending_backups = Vec::new();
        let mut state_snapshot_backups = Vec::new();
        let mut transaction_backups = Vec::new();
        let mut identity = None;
        let mut compaction_timestamps = Vec::new();

        for meta in metadata_vec {
            match meta {
                Metadata::EpochEndingBackup(e) => epoch_ending_backups.push(e),
                Metadata::StateSnapshotBackup(s) => state_snapshot_backups.push(s),
                Metadata::TransactionBackup(t) => transaction_backups.push(t),
                Metadata::Identity(i) => identity = Some(i),
                Metadata::CompactionTimestamps(t) => compaction_timestamps.push(t),
            }
        }
        epoch_ending_backups.sort_unstable();
        epoch_ending_backups.dedup();
        state_snapshot_backups.sort_unstable();
        state_snapshot_backups.dedup();
        transaction_backups.sort_unstable();
        transaction_backups.dedup();

        let mut compaction_meta_opt = compaction_timestamps.iter().max().cloned();
        if let Some(ref mut compaction_meta) = compaction_meta_opt {
            // insert new_files into the previous_compaction_timestamps
            for file in file_handles.into_iter() {
                // if file is not in timestamps, set it to None, otherwise, keep it the same
                compaction_meta
                    .compaction_timestamps
                    .entry(file)
                    .or_insert(None);
            }
        } else {
            // Create new compaction timestamp meta with new files only
            let compaction_timestamps = file_handles.into_iter().map(|file| (file, None)).collect();
            compaction_meta_opt = Some(CompactionTimestampsMeta {
                file_compacted_at: duration_since_epoch().as_secs(),
                compaction_timestamps,
            });
        };

        Self {
            epoch_ending_backups,
            state_snapshot_backups,
            transaction_backups,
            _identity: identity,
            compaction_timestamps: compaction_meta_opt,
        }
    }
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L276-288)
```rust
    pub fn verify_ledger_info(&self, li_with_sigs: &LedgerInfoWithSignatures) -> Result<()> {
        let epoch = li_with_sigs.ledger_info().epoch();
        ensure!(!self.epoch_endings.is_empty(), "Empty epoch history.",);
        if epoch > self.epoch_endings.len() as u64 {
            // TODO(aldenhu): fix this from upper level
            warn!(
                epoch = epoch,
                epoch_history_until = self.epoch_endings.len(),
                "Epoch is too new and can't be verified. Previous chunks are verified and node \
                won't be able to start if this data is malicious."
            );
            return Ok(());
        }
```

**File:** storage/backup/backup-cli/src/coordinators/restore.rs (L211-213)
```rust
        let transaction_backups =
            metadata_view.select_transaction_backups(txn_start_version, target_version)?;
        let epoch_ending_backups = metadata_view.select_epoch_ending_backups(target_version)?;
```

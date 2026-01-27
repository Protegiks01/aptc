# Audit Report

## Title
Panic-Induced DoS in Epoch Ending Restore Due to Empty Ledger Info Vector After Filtering

## Summary
The `PreheatedEpochEndingRestore::run_impl()` function contains two `expect()` calls that panic when the `ledger_infos` vector is empty. An attacker can craft backup data or a misconfiguration can occur where all ledger infos have versions exceeding the `target_version`, causing all entries to be filtered out during the preheat phase, resulting in a node crash during restore operations.

## Finding Description
The vulnerability exists in the epoch ending backup restore process. The issue manifests through the following execution path:

1. In `preheat_impl()`, ledger infos are loaded from backup chunks and filtered based on whether their version exceeds `target_version`. [1](#0-0) 

2. If ALL ledger infos across ALL chunks have versions greater than `target_version`, they are all filtered out, and the `ledger_infos` vector remains empty. [2](#0-1) 

3. The function successfully returns with an empty vector since there's no validation check. [3](#0-2) 

4. In `run_impl()`, the code calls `first().expect()` on the potentially empty vector, causing a panic. [4](#0-3) 

5. Similarly, `last().expect()` is called later, which would also panic if reached. [5](#0-4) 

The manifest verification only checks structural integrity (chunk continuity, epoch ranges), not version compatibility. [6](#0-5) 

The `target_version` parameter is user-controllable through CLI arguments and defaults to `Version::MAX` if not specified. [7](#0-6) [8](#0-7) 

**Attack Scenario:**
- Attacker provides backup data where all ledger info versions are ≥ 1000
- Node operator attempts restore with `--target-version 500`
- All ledger infos are filtered during preheat
- Node panics with "Epoch ending backup can't be empty."

## Impact Explanation
This is a **Medium Severity** vulnerability per the Aptos bug bounty criteria. It causes a Denial of Service (DoS) by crashing the node process during backup restoration. The impact includes:

- **Availability Violation**: Node crashes during critical restore operations
- **Recovery Prevention**: Prevents nodes from successfully restoring from backups, which is essential for disaster recovery scenarios
- **Operational Disruption**: Operators must identify and fix the incompatibility issue before restoration can succeed

While this doesn't directly affect consensus or cause fund loss, it impacts the operational resilience of the network by preventing backup-based recovery mechanisms. For comparison, the state-sync component properly handles empty epoch ending payloads by returning an error rather than panicking. [9](#0-8) 

## Likelihood Explanation
**Likelihood: Medium**

This vulnerability can manifest in two scenarios:

1. **Malicious Attack**: An attacker with control over backup storage (e.g., compromised S3 bucket, malicious backup provider) intentionally crafts incompatible backup data.

2. **Operational Misconfiguration**: More commonly, this occurs when operators attempt partial restores using `--target-version` against backups containing only newer epochs, which is a legitimate operational scenario.

The backup system is designed to accept data from various sources including remote storage. [10](#0-9) 

The attack requires no special privileges - only the ability to influence backup data or CLI parameters used during restore operations.

## Recommendation
Replace the `expect()` calls with proper error handling that validates the vector is non-empty before accessing elements:

```rust
async fn run_impl(
    self,
    previous_epoch_ending_ledger_info: Option<&LedgerInfo>,
) -> Result<Vec<LedgerInfo>> {
    let preheat_data = self
        .preheat_result
        .map_err(|e| anyhow!("Preheat failed: {}", e))?;

    // Add validation BEFORE accessing first element
    ensure!(
        !preheat_data.ledger_infos.is_empty(),
        "No epoch endings found within target version {}. \
         Backup contains epochs with versions higher than target. \
         Either increase target_version or use a different backup.",
        self.controller.target_version
    );

    let first_li = preheat_data
        .ledger_infos
        .first()
        .unwrap(); // Safe after the ensure check

    // ... rest of the function ...

    let last_li = preheat_data
        .ledger_infos
        .last()
        .unwrap() // Safe after the ensure check
        .ledger_info();
    
    // ... rest of the function ...
}
```

Alternatively, validate in `preheat_impl()` before returning, providing clearer error context about the filtering that occurred.

## Proof of Concept
```rust
// PoC demonstrating the panic scenario
// This would be integrated into the backup-cli crate's test suite

#[tokio::test]
async fn test_empty_ledger_infos_after_filtering_causes_panic() {
    // Setup: Create a mock backup with ledger infos at version 1000+
    let manifest = EpochEndingBackup {
        first_epoch: 0,
        last_epoch: 0,
        waypoints: vec![/* waypoint at version 1000 */],
        chunks: vec![EpochEndingChunk {
            first_epoch: 0,
            last_epoch: 0,
            ledger_infos: /* handle pointing to LI with version 1000 */,
        }],
    };
    
    // Create controller with target_version = 500
    let controller = EpochEndingRestoreController {
        storage: Arc::new(/* mock storage with manifest */),
        run_mode: Arc::new(RestoreRunMode::Verify),
        manifest_handle: /* handle */,
        target_version: 500, // Lower than all LI versions
        trusted_waypoints: Arc::new(HashMap::new()),
    };
    
    // Run restore - this will panic
    let result = controller.run(None).await;
    
    // Expected: Should return an error, not panic
    // Actual: Panics with "Epoch ending backup can't be empty."
    assert!(result.is_err());
}
```

## Notes
The vulnerability is confirmed through code analysis. The filtering logic correctly implements version-based truncation, but lacks validation for the edge case where ALL entries are filtered. The state-sync subsystem demonstrates the proper pattern for handling this scenario by explicitly checking for empty payloads and returning descriptive errors rather than panicking.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L28-32)
```rust
#[derive(Parser)]
pub struct EpochEndingRestoreOpt {
    #[clap(long = "epoch-ending-manifest")]
    pub manifest_handle: FileHandle,
}
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L89-89)
```rust
        let mut ledger_infos = Vec::new();
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L108-111)
```rust
                if li.ledger_info().version() > self.target_version {
                    past_target = true;
                    break;
                }
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L154-157)
```rust
        Ok(EpochEndingRestorePreheatData {
            manifest,
            ledger_infos,
        })
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L213-216)
```rust
        let first_li = preheat_data
            .ledger_infos
            .first()
            .expect("Epoch ending backup can't be empty.");
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L242-246)
```rust
        let last_li = preheat_data
            .ledger_infos
            .last()
            .expect("Verified not empty.")
            .ledger_info();
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/manifest.rs (L29-68)
```rust
    pub fn verify(&self) -> Result<()> {
        // check number of waypoints
        ensure!(
            self.first_epoch <= self.last_epoch
                && self.last_epoch - self.first_epoch + 1 == self.waypoints.len() as u64,
            "Malformed manifest. first epoch: {}, last epoch {}, num waypoints {}",
            self.first_epoch,
            self.last_epoch,
            self.waypoints.len(),
        );

        // check chunk ranges
        ensure!(!self.chunks.is_empty(), "No chunks.");
        let mut next_epoch = self.first_epoch;
        for chunk in &self.chunks {
            ensure!(
                chunk.first_epoch == next_epoch,
                "Chunk ranges not continuous. Expected first epoch: {}, actual: {}.",
                next_epoch,
                chunk.first_epoch,
            );
            ensure!(
                chunk.last_epoch >= chunk.first_epoch,
                "Chunk range invalid. [{}, {}]",
                chunk.first_epoch,
                chunk.last_epoch,
            );
            next_epoch = chunk.last_epoch + 1;
        }

        // check last epoch in chunk matches manifest
        ensure!(
            next_epoch - 1 == self.last_epoch, // okay to -1 because chunks is not empty.
            "Last epoch in chunks: {}, in manifest: {}",
            next_epoch - 1,
            self.last_epoch,
        );

        Ok(())
    }
```

**File:** storage/backup/backup-cli/src/utils/mod.rs (L151-151)
```rust
    pub target_version: Option<Version>,
```

**File:** storage/backup/backup-cli/src/utils/mod.rs (L294-294)
```rust
        let target_version = opt.target_version.unwrap_or(Version::MAX);
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L1081-1089)
```rust
        if epoch_ending_ledger_infos.is_empty() {
            self.reset_active_stream(Some(NotificationAndFeedback::new(
                notification_id,
                NotificationFeedback::EmptyPayloadData,
            )))
            .await?;
            return Err(Error::VerificationError(
                "The epoch ending payload was empty!".into(),
            ));
```

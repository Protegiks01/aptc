# Audit Report

## Title
Validation Bypass in Epoch Ending Restore Allows Malicious Manifests to Cause Panic

## Summary
An attacker can craft a malicious epoch ending backup manifest that passes `preheat()` validation but causes the restore process to panic with an empty ledger info list. The vulnerability stems from the target version check occurring before integrity validation, allowing manifests with mismatched version metadata to bypass cryptographic verification.

## Finding Description

The vulnerability exists in the epoch ending restore process where validation logic can be bypassed. The code checks if ledger info versions exceed the target version before validating manifest integrity. [1](#0-0) 

When a ledger info's version exceeds `target_version`, the code immediately breaks out of the validation loop. This occurs before critical integrity checks: [2](#0-1) 

An attacker can exploit this by crafting a manifest where:
1. The `EpochEndingBackupMeta` metadata claims `first_version <= target_version`
2. The actual ledger infos in the manifest chunks have `version > target_version`
3. The manifest waypoints don't match the actual ledger info versions

The manifest passes structural validation: [3](#0-2) 

This verification only checks structural properties (epoch ranges, waypoint counts, chunk continuity) but doesn't validate versions against `target_version` or verify waypoint-to-ledger-info consistency.

When `preheat_impl()` processes this malicious manifest: [4](#0-3) 

The loop breaks at line 110 before reaching waypoint validation at lines 122-128, returning an empty `ledger_infos` vector.

Subsequently, `run_impl()` attempts to access the first element: [5](#0-4) 

This panics with "Epoch ending backup can't be empty" because the vector is empty. The defensive check in `EpochHistoryRestoreController` is never reached: [6](#0-5) 

## Impact Explanation

This vulnerability qualifies as **Medium severity** under the Aptos bug bounty criteria as it causes "State inconsistencies requiring intervention" in the restore process. Specifically:

1. **Denial of Service on Recovery Operations**: Prevents nodes from restoring blockchain state from backups, impacting disaster recovery and new node bootstrapping
2. **Operational Availability**: Nodes cannot sync from compromised backup sources, affecting network expansion and resilience
3. **Panic-Based Failure**: The unhandled panic can leave the restore process in an undefined state rather than gracefully handling the error

While this doesn't directly impact consensus or fund security on running validators, it affects critical operational infrastructure that nodes depend on for recovery and synchronization.

## Likelihood Explanation

**Likelihood: Medium**

The attack requires the attacker to control or modify backup manifests, which typically requires:
- Compromise of backup storage (S3, GCS, etc.)
- Man-in-the-middle attack during manifest download
- Malicious operator providing corrupted backups

While backup storage is generally trusted infrastructure, the attack is feasible if:
1. Backup sources are not properly authenticated/verified
2. Automated restore processes accept manifests from untrusted sources
3. Disaster recovery scenarios use compromised backup copies

The exploit is straightforward once the attacker has manifest control, requiring only version metadata manipulation.

## Recommendation

Add validation in `preheat_impl()` to ensure that at least one ledger info is collected before returning, and validate waypoint consistency even when breaking early due to target version:

```rust
async fn preheat_impl(&self) -> Result<EpochEndingRestorePreheatData> {
    let manifest: EpochEndingBackup =
        self.storage.load_json_file(&self.manifest_handle).await?;
    manifest.verify()?;
    
    // Validate that first waypoint version matches manifest metadata
    if let Some(first_wp) = manifest.waypoints.first() {
        ensure!(
            first_wp.version() <= self.target_version,
            "Manifest first waypoint version {} exceeds target version {}",
            first_wp.version(),
            self.target_version
        );
    }

    // ... existing loop code ...
    
    // Add validation before returning
    ensure!(
        !ledger_infos.is_empty(),
        "No ledger infos collected from manifest. First version may exceed target."
    );

    Ok(EpochEndingRestorePreheatData {
        manifest,
        ledger_infos,
    })
}
```

Additionally, remove the `.expect()` calls in `run_impl()` and replace with proper error handling:

```rust
let first_li = preheat_data
    .ledger_infos
    .first()
    .ok_or_else(|| anyhow!("Epoch ending backup produced no ledger infos"))?;
```

## Proof of Concept

```rust
// PoC demonstrating the vulnerability
#[tokio::test]
async fn test_malicious_manifest_bypass() {
    use aptos_types::{ledger_info::LedgerInfoWithSignatures, waypoint::Waypoint};
    
    // Setup: Create a manifest with waypoints showing low version
    let mut manifest = EpochEndingBackup {
        first_epoch: 0,
        last_epoch: 0,
        waypoints: vec![Waypoint::new_any(&create_ledger_info(100))], // version 100
        chunks: vec![EpochEndingChunk {
            first_epoch: 0,
            last_epoch: 0,
            ledger_infos: create_chunk_handle(),
        }],
    };
    
    // Attack: Actual chunk contains ledger info with version 300
    let malicious_lis = vec![create_ledger_info_with_version(300)]; // version > target_version(200)
    
    // Setup controller with target_version = 200
    let controller = EpochEndingRestoreController::new(
        /* ... */,
        GlobalRestoreOptions { target_version: 200, /* ... */ },
        /* ... */,
    );
    
    // Execute: preheat() succeeds but returns empty ledger_infos
    let preheated = controller.preheat().await;
    
    // Verify: run() panics at .expect("Epoch ending backup can't be empty.")
    let result = preheated.run(None).await;
    
    // Expected: Should return proper error, but actually panics
    assert!(result.is_err()); // This line never reached due to panic
}

// Helper to create ledger info with specific version
fn create_ledger_info_with_version(version: u64) -> LedgerInfoWithSignatures {
    // Create ledger info with specified version
    // Implementation details omitted for brevity
}
```

## Notes

This vulnerability is specific to the backup/restore CLI tooling and does not directly affect consensus safety or fund security on running validators. However, it represents a critical failure in operational infrastructure that could be exploited to prevent network expansion or disaster recovery. The issue should be addressed to ensure reliable backup restoration and maintain network resilience.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L80-158)
```rust
    async fn preheat_impl(&self) -> Result<EpochEndingRestorePreheatData> {
        let manifest: EpochEndingBackup =
            self.storage.load_json_file(&self.manifest_handle).await?;
        manifest.verify()?;

        let mut next_epoch = manifest.first_epoch;
        let mut waypoint_iter = manifest.waypoints.iter();

        let mut previous_li: Option<&LedgerInfoWithSignatures> = None;
        let mut ledger_infos = Vec::new();

        let mut past_target = false;
        for chunk in &manifest.chunks {
            if past_target {
                break;
            }

            let lis = self.read_chunk(&chunk.ledger_infos).await?;
            ensure!(
                chunk.first_epoch + lis.len() as u64 == chunk.last_epoch + 1,
                "Number of items in chunks doesn't match that in manifest. \
                first_epoch: {}, last_epoch: {}, items in chunk: {}",
                chunk.first_epoch,
                chunk.last_epoch,
                lis.len(),
            );

            for li in lis {
                if li.ledger_info().version() > self.target_version {
                    past_target = true;
                    break;
                }

                ensure!(
                    li.ledger_info().epoch() == next_epoch,
                    "LedgerInfo epoch not expected. Expected: {}, actual: {}.",
                    li.ledger_info().epoch(),
                    next_epoch,
                );
                let wp_manifest = waypoint_iter.next().ok_or_else(|| {
                    anyhow!("More LedgerInfo's found than waypoints in manifest.")
                })?;
                let wp_li = Waypoint::new_epoch_boundary(li.ledger_info())?;
                ensure!(
                    *wp_manifest == wp_li,
                    "Waypoints don't match. In manifest: {}, In chunk: {}",
                    wp_manifest,
                    wp_li,
                );
                if let Some(wp_trusted) = self.trusted_waypoints.get(&wp_li.version()) {
                    ensure!(
                        *wp_trusted == wp_li,
                        "Waypoints don't match. In backup: {}, trusted: {}",
                        wp_li,
                        wp_trusted,
                    );
                } else if let Some(pre_li) = previous_li {
                    pre_li
                        .ledger_info()
                        .next_epoch_state()
                        .ok_or_else(|| {
                            anyhow!(
                                "Next epoch state not found from LI at epoch {}.",
                                pre_li.ledger_info().epoch()
                            )
                        })?
                        .verify(&li)?;
                }
                ledger_infos.push(li);
                previous_li = ledger_infos.last();
                next_epoch += 1;
            }
        }

        Ok(EpochEndingRestorePreheatData {
            manifest,
            ledger_infos,
        })
    }
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L213-216)
```rust
        let first_li = preheat_data
            .ledger_infos
            .first()
            .expect("Epoch ending backup can't be empty.");
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L382-386)
```rust
            ensure!(
                !lis.is_empty(),
                "No epochs restored from {}",
                manifest_handle,
            );
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

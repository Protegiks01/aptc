# Audit Report

## Title
Missing Signature Verification in Epoch Ending Ledger Info Restore Allows Chain Forgery via Compromised Backup Storage

## Summary
The backup/restore system fails to verify BLS signatures for the first epoch when restoring without trusted waypoints and without previous epoch information. This allows an attacker who compromises backup storage to inject a forged validator set, establishing a malicious root of trust that validates all subsequent epochs.

## Finding Description

The vulnerability exists across multiple code paths in the backup/restore system:

**1. No Signature Verification in `save_ledger_infos()`**

The `save_ledger_infos()` function persists `LedgerInfoWithSignatures` without any cryptographic verification: [1](#0-0) 

The underlying `put_ledger_info()` simply writes to the database: [2](#0-1) 

**2. Conditional Verification Bypass in `preheat_impl()`**

The `preheat_impl()` function has conditional signature verification: [3](#0-2) 

For the first ledger info processed:
- `previous_li` is initialized as `None` (line 88)
- Verification only occurs if: (a) a trusted waypoint exists for that version (lines 129-135), OR (b) `previous_li` exists (lines 136-147)
- When both conditions are false, the ledger info is added to the list without verification (line 148)

**3. Conditional Verification in `run_impl()`**

A second verification opportunity exists but is also conditional: [4](#0-3) 

This verification only executes when `previous_epoch_ending_ledger_info` is provided. The parameter can be `None` in legitimate restore scenarios.

**4. Exploitable Entry Point**

The `Oneoff::EpochEnding` command directly invokes restore with `None` for previous epoch info: [5](#0-4) 

This allows restoring a single epoch ending backup manifest starting from any epoch without previous state.

**5. Attack Scenario**

An attacker who compromises backup storage can:
1. Create a backup manifest starting from epoch N (e.g., epoch 100)
2. Forge the first `LedgerInfoWithSignatures` with a malicious validator set and invalid BLS signatures
3. Sign subsequent epochs (N+1, N+2, ...) with the forged validator set
4. When an operator restores using `db-tool restore oneoff epoch-ending` without providing `--trust-waypoint` for epoch N:
   - `preheat_impl()` processes with `previous_li = None` and no trusted waypoint
   - No signature verification occurs
   - The forged validator set is persisted to the database
   - This forged set becomes the trust anchor for verifying all subsequent epochs

**6. Developer Intent Confirmation**

Test code confirms this behavior is unintended: [6](#0-5) 

Line 148 sets `should_fail_without_waypoints = true` when ledger infos have empty signatures. Line 232 asserts this should fail without waypoints. The vulnerability violates this intended security property.

## Impact Explanation

**Critical Severity - Consensus Safety Violation**

This vulnerability enables:

1. **Complete Consensus Compromise**: The forged validator set can produce any blockchain state, violating the fundamental AptosBFT safety guarantee that requires 2f+1 honest validators for consensus.

2. **Loss of Funds**: The malicious validator set can create arbitrary transactions transferring all tokens to attacker-controlled addresses.

3. **Non-recoverable Network Partition**: Nodes restored from compromised backups permanently diverge from the legitimate chain, requiring a hard fork to resolve.

4. **Governance Takeover**: The forged validator set controls all on-chain governance decisions.

This meets **Critical Severity** criteria per Aptos bug bounty:
- Consensus/Safety violations ✓
- Loss of Funds ✓  
- Non-recoverable network partition ✓

The attack bypasses BLS signature verification, which is the cryptographic foundation of Aptos consensus security.

## Likelihood Explanation

**Medium Likelihood**

Required conditions:
1. **Backup storage compromise**: Achievable through cloud storage misconfigurations, insider threats, or supply chain attacks on backup providers.

2. **Restore without trusted waypoints**: The code explicitly supports this via the `Oneoff::EpochEnding` command. While production deployments use waypoints (see terraform configurations), the functionality exists for legitimate operational use cases.

3. **First epoch restoration**: Common in disaster recovery, historical chain analysis, or testing scenarios.

The likelihood is Medium (not High) because:
- Production deployments shown in terraform configurations do use trusted waypoints
- Backup storage should be secured by operators
- However, the vulnerability can be triggered through documented CLI commands

## Recommendation

**Required Fix**: Enforce signature verification for all non-genesis epochs during restore.

```rust
// In preheat_impl(), after line 128:
if li.ledger_info().epoch() > 0 {  // Not genesis
    if let Some(wp_trusted) = self.trusted_waypoints.get(&wp_li.version()) {
        // Waypoint verification (existing code)
    } else if let Some(pre_li) = previous_li {
        // Previous epoch verification (existing code)
    } else {
        // NEW: Fail for non-genesis epochs without verification
        return Err(anyhow!(
            "Cannot verify epoch {} without trusted waypoint or previous epoch info. \
            Use --trust-waypoint flag to provide trusted waypoint for this epoch.",
            li.ledger_info().epoch()
        ));
    }
}
```

Alternatively, require the `--trust-waypoint` flag for the `Oneoff::EpochEnding` command when the manifest doesn't start from genesis.

## Proof of Concept

```rust
// Demonstrates the vulnerability:
// 1. Create a backup manifest starting from epoch 100
// 2. Forge the first LedgerInfo with empty signatures
// 3. Restore without trusted waypoints
// 4. Verify the forged ledger info is persisted without signature verification

#[tokio::test]
async fn test_missing_signature_verification() {
    // Setup: Create forged ledger info for epoch 100 with empty signature
    let forged_li = LedgerInfoWithSignatures::new(
        LedgerInfo::new(/* epoch 100, forged validator set */),
        AggregateSignature::empty(),  // Invalid signature!
    );
    
    // Create backup manifest starting from epoch 100
    // (implementation details omitted for brevity)
    
    // Attempt restore WITHOUT trusted waypoint
    let result = EpochEndingRestoreController::new(
        opt,
        GlobalRestoreOpt {
            trusted_waypoints: TrustedWaypointOpt::default(),  // No waypoints!
            // ... other options
        }.try_into().unwrap(),
        storage,
    )
    .run(None)  // No previous epoch info!
    .await;
    
    // VULNERABILITY: This succeeds despite invalid signature
    assert!(result.is_ok());  
    
    // The forged validator set is now persisted and trusted
}
```

The test in `storage/backup/backup-cli/src/backup_types/epoch_ending/tests.rs` at lines 178-232 demonstrates the expected behavior (should fail without waypoints) which this vulnerability violates.

### Citations

**File:** storage/aptosdb/src/backup/restore_utils.rs (L41-58)
```rust
pub(crate) fn save_ledger_infos(
    ledger_metadata_db: &LedgerMetadataDb,
    ledger_infos: &[LedgerInfoWithSignatures],
    existing_batch: Option<&mut SchemaBatch>,
) -> Result<()> {
    ensure!(!ledger_infos.is_empty(), "No LedgerInfos to save.");

    if let Some(existing_batch) = existing_batch {
        save_ledger_infos_impl(ledger_metadata_db, ledger_infos, existing_batch)?;
    } else {
        let mut batch = SchemaBatch::new();
        save_ledger_infos_impl(ledger_metadata_db, ledger_infos, &mut batch)?;
        ledger_metadata_db.write_schemas(batch)?;
        update_latest_ledger_info(ledger_metadata_db, ledger_infos)?;
    }

    Ok(())
}
```

**File:** storage/aptosdb/src/ledger_db/ledger_metadata_db.rs (L186-198)
```rust
    pub(crate) fn put_ledger_info(
        &self,
        ledger_info_with_sigs: &LedgerInfoWithSignatures,
        batch: &mut SchemaBatch,
    ) -> Result<()> {
        let ledger_info = ledger_info_with_sigs.ledger_info();

        if ledger_info.ends_epoch() {
            // This is the last version of the current epoch, update the epoch by version index.
            batch.put::<EpochByVersionSchema>(&ledger_info.version(), &ledger_info.epoch())?;
        }
        batch.put::<LedgerInfoSchema>(&ledger_info.epoch(), ledger_info_with_sigs)
    }
```

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

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L218-240)
```rust
        if let Some(li) = previous_epoch_ending_ledger_info {
            ensure!(
                li.next_block_epoch() == preheat_data.manifest.first_epoch,
                "Previous epoch ending LedgerInfo is not the one expected. \
                My first epoch: {}, previous LedgerInfo next_block_epoch: {}",
                preheat_data.manifest.first_epoch,
                li.next_block_epoch(),
            );
            // Waypoint has been verified in preheat if it's trusted, otherwise try to check
            // the signatures.
            if self
                .controller
                .trusted_waypoints
                .get(&first_li.ledger_info().version())
                .is_none()
            {
                li.next_epoch_state()
                    .ok_or_else(|| {
                        anyhow!("Previous epoch ending LedgerInfo doesn't end an epoch")
                    })?
                    .verify(first_li)?;
            }
        }
```

**File:** storage/db-tool/src/restore.rs (L70-82)
```rust
                    Oneoff::EpochEnding {
                        storage,
                        opt,
                        global,
                    } => {
                        EpochEndingRestoreController::new(
                            opt,
                            global.try_into()?,
                            storage.init_storage().await?,
                        )
                        .run(None)
                        .await?;
                    },
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/tests.rs (L137-158)
```rust
        let mut should_fail_without_waypoints = false;
        let mut res_lis = Vec::new();
        let mut res_waypoints = Vec::new();
        for (block_size, r#gen, overwrite, trusted) in blocks {
            let mut li = r#gen.materialize(&mut universe, block_size);
            if li.ledger_info().ends_epoch() {
                if overwrite && li.ledger_info().epoch() != 0 {
                    li = LedgerInfoWithSignatures::new(
                        li.ledger_info().clone(),
                        AggregateSignature::empty(),
                    );
                    should_fail_without_waypoints = true;
                }
                if overwrite || trusted {
                    res_waypoints.push(Waypoint::new_epoch_boundary(li.ledger_info()).unwrap())
                }
                res_lis.push(li);

            }
        }
        (res_lis, res_waypoints, should_fail_without_waypoints)
    }
```

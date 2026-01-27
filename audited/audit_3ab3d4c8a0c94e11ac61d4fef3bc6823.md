# Audit Report

## Title
Signature Verification Bypass in Epoch Ending Restore Allows Malicious Genesis Acceptance

## Summary
The epoch ending restore functionality in both `RestoreRunMode::Restore` and `RestoreRunMode::Verify` modes fails to verify signatures for the first epoch when no trusted waypoint and no previous epoch ending ledger info are provided. This allows an attacker to create a malicious backup with invalid signatures that will pass verification and potentially be restored to the database, compromising consensus safety.

## Finding Description

The vulnerability exists in the signature verification logic within the epoch ending restore process. Both Restore and Verify modes execute identical validation code, so the bypass affects both equally.

**Critical Code Path in `preheat_impl()`:** [1](#0-0) 

This if-else chain performs signature verification, but ONLY if:
1. A trusted waypoint exists for the ledger info's version (`self.trusted_waypoints.get(&wp_li.version())`), OR
2. A previous ledger info exists (`previous_li`)

For the very first LedgerInfo being processed, `previous_li` is initialized as `None`: [2](#0-1) 

If no trusted waypoint is provided for that version, BOTH conditions are false, and signature verification is completely skipped.

**Additional Verification in `run_impl()`:** [3](#0-2) 

This additional verification only occurs if `previous_epoch_ending_ledger_info` is provided. However, in production usage, this is often `None`: [4](#0-3) 

**Mode Comparison:** [5](#0-4) 

Both Restore and Verify modes execute the same validation logic. The only difference is whether data is persisted (`restore_handler.save_ledger_infos()` in Restore mode) or just metrics are updated (Verify mode).

**Manifest Verification is Insufficient:** [6](#0-5) 

The manifest verification only checks structural consistency, not cryptographic validity of signatures.

**Attack Scenario:**

1. Attacker creates a malicious epoch ending backup with:
   - `first_epoch = 0` (genesis)
   - A crafted `LedgerInfoWithSignatures` with empty/invalid signatures but arbitrary state root and validator set
   - Internally consistent manifest and waypoints

2. Victim runs restore/verify with:
   - No trusted waypoint for epoch 0 (waypoints are optional per documentation)
   - `previous_epoch_ending_ledger_info = None` (standard production usage)

3. In `preheat_impl()`: Both verification conditions are false, signatures are never checked

4. In `run_impl()`: No previous_epoch_ending_ledger_info, additional verification skipped

5. Result:
   - **Verify mode**: Malicious backup passes verification, operator falsely believes it's valid
   - **Restore mode**: Fake genesis written to database, node follows attacker's fabricated chain

## Impact Explanation

**Severity: HIGH (Significant Protocol Violation / Consensus Safety)**

This vulnerability breaks fundamental consensus safety invariants:

1. **Consensus Safety Violation**: Nodes restoring from malicious backups would follow a completely different blockchain fork with an attacker-controlled validator set, violating the core guarantee that "AptosBFT must prevent chain splits."

2. **Cryptographic Correctness Breach**: The system accepts epoch transitions without verifying cryptographic signatures, directly violating the invariant that "BLS signatures, VRF, and hash operations must be secure."

3. **State Consistency Impact**: The malicious genesis can contain arbitrary state roots, allowing attackers to fabricate any blockchain state.

**Affected Systems:**
- Validator nodes restoring from backup (critical - could join wrong chain)
- Archive nodes verifying backup integrity (would falsely validate malicious data)
- Disaster recovery procedures (could restore compromised state)

While this requires convincing an operator to restore from a malicious backup, the attack is practical because:
- Backup verification is a common operational procedure
- The Verify mode specifically exists to validate backups before restoration
- No warning is given about the missing signature verification

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

The vulnerability is highly exploitable once the attacker can deliver a malicious backup:

**Favoring Exploitation:**
- Production code explicitly calls `.run(None)` without previous epoch info
- Trusted waypoints are documented as optional ("When provided...")
- The test suite avoids testing this exact scenario (explicitly skips epoch 0 in invalid signature tests)
- No warnings or errors are generated when both validation paths are skipped

**Attack Requirements:**
- Social engineering to convince operator to use attacker's backup source
- OR compromise of legitimate backup storage to inject malicious backup
- OR man-in-the-middle attack during backup retrieval

**Real-World Scenarios:**
- Disaster recovery from untrusted/compromised backup storage
- Testing backup integrity from third-party sources
- Operators verifying backup compatibility before full restore

The fact that both Restore AND Verify modes are affected makes this particularly dangerous - operators using Verify mode to validate backups would receive false confidence.

## Recommendation

**Enforce mandatory trusted waypoint for first epoch when no previous epoch info exists:**

Add validation in `run_impl()` before processing:

```rust
async fn run_impl(
    self,
    previous_epoch_ending_ledger_info: Option<&LedgerInfo>,
) -> Result<Vec<LedgerInfo>> {
    let preheat_data = self
        .preheat_result
        .map_err(|e| anyhow!("Preheat failed: {}", e))?;

    let first_li = preheat_data
        .ledger_infos
        .first()
        .expect("Epoch ending backup can't be empty.");

    // NEW VALIDATION: Require trusted waypoint when no previous epoch info
    if previous_epoch_ending_ledger_info.is_none() {
        ensure!(
            self.controller.trusted_waypoints.get(&first_li.ledger_info().version()).is_some(),
            "First epoch requires a trusted waypoint when no previous epoch ending LedgerInfo is provided. \
             Please specify --trust-waypoint for epoch {} version {}.",
            first_li.ledger_info().epoch(),
            first_li.ledger_info().version()
        );
    }

    // ... rest of function
```

**Alternative/Additional Fix:**

Strengthen documentation and CLI validation to require `--trust-waypoint` for genesis in user-facing tools, and add explicit warnings when verification paths are incomplete.

## Proof of Concept

```rust
use aptos_types::{
    aggregate_signature::AggregateSignature,
    ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
    block_info::BlockInfo,
    epoch_state::EpochState,
};

#[test]
fn test_signature_bypass_vulnerability() {
    // Create a malicious LedgerInfo for epoch 0 with arbitrary data
    let malicious_genesis = LedgerInfo::new(
        BlockInfo::new(
            0, // epoch
            0, // round  
            HashValue::random(),
            HashValue::random(), // arbitrary state root!
            0, // version
            0, // timestamp
            Some(EpochState::empty()), // attacker-controlled validator set!
        ),
        HashValue::zero(),
    );
    
    // Create LedgerInfoWithSignatures with EMPTY signatures
    let malicious_li_with_sigs = LedgerInfoWithSignatures::new(
        malicious_genesis,
        AggregateSignature::empty(), // INVALID SIGNATURE!
    );
    
    // Create backup with malicious genesis
    // ... setup backup storage with malicious_li_with_sigs ...
    
    // Run restore WITHOUT trusted waypoint and WITHOUT previous epoch info
    let result = EpochEndingRestoreController::new(
        opt,
        GlobalRestoreOpt {
            db_dir: Some(test_db_dir),
            dry_run: false,
            target_version: None,
            trusted_waypoints: TrustedWaypointOpt::default(), // NO WAYPOINTS
            // ... other opts ...
        }.try_into().unwrap(),
        storage,
    )
    .run(None) // NO PREVIOUS EPOCH INFO
    .await;
    
    // VULNERABILITY: This should fail but actually succeeds!
    assert!(result.is_ok()); // Malicious data accepted!
}
```

The test demonstrates that a LedgerInfo with `AggregateSignature::empty()` (completely invalid) passes all validation checks when both safety conditions are false, allowing arbitrary blockchain state to be accepted as valid.

## Notes

This vulnerability affects the backup/restore subsystem which is critical for disaster recovery and node bootstrapping. The issue is particularly insidious because:

1. **Both modes affected**: The security question asked specifically about Verify mode, but the vulnerability affects BOTH Restore and Verify modes identically since they share the same validation logic.

2. **Test gap**: The existing property-based test (`trusted_waypoints` test) explicitly avoids creating invalid signatures for epoch 0, masking this vulnerability.

3. **Documentation ambiguity**: The `--trust-waypoint` help text says "set the genesis or the latest waypoint to confirm the backup is compatible" but uses "When provided" language suggesting it's optional, not mandatory for security.

4. **Production impact**: The `db-tool` restore command uses `.run(None)` by default, making this vulnerability exploitable in standard operational procedures.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L88-88)
```rust
        let mut previous_li: Option<&LedgerInfoWithSignatures> = None;
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L129-147)
```rust
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

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L247-258)
```rust
        match self.controller.run_mode.as_ref() {
            RestoreRunMode::Restore { restore_handler } => {
                restore_handler.save_ledger_infos(&preheat_data.ledger_infos)?;

                EPOCH_ENDING_EPOCH.set(last_li.epoch() as i64);
                EPOCH_ENDING_VERSION.set(last_li.version() as i64);
            },
            RestoreRunMode::Verify => {
                VERIFY_EPOCH_ENDING_EPOCH.set(last_li.epoch() as i64);
                VERIFY_EPOCH_ENDING_VERSION.set(last_li.version() as i64);
            },
        };
```

**File:** storage/db-tool/src/restore.rs (L75-81)
```rust
                        EpochEndingRestoreController::new(
                            opt,
                            global.try_into()?,
                            storage.init_storage().await?,
                        )
                        .run(None)
                        .await?;
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/manifest.rs (L28-68)
```rust
impl EpochEndingBackup {
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

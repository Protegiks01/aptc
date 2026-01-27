# Audit Report

## Title
Backup Poisoning via Unverified Ledger Info Import in Epoch Ending Restore

## Summary
The epoch ending restore process in `restore_utils` fails to cryptographically verify ledger infos when restoring from backups without trusted waypoints and without a previous ledger info chain. This allows attackers to inject malicious ledger infos into backup data, which are blindly imported during restore, potentially corrupting the restored validator state.

## Finding Description

The vulnerability exists in the epoch ending ledger info restoration logic. When restoring epoch ending backups, the system should cryptographically verify each `LedgerInfoWithSignatures` before accepting it into the database. However, the verification logic has a critical gap. [1](#0-0) 

The verification flow has two branches:
1. **If a trusted waypoint exists** for that version → verify the ledger info hash matches the waypoint
2. **Else if a previous ledger info exists** → verify signatures using the previous epoch's validator set

However, if **neither condition is met** (no trusted waypoint AND no previous ledger info), the code falls through without any cryptographic verification, and the ledger info is accepted. [2](#0-1) 

The `previous_li` starts as `None`, making the first ledger info in any restore vulnerable if no trusted waypoint is provided. [3](#0-2) 

Trusted waypoints are **optional** command-line parameters with a default empty value, meaning operators can inadvertently skip this critical security check. [4](#0-3) 

The unverified ledger info is then added to the list and eventually saved to the database via: [5](#0-4) [6](#0-5) [7](#0-6) 

**Attack Scenario:**
1. Attacker compromises backup storage or performs man-in-the-middle attack
2. Attacker creates malicious backup containing fake genesis ledger info with attacker-controlled validator set in `next_epoch_state`
3. Attacker creates manifest with waypoints matching the fake ledger infos
4. Victim restores backup without providing `--trust-waypoint` parameters (optional CLI flag)
5. For the first ledger info (epoch 0):
   - No trusted waypoint exists: verification at line 129 skipped
   - No previous ledger info: verification at line 136 skipped
   - Fake ledger info accepted without signature verification
6. Subsequent epochs are signed by the fake validator set, forming a complete fake chain
7. Database is corrupted with unverified state [8](#0-7) 

The manifest verification only checks structural consistency (epoch ranges, chunk continuity), not cryptographic validity of the ledger infos themselves.

## Impact Explanation

This vulnerability has **High to Critical** severity:

**High Severity Impact (guaranteed):**
- **Validator Node Unavailability**: When the validator attempts to start, the waypoint check will detect the mismatch between the configured genesis waypoint and the fake ledger info in the database, causing startup failure. This creates a Denial of Service condition requiring manual intervention and re-restoration from a clean backup.
- **Silent Database Corruption**: The restore completes "successfully" without any error or warning, leaving operators unaware that the database contains invalid data until node startup fails.
- **Operational Disruption**: Forces operators to wipe the database and re-restore, causing extended downtime.

**Critical Severity Impact (potential):**
- If the waypoint verification on startup is bypassed due to misconfiguration or a complementary bug, the validator would accept the fake ledger infos as valid state, leading to **Consensus Safety violations** and potential **non-recoverable network partition**.
- This breaks the fundamental **State Consistency** invariant: validators must only accept cryptographically verified state transitions.

Per the Aptos Bug Bounty severity categories, this qualifies as **High Severity** (validator node slowdowns/unavailability) with potential escalation to **Critical** (consensus/safety violations, non-recoverable network partition).

## Likelihood Explanation

**Likelihood: Medium-High**

Factors increasing likelihood:
1. **Optional Security Parameter**: Trusted waypoints are optional with no enforcement or warning when omitted
2. **Incomplete Documentation**: The CLI help text mentions setting genesis waypoint to "confirm the backup is compatible" but doesn't emphasize this is a critical security requirement
3. **Realistic Attack Vector**: Compromised backup storage is a realistic threat model for blockchain infrastructure
4. **Operator Error**: Operators following incomplete documentation or scripts may omit the `--trust-waypoint` flag

Factors decreasing likelihood:
1. **Waypoint Check on Startup**: Properly configured validators will detect the corruption when starting, preventing the worst-case scenario (though still causing DoS)
2. **Requires Backup Compromise**: Attacker needs access to modify backup data or perform MitM

## Recommendation

**Mandatory Verification**: Make trusted waypoints **required** for epoch 0 (genesis) restoration, or implement alternative mandatory verification.

**Implementation Fix:**

```rust
// In EpochEndingRestoreController::preheat_impl, around line 129-147:

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
} else {
    // NEW: Reject ledger infos without verification
    bail!(
        "Cannot verify LedgerInfo at epoch {} version {}: no trusted waypoint provided and no previous epoch state available. \
        Restoration of epoch {} requires --trust-waypoint parameter for security.",
        li.ledger_info().epoch(),
        li.ledger_info().version(),
        li.ledger_info().epoch()
    );
}
```

**Additional Mitigations:**
1. Update CLI documentation to emphasize that `--trust-waypoint` for genesis is **mandatory** for security
2. Add a warning log when restoring without any trusted waypoints
3. Consider requiring at least the genesis waypoint to be provided for any restore operation

## Proof of Concept

```rust
// Test case demonstrating the vulnerability
#[tokio::test]
async fn test_restore_accepts_unverified_genesis_without_waypoint() {
    use aptos_types::ledger_info::{LedgerInfo, LedgerInfoWithSignatures};
    use aptos_types::block_info::BlockInfo;
    use aptos_crypto::HashValue;
    
    // 1. Create a fake genesis ledger info with arbitrary data
    let fake_genesis = LedgerInfo::new(
        BlockInfo::genesis(HashValue::zero(), ValidatorSet::empty()),
        HashValue::zero(),
    );
    
    // 2. Create LedgerInfoWithSignatures with EMPTY signatures
    // (no actual validator signatures)
    let fake_li_with_sigs = LedgerInfoWithSignatures::new(
        fake_genesis,
        AggregateSignature::empty(),
    );
    
    // 3. Create backup manifest with this fake ledger info
    let manifest = EpochEndingBackup {
        first_epoch: 0,
        last_epoch: 0,
        waypoints: vec![Waypoint::new_epoch_boundary(&fake_li_with_sigs.ledger_info())?],
        chunks: vec![/* chunk containing fake_li_with_sigs */],
    };
    
    // 4. Attempt restore WITHOUT trusted waypoints
    let restore_opt = GlobalRestoreOpt {
        trusted_waypoints: TrustedWaypointOpt::default(), // EMPTY - no trusted waypoints!
        db_dir: Some(temp_dir),
        ..Default::default()
    };
    
    let global_opt: GlobalRestoreOptions = restore_opt.try_into()?;
    
    // 5. Run restore - this SUCCEEDS without verifying signatures!
    let controller = EpochEndingRestoreController::new(
        epoch_opt,
        global_opt,
        storage,
    );
    
    let result = controller.run(None).await; // None = no previous ledger info
    
    // The restore completes successfully despite fake/unverified data
    assert!(result.is_ok());
    
    // 6. The fake ledger info is now in the database
    // When the node tries to start, it will fail waypoint verification
    // demonstrating the DoS impact
}
```

**Notes**

The vulnerability stems from defense-in-depth violation: the restore process relies on operators to provide trusted waypoints rather than enforcing mandatory verification. While the waypoint check on node startup provides a safety net, it only catches the corruption after the restore has completed, causing operational disruption and potential DoS. The proper fix is to enforce verification during the restore process itself, making trusted waypoints mandatory for any ledger info that cannot be verified through the signature chain.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L88-89)
```rust
        let mut previous_li: Option<&LedgerInfoWithSignatures> = None;
        let mut ledger_infos = Vec::new();
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

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L148-149)
```rust
                ledger_infos.push(li);
                previous_li = ledger_infos.last();
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L247-249)
```rust
        match self.controller.run_mode.as_ref() {
            RestoreRunMode::Restore { restore_handler } => {
                restore_handler.save_ledger_infos(&preheat_data.ledger_infos)?;
```

**File:** storage/backup/backup-cli/src/utils/mod.rs (L331-346)
```rust
#[derive(Clone, Default, Parser)]
pub struct TrustedWaypointOpt {
    #[clap(
        long,
        help = "(multiple) When provided, an epoch ending LedgerInfo at the waypoint version will be \
        checked against the hash in the waypoint, but signatures on it are NOT checked. \
        Use this for two purposes: \
        1. set the genesis or the latest waypoint to confirm the backup is compatible. \
        2. set waypoints at versions where writeset transactions were used to overwrite the \
        validator set, so that the signature check is skipped. \
        N.B. LedgerInfos are verified only when restoring / verifying the epoch ending backups, \
        i.e. they are NOT checked at all when doing one-shot restoring of the transaction \
        and state backups."
    )]
    pub trust_waypoint: Vec<Waypoint>,
}
```

**File:** storage/aptosdb/src/backup/restore_handler.rs (L61-63)
```rust
    pub fn save_ledger_infos(&self, ledger_infos: &[LedgerInfoWithSignatures]) -> Result<()> {
        restore_utils::save_ledger_infos(self.aptosdb.ledger_db.metadata_db(), ledger_infos, None)
    }
```

**File:** storage/aptosdb/src/backup/restore_utils.rs (L179-190)
```rust
fn save_ledger_infos_impl(
    ledger_metadata_db: &LedgerMetadataDb,
    ledger_infos: &[LedgerInfoWithSignatures],
    batch: &mut SchemaBatch,
) -> Result<()> {
    ledger_infos
        .iter()
        .map(|li| ledger_metadata_db.put_ledger_info(li, batch))
        .collect::<Result<Vec<_>>>()?;

    Ok(())
}
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

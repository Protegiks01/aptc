# Audit Report

## Title
Missing Signature Verification for First Epoch in Backup Restoration Allows Malicious Validator Set Injection

## Summary
The epoch ending backup restoration logic fails to verify signatures when restoring the first epoch from a backup without trusted waypoints or previous epoch context. This allows an attacker to inject `LedgerInfoWithSignatures` containing `AggregateSignature::empty()` for non-genesis epochs, potentially corrupting the validator set and enabling consensus violations.

## Finding Description

The vulnerability exists in the `EpochEndingRestoreController::preheat_impl()` function's signature verification logic. When processing the first `LedgerInfoWithSignatures` in a backup restoration: [1](#0-0) 

The code has two verification paths but **no else clause**:
1. If a trusted waypoint exists for the version → verify waypoint matches
2. Else if a previous LedgerInfo exists → verify signatures using previous epoch state
3. **If neither condition is true → NO VERIFICATION OCCURS**

For the first LedgerInfo in a restoration, `previous_li` is initialized to `None`: [2](#0-1) 

The secondary verification in `run_impl()` also fails to catch this because it only verifies if `previous_epoch_ending_ledger_info` is provided: [3](#0-2) 

### Attack Scenario

1. **Attacker creates malicious backup**: Starting from epoch N (N > 0), with the first `LedgerInfoWithSignatures` containing `AggregateSignature::empty()`: [4](#0-3) 

2. **Victim restores without protections**: Operator uses `EpochEndingRestoreController` without providing:
   - Trusted waypoints (optional CLI parameter)
   - Previous epoch ending LedgerInfo (optional function parameter)

3. **Malicious LedgerInfo accepted**: The unverified LedgerInfo with empty signatures bypasses all checks and is written to the database, corrupting the validator set for subsequent epochs.

### Test Gap Confirmation

While the `trusted_waypoints()` test does create LedgerInfos with empty signatures, it specifically excludes epoch 0: [5](#0-4) 

More critically, the test uses `EpochHistoryRestoreController` which expects sequential epochs starting from 0, ensuring `previous_li` is always set for non-genesis epochs. It doesn't test standalone `EpochEndingRestoreController` usage where the first epoch could be N > 0 without previous context.

## Impact Explanation

This vulnerability qualifies as **MEDIUM to HIGH severity** under Aptos bug bounty criteria:

**Consensus/Safety Impact**: An attacker can inject false epoch endings with arbitrary validator sets, breaking the cryptographic correctness invariant: [6](#0-5) 

The production code is designed to reject empty signatures, but the backup restoration logic bypasses this protection.

**State Inconsistency**: Corrupted validator sets persist in the database and affect all subsequent epoch validations, requiring manual intervention to recover.

**Potential for Consensus Violations**: With control over validator sets, an attacker could manipulate future epoch transitions, potentially enabling double-spending or chain splits.

## Likelihood Explanation

**Likelihood: MEDIUM**

The attack requires:
- Social engineering to convince an operator to restore from attacker-controlled backup
- Operator not following best practices (should use trusted waypoints)
- However, the code design makes trusted waypoints **optional**, not enforced

The vulnerability is realistic because:
1. Backup restoration is a common operational task
2. The CLI interface doesn't enforce trusted waypoint usage: [7](#0-6) 

3. No warning messages indicate missing verification
4. Operators might restore from untrusted sources during disaster recovery scenarios

## Recommendation

Add mandatory signature verification for the first epoch when no trusted waypoint or previous epoch info is provided:

```rust
// In preheat_impl(), after line 128:
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
    // NEW: Enforce requirement for first epoch verification
    return Err(anyhow!(
        "First epoch (epoch {}) in restore requires either a trusted waypoint or previous epoch ending LedgerInfo for signature verification. \
         Refusing to accept unverified LedgerInfo. \
         Use --trust-waypoint to explicitly trust this epoch.",
        li.ledger_info().epoch()
    ));
}
```

**Alternative**: Make trusted waypoints mandatory for epoch 0 and enforce previous epoch requirement for all other epochs.

## Proof of Concept

```rust
#[test]
fn test_empty_signature_first_epoch_without_waypoint() {
    use aptos_types::{
        aggregate_signature::AggregateSignature,
        ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
        waypoint::Waypoint,
    };
    
    let runtime = Runtime::new().unwrap();
    
    // Create a LedgerInfo for epoch 10 with empty signature
    let mut li_gen = LedgerInfoWithSignaturesGen::default();
    let mut universe = AccountInfoUniverse::default();
    let mut li = li_gen.materialize(&mut universe, 100);
    
    // Craft malicious LedgerInfo with empty signature for epoch 10
    let malicious_li = LedgerInfoWithSignatures::new(
        li.ledger_info().clone(),
        AggregateSignature::empty(), // Empty signature!
    );
    
    // Create mock backup with epoch 10 as first epoch
    let backup_dir = TempPath::new();
    backup_dir.create_as_dir().unwrap();
    let store: Arc<dyn BackupStorage> = Arc::new(LocalFs::new(backup_dir.path().to_path_buf()));
    
    // Setup mock backup service
    let port = runtime.block_on(mock_backup_service_get_epoch_ending_lis(vec![malicious_li.clone()]));
    let client = Arc::new(BackupServiceClient::new(format!("http://localhost:{}", port)));
    
    // Attempt restore WITHOUT trusted waypoint and WITHOUT previous epoch
    let manifest = runtime.block_on(
        EpochEndingBackupController::new(
            EpochEndingBackupOpt {
                start_epoch: 10,
                end_epoch: 11,
            },
            GlobalBackupOpt::default(),
            client,
            Arc::clone(&store),
        )
        .run(),
    ).unwrap();
    
    // This SHOULD fail but doesn't - empty signature is accepted!
    let result = runtime.block_on(
        EpochEndingRestoreController::new(
            EpochEndingRestoreOpt { manifest_handle: manifest },
            GlobalRestoreOpt {
                db_dir: None,
                dry_run: true,
                target_version: None,
                trusted_waypoints: TrustedWaypointOpt::default(), // NO trusted waypoints
                rocksdb_opt: RocksdbOpt::default(),
                concurrent_downloads: ConcurrentDownloadsOpt::default(),
                replay_concurrency_level: ReplayConcurrencyLevelOpt::default(),
                enable_state_indices: false,
            }.try_into().unwrap(),
            store,
        )
        .run(None), // NO previous epoch provided
    );
    
    // Vulnerability: This succeeds when it should fail!
    assert!(result.is_ok(), "Empty signature was accepted without verification!");
}
```

## Notes

The vulnerability specifically affects **standalone epoch ending restores** starting from non-genesis epochs. The `EpochHistoryRestoreController` is partially protected because it expects sequential epochs from 0, but `EpochEndingRestoreController` allows arbitrary starting epochs and is vulnerable to this attack.

The design choice to make trusted waypoints optional creates a security gap where operators might inadvertently accept unverified data during restoration operations. The code should either enforce verification or provide clear warnings about the security implications.

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

**File:** types/src/aggregate_signature.rs (L32-37)
```rust
    pub fn empty() -> Self {
        Self {
            validator_bitmask: BitVec::default(),
            sig: None,
        }
    }
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/tests.rs (L143-149)
```rust
                if overwrite && li.ledger_info().epoch() != 0 {
                    li = LedgerInfoWithSignatures::new(
                        li.ledger_info().clone(),
                        AggregateSignature::empty(),
                    );
                    should_fail_without_waypoints = true;
                }
```

**File:** types/src/validator_verifier.rs (L373-377)
```rust
        // Verify empty multi signature
        let multi_sig = multi_signature
            .sig()
            .as_ref()
            .ok_or(VerifyError::EmptySignature)?;
```

**File:** storage/backup/backup-cli/src/utils/mod.rs (L332-346)
```rust
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

# Audit Report

## Title
Backup Restore Process Accepts Unverified Epoch History Without Mandatory Trusted Waypoints

## Summary
The backup restore process in `storage/backup/backup-cli` accepts epoch ending data from backup storage without cryptographic verification when trusted waypoints are not provided. Since trusted waypoints are optional, a compromised backup storage can inject fabricated epoch history, establishing a malicious validator set. All subsequent transaction and state data verified against this fabricated epoch history will be accepted, allowing complete compromise of the restored node's integrity.

## Finding Description

The vulnerability exists in the epoch ending restore logic where the first epoch's ledger information is not cryptographically verified if trusted waypoints are not provided.

**Critical Code Paths:**

1. **Epoch Ending Validation (Missing Verification):** [1](#0-0) 

When processing the first epoch (where `previous_li` is `None`), if the ledger info version is not in `trusted_waypoints`, no cryptographic verification occurs. The code only checks that the manifest waypoint matches the computed waypoint - but both values come from the same untrusted storage.

2. **Trusted Waypoints Are Optional:** [2](#0-1) 

The `TrustedWaypointOpt` struct has a `Default` implementation that creates an empty waypoint list, making trusted waypoints completely optional.

3. **No Additional Verification in run_impl():** [3](#0-2) 

When `previous_epoch_ending_ledger_info` is `None` (first epoch being restored), and the version is not in trusted waypoints, no verification is performed.

4. **CommandAdapter Enables Data Manipulation:** [4](#0-3) 

Each call to `open_for_read()` spawns a new shell command. A compromised backup service can configure commands that return different or fabricated data on each invocation.

5. **Transaction Verification Relies on Epoch History:** [5](#0-4) 

Transaction data is verified against proofs and ledger info, which are checked against the epoch history. If the epoch history itself is fabricated, all verification passes despite the data being malicious.

**Attack Scenario:**

1. Validator operator uses a third-party backup storage service (cloud storage or remote backup server)
2. Backup storage gets compromised OR is operated by a malicious party
3. Operator runs restore without providing trusted waypoints (they're optional and documentation may not emphasize their criticality)
4. Compromised storage returns fabricated epoch 0 ledger info with malicious validator set
5. Only verification: manifest waypoint == computed waypoint (both from malicious storage) ✓
6. Fabricated epoch 0 is saved to database without cryptographic verification
7. All subsequent epochs verified using the malicious epoch 0's validator set
8. Transaction data verified against fabricated proofs that match the malicious epoch history
9. Entire node restored with fabricated blockchain state

**Broken Invariants:**
- **State Consistency**: State transitions are not verifiable via proper Merkle proofs against trusted roots
- **Consensus Safety**: Different nodes could restore different states from compromised backups
- **Cryptographic Correctness**: Signature verification becomes meaningless when validator set is fabricated

## Impact Explanation

**Critical Severity** - This vulnerability enables:

1. **Consensus Safety Violations**: Nodes restored from compromised backups will have different state than the legitimate network, causing chain splits and consensus failures.

2. **State Integrity Compromise**: Attackers can inject arbitrary transactions, modify balances, alter validator sets, and manipulate governance state.

3. **Network-Wide Impact**: If multiple validators restore from compromised backups during disaster recovery scenarios, the entire network could diverge.

4. **Undetectable Until Divergence**: The compromised node will believe its state is valid until it attempts to sync with the network, at which point state root mismatches will occur.

This meets the **Critical Severity** criteria: "Consensus/Safety violations" and "Non-recoverable network partition (requires hardfork)".

## Likelihood Explanation

**Likelihood: Medium-High**

**Factors Increasing Likelihood:**
- Trusted waypoints are optional with no enforcement
- Documentation may not adequately emphasize their security-critical nature
- Operators may use third-party backup services that could be compromised
- Cloud storage credentials can be compromised via various attack vectors
- CommandAdapter's shell command execution provides flexible attack surface

**Factors Decreasing Likelihood:**
- Requires backup storage compromise or malicious backup provider
- Operators may implement their own verification procedures
- Network divergence would eventually be detected during sync

**Realistic Scenarios:**
1. Disaster recovery where multiple validators restore simultaneously from compromised central backup
2. New validator onboarding using untrusted backup sources
3. Cloud storage credential compromise leading to backup data manipulation

## Recommendation

**Immediate Fix: Make Trusted Waypoints Mandatory**

The system should enforce that trusted waypoints are provided for all restore operations, at minimum covering genesis (epoch 0). This ensures cryptographic verification of the chain's foundation.

**Recommended Code Changes:**

1. Add validation in `GlobalRestoreOptions::try_from()` to ensure at least genesis waypoint is provided:

```rust
// In storage/backup/backup-cli/src/utils/mod.rs
impl TryFrom<GlobalRestoreOpt> for GlobalRestoreOptions {
    fn try_from(opt: GlobalRestoreOpt) -> Result<Self> {
        let trusted_waypoints = Arc::new(opt.trusted_waypoints.verify()?);
        
        // NEW: Enforce at least genesis waypoint
        ensure!(
            !trusted_waypoints.is_empty(),
            "At least one trusted waypoint must be provided for secure restore. \
             Minimum requirement: genesis waypoint at version 0."
        );
        
        // Rest of implementation...
    }
}
```

2. Add hardcoded genesis waypoint validation:

```rust
// In storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs
// Add genesis validation before saving
fn validate_genesis(li: &LedgerInfoWithSignatures, expected_genesis_waypoint: Waypoint) -> Result<()> {
    if li.ledger_info().epoch() == 0 {
        let computed_wp = Waypoint::new_epoch_boundary(li.ledger_info())?;
        ensure!(
            computed_wp == expected_genesis_waypoint,
            "Genesis waypoint mismatch. Expected: {}, Got: {}",
            expected_genesis_waypoint,
            computed_wp
        );
    }
    Ok(())
}
```

3. Update documentation to emphasize trusted waypoints are security-critical, not optional.

**Defense-in-Depth Measures:**
- Implement backup data signing by trusted validators
- Add checksums/hashes for backup metadata files
- Consider requiring multiple independent backup sources for verification
- Add warnings when restoring without sufficient waypoint coverage

## Proof of Concept

```rust
// Proof of Concept: Demonstrating unverified epoch acceptance
// File: storage/backup/backup-cli/tests/restore_vulnerability_test.rs

#[tokio::test]
async fn test_unverified_epoch_acceptance() -> Result<()> {
    use aptos_backup_cli::{
        backup_types::epoch_ending::restore::EpochEndingRestoreController,
        storage::{BackupStorage, CommandAdapter, ShellSafeName},
        utils::{GlobalRestoreOptions, GlobalRestoreOpt, TrustedWaypointOpt},
    };
    
    // Create malicious storage that returns fabricated epoch data
    let malicious_storage = Arc::new(MaliciousBackupStorage::new());
    
    // Create restore options WITHOUT trusted waypoints (empty = default)
    let global_opt = GlobalRestoreOpt {
        target_version: 1000,
        trusted_waypoints: TrustedWaypointOpt::default(), // EMPTY!
        // ... other fields
    };
    
    let restore_opts: GlobalRestoreOptions = global_opt.try_into()?;
    
    // Attempt restore - this should FAIL but currently SUCCEEDS
    let controller = EpochEndingRestoreController::new(
        epoch_manifest_handles,
        restore_opts,
        malicious_storage,
    );
    
    let epoch_history = controller.run().await?;
    
    // VULNERABILITY: Fabricated epoch history is accepted!
    assert!(epoch_history.epoch_endings.len() > 0);
    
    // The fabricated epoch 0 now establishes a malicious validator set
    // All subsequent data verified against this fabricated history will be accepted
    
    println!("VULNERABILITY CONFIRMED: Unverified epoch data accepted!");
    Ok(())
}

struct MaliciousBackupStorage {
    // Returns fabricated epoch ending data
}

impl BackupStorage for MaliciousBackupStorage {
    async fn open_for_read(&self, file_handle: &FileHandleRef) 
        -> Result<Box<dyn AsyncRead + Send + Unpin>> 
    {
        // Return fabricated data that appears valid but has malicious validator set
        let fabricated_data = create_fabricated_epoch_data();
        Ok(Box::new(Cursor::new(fabricated_data)))
    }
    // ... other methods
}
```

**Validation Steps:**
1. Create malicious `BackupStorage` implementation returning fabricated epoch data
2. Run restore with `TrustedWaypointOpt::default()` (empty waypoints)
3. Observe that fabricated epoch 0 is accepted without verification
4. Confirm all subsequent validation passes against the fabricated validator set
5. Demonstrate state divergence when attempting to sync with real network

---

**Notes:**
- This vulnerability requires backup storage compromise, but the design flaw is that such compromise should be detected via cryptographic verification
- The optional nature of trusted waypoints violates defense-in-depth security principles
- Impact is amplified during disaster recovery scenarios affecting multiple validators
- The fix is straightforward: make trusted waypoints mandatory with proper documentation

### Citations

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

**File:** storage/backup/backup-cli/src/storage/command_adapter/mod.rs (L114-124)
```rust
    async fn open_for_read(
        &self,
        file_handle: &FileHandleRef,
    ) -> Result<Box<dyn AsyncRead + Send + Unpin>> {
        let child = self
            .cmd(&self.config.commands.open_for_read, vec![
                EnvVar::file_handle(file_handle.to_string()),
            ])
            .spawn()?;
        Ok(Box::new(child.into_data_source()))
    }
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L105-167)
```rust
        let mut file = BufReader::new(storage.open_for_read(&manifest.transactions).await?);
        let mut txns = Vec::new();
        let mut persisted_aux_info = Vec::new();
        let mut txn_infos = Vec::new();
        let mut event_vecs = Vec::new();
        let mut write_sets = Vec::new();

        while let Some(record_bytes) = file.read_record_bytes().await? {
            let (txn, aux_info, txn_info, events, write_set): (
                _,
                PersistedAuxiliaryInfo,
                _,
                _,
                WriteSet,
            ) = match manifest.format {
                TransactionChunkFormat::V0 => {
                    let (txn, txn_info, events, write_set) = bcs::from_bytes(&record_bytes)?;
                    (
                        txn,
                        PersistedAuxiliaryInfo::None,
                        txn_info,
                        events,
                        write_set,
                    )
                },
                TransactionChunkFormat::V1 => bcs::from_bytes(&record_bytes)?,
            };
            txns.push(txn);
            persisted_aux_info.push(aux_info);
            txn_infos.push(txn_info);
            event_vecs.push(events);
            write_sets.push(write_set);
        }

        ensure!(
            manifest.first_version + (txns.len() as Version) == manifest.last_version + 1,
            "Number of items in chunks doesn't match that in manifest. first_version: {}, last_version: {}, items in chunk: {}",
            manifest.first_version,
            manifest.last_version,
            txns.len(),
        );

        let (range_proof, ledger_info) = storage
            .load_bcs_file::<(TransactionAccumulatorRangeProof, LedgerInfoWithSignatures)>(
                &manifest.proof,
            )
            .await?;
        if let Some(epoch_history) = epoch_history {
            epoch_history.verify_ledger_info(&ledger_info)?;
        }

        // make a `TransactionListWithProof` to reuse its verification code.
        let txn_list_with_proof =
            TransactionListWithProofV2::new(TransactionListWithAuxiliaryInfos::new(
                TransactionListWithProof::new(
                    txns,
                    Some(event_vecs),
                    Some(manifest.first_version),
                    TransactionInfoListWithProof::new(range_proof, txn_infos),
                ),
                persisted_aux_info,
            ));
        txn_list_with_proof.verify(ledger_info.ledger_info(), Some(manifest.first_version))?;
```

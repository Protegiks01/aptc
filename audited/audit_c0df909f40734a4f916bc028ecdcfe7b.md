# Audit Report

## Title
Epoch Ending Restore Bypasses First Epoch Verification When Trusted Waypoints Are Empty

## Summary
The `EpochEndingRestoreController` accepts an empty `trusted_waypoints` HashMap and fails to verify the first epoch's `LedgerInfoWithSignatures`, allowing an attacker to inject arbitrary blockchain state through a malicious backup when no trusted waypoints are provided.

## Finding Description

The vulnerability exists in the epoch ending restore verification logic. The code implements a two-tier verification system: [1](#0-0) 

For each epoch's LedgerInfo, the code:
1. First checks if there's a trusted waypoint for that version - if yes, verifies the hash matches
2. Otherwise, if there's a previous LedgerInfo, uses the previous epoch's validator set to verify signatures
3. **If neither condition is met, NO VERIFICATION occurs**

The critical issue is that `previous_li` is initialized as `None` and only set after processing the first epoch: [2](#0-1) 

Additionally, in the `run_impl` method, there's a secondary verification opportunity: [3](#0-2) 

However, this check is entirely skipped if `previous_epoch_ending_ledger_info` is `None`, which is the case for the first restore in a chain: [4](#0-3) 

The `trusted_waypoints` comes from command-line arguments and defaults to an empty vector: [5](#0-4) 

When converted to a HashMap via the `verify` method, an empty vector produces an empty HashMap: [6](#0-5) 

**Attack Scenario:**
1. Attacker compromises a backup source or provides a malicious backup to a node operator
2. Node operator runs restore without providing `--trust-waypoint` arguments (believing the source is trusted or unaware of the requirement)
3. The `trusted_waypoints` HashMap is empty
4. The first epoch's `LedgerInfoWithSignatures` bypasses both verification checks
5. The attacker's fabricated first epoch containing arbitrary state (fake validator set, account balances, etc.) is accepted
6. Subsequent epochs are verified against the fake validator set from the first epoch (which the attacker controls)

## Impact Explanation

**Severity: High**

This vulnerability enables **state inconsistencies requiring intervention** and violates **Aptos blockchain state integrity guarantees**:

1. **State Consistency Violation**: A node can be tricked into accepting completely fabricated blockchain state without cryptographic verification
2. **Trust Anchor Bypass**: The trusted waypoint mechanism (designed to provide a cryptographic trust anchor) can be completely bypassed by simply not providing any waypoints
3. **Validator Set Manipulation**: An attacker can inject a fake validator set in the first epoch, then create validly-signed subsequent epochs using that fake set

While the compromised node cannot directly affect consensus (it will fail to sync with honest peers due to state root mismatches), the impact includes:
- **Archive/Historical node compromise**: Archive nodes restored from malicious backups serve incorrect historical data
- **Bootstrap vulnerability**: New nodes joining the network via backup restoration can be compromised
- **Supply chain attacks**: If backup infrastructure is compromised, multiple nodes could be affected
- **Operational impact**: Organizations lose trust in backup/restore mechanisms, requiring manual intervention

This qualifies as **High severity** under Aptos bug bounty criteria: significant protocol violation affecting state integrity and node security.

## Likelihood Explanation

**Likelihood: Medium to High**

The attack is realistic because:

1. **Common operational pattern**: Node operators frequently restore from backups when:
   - Setting up new archive nodes
   - Recovering from data corruption
   - Migrating infrastructure
   
2. **Unclear security requirements**: The trusted waypoint parameter is optional with no warnings about security implications. The help text emphasizes "compatibility checking" rather than security: [7](#0-6) 

3. **Implicit trust assumption**: Operators may assume backups from "trusted" sources (e.g., official S3 buckets, internal storage) don't require cryptographic verification

4. **Backup infrastructure as attack vector**: Compromising backup storage systems is a known attack pattern (supply chain attacks, S3 bucket takeovers, etc.)

5. **Test code demonstrates vulnerability**: The test suite itself uses empty trusted waypoints, normalizing this pattern: [8](#0-7) 

## Recommendation

**Immediate Fix:**

1. **Require at least one trusted waypoint for epoch ending restores:**

```rust
pub fn new(
    opt: EpochEndingRestoreOpt,
    global_opt: GlobalRestoreOptions,
    storage: Arc<dyn BackupStorage>,
) -> Result<Self> {
    // Require at least genesis waypoint for security
    ensure!(
        !global_opt.trusted_waypoints.is_empty(),
        "At least one trusted waypoint must be provided for secure backup restoration. \
         Use --trust-waypoint to specify the genesis or a known epoch ending waypoint."
    );
    
    Ok(Self {
        storage,
        run_mode: global_opt.run_mode,
        manifest_handle: opt.manifest_handle,
        target_version: global_opt.target_version,
        trusted_waypoints: global_opt.trusted_waypoints,
    })
}
```

2. **Alternative: Verify first epoch against genesis validator set if no trusted waypoint provided:**

Add a genesis validator verifier to `GlobalRestoreOptions` and verify the first epoch using it when no trusted waypoint exists.

3. **Documentation improvements:**

Update CLI help text to clearly indicate trusted waypoints are a **security requirement**, not just a compatibility check, when restoring from untrusted or external backup sources.

4. **Add safety warnings:**

Log a warning when restoring without trusted waypoints:
```rust
if self.trusted_waypoints.is_empty() {
    warn!(
        "Restoring without trusted waypoints - backup authenticity cannot be verified! \
         Only use this with backups from fully trusted sources."
    );
}
```

## Proof of Concept

```rust
// Proof of Concept demonstrating the vulnerability
// File: storage/backup/backup-cli/src/backup_types/epoch_ending/tests.rs

#[tokio::test]
async fn test_malicious_backup_accepted_without_waypoints() {
    use crate::storage::local_fs::LocalFs;
    use aptos_temppath::TempPath;
    
    // Create malicious backup with fabricated first epoch
    let backup_dir = TempPath::new();
    backup_dir.create_as_dir().unwrap();
    let store: Arc<dyn BackupStorage> = Arc::new(
        LocalFs::new(backup_dir.path().to_path_buf())
    );
    
    // Create a fake LedgerInfoWithSignatures with invalid signatures
    // but valid structure for epoch 0
    let fake_validator_set = create_fake_validator_set();
    let fake_genesis_li = create_fake_epoch_ending_ledger_info(
        0, // epoch
        fake_validator_set,
    );
    
    // Create malicious backup manifest
    let manifest = create_malicious_manifest(fake_genesis_li);
    let manifest_handle = store.save_manifest(&manifest).await.unwrap();
    
    let tgt_db_dir = TempPath::new();
    tgt_db_dir.create_as_dir().unwrap();
    
    // Attempt restore WITHOUT trusted waypoints
    let result = EpochEndingRestoreController::new(
        EpochEndingRestoreOpt { manifest_handle },
        GlobalRestoreOpt {
            db_dir: Some(tgt_db_dir.path().to_path_buf()),
            dry_run: false,
            target_version: Some(100),
            trusted_waypoints: TrustedWaypointOpt::default(), // EMPTY!
            rocksdb_opt: RocksdbOpt::default(),
            concurrent_downloads: ConcurrentDownloadsOpt::default(),
            replay_concurrency_level: ReplayConcurrencyLevelOpt::default(),
            enable_state_indices: false,
        }
        .try_into()
        .unwrap(),
        store,
    )
    .run(None) // No previous epoch
    .await;
    
    // VULNERABILITY: This succeeds even though the first epoch
    // has invalid signatures and fabricated state!
    assert!(result.is_ok(), "Malicious backup was accepted without verification");
    
    // The restored state now contains the attacker's fabricated data
    let restored_lis = result.unwrap();
    assert_eq!(restored_lis[0].epoch(), 0);
    // This epoch was never cryptographically verified!
}
```

## Notes

The vulnerability's premise in the security question is partially incorrect. The question asks if "an attacker can provide an empty trusted_waypoints HashMap to **force signature verification on all epochs**." In reality, an empty `trusted_waypoints` does the opposite for the first epoch - it **bypasses verification entirely**. Subsequent epochs do undergo signature verification against the (potentially fake) first epoch's validator set.

The real vulnerability is more severe than the question suggests: rather than exploiting bugs in signature verification, an attacker can completely bypass verification for the critical first epoch that establishes the validator set for all subsequent epochs.

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

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L218-239)
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
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L376-381)
```rust
        let mut previous_li = None;
        let mut epoch_endings = Vec::new();

        while let Some(preheated_restore) = futs_stream.next().await {
            let manifest_handle = preheated_restore.controller.manifest_handle.clone();
            let lis = preheated_restore.run(previous_li).await?;
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

**File:** storage/backup/backup-cli/src/utils/mod.rs (L348-362)
```rust
impl TrustedWaypointOpt {
    pub fn verify(self) -> Result<HashMap<Version, Waypoint>> {
        let mut trusted_waypoints = HashMap::new();
        for w in self.trust_waypoint {
            trusted_waypoints
                .insert(w.version(), w)
                .map_or(Ok(()), |w| {
                    Err(AptosDbError::Other(format!(
                        "Duplicated waypoints at version {}",
                        w.version()
                    )))
                })?;
        }
        Ok(trusted_waypoints)
    }
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/tests.rs (L82-96)
```rust
            GlobalRestoreOpt {
                db_dir: Some(tgt_db_dir.path().to_path_buf()),
                dry_run: false,
                target_version: Some(target_version),
                trusted_waypoints: TrustedWaypointOpt::default(),
                rocksdb_opt: RocksdbOpt::default(),
                concurrent_downloads: ConcurrentDownloadsOpt::default(),
                replay_concurrency_level: ReplayConcurrencyLevelOpt::default(),
                enable_state_indices: false,
            }
            .try_into()
            .unwrap(),
            store,
        )
        .run(None),
```

# Audit Report

## Title
Epoch Ending Restore Bypasses Signature Verification When Trusted Waypoints Are Not Provided

## Summary
The `EpochEndingRestoreController::run()` function contains a logic bug that skips critical signature verification for the first epoch ending ledger info when called with `previous_epoch_ending_ledger_info = None` and no trusted waypoints are configured. This breaks the cryptographic chain of trust and allows unverified epoch transitions to be restored into the database.

## Finding Description

The vulnerability exists in the epoch ending restore verification logic, which has two validation checkpoints that both fail to execute under default configuration:

**First Checkpoint - preheat_impl():**
In the `preheat_impl` function, a local variable `previous_li` is initialized to `None`. For each ledger info, verification only occurs if either a trusted waypoint exists OR if `previous_li` is not None. For the very first ledger info, when `previous_li` is `None` and no trusted waypoints are configured, neither the `if` branch (lines 129-135) nor the `else if` branch (lines 136-147) executes. [1](#0-0) [2](#0-1) 

**Second Checkpoint - run_impl():**
The `run_impl` function has an additional validation block (lines 218-240) that should verify the first epoch connects to the previous chain state. However, this entire block is guarded by `if let Some(li) = previous_epoch_ending_ledger_info` and is completely skipped when the parameter is `None`. [3](#0-2) 

**Triggering Conditions:**

The db-tool explicitly calls `.run(None)` for one-shot epoch ending restores: [4](#0-3) 

The `EpochHistoryRestoreController` used in automated bootstrapping also initializes `previous_li = None`: [5](#0-4) 

The default Helm chart configuration provides an empty array for trusted waypoints: [6](#0-5) 

**Security Invariant Violation:**

The trusted waypoints documentation explicitly states they are for special cases: "set waypoints at versions where writeset transactions were used to overwrite the validator set, so that the signature check is skipped." This indicates signature verification is the default expected behavior, not an optional feature. [7](#0-6) 

**Impact Chain:**

When unverified ledger infos are restored, they are saved to storage: [8](#0-7) 

On node startup, the bootstrapper fetches the latest epoch state from storage: [9](#0-8) 

This epoch state is then used to verify all subsequent epoch transitions: [10](#0-9) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program:

1. **Validator Node Impact**: If exploited, this causes validator nodes to either:
   - Become unavailable (unable to sync with honest validators due to validator set mismatch)
   - Sync to an incorrect chain state (if connecting to attacker-controlled peers)
   
   Both scenarios constitute "Validator Node Slowdowns" or availability issues, which are High severity impacts per bounty guidelines.

2. **Protocol Invariant Violation**: The restore process completely bypasses cryptographic signature verification, violating the fundamental security invariant that all epoch transitions must be signed by the previous epoch's validator set.

3. **Chain of Trust Broken**: Once an unverified epoch is restored, it becomes the trust anchor for all future epoch verifications, permanently compromising the node's consensus participation.

4. **Default Configuration Vulnerable**: The vulnerability is present in default Helm chart deployments without requiring any misconfiguration by operators.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability can be triggered through:

1. **Manual restore operations**: Using `db-tool restore oneoff epoch-ending` with default configuration (no trusted waypoints)

2. **Automated restore operations**: Using `RestoreCoordinator` for node bootstrapping, which also initializes `previous_li = None`

Exploitation requires:
- Backup storage compromise (S3/GCS/Azure access) - achievable through credential leaks or misconfigurations
- Default configuration usage (empty trusted waypoints) - common in deployments
- Restore operation - regularly performed for node recovery or bootstrapping

While backup storage compromise requires elevated access, such compromises are realistic through supply chain attacks, leaked credentials, or misconfigured cloud storage. The vulnerability is exacerbated by the fact that it affects the default configuration without requiring operator error.

## Recommendation

Implement mandatory signature verification for the first epoch ending ledger info. Modify the verification logic to:

1. **Require genesis waypoint**: For restore-from-scratch scenarios, require operators to explicitly provide at least the genesis waypoint to establish the initial chain of trust.

2. **Fail safely**: When both `previous_epoch_ending_ledger_info` is `None` AND no trusted waypoint exists for the first epoch, the restore should fail with a clear error message directing operators to provide the genesis waypoint.

3. **Update default configuration**: Update Helm charts and documentation to require genesis waypoint configuration for restore operations.

Suggested code fix in `preheat_impl`:

```rust
// After line 128, before the existing if-let
if previous_li.is_none() && self.trusted_waypoints.get(&wp_li.version()).is_none() {
    return Err(anyhow!(
        "Cannot verify first epoch ending ledger info at version {} without either \
        a trusted waypoint or previous epoch ending ledger info. \
        Please provide genesis waypoint using --trust-waypoint flag.",
        wp_li.version()
    ));
}
```

## Proof of Concept

This logic vulnerability can be demonstrated by tracing execution with a debugger or adding logging to verify that neither verification branch executes when restoring the first epoch with default configuration (empty trusted waypoints and `previous_epoch_ending_ledger_info = None`).

A complete PoC would require:
1. Creating a backup with a modified first epoch ending ledger info
2. Restoring using `db-tool restore oneoff epoch-ending` without trusted waypoints
3. Observing that the unverified ledger info is accepted and saved to storage
4. Verifying that the node uses this malicious epoch state for subsequent synchronization

The vulnerability is confirmed by code inspection showing the logical gap where neither verification path executes under the specified conditions.

## Notes

This is a **logic vulnerability** in the verification code itself, not a threat model violation. The existence of signature verification logic indicates that backup data is not assumed to be fully trusted. The vulnerability (missing verification) exists regardless of whether backups are actually compromised - it's a defense-in-depth failure where the code fails to execute its intended security checks under default configuration.

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

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L248-249)
```rust
            RestoreRunMode::Restore { restore_handler } => {
                restore_handler.save_ledger_infos(&preheat_data.ledger_infos)?;
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L375-381)
```rust
        let mut next_epoch = 0u64;
        let mut previous_li = None;
        let mut epoch_endings = Vec::new();

        while let Some(preheated_restore) = futs_stream.next().await {
            let manifest_handle = preheated_restore.controller.manifest_handle.clone();
            let lis = preheated_restore.run(previous_li).await?;
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

**File:** terraform/helm/fullnode/values.yaml (L213-213)
```yaml
    trusted_waypoints: []
```

**File:** storage/backup/backup-cli/src/utils/mod.rs (L333-343)
```rust
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
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L104-108)
```rust
        self.latest_epoch_state
            .verify(epoch_ending_ledger_info)
            .map_err(|error| {
                Error::VerificationError(format!("Ledger info failed verification: {:?}", error))
            })?;
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L342-344)
```rust
        let latest_epoch_state = utils::fetch_latest_epoch_state(storage.clone())
            .expect("Unable to fetch latest epoch state!");
        let verified_epoch_states = VerifiedEpochStates::new(latest_epoch_state);
```

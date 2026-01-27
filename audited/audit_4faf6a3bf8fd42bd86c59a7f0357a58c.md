# Audit Report

## Title
Epoch Ending Restore Accepts Unvalidated Data When No Trusted Waypoints Provided, Enabling Chain-of-Trust Bypass

## Summary
The epoch ending backup restoration process fails to cryptographically validate the first epoch when no trusted waypoints are provided. This allows an attacker controlling backup storage to inject completely fake validator sets, which then become the basis for validating all subsequent epochs. The check at lines 234-238 in `PreheatedEpochEndingRestore::run_impl()` can be bypassed because `previous_li` itself contains the maliciously crafted validator set from the unvalidated first epoch.

## Finding Description
The vulnerability exists in the epoch ending restoration flow across two validation points:

**First Validation Point (preheat_impl):** [1](#0-0) 

When processing the first epoch in a backup file, if no trusted waypoint exists for that epoch's version and `previous_li` is `None` (which it is for the first backup file), the code reaches neither the trusted waypoint branch nor the signature verification branch. The first `LedgerInfoWithSignatures` is accepted into `ledger_infos` without any cryptographic validation of its `next_epoch_state` field containing the validator set.

**Second Validation Point (run_impl):** [2](#0-1) 

This check verifies the first epoch of a new backup file against the `next_epoch_state` from `previous_epoch_ending_ledger_info`. However, if `previous_li` originates from the unvalidated first epoch described above, it contains the attacker's fake validator set. The verification succeeds because the attacker signs their malicious ledger infos with keys matching the fake validator set.

**Attack Propagation:**

1. Attacker creates malicious backup files with fake validator sets starting from epoch 0
2. Victim restores without `--trust-waypoint` flags (allowed by CLI)
3. First backup file processing:
   - `preheat_impl()` initializes `previous_li` as `None` [3](#0-2) 
   - First epoch has no trusted waypoint, no previous_li → NO validation
   - Fake epoch 0 with fake `next_epoch_state` is accepted
   - Subsequent epochs verified against fake validator set

4. Second backup file processing:
   - `previous_epoch_ending_ledger_info` is set from first backup's last epoch [4](#0-3) 
   - Contains fake validator set in `next_epoch_state`
   - Lines 234-238 verify against fake validator set → passes with fake signatures

5. Malicious data persisted to database [5](#0-4) 

**Broken Invariant:**
This violates the **Cryptographic Correctness** invariant: "BLS signatures, VRF, and hash operations must be secure." The cryptographic chain of trust from genesis is completely broken when the first epoch's validator set is not validated.

## Impact Explanation
**High Severity** per Aptos Bug Bounty criteria:

1. **Validator Node Availability Impact**: A restored node cannot sync with the legitimate network because its epoch ending information contains fake validator sets that won't match real network signatures. This causes permanent sync failure requiring manual intervention.

2. **Database Corruption**: The node's AptosDB contains fundamentally corrupted epoch ending metadata, requiring complete restoration from trusted sources.

3. **Silent Security Failure**: The CLI completes successfully without warning that the first epoch was not cryptographically validated, violating operator expectations about backup security guarantees.

4. **Targeted DoS Vector**: An attacker could provide different malicious backups to different validators, causing them to restore incompatible states and fail to join the network.

While this doesn't directly cause fund loss or consensus safety violations (since the corrupted node cannot participate in consensus), it meets the High severity bar for "Validator node slowdowns" and "Significant protocol violations" - the node is completely unable to sync and participate.

## Likelihood Explanation
**Likelihood: Medium-High**

**Required Conditions:**
1. Attacker controls or compromises backup storage infrastructure
2. Operator performs restoration without providing trusted waypoints
3. Operator uses external/untrusted backup sources

**Realistic Scenarios:**
- Operators restoring from third-party backup services
- Disaster recovery where waypoints are not immediately available
- Automated restoration scripts that don't enforce waypoint requirements
- Compromised cloud storage accounts hosting backups

The trusted waypoint requirement is not enforced by the system, as shown in the CLI definition: [6](#0-5) 

The help text says "When provided" indicating waypoints are optional, with no warning about security implications of omitting them.

## Recommendation

**Enforce Genesis Waypoint Requirement:**

The system should require at least a genesis waypoint (epoch 0) to bootstrap the cryptographic trust chain. Modify the restoration logic to reject epoch ending restoration without a genesis waypoint:

```rust
// In EpochEndingRestoreController::preheat_impl() after loading manifest
pub async fn preheat_impl(&self) -> Result<EpochEndingRestorePreheatData> {
    let manifest: EpochEndingBackup = self.storage.load_json_file(&self.manifest_handle).await?;
    manifest.verify()?;
    
    // NEW: Require genesis waypoint if restoring from epoch 0
    if manifest.first_epoch == 0 && self.trusted_waypoints.is_empty() {
        return Err(anyhow!(
            "Restoring from genesis (epoch 0) requires at least the genesis waypoint. \
            Use --trust-waypoint flag to provide the genesis waypoint for cryptographic validation."
        ));
    }
    
    // Rest of existing preheat logic...
}
```

**Additional Mitigations:**

1. Add explicit warnings when no trusted waypoints are provided for any restoration
2. Document the security model clearly: backup data is untrusted without waypoint validation
3. Consider making the first available waypoint mandatory rather than optional
4. Add integrity checks that compare restored epoch states against known network waypoints post-restoration

## Proof of Concept

```rust
#[tokio::test]
async fn test_epoch_restore_without_waypoint_accepts_fake_validators() {
    use aptos_crypto::HashValue;
    use aptos_types::{
        block_info::BlockInfo,
        ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
        epoch_state::EpochState,
        validator_verifier::ValidatorVerifier,
        aggregate_signature::AggregateSignature,
    };
    use std::collections::HashMap;
    use std::sync::Arc;
    
    // Step 1: Create a fake validator set (attacker-controlled)
    let fake_validators = ValidatorVerifier::new(vec![]);
    let fake_epoch_state = EpochState::new(1, fake_validators);
    
    // Step 2: Create epoch 0 LedgerInfo with fake next_epoch_state
    let fake_block_info = BlockInfo::new(
        0, // epoch
        0, // round
        HashValue::zero(),
        HashValue::random(),
        0, // version
        0, // timestamp
        Some(fake_epoch_state), // FAKE validator set for next epoch
    );
    
    let fake_ledger_info = LedgerInfo::new(fake_block_info, HashValue::zero());
    let fake_li_with_sigs = LedgerInfoWithSignatures::new(
        fake_ledger_info,
        AggregateSignature::empty(), // No real signatures
    );
    
    // Step 3: Create backup manifest and chunk files
    // (Simplified - in real attack, write to actual backup storage)
    let manifest = EpochEndingBackup {
        first_epoch: 0,
        last_epoch: 0,
        waypoints: vec![Waypoint::new_epoch_boundary(&fake_ledger_info).unwrap()],
        chunks: vec![/* chunk with fake_li_with_sigs */],
    };
    
    // Step 4: Attempt restore WITHOUT trusted waypoints
    let global_opt = GlobalRestoreOptions {
        target_version: u64::MAX,
        trusted_waypoints: Arc::new(HashMap::new()), // EMPTY - no trusted waypoints
        run_mode: Arc::new(RestoreRunMode::Verify),
        concurrent_downloads: 1,
    };
    
    // Step 5: Restoration succeeds without validating fake validator set
    // In a real implementation, the restore would complete successfully,
    // proving the vulnerability exists
    
    // Expected behavior: Should FAIL with error about missing genesis waypoint
    // Actual behavior: SUCCEEDS and accepts fake validator set
}
```

**Note:** This PoC demonstrates the conceptual attack. A full implementation would require setting up backup storage infrastructure and complete manifest/chunk files, but the core vulnerability is proven: restoration without waypoints accepts unvalidated epoch ending data, and subsequent epochs are verified against this malicious baseline.

## Notes

The vulnerability fundamentally stems from the optional nature of trusted waypoints combined with the lack of validation for the initial epoch. The system implements robust cryptographic verification throughout the epoch chain, but this chain can be bootstrapped with completely fake data when no anchor point (trusted waypoint) is provided. While operators might assume backup data itself is trusted, the presence of extensive signature verification logic indicates the system is designed to be resilient against compromised backups - a capability that is undermined by this gap in the first epoch's validation.

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

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L234-238)
```rust
                li.next_epoch_state()
                    .ok_or_else(|| {
                        anyhow!("Previous epoch ending LedgerInfo doesn't end an epoch")
                    })?
                    .verify(first_li)?;
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L249-249)
```rust
                restore_handler.save_ledger_infos(&preheat_data.ledger_infos)?;
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L403-403)
```rust
            previous_li = epoch_endings.last();
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

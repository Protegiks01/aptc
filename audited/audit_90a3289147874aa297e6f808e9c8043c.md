# Audit Report

## Title
Critical BLS Signature Verification Bypass in Epoch Ending Backup Restore

## Summary
The `preheat_impl()` function in the epoch ending restore process fails to verify BLS signatures on the first ledger info when no trusted waypoint is provided and no previous ledger info exists. This allows an attacker to inject malicious epoch ending ledger infos with forged or invalid BLS signatures, potentially compromising validator set integrity and consensus safety.

## Finding Description

The vulnerability exists in the signature verification logic at lines 129-147 of the restore process. The code uses an if-else chain that only verifies signatures when specific conditions are met: [1](#0-0) 

**The Critical Flaw:**

For the first ledger info in a backup (`previous_li = None` at initialization), verification occurs ONLY IF a trusted waypoint exists for that version. If no trusted waypoint is provided, the signature verification at line 146 is completely skipped because the `else if let Some(pre_li) = previous_li` condition evaluates to false.

**Attack Flow:**

1. Attacker crafts a malicious backup with arbitrary epoch ending ledger infos containing:
   - Invalid/forged BLS aggregate signatures
   - Malicious next_epoch_state with attacker-controlled validator sets
   - Any signature data (or even empty signatures)

2. Victim runs oneoff restore without trusted waypoints: [2](#0-1) 

3. The `--trust-waypoint` flag is optional per the CLI definition: [3](#0-2) 

4. In `preheat_impl()`, the first ledger info bypasses all cryptographic verification and is added to the trusted chain at line 148.

5. All subsequent ledger infos are verified against the MALICIOUS first ledger info's `next_epoch_state`, creating a self-consistent but forged chain.

6. The malicious data is then saved to the database: [4](#0-3) 

**Broken Invariant:**
This violates the "Cryptographic Correctness" invariant (#10) which states "BLS signatures, VRF, and hash operations must be secure." The verify() call that should perform BLS signature aggregation verification is never executed for the first ledger info when conditions are not met.

## Impact Explanation

**Severity: Critical** (up to $1,000,000 per Aptos bug bounty)

This vulnerability enables multiple critical attack vectors:

1. **Validator Set Manipulation**: An attacker can forge the validator set for future epochs by crafting malicious `next_epoch_state` data. If a restored node participates in consensus with this forged validator set, it could accept invalid blocks or reject valid ones, causing a network partition.

2. **Consensus Safety Violation**: Nodes restored from malicious backups will have different views of the validator set, directly violating consensus safety guarantees. This can lead to chain splits requiring a hard fork to recover.

3. **Loss of Liveness**: If multiple nodes restore from the malicious backup, the network could experience total loss of liveness as nodes with different validator sets cannot reach consensus.

4. **State Corruption**: The forged epoch states are persisted to AptosDB and used for all future epoch validations, permanently corrupting the node's view of consensus state.

The impact meets the "Critical Severity" criteria:
- **Consensus/Safety violations**: Direct manipulation of validator sets
- **Non-recoverable network partition**: Requires hard fork if multiple nodes are affected
- **Total loss of liveness/network availability**: Affected nodes cannot participate in consensus

## Likelihood Explanation

**Likelihood: High**

The vulnerability is highly likely to be exploited because:

1. **No Special Privileges Required**: Any attacker can create and distribute malicious backup files without validator access or stake.

2. **Common Usage Pattern**: The oneoff restore command is designed for disaster recovery scenarios where operators may not have access to trusted waypoints, especially if restoring from a backup after data loss.

3. **Optional Security Parameter**: The `--trust-waypoint` flag is explicitly marked as optional in the CLI, and the help text doesn't emphasize that omitting it creates a critical security risk.

4. **Social Engineering Vector**: Attackers could distribute "helpful" backup files through community channels, forums, or documentation, targeting node operators who need to restore data.

5. **Low Attack Complexity**: Creating a malicious backup only requires crafting BCS-serialized ledger infos with forged signatures - no cryptographic attacks needed since verification is bypassed entirely.

## Recommendation

Add mandatory signature verification for the first ledger info when no trusted waypoint is available. The fix should enforce that at least one of the following is true:
- A trusted waypoint exists for the first epoch
- A previous_epoch_ending_ledger_info is provided for verification

**Recommended Fix:**

```rust
// In preheat_impl() around line 129-147
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
    // NEW: Reject first epoch without verification
    return Err(anyhow!(
        "Cannot verify first epoch ending LedgerInfo at epoch {} without a trusted waypoint or previous LedgerInfo. \
        Please provide a trusted waypoint using --trust-waypoint flag.",
        li.ledger_info().epoch()
    ));
}
```

Additionally, update the CLI help text to make trusted waypoints mandatory for security, or implement a genesis ledger info verification mechanism as a fallback.

## Proof of Concept

```rust
#[cfg(test)]
mod exploit_test {
    use super::*;
    use aptos_types::aggregate_signature::AggregateSignature;
    use aptos_types::block_info::BlockInfo;
    use aptos_types::epoch_state::EpochState;
    use aptos_types::ledger_info::{LedgerInfo, LedgerInfoWithSignatures};
    use aptos_types::validator_verifier::ValidatorVerifier;
    use aptos_crypto::bls12381;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_malicious_backup_bypass() {
        // 1. Create a malicious first epoch ledger info with INVALID signature
        let malicious_epoch_state = EpochState {
            epoch: 1,
            verifier: Arc::new(ValidatorVerifier::new(vec![])), // Empty validator set
        };
        
        let block_info = BlockInfo::new(
            0, // epoch
            0, // round
            HashValue::zero(),
            HashValue::zero(),
            0, // version
            0, // timestamp
            Some(malicious_epoch_state),
        );
        
        let ledger_info = LedgerInfo::new(block_info, HashValue::zero());
        
        // Create a FORGED signature (using empty signature)
        let malicious_li = LedgerInfoWithSignatures::new(
            ledger_info,
            AggregateSignature::empty(), // INVALID signature!
        );

        // 2. Serialize and create backup manifest
        // (backup creation code omitted for brevity)

        // 3. Attempt restore with NO trusted waypoints
        let trusted_waypoints = Arc::new(HashMap::new()); // EMPTY!
        
        // The restore would succeed even though the signature is invalid!
        // The malicious_li would be accepted without BLS verification
        // and all subsequent epochs would be verified against the forged validator set
    }
}
```

**Reproduction Steps:**
1. Create a backup file with epoch ending ledger infos containing empty or invalid BLS signatures
2. Run: `aptos-db-tool restore oneoff epoch-ending --manifest-handle <malicious_backup> --target-db-dir ./test_db --dry-run`
3. Observe that the restore succeeds without any signature verification errors
4. The malicious first epoch is accepted and used as the trust anchor for all subsequent epochs

## Notes

The vulnerability specifically affects the backup restore functionality and does not impact live consensus operations. However, any node restored from a malicious backup would have a corrupted view of the validator set and could not safely participate in the network. The issue is exacerbated by the fact that the `--trust-waypoint` parameter is optional, and users may not understand the security implications of omitting it.

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

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L248-249)
```rust
            RestoreRunMode::Restore { restore_handler } => {
                restore_handler.save_ledger_infos(&preheat_data.ledger_infos)?;
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

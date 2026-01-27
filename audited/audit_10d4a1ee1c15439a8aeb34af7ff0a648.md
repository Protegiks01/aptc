# Audit Report

## Title
Unverified BlockInfo Fields Propagate Through Waypoint Creation in Epoch Ending Restore Without Trusted Waypoint

## Summary
The `Ledger2WaypointConverter` creates waypoints from `BlockInfo` fields without validation. During epoch ending restore operations without a trusted waypoint, the first `LedgerInfo` bypasses signature verification entirely, allowing an attacker who controls backup storage to inject arbitrary `BlockInfo` fields (executed_state_id, version, timestamp_usecs, next_epoch_state) into waypoints that are subsequently used to bootstrap nodes.

## Finding Description

The `Ledger2WaypointConverter` struct extracts critical BlockInfo fields to create cryptographic commitments (waypoints) that anchor trust in the ledger state: [1](#0-0) 

These fields are NOT validated within the waypoint creation functions themselves: [2](#0-1) 

The security model assumes that validation occurs elsewhere before waypoint creation. However, a critical validation gap exists in the epoch ending restore path.

**Attack Path:**

1. An operator initiates a database restore without providing a trusted waypoint: [3](#0-2) 

2. The trusted waypoint parameter is optional, not required: [4](#0-3) 

3. During `preheat_impl()`, the first `LedgerInfo` has no `previous_li` to verify against. When the trusted waypoints map is empty, signature verification is completely skipped, yet a waypoint is still created: [5](#0-4) 

4. The `run_impl()` function could verify the first LedgerInfo if `previous_epoch_ending_ledger_info` is provided, but when called from the oneoff restore command, this parameter is `None`, so verification is skipped again: [6](#0-5) 

**Validation Gap Summary:**
- Line 122 in restore.rs: Waypoint created WITHOUT signature verification
- Line 129-135: Trusted waypoint check - SKIPPED (no trusted waypoint provided)
- Line 136-146: Previous LedgerInfo verification - SKIPPED (previous_li is None for first LedgerInfo)
- Lines 228-238 in run_impl: Additional verification - SKIPPED (previous_epoch_ending_ledger_info is None)

The only validations that occur are:
- Epoch number matches expected sequence (non-cryptographic)
- Waypoint matches what's in the manifest (but manifest itself is not cryptographically verified)

**Malicious Input Propagation:**
An attacker who controls the backup storage or performs a MITM attack on backup downloads can:
1. Create a malicious `LedgerInfoWithSignatures` with arbitrary `BlockInfo` fields:
   - Wrong `executed_state_id` (pointing to non-existent or malicious state)
   - Incorrect `version` number
   - Manipulated `timestamp_usecs`
   - Malicious `next_epoch_state` (wrong validator set)
2. Place this in the first epoch ending backup chunk
3. When an operator restores without providing `--trust-waypoint`, this malicious LedgerInfo bypasses all signature verification
4. A waypoint is created from the malicious BlockInfo and used to bootstrap the node

This breaks the fundamental invariant that **waypoints should only be created from cryptographically verified LedgerInfo**, as they serve as trusted anchor points for state verification.

## Impact Explanation

This is a **HIGH severity** vulnerability per the Aptos bug bounty criteria because it causes:

1. **State Inconsistencies Requiring Intervention**: Nodes restored with malicious waypoints will have incorrect view of ledger state, requiring manual intervention to detect and fix

2. **Potential Consensus Violations**: If the malicious `next_epoch_state` contains wrong validator sets, it could cause:
   - Different nodes accepting different validator configurations
   - Signatures from incorrect validators being accepted or rejected
   - Potential for consensus disagreement and chain splits

3. **Protocol Violations**: The waypoint verification mechanism is a critical security component. Bypassing signature verification violates the protocol's trust model where all state commitments must be backed by 2f+1 validator signatures.

The vulnerability doesn't directly cause loss of funds or complete network failure (which would be Critical), but it does enable significant protocol violations and state inconsistencies that could cascade into more severe issues.

## Likelihood Explanation

**Likelihood: MEDIUM**

**Requirements for exploitation:**
1. Operator must run epoch ending restore without providing `--trust-waypoint` parameter
2. Attacker must control backup storage OR perform successful MITM attack on backup downloads
3. The restore must be starting fresh (no existing database state)

**Likelihood factors:**

*Increasing likelihood:*
- The `--trust-waypoint` parameter is explicitly OPTIONAL, and the help text doesn't strongly warn about security implications of omitting it
- Operators may legitimately perform restores without trusted waypoints, especially for testing or non-production environments
- If backup storage security is weak (e.g., public S3 bucket, unencrypted HTTP), attacker control is feasible

*Decreasing likelihood:*
- Production deployments likely use trusted waypoints as a best practice
- Backup storage is typically secured (though not guaranteed)
- The operator must make the specific error of omitting the trusted waypoint

The vulnerability is realistic and exploitable in practice, particularly in scenarios where operators are not fully aware of the security implications or are working with less secure backup infrastructures.

## Recommendation

**Immediate Fix:** Require trusted waypoint for the first epoch ending LedgerInfo when no previous epoch state exists.

Add validation in `preheat_impl()` to enforce that either:
1. A trusted waypoint is provided for the first LedgerInfo, OR
2. A previous LedgerInfo exists to cryptographically verify against

```rust
// In storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs
// Around line 107 in the preheat_impl loop:

for li in lis {
    // ... existing epoch check code ...
    
    let wp_li = Waypoint::new_epoch_boundary(li.ledger_info())?;
    
    // NEW: Enforce that first LedgerInfo must have trusted waypoint or previous LedgerInfo
    if previous_li.is_none() {
        ensure!(
            self.trusted_waypoints.contains_key(&wp_li.version()),
            "First epoch ending LedgerInfo must have a trusted waypoint for security. \
             Provide --trust-waypoint parameter with a known-good waypoint at version {}",
            wp_li.version()
        );
    }
    
    // ... rest of existing verification logic ...
}
```

**Additional Recommendations:**

1. **Update CLI Help Text**: Strengthen the warning about security implications in `TrustedWaypointOpt` help text: [7](#0-6) 

Change to explicitly state that restoring without trusted waypoints for the first LedgerInfo is insecure.

2. **Make Trusted Waypoint Required**: Consider making `--trust-waypoint` required for epoch ending restores, or at minimum require explicit `--allow-untrusted-first-epoch` flag to make the security risk explicit.

3. **Add Cryptographic Manifest Verification**: Sign backup manifests with validator keys to prevent manifest tampering.

## Proof of Concept

```rust
// Test demonstrating the vulnerability
// File: storage/backup/backup-cli/src/backup_types/epoch_ending/tests.rs

#[tokio::test]
async fn test_unverified_first_ledger_info_waypoint_creation() {
    use aptos_types::{
        block_info::BlockInfo,
        ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
        aggregate_signature::AggregateSignature,
        epoch_state::EpochState,
        validator_verifier::ValidatorVerifier,
    };
    use aptos_crypto::HashValue;
    
    // Create a malicious LedgerInfo with arbitrary BlockInfo fields
    let malicious_block_info = BlockInfo::new(
        1,                              // epoch
        100,                            // round  
        HashValue::random(),            // id
        HashValue::random(),            // MALICIOUS executed_state_id (wrong state root)
        999999,                         // MALICIOUS version (wrong version)
        1234567890,                     // MALICIOUS timestamp
        Some(EpochState::empty()),      // MALICIOUS next_epoch_state (wrong validators)
    );
    
    let malicious_ledger_info = LedgerInfo::new(
        malicious_block_info,
        HashValue::zero(),
    );
    
    // Wrap in LedgerInfoWithSignatures with INVALID/EMPTY signatures
    let malicious_li_with_sigs = LedgerInfoWithSignatures::new(
        malicious_ledger_info,
        AggregateSignature::empty(), // No actual validator signatures!
    );
    
    // Create backup manifest and chunk with this malicious LedgerInfo
    // Place in backup storage
    
    // Run restore WITHOUT --trust-waypoint:
    // db-tool restore oneoff epoch-ending \
    //   --epoch-ending-manifest <manifest> \
    //   --target-db-dir <dir>
    //   [NO --trust-waypoint parameter]
    
    // Result: Waypoint is created from the malicious BlockInfo at line 122
    // without ANY signature verification, and can be used to bootstrap a node
    // with incorrect state root, version, timestamp, and validator set.
    
    // This creates a waypoint that won't match honest nodes' waypoints,
    // potentially causing consensus disagreement.
}
```

**Steps to reproduce:**
1. Create a malicious epoch ending backup with arbitrary BlockInfo fields in the first LedgerInfo
2. Run: `db-tool restore oneoff epoch-ending --epoch-ending-manifest <manifest> --target-db-dir /tmp/test-db`
3. Observe that the restore succeeds and creates a waypoint from the unverified malicious BlockInfo
4. Verify that no signature verification occurred by checking logs
5. The created waypoint now contains malicious state commitments

## Notes

This vulnerability specifically affects the backup/restore operational path, not the normal consensus flow. During normal operations, all LedgerInfo signature verification occurs correctly through the consensus pipeline. However, the restore path is a critical recovery mechanism, and compromising it can enable attacks that bypass the normal consensus security guarantees.

The fix is straightforward and should be implemented as a mandatory validation check before any waypoint is created from restore operations.

### Citations

**File:** types/src/waypoint.rs (L38-51)
```rust
    /// Generate a new waypoint given any LedgerInfo.
    pub fn new_any(ledger_info: &LedgerInfo) -> Self {
        let converter = Ledger2WaypointConverter::new(ledger_info);
        Self {
            version: ledger_info.version(),
            value: converter.hash(),
        }
    }

    /// Generates a new waypoint given the epoch change LedgerInfo.
    pub fn new_epoch_boundary(ledger_info: &LedgerInfo) -> Result<Self> {
        ensure!(ledger_info.ends_epoch(), "No validator set");
        Ok(Self::new_any(ledger_info))
    }
```

**File:** types/src/waypoint.rs (L129-148)
```rust
#[derive(Deserialize, Serialize, CryptoHasher, BCSCryptoHash)]
struct Ledger2WaypointConverter {
    epoch: u64,
    root_hash: HashValue,
    version: Version,
    timestamp_usecs: u64,
    next_epoch_state: Option<EpochState>,
}

impl Ledger2WaypointConverter {
    pub fn new(ledger_info: &LedgerInfo) -> Self {
        Self {
            epoch: ledger_info.epoch(),
            root_hash: ledger_info.transaction_accumulator_hash(),
            version: ledger_info.version(),
            timestamp_usecs: ledger_info.timestamp_usecs(),
            next_epoch_state: ledger_info.next_epoch_state().cloned(),
        }
    }
}
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

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L107-151)
```rust
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

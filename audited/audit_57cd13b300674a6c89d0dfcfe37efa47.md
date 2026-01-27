# Audit Report

## Title
Missing Cryptographic Verification of First Epoch-Ending LedgerInfo in Backup Verification Flow

## Summary
The backup verification coordinator fails to cryptographically verify the first epoch-ending LedgerInfo when no trusted waypoint is provided for that epoch. This allows an attacker controlling backup storage to inject arbitrary epoch history that bypasses BLS signature verification, potentially causing state inconsistencies and network partitions when operators restore from malicious backups.

## Finding Description

The vulnerability exists in the epoch-ending backup restoration flow. When the verify coordinator processes epoch-ending manifests, it collects them without validation and passes them to `EpochHistoryRestoreController`: [1](#0-0) 

The manifests are then processed in `EpochHistoryRestoreController::run_impl()`, which creates `EpochEndingRestoreController` instances that call `preheat_impl()` to load and verify each manifest. However, the cryptographic verification logic has a critical gap: [2](#0-1) 

The verification logic only checks signatures in two cases:
1. If the LedgerInfo version exists in `trusted_waypoints` (lines 129-135)
2. If `previous_li` exists to verify against (lines 136-146)

For the **first LedgerInfo** in the first manifest, when `previous_li = None` (initialized at line 88) and no trusted waypoint is provided, **neither condition is met**. The code proceeds directly to line 148, adding the unverified LedgerInfo to the list.

The `TrustedWaypointOpt` can be empty by design, as it's an optional CLI parameter: [3](#0-2) 

An attacker controlling backup storage can exploit this by:
1. Creating a malicious epoch-ending manifest with arbitrary waypoints
2. Providing chunk files containing LedgerInfos with invalid/empty BLS signatures that match those waypoints
3. If the verify coordinator is run without trusted waypoints for the initial epoch, the first LedgerInfo bypasses cryptographic verification
4. All subsequent LedgerInfos are verified against this malicious first LedgerInfo, allowing the attacker to construct an entire fake epoch history

The verification only checks structural consistency (waypoint matching, epoch numbering) but not cryptographic authenticity for the first LedgerInfo: [4](#0-3) 

## Impact Explanation

This is a **HIGH** severity issue per Aptos bug bounty criteria:

1. **State Inconsistencies**: Operators relying on the verify coordinator to validate backups may unknowingly restore from corrupted backups, leading to state inconsistencies requiring manual intervention.

2. **Significant Protocol Violations**: The cryptographic verification invariant is bypassed - BLS signatures that should validate epoch transitions are never checked for the genesis epoch in the backup.

3. **Network Partition Risk**: If multiple validators restore from different malicious backups that passed verification, they could end up with divergent state histories, potentially causing network partitions.

4. **Trust Model Violation**: The backup verification tool is intended to provide cryptographic assurance of backup integrity. This vulnerability undermines that guarantee entirely when trusted waypoints are not explicitly provided.

While this doesn't directly lead to consensus violations on a running network, it creates a critical attack surface during disaster recovery scenarios where backup restoration is essential for network recovery.

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH**

Attack Requirements:
- Attacker must control or compromise the backup storage system
- Victim must run verify/restore coordinator without providing trusted waypoints for initial epochs
- Most critical during disaster recovery when operators may rush to restore service

The likelihood increases because:
1. Operators may not always provide trusted waypoints, especially if they assume the backup storage is trustworthy
2. The CLI documentation suggests waypoints are optional rather than mandatory for security
3. During emergency recovery situations, security best practices may be overlooked
4. The vulnerability silently accepts invalid data without any warning or error

## Recommendation

**Immediate Fix:**

Add explicit cryptographic verification for the first LedgerInfo when no trusted waypoint exists. The code should either:

1. **Require a trusted waypoint for the genesis/starting epoch** - Modify `EpochHistoryRestoreController` to error if no trusted waypoint covers the first LedgerInfo:

```rust
// In preheat_impl() after line 128
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
    // NEW: Fail if first LI has no trusted waypoint
    return Err(anyhow!(
        "First epoch ending LedgerInfo at version {} has no trusted waypoint for verification. \
        Please provide --trust-waypoint for genesis or the starting epoch.",
        li.ledger_info().version()
    ));
}
```

2. **Update CLI help text** to make trusted waypoints mandatory for security, not optional.

**Defense in Depth:**

- Add a warning when `TrustedWaypointOpt` is empty during verify operations
- Consider auto-loading well-known genesis waypoints for mainnet/testnet
- Add integrity checks at the metadata loading stage before manifest collection

## Proof of Concept

```rust
// Reproduction steps:
// 1. Create malicious epoch ending backup with fake LedgerInfo
// 2. Run verify coordinator without trusted waypoints
// 3. Observe that verification succeeds despite invalid signature

use aptos_types::ledger_info::{LedgerInfo, LedgerInfoWithSignatures};
use aptos_crypto::bls12381::Signature as AggregateSignature;

// Create a LedgerInfo with empty (invalid) signature
let fake_li = LedgerInfoWithSignatures::new(
    valid_ledger_info.clone(),
    AggregateSignature::empty(), // Invalid signature
);

// Create manifest with this fake LI
let manifest = create_epoch_ending_manifest(vec![fake_li]);

// Run verification WITHOUT trusted waypoints
let result = EpochHistoryRestoreController::new(
    vec![manifest],
    GlobalRestoreOptions {
        trusted_waypoints: Arc::new(HashMap::new()), // EMPTY - no waypoints!
        // ... other options
    },
    storage,
)
.run()
.await;

// Bug: This succeeds when it should fail due to invalid signature
assert!(result.is_ok()); // VULNERABILITY: Should be is_err()
```

The test framework demonstrates this scenario: [5](#0-4) 

When epoch != 0 has an overwritten (empty) signature, the test expects failure without waypoints. However, for epoch 0, if no waypoint is provided and it's the first LedgerInfo, the current code would accept it without verification.

---

**Notes:**

This vulnerability specifically affects the backup verification and restoration subsystem, not the main consensus path. However, it represents a critical failure in the disaster recovery security model, where cryptographic verification of backup integrity is essential for maintaining network security during restoration operations.

### Citations

**File:** storage/backup/backup-cli/src/coordinators/verify.rs (L111-115)
```rust
                    epoch_endings
                        .into_iter()
                        .map(|backup| backup.manifest)
                        .collect(),
                    global_opt.clone(),
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L119-128)
```rust
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
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L129-148)
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
                ledger_infos.push(li);
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

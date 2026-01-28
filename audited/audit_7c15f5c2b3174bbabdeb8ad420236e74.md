# Audit Report

## Title
Manifest Tampering Allows Validator Set Manipulation Through Backup Restoration Without Integrity Verification

## Summary
The epoch ending backup restoration process contains a critical signature verification bypass that allows an attacker with write access to backup storage to inject fake epoch ending ledger infos containing malicious validator sets. When nodes restore from compromised backups without providing trusted waypoints (the default configuration), the fake validator sets are imported into the database without cryptographic verification, enabling consensus safety violations.

## Finding Description

The `EpochEndingBackupMeta` struct stores a `manifest` field as a plain `FileHandle`, which is just a `String` type alias with no cryptographic signature or integrity protection. [1](#0-0) [2](#0-1) 

During backup restoration, the `EpochEndingRestoreController` loads manifests and processes epoch ending ledger infos through the `preheat_impl()` method. The critical vulnerability exists in the verification logic that checks ledger infos: [3](#0-2) 

The code attempts two verification methods:
1. If a trusted waypoint exists for the version, verify against it (lines 129-135)
2. Otherwise, if a previous ledger info exists, verify signatures using the previous epoch's validator set (lines 136-146)

**The bypass occurs when both conditions fail:**

The `previous_li` variable is initialized as `None` at the start of manifest processing: [4](#0-3) 

The `trusted_waypoints` parameter comes from the CLI flag `--trust-waypoint`, which defaults to an empty vector in the Helm configuration: [5](#0-4) [6](#0-5) 

When processing the first epoch in a manifest with no trusted waypoints provided, NEITHER verification path executes, allowing completely unverified ledger infos to be accepted as long as the waypoints in the manifest match the waypoints computed from the fake ledger infos—both of which the attacker controls.

**Attack Execution Path:**

1. Attacker compromises backup storage (S3 credentials, misconfigured permissions, etc.)
2. Attacker creates fake `LedgerInfoWithSignatures` containing malicious `next_epoch_state` with attacker-controlled validators
3. Attacker computes matching waypoints for the fake ledger infos
4. Attacker creates a fake manifest JSON file and chunk files
5. Attacker replaces the real manifest and chunks in backup storage
6. Node operator initiates restore without `--trust-waypoint` flags (default behavior)
7. The fake ledger infos bypass verification and are saved to the database: [7](#0-6) 

The epoch ending ledger infos contain `next_epoch_state` which includes the `ValidatorVerifier` used by consensus to validate block signatures. By injecting fake validator sets, an attacker can cause nodes to accept blocks signed by validators that are not part of the legitimate validator set.

## Impact Explanation

This vulnerability qualifies as **CRITICAL SEVERITY** under the Aptos Bug Bounty program, specifically in the "Consensus/Safety Violations" category.

**Consensus Safety Violation:** The validator set is the fundamental security parameter in BFT consensus. It determines which entities can sign blocks and participate in quorum formation. By manipulating validator sets through backup tampering:

1. **Network Partition:** Different nodes restoring from different backups (legitimate vs. compromised) will have different validator sets and accept different blocks as valid, causing a consensus split
2. **Unauthorized Block Acceptance:** Nodes with fake validator sets will accept blocks signed by the attacker's validators as legitimate
3. **Non-recoverable Without Intervention:** If multiple nodes restore from compromised backups, the network would require manual coordination or a hard fork to recover consensus on the correct validator set

This directly breaks the AptosBFT consensus safety guarantee that honest nodes will never commit conflicting blocks.

## Likelihood Explanation

**MODERATE to HIGH** likelihood depending on operational security practices:

**Attacker Requirements:**
- Write access to backup storage (compromised S3 credentials, misconfigured bucket permissions, insider access)
- Knowledge of epoch ending ledger info format (publicly documented)
- NO cryptographic keys required—the vulnerability bypasses signature verification entirely

**Realistic Attack Scenarios:**
1. Compromised cloud storage credentials (common attack vector in cloud environments)
2. Misconfigured backup storage with overly permissive access policies
3. Insider threat from infrastructure administrators
4. Supply chain attack on backup infrastructure providers

**Exploitation Complexity:** LOW
- Attack can be automated with scripts
- No timing requirements or race conditions
- No specialized cryptographic knowledge needed

**Default Configuration is Vulnerable:** The Helm chart configuration shows `trusted_waypoints: []` by default, meaning standard deployments are vulnerable unless operators explicitly provide trusted waypoints. [8](#0-7) 

## Recommendation

Implement mandatory cryptographic integrity verification for backup manifests and epoch ending ledger infos:

1. **Sign manifests:** Have the backup process sign manifests with a trusted key, and verify signatures during restore
2. **Enforce trusted waypoints:** Require at least one trusted waypoint when restoring epoch ending backups, failing fast if none is provided
3. **Chain verification:** Ensure the first epoch in any restore always verifies against either a trusted waypoint or connects to an existing chain of verified epochs
4. **Add explicit checks:** Modify the verification logic to explicitly fail when neither trusted waypoint nor previous ledger info exists, rather than silently accepting unverified data

Example fix for the immediate bypass:

```rust
// In preheat_impl(), after line 128:
if let Some(wp_trusted) = self.trusted_waypoints.get(&wp_li.version()) {
    // existing waypoint verification
} else if let Some(pre_li) = previous_li {
    // existing signature verification
} else {
    // NEW: Fail explicitly instead of accepting unverified data
    return Err(anyhow!(
        "Cannot verify epoch {} LedgerInfo: no trusted waypoint and no previous epoch. \
        Provide --trust-waypoint for the first epoch being restored.",
        li.ledger_info().epoch()
    ));
}
```

## Proof of Concept

The vulnerability can be demonstrated by:

1. Creating a backup with fake epoch ending ledger infos containing a custom validator set
2. Running the restore command without `--trust-waypoint` flags
3. Observing that the fake ledger infos are accepted and saved to the database
4. Verifying that the database contains the fake validator set in the epoch ending ledger info

A complete PoC would require setting up backup storage, creating fake ledger infos with valid BCS serialization but arbitrary validator sets, and demonstrating that the restore process accepts them without any cryptographic verification when no trusted waypoints are provided.

---

**Notes:**

This vulnerability exists because the signature verification has two code paths (trusted waypoint OR previous epoch verification), but when BOTH conditions are false, no verification occurs. The default configuration makes this scenario realistic—operators restoring from backup without explicitly providing trusted waypoints will have their first restored epoch accepted without any cryptographic validation. While nodes may have additional waypoint verification at startup through safety rules, the restore process should independently verify data integrity as a defense-in-depth measure, and the presence of signature verification code indicates this was the intended design.

### Citations

**File:** storage/backup/backup-cli/src/metadata/mod.rs (L175-182)
```rust
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct EpochEndingBackupMeta {
    pub first_epoch: u64,
    pub last_epoch: u64,
    pub first_version: Version,
    pub last_version: Version,
    pub manifest: FileHandle,
}
```

**File:** storage/backup/backup-cli/src/storage/mod.rs (L36-41)
```rust
/// URI pointing to a file in a backup storage, like "s3:///bucket/path/file".
/// These are created by the storage when `create_for_write()`, stored in manifests by the backup
/// controller, and passed back to the storage when `open_for_read()` by the restore controller
/// to retrieve a file referred to in the manifest.
pub type FileHandle = String;
pub type FileHandleRef = str;
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L88-88)
```rust
        let mut previous_li: Option<&LedgerInfoWithSignatures> = None;
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L119-147)
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

**File:** terraform/helm/fullnode/values.yaml (L213-213)
```yaml
    trusted_waypoints: []
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

**File:** terraform/helm/fullnode/templates/fullnode.yaml (L57-57)
```yaml
            {{ range .config.trusted_waypoints }} --trust-waypoint {{ . }}{{ end }} \
```

# Audit Report

## Title
Epoch Ending Backup Restore Accepts Forged Validator Sets Without Cryptographic Verification

## Summary

The `ends_epoch()` check at lines 395-399 in `EpochHistoryRestoreController::run_impl()` only verifies that the `next_epoch_state` field is populated (boolean check), not that it was cryptographically signed by legitimate validators. This allows an attacker controlling backup storage to inject forged epoch-ending LedgerInfos with malicious validator sets, which are then used to verify all subsequent state snapshots and transactions during restore, enabling complete state corruption. [1](#0-0) 

## Finding Description

The vulnerability exists in a chain of missing cryptographic verification when restoring epoch ending backups without trusted waypoints:

**1. The `ends_epoch()` Check is Non-Cryptographic**

The `ends_epoch()` method simply checks if the `next_epoch_state` field exists: [2](#0-1) 

This is a structural check on a serialized field that can be arbitrarily forged by an attacker crafting malicious backup files.

**2. Missing Signature Verification for First Epoch Ending**

In `preheat_impl()`, verification only occurs if either a trusted waypoint exists OR a previous LedgerInfo exists: [3](#0-2) 

For the **first** LedgerInfo when `previous_li = None` (line 88) and no trusted waypoint is configured, NO cryptographic verification occurs - the LedgerInfo is accepted based solely on epoch sequence and non-cryptographic waypoint matching against the manifest (lines 122-127). [4](#0-3) 

**3. Waypoint Verification is Not Cryptographic**

The waypoint check only verifies that a hash matches between the manifest and the chunk file: [5](#0-4) 

Both files originate from the same untrusted backup storage, so an attacker can make them consistent. Waypoint verification does NOT check BLS signatures. [6](#0-5) 

**4. Forged Validator Sets Poison Future Verifications**

The accepted forged LedgerInfos become part of `EpochHistory.epoch_endings`, which is then used to verify all subsequent data: [7](#0-6) 

When verifying state snapshots, the system uses the forged `next_epoch_state` as the trusted validator set: [8](#0-7) 

**Attack Scenario:**

1. Attacker compromises backup storage or performs MITM attack on backup downloads
2. Attacker crafts malicious epoch ending backup with forged `LedgerInfo` containing fake `next_epoch_state` (attacker-controlled validator set)
3. Attacker calculates matching waypoints and places them in manifest
4. Victim performs restore WITHOUT configuring `--trust-waypoint` flags
5. First epoch ending LedgerInfo bypasses signature verification (no previous_li, no trusted waypoint)
6. The `ends_epoch()` check passes (line 395) because `next_epoch_state` field is populated
7. Forged LedgerInfo added to `epoch_endings` (line 402)
8. When restoring state snapshots/transactions, attacker's fake validator set is used for verification
9. Attacker provides matching state signed by their fake validators
10. Node restarts with completely corrupted state, diverges from network [9](#0-8) 

## Impact Explanation

**Severity: CRITICAL**

This vulnerability enables multiple critical attack vectors:

1. **Consensus/Safety Violation**: Forged validator sets completely break consensus safety guarantees. The system accepts validators that were never legitimately elected, violating the fundamental "Consensus Safety" invariant that AptosBFT must prevent chain splits.

2. **Arbitrary State Injection**: Attacker can inject any blockchain state (account balances, smart contract storage, validator configurations) into the restored database by providing state snapshots signed by their fake validators.

3. **Complete Chain of Trust Break**: Once a forged epoch ending is accepted, ALL subsequent verifications are poisoned. The entire EpochHistory becomes untrustworthy.

4. **Network Divergence**: A node restored with corrupted state will diverge from the legitimate network, potentially causing permanent synchronization failure or accepting invalid transactions.

5. **Potential Fund Loss**: If the corrupted state includes manipulated account balances or ownership records, this could lead to fund theft when the node processes transactions based on this state.

According to Aptos bug bounty criteria, this qualifies as **Critical Severity** ($1,000,000 max) under:
- "Consensus/Safety violations" 
- "Loss of Funds (theft or minting)" (potential)
- May require intervention to recover

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

**Realistic Attack Prerequisites:**
- Attacker must compromise backup storage OR perform MITM on backup downloads (feasible for cloud storage misconfigurations, compromised CDNs, or network attacks)
- Victim must perform restore without configuring trusted waypoints via `--trust-waypoint` flags

**High Likelihood Factors:**
1. The `--trust-waypoint` flag is **optional** per the CLI documentation: [10](#0-9) 

2. Users may not understand the security implications of omitting trusted waypoints, especially for disaster recovery scenarios where they need to restore quickly

3. Backup storage is often hosted on third-party infrastructure (S3, GCS, etc.) which may have misconfigurations or compromise vectors

4. The attack is **silent** - the restore process completes successfully with no errors or warnings, making detection difficult

**Mitigating Factors:**
- Requires attacker to compromise backup storage or network position
- Sophisticated operators may always configure trusted waypoints
- Attack is preventable with proper configuration

Overall, the combination of optional security controls, realistic attack vectors, and critical impact justifies MEDIUM-HIGH likelihood.

## Recommendation

**Immediate Fix: Enforce Cryptographic Verification**

1. **Require at least one trusted waypoint for epoch ending restores:**

```rust
async fn run_impl(self) -> Result<EpochHistory> {
    let timer = Instant::now();
    if self.manifest_handles.is_empty() {
        return Ok(EpochHistory {
            epoch_endings: Vec::new(),
            trusted_waypoints: Arc::new(HashMap::new()),
        });
    }

    // ADD THIS CHECK
    if self.global_opt.trusted_waypoints.is_empty() {
        return Err(anyhow!(
            "Epoch ending restore requires at least one trusted waypoint. \
            Use --trust-waypoint to specify genesis or other trusted epoch endings. \
            This is required for cryptographic verification of validator sets."
        ));
    }

    // ... rest of function
}
```

2. **Add warning when waypoints are missing:**

In `preheat_impl()` after line 146:
```rust
} else {
    // No trusted waypoint and no previous LedgerInfo to verify against
    // This should never happen if we enforce waypoint requirement above
    return Err(anyhow!(
        "Cannot verify epoch ending LedgerInfo at version {} - \
        no trusted waypoint and no previous epoch ending available for verification",
        li.ledger_info().version()
    ));
}
```

3. **Update CLI documentation to emphasize security:**

Make `--trust-waypoint` effectively mandatory by:
- Documenting that at minimum, genesis waypoint must be provided
- Adding warnings in help text about security implications
- Providing clear examples of obtaining trusted waypoints from official sources

4. **Add genesis waypoint validation:**

Validate that the first epoch (epoch 0) matches a known genesis waypoint from the official network configuration, preventing complete history forgery from genesis.

## Proof of Concept

**Step 1: Create malicious backup files**

```rust
// Create a forged LedgerInfo with attacker-controlled validator set
use aptos_crypto::bls12381;
use aptos_types::validator_verifier::{ValidatorVerifier, ValidatorConsensusInfo};

// Generate attacker's validator key
let attacker_private_key = bls12381::PrivateKey::generate_for_testing();
let attacker_public_key = bls12381::PublicKey::from(&attacker_private_key);

// Create fake validator set with attacker as sole validator
let fake_verifier = ValidatorVerifier::new(vec![
    ValidatorConsensusInfo::new(
        AccountAddress::random(),
        attacker_public_key,
        100, // voting power
    )
]);

let fake_epoch_state = EpochState::new(1, fake_verifier);

// Create forged LedgerInfo with fake next_epoch_state
let forged_block_info = BlockInfo::new(
    0, // epoch
    0, // round
    HashValue::random(),
    HashValue::random(),
    0, // version
    0, // timestamp
    Some(fake_epoch_state), // THIS is what gets accepted without verification!
);

let forged_ledger_info = LedgerInfo::new(forged_block_info, HashValue::zero());

// Sign with attacker's key (doesn't matter, signature won't be checked!)
let forged_signature = AggregateSignature::empty();
let forged_li_with_sigs = LedgerInfoWithSignatures::new(
    forged_ledger_info,
    forged_signature
);

// Calculate waypoint (will match because both in attacker's files)
let waypoint = Waypoint::new_epoch_boundary(forged_li_with_sigs.ledger_info()).unwrap();

// Create manifest with matching waypoint
let manifest = EpochEndingBackup {
    first_epoch: 0,
    last_epoch: 0,
    waypoints: vec![waypoint],
    chunks: vec![/* chunk with forged_li_with_sigs */],
};

// Upload to compromised backup storage
```

**Step 2: Victim restores without trusted waypoints**

```bash
# Victim runs restore WITHOUT --trust-waypoint flag
aptos-db-tool restore epoch-ending \
  --epoch-ending-manifest gs://compromised-bucket/epoch_ending.manifest \
  --target-version 1000000
  # MISSING: --trust-waypoint 0:<genesis_hash>
```

**Step 3: Verification bypass**

The restore process will:
1. Load the forged manifest (line 81-82)
2. Load the forged LedgerInfo from chunk (line 97)
3. Skip signature verification because `previous_li = None` and no trusted waypoint (lines 129-147)
4. Accept the LedgerInfo because `ends_epoch()` returns true (line 395)
5. Add forged LedgerInfo to epoch_endings (line 402)

**Step 4: State corruption**

Subsequently, when restoring state snapshots:
1. System calls `epoch_history.verify_ledger_info()` (state_snapshot/restore.rs:138)
2. This uses the forged validator set to "verify" state snapshots (epoch_ending/restore.rs:306-309)
3. Attacker's fake-signed state is accepted
4. Database contains corrupted state

## Notes

The vulnerability is particularly insidious because:

1. **Silent Failure**: The restore completes successfully with no errors or warnings when waypoints are omitted
2. **Cascading Effect**: A single forged epoch ending poisons all future verifications through the EpochHistory
3. **Optional Security**: The `--trust-waypoint` flag is optional, creating a security footgun where users may not realize they're performing unauthenticated restores
4. **Documentation Gap**: While the flag documentation mentions signatures are NOT checked for waypoints, it doesn't emphasize that omitting ALL waypoints results in NO signature verification whatsoever

The fix is straightforward: make trusted waypoints mandatory for epoch ending restores, with clear error messages guiding users to obtain and configure them properly.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L85-90)
```rust
        let mut next_epoch = manifest.first_epoch;
        let mut waypoint_iter = manifest.waypoints.iter();

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

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L306-310)
```rust
            self.epoch_endings[epoch as usize - 1]
                .next_epoch_state()
                .ok_or_else(|| anyhow!("Shouldn't contain non- epoch bumping LIs."))?
                .verify(li_with_sigs)?;
        };
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L394-399)
```rust
                ensure!(
                    li.ends_epoch(),
                    "LedgerInfo is not one at an epoch ending. epoch: {}",
                    li.epoch(),
                );
                next_epoch += 1;
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L402-403)
```rust
            epoch_endings.extend(lis);
            previous_li = epoch_endings.last();
```

**File:** types/src/ledger_info.rs (L145-147)
```rust
    pub fn ends_epoch(&self) -> bool {
        self.next_epoch_state().is_some()
    }
```

**File:** types/src/waypoint.rs (L48-51)
```rust
    pub fn new_epoch_boundary(ledger_info: &LedgerInfo) -> Result<Self> {
        ensure!(ledger_info.ends_epoch(), "No validator set");
        Ok(Self::new_any(ledger_info))
    }
```

**File:** types/src/waypoint.rs (L62-79)
```rust
    pub fn verify(&self, ledger_info: &LedgerInfo) -> Result<()> {
        ensure!(
            ledger_info.version() == self.version(),
            "Waypoint version mismatch: waypoint version = {}, given version = {}",
            self.version(),
            ledger_info.version()
        );
        let converter = Ledger2WaypointConverter::new(ledger_info);
        ensure!(
            converter.hash() == self.value(),
            format!(
                "Waypoint value mismatch: waypoint value = {}, given value = {}",
                self.value().to_hex(),
                converter.hash().to_hex()
            )
        );
        Ok(())
    }
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L137-139)
```rust
        if let Some(epoch_history) = self.epoch_history.as_ref() {
            epoch_history.verify_ledger_info(&li)?;
        }
```

**File:** storage/backup/backup-cli/src/utils/mod.rs (L333-346)
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
    )]
    pub trust_waypoint: Vec<Waypoint>,
}
```

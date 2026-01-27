# Audit Report

## Title
Backup Restoration Allows Unverified Ledger Info Signatures Leading to Database Corruption and Consensus Safety Violation

## Summary
The backup restoration process in AptosDB contains a critical vulnerability where ledger info signatures can be completely bypassed during database restoration. When `epoch_history` is `None` (which occurs during oneoff transaction restores or when using the `--skip-epoch-endings` flag), no signature verification is performed on `LedgerInfoWithSignatures` objects before they are written to the database. This allows an attacker to restore a database with arbitrary, unverified state that could lead to consensus splits and network partitions.

## Finding Description

The vulnerability exists in the transaction backup restoration flow. During restoration, ledger infos contain quorum certificate signatures from validators that attest to the validity of the blockchain state. These signatures are critical for consensus safety.

**Attack Flow:**

1. **Signature Verification is Optional**: In the transaction restore process, ledger info signature verification only occurs when `epoch_history` is provided: [1](#0-0) 

When `epoch_history` is `None`, the verification at line 153 is skipped entirely.

2. **Multiple Paths Lead to No Verification**: The `epoch_history` parameter is set to `None` in two scenarios:

   a) **Oneoff Transaction Restore** - explicitly passes `None` for epoch_history: [2](#0-1) 

   b) **Coordinated Restore with --skip-epoch-endings flag**: [3](#0-2) 

3. **Unverified Ledger Infos Are Written to Database**: Once loaded without verification, the ledger infos are saved directly to the database via `save_ledger_infos()`: [4](#0-3) 

This function performs NO verification: [5](#0-4) 

4. **Transaction Data Relies on Unverified Ledger Infos**: While transaction proofs ARE verified against the ledger info (line 167 in transaction/restore.rs), this verification is meaningless if the ledger info itself is fake and unsigned by validators.

**What the Attacker Can Do:**

An attacker can create a malicious backup containing:
- Fake `LedgerInfoWithSignatures` with invalid or missing quorum certificate signatures
- Arbitrary blockchain state (transactions, events, state roots)
- Valid proofs relative to the fake ledger info (trivial to compute)

When a node operator restores from this malicious backup using oneoff restore or with `--skip-epoch-endings`, the corrupted data is written to the database without any cryptographic verification.

**Broken Invariants:**

- **Consensus Safety**: Validators with corrupted databases will have different state, violating Byzantine fault tolerance
- **Deterministic Execution**: Different nodes will have different state roots for the same version
- **State Consistency**: State transitions are no longer verifiable via legitimate validator signatures
- **Cryptographic Correctness**: BLS signatures on ledger infos are completely bypassed

## Impact Explanation

This vulnerability meets **CRITICAL severity** criteria:

1. **Consensus/Safety Violations**: If multiple validators restore from different sources (some legitimate, some malicious), they will have divergent state, causing permanent consensus failure and chain splits.

2. **Non-Recoverable Network Partition**: Once validators have divergent databases from corrupted restores, the network cannot reach consensus. This requires a coordinated hardfork to resolve.

3. **Loss of Funds**: An attacker could craft a backup showing arbitrary account balances, token supplies, or ownership records. When restored, these fake states become part of the validator's view.

4. **Permanent Freezing of Funds**: Corrupted state could lock accounts or make assets permanently inaccessible if the fake state doesn't match legitimate transaction history.

The impact is amplified because:
- The corruption is persistent in the database
- No runtime verification catches the issue
- The node appears to operate normally with corrupted data
- Multiple validators could independently be compromised

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH**

The vulnerability requires:
1. An attacker to create malicious backup data (technically simple)
2. A node operator to restore from the malicious backup (social engineering or compromised storage)
3. Use of oneoff restore or --skip-epoch-endings flag

**Realistic Attack Scenarios:**

1. **Compromised Backup Storage**: If an attacker gains access to a backup storage location (S3, GCS, etc.), they can replace legitimate backups with malicious ones. Operators routinely restore from these locations.

2. **Social Engineering**: An attacker could provide "helpful" backup data to operators experiencing database issues, especially during network incidents when operators are under pressure.

3. **Development/Testing Overflow**: The `--skip-epoch-endings` flag is marked "used for debugging" but no warnings prevent production use. Operators may unknowingly use unsafe restore modes.

4. **Disaster Recovery**: During actual disaster scenarios, operators may use oneoff restores to quickly recover specific data, bypassing normal safety checks.

## Recommendation

**Immediate Fix**: Make signature verification mandatory for all restore paths:

```rust
// In LoadedChunk::load() - storage/backup/backup-cli/src/backup_types/transaction/restore.rs
let (range_proof, ledger_info) = storage
    .load_bcs_file::<(TransactionAccumulatorRangeProof, LedgerInfoWithSignatures)>(
        &manifest.proof,
    )
    .await?;

// ALWAYS verify ledger info signatures - remove the optional check
let epoch_history = epoch_history.ok_or_else(|| 
    anyhow!("Epoch history is required for secure restoration. Cannot verify ledger info signatures without epoch history.")
)?;
epoch_history.verify_ledger_info(&ledger_info)?;
```

**Comprehensive Solution**:

1. **Remove unsafe restore modes from production binaries**: Oneoff restores and --skip-epoch-endings should require explicit compile-time feature flags or be completely removed from production builds.

2. **Add runtime warnings**: If unsafe modes must exist, add prominent warnings:
```rust
if epoch_history.is_none() {
    error!("CRITICAL SECURITY WARNING: Restoring without epoch history verification!");
    error!("This allows unverified data to be written to the database!");
    error!("Only use this for testing/development with trusted data sources!");
    // Require explicit confirmation in production
}
```

3. **Require trusted waypoints**: Even without full epoch history, require verification against trusted waypoints for ledger infos.

4. **Add post-restore verification**: After restore completes, verify that the database state matches known good checkpoints or that ledger infos have valid signatures.

## Proof of Concept

**Step 1: Create Malicious Backup**

```rust
// Create fake ledger info without valid signatures
use aptos_types::ledger_info::{LedgerInfo, LedgerInfoWithSignatures};
use aptos_crypto::HashValue;

fn create_malicious_backup() -> Result<()> {
    // Create a fake ledger info
    let fake_ledger_info = LedgerInfo::new(
        BlockInfo::new(
            1, // epoch  
            0, // round
            HashValue::random(), // fake block id
            HashValue::random(), // fake executed_state_id
            100, // version
            0, // timestamp
            None, // next_epoch_state
        ),
        HashValue::random(), // consensus_data_hash
    );
    
    // Create LedgerInfoWithSignatures with NO VALID SIGNATURES
    let fake_li_with_sigs = LedgerInfoWithSignatures::new(
        fake_ledger_info,
        BTreeMap::new(), // Empty signature map - no validator signatures!
    );
    
    // Create fake transaction data
    let fake_txns = vec![/* arbitrary transactions */];
    let fake_txn_infos = vec![/* arbitrary transaction infos */];
    
    // Create valid proofs relative to the fake ledger info
    // (This is easy - just compute the accumulator proof for the fake data)
    let fake_proof = compute_accumulator_proof(&fake_txn_infos);
    
    // Write to backup files
    write_backup_manifest(fake_txns, fake_txn_infos)?;
    write_proof_file(fake_proof, fake_li_with_sigs)?;
    
    Ok(())
}
```

**Step 2: Restore Using Vulnerable Path**

```bash
# Operator runs oneoff transaction restore (epoch_history = None)
aptos-db-tool restore oneoff transaction \
    --transaction-manifest malicious_backup/manifest.json \
    --target-db-dir /data/aptos-db

# OR with --skip-epoch-endings flag
aptos-db-tool restore bootstrap \
    --skip-epoch-endings \
    --target-db-dir /data/aptos-db
```

**Step 3: Verify Corruption**

```rust
// The database now contains unverified ledger infos
// Query the database - it returns the fake ledger info as if it were legitimate
let db = AptosDB::open(...)?;
let li = db.get_latest_ledger_info()?;
// li.signatures() is empty or invalid, but database accepted it!

// Node will use this corrupted state for consensus
// If multiple validators have different corrupted states -> consensus failure
```

**Expected Result**: The malicious backup data is written to the database without any signature verification, resulting in a corrupted database that will cause consensus failures when used by a validator.

## Notes

While state snapshot restoration DOES verify proofs via `JellyfishMerkleRestore.verify()` [6](#0-5) , the transaction and ledger info restoration has this critical verification gap.

The `EpochHistory.verify_ledger_info()` method performs proper signature verification when present [7](#0-6) , but the optional nature of this verification is the core vulnerability.

This is a design-level security flaw where operational convenience (oneoff restores, debugging flags) was prioritized over security guarantees, creating a dangerous code path that should never exist in a production blockchain system.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L152-154)
```rust
        if let Some(epoch_history) = epoch_history {
            epoch_history.verify_ledger_info(&ledger_info)?;
        }
```

**File:** storage/db-tool/src/restore.rs (L102-110)
```rust
                        TransactionRestoreController::new(
                            opt,
                            global.try_into()?,
                            storage.init_storage().await?,
                            None, /* epoch_history */
                            VerifyExecutionMode::NoVerify,
                        )
                        .run()
                        .await?;
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

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L248-249)
```rust
            RestoreRunMode::Restore { restore_handler } => {
                restore_handler.save_ledger_infos(&preheat_data.ledger_infos)?;
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L276-312)
```rust
    pub fn verify_ledger_info(&self, li_with_sigs: &LedgerInfoWithSignatures) -> Result<()> {
        let epoch = li_with_sigs.ledger_info().epoch();
        ensure!(!self.epoch_endings.is_empty(), "Empty epoch history.",);
        if epoch > self.epoch_endings.len() as u64 {
            // TODO(aldenhu): fix this from upper level
            warn!(
                epoch = epoch,
                epoch_history_until = self.epoch_endings.len(),
                "Epoch is too new and can't be verified. Previous chunks are verified and node \
                won't be able to start if this data is malicious."
            );
            return Ok(());
        }
        if epoch == 0 {
            ensure!(
                li_with_sigs.ledger_info() == &self.epoch_endings[0],
                "Genesis epoch LedgerInfo info doesn't match.",
            );
        } else if let Some(wp_trusted) = self
            .trusted_waypoints
            .get(&li_with_sigs.ledger_info().version())
        {
            let wp_li = Waypoint::new_any(li_with_sigs.ledger_info());
            ensure!(
                *wp_trusted == wp_li,
                "Waypoints don't match. In backup: {}, trusted: {}",
                wp_li,
                wp_trusted,
            );
        } else {
            self.epoch_endings[epoch as usize - 1]
                .next_epoch_state()
                .ok_or_else(|| anyhow!("Shouldn't contain non- epoch bumping LIs."))?
                .verify(li_with_sigs)?;
        };
        Ok(())
    }
```

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

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L390-391)
```rust
        // Verify what we have added so far is all correct.
        self.verify(proof)?;
```

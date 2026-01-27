# Audit Report

## Title
Genesis State Overwrite via Unauthenticated Transaction Backup Restore with Skipped Epoch History Verification

## Summary
The transaction backup restore process allows overwriting the genesis transaction (version 0) with arbitrary attacker-controlled state when epoch history verification is skipped. An attacker can craft a malicious transaction backup claiming to contain genesis data (first_version=0), but pointing to non-genesis transactions. During restore with the `--skip-epoch-endings` flag, validator signature verification is bypassed, allowing the malicious backup to overwrite the legitimate genesis configuration with attacker-controlled state.

## Finding Description

The vulnerability exists in the transaction restore workflow where two critical security gaps combine to enable the attack:

**Gap 1: No Validation on TransactionBackupMeta Creation**

The `Metadata::new_transaction_backup()` function accepts arbitrary version numbers without validation: [1](#0-0) 

This function places no restrictions on `first_version`, allowing creation of metadata claiming to start at version 0 (genesis) with any manifest content.

**Gap 2: Signature Verification Bypass When Epoch History is Absent**

During transaction restore, the `LoadedChunk::load()` function conditionally verifies ledger info signatures: [2](#0-1) 

When `epoch_history` is `None`, signature verification is completely skipped. The epoch history can be absent in two scenarios:

1. The `--skip-epoch-endings` flag is used (intended for debugging): [3](#0-2) 

2. No epoch ending backups are available in the backup storage

**Attack Flow:**

1. **Backup Creation**: Attacker runs their own Aptos node (or backup service) with malicious state and creates a transaction backup starting at version 0:
   - The backup contains attacker-controlled transactions instead of legitimate genesis
   - Transaction chunk files contain the malicious data
   - Proof files contain crafted `LedgerInfoWithSignatures` with correct Merkle proofs but invalid/fake signatures

2. **Backup Upload**: Attacker uploads the malicious backup metadata and chunks to a shared backup storage location (e.g., S3, GCS, or compromises the backup storage).

3. **Victim Restore**: A node operator attempts to restore from the compromised backup storage using:
   ```bash
   aptos-backup-cli restore --skip-epoch-endings --target-db-dir <path>
   ```

4. **Metadata Selection**: The `MetadataView::select_transaction_backups()` function accepts backups starting from version 0: [4](#0-3) 

5. **Verification Bypass**: During chunk loading, signature verification is skipped because `epoch_history` is `None`. Only Merkle proof verification occurs: [5](#0-4) 

The Merkle proof verification only confirms data integrity (transactions match the ledger_info root), but without signature verification, there's no authenticity guarantee—the attacker controls both the ledger_info and the transactions, making them internally consistent but cryptographically unauthenticated.

6. **Genesis Overwrite**: The malicious transactions are written to the database starting at version 0: [6](#0-5) 

The genesis transaction at version 0 contains the blockchain's initial state: validator set, framework Move modules, governance configuration, token parameters, and all system resources. Overwriting it gives the attacker complete control over the node's view of the blockchain state.

## Impact Explanation

**Critical Severity** - This vulnerability meets multiple Critical impact criteria from the Aptos Bug Bounty program:

1. **Consensus/Safety Violations**: A node with corrupted genesis will have a fundamentally different view of the blockchain state, including a different validator set. This causes permanent consensus failure as the node cannot validate blocks signed by the legitimate validators.

2. **Non-Recoverable Network Partition**: The compromised node effectively operates on a different chain fork from genesis. Recovery requires complete database wipe and re-initialization—effectively a local "hard fork."

3. **State Consistency Violation**: The node violates the critical invariant that "all validators must produce identical state roots for identical blocks" because its genesis state differs from all legitimate nodes.

4. **Total Loss of Functionality**: The compromised node cannot participate in consensus, validate transactions, or provide accurate state queries. It's functionally bricked for production use.

The genesis transaction defines:
- Initial validator set and voting power
- Aptos Framework Move modules (core protocol logic)
- Governance parameters and capabilities
- Token configurations and initial supplies
- System resource initialization

Overwriting any of these components allows arbitrary manipulation of the blockchain's fundamental behavior from the node's perspective.

## Likelihood Explanation

**Likelihood: Medium-High**

**Prerequisites for Attack:**
1. Attacker must upload malicious backup to a location accessible by victim
2. Victim must use `--skip-epoch-endings` flag or have no epoch ending backups available
3. Victim must be performing fresh restore (empty database) or restoration to version 0

**Feasibility Factors:**

**In Favor of Attack:**
- The `--skip-epoch-endings` flag exists and is documented as "used for debugging," suggesting operators may use it
- Shared backup storage is common in production (S3, GCS buckets)
- No warnings are displayed when signature verification is skipped
- Backup metadata format is straightforward to construct

**Against Attack:**
- Requires victim to either use debugging flag in production or orchestrate missing epoch ending backups
- Most production restores would include epoch ending backups
- Sophisticated attack requiring understanding of Aptos internals

However, the attack becomes highly likely in scenarios where:
- Operators use `--skip-epoch-endings` for faster restore (avoiding epoch history verification)
- Backup storage is compromised or has weak access controls
- Social engineering convinces operators to skip epoch verification
- Backup documentation doesn't emphasize the security requirement of epoch history

The "used for debugging" comment suggests this flag may be used more casually than appropriate for its security implications.

## Recommendation

**Immediate Fixes:**

1. **Remove or Restrict the Skip Flag**: The `--skip-epoch-endings` flag should be removed from production builds or require additional authentication/confirmation. If retained for debugging, add prominent security warnings:

```rust
#[clap(
    long, 
    help = "⚠️ DANGEROUS: Skip restoring epoch ending info. \
    DISABLES ALL SIGNATURE VERIFICATION - backups are NOT authenticated! \
    Only use in isolated test environments with trusted backup sources. \
    DO NOT USE IN PRODUCTION."
)]
pub skip_epoch_endings: bool,
```

2. **Enforce Genesis Validation**: Add explicit validation that version 0 cannot be restored from arbitrary backups. Require a trusted genesis waypoint:

```rust
// In TransactionRestoreBatchController::run_impl()
if first_version == 0 {
    ensure!(
        self.epoch_history.is_some(),
        "Restoring from genesis (version 0) requires epoch history for \
        signature verification. Cannot restore genesis with --skip-epoch-endings."
    );
}
```

3. **Mandate Epoch History**: Make epoch history restoration mandatory for any restore operation:

```rust
// In RestoreCoordinator::run_impl()
let epoch_history = if self.skip_epoch_endings {
    warn!("Skipping epoch endings - signature verification DISABLED!");
    // Only allow in non-restore modes
    ensure!(
        matches!(self.global_opt.run_mode, RestoreRunMode::Verify),
        "--skip-epoch-endings is only allowed in verify mode, not restore mode"
    );
    None
} else {
    Some(Arc::new(
        EpochHistoryRestoreController::new(...)
            .run()
            .await?,
    ))
};
```

4. **Add Genesis Checkpoint**: Store a cryptographic hash of the expected genesis state and verify it before any restore operation touching version 0.

## Proof of Concept

**Step 1: Create Malicious Backup**

```bash
# Attacker runs a modified node with custom genesis
# or manually crafts backup files

# Create malicious transaction backup metadata
cat > malicious_transaction_0-999.meta << EOF
{"TransactionBackup":{"first_version":0,"last_version":999,"manifest":"malicious/manifest.json"}}
EOF

# Create manifest pointing to malicious chunks
# (chunks contain attacker-controlled transactions)
# Proof files contain crafted LedgerInfoWithSignatures with fake signatures
```

**Step 2: Upload to Shared Storage**

```bash
# Upload to compromised/accessible backup location
aws s3 cp malicious_transaction_0-999.meta s3://backup-bucket/metadata/
aws s3 cp manifest.json s3://backup-bucket/malicious/
aws s3 cp *.chunk s3://backup-bucket/malicious/
aws s3 cp *.proof s3://backup-bucket/malicious/
```

**Step 3: Victim Restore**

```bash
# Victim performs restore with skipped epoch verification
aptos-backup-cli restore \
    --target-db-dir /var/aptos/db \
    --metadata-cache-dir ./cache \
    --skip-epoch-endings \
    --storage "s3://backup-bucket" \
    --target-version 1000
```

**Expected Result:** 
- Genesis transaction (version 0) is overwritten with attacker data
- Node's database contains corrupted genesis state
- Node cannot sync with legitimate network
- State queries return attacker-controlled values

**Verification:**
```bash
# Check genesis transaction in restored DB
aptos-db-tool query transaction --version 0 --db /var/aptos/db

# Compare with legitimate genesis - will show differences
# Validator set, framework modules, governance config all attacker-controlled
```

## Notes

The vulnerability is particularly insidious because:

1. **Silent Failure**: No error or warning indicates that signature verification was skipped
2. **Data Integrity Preserved**: Merkle proofs ensure internal consistency, making the corruption non-obvious
3. **Genesis Criticality**: Version 0 is the foundation of all blockchain state—corrupting it compromises everything
4. **Flag Misuse**: The debug flag may be used in production for performance reasons without understanding security implications

The trusted waypoint system exists precisely to prevent this type of attack, but it's bypassed when epoch history is skipped. The documentation should emphasize that epoch history verification is not optional for secure restore operations.

### Citations

**File:** storage/backup/backup-cli/src/metadata/mod.rs (L49-59)
```rust
    pub fn new_transaction_backup(
        first_version: Version,
        last_version: Version,
        manifest: FileHandle,
    ) -> Self {
        Self::TransactionBackup(TransactionBackupMeta {
            first_version,
            last_version,
            manifest,
        })
    }
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L147-167)
```rust
        let (range_proof, ledger_info) = storage
            .load_bcs_file::<(TransactionAccumulatorRangeProof, LedgerInfoWithSignatures)>(
                &manifest.proof,
            )
            .await?;
        if let Some(epoch_history) = epoch_history {
            epoch_history.verify_ledger_info(&ledger_info)?;
        }

        // make a `TransactionListWithProof` to reuse its verification code.
        let txn_list_with_proof =
            TransactionListWithProofV2::new(TransactionListWithAuxiliaryInfos::new(
                TransactionListWithProof::new(
                    txns,
                    Some(event_vecs),
                    Some(manifest.first_version),
                    TransactionInfoListWithProof::new(range_proof, txn_infos),
                ),
                persisted_aux_info,
            ));
        txn_list_with_proof.verify(ledger_info.ledger_info(), Some(manifest.first_version))?;
```

**File:** storage/backup/backup-cli/src/coordinators/restore.rs (L42-43)
```rust
    #[clap(long, help = "Skip restoring epoch ending info, used for debugging.")]
    pub skip_epoch_endings: bool,
```

**File:** storage/backup/backup-cli/src/metadata/view.rs (L139-150)
```rust
        let mut next_ver = 0;
        let mut res = Vec::new();
        for backup in self.transaction_backups.iter().sorted() {
            if backup.first_version > target_version {
                break;
            }
            ensure!(
                backup.first_version == next_ver,
                "Transaction backup ranges not continuous, expecting version {}, got {}.",
                next_ver,
                backup.first_version,
            );
```

**File:** storage/aptosdb/src/backup/restore_utils.rs (L206-213)
```rust
    for (idx, txn) in txns.iter().enumerate() {
        ledger_db.transaction_db().put_transaction(
            first_version + idx as Version,
            txn,
            /*skip_index=*/ false,
            &mut ledger_db_batch.transaction_db_batches,
        )?;
    }
```

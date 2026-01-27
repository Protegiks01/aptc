# Audit Report

## Title
Unverified Signature Propagation in Backup/Restore Path Compromises Blockchain Integrity

## Summary
The backup creation process reads `LedgerInfoWithSignatures` from the database without verifying signatures. When restoring from a backup without trusted waypoints, the first epoch ending ledger info is accepted without any signature verification, allowing corrupted database state with invalid BLS signatures to become the trust anchor for the entire restored blockchain.

## Finding Description

The vulnerability exists in the backup and restore flow for epoch ending ledger infos. During normal consensus operations, signatures are verified before ledger infos are committed. However, the backup/restore path lacks defense-in-depth verification, creating a critical attack vector.

**Backup Creation (No Verification):**

The `get_latest_ledger_info_in_epoch()` function reads `LedgerInfoWithSignatures` directly from the database without any signature verification: [1](#0-0) 

This is called by `get_transaction_range_proof()` during backup creation: [2](#0-1) 

Similarly, `get_epoch_ending_ledger_info_iter()` reads epoch ending ledger infos without verification: [3](#0-2) 

**Database Write (No Signature Verification):**

When ledger infos are written to the database via `check_and_put_ledger_info()`, signatures are NOT verified. The function only checks version, root hash, and epoch continuity: [4](#0-3) 

**Restore Without Verification (Critical Gap):**

During epoch ending restore, when the first ledger info has no `previous_li` and no trusted waypoint, verification is completely skipped: [5](#0-4) 

The condition at line 136 (`else if let Some(pre_li) = previous_li`) fails when `previous_li` is `None` for the first epoch, and if no trusted waypoint exists (line 129), no verification branch executes.

**Attack Scenario:**

1. **Database Corruption:** Attacker with database write access corrupts the epoch 0 (genesis) `LedgerInfoWithSignatures` by replacing valid BLS signatures with invalid/forged ones
2. **Backup Creation:** `get_epoch_ending_ledger_info_iter()` reads the corrupted ledger info without verification and includes it in the backup
3. **Restore Initialization:** `EpochHistoryRestoreController` restores without trusted waypoints, calling `preheat_impl()` with `previous_li = None`
4. **Verification Bypass:** For epoch 0, no trusted waypoint exists, and `previous_li` is `None`, so lines 136-147 are skipped entirely
5. **Persistence:** The corrupted ledger info is saved via `save_ledger_infos()`: [6](#0-5) 

6. **Trust Anchor Compromise:** The corrupted epoch 0 becomes `epoch_endings[0]` in the `EpochHistory` used to verify all subsequent transactions
7. **Cascading Failure:** All future epoch verifications rely on the corrupted genesis, potentially accepting forged validator sets in `next_epoch_state`

**Invariant Violation:**

This breaks the **Cryptographic Correctness** invariant: "BLS signatures, VRF, and hash operations must be secure." The system accepts and persists `LedgerInfoWithSignatures` with unverified (potentially invalid) BLS signatures as the foundation of blockchain state.

## Impact Explanation

This vulnerability achieves **Critical Severity** under Aptos Bug Bounty criteria:

**Consensus/Safety Violation:** The corrupted genesis ledger info with invalid signatures becomes the trust anchor for the entire blockchain. This violates consensus safety by allowing an untrusted state to be accepted as canonical. Any subsequent validator set changes in the corrupted `next_epoch_state` could be forged.

**Non-Recoverable Network Partition:** Once a significant portion of the network restores from corrupted backups without trusted waypoints, nodes with valid genesis will reject blocks from nodes with corrupted genesis, causing a permanent network split requiring hardfork intervention.

**Blockchain Integrity Compromise:** The fundamental guarantee that all committed ledger infos have valid quorum signatures (2f+1 validators) is violated. This undermines the entire Byzantine fault tolerance model of AptosBFT.

## Likelihood Explanation

**Prerequisites:**
- Attacker has write access to a validator node's database (through system compromise, insider threat, or storage vulnerability)
- Restore operation performed without trusted waypoints configured
- Backup created from the compromised database

**Likelihood: Medium-High**

While database write access is a significant prerequisite, several factors increase likelihood:

1. **Operational Reality:** Many node operators may not configure trusted waypoints for routine backup/restore operations, especially during disaster recovery
2. **Storage Layer Attacks:** Database files are often stored with weaker access controls than consensus keys
3. **Supply Chain Risk:** Compromised backup storage systems could inject malicious backups
4. **Insider Threat:** Malicious node operators have direct database access

The lack of defense-in-depth verification in the backup path means a single point of compromise (database access) fully defeats the cryptographic security model.

## Recommendation

**Immediate Fix: Verify Signatures During Backup Creation**

Add signature verification in `get_latest_ledger_info_in_epoch()`:

```rust
pub(crate) fn get_latest_ledger_info_in_epoch(
    &self,
    epoch: u64,
) -> Result<LedgerInfoWithSignatures> {
    let ledger_info = self.db
        .get::<LedgerInfoSchema>(&epoch)?
        .ok_or_else(|| AptosDbError::NotFound(format!("Last LedgerInfo of epoch {epoch}")))?;
    
    // Verify signatures before returning
    if epoch > 0 {
        // Get validator set from previous epoch
        let prev_epoch_li = self.db
            .get::<LedgerInfoSchema>(&(epoch - 1))?
            .ok_or_else(|| AptosDbError::NotFound(format!("Previous epoch {} LedgerInfo", epoch - 1)))?;
        
        if let Some(next_epoch_state) = prev_epoch_li.ledger_info().next_epoch_state() {
            ledger_info.verify_signatures(&next_epoch_state.verifier)?;
        }
    }
    
    Ok(ledger_info)
}
```

**Additional Hardening:**

1. **Mandatory Trusted Waypoints:** Require at least one trusted waypoint for genesis epoch in restore operations
2. **Backup Integrity Checksums:** Sign entire backup manifests with operator keys
3. **Database Write Auditing:** Log all writes to `LedgerInfoSchema` with source verification
4. **Restore Validation Mode:** Add `--verify-signatures` flag that re-verifies all ledger info signatures during restore

**Long-term Defense:**

Implement a backup attestation system where backup creation includes a signed manifest of all included ledger infos with their signature verification status, allowing restore to detect corrupted backups.

## Proof of Concept

```rust
// Reproduction Steps (Conceptual - requires database manipulation):

// 1. Setup: Create a test database with genesis ledger info
let genesis_li = create_valid_genesis_ledger_info();
db.put::<LedgerInfoSchema>(&0, &genesis_li)?;

// 2. Corruption: Attacker corrupts epoch 0 with invalid signatures
let corrupted_li = genesis_li.clone();
// Replace valid signatures with invalid ones (requires access to LedgerInfoWithSignatures internals)
corrupted_li.signatures = BTreeMap::new(); // Empty signatures - clearly invalid
db.put::<LedgerInfoSchema>(&0, &corrupted_li)?;

// 3. Backup Creation: No verification happens
let backup_handler = BackupHandler::new(state_store, ledger_db);
let mut iter = backup_handler.get_epoch_ending_ledger_info_iter(0, 1)?;
let backed_up_li = iter.next().unwrap()?;
assert_eq!(backed_up_li.signatures.len(), 0); // Corrupted data in backup

// 4. Restore: Without trusted waypoints, corrupted LI is accepted
let restore_controller = EpochEndingRestoreController::new(
    opt,
    GlobalRestoreOptions {
        trusted_waypoints: Arc::new(HashMap::new()), // No trusted waypoints!
        // ... other options
    },
    storage,
);

// This will succeed without verifying signatures for epoch 0
let epoch_history = restore_controller.run(None).await?;

// 5. Verification: The corrupted genesis is now the trust anchor
assert_eq!(epoch_history.epoch_endings[0], corrupted_li.ledger_info());

// 6. Impact: All subsequent verifications use corrupted base
// Future transaction verifications will trust this corrupted genesis
```

**Actual PoC Implementation:**

To demonstrate this vulnerability in a real test environment:

1. Create a test backup with a deliberately corrupted epoch 0 ledger info (empty signature map)
2. Restore using `TransactionRestoreController::new(..., None /* epoch_history */, ...)`
3. Verify that the restore succeeds without error
4. Check database contains the corrupted ledger info
5. Attempt to verify a transaction against this ledger info - verification logic will use the corrupted trust anchor

This demonstrates that the backup/restore path lacks the cryptographic verification required for blockchain integrity.

---

**Notes:**

The vulnerability requires database write access as a prerequisite, but the absence of signature verification in the backup/restore path violates defense-in-depth principles. Even trusted backups should re-verify cryptographic signatures to detect corruption or malicious tampering. The restore path for epoch 0 without trusted waypoints is particularly vulnerable, as it becomes a single point of failure for the entire chain of trust.

### Citations

**File:** storage/aptosdb/src/ledger_db/ledger_metadata_db.rs (L113-120)
```rust
    pub(crate) fn get_latest_ledger_info_in_epoch(
        &self,
        epoch: u64,
    ) -> Result<LedgerInfoWithSignatures> {
        self.db
            .get::<LedgerInfoSchema>(&epoch)?
            .ok_or_else(|| AptosDbError::NotFound(format!("Last LedgerInfo of epoch {epoch}")))
    }
```

**File:** storage/aptosdb/src/backup/backup_handler.rs (L113-137)
```rust
    pub fn get_transaction_range_proof(
        &self,
        first_version: Version,
        last_version: Version,
    ) -> Result<(TransactionAccumulatorRangeProof, LedgerInfoWithSignatures)> {
        ensure!(
            last_version >= first_version,
            "Bad transaction range: [{}, {}]",
            first_version,
            last_version
        );
        let num_transactions = last_version - first_version + 1;
        let ledger_metadata_db = self.ledger_db.metadata_db();
        let epoch = ledger_metadata_db.get_epoch(last_version)?;
        let ledger_info = ledger_metadata_db.get_latest_ledger_info_in_epoch(epoch)?;
        let accumulator_proof = self
            .ledger_db
            .transaction_accumulator_db()
            .get_transaction_range_proof(
                Some(first_version),
                num_transactions,
                ledger_info.ledger_info().version(),
            )?;
        Ok((accumulator_proof, ledger_info))
    }
```

**File:** storage/aptosdb/src/backup/backup_handler.rs (L207-221)
```rust
    pub fn get_epoch_ending_ledger_info_iter(
        &self,
        start_epoch: u64,
        end_epoch: u64,
    ) -> Result<impl Iterator<Item = Result<LedgerInfoWithSignatures>> + '_> {
        Ok(self
            .ledger_db
            .metadata_db()
            .get_epoch_ending_ledger_info_iter(start_epoch, end_epoch)?
            .enumerate()
            .map(move |(idx, li)| {
                BACKUP_EPOCH_ENDING_EPOCH.set((start_epoch + idx as u64) as i64);
                li
            }))
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L540-600)
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
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L129-151)
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
                previous_li = ledger_infos.last();
                next_epoch += 1;
            }
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L247-249)
```rust
        match self.controller.run_mode.as_ref() {
            RestoreRunMode::Restore { restore_handler } => {
                restore_handler.save_ledger_infos(&preheat_data.ledger_infos)?;
```

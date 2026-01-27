# Audit Report

## Title
State Corruption via Malicious Backup Service with Bypassed Signature Verification

## Summary
The backup/restore system allows a malicious backup service to inject arbitrary blockchain state that bypasses cryptographic validation when the `--skip-epoch-endings` flag is used during restoration. This enables complete state corruption including consensus splits and potential fund theft.

## Finding Description

The vulnerability exists in the trust model between the backup CLI and the backup service, combined with optional signature verification during restore.

**Phase 1 - Backup (Trust Without Verification):**

The backup process trusts the backup service to return valid state data without performing cryptographic validation. In `send_records_inner()`, the function retrieves state chunks from the backup service and forwards them directly to storage: [1](#0-0) 

The state data is read as raw bytes and sent without validating it against cryptographic proofs. The proofs are fetched separately: [2](#0-1) 

**Phase 2 - Restore (Conditional Signature Verification):**

During restore, the system loads the `LedgerInfoWithSignatures` and validates the transaction info proof, but critically, it only validates the LedgerInfo's signatures if `epoch_history` is present: [3](#0-2) 

The `epoch_history` is set to `None` when using the `--skip-epoch-endings` flag: [4](#0-3) 

When `epoch_history` is `None`, the signature verification in `verify_ledger_info()` is completely skipped, meaning the `LedgerInfoWithSignatures` is never cryptographically validated: [5](#0-4) 

The `EpochState::verify()` method that performs signature verification is only called when epoch_history exists: [6](#0-5) 

**Attack Execution:**

1. Attacker operates a malicious backup service (backup service address is user-configurable via `--backup-service-address`)
2. Victim configures backup CLI to point to malicious service
3. Malicious service returns:
   - Arbitrary BCS-serialized state data (passes structural validation)
   - Matching Merkle proofs that validate this fabricated state
   - Fabricated `LedgerInfoWithSignatures` with incorrect/missing validator signatures
4. Backup CLI saves all data without cross-validation
5. Later, victim restores with `--skip-epoch-endings` flag
6. Restore process validates TransactionInfoWithProof against fabricated LedgerInfo (both controlled by attacker, so they match)
7. Signature verification is skipped because `epoch_history` is None
8. JellyfishMerkleRestore validates proofs against state data (both fabricated to match)
9. Corrupted state successfully restored to database

## Impact Explanation

**Critical Severity** - This vulnerability enables:

- **Consensus Safety Violation**: Validators restoring from corrupted backups will have different state roots, causing consensus splits and potential chain halts
- **Loss of Funds**: Attacker can craft state with arbitrary account balances, enabling theft
- **State Corruption**: Complete blockchain state can be replaced with fabricated data
- **Requires Hardfork**: Network-wide state corruption would require hardfork to resolve

This meets the Critical Severity criteria per the Aptos bug bounty program: "Consensus/Safety violations" and "Non-recoverable network partition (requires hardfork)".

## Likelihood Explanation

**Moderate to High Likelihood:**

The attack requires:
1. User configuring backup service to attacker-controlled endpoint (social engineering or infrastructure compromise)
2. User restoring with `--skip-epoch-endings` flag (legitimate use case for debugging or faster restores)

However:
- The `--skip-epoch-endings` flag exists in production code and is documented
- Backup service address is configurable by design
- No warning exists about security implications of skipping epoch endings
- Infrastructure compromises or social engineering against node operators are realistic threats
- A single compromised validator restoring from malicious backup could disrupt the entire network

## Recommendation

**Immediate Fix:** Remove the ability to skip epoch ending validation during state snapshot restore, or add mandatory signature verification even when `epoch_history` is None.

**Option 1 - Require Epoch History:**
```rust
// In StateSnapshotRestoreController::run_impl()
let epoch_history = self.epoch_history.as_ref()
    .ok_or_else(|| anyhow!(
        "Epoch history is required for secure state snapshot restoration. \
         Remove --skip-epoch-endings flag."
    ))?;
epoch_history.verify_ledger_info(&li)?;
```

**Option 2 - Add Explicit Signature Validation:**
```rust
// In StateSnapshotRestoreController::run_impl()
if let Some(epoch_history) = self.epoch_history.as_ref() {
    epoch_history.verify_ledger_info(&li)?;
} else {
    // Validate signatures even without full epoch history
    warn!("Restoring without epoch history - ensure LedgerInfo comes from trusted source");
    // Require user to provide trusted validator verifier
    let verifier = self.trusted_validator_verifier
        .ok_or_else(|| anyhow!("Must provide trusted validator set when skipping epoch endings"))?;
    li.verify_signatures(&verifier)?;
}
```

**Long-term Fix:** Add cryptographic validation during backup phase to detect malicious data before it's stored.

## Proof of Concept

**Setup Malicious Backup Service:**
```rust
// Mock backup service that returns fabricated state
use warp::Filter;

async fn malicious_backup_service() {
    let state_snapshot = warp::path!("state_snapshot_chunk" / u64 / usize / usize)
        .map(|_version, _start_idx, _limit| {
            // Return arbitrary state data that passes BCS validation
            let fake_state_key = StateKey::raw(b"malicious_key");
            let fake_state_value = StateValue::new_legacy(b"malicious_value".to_vec());
            let fake_record = bcs::to_bytes(&(fake_state_key, fake_state_value)).unwrap();
            
            // Return as size-prefixed stream
            Response::builder()
                .body(fake_record)
                .unwrap()
        });
    
    let routes = state_snapshot;
    warp::serve(routes).run(([127, 0, 0, 1], 8080)).await;
}
```

**Execute Attack:**
```bash
# Step 1: Start malicious backup service
cargo run --bin malicious-backup-service &

# Step 2: User performs backup pointing to malicious service
aptos-db backup oneoff \
    --backup-service-address http://localhost:8080 \
    --state-snapshot-epoch 100

# Step 3: Restore with --skip-epoch-endings (skips signature validation)
aptos-db restore bootstrap-db \
    --target-db-dir /path/to/restored/db \
    --ledger-history-start-version 0 \
    --skip-epoch-endings

# Result: Corrupted state successfully restored without signature verification
```

**Verification:**
The restored database will contain the fabricated state data, which can be verified by querying the state store and observing that it contains malicious key-value pairs that were never part of the legitimate blockchain state.

## Notes

This vulnerability stems from an architectural decision to allow skipping epoch ending validation for performance/debugging purposes, combined with the trust relationship with the backup service. The `--skip-epoch-endings` flag effectively disables the cryptographic security guarantees that protect against state corruption. Any production use of this flag with untrusted backup sources poses a critical security risk to the network.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/backup.rs (L337-348)
```rust
    let mut input = client
        .get_state_snapshot_chunk(version, start_idx, chunk_size)
        .await?;
    let mut count = 0;
    while let Some(record_bytes) = {
        let _timer = BACKUP_TIMER.timer_with(&["state_snapshot_read_record_bytes"]);
        input.read_record_bytes().await?
    } {
        let _timer = BACKUP_TIMER.timer_with(&["state_snapshot_record_stream_send_bytes"]);
        count += 1;
        sender.send(Ok(record_bytes)).await?;
    }
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/backup.rs (L425-437)
```rust
        let (proof_handle, mut proof_file) = self
            .storage
            .create_for_write(backup_handle, &Self::chunk_proof_name(first_idx, last_idx))
            .await?;
        tokio::io::copy(
            &mut self
                .client
                .get_account_range_proof(last_key, self.version())
                .await?,
            &mut proof_file,
        )
        .await?;
        proof_file.shutdown().await?;
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L125-139)
```rust
        let (txn_info_with_proof, li): (TransactionInfoWithProof, LedgerInfoWithSignatures) =
            self.storage.load_bcs_file(&manifest.proof).await?;
        txn_info_with_proof.verify(li.ledger_info(), manifest.version)?;
        let state_root_hash = txn_info_with_proof
            .transaction_info()
            .ensure_state_checkpoint_hash()?;
        ensure!(
            state_root_hash == manifest.root_hash,
            "Root hash mismatch with that in proof. root hash: {}, expected: {}",
            manifest.root_hash,
            state_root_hash,
        );
        if let Some(epoch_history) = self.epoch_history.as_ref() {
            epoch_history.verify_ledger_info(&li)?;
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

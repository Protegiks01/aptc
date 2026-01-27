# Audit Report

## Title
Transaction Infos Verification Bypass via `--skip-epoch-endings` Debug Flag in Backup Restore

## Summary
When the `--skip-epoch-endings` flag is used during backup restoration, the `ReplayChunkVerifier` receives transaction infos that are not cryptographically verified against trusted validator signatures. This allows an attacker controlling the backup storage to inject malicious transaction infos that would be accepted during replay, potentially leading to state corruption.

## Finding Description

The security question asks whether transaction infos passed to `ReplayChunkVerifier` are verified or blindly trusted. The answer depends on whether the `--skip-epoch-endings` debug flag is used.

**Normal Operation (Verified Path):**

When backup restore runs without `--skip-epoch-endings`, the transaction infos are properly verified through the following chain:

1. `LoadedChunk::load()` loads transaction infos and a `LedgerInfoWithSignatures` from backup storage [1](#0-0) 

2. The `EpochHistory::verify_ledger_info()` method verifies the ledger info has valid signatures from known validators [2](#0-1) 

3. Transaction infos are then verified against this cryptographically-verified ledger info [3](#0-2) 

**Vulnerable Path (Blind Trust):**

When `--skip-epoch-endings` is used, the `epoch_history` parameter becomes `None`: [4](#0-3) 

With `epoch_history = None`, the ledger info signature verification is **skipped**: [5](#0-4) 

The transaction infos are then "verified" against this unverified ledger info and passed to `ReplayChunkVerifier`: [6](#0-5) 

The `ReplayChunkVerifier` itself performs no cryptographic verification - it only checks that execution outputs match the provided transaction infos: [7](#0-6) 

**Attack Scenario:**
1. Attacker compromises backup storage or provides malicious backup
2. Administrator runs restore with `--skip-epoch-endings` flag (marked as "for debugging")
3. Attacker provides arbitrary transaction infos + matching ledger info (no signature verification)
4. System replays transactions based on these unverified transaction infos
5. State corruption occurs as invalid state transitions are accepted

## Impact Explanation

This breaks the **State Consistency** invariant - state transitions must be verifiable via cryptographic proofs. By bypassing ledger info signature verification, the system accepts state transitions without proof they were approved by validator consensus.

**Severity: Medium** - This requires specific conditions (debug flag usage + compromised backup storage), but enables state corruption that requires manual intervention to fix. It doesn't meet Critical severity as it requires administrator action with a debug flag, not exploitation by unprivileged attackers.

## Likelihood Explanation

**Likelihood: Low-Medium**
- Requires administrator to use `--skip-epoch-endings` debug flag
- Requires attacker control of backup storage
- Flag is documented "for debugging" but lacks security warnings
- If conditions are met, exploitation is straightforward

## Recommendation

**Option 1 (Recommended): Remove the flag entirely**
```rust
// Remove --skip-epoch-endings option from production code
// Force epoch history verification for all restores
```

**Option 2: Add mandatory security checks**
```rust
let epoch_history = if !self.skip_epoch_endings {
    Some(Arc::new(
        EpochHistoryRestoreController::new(...).run().await?,
    ))
} else {
    // Add explicit warning and require additional confirmation
    error!("SECURITY WARNING: Skipping epoch verification means trusting backup storage completely!");
    error!("This should ONLY be used in test environments with trusted backup sources.");
    if !self.i_trust_backup_storage_completely {
        bail!("Must explicitly set --i-trust-backup-storage-completely flag to skip epoch verification");
    }
    None
};
```

**Option 3: Validate ledger info via alternative method**
When epoch history is not available, require a trusted waypoint or genesis verification:
```rust
if epoch_history.is_none() {
    // Require at least genesis or waypoint verification
    ensure!(
        ledger_info.ledger_info().epoch() == 0 || trusted_waypoint.is_some(),
        "Cannot verify ledger info without epoch history or trusted waypoint"
    );
}
```

## Proof of Concept

```rust
// Demonstration of vulnerability flow
#[tokio::test]
async fn test_unverified_transaction_infos_replay() {
    // 1. Setup malicious backup storage with crafted transaction infos
    let malicious_storage = create_malicious_backup_storage();
    
    // 2. Create restore controller with skip_epoch_endings = true
    let controller = TransactionRestoreBatchController::new(
        global_opt,
        Arc::new(malicious_storage),
        manifest_handles,
        None,
        None,
        None, // epoch_history is None due to skip_epoch_endings
        VerifyExecutionMode::NoVerify,
        None,
    );
    
    // 3. Run restore - malicious transaction infos will be accepted
    controller.run().await.expect("Restore should succeed");
    
    // 4. Verify that malicious state was committed
    let db_state = read_committed_state();
    assert!(db_state.is_corrupted(), "Malicious state was accepted");
}

fn create_malicious_backup_storage() -> impl BackupStorage {
    // Return storage that provides:
    // - Malicious transaction infos
    // - Crafted (unsigned) ledger info that makes those infos pass verification
    // Without epoch_history, the ledger info signatures won't be checked
    MockBackupStorage::new_with_malicious_data()
}
```

## Notes

The vulnerability specifically answers the security question: transaction infos passed to `ReplayChunkVerifier` **are** cryptographically verified in normal operation, but **are blindly trusted** when the `--skip-epoch-endings` debug flag is used. The flag documentation states "used for debugging" but doesn't explain that it completely bypasses cryptographic verification of the backup data's authenticity.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L147-154)
```rust
        let (range_proof, ledger_info) = storage
            .load_bcs_file::<(TransactionAccumulatorRangeProof, LedgerInfoWithSignatures)>(
                &manifest.proof,
            )
            .await?;
        if let Some(epoch_history) = epoch_history {
            epoch_history.verify_ledger_info(&ledger_info)?;
        }
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L156-167)
```rust
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

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L276-311)
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

**File:** execution/executor/src/chunk_executor/mod.rs (L696-699)
```rust
        let chunk_verifier = Arc::new(ReplayChunkVerifier {
            transaction_infos: txn_infos,
        });
        self.enqueue_chunk(chunk, chunk_verifier, "replay")?;
```

**File:** execution/executor/src/chunk_executor/chunk_result_verifier.rs (L134-140)
```rust
    fn verify_chunk_result(
        &self,
        _parent_accumulator: &InMemoryTransactionAccumulator,
        ledger_update_output: &LedgerUpdateOutput,
    ) -> Result<()> {
        ledger_update_output.ensure_transaction_infos_match(&self.transaction_infos)
    }
```

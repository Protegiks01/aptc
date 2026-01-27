# Audit Report

## Title
Event Forgery in Backup Restoration with Disabled Epoch Verification

## Summary
When restoring transaction backups with the `--skip-epoch-endings` flag, the backup restoration process bypasses cryptographic signature verification of `LedgerInfoWithSignatures`, allowing attackers with write access to backup storage to inject arbitrary forged events that will corrupt off-chain indexing systems.

## Finding Description

The Aptos backup restoration system is designed to cryptographically verify the authenticity of backup data through validator signatures in `LedgerInfoWithSignatures`. However, when the `--skip-epoch-endings` command-line flag is used during restoration, this critical verification is bypassed.

**Vulnerability Location:**

The vulnerability exists in the `LoadedChunk::load()` method where epoch history verification is conditionally skipped: [1](#0-0) 

When `epoch_history` is `None` (which occurs when `skip_epoch_endings` is set), the `verify_ledger_info()` call is skipped, meaning the validator signatures in the `LedgerInfoWithSignatures` are never verified.

The `epoch_history` is set to `None` when the debugging flag is enabled: [2](#0-1) 

**How Normal Verification Works:**

When epoch history is present, signatures are properly verified: [3](#0-2) 

**Why Subsequent Verification is Insufficient:**

The subsequent `TransactionListWithProof::verify()` call only validates Merkle proofs, not signatures: [4](#0-3) 

This verification only checks that the transaction infos hash to values proven by the accumulator proof, but doesn't verify the `LedgerInfo` itself is signed by validators.

**Attack Path:**

1. **Attacker compromises backup storage** (e.g., gains write access to S3/GCS bucket)
2. **Attacker crafts malicious backup chunk** containing:
   - Arbitrary forged `ContractEvent` objects (e.g., fake coin transfer events)
   - `TransactionInfo` objects with `event_root_hash` values computed from the forged events
   - A valid `TransactionAccumulatorRangeProof` (purely mathematical structure)
   - A `LedgerInfoWithSignatures` with matching `transaction_accumulator_hash` but invalid/missing validator signatures
3. **Operator restores backup with `--skip-epoch-endings`** flag (believing it's just for debugging)
4. **Forged events pass verification** because:
   - Events match the `event_root_hash` in `TransactionInfo` (attacker made them match)
   - `TransactionInfo` hashes match the accumulator proof (attacker crafted consistent proof)
   - Accumulator root matches `LedgerInfo` (attacker crafted matching structure)
   - Signature verification is skipped (due to flag)
5. **Forged events are saved to database**: [5](#0-4) 

6. **Off-chain systems read forged events** from the restored database, corrupting their indexes, analytics, and user interfaces

## Impact Explanation

**Severity: High**

This vulnerability meets the **High Severity** criteria from the Aptos bug bounty program:
- **Significant protocol violation**: Bypasses cryptographic verification that is fundamental to blockchain data integrity
- **Corruption of dependent systems**: Off-chain indexers, blockchain explorers, DEX frontends, and analytics platforms that rely on event data will process and display false information

**Specific Impacts:**
- **Data Integrity Violation**: Breaks the cryptographic chain of trust that ensures all blockchain data is validator-signed
- **Off-Chain System Corruption**: Applications indexing events (transfers, NFT mints, DEX swaps, etc.) will contain false data
- **User Harm**: Users relying on explorers/indexers will see incorrect balances, transaction histories, and state
- **Trust Degradation**: Once discovered, undermines confidence in backup restoration procedures

While this doesn't directly affect on-chain consensus or steal funds, it violates the fundamental invariant that all committed blockchain data must be cryptographically authenticated by validators.

## Likelihood Explanation

**Likelihood: Medium-Low** but with serious consequences when it occurs.

**Required Conditions:**
1. **Compromised backup storage** (Medium difficulty) - Requires attacker to gain write access to the backup storage system (S3, GCS, etc.)
2. **Operator using debugging flag** (Low-Medium probability) - The `--skip-epoch-endings` flag is documented as "used for debugging" but:
   - Flag name doesn't clearly indicate it bypasses cryptographic security
   - No prominent security warning about signature verification bypass
   - Operators may use it for performance reasons without understanding implications
   - May be used in disaster recovery scenarios where speed is prioritized

**Mitigating Factors:**
- Requires both compromised storage AND operator error
- Production deployments should have secured backup storage

**Aggravating Factors:**
- Defense-in-depth failure: even with compromised storage, crypto should catch tampering
- Silent failure: no warning that security checks are disabled
- Persistent impact: once fake events are in DB, they appear legitimate

## Recommendation

**Immediate Fix:**

1. **Remove the ability to skip signature verification entirely**, or at minimum:
   - Require an explicit `--allow-unverified-backups` flag with prominent security warning
   - Log critical security warnings when verification is disabled
   - Prevent production use of unverified restores

2. **Add mandatory signature verification** even when `epoch_history` is `None`:

```rust
// In LoadedChunk::load(), replace lines 152-154 with:
let (range_proof, ledger_info) = storage
    .load_bcs_file::<(TransactionAccumulatorRangeProof, LedgerInfoWithSignatures)>(
        &manifest.proof,
    )
    .await?;

// Always verify ledger info if epoch_history is available
if let Some(epoch_history) = epoch_history {
    epoch_history.verify_ledger_info(&ledger_info)?;
} else {
    // If epoch_history is None, we cannot verify signatures
    // This should only be allowed in non-production environments
    if !allow_unverified_restore {
        bail!(
            "Cannot verify LedgerInfo signatures without epoch history. \
             Refusing to restore potentially forged data. \
             Use --allow-unverified-backups flag ONLY in test environments."
        );
    }
    warn!(
        "SECURITY WARNING: Restoring backup without signature verification. \
         This backup could contain forged data. \
         Only use in isolated test environments."
    );
}
```

3. **Update CLI documentation** to clearly warn about security implications:

```rust
#[clap(
    long, 
    help = "DANGEROUS: Skip epoch ending verification. This disables cryptographic \
            signature verification and allows forged data to be restored. \
            NEVER use in production. Only for isolated test environments."
)]
skip_epoch_endings: bool,
```

4. **Add backup file signing** as an additional layer of defense-in-depth:
   - Sign backup manifests with a separate key
   - Verify manifest signatures before restoration
   - Independent from LedgerInfo signatures

## Proof of Concept

```rust
// Test demonstrating the vulnerability
// File: storage/backup/backup-cli/src/backup_types/transaction/restore_test.rs

#[tokio::test]
async fn test_forged_events_accepted_without_epoch_history() {
    use aptos_types::{
        contract_event::ContractEvent,
        transaction::{Transaction, TransactionInfo, Version},
        ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
        proof::TransactionAccumulatorRangeProof,
        event::EventKey,
    };
    use aptos_crypto::hash::CryptoHash;
    use aptos_accumulator::InMemoryEventAccumulator;
    
    // Step 1: Create forged events
    let forged_event = ContractEvent::new(
        EventKey::random(),
        0,
        aptos_types::account_address::AccountAddress::random(),
        bcs::to_bytes(&"FORGED_TRANSFER_EVENT").unwrap(),
    );
    let forged_events = vec![forged_event];
    
    // Step 2: Compute event_root_hash from forged events
    let event_hashes: Vec<_> = forged_events.iter().map(CryptoHash::hash).collect();
    let forged_event_root = InMemoryEventAccumulator::from_leaves(&event_hashes).root_hash();
    
    // Step 3: Create TransactionInfo with forged event_root_hash
    let forged_txn_info = TransactionInfo::new(
        HashValue::random(),      // transaction_hash
        HashValue::random(),      // state_change_hash  
        forged_event_root,        // event_root_hash - matches our forged events!
        None,                     // state_checkpoint_hash
        100,                      // gas_used
        ExecutionStatus::Success,
        None,                     // auxiliary_info_hash
    );
    
    // Step 4: Create fake LedgerInfo (without valid signatures)
    let fake_ledger_info = LedgerInfoWithSignatures::new(
        LedgerInfo::new(/* ... parameters without valid validator signatures */),
        BTreeMap::new(), // Empty signatures!
    );
    
    // Step 5: Create valid-looking Merkle proof
    let fake_proof = TransactionAccumulatorRangeProof::new(/* ... */);
    
    // Step 6: Save to backup file (attacker controls backup storage)
    // ... code to write forged data to backup chunk ...
    
    // Step 7: Restore WITHOUT epoch_history (skip_epoch_endings = true)
    let loaded_chunk = LoadedChunk::load(
        manifest_chunk,
        &storage,
        None, // epoch_history is None - signature verification skipped!
    ).await.unwrap();
    
    // Step 8: Verify passes because only Merkle proofs are checked
    // Forged events are now in the loaded chunk and will be saved to DB!
    assert_eq!(loaded_chunk.event_vecs[0], forged_events);
    
    // Step 9: When saved to DB, off-chain indexers will read these forged events
    // and corrupt their data
}

#[tokio::test]
async fn test_forged_events_rejected_with_epoch_history() {
    // Same setup as above, but with epoch_history provided
    
    let epoch_history = Arc::new(EpochHistory { /* ... with real validator set */ });
    
    // This should FAIL because signatures in fake_ledger_info are invalid
    let result = LoadedChunk::load(
        manifest_chunk,
        &storage,
        Some(&epoch_history), // Signature verification enabled
    ).await;
    
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("signature"));
}
```

**Notes:**

This vulnerability demonstrates a critical defense-in-depth failure. While the `--skip-epoch-endings` flag is intended for debugging, its name and documentation do not adequately convey that it completely bypasses cryptographic signature verification. An operator performing disaster recovery might use this flag for performance without realizing it allows forged data to be restored. The impact is significant: off-chain systems that index blockchain events (explorers, analytics, DEX frontends) will be corrupted with false data, potentially affecting user decisions and application functionality.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L152-154)
```rust
        if let Some(epoch_history) = epoch_history {
            epoch_history.verify_ledger_info(&ledger_info)?;
        }
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L507-517)
```rust
                        tokio::task::spawn_blocking(move || {
                            restore_handler.save_transactions(
                                first_version,
                                &txns_to_save,
                                &persisted_aux_info_to_save,
                                &txn_infos_to_save,
                                &event_vecs_to_save,
                                write_sets_to_save,
                            )
                        })
                        .await??;
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

**File:** types/src/proof/definition.rs (L910-925)
```rust
    pub fn verify(
        &self,
        ledger_info: &LedgerInfo,
        first_transaction_info_version: Option<Version>,
    ) -> Result<()> {
        let txn_info_hashes: Vec<_> = self
            .transaction_infos
            .iter()
            .map(CryptoHash::hash)
            .collect();
        self.ledger_info_to_transaction_infos_proof.verify(
            ledger_info.transaction_accumulator_hash(),
            first_transaction_info_version,
            &txn_info_hashes,
        )
    }
```

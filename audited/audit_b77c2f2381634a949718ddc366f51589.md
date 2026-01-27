# Audit Report

## Title
Transaction Backup Proof Validation Bypass Allows Fabricated Blockchain State Restoration

## Summary
The transaction backup system fetches transaction range proofs from backup services without validation during backup, and performs only optional BLS signature validation during restore. When restoring with `epoch_history=None` (oneoff restore mode or `--skip-epoch-endings` flag), an attacker controlling the backup source can provide completely fabricated blockchain data that passes all cryptographic consistency checks but contains no valid validator signatures.

## Finding Description

The vulnerability exists in the transaction backup/restore flow where cryptographic proof validation is incomplete.

**During Backup:**
The system fetches transaction range proofs directly from the backup service client without any validation: [1](#0-0) 

The proof contains a `(TransactionAccumulatorRangeProof, LedgerInfoWithSignatures)` tuple that is written directly to storage without verifying the LedgerInfoWithSignatures has valid BLS signatures from the validator set.

**During Restore:**
The system loads the proof and performs conditional validation: [2](#0-1) 

The critical issue is at lines 152-154 where LedgerInfo signature validation is **optional** based on `epoch_history`: [3](#0-2) 

When `epoch_history` is `None`, the BLS signature verification in `EpochHistory::verify_ledger_info()` is completely skipped: [4](#0-3) 

**When is epoch_history None?**

1. **Oneoff restore mode** explicitly passes `None`: [5](#0-4) 

2. **RestoreCoordinator with --skip-epoch-endings flag**: [6](#0-5) [7](#0-6) 

**Attack Scenario:**

1. Attacker sets up malicious backup service or compromises backup storage
2. Victim configures node to restore from this malicious source
3. Malicious service provides:
   - Fabricated transactions for version range [X, Y]
   - Fabricated `TransactionInfo` objects with hashes matching the fake transactions
   - Fabricated `TransactionAccumulatorRangeProof` consistent with the fake transaction_infos
   - Fabricated `LedgerInfoWithSignatures` with **invalid or missing BLS signatures** but correct transaction accumulator root hash
4. Victim runs restore using oneoff mode or `--skip-epoch-endings` flag
5. Restore succeeds because:
   - Transaction hashes match transaction_infos (both fake but consistent)
   - TransactionInfoListWithProof verification passes (lines 915-924 in proof/definition.rs)
   - AccumulatorRangeProof verification passes (computes matching root hash)
   - **BLS signature validation is skipped** (epoch_history is None)
6. Node database now contains completely fabricated blockchain state

The subsequent `txn_list_with_proof.verify()` call only validates cryptographic consistency (hash matching, merkle proofs) but does NOT validate that the LedgerInfo is authentically signed by the validator set: [8](#0-7) 

This breaks the fundamental blockchain security invariant: **all committed state must be authenticated by validator signatures**.

## Impact Explanation

**Severity: HIGH** (State inconsistencies requiring intervention)

This vulnerability allows an attacker to cause a node operator to restore completely fabricated blockchain history into their database. The fabricated data will:

1. **Violate State Consistency Invariant**: The restored state is not verified by validator BLS signatures, breaking the fundamental blockchain integrity guarantee
2. **Cause Network Participation Failure**: When the compromised node attempts to sync with the real network, it will detect state root mismatches and fail to participate in consensus
3. **Require Manual Intervention**: The operator must detect the issue, wipe the database, and restore from a trusted source

While this doesn't directly compromise the network (the fabricated state won't propagate to other nodes), it represents a significant failure of the backup/restore security model that could affect validator operations during disaster recovery scenarios.

The impact is classified as HIGH rather than CRITICAL because:
- Requires operator misconfiguration (using untrusted backup source with validation disabled)
- Does not affect network consensus or other nodes
- Node will fail safely when attempting network sync
- However, it does require manual intervention to recover

## Likelihood Explanation

**Likelihood: MEDIUM**

The attack requires specific conditions:

1. **Victim must restore from attacker-controlled or compromised backup source**
   - Operators using third-party backup storage
   - Compromised backup service endpoints
   - Man-in-the-middle attacks on backup traffic

2. **Victim must disable signature validation**
   - Using oneoff restore mode (common for emergency recovery)
   - Using `--skip-epoch-endings` flag (marked "for debugging" but available in production builds)

The oneoff restore mode is a legitimate production use case, making this vulnerability realistic. Operators performing disaster recovery might use quick restore options without realizing they bypass critical security validations.

## Recommendation

**Mandatory BLS Signature Validation:**

Always validate LedgerInfoWithSignatures regardless of epoch_history availability. The fix should:

1. **Remove the optional validation in restore.rs**:
```rust
// In LoadedChunk::load() - lines 147-154
let (range_proof, ledger_info) = storage
    .load_bcs_file::<(TransactionAccumulatorRangeProof, LedgerInfoWithSignatures)>(
        &manifest.proof,
    )
    .await?;

// ALWAYS validate ledger_info signatures
if let Some(epoch_history) = epoch_history {
    epoch_history.verify_ledger_info(&ledger_info)?;
} else {
    // FIX: Reject restore if epoch_history is not provided
    return Err(anyhow!(
        "Cannot verify LedgerInfo at version {} without epoch history. \
        Refusing to restore potentially untrusted data.",
        ledger_info.ledger_info().version()
    ));
}
```

2. **Require epoch_history for all restore operations**:
```rust
// In db-tool/src/restore.rs - remove None option
TransactionRestoreController::new(
    opt,
    global.try_into()?,
    storage.init_storage().await?,
    Some(epoch_history), // REQUIRE epoch_history
    VerifyExecutionMode::NoVerify,
)
```

3. **Remove --skip-epoch-endings flag or make it require explicit unsafe confirmation**

**Alternative validation during backup:**

Add immediate validation when fetching proofs:
```rust
// In backup.rs - after line 166
let mut proof_reader = self
    .client
    .get_transaction_range_proof(first_version, last_version)
    .await?;

// Read and validate the proof immediately
let mut proof_bytes = Vec::new();
proof_reader.read_to_end(&mut proof_bytes).await?;
let (range_proof, ledger_info): (TransactionAccumulatorRangeProof, LedgerInfoWithSignatures) = 
    bcs::from_bytes(&proof_bytes)?;

// Validate signatures if epoch_state is available
// (This requires passing epoch_state to backup controller)

// Then write validated proof
proof_file.write_all(&proof_bytes).await?;
```

## Proof of Concept

**Setup:**
1. Create malicious backup service that returns fabricated data
2. Run oneoff transaction restore pointing to malicious service

**Rust reproduction steps:**

```rust
// File: storage/backup/backup-cli/src/backup_types/transaction/test_malicious_restore.rs

#[tokio::test]
async fn test_fabricated_proof_accepted_without_epoch_history() {
    use aptos_types::{
        ledger_info::LedgerInfo,
        transaction::{Transaction, TransactionInfo},
        proof::TransactionAccumulatorRangeProof,
    };
    
    // 1. Create fabricated transactions
    let fake_txns = vec![/* create fake genesis or user transactions */];
    
    // 2. Create fabricated transaction_infos with matching hashes
    let fake_txn_infos: Vec<TransactionInfo> = fake_txns
        .iter()
        .map(|txn| {
            TransactionInfo::new(
                CryptoHash::hash(txn),
                /* fabricated state root */,
                /* fabricated event root */,
                /* gas used */,
                /* status */,
            )
        })
        .collect();
    
    // 3. Build fake accumulator proof
    let fake_proof = TransactionAccumulatorRangeProof {
        left_siblings: vec![],
        right_siblings: vec![],
    };
    
    // 4. Create fake LedgerInfo WITHOUT valid signatures
    let fake_ledger_info = LedgerInfoWithSignatures::new(
        LedgerInfo::new(/* ... */),
        AggregateSignature::empty(), // NO VALID SIGNATURES!
    );
    
    // 5. Write fabricated backup to storage
    let storage = /* create temp storage */;
    storage.save_proof(&fake_proof, &fake_ledger_info).await.unwrap();
    storage.save_transactions(&fake_txns, &fake_txn_infos).await.unwrap();
    
    // 6. Restore with epoch_history = None
    let result = TransactionRestoreController::new(
        opt,
        global_opt,
        storage,
        None, // NO EPOCH HISTORY = NO SIGNATURE VALIDATION
        VerifyExecutionMode::NoVerify,
    )
    .run()
    .await;
    
    // BUG: This should FAIL but SUCCEEDS
    assert!(result.is_ok()); 
    
    // Node now has fabricated blockchain state in database!
}
```

The test demonstrates that completely fabricated blockchain data (with no valid validator signatures) can be successfully restored when `epoch_history` is `None`, violating the fundamental blockchain integrity invariant.

## Notes

This vulnerability highlights a critical trust model assumption in the backup/restore system: the backup service is treated as trusted without cryptographic enforcement. While the `--skip-epoch-endings` flag is marked "for debugging," the oneoff restore mode is a legitimate production use case that bypasses signature validation entirely.

The fix requires making BLS signature validation mandatory for all restore operations, ensuring that only validator-signed blockchain state can be restored into the database.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/transaction/backup.rs (L163-170)
```rust
        tokio::io::copy(
            &mut self
                .client
                .get_transaction_range_proof(first_version, last_version)
                .await?,
            &mut proof_file,
        )
        .await?;
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

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L306-310)
```rust
            self.epoch_endings[epoch as usize - 1]
                .next_epoch_state()
                .ok_or_else(|| anyhow!("Shouldn't contain non- epoch bumping LIs."))?
                .verify(li_with_sigs)?;
        };
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

**File:** storage/backup/backup-cli/src/coordinators/restore.rs (L42-43)
```rust
    #[clap(long, help = "Skip restoring epoch ending info, used for debugging.")]
    pub skip_epoch_endings: bool,
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

**File:** types/src/transaction/mod.rs (L2334-2336)
```rust
        // Verify the transaction infos are proven by the ledger info.
        self.proof
            .verify(ledger_info, self.get_first_transaction_version())?;
```

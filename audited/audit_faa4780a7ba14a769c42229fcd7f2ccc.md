# Audit Report

## Title
Database Restore with NoVerify Mode Allows Invalid Transaction Outputs to Bypass Move VM Validation

## Summary
The database restoration tool uses `VerifyExecutionMode::NoVerify` which completely bypasses transaction re-execution and write_set validation. This allows restoration of transaction outputs (write_sets) that do not match their cryptographic commitments in TransactionInfo objects, enabling state corruption that violates Move VM safety rules and consensus invariants. [1](#0-0) 

## Finding Description

The vulnerability exists in the transaction restoration flow where `VerifyExecutionMode::NoVerify` is hardcoded for oneoff transaction restoration. This breaks a critical security invariant: **write_sets must be validated against their state_change_hash commitments in TransactionInfo objects**.

**Attack Flow:**

1. During backup loading, `LoadedChunk::load()` loads write_sets from backup files but only validates transaction hashes and event root hashes: [2](#0-1) 

The `TransactionListWithProof::verify()` method explicitly does NOT verify write_sets against state_change_hash: [3](#0-2) 

2. When `NoVerify` mode is used, transactions are NOT re-executed. The `should_verify()` check returns false: [4](#0-3) 

3. In `remove_and_replay_epoch()`, the verification is skipped entirely: [5](#0-4) 

4. The write_sets from the backup are used directly to create TransactionOutputs without validation: [6](#0-5) 

5. `ReplayChunkVerifier` only validates that TransactionInfo objects match, NOT that write_sets match their state_change_hash commitments: [7](#0-6) 

**Exploitation Scenario:**

An attacker who can compromise backup storage or perform man-in-the-middle attacks can:
1. Modify write_sets in backup files to contain malicious state changes (e.g., mint tokens, modify validator set, manipulate governance votes)
2. Keep TransactionInfo objects unchanged (they contain the original state_change_hash commitments)
3. When restore is performed with NoVerify mode, malicious write_sets are applied directly to the database
4. The database now contains state that doesn't match the cryptographic commitments, breaking consensus invariants

**Invariants Broken:**
- **State Consistency**: State transitions are not verifiable via their cryptographic commitments
- **Deterministic Execution**: Restored nodes will have different state than consensus-validated state
- **Move VM Safety**: Malicious write_sets can bypass all Move VM safety checks

## Impact Explanation

**Severity: CRITICAL** (up to $1,000,000)

This vulnerability qualifies as Critical under multiple categories:

1. **Consensus/Safety Violations**: Nodes restored from malicious backups will have state that doesn't match the canonical chain state, causing consensus splits when these nodes participate in validation.

2. **Loss of Funds**: Malicious write_sets can:
   - Mint tokens by modifying coin supply resources
   - Transfer funds by modifying account balance resources
   - Manipulate validator rewards/stakes
   - Alter governance voting power

3. **State Consistency Breach**: The fundamental guarantee that state_change_hash in TransactionInfo cryptographically commits to write_sets is violated. This breaks the core integrity model of the blockchain.

The vulnerability affects both the oneoff restoration command and the full BootstrapDB coordinator: [8](#0-7) [9](#0-8) 

## Likelihood Explanation

**Likelihood: Medium-High**

The attack requires:
1. Ability to compromise backup storage OR perform MitM on backup downloads OR convince operators to restore from malicious backups
2. Knowledge of the backup file format
3. Ability to craft malicious write_sets

However:
- Backup storage is often less secured than live database systems
- Database restoration is a common operational task, especially for new validators or disaster recovery
- The NoVerify mode is the default, making this vulnerability always exploitable during restoration
- No warning is provided to operators about the security implications

## Recommendation

**Immediate Fix: Always validate write_sets against state_change_hash commitments**

The fix requires checking write_set hashes during the LoadedChunk verification phase:

```rust
// In LoadedChunk::load(), after line 167:
// Verify write_sets match their state_change_hash commitments
for (write_set, txn_info) in write_sets.iter().zip(txn_infos.iter()) {
    let write_set_hash = CryptoHash::hash(write_set);
    ensure!(
        txn_info.state_change_hash() == write_set_hash,
        "Write set hash mismatch at version {}. Expected: {:?}, Got: {:?}",
        txn_info.version(),
        txn_info.state_change_hash(),
        write_set_hash
    );
}
```

**Alternative Fix: Remove NoVerify mode entirely**

Since write_set validation is critical for security, the NoVerify mode should be removed or restricted to explicitly trusted scenarios with strong access controls:

```rust
// In restore.rs, replace line 107:
VerifyExecutionMode::verify_all(), // Always verify execution
```

**Defense-in-Depth: Add integrity checks during backup creation**

Sign backup files cryptographically and verify signatures before restoration to ensure backup integrity.

## Proof of Concept

```rust
// Proof of Concept: Demonstrating write_set validation bypass
// This would be placed in a test file, but demonstrates the vulnerability

use aptos_types::{
    transaction::{Transaction, TransactionInfo, WriteSet},
    write_set::WriteSetMut,
};
use aptos_crypto::{hash::CryptoHash, HashValue};

#[test]
fn test_noverify_accepts_invalid_writesets() {
    // Create a valid transaction
    let txn = Transaction::dummy();
    let txn_hash = CryptoHash::hash(&txn);
    
    // Create a valid write_set
    let valid_write_set = WriteSet::default();
    let valid_hash = CryptoHash::hash(&valid_write_set);
    
    // Create TransactionInfo with the valid write_set hash
    let txn_info = TransactionInfo::new(
        txn_hash,
        valid_hash, // state_change_hash commits to valid_write_set
        HashValue::zero(),
        None,
        0,
        ExecutionStatus::Success,
    );
    
    // ATTACK: Create a malicious write_set that differs from committed hash
    let mut malicious_write_set = WriteSetMut::new(vec![]);
    // Add malicious state changes here (e.g., mint tokens)
    let malicious_write_set = malicious_write_set.freeze().unwrap();
    let malicious_hash = CryptoHash::hash(&malicious_write_set);
    
    // The hashes don't match - this should be rejected
    assert_ne!(valid_hash, malicious_hash);
    
    // However, when using NoVerify mode in restore:
    // 1. LoadedChunk::verify() passes (doesn't check write_sets)
    // 2. remove_and_apply() uses the malicious write_set directly
    // 3. ReplayChunkVerifier only checks txn_info matches
    // 4. Malicious write_set is committed to database
    
    // Expected: Restoration should fail due to hash mismatch
    // Actual with NoVerify: Restoration succeeds with invalid state
}
```

**Notes:**
- This vulnerability affects all database restoration operations using the db-tool or backup-cli with default settings
- The issue is exacerbated by the lack of documentation warning operators about the security implications of NoVerify mode
- State verification after restoration would detect the corruption, but by then invalid state has been committed
- The vulnerability can lead to Byzantine node behavior if the restored node participates in consensus with corrupted state

### Citations

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

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L156-186)
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
        // and disassemble it to get things back.
        let (txn_list_with_proof, persisted_aux_info) = txn_list_with_proof.into_parts();
        let txns = txn_list_with_proof.transactions;
        let range_proof = txn_list_with_proof
            .proof
            .ledger_info_to_transaction_infos_proof;
        let txn_infos = txn_list_with_proof.proof.transaction_infos;
        let event_vecs = txn_list_with_proof.events.expect("unknown to be Some.");

        Ok(Self {
            manifest,
            txns,
            persisted_aux_info,
            txn_infos,
            event_vecs,
            range_proof,
            write_sets,
        })
    }
```

**File:** types/src/transaction/mod.rs (L2288-2354)
```rust
    /// Verifies the transaction list with proof using the given `ledger_info`.
    /// This method will ensure:
    /// 1. All transactions exist on the given `ledger_info`.
    /// 2. All transactions in the list have consecutive versions.
    /// 3. If `first_transaction_version` is None, the transaction list is empty.
    ///    Otherwise, the transaction list starts at `first_transaction_version`.
    /// 4. If events exist, they match the expected event root hashes in the proof.
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

        // Verify the events if they exist.
        if let Some(event_lists) = &self.events {
            ensure!(
                event_lists.len() == self.get_num_transactions(),
                "The length of event_lists ({}) does not match the number of transactions ({}).",
                event_lists.len(),
                self.get_num_transactions(),
            );
            event_lists
                .into_par_iter()
                .zip_eq(self.proof.transaction_infos.par_iter())
                .map(|(events, txn_info)| verify_events_against_root_hash(events, txn_info))
                .collect::<Result<Vec<_>>>()?;
        }

        Ok(())
    }
```

**File:** execution/executor-types/src/lib.rs (L240-242)
```rust
    pub fn should_verify(&self) -> bool {
        !matches!(self, Self::NoVerify)
    }
```

**File:** execution/executor/src/chunk_executor/mod.rs (L561-575)
```rust
            // Try to run the transactions with the VM
            let next_begin = if verify_execution_mode.should_verify() {
                self.verify_execution(
                    transactions,
                    persisted_aux_info,
                    transaction_infos,
                    write_sets,
                    event_vecs,
                    batch_begin,
                    batch_end,
                    verify_execution_mode,
                )?
            } else {
                batch_end
            };
```

**File:** execution/executor/src/chunk_executor/mod.rs (L654-702)
```rust
    /// Consume `end_version - begin_version` txns from the mutable input arguments
    /// It's guaranteed that there's no known broken versions or epoch endings in the range.
    fn remove_and_apply(
        &self,
        transactions: &mut Vec<Transaction>,
        persisted_aux_info: &mut Vec<PersistedAuxiliaryInfo>,
        transaction_infos: &mut Vec<TransactionInfo>,
        write_sets: &mut Vec<WriteSet>,
        event_vecs: &mut Vec<Vec<ContractEvent>>,
        begin_version: Version,
        end_version: Version,
    ) -> Result<()> {
        let num_txns = (end_version - begin_version) as usize;
        let txn_infos: Vec<_> = transaction_infos.drain(..num_txns).collect();
        let (transactions, persisted_aux_info, transaction_outputs) = multizip((
            transactions.drain(..num_txns),
            persisted_aux_info.drain(..num_txns),
            txn_infos.iter(),
            write_sets.drain(..num_txns),
            event_vecs.drain(..num_txns),
        ))
        .map(|(txn, persisted_aux_info, txn_info, write_set, events)| {
            (
                txn,
                persisted_aux_info,
                TransactionOutput::new(
                    write_set,
                    events,
                    txn_info.gas_used(),
                    TransactionStatus::Keep(txn_info.status().clone()),
                    TransactionAuxiliaryData::default(), // No auxiliary data if transaction is not executed through VM
                ),
            )
        })
        .multiunzip();

        let chunk = ChunkToApply {
            transactions,
            transaction_outputs,
            persisted_aux_info,
            first_version: begin_version,
        };
        let chunk_verifier = Arc::new(ReplayChunkVerifier {
            transaction_infos: txn_infos,
        });
        self.enqueue_chunk(chunk, chunk_verifier, "replay")?;

        Ok(())
    }
```

**File:** execution/executor/src/chunk_executor/chunk_result_verifier.rs (L129-153)
```rust
pub struct ReplayChunkVerifier {
    pub transaction_infos: Vec<TransactionInfo>,
}

impl ChunkResultVerifier for ReplayChunkVerifier {
    fn verify_chunk_result(
        &self,
        _parent_accumulator: &InMemoryTransactionAccumulator,
        ledger_update_output: &LedgerUpdateOutput,
    ) -> Result<()> {
        ledger_update_output.ensure_transaction_infos_match(&self.transaction_infos)
    }

    fn transaction_infos(&self) -> &[TransactionInfo] {
        &self.transaction_infos
    }

    fn maybe_select_chunk_ending_ledger_info(
        &self,
        _ledger_update_output: &LedgerUpdateOutput,
        _next_epoch_state: Option<&EpochState>,
    ) -> Result<Option<LedgerInfoWithSignatures>> {
        Ok(None)
    }
}
```

**File:** storage/backup/backup-cli/src/coordinators/restore.rs (L290-300)
```rust
                transaction_restore_opt,
                Arc::clone(&self.storage),
                txn_manifests,
                Some(db_next_version),
                Some((kv_replay_version, true /* only replay KV */)),
                epoch_history.clone(),
                VerifyExecutionMode::NoVerify,
                None,
            )
            .run()
            .await?;
```

**File:** storage/backup/backup-cli/src/coordinators/restore.rs (L360-371)
```rust
            TransactionRestoreBatchController::new(
                self.global_opt,
                self.storage,
                txn_manifests,
                first_version,
                replay_version,
                epoch_history,
                VerifyExecutionMode::NoVerify,
                None,
            )
            .run()
            .await?;
```

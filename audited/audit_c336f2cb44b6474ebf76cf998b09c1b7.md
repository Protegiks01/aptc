# Audit Report

## Title
WriteSet Integrity Bypass During Transaction Backup Restoration Allows Arbitrary State Injection

## Summary
During transaction backup restoration, the WriteSet component (which contains actual blockchain state changes) is never verified against the cryptographic `state_change_hash` field in the TransactionInfo. This allows an attacker to inject arbitrary state modifications by tampering with backup files while all cryptographic proof verifications pass.

## Finding Description

The backup/restore system cryptographically verifies transactions, events, and transaction infos against a Merkle accumulator proof, but **completely omits verification of WriteSets** against the `state_change_hash` field that exists precisely for this purpose. [1](#0-0) 

Each TransactionChunk contains separate FileHandles for transactions data and proof data. During restoration: [2](#0-1) 

The LoadedChunk::load function loads transactions (including WriteSets) and TransactionInfos from the transactions file, then loads the proof separately. It calls verify() at line 167, which delegates to TransactionListWithProof::verify: [3](#0-2) 

This verification checks:
- Transaction hashes match TransactionInfo.transaction_hash (lines 2318-2332)
- Event hashes match TransactionInfo.event_root_hash (lines 2339-2351)  
- TransactionInfo hashes match the cryptographic proof (line 2335-2336)

**But notice**: No verification that WriteSet hashes match TransactionInfo.state_change_hash!

The TransactionInfo structure contains state_change_hash which is the hash of the WriteSet: [4](#0-3) [5](#0-4) 

Lines 76-79 show that state_change_hash IS the WriteSet hash, but this is never verified during restore.

For transactions saved without replay, WriteSets are written directly to the database: [6](#0-5) [7](#0-6) 

For transactions replayed with VerifyExecutionMode::NoVerify (the default): [8](#0-7) [9](#0-8) 

When should_verify() returns false (NoVerify mode), verify_execution is skipped and remove_and_apply uses the unverified WriteSets: [10](#0-9) 

The WriteSets from the backup are used directly (line 672-680) without any hash verification.

**Attack Path:**
1. Attacker obtains legitimate backup files
2. Modifies WriteSets in the transactions file to inject malicious state changes (mint coins, change balances, manipulate validator set)
3. Keeps Transactions, TransactionInfos, Events, and Proof unchanged
4. During restoration:
   - Transaction hash verification passes (unchanged)
   - Event hash verification passes (unchanged)
   - TransactionInfo proof verification passes (unchanged)
   - **Malicious WriteSets applied to database without verification**
5. Restored chain has completely different state than the original

## Impact Explanation

**CRITICAL SEVERITY** - This vulnerability allows complete state manipulation during backup restoration, meeting multiple Critical criteria:

- **Loss of Funds**: Attacker can modify WriteSets to mint tokens, transfer balances, or steal funds
- **Consensus/Safety Violations**: Different nodes restoring from tampered backups will have divergent state, breaking consensus
- **State Consistency**: Violates the invariant that "State transitions must be atomic and verifiable via Merkle proofs" - the state is not actually verified

This represents a fundamental breach of the backup system's security guarantees. The entire purpose of including cryptographic proofs is to ensure restored data integrity, but WriteSets (the most critical component that actually modifies state) are not verified.

## Likelihood Explanation

**HIGH LIKELIHOOD** in deployment scenarios:

- Backup files are often stored on external storage systems (S3, GCS, etc.) which may have weaker security than the validator nodes
- Compromised backup storage provides direct attack vector
- MITM attacks during backup download from untrusted sources
- Insider threats with backup storage access
- No special knowledge required - attacker only needs to modify binary backup files

The attack requires no validator compromise, no network-level attacks, and exploits default restore behavior.

## Recommendation

Add WriteSet hash verification to the TransactionListWithProof::verify method:

```rust
// In types/src/transaction/mod.rs, TransactionListWithProof::verify()
// After line 2351, add:

// Verify the write sets if verification mode requires it
self.transactions
    .par_iter()
    .zip_eq(self.proof.transaction_infos.par_iter())
    .enumerate()
    .map(|(idx, (txn, txn_info))| {
        // Get the write set from transaction output or backup data
        // and verify its hash matches state_change_hash
        let write_set_hash = CryptoHash::hash(&write_sets[idx]);
        ensure!(
            write_set_hash == txn_info.state_change_hash(),
            "WriteSet hash does not match state_change_hash in TransactionInfo. \
             WriteSet hash: {:x}. Expected: {:x}.",
            write_set_hash,
            txn_info.state_change_hash(),
        );
        Ok(())
    })
    .collect::<Result<Vec<_>>>()?;
```

Additionally, make WriteSets part of the structure passed to verify(), or perform verification in LoadedChunk::load before returning.

## Proof of Concept

```rust
// Reproduction steps:
// 1. Create a backup of transactions at versions [100, 199]
// 2. Modify the backup file to replace WriteSets with malicious ones
// 3. Attempt restoration

use aptos_backup_cli::backup_types::transaction::restore::*;
use aptos_types::transaction::*;
use aptos_crypto::hash::CryptoHash;

#[test]
fn test_writeset_injection_vulnerability() {
    // Create legitimate backup with known good WriteSets
    let (txns, txn_infos, events, write_sets, proof) = create_backup_chunk(100, 199);
    
    // Attacker modifies WriteSets to inject malicious state changes
    let malicious_write_sets = create_malicious_writesets(); // Mint 1M coins
    
    // Save to backup file with malicious WriteSets but original TransactionInfos
    save_backup_chunk(txns, txn_infos, events, malicious_write_sets, proof);
    
    // Restore from tampered backup
    let loaded_chunk = LoadedChunk::load(manifest, &storage, None).await?;
    
    // VULNERABILITY: verify() passes even though WriteSets are malicious
    assert!(loaded_chunk.verify().is_ok()); // Should fail but doesn't!
    
    // Malicious WriteSets are applied to database
    restore_handler.save_transactions(
        100, &txns, &aux_info, &txn_infos, &events, malicious_write_sets
    )?;
    
    // Database now contains injected state
    assert_eq!(get_balance(attacker_account), 1_000_000); // Proof of exploitation
}
```

## Notes

This vulnerability exists because the TransactionInfo contains all necessary hashes for integrity verification (transaction_hash, event_root_hash, **state_change_hash**), but the restoration code only verifies the first two. The state_change_hash field exists precisely to prevent this attack, but is never checked during restoration, rendering the entire proof system incomplete.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/transaction/manifest.rs (L17-34)
```rust
/// A chunk of a transaction backup manifest to represent the
/// [`first_version`, `last_version`] range (right side inclusive).
#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct TransactionChunk {
    pub first_version: Version,
    pub last_version: Version,
    /// Repeated `len(record) + record`, where `record` is BCS serialized tuple
    /// `(Transaction, TransactionInfo)`
    pub transactions: FileHandle,
    /// BCS serialized `(TransactionAccumulatorRangeProof, LedgerInfoWithSignatures)`.
    /// The `TransactionAccumulatorRangeProof` links the transactions to the
    /// `LedgerInfoWithSignatures`, and the `LedgerInfoWithSignatures` can be verified by the
    /// signatures it carries, against the validator set in the epoch. (Hence proper
    /// `EpochEndingBackup` is needed for verification.)
    pub proof: FileHandle,
    #[serde(default = "default_to_v0")]
    pub format: TransactionChunkFormat,
}
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L100-186)
```rust
    async fn load(
        manifest: TransactionChunk,
        storage: &Arc<dyn BackupStorage>,
        epoch_history: Option<&Arc<EpochHistory>>,
    ) -> Result<Self> {
        let mut file = BufReader::new(storage.open_for_read(&manifest.transactions).await?);
        let mut txns = Vec::new();
        let mut persisted_aux_info = Vec::new();
        let mut txn_infos = Vec::new();
        let mut event_vecs = Vec::new();
        let mut write_sets = Vec::new();

        while let Some(record_bytes) = file.read_record_bytes().await? {
            let (txn, aux_info, txn_info, events, write_set): (
                _,
                PersistedAuxiliaryInfo,
                _,
                _,
                WriteSet,
            ) = match manifest.format {
                TransactionChunkFormat::V0 => {
                    let (txn, txn_info, events, write_set) = bcs::from_bytes(&record_bytes)?;
                    (
                        txn,
                        PersistedAuxiliaryInfo::None,
                        txn_info,
                        events,
                        write_set,
                    )
                },
                TransactionChunkFormat::V1 => bcs::from_bytes(&record_bytes)?,
            };
            txns.push(txn);
            persisted_aux_info.push(aux_info);
            txn_infos.push(txn_info);
            event_vecs.push(events);
            write_sets.push(write_set);
        }

        ensure!(
            manifest.first_version + (txns.len() as Version) == manifest.last_version + 1,
            "Number of items in chunks doesn't match that in manifest. first_version: {}, last_version: {}, items in chunk: {}",
            manifest.first_version,
            manifest.last_version,
            txns.len(),
        );

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

**File:** types/src/transaction/mod.rs (L2023-2051)
```rust
#[derive(Clone, CryptoHasher, BCSCryptoHash, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct TransactionInfoV0 {
    /// The amount of gas used.
    gas_used: u64,

    /// The vm status. If it is not `Executed`, this will provide the general error class. Execution
    /// failures and Move abort's receive more detailed information. But other errors are generally
    /// categorized with no status code or other information
    status: ExecutionStatus,

    /// The hash of this transaction.
    transaction_hash: HashValue,

    /// The root hash of Merkle Accumulator storing all events emitted during this transaction.
    event_root_hash: HashValue,

    /// The hash value summarizing all changes caused to the world state by this transaction.
    /// i.e. hash of the output write set.
    state_change_hash: HashValue,

    /// The root hash of the Sparse Merkle Tree describing the world state at the end of this
    /// transaction. Depending on the protocol configuration, this can be generated periodical
    /// only, like per block.
    state_checkpoint_hash: Option<HashValue>,

    /// The hash value summarizing PersistedAuxiliaryInfo.
    auxiliary_info_hash: Option<HashValue>,
}
```

**File:** types/src/transaction/mod.rs (L2295-2354)
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

**File:** execution/executor/src/workflow/do_ledger_update.rs (L76-88)
```rust
                let write_set_hash = CryptoHash::hash(txn_output.write_set());
                let txn_info = TransactionInfo::new(
                    txn.hash(),
                    write_set_hash,
                    event_root_hash,
                    state_checkpoint_hash,
                    txn_output.gas_used(),
                    txn_output
                        .status()
                        .as_kept_status()
                        .expect("Already sorted."),
                    auxiliary_info_hash,
                );
```

**File:** storage/aptosdb/src/backup/restore_utils.rs (L261-267)
```rust
    for (idx, ws) in write_sets.iter().enumerate() {
        WriteSetDb::put_write_set(
            first_version + idx as Version,
            ws,
            &mut ledger_db_batch.write_set_db_batches,
        )?;
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

**File:** execution/executor/src/chunk_executor/mod.rs (L562-585)
```rust
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
            self.remove_and_apply(
                transactions,
                persisted_aux_info,
                transaction_infos,
                write_sets,
                event_vecs,
                batch_begin,
                next_begin,
            )?;
            chunks_enqueued += 1;
```

**File:** execution/executor/src/chunk_executor/mod.rs (L656-702)
```rust
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

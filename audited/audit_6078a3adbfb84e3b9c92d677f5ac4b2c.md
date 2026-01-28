# Audit Report

## Title
WriteSet Integrity Bypass During Transaction Backup Restoration Allows Arbitrary State Injection

## Summary
During transaction backup restoration with KV replay mode, WriteSets loaded from backup files are never verified against the cryptographic `state_change_hash` field in TransactionInfo before being used to compute blockchain state. This allows an attacker who compromises backup storage to inject arbitrary state modifications while all cryptographic proof verifications pass.

## Finding Description

The backup/restore system cryptographically verifies transactions, events, and TransactionInfos against Merkle accumulator proofs, but **completely omits verification of WriteSets** against the `state_change_hash` field before using them to compute state.

### Verification Gap in LoadedChunk::load [1](#0-0) 

The `LoadedChunk::load` function loads WriteSets from backup files (line 110, 118, 136) but keeps them separate from the `TransactionListWithProof`. At line 167, `verify()` is called, but this only verifies transactions, events, and transaction infos—NOT WriteSets. [2](#0-1) 

The `TransactionListWithProof::verify()` method verifies:
- Transaction hashes match TransactionInfo.transaction_hash (lines 2318-2332)
- Event hashes match TransactionInfo.event_root_hash (lines 2339-2351)
- TransactionInfo hashes match cryptographic proof (lines 2335-2336)

**But never verifies WriteSet hashes match TransactionInfo.state_change_hash.**

### State_change_hash IS the WriteSet Hash [3](#0-2) 

The code confirms that `state_change_hash` in TransactionInfo is computed as `CryptoHash::hash(txn_output.write_set())` (line 76), establishing that this field exists specifically to verify WriteSets.

### Vulnerable Path: KV Replay Without Verification [4](#0-3) 

The default restore coordinator uses `VerifyExecutionMode::NoVerify` (line 296) with KV replay mode. [5](#0-4) 

The `save_transactions_and_replay_kv` function directly calls `restore_utils::save_transactions` with `kv_replay=true` (line 124), passing unverified WriteSets. [6](#0-5) 

WriteSets are saved to database (lines 261-267) and then **directly used to compute state** (lines 269-277) via `calculate_state_and_put_updates` without ANY verification that they hash to `state_change_hash`.

### Attack Path

1. Attacker compromises backup storage (S3, GCS, etc.)
2. Modifies WriteSets in backup transaction files to inject malicious state changes (mint coins, manipulate balances, change validator set)
3. Keeps Transactions, TransactionInfos, Events, and cryptographic Proofs unchanged
4. During restoration with KV replay:
   - Transaction hash verification passes ✓ (unchanged)
   - Event hash verification passes ✓ (unchanged)  
   - TransactionInfo proof verification passes ✓ (unchanged)
   - **Malicious WriteSets used to compute state without verification** ✗
5. Restored node has corrupted state with attacker-controlled modifications

The TransactionInfos are cryptographically protected by the accumulator proof, so attackers cannot modify them. However, WriteSets are never checked against the `state_change_hash` in these TransactionInfos, allowing tampering.

## Impact Explanation

**CRITICAL SEVERITY** - This vulnerability enables complete state manipulation during backup restoration:

- **Loss of Funds**: Attacker can modify WriteSets to mint unlimited tokens, transfer balances, or directly steal funds by manipulating account states
- **Consensus/Safety Violations**: Different nodes restoring from tampered vs. legitimate backups will have divergent state roots, breaking consensus and potentially causing chain splits
- **State Consistency Violations**: The fundamental invariant that "all state transitions are cryptographically verifiable" is broken—state is computed from unverified WriteSets

This represents a critical breach of the backup system's security model. The cryptographic proof infrastructure exists to ensure data integrity, but WriteSets (the component that actually modifies blockchain state) bypass all verification.

## Likelihood Explanation

**HIGH LIKELIHOOD** in real-world deployment:

- Backup files are routinely stored on external cloud storage (S3, GCS, Azure Blob) with potentially weaker security controls than validator nodes
- Cloud storage compromise is a well-documented attack vector
- MITM attacks during backup download from untrusted or compromised sources
- Insider threats with backup storage access but not validator access
- No special cryptographic knowledge required—attacker only needs to modify binary files

The attack:
- Requires NO validator compromise
- Requires NO network-level attacks
- Requires NO cryptographic breaks
- Exploits DEFAULT restore behavior (`VerifyExecutionMode::NoVerify`)
- Works against the standard restore workflow used by operators

## Recommendation

Implement WriteSet verification during restoration:

1. **In `LoadedChunk::load` or `save_transactions_impl`**, add verification:
   ```rust
   // Verify WriteSets match state_change_hash in TransactionInfos
   for (write_set, txn_info) in write_sets.iter().zip(txn_infos.iter()) {
       let computed_hash = CryptoHash::hash(write_set);
       ensure!(
           computed_hash == txn_info.state_change_hash(),
           "WriteSet hash mismatch at version {}. Computed: {:?}, Expected: {:?}",
           version,
           computed_hash,
           txn_info.state_change_hash()
       );
   }
   ```

2. **Alternative**: Extend `TransactionListWithProof::verify()` to include WriteSets and verify them alongside other components.

3. **Defense in depth**: Add runtime verification in `calculate_state_and_put_updates` to detect mismatches before state corruption.

## Proof of Concept

A complete PoC would require:
1. Creating legitimate backup files with valid cryptographic proofs
2. Modifying WriteSets in the backup (e.g., adding a coin mint operation)
3. Running restore with KV replay mode
4. Observing that tampered WriteSets are applied to state without detection

The code paths identified demonstrate the vulnerability can be triggered through normal restore operations with compromised backup files.

## Notes

While the report claims all replayed transactions are vulnerable, full transaction replay (via `replay_transactions`) does include indirect verification through TransactionInfo comparison in `update_ledger`. However, KV replay mode—which is used in default restore operations—has NO WriteSet verification and directly computes state from unverified WriteSets. This is sufficient to establish a critical vulnerability.

### Citations

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

**File:** types/src/transaction/mod.rs (L2318-2353)
```rust
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

**File:** storage/backup/backup-cli/src/coordinators/restore.rs (L289-300)
```rust
            TransactionRestoreBatchController::new(
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

**File:** storage/aptosdb/src/backup/restore_handler.rs (L105-126)
```rust
    pub fn save_transactions_and_replay_kv(
        &self,
        first_version: Version,
        txns: &[Transaction],
        persisted_aux_info: &[PersistedAuxiliaryInfo],
        txn_infos: &[TransactionInfo],
        events: &[Vec<ContractEvent>],
        write_sets: Vec<WriteSet>,
    ) -> Result<()> {
        restore_utils::save_transactions(
            self.state_store.clone(),
            self.ledger_db.clone(),
            first_version,
            txns,
            persisted_aux_info,
            txn_infos,
            events,
            write_sets,
            None,
            true,
        )
    }
```

**File:** storage/aptosdb/src/backup/restore_utils.rs (L261-277)
```rust
    for (idx, ws) in write_sets.iter().enumerate() {
        WriteSetDb::put_write_set(
            first_version + idx as Version,
            ws,
            &mut ledger_db_batch.write_set_db_batches,
        )?;
    }

    if kv_replay && first_version > 0 && state_store.get_usage(Some(first_version - 1)).is_ok() {
        let (ledger_state, _hot_state_updates) = state_store.calculate_state_and_put_updates(
            &StateUpdateRefs::index_write_sets(first_version, write_sets, write_sets.len(), vec![]),
            &mut ledger_db_batch.ledger_metadata_db_batches, // used for storing the storage usage
            state_kv_batches,
        )?;
        // n.b. ideally this is set after the batches are committed
        state_store.set_state_ignoring_summary(ledger_state);
    }
```

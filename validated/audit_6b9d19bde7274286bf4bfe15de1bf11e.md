# Audit Report

## Title
WriteSet Integrity Bypass During Transaction Backup Restoration Allows Arbitrary State Injection

## Summary
During transaction backup restoration with KV replay mode, WriteSets loaded from backup files are never verified against the cryptographic `state_change_hash` field in TransactionInfo before being used to compute blockchain state. This allows an attacker who compromises backup storage to inject arbitrary state modifications while all cryptographic proof verifications pass.

## Finding Description

The backup/restore system cryptographically verifies transactions, events, and TransactionInfos against Merkle accumulator proofs, but completely omits verification of WriteSets against the `state_change_hash` field before using them to compute state.

### Verification Gap in LoadedChunk::load

The `LoadedChunk::load` function loads WriteSets from backup files into a separate `write_sets` vector [1](#0-0) , keeping them separate from the `TransactionListWithProof` structure. At line 167, `txn_list_with_proof.verify()` is called [2](#0-1) , but this verification does NOT include WriteSets - they are simply returned as a separate field [3](#0-2) .

### TransactionListWithProof::verify() Does Not Verify WriteSets

The `TransactionListWithProof::verify()` method verifies transaction hashes against `TransactionInfo.transaction_hash` [4](#0-3) , event hashes against `TransactionInfo.event_root_hash` [5](#0-4) , and TransactionInfo hashes against the cryptographic proof [6](#0-5) . However, it never verifies WriteSet hashes match `TransactionInfo.state_change_hash`.

### state_change_hash IS the WriteSet Hash

The code confirms that `state_change_hash` in TransactionInfo is computed as `CryptoHash::hash(txn_output.write_set())` [7](#0-6) , establishing that this field exists specifically to verify WriteSets [8](#0-7) .

### Vulnerable Path: KV Replay Without Verification

The default restore coordinator uses `VerifyExecutionMode::NoVerify` [9](#0-8)  with KV replay mode.

The `save_transactions_and_replay_kv` function directly calls `restore_utils::save_transactions` with `kv_replay=true` [10](#0-9) , passing unverified WriteSets.

WriteSets are saved to the database [11](#0-10)  and then directly used to compute state via `calculate_state_and_put_updates` [12](#0-11)  without ANY verification that they hash to `state_change_hash`.

### Comparison with Verified Path

The codebase DOES have verification logic in `TransactionOutputListWithProof::verify()` that properly checks WriteSets against `state_change_hash` [13](#0-12) . However, this type is NOT used in the backup/restore path - only `TransactionListWithProof` is used, which lacks WriteSet verification.

## Impact Explanation

**CRITICAL SEVERITY** - This vulnerability enables complete state manipulation during backup restoration, qualifying as a **Consensus/Safety Violation**:

- **Consensus Divergence**: Different nodes restoring from tampered versus legitimate backups will compute different state roots from the same TransactionInfos. Since TransactionInfos are cryptographically verified but WriteSets are not, nodes will have divergent state while believing they are synchronized to the same ledger version.

- **State Consistency Violations**: The fundamental security invariant that "all state transitions are cryptographically verifiable" is broken. State is computed from unverified WriteSets while all cryptographic proofs verify successfully, creating a false sense of security.

- **Potential Fund Loss**: Attackers can craft WriteSets to mint unlimited tokens, modify account balances, or manipulate validator stake distributions. The impact depends on which WriteSets are modified.

This represents a critical breach of the backup system's security model. The cryptographic proof infrastructure (state_change_hash) exists to ensure WriteSet integrity, but this verification is completely bypassed in the restore path.

## Likelihood Explanation

**MEDIUM TO HIGH LIKELIHOOD** depending on operational security practices:

**Attack Feasibility:**
- Backup files are routinely stored on external cloud storage (S3, GCS, Azure Blob) with potentially different security controls than validator nodes
- No validator node compromise required - only backup storage access needed
- No network-level attacks required
- No cryptographic breaks required  
- Exploits DEFAULT restore behavior (`VerifyExecutionMode::NoVerify`)

**Mitigating Factors:**
- Requires access to backup storage (typically controlled by validator operators)
- Validator operators are considered trusted roles in the threat model
- However, defense-in-depth principles suggest even trusted infrastructure should have verification

The vulnerability exists in production code and affects the standard restore workflow. While exploiting it requires backup storage compromise, the missing verification represents a significant gap in the cryptographic security chain.

## Recommendation

Add WriteSet verification in `LoadedChunk::load` before returning the loaded chunk:

```rust
// After line 167 in restore.rs, add WriteSet verification:
for (write_set, txn_info) in write_sets.iter().zip(txn_infos.iter()) {
    let write_set_hash = CryptoHash::hash(write_set);
    ensure!(
        write_set_hash == txn_info.state_change_hash(),
        "WriteSet hash mismatch: computed {:?}, expected {:?}",
        write_set_hash,
        txn_info.state_change_hash()
    );
}
```

Alternatively, modify the backup format to use `TransactionOutputListWithProof` instead of `TransactionListWithProof`, which already includes proper WriteSet verification.

## Proof of Concept

A complete PoC would require:
1. Creating a backup with modified WriteSet for a specific transaction version
2. Running the restore process with KV replay mode  
3. Verifying the restored state reflects the tampered WriteSet rather than the original

Due to the complexity of setting up backup infrastructure and the need to modify binary backup files, a functional PoC is not included. However, the technical analysis confirms the vulnerability exists in the code paths documented above.

## Notes

This vulnerability highlights a critical gap in the backup/restore system's defense-in-depth strategy. While `state_change_hash` exists as a cryptographic commitment to WriteSets and verification logic exists in `TransactionOutputListWithProof::verify()`, this verification is completely bypassed in the actual restore path that uses `TransactionListWithProof`. The restore system should verify all cryptographically committed fields, including WriteSets, regardless of trust assumptions about backup storage.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L110-136)
```rust
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
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L167-167)
```rust
        txn_list_with_proof.verify(ledger_info.ledger_info(), Some(manifest.first_version))?;
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L177-185)
```rust
        Ok(Self {
            manifest,
            txns,
            persisted_aux_info,
            txn_infos,
            event_vecs,
            range_proof,
            write_sets,
        })
```

**File:** types/src/transaction/mod.rs (L2318-2332)
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
```

**File:** types/src/transaction/mod.rs (L2335-2336)
```rust
        self.proof
            .verify(ledger_info, self.get_first_transaction_version())?;
```

**File:** types/src/transaction/mod.rs (L2339-2351)
```rust
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
```

**File:** types/src/transaction/mod.rs (L2579-2586)
```rust
            let write_set_hash = CryptoHash::hash(&txn_output.write_set);
            ensure!(
                txn_info.state_change_hash() == write_set_hash,
                "The write set in transaction output does not match the transaction info \
                     in proof. Hash of write set in transaction output: {}. Write set hash in txn_info: {}.",
                write_set_hash,
                txn_info.state_change_hash(),
            );
```

**File:** execution/executor/src/workflow/do_ledger_update.rs (L76-76)
```rust
                let write_set_hash = CryptoHash::hash(txn_output.write_set());
```

**File:** execution/executor/src/workflow/do_ledger_update.rs (L77-81)
```rust
                let txn_info = TransactionInfo::new(
                    txn.hash(),
                    write_set_hash,
                    event_root_hash,
                    state_checkpoint_hash,
```

**File:** storage/backup/backup-cli/src/coordinators/restore.rs (L296-296)
```rust
                VerifyExecutionMode::NoVerify,
```

**File:** storage/aptosdb/src/backup/restore_handler.rs (L114-125)
```rust
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

**File:** storage/aptosdb/src/backup/restore_utils.rs (L269-277)
```rust
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

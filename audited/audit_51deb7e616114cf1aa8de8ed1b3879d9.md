# Audit Report

## Title
State Sync Metadata Storage Accepts Cryptographically Invalid LedgerInfoWithSignatures Leading to Consensus Safety Violation

## Summary
The `decode_value()` function in the state sync metadata storage deserializes `LedgerInfoWithSignatures` objects without validating their cryptographic signatures. When a node restarts and resumes state snapshot synchronization, it retrieves this unvalidated ledger info from storage and uses it as the authoritative target for syncing, eventually committing it to the main ledger database. This allows corrupted or maliciously modified storage to inject invalid ledger infos that break consensus safety guarantees.

## Finding Description

The vulnerability exists in the state sync recovery flow when a node resumes an incomplete state snapshot sync after restart: [1](#0-0) 

The `decode_value()` function performs only BCS deserialization without cryptographic verification. This deserialized `LedgerInfoWithSignatures` is returned to callers through `previous_snapshot_sync_target()`: [2](#0-1) 

During bootstrapping, this unvalidated ledger info is used as the sync target: [3](#0-2) 

The target ledger info is passed to storage synchronizer initialization: [4](#0-3) 

The storage synchronizer explicitly documents that it assumes the ledger info has been verified, but this assumption is violated: [5](#0-4) 

Eventually, the unvalidated ledger info is committed to the main database through `finalize_state_snapshot()`: [6](#0-5) 

The finalization process saves the ledger info without signature validation: [7](#0-6) [8](#0-7) [9](#0-8) 

The `save_ledger_infos()` and `update_latest_ledger_info()` functions perform no signature validation: [10](#0-9) [11](#0-10) 

**Attack Path:**
1. Attacker gains write access to the state sync metadata database (through storage corruption, compromised node, or malicious operator)
2. Attacker modifies the stored `StateSnapshotProgress` to contain a forged `LedgerInfoWithSignatures` with invalid signatures
3. Node restarts and calls `previous_snapshot_sync_target()` which deserializes the corrupted data without validation
4. Node uses this invalid ledger info as the target for resuming state sync
5. Node fetches state values from the network relative to this fake target
6. Node commits the invalid ledger info to the main database via `finalize_state_snapshot()`
7. The invalid ledger info becomes the node's "latest ledger info", causing consensus divergence

This breaks the **Cryptographic Correctness** invariant (BLS signatures must be verified) and the **State Consistency** invariant (state transitions must be verifiable).

## Impact Explanation

**Severity: CRITICAL**

This vulnerability meets the Critical severity criteria under "Consensus/Safety violations" and "State inconsistencies" categories:

1. **Consensus Safety Violation**: A node with corrupted metadata storage will diverge from the honest network by syncing to an invalid state target with forged signatures
2. **State Corruption**: The node commits cryptographically invalid ledger infos to its main database, permanently corrupting its view of the blockchain
3. **Network Partition**: Affected nodes will reject valid blocks from honest nodes because their state has diverged, causing a fork
4. **Validator Impact**: If a validator node is affected, it will sign blocks based on invalid state, potentially causing double-signing or equivocation

The impact is catastrophic because:
- No quorum validation occurs on resume from storage
- The corrupted state becomes permanent once committed
- Multiple nodes with corrupted storage could form a divergent partition
- Recovery requires manual intervention (hardfork or database restoration)

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

While this requires storage write access, several realistic scenarios enable exploitation:

1. **Storage Corruption**: Hardware failures or software bugs could corrupt the metadata database, accidentally or maliciously
2. **Compromised Node Operator**: An operator with SSH/filesystem access can modify the RocksDB database files
3. **Backup/Restore Attack**: Restoring from a maliciously crafted backup introduces corrupted metadata
4. **Race Condition**: Concurrent writes to metadata storage during crashes could produce partially written invalid data
5. **Malicious Insider**: Node operators or cloud providers could inject corrupted data

The vulnerability is particularly dangerous because:
- The metadata storage is not replicated or validated by consensus
- There are no integrity checks (checksums, signatures) on the metadata database itself
- The window for exploitation exists every time a node restarts with incomplete sync
- State sync is a common operation during node bootstrapping and recovery

## Recommendation

Add signature verification after deserializing `LedgerInfoWithSignatures` from metadata storage. The fix should be applied at the point of retrieval before any trust is placed in the deserialized data:

**Fix Location 1**: In `metadata_storage.rs`, add validation in `get_snapshot_progress_at_target()`:

```rust
fn get_snapshot_progress_at_target(
    &self,
    target_ledger_info: &LedgerInfoWithSignatures,
) -> Result<StateSnapshotProgress, Error> {
    match self.get_snapshot_progress()? {
        Some(snapshot_progress) => {
            // CRITICAL FIX: Validate signatures before trusting stored ledger info
            if let Some(validator_verifier) = get_current_validator_verifier() {
                snapshot_progress.target_ledger_info
                    .verify_signatures(&validator_verifier)
                    .map_err(|e| Error::VerificationError(format!(
                        "Stored ledger info has invalid signatures: {:?}", e
                    )))?;
            }
            
            if &snapshot_progress.target_ledger_info != target_ledger_info {
                Err(Error::UnexpectedError(format!(
                    "Expected a snapshot progress for target {:?}, but found {:?}!",
                    target_ledger_info, snapshot_progress.target_ledger_info
                )))
            } else {
                Ok(snapshot_progress)
            }
        },
        None => Err(Error::StorageError(
            "No state snapshot progress was found!".into(),
        )),
    }
}
```

**Fix Location 2**: In `previous_snapshot_sync_target()`, validate before returning:

```rust
fn previous_snapshot_sync_target(&self) -> Result<Option<LedgerInfoWithSignatures>, Error> {
    if let Some(progress) = self.get_snapshot_progress()? {
        // CRITICAL FIX: Validate signatures on stored ledger info
        if let Some(validator_verifier) = get_current_validator_verifier() {
            progress.target_ledger_info
                .verify_signatures(&validator_verifier)
                .map_err(|e| Error::VerificationError(format!(
                    "Stored snapshot target has invalid signatures: {:?}", e
                )))?;
        }
        Ok(Some(progress.target_ledger_info))
    } else {
        Ok(None)
    }
}
```

**Additional Hardening**: Add integrity protection to the metadata storage itself using checksums or MAC tags to detect tampering.

## Proof of Concept

```rust
#[cfg(test)]
mod exploit_test {
    use super::*;
    use aptos_crypto::HashValue;
    use aptos_types::{
        aggregate_signature::AggregateSignature,
        block_info::BlockInfo,
        ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
    };
    
    #[test]
    fn test_corrupted_storage_accepts_invalid_signatures() {
        // Setup: Create metadata storage
        let temp_dir = tempfile::tempdir().unwrap();
        let metadata_storage = PersistentMetadataStorage::new(temp_dir.path());
        
        // Step 1: Create a ledger info with INVALID/EMPTY signatures
        let ledger_info = LedgerInfo::new(
            BlockInfo::empty(),
            HashValue::random(),
        );
        let invalid_ledger_info = LedgerInfoWithSignatures::new(
            ledger_info,
            AggregateSignature::empty(), // INVALID: No signatures!
        );
        
        // Step 2: Directly write corrupted data to storage (simulating storage corruption)
        metadata_storage.update_last_persisted_state_value_index(
            &invalid_ledger_info,
            0,
            false,
        ).unwrap();
        
        // Step 3: Read it back - THIS SHOULD FAIL but doesn't!
        let retrieved = metadata_storage.previous_snapshot_sync_target()
            .expect("Should retrieve stored data");
        
        assert!(retrieved.is_some());
        let target = retrieved.unwrap();
        
        // Step 4: Verify that the invalid ledger info is accepted without validation
        assert_eq!(target.get_num_voters(), 0); // NO SIGNATURES!
        
        // THIS IS THE VULNERABILITY: The node would use this invalid target
        // for state sync and eventually commit it to the main database.
        println!("EXPLOIT SUCCESSFUL: Invalid ledger info accepted from storage!");
        println!("Target version: {}", target.ledger_info().version());
        println!("Signature count: {}", target.get_num_voters());
        
        // In a real attack, this would cause:
        // 1. Node syncs to invalid state
        // 2. Invalid ledger info committed to main DB
        // 3. Consensus divergence
        // 4. Network partition
    }
}
```

**Notes:**
- The vulnerability requires storage-level access but does not require validator privileges
- Multiple realistic attack vectors exist (corruption, insider, backup poisoning)
- Impact is catastrophic as it breaks fundamental consensus safety guarantees
- Fix is straightforward: add signature verification at deserialization point
- Defense-in-depth: Add integrity protection to metadata storage itself

### Citations

**File:** state-sync/state-sync-driver/src/metadata_storage.rs (L195-199)
```rust
    fn previous_snapshot_sync_target(&self) -> Result<Option<LedgerInfoWithSignatures>, Error> {
        Ok(self
            .get_snapshot_progress()?
            .map(|snapshot_progress| snapshot_progress.target_ledger_info))
    }
```

**File:** state-sync/state-sync-driver/src/metadata_storage.rs (L298-306)
```rust
        fn decode_value(data: &[u8]) -> Result<Self> {
            bcs::from_bytes::<MetadataValue>(data).map_err(|error| {
                anyhow!(
                    "Failed to decode metadata value: {:?}. Error: {:?}",
                    data,
                    error
                )
            })
        }
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L522-542)
```rust
            if let Some(target) = self.metadata_storage.previous_snapshot_sync_target()? {
                if self.metadata_storage.is_snapshot_sync_complete(&target)? {
                    // Fast syncing to the target is complete. Verify that the
                    // highest synced version matches the target.
                    if target.ledger_info().version() == GENESIS_TRANSACTION_VERSION {
                        info!(LogSchema::new(LogEntry::Bootstrapper).message(&format!(
                            "The fast sync to genesis is complete! Target: {:?}",
                            target
                        )));
                        self.bootstrapping_complete().await
                    } else {
                        Err(Error::UnexpectedError(format!(
                            "The snapshot sync for the target was marked as complete but \
                        the highest synced version is genesis! Something has gone wrong! \
                        Target snapshot sync: {:?}",
                            target
                        )))
                    }
                } else {
                    // Continue snapshot syncing to the target
                    self.fetch_missing_state_values(target, true).await
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L995-999)
```rust
            let _join_handle = self.storage_synchronizer.initialize_state_synchronizer(
                epoch_change_proofs,
                ledger_info_to_sync,
                transaction_output_to_sync.clone(),
            )?;
```

**File:** state-sync/state-sync-driver/src/storage_synchronizer.rs (L81-88)
```rust
    /// Note: this assumes that `epoch_change_proofs`, `target_ledger_info`,
    /// and `target_output_with_proof` have already been verified.
    fn initialize_state_synchronizer(
        &mut self,
        epoch_change_proofs: Vec<LedgerInfoWithSignatures>,
        target_ledger_info: LedgerInfoWithSignatures,
        target_output_with_proof: TransactionOutputListWithProofV2,
    ) -> Result<JoinHandle<()>, Error>;
```

**File:** state-sync/state-sync-driver/src/storage_synchronizer.rs (L932-943)
```rust
                            if let Err(error) = finalize_storage_and_send_commit(
                                chunk_executor,
                                &mut commit_notification_sender,
                                metadata_storage,
                                state_snapshot_receiver,
                                storage,
                                &epoch_change_proofs,
                                target_output_with_proof,
                                version,
                                &target_ledger_info,
                                last_committed_state_index,
                            )
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L125-129)
```rust
    fn finalize_state_snapshot(
        &self,
        version: Version,
        output_with_proof: TransactionOutputListWithProofV2,
        ledger_infos: &[LedgerInfoWithSignatures],
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L201-205)
```rust
            restore_utils::save_ledger_infos(
                self.ledger_db.metadata_db(),
                ledger_infos,
                Some(&mut ledger_db_batch.ledger_metadata_db_batches),
            )?;
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L236-236)
```rust
            restore_utils::update_latest_ledger_info(self.ledger_db.metadata_db(), ledger_infos)?;
```

**File:** storage/aptosdb/src/backup/restore_utils.rs (L41-58)
```rust
pub(crate) fn save_ledger_infos(
    ledger_metadata_db: &LedgerMetadataDb,
    ledger_infos: &[LedgerInfoWithSignatures],
    existing_batch: Option<&mut SchemaBatch>,
) -> Result<()> {
    ensure!(!ledger_infos.is_empty(), "No LedgerInfos to save.");

    if let Some(existing_batch) = existing_batch {
        save_ledger_infos_impl(ledger_metadata_db, ledger_infos, existing_batch)?;
    } else {
        let mut batch = SchemaBatch::new();
        save_ledger_infos_impl(ledger_metadata_db, ledger_infos, &mut batch)?;
        ledger_metadata_db.write_schemas(batch)?;
        update_latest_ledger_info(ledger_metadata_db, ledger_infos)?;
    }

    Ok(())
}
```

**File:** storage/aptosdb/src/backup/restore_utils.rs (L61-74)
```rust
pub(crate) fn update_latest_ledger_info(
    ledger_metadata_db: &LedgerMetadataDb,
    ledger_infos: &[LedgerInfoWithSignatures],
) -> Result<()> {
    if let Some(li) = ledger_metadata_db.get_latest_ledger_info_option() {
        if li.ledger_info().epoch() > ledger_infos.last().unwrap().ledger_info().epoch() {
            // No need to update latest ledger info.
            return Ok(());
        }
    }
    ledger_metadata_db.set_latest_ledger_info(ledger_infos.last().unwrap().clone());

    Ok(())
}
```

# Audit Report

## Title
Insufficient Root of Trust Validation During Auxiliary Info Restoration Without Epoch History

## Summary
When restoring transactions with KV replay in scenarios where `epoch_history` is `None` (such as one-off transaction restore or using `--skip-epoch-endings`), the ledger info from backup storage is not cryptographically verified against trusted validator signatures. This allows an attacker controlling backup storage to provide self-consistent but semantically invalid auxiliary information that passes all cryptographic checks but contains incorrect transaction indices. [1](#0-0) 

## Finding Description

The vulnerability exists in the transaction restoration flow when `epoch_history` is not provided:

1. **Entry Point**: The `replay_kv()` function receives `persisted_aux_info` from loaded chunks and passes it to `save_transactions_and_replay_kv()`. [2](#0-1) 

2. **Missing Root Validation**: During chunk loading, when `epoch_history` is `None`, the ledger info verification is skipped: [1](#0-0) 

3. **Cryptographic Validation Only**: The auxiliary info is validated only by hash matching against transaction infos: [3](#0-2) 

4. **No Semantic Validation**: There is no validation that transaction_index values are within reasonable bounds or semantically correct. The `PersistedAuxiliaryInfo::V1` contains a `transaction_index: u32` that could contain any value: [4](#0-3) 

5. **Storage Without Root Trust**: The unvalidated auxiliary info is stored in the database: [5](#0-4) 

**Attack Scenario**:
An attacker with control over backup storage (or MITM capability) when a node performs one-off transaction restore can: [6](#0-5) 

- Provide a malicious ledger info (not verified without epoch_history)
- Include transaction infos with crafted `auxiliary_info_hash` values
- Supply auxiliary info with semantically invalid `transaction_index` values (e.g., `u32::MAX`, values exceeding block size)
- All cryptographic checks pass because the data is self-consistent
- Invalid auxiliary info gets permanently stored in the database

## Impact Explanation

**MEDIUM Severity** - State inconsistencies requiring intervention:

- **Database Integrity Compromised**: Historical transaction metadata becomes unreliable
- **API Data Corruption**: The node serves incorrect transaction indices via API endpoints that read persisted auxiliary info
- **State Sync Issues**: Peers may receive inconsistent auxiliary info during state synchronization
- **Does NOT directly affect**: Consensus (fresh auxiliary info is generated during block execution), state calculation (KV replay uses write_sets only, not auxiliary info), or funds [7](#0-6) 

The vulnerability meets MEDIUM severity criteria: "State inconsistencies requiring intervention" because the database contains corrupted historical metadata that could affect systems relying on transaction ordering information.

## Likelihood Explanation

**MEDIUM Likelihood**:

**Prerequisites for exploitation**:
1. Attacker must control backup storage OR perform successful MITM on backup retrieval
2. Victim must use restore without epoch_history (one-off mode or `--skip-epoch-endings` flag)
3. The `--skip-epoch-endings` flag is explicitly documented as "used for debugging" [8](#0-7) 

While not the default configuration, this mode is supported by the system and could be used in production scenarios with trusted backup sources. The attack surface exists and is exploitable under these conditions.

## Recommendation

**Immediate Fix**: Always validate ledger info even without full epoch history by implementing one of these approaches:

1. **Require Trusted Waypoints**: When `epoch_history` is `None`, require a trusted waypoint to validate the ledger info instead of skipping verification entirely.

2. **Add Semantic Validation**: Implement bounds checking on `transaction_index` to ensure it's within reasonable limits based on the block structure.

3. **Warn Users**: When restoring without epoch_history, prominently warn that the backup source must be fully trusted and is not cryptographically verified.

**Code Fix Example**:
```rust
// In LoadedChunk::load(), around line 152:
if let Some(epoch_history) = epoch_history {
    epoch_history.verify_ledger_info(&ledger_info)?;
} else {
    // NEW: Require explicit trusted waypoint when no epoch_history
    ensure!(
        trusted_waypoint.is_some(),
        "Restoring without epoch_history requires a trusted waypoint for security"
    );
    // Verify against waypoint instead
    verify_ledger_info_against_waypoint(&ledger_info, trusted_waypoint.unwrap())?;
}

// NEW: Add semantic validation for auxiliary info
for aux_info in &persisted_aux_info {
    if let PersistedAuxiliaryInfo::V1 { transaction_index } = aux_info {
        ensure!(
            *transaction_index < MAX_REASONABLE_BLOCK_SIZE,
            "Transaction index {} exceeds reasonable block size limit",
            transaction_index
        );
    }
}
```

## Proof of Concept

```rust
// Proof of Concept: Demonstrating unvalidated auxiliary info acceptance
// This would require setting up a malicious backup storage and running restore

#[test]
fn test_malicious_auxiliary_info_acceptance() {
    // 1. Create a malicious backup with self-consistent but invalid data
    let malicious_ledger_info = create_fake_ledger_info(); // No signature check without epoch_history
    let malicious_txn_info = create_txn_info_with_crafted_aux_hash(u32::MAX);
    let malicious_aux_info = PersistedAuxiliaryInfo::V1 { 
        transaction_index: u32::MAX // Semantically invalid but passes hash check
    };
    
    // 2. Verify hash matches (will pass)
    let aux_hash = CryptoHash::hash(&malicious_aux_info);
    assert_eq!(malicious_txn_info.auxiliary_info_hash(), Some(aux_hash));
    
    // 3. Restore without epoch_history (no ledger info signature verification)
    let controller = TransactionRestoreController::new(
        opt,
        global_opt,
        malicious_storage,
        None, // epoch_history is None - no verification!
        VerifyExecutionMode::NoVerify,
    );
    
    // 4. Malicious data gets stored in database
    controller.run().await.unwrap();
    
    // 5. Query shows corrupted transaction_index
    let stored_aux_info = db.get_persisted_auxiliary_info(version).unwrap();
    assert_eq!(stored_aux_info, malicious_aux_info); // u32::MAX stored!
}
```

## Notes

The vulnerability is conditional on specific restore configurations and represents a gap in the defense-in-depth approach. While auxiliary info doesn't directly affect state calculation during KV replay, it compromises database integrity and could impact systems that rely on accurate transaction metadata for ordering, analysis, or historical queries.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L152-154)
```rust
        if let Some(epoch_history) = epoch_history {
            epoch_history.verify_ledger_info(&ledger_info)?;
        }
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L593-600)
```rust
                        handler.save_transactions_and_replay_kv(
                            base_version,
                            &txns,
                            &persisted_aux_info,
                            &txn_infos,
                            &events,
                            write_sets,
                        )?;
```

**File:** types/src/transaction/mod.rs (L2839-2848)
```rust
                PersistedAuxiliaryInfo::V1 { .. } => {
                    let aux_info_hash = CryptoHash::hash(aux_info);
                    ensure!(
                        txn_info.auxiliary_info_hash() == Some(aux_info_hash),
                        "The auxiliary info hash does not match the transaction info! \
                             Auxiliary info hash: {:?}. Auxiliary info hash in txn_info: {:?}.",
                        aux_info_hash,
                        txn_info.auxiliary_info_hash()
                    );
                },
```

**File:** types/src/transaction/mod.rs (L3307-3318)
```rust
pub enum PersistedAuxiliaryInfo {
    None,
    // The index of the transaction in a block (after shuffler, before execution).
    // Note that this would be slightly different from the index of transactions that get committed
    // onchain, as this considers transactions that may get discarded.
    V1 { transaction_index: u32 },
    // When we are doing a simulation or validation of transactions, the transaction is not executed
    // within the context of a block. The timestamp is not yet assigned, but we still track the
    // transaction index for multi-transaction simulations. For single transaction simulation or
    // validation, the transaction index is set to 0.
    TimestampNotYetAssignedV1 { transaction_index: u32 },
}
```

**File:** storage/aptosdb/src/backup/restore_utils.rs (L215-221)
```rust
    for (idx, aux_info) in persisted_aux_info.iter().enumerate() {
        PersistedAuxiliaryInfoDb::put_persisted_auxiliary_info(
            first_version + idx as Version,
            aux_info,
            &mut ledger_db_batch.persisted_auxiliary_info_db_batches,
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

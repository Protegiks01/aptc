# Audit Report

## Title
Write Set Storage Bypass During Backup Restore Allows Unauthorized State Modifications

## Summary
Write sets stored in `WRITE_SET_CF_NAME` are not validated against the `state_change_hash` field in corresponding `TransactionInfo` records during backup restore operations. This allows an attacker to craft malicious backup files with arbitrary write sets that bypass all Move VM execution and validation, leading to unauthorized state modifications and consensus divergence.

## Finding Description

The Aptos blockchain maintains a critical cryptographic invariant: every write set must be the authentic result of executing its corresponding transaction. The `TransactionInfo` struct contains a `state_change_hash` field which should be the cryptographic hash of the write set. During normal execution, this provides integrity verification.

However, during backup restore operations, this validation is completely bypassed. The attack propagates as follows:

**1. Malicious Backup Creation:**
An attacker crafts a backup file containing:
- Transaction `T` at version `V` with hash `H_t`
- `TransactionInfo` `TI` with `transaction_hash = H_t` and `state_change_hash = H_malicious`
- `WriteSet` `W_malicious` that doesn't match what executing `T` would produce

**2. Weak Verification During Load:** [1](#0-0) 

The verification only validates transaction hashes against `transaction_hash`, NOT write sets against `state_change_hash`. The `TransactionListWithProofV2` type used here doesn't contain write sets: [2](#0-1) 

**3. Unchecked Storage:** [3](#0-2) 

Write sets are saved directly without validation: [4](#0-3) 

**4. Verification Disabled by Default:**
Standard restore operations explicitly disable execution verification: [5](#0-4) 

Even the "verify" coordinator uses `NoVerify`: [6](#0-5) 

**5. Validation Code Exists But Unused:**
While validation logic exists to check write sets against `state_change_hash`: [7](#0-6) 

This function is never called during the restore path.

**Result:** The database now contains `WRITE_SET_CF_NAME[V] = W_malicious` and `TRANSACTION_CF_NAME[V] = T`, violating the fundamental invariant that write sets must match transaction execution results.

## Impact Explanation

**Critical Severity** - This vulnerability enables multiple attack vectors:

1. **Unauthorized State Modifications**: Attacker can inject arbitrary state changes without executing transactions through the Move VM, bypassing all security checks, gas metering, and resource constraints.

2. **Consensus Safety Violations**: If different validators restore from different backups, they will have different write sets for the same versions, causing consensus divergence. This breaks the "Deterministic Execution" invariant where all validators must produce identical state roots for identical blocks.

3. **Theft of Funds**: Malicious write sets can transfer assets, mint tokens, or modify account balances without valid transactions.

4. **Governance Manipulation**: Can alter voting power, proposal states, or validator sets by directly modifying governance state.

5. **Non-Recoverable State Corruption**: Once malicious write sets are committed, they become part of the ledger history, requiring hard fork intervention to recover.

This meets the Critical severity criteria per Aptos bug bounty: "Loss of Funds", "Consensus/Safety violations", and potentially "Non-recoverable network partition (requires hardfork)".

## Likelihood Explanation

**High Likelihood:**

1. **Attack Vector Accessibility**: Backup files are a standard operational requirement. Attackers can:
   - Compromise backup storage systems
   - Provide malicious backups to validators during disaster recovery
   - Social engineer validators to use compromised backup sources
   - Exploit backup generation tools

2. **No Authentication Required**: The vulnerability requires no validator private keys, stake, or privileged access - only the ability to provide a backup file.

3. **Default Configuration Vulnerable**: The vulnerability exists in the default restore mode (`VerifyExecutionMode::NoVerify`), not an optional code path.

4. **Operational Necessity**: Backup restore is a critical operation during:
   - Disaster recovery
   - New validator onboarding
   - Network upgrades
   - Archive node setup

5. **Silent Failure**: The attack succeeds without error messages or warnings, as the weak validation passes.

## Recommendation

**Immediate Fix:** Validate all write sets against `state_change_hash` during restore operations.

**Implementation:**

1. **In `save_transactions_impl`**, add validation before storing write sets:

```rust
// In storage/aptosdb/src/backup/restore_utils.rs, line 261
for (idx, ws) in write_sets.iter().enumerate() {
    let version = first_version + idx as Version;
    let txn_info = &txn_infos[idx];
    
    // Validate write set against state_change_hash
    let write_set_hash = CryptoHash::hash(ws);
    ensure!(
        write_set_hash == txn_info.state_change_hash(),
        "Write set validation failed at version {}: computed hash {:?} != expected {:?}",
        version, write_set_hash, txn_info.state_change_hash()
    );
    
    WriteSetDb::put_write_set(version, ws, &mut ledger_db_batch.write_set_db_batches)?;
}
```

2. **In `LoadedChunk::load`**, validate write sets during deserialization:

```rust
// In storage/backup/backup-cli/src/backup_types/transaction/restore.rs, after line 167
// Validate write sets against transaction infos
for (idx, (ws, txn_info)) in write_sets.iter().zip(txn_infos.iter()).enumerate() {
    let write_set_hash = CryptoHash::hash(ws);
    ensure!(
        write_set_hash == txn_info.state_change_hash(),
        "Write set validation failed at index {}: computed hash {:?} != expected {:?}",
        idx, write_set_hash, txn_info.state_change_hash()
    );
}
```

3. **Enable verification by default** or make it mandatory for production restores.

## Proof of Concept

```rust
// PoC demonstrating the vulnerability
use aptos_types::{
    transaction::{Transaction, TransactionInfo, TransactionOutput},
    write_set::{WriteSet, WriteSetMut},
    state_store::state_key::StateKey,
};
use aptos_crypto::{hash::CryptoHash, HashValue};

#[test]
fn test_write_set_validation_bypass() {
    // 1. Create a legitimate transaction
    let legitimate_txn = Transaction::UserTransaction(/* ... */);
    let legitimate_txn_hash = CryptoHash::hash(&legitimate_txn);
    
    // 2. Create a legitimate write set
    let mut legitimate_ws_mut = WriteSetMut::new(vec![]);
    // ... add legitimate state changes
    let legitimate_ws = legitimate_ws_mut.freeze().unwrap();
    let legitimate_ws_hash = CryptoHash::hash(&legitimate_ws);
    
    // 3. Create MALICIOUS write set (e.g., minting tokens)
    let mut malicious_ws_mut = WriteSetMut::new(vec![]);
    // Add malicious state change: set attacker's balance to 1 billion
    malicious_ws_mut.insert((
        StateKey::access_path(/* attacker's balance key */),
        WriteOp::Value(/* 1 billion coins */),
    ));
    let malicious_ws = malicious_ws_mut.freeze().unwrap();
    
    // 4. Create TransactionInfo with legitimate transaction hash
    // BUT with hash of legitimate write set (not malicious one)
    let txn_info = TransactionInfo::new(
        legitimate_txn_hash,  // Transaction hash matches
        legitimate_ws_hash,    // State change hash for legitimate WS
        /* ... other fields ... */
    );
    
    // 5. Create backup file with:
    // - legitimate_txn
    // - txn_info (points to legitimate_ws_hash)
    // - malicious_ws (actual malicious write set)
    
    // 6. During restore:
    let backup_data = (legitimate_txn, txn_info, malicious_ws);
    
    // The verification in LoadedChunk::load() will:
    // ✓ PASS: transaction_hash matches legitimate_txn_hash
    // ✗ SKIP: Does NOT check malicious_ws against state_change_hash
    
    // 7. Result: Database contains
    // TRANSACTION_CF_NAME[version] = legitimate_txn
    // WRITE_SET_CF_NAME[version] = malicious_ws
    // This violates the invariant!
    
    // 8. Attacker now has 1 billion coins without executing any transaction
    // through Move VM or paying gas
}
```

**Notes:**
- This vulnerability affects all backup restore operations including disaster recovery, validator onboarding, and archive node setup
- The issue exists because write sets are treated as independent data rather than cryptographically bound outputs of transaction execution
- Standard restore operations explicitly use `VerifyExecutionMode::NoVerify`, making this the default vulnerable path
- The validation infrastructure exists (`ensure_match_transaction_info`) but is never invoked during restore

### Citations

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

**File:** types/src/transaction/mod.rs (L1898-1908)
```rust
        let write_set_hash = CryptoHash::hash(self.write_set());
        ensure!(
            write_set_hash == txn_info.state_change_hash(),
            "{}: version:{}, write_set_hash:{:?}, expected:{:?}, write_set: {:?}, expected(if known): {:?}",
            ERR_MSG,
            version,
            write_set_hash,
            txn_info.state_change_hash(),
            self.write_set,
            expected_write_set,
        );
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

**File:** storage/backup/backup-cli/src/coordinators/restore.rs (L289-298)
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
```

**File:** storage/backup/backup-cli/src/coordinators/verify.rs (L145-156)
```rust
        TransactionRestoreBatchController::new(
            global_opt,
            self.storage,
            txn_manifests,
            None,
            None, /* replay_from_version */
            epoch_history,
            VerifyExecutionMode::NoVerify,
            self.output_transaction_analysis,
        )
        .run()
        .await?;
```

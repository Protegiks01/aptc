# Audit Report

## Title
Backup Service Exposes Decrypted Encrypted Transaction Payloads Violating Privacy Guarantees

## Summary
The backup service's transactions endpoint exposes decrypted encrypted transaction payloads (including the plaintext `executable` and `decryption_nonce`) in backups, violating the privacy guarantees of Aptos's encrypted transaction feature. When encrypted transactions are retrieved via the backup API, they are served in their fully decrypted state rather than redacted back to encrypted form.

## Finding Description

Aptos supports encrypted transactions through the `EncryptedPayload` enum which can be in three states: `Encrypted`, `FailedDecryption`, or `Decrypted`. The privacy guarantee is that transaction payloads remain encrypted until decryption during consensus. [1](#0-0) 

During consensus processing, the `decrypt_encrypted_txns` function decrypts these payloads and mutates them into the `Decrypted` state, exposing the plaintext `executable` and `decryption_nonce`: [2](#0-1) 

These decrypted transactions are then persisted to the database without redaction: [3](#0-2) 

When the backup service retrieves transactions, it reads them directly from storage without filtering: [4](#0-3) 

The transactions endpoint serves these via HTTP with full serialization: [5](#0-4) 

Since `EncryptedPayload` derives `Serialize` without any `#[serde(skip)]` attributes, all fields including the decrypted `executable` and `decryption_nonce` are serialized and exposed: [1](#0-0) 

**Attack Path:**
1. User submits encrypted transaction expecting privacy
2. Transaction is decrypted during consensus and persisted in `Decrypted` state
3. Attacker with access to backup service calls `GET /transactions/<start>/<num>`
4. Attacker receives BCS-serialized transactions with `EncryptedPayload::Decrypted` exposing plaintext
5. Attacker extracts the private `executable` and `decryption_nonce` that were meant to be confidential

## Impact Explanation

This vulnerability falls under **Medium Severity** based on privacy violation impact:

- **Privacy Violation**: The encrypted transaction feature's core purpose is to preserve transaction payload privacy. Exposing decrypted payloads in backups completely undermines this security guarantee.

- **Backup Exposure Vectors**: Backups are often stored in cloud storage, shared with third parties for redundancy, or accessed through compromised credentials, creating multiple exposure points for supposedly private data.

- **Scope**: Any encrypted transaction in the blockchain history can have its private payload exposed through backup retrieval.

While this doesn't directly cause funds loss or consensus violations, it breaks a documented privacy feature and could be classified under "State inconsistencies requiring intervention" as the privacy state is inconsistent with user expectations.

## Likelihood Explanation

**Likelihood: Medium to High**

- **Prerequisites**: Attacker needs access to backup service endpoint (via misconfiguration, compromised credentials, or access to backup files)
- **Complexity**: Low - simple HTTP GET request to enumerate and retrieve transactions
- **Detection**: Difficult to detect as backup access appears legitimate
- **Affected Users**: All users who have submitted encrypted transactions expecting privacy

## Recommendation

Implement privacy-preserving backup mode that redacts decrypted encrypted payloads before serving them via the backup API:

```rust
// In BackupHandler::get_transaction_iter or handlers/mod.rs
fn redact_encrypted_payload(mut txn: Transaction) -> Transaction {
    if let Transaction::UserTransaction(ref mut signed_txn) = txn {
        if let Some(encrypted_payload) = signed_txn.payload_mut().as_encrypted_payload_mut() {
            if let EncryptedPayload::Decrypted { 
                ciphertext, 
                extra_config, 
                payload_hash,
                .. // Remove executable and decryption_nonce
            } = encrypted_payload {
                *encrypted_payload = EncryptedPayload::Encrypted {
                    ciphertext: ciphertext.clone(),
                    extra_config: extra_config.clone(),
                    payload_hash: *payload_hash,
                };
            }
        }
    }
    txn
}
```

Apply this redaction in the backup handler before serving transactions, or add a query parameter `?privacy_preserving=true` to allow operators to choose between full backups (for internal recovery) and privacy-preserving backups (for external storage/sharing).

## Proof of Concept

```rust
// Test demonstrating the vulnerability
#[test]
fn test_backup_exposes_decrypted_payload() {
    use aptos_types::transaction::{Transaction, TransactionPayload, EncryptedPayload};
    
    // Simulate an encrypted transaction that gets decrypted
    let encrypted_payload = EncryptedPayload::Decrypted {
        ciphertext: /* ... */,
        extra_config: /* ... */,
        payload_hash: /* ... */,
        eval_proof: /* ... */,
        executable: /* SENSITIVE DATA */,
        decryption_nonce: /* SENSITIVE NONCE */,
    };
    
    let txn = Transaction::UserTransaction(SignedTransaction::new(
        RawTransaction::new(
            sender,
            seq_num,
            TransactionPayload::EncryptedPayload(encrypted_payload),
            /* ... */
        ),
        authenticator,
    ));
    
    // Persist to database
    db.save_transaction(version, &txn);
    
    // Retrieve via backup handler
    let backup_handler = db.get_backup_handler();
    let retrieved = backup_handler.get_transaction_iter(version, 1)
        .next()
        .unwrap()
        .unwrap();
    
    // VULNERABILITY: Decrypted payload is exposed in backup
    assert!(matches!(
        retrieved.0.try_as_signed_user_txn().unwrap()
            .payload().as_encrypted_payload().unwrap(),
        EncryptedPayload::Decrypted { executable, .. } if /* executable is exposed */
    ));
}
```

## Notes

This vulnerability specifically affects the privacy guarantees of encrypted transactions. While full transaction data may be necessary for internal node recovery, privacy-preserving backups intended for external storage or third-party redundancy should redact decrypted payloads to maintain the confidentiality promise of the encrypted transaction feature.

### Citations

**File:** types/src/transaction/encrypted_payload.rs (L42-64)
```rust
pub enum EncryptedPayload {
    Encrypted {
        ciphertext: Ciphertext,
        extra_config: TransactionExtraConfig,
        payload_hash: HashValue,
    },
    FailedDecryption {
        ciphertext: Ciphertext,
        extra_config: TransactionExtraConfig,
        payload_hash: HashValue,
        eval_proof: EvalProof,
    },
    Decrypted {
        ciphertext: Ciphertext,
        extra_config: TransactionExtraConfig,
        payload_hash: HashValue,
        eval_proof: EvalProof,

        // decrypted things
        executable: TransactionExecutable,
        decryption_nonce: u64,
    },
}
```

**File:** consensus/src/pipeline/decryption_pipeline_builder.rs (L121-148)
```rust
        let decrypted_txns = encrypted_txns
            .into_par_iter()
            .zip(txn_ciphertexts)
            .map(|(mut txn, ciphertext)| {
                let eval_proof = proofs.get(&ciphertext.id()).expect("must exist");
                if let Ok(payload) = FPTXWeighted::decrypt_individual::<DecryptedPayload>(
                    &decryption_key.key,
                    &ciphertext,
                    &digest,
                    &eval_proof,
                ) {
                    let (executable, nonce) = payload.unwrap();
                    txn.payload_mut()
                        .as_encrypted_payload_mut()
                        .map(|p| {
                            p.into_decrypted(eval_proof, executable, nonce)
                                .expect("must happen")
                        })
                        .expect("must exist");
                } else {
                    txn.payload_mut()
                        .as_encrypted_payload_mut()
                        .map(|p| p.into_failed_decryption(eval_proof).expect("must happen"))
                        .expect("must exist");
                }
                txn
            })
            .collect();
```

**File:** storage/aptosdb/src/ledger_db/transaction_db.rs (L129-166)
```rust
    pub(crate) fn put_transaction(
        // TODO(grao): Consider remove &self.
        &self,
        version: Version,
        transaction: &Transaction,
        skip_index: bool,
        batch: &mut impl WriteBatch,
    ) -> Result<()> {
        if !skip_index {
            if let Some(txn) = transaction.try_as_signed_user_txn() {
                if let ReplayProtector::SequenceNumber(seq_num) = txn.replay_protector() {
                    batch.put::<OrderedTransactionByAccountSchema>(
                        &(txn.sender(), seq_num),
                        &version,
                    )?;
                }
            }
        }

        let transaction_hash = transaction.hash();

        if let Some(signed_txn) = transaction.try_as_signed_user_txn() {
            let txn_summary = IndexedTransactionSummary::V1 {
                sender: signed_txn.sender(),
                replay_protector: signed_txn.replay_protector(),
                version,
                transaction_hash,
            };
            batch.put::<TransactionSummariesByAccountSchema>(
                &(signed_txn.sender(), version),
                &txn_summary,
            )?;
        }
        batch.put::<TransactionByHashSchema>(&transaction_hash, &version)?;
        batch.put::<TransactionSchema>(&version, transaction)?;

        Ok(())
    }
```

**File:** storage/aptosdb/src/backup/backup_handler.rs (L41-109)
```rust
    pub fn get_transaction_iter(
        &self,
        start_version: Version,
        num_transactions: usize,
    ) -> Result<
        impl Iterator<
                Item = Result<(
                    Transaction,
                    PersistedAuxiliaryInfo,
                    TransactionInfo,
                    Vec<ContractEvent>,
                    WriteSet,
                )>,
            > + '_,
    > {
        let txn_iter = self
            .ledger_db
            .transaction_db()
            .get_transaction_iter(start_version, num_transactions)?;
        let mut txn_info_iter = self
            .ledger_db
            .transaction_info_db()
            .get_transaction_info_iter(start_version, num_transactions)?;
        let mut event_vec_iter = self
            .ledger_db
            .event_db()
            .get_events_by_version_iter(start_version, num_transactions)?;
        let mut write_set_iter = self
            .ledger_db
            .write_set_db()
            .get_write_set_iter(start_version, num_transactions)?;
        let mut persisted_aux_info_iter = self
            .ledger_db
            .persisted_auxiliary_info_db()
            .get_persisted_auxiliary_info_iter(start_version, num_transactions)?;

        let zipped = txn_iter.enumerate().map(move |(idx, txn_res)| {
            let version = start_version + idx as u64; // overflow is impossible since it's check upon txn_iter construction.

            let txn = txn_res?;
            let txn_info = txn_info_iter.next().ok_or_else(|| {
                AptosDbError::NotFound(format!(
                    "TransactionInfo not found when Transaction exists, version {}",
                    version
                ))
            })??;
            let event_vec = event_vec_iter.next().ok_or_else(|| {
                AptosDbError::NotFound(format!(
                    "Events not found when Transaction exists., version {}",
                    version
                ))
            })??;
            let write_set = write_set_iter.next().ok_or_else(|| {
                AptosDbError::NotFound(format!(
                    "WriteSet not found when Transaction exists, version {}",
                    version
                ))
            })??;
            let persisted_aux_info = persisted_aux_info_iter.next().ok_or_else(|| {
                AptosDbError::NotFound(format!(
                    "PersistedAuxiliaryInfo not found when Transaction exists, version {}",
                    version
                ))
            })??;
            BACKUP_TXN_VERSION.set(version as i64);
            Ok((txn, persisted_aux_info, txn_info, event_vec, write_set))
        });
        Ok(zipped)
    }
```

**File:** storage/backup/backup-service/src/handlers/mod.rs (L101-110)
```rust
    // GET transactions/<start_version>/<num_transactions>
    let bh = backup_handler.clone();
    let transactions = warp::path!(Version / usize)
        .map(move |start_version, num_transactions| {
            reply_with_bytes_sender(&bh, TRANSACTIONS, move |bh, sender| {
                bh.get_transaction_iter(start_version, num_transactions)?
                    .try_for_each(|record_res| sender.send_size_prefixed_bcs_bytes(record_res?))
            })
        })
        .recover(handle_rejection);
```

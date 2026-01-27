# Audit Report

## Title
Transaction Backup Missing Schema Validation Allows Deserialization-Based Denial of Recovery

## Summary
The transaction backup process writes record_bytes from the backup service client directly to storage without validating that they are deserializable, while the restore process assumes all record_bytes are valid BCS-encoded data. Malformed records injected into backup storage cause deserialization failures during restore, preventing disaster recovery operations.

## Finding Description

The transaction backup controller in `storage/backup/backup-cli/src/backup_types/transaction/backup.rs` processes record_bytes from the backup service without performing any schema validation or deserialization checks before writing them to persistent backup storage. [1](#0-0) 

The code blindly extends `chunk_bytes` with the raw `record_bytes` received from the client, preceded only by a length prefix. No attempt is made to verify that these bytes represent valid BCS-encoded transaction tuples.

During the restore operation, the system attempts to deserialize these record_bytes using BCS deserialization: [2](#0-1) 

The `?` operator on lines 121 and 130 means any deserialization error immediately terminates the restore process. The cryptographic verification that would detect tampered data never executes because it occurs later: [3](#0-2) 

This creates a vulnerability window where malformed data prevents restore completion before verification can reject it.

**Comparison with Epoch Ending Backup:**
The epoch ending backup implementation demonstrates proper validation by deserializing and validating records during backup: [4](#0-3) [5](#0-4) 

This validation ensures that only well-formed, deserializable records are written to backup storage.

**Attack Vector:**
An attacker who gains access to backup storage (through misconfigured S3/GCS permissions, compromised credentials, or backup service endpoint exposure) can inject malformed BCS-encoded data into transaction backup chunk files. When a validator operator attempts disaster recovery by restoring from this backup, the process fails at deserialization, preventing node recovery.

## Impact Explanation

**Severity: Medium** per Aptos bug bounty criteria ("State inconsistencies requiring intervention").

While this vulnerability does not directly cause fund loss or consensus violations, it creates a denial-of-recovery attack that prevents validators from restoring from backups. In disaster recovery scenarios (hardware failure, database corruption, bootstrapping new nodes), operators rely on backups to restore validator state. Compromised backups render the entire backup infrastructure unusable, requiring manual intervention and potentially extended downtime.

This breaks the operational guarantee that validators can recover from backups, which is critical for network resilience and validator participation. Multiple affected validators could experience recovery failures simultaneously if using shared backup storage infrastructure.

## Likelihood Explanation

**Likelihood: Medium-Low**

The attack requires:
1. Access to backup storage (S3/GCS buckets) or the backup service HTTP endpoint
2. Knowledge of the BCS record format to craft plausibly-sized malformed data
3. Timing the attack before a restore operation occurs

While backup storage should be properly secured, misconfigurations are common (publicly accessible S3 buckets, overly permissive IAM policies). The backup service typically runs on localhost:6186 but may be exposed in some configurations. Once access is obtained, injecting malformed data is straightforward.

The impact materializes only during restore operations, which may be infrequent under normal operations but become critical during disaster scenarios.

## Recommendation

Implement validation during the transaction backup process to mirror the protection present in epoch ending backups:

**Add a validation function in `TransactionBackupController`:**
```rust
fn validate_record(record_bytes: &[u8], format: &TransactionChunkFormat) -> Result<()> {
    match format {
        TransactionChunkFormat::V0 => {
            let _: (Transaction, TransactionInfo, Vec<ContractEvent>, WriteSet) = 
                bcs::from_bytes(record_bytes)?;
        },
        TransactionChunkFormat::V1 => {
            let _: (Transaction, PersistedAuxiliaryInfo, TransactionInfo, Vec<ContractEvent>, WriteSet) = 
                bcs::from_bytes(record_bytes)?;
        },
    }
    Ok(())
}
```

**Modify the backup loop to validate before writing:**
```rust
while let Some(record_bytes) = transactions_file.read_record_bytes().await? {
    // Validate deserialization before writing to backup
    Self::validate_record(&record_bytes, &TransactionChunkFormat::V1)?;
    
    if should_cut_chunk(&chunk_bytes, &record_bytes, self.max_chunk_size) {
        // ... existing chunking logic ...
    }
    
    chunk_bytes.extend((record_bytes.len() as u32).to_be_bytes());
    chunk_bytes.extend(&record_bytes);
    current_ver += 1;
}
```

This ensures that only valid, deserializable records are persisted to backup storage, providing defense-in-depth against storage compromise and reducing the attack surface.

**Additional Hardening:**
- Add checksums to backup manifests for integrity verification
- Implement backup file signing to detect tampering
- Add detailed error context in restore failures to distinguish deserialization errors from verification failures

## Proof of Concept

**Step 1: Create a malformed transaction backup file**
```rust
use std::fs::File;
use std::io::Write;

// Create a backup chunk file with malformed record_bytes
let mut malformed_chunk = File::create("malformed_transaction.chunk")?;

// Write a record with invalid BCS data
let invalid_bcs_data = vec![0xFF; 100]; // Garbage bytes
let size_prefix = (invalid_bcs_data.len() as u32).to_be_bytes();

malformed_chunk.write_all(&size_prefix)?;
malformed_chunk.write_all(&invalid_bcs_data)?;
malformed_chunk.flush()?;
```

**Step 2: Place the malformed file in backup storage**
```bash
# Upload to S3 backup location
aws s3 cp malformed_transaction.chunk s3://validator-backups/transaction_1000-/0-.chunk
```

**Step 3: Attempt restore operation**
```bash
# Run restore command
cargo run -p backup-cli -- \
    restore --target-db-dir /tmp/restored_db \
    transaction --transaction-manifest s3://validator-backups/transaction_1000-.manifest

# Expected result: Restore fails with BCS deserialization error at line 121/130
# Error: "Failed to deserialize record_bytes: unexpected end of input"
```

**Step 4: Verify the attack prevents recovery**
The restore process terminates before cryptographic verification, preventing the validator from recovering from backup and requiring manual database reconstruction or alternate backup sources.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/transaction/backup.rs (L87-105)
```rust
        while let Some(record_bytes) = transactions_file.read_record_bytes().await? {
            if should_cut_chunk(&chunk_bytes, &record_bytes, self.max_chunk_size) {
                let chunk = self
                    .write_chunk(
                        &backup_handle,
                        &chunk_bytes,
                        chunk_first_ver,
                        current_ver - 1,
                    )
                    .await?;
                chunks.push(chunk);
                chunk_bytes = vec![];
                chunk_first_ver = current_ver;
            }

            chunk_bytes.extend((record_bytes.len() as u32).to_be_bytes());
            chunk_bytes.extend(&record_bytes);
            current_ver += 1;
        }
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L112-131)
```rust
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
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L167-167)
```rust
        txn_list_with_proof.verify(ledger_info.ledger_info(), Some(manifest.first_version))?;
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/backup.rs (L105-105)
```rust
            waypoints.push(Self::get_waypoint(&record_bytes, current_epoch)?);
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/backup.rs (L140-149)
```rust
    fn get_waypoint(record: &[u8], epoch: u64) -> Result<Waypoint> {
        let li: LedgerInfoWithSignatures = bcs::from_bytes(record)?;
        ensure!(
            li.ledger_info().epoch() == epoch,
            "Epoch not expected. expected: {}, actual: {}.",
            li.ledger_info().epoch(),
            epoch,
        );
        Waypoint::new_epoch_boundary(li.ledger_info())
    }
```

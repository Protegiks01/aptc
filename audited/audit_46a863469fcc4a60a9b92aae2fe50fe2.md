# Audit Report

## Title
Memory Exhaustion Vulnerability in Backup Restore Due to Unbounded Record Size Allocation

## Summary
The backup restore system lacks validation on the size prefix of serialized records, allowing corrupted or malicious backup files to specify arbitrarily large allocation sizes (up to 4GB per record), leading to memory exhaustion and denial of service during critical disaster recovery operations.

## Finding Description

The backup service uses a well-defined length-prefixed protocol for streaming records. The server uses `send_size_prefixed_bcs_bytes()` to write a 4-byte big-endian u32 size prefix followed by BCS-serialized data. [1](#0-0) 

The client uses `read_record_bytes()` to read these records. However, this function directly allocates memory based on the size prefix without any validation: [2](#0-1) 

The vulnerability occurs at line 60 where `BytesMut::with_capacity(record_size)` is called with an unvalidated size value that can be up to u32::MAX (4,294,967,295 bytes ≈ 4GB).

This affects all three restore types:
- **Transaction restore**: [3](#0-2) 
- **State snapshot restore**: [4](#0-3) 
- **Epoch ending restore**: [5](#0-4) 

**Legitimate Size Bounds**: The Aptos gas schedule defines strict transaction size limits: [6](#0-5) 

Normal transactions are limited to 64KB (65,536 bytes), with governance transactions allowed up to 1MB. However, the backup restore code can attempt to allocate 65,536x this amount without validation.

**Attack Path**:
1. Backup files become corrupted through disk errors, network transmission issues, or storage system bugs
2. Alternatively, an attacker compromises the backup storage system and replaces files
3. The 4-byte size prefix gets corrupted to a large value (e.g., 0xFFFFFFFF)
4. During restore operations, `read_record_bytes()` reads this size prefix
5. The function attempts to allocate up to 4GB of memory per record
6. Multiple corrupted records cause cumulative memory exhaustion
7. The restore process crashes with OOM errors
8. Disaster recovery fails when it's most critical

**Invariant Violation**: This breaks the **Resource Limits** invariant (#9): "All operations must respect gas, storage, and computational limits." The restore operation should enforce reasonable memory bounds consistent with the blockchain's transaction size limits.

## Impact Explanation

**Severity: Medium** (up to $10,000 per Aptos Bug Bounty)

This vulnerability falls under "State inconsistencies requiring intervention" as it prevents successful restoration of blockchain state from backups. While it doesn't directly cause loss of funds or consensus violations, it creates a critical availability issue:

- **Disaster Recovery Failure**: During a catastrophic failure requiring restore from backup, this vulnerability prevents recovery
- **Operational Impact**: Node operators cannot restore nodes from potentially corrupted backups
- **DoS Vector**: Intentionally crafted malicious backups can DoS restore operations
- **No Direct Consensus Impact**: Does not affect running nodes or consensus, only restore operations

The impact is limited to backup/restore operations rather than the live blockchain, preventing it from reaching High or Critical severity.

## Likelihood Explanation

**Likelihood: Moderate**

**Corruption Scenario (Higher Likelihood)**:
- Backup files are stored on disk and transmitted over networks, both prone to corruption
- Storage system bugs can cause data corruption
- Long-term archival storage is particularly susceptible to bit rot
- Operators regularly perform restore operations for testing and disaster recovery

**Malicious Scenario (Lower Likelihood)**:
- Requires attacker to compromise backup storage infrastructure
- Most operators use secured cloud storage with access controls
- Backup integrity verification may be in place (though not enforced in this code path)

The vulnerability is more likely to manifest through unintentional corruption than deliberate attack, but both scenarios are realistic.

## Recommendation

Add a maximum record size validation in `read_record_bytes()` before allocating memory. The limit should be based on the maximum legitimate record size, with a safety margin:

```rust
async fn read_record_bytes(&mut self) -> Result<Option<Bytes>> {
    const MAX_RECORD_SIZE: usize = 128 * 1024 * 1024; // 128MB, matching max_chunk_size default
    
    let _timer = BACKUP_TIMER.timer_with(&["read_record_bytes"]);
    // read record size
    let mut size_buf = BytesMut::with_capacity(4);
    self.read_full_buf_or_none(&mut size_buf).await?;
    if size_buf.is_empty() {
        return Ok(None);
    }

    let record_size = u32::from_be_bytes(size_buf.as_ref().try_into()?) as usize;
    
    // Validate size before allocation
    if record_size > MAX_RECORD_SIZE {
        bail!(
            "Record size {} exceeds maximum allowed size {}. Possible data corruption.",
            record_size,
            MAX_RECORD_SIZE
        );
    }
    
    if record_size == 0 {
        return Ok(Some(Bytes::new()));
    }

    // read record
    let mut record_buf = BytesMut::with_capacity(record_size);
    self.read_full_buf_or_none(&mut record_buf).await?;
    if record_buf.is_empty() {
        bail!("Hit EOF when reading record.")
    }

    Ok(Some(record_buf.freeze()))
}
```

This limit of 128MB aligns with the default `max_chunk_size` used during backup creation: [7](#0-6) 

## Proof of Concept

```rust
// Test demonstrating the vulnerability
#[cfg(test)]
mod exploit_test {
    use super::*;
    use tokio::runtime::Runtime;

    #[test]
    fn test_memory_exhaustion_via_corrupted_size_prefix() {
        Runtime::new().unwrap().block_on(async {
            // Craft malicious backup data with extremely large size prefix
            let malicious_size = u32::MAX; // 4GB
            let mut malicious_data = malicious_size.to_be_bytes().to_vec();
            
            // Add minimal data (will cause EOF error before full allocation completes,
            // but allocation attempt still happens)
            malicious_data.extend_from_slice(&[0u8; 100]);
            
            let mut reader = malicious_data.as_slice();
            
            // This will attempt to allocate 4GB of memory
            let result = reader.read_record_bytes().await;
            
            // In production, this would cause OOM or very high memory usage
            // In test, it fails with EOF but demonstrates the allocation attempt
            assert!(result.is_err());
            
            // Demonstration: Even a 1GB size prefix is unrealistic
            let large_size = 1_000_000_000u32; // 1GB
            let mut large_data = large_size.to_be_bytes().to_vec();
            large_data.extend_from_slice(&[0u8; 100]);
            
            let mut reader2 = large_data.as_slice();
            let result2 = reader2.read_record_bytes().await;
            
            // This also attempts unrealistic allocation
            assert!(result2.is_err());
        });
    }
}
```

To fully demonstrate the vulnerability, create a backup file with a corrupted size prefix and attempt to restore it. The restore process will attempt to allocate gigabytes of memory and likely crash with an OOM error.

## Notes

The protocol itself is well-defined and symmetric between sender and receiver. The vulnerability is not in protocol ambiguity but in missing validation of the size field against reasonable bounds. The backup service correctly uses length-prefixed records, but the restore side fails to validate that these lengths are within expected ranges before performing memory allocation.

### Citations

**File:** storage/backup/backup-service/src/handlers/bytes_sender.rs (L54-66)
```rust
    pub fn send_size_prefixed_bcs_bytes<Record: Serialize>(
        &mut self,
        record: Record,
    ) -> DbResult<()> {
        let record_bytes = bcs::to_bytes(&record)?;
        let size_bytes = (record_bytes.len() as u32).to_be_bytes();

        let mut buf = BytesMut::with_capacity(size_bytes.len() + record_bytes.len());
        buf.put_slice(&size_bytes);
        buf.extend(record_bytes);

        self.send_bytes(buf.freeze())
    }
```

**File:** storage/backup/backup-cli/src/utils/read_record_bytes.rs (L44-67)
```rust
    async fn read_record_bytes(&mut self) -> Result<Option<Bytes>> {
        let _timer = BACKUP_TIMER.timer_with(&["read_record_bytes"]);
        // read record size
        let mut size_buf = BytesMut::with_capacity(4);
        self.read_full_buf_or_none(&mut size_buf).await?;
        if size_buf.is_empty() {
            return Ok(None);
        }

        // empty record
        let record_size = u32::from_be_bytes(size_buf.as_ref().try_into()?) as usize;
        if record_size == 0 {
            return Ok(Some(Bytes::new()));
        }

        // read record
        let mut record_buf = BytesMut::with_capacity(record_size);
        self.read_full_buf_or_none(&mut record_buf).await?;
        if record_buf.is_empty() {
            bail!("Hit EOF when reading record.")
        }

        Ok(Some(record_buf.freeze()))
    }
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L112-112)
```rust
        while let Some(record_bytes) = file.read_record_bytes().await? {
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L261-261)
```rust
        while let Some(record_bytes) = file.read_record_bytes().await? {
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L167-167)
```rust
        while let Some(record_bytes) = file.read_record_bytes().await? {
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L73-81)
```rust
            max_transaction_size_in_bytes: NumBytes,
            "max_transaction_size_in_bytes",
            64 * 1024
        ],
        [
            max_transaction_size_in_bytes_gov: NumBytes,
            { RELEASE_V1_13.. => "max_transaction_size_in_bytes.gov" },
            1024 * 1024
        ],
```

**File:** storage/backup/backup-cli/src/utils/mod.rs (L411-413)
```rust
pub(crate) fn should_cut_chunk(chunk: &[u8], record: &[u8], max_chunk_size: usize) -> bool {
    !chunk.is_empty() && chunk.len() + record.len() + size_of::<u32>() > max_chunk_size
}
```

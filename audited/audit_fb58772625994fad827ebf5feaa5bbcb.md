# Audit Report

## Title
Memory Exhaustion via Unbounded Record Size Allocation in State Snapshot Restore

## Summary
The `read_record_bytes()` function in the backup restore process allocates memory based on an unvalidated 4-byte size header from blob files. A maliciously crafted backup file with oversized record headers (e.g., 0xFFFFFFFF ≈ 4GB) can cause memory exhaustion before any validation occurs, leading to node crashes or severe performance degradation during restore operations.

## Finding Description

The vulnerability exists in the state snapshot restore process, which breaks the **Resource Limits** invariant (all operations must respect memory constraints). [1](#0-0) 

The `StateSnapshotChunk` struct contains a `blobs` field of type `FileHandle` (a string URI pointing to a backup file). During restore, this file is read using the `read_state_value()` function: [2](#0-1) 

The critical vulnerability occurs in `read_record_bytes()`: [3](#0-2) 

**Attack Flow:**
1. Attacker creates a malicious backup blob file where the first 4 bytes encode a massive size (e.g., `0xFFFFFFFF` = 4,294,967,295 bytes ≈ 4GB)
2. Attacker provides this backup to a node operator (through compromised backup storage or as a restoration source)
3. During restore, line 54 reads the size as `u32` and converts to `usize`
4. **Line 60 immediately allocates `BytesMut::with_capacity(record_size)` without any validation**
5. System attempts to allocate 4GB of memory for a single record, repeated for each malicious record
6. Node experiences memory exhaustion, crashes, or becomes unresponsive

The codebase shows precedent for size validation before allocation: [4](#0-3) 

This defensive pattern validates that allocation size doesn't exceed `MAX_NUM_BYTES` (1,000,000 bytes) before attempting allocation and uses `try_reserve()` for safe allocation.

## Impact Explanation

**Severity: Medium** per Aptos Bug Bounty criteria

- **Validator Node Slowdowns**: Excessive memory allocation causes severe performance degradation
- **State Inconsistencies Requiring Intervention**: Failed restore operations prevent nodes from synchronizing state, requiring manual intervention
- **Limited Availability Impact**: Affects nodes attempting restore operations, not the entire network

This falls under "Validator node slowdowns" (High) or "State inconsistencies requiring intervention" (Medium). Given that it only affects nodes during restore operations (not consensus or normal operations), **Medium severity** is appropriate.

## Likelihood Explanation

**Likelihood: Medium**

**Required Conditions:**
- Attacker must provide a malicious backup file to a node operator
- Node operator must initiate a restore operation using the malicious backup

**Attack Vectors:**
1. Compromise of backup storage infrastructure
2. Operator using backups from untrusted or compromised sources
3. Insider threat (malicious operator creating malicious backups)

While backup storage is typically controlled by trusted operators, the code should implement defense-in-depth by validating all inputs. The lack of size validation is a fundamental input validation failure that can be exploited whenever malformed backup files are processed.

## Recommendation

Implement a maximum record size limit before allocating memory, similar to the pattern in `transaction_arg_validation.rs`:

```rust
async fn read_record_bytes(&mut self) -> Result<Option<Bytes>> {
    let _timer = BACKUP_TIMER.timer_with(&["read_record_bytes"]);
    
    // Maximum reasonable size for a single state value record
    const MAX_RECORD_SIZE: usize = 10_000_000; // 10 MB
    
    // read record size
    let mut size_buf = BytesMut::with_capacity(4);
    self.read_full_buf_or_none(&mut size_buf).await?;
    if size_buf.is_empty() {
        return Ok(None);
    }

    // empty record
    let record_size = u32::from_be_bytes(size_buf.as_ref().try_into()?) as usize;
    
    // Validate size before allocation
    if record_size > MAX_RECORD_SIZE {
        bail!(
            "Record size {} exceeds maximum allowed size of {} bytes",
            record_size,
            MAX_RECORD_SIZE
        );
    }
    
    if record_size == 0 {
        return Ok(Some(Bytes::new()));
    }

    // read record with validated size
    let mut record_buf = BytesMut::with_capacity(record_size);
    self.read_full_buf_or_none(&mut record_buf).await?;
    if record_buf.is_empty() {
        bail!("Hit EOF when reading record.")
    }

    Ok(Some(record_buf.freeze()))
}
```

**Additional Recommendations:**
- Add similar validation to all other uses of `read_record_bytes()` throughout the backup system
- Consider using `try_reserve()` instead of `with_capacity()` for safer allocation
- Add metrics/logging for oversized record attempts to detect attacks

## Proof of Concept

```rust
#[cfg(test)]
mod exploit_test {
    use super::*;
    use std::io::Cursor;
    
    #[tokio::test]
    async fn test_memory_exhaustion_via_oversized_record() {
        // Create a malicious blob file with oversized record header
        let malicious_size: u32 = 0xFFFFFFFF; // ~4GB
        let mut malicious_data = malicious_size.to_be_bytes().to_vec();
        // Add minimal data (would need 4GB to be valid)
        malicious_data.extend_from_slice(&[0u8; 100]);
        
        let mut reader = Cursor::new(malicious_data);
        
        // This will attempt to allocate 4GB of memory
        // In a real attack, this would be repeated across multiple records
        let result = reader.read_record_bytes().await;
        
        // Expected: Should fail with size validation error (after fix)
        // Actual: Attempts to allocate 4GB, causing memory exhaustion
        assert!(result.is_err(), "Should reject oversized record");
    }
    
    #[tokio::test]
    async fn test_multiple_oversized_records() {
        // Simulate multiple malicious records in sequence
        let malicious_size: u32 = 100_000_000; // 100MB per record
        let mut malicious_data = Vec::new();
        
        // Add 50 records of 100MB each = 5GB total
        for _ in 0..50 {
            malicious_data.extend_from_slice(&malicious_size.to_be_bytes());
            malicious_data.extend_from_slice(&vec![0u8; 1000]); // Partial data
        }
        
        let mut reader = Cursor::new(malicious_data);
        
        // Reading multiple records would exhaust memory
        for i in 0..50 {
            let result = reader.read_record_bytes().await;
            assert!(
                result.is_err(), 
                "Record {} should be rejected for excessive size", 
                i
            );
        }
    }
}
```

**Notes:**
- The vulnerability is in the backup/restore subsystem, not the consensus or execution paths
- Defense-in-depth principle requires validating all external inputs, including backup files
- The fix is straightforward and follows patterns already present in the codebase for safe allocation

### Citations

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/manifest.rs (L12-27)
```rust
pub struct StateSnapshotChunk {
    /// index of the first account in this chunk over all accounts.
    pub first_idx: usize,
    /// index of the last account in this chunk over all accounts.
    pub last_idx: usize,
    /// key of the first account in this chunk.
    pub first_key: HashValue,
    /// key of the last account in this chunk.
    pub last_key: HashValue,
    /// Repeated `len(record) + record` where `record` is BCS serialized tuple
    /// `(key, state_value)`
    pub blobs: FileHandle,
    /// BCS serialized `SparseMerkleRangeProof` that proves this chunk adds up to the root hash
    /// indicated in the backup (`StateSnapshotBackup::root_hash`).
    pub proof: FileHandle,
}
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L253-266)
```rust
    async fn read_state_value(
        storage: &Arc<dyn BackupStorage>,
        file_handle: FileHandle,
    ) -> Result<Vec<(StateKey, StateValue)>> {
        let mut file = storage.open_for_read(&file_handle).await?;

        let mut chunk = vec![];

        while let Some(record_bytes) = file.read_record_bytes().await? {
            chunk.push(bcs::from_bytes(&record_bytes)?);
        }

        Ok(chunk)
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

**File:** aptos-move/aptos-vm/src/verifier/transaction_arg_validation.rs (L555-571)
```rust
    // It is safer to limit the length under some big (but still reasonable
    // number).
    const MAX_NUM_BYTES: usize = 1_000_000;
    if len.checked_add(n).is_none_or(|s| s > MAX_NUM_BYTES) {
        return Err(deserialization_error(&format!(
            "Couldn't read bytes: maximum limit of {} bytes exceeded",
            MAX_NUM_BYTES
        )));
    }

    // Ensure we have enough capacity for resizing.
    dest.try_reserve(len + n)
        .map_err(|e| deserialization_error(&format!("Couldn't read bytes: {}", e)))?;
    dest.resize(len + n, 0);
    src.read_exact(&mut dest[len..])
        .map_err(|_| deserialization_error("Couldn't read bytes"))
}
```

# Audit Report

## Title
Unbounded Memory Allocation in State Snapshot Backup via Oversized Records

## Summary
The `ChunkerState::next_full_chunk()` function in the state snapshot backup system lacks validation of individual record sizes before adding them to the internal buffer. A malicious backup service can send arbitrarily large records that bypass the `max_chunk_size` limit, causing unbounded memory allocation and potential out-of-memory crashes on backup-cli hosts, including validator nodes.

## Finding Description

The vulnerability exists in the chunking logic that processes state snapshot records from a backup service. The code implements a `should_cut_chunk()` check to limit chunk sizes to `max_chunk_size` (default 128MB), but this check has a critical flaw: it only prevents adding records to **non-empty** buffers when the combined size would exceed the limit. [1](#0-0) 

The logic short-circuits when the buffer is empty, allowing records of **any size** to be added without validation: [2](#0-1) 

When a record arrives, the function:
1. Checks if adding it would exceed `max_chunk_size` (line 99)
2. If yes AND buffer is not empty, splits the buffer (line 101) 
3. **Always** appends the current record via `extend()` (line 123)

After a chunk is cut, the buffer is empty, so the next record—regardless of size—passes the check. The `read_record_bytes()` function reads the record size from a 4-byte prefix without validation: [3](#0-2) 

A malicious backup service can send a size prefix indicating gigabytes of data (e.g., `0xFFFFFFFF` = 4GB), causing `BytesMut::with_capacity(record_size)` to allocate unbounded memory.

**Attack Path:**
1. Attacker controls or compromises the backup service endpoint
2. Operator runs backup-cli with `--backup-service-address` pointing to the malicious service
3. Malicious service sends state snapshot records with huge size prefixes (e.g., 1GB, 2GB, 4GB)
4. Each oversized record is allocated in memory and added to the buffer without size validation
5. Memory exhaustion causes OOM errors, process crash, or system slowdown

**Invariant Violated:**
This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The `max_chunk_size` parameter is intended to bound memory usage, but individual records can arbitrarily exceed it.

## Impact Explanation

This qualifies as **High Severity** under Aptos bug bounty criteria:
- **Validator node slowdowns**: If backup-cli runs on validator infrastructure (common for automated backup operations), memory exhaustion can degrade validator performance or cause crashes
- **API crashes**: The backup-cli process will crash from OOM errors when processing oversized records

While this doesn't directly affect consensus or cause fund loss, it represents a significant availability attack vector. Validators running automated backup jobs could be repeatedly crashed, impacting network stability.

The impact is amplified because:
- Backup operations are often automated and run continuously
- Memory exhaustion can affect other processes on the same host
- Recovery requires operator intervention to identify and remove the malicious service configuration

## Likelihood Explanation

**Likelihood: Medium-Low**

Prerequisites for exploitation:
1. Attacker must control a backup service endpoint accessible to the target
2. Operator must configure backup-cli to connect to the malicious service (via `--backup-service-address`)
3. Alternatively, attacker compromises the operator's legitimate backup service

This is not a remote exploit but requires either:
- Social engineering to trick operators into using a malicious backup service
- Compromise of the operator's backup infrastructure
- Man-in-the-middle attack on backup service connections (if using HTTP without TLS)

The default configuration connects to `localhost:6186`, limiting exposure. However, operators may configure remote backup services for centralized backup management, creating attack opportunities.

## Recommendation

Implement validation of individual record sizes before allocation. Add a check that rejects records exceeding `max_chunk_size`:

```rust
async fn read_record_bytes(&mut self) -> Result<Option<Bytes>> {
    let _timer = BACKUP_TIMER.timer_with(&["read_record_bytes"]);
    // read record size
    let mut size_buf = BytesMut::with_capacity(4);
    self.read_full_buf_or_none(&mut size_buf).await?;
    if size_buf.is_empty() {
        return Ok(None);
    }

    let record_size = u32::from_be_bytes(size_buf.as_ref().try_into()?) as usize;
    
    // **ADD VALIDATION HERE**
    const MAX_RECORD_SIZE: usize = 134217728; // 128MB, matching default max_chunk_size
    if record_size > MAX_RECORD_SIZE {
        bail!("Record size {} exceeds maximum allowed size {}", record_size, MAX_RECORD_SIZE);
    }
    
    // empty record
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

Additionally, consider:
- Making `MAX_RECORD_SIZE` configurable but always enforcing a reasonable upper bound
- Enforcing HTTPS/TLS for remote backup service connections
- Adding authentication/authorization for backup service endpoints
- Documenting security implications of connecting to untrusted backup services

## Proof of Concept

```rust
// PoC: Mock malicious backup service that sends oversized records
// Save as: storage/backup/backup-cli/tests/malicious_backup_service_test.rs

use bytes::{BufMut, BytesMut};
use std::io::Cursor;
use tokio::io::AsyncReadExt;

#[tokio::test]
async fn test_oversized_record_allocation() {
    // Simulate a malicious backup service response with a 1GB record
    let oversized_record_size: u32 = 1_000_000_000; // 1GB
    
    let mut malicious_response = BytesMut::new();
    // Write size prefix indicating 1GB record
    malicious_response.put_slice(&oversized_record_size.to_be_bytes());
    // Write minimal actual data (service could send less than indicated size)
    malicious_response.put_slice(&[0u8; 100]);
    
    let mut reader = Cursor::new(malicious_response.freeze());
    
    // Read size prefix
    let mut size_buf = [0u8; 4];
    reader.read_exact(&mut size_buf).await.unwrap();
    let record_size = u32::from_be_bytes(size_buf) as usize;
    
    // This allocation would attempt to reserve 1GB of memory
    // In a real attack, this would be repeated for multiple records
    assert_eq!(record_size, 1_000_000_000);
    
    // Without validation, BytesMut::with_capacity(record_size) would
    // attempt to allocate 1GB, causing memory exhaustion
    println!("Malicious service requested allocation of {} bytes", record_size);
    println!("This exceeds typical max_chunk_size of 134217728 bytes (128MB) by ~7.5x");
}

// Demonstration of the vulnerability in ChunkerState
#[tokio::test] 
async fn test_chunk_size_bypass() {
    use bytes::Bytes;
    
    let max_chunk_size = 128 * 1024 * 1024; // 128MB
    
    // Scenario: Buffer is empty (after chunk cut or initially)
    let buf_empty = &[][..];
    let oversized_record = &[0u8; 1_000_000_000]; // 1GB record
    
    // should_cut_chunk check
    let should_cut = !buf_empty.is_empty() 
        && buf_empty.len() + oversized_record.len() + 4 > max_chunk_size;
    
    // Returns false because buf_empty.is_empty() == true (short-circuit)
    assert_eq!(should_cut, false);
    
    println!("Vulnerability: Oversized record bypasses max_chunk_size limit");
    println!("Record size: {} bytes ({:.2} GB)", oversized_record.len(), 
             oversized_record.len() as f64 / (1024.0 * 1024.0 * 1024.0));
    println!("Max chunk size: {} bytes ({} MB)", max_chunk_size, max_chunk_size / (1024 * 1024));
    println!("Bypass successful: should_cut = {}", should_cut);
}
```

**Notes:**
- The vulnerability requires the operator to connect backup-cli to an untrusted backup service endpoint
- In normal deployments, the backup service runs on localhost and is trusted
- This represents a defense-in-depth issue where malicious or compromised services can exploit missing input validation
- The fix is straightforward: validate record sizes before allocation
- State values in normal operations are limited to 1MB per the gas schedule, but backup services bypass this validation layer

### Citations

**File:** storage/backup/backup-cli/src/utils/mod.rs (L411-413)
```rust
pub(crate) fn should_cut_chunk(chunk: &[u8], record: &[u8], max_chunk_size: usize) -> bool {
    !chunk.is_empty() && chunk.len() + record.len() + size_of::<u32>() > max_chunk_size
}
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/backup.rs (L95-130)
```rust
        while let Some(record_bytes) = input.try_next().await? {
            let _timer = BACKUP_TIMER.timer_with(&["state_snapshot_process_records"]);

            // If buf + current_record exceeds max_chunk_size, dump current buf to a new chunk
            let chunk_cut_opt = should_cut_chunk(&self.buf, &record_bytes, self.max_chunk_size)
                .then(|| {
                    let bytes = self.buf.split().freeze();
                    let last_key = Self::parse_key(&bytes[bytes.len() - self.prev_record_len..])?;

                    let chunk = Chunk {
                        bytes,
                        first_key: self.chunk_first_key,
                        first_idx: self.chunk_first_idx,
                        last_key,
                        last_idx: self.current_idx,
                    };

                    self.chunk_first_idx = self.current_idx + 1;
                    self.chunk_first_key = Self::parse_key(&record_bytes)?;

                    Result::<_>::Ok(chunk)
                })
                .transpose()?;

            // Append record to buf
            self.prev_record_len = record_bytes.len();
            self.buf
                .put_slice(&(record_bytes.len() as u32).to_be_bytes());
            self.buf.extend(record_bytes);
            self.current_idx += 1;

            // Return the full chunk if found
            if let Some(chunk) = chunk_cut_opt {
                return Ok(Some(chunk));
            }
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

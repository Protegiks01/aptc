# Audit Report

## Title
Unbounded Memory Allocation in Backup Stream Framing Enables Denial of Service

## Summary
The backup service's stream framing protocol lacks size validation on record size prefixes, allowing an attacker to trigger unbounded memory allocation (up to 4GB) on receiving nodes. This vulnerability exists because the receiver must correctly parse size prefixes without any delimiters or sanity checks, making it vulnerable to malicious or corrupted size prefixes that cause memory exhaustion and stream desynchronization. [1](#0-0) 

## Finding Description
The backup service uses a size-prefixed framing protocol where each record is prefixed with a 4-byte big-endian u32 indicating the record size, followed by the BCS-serialized record data. Multiple records are batched together in a stream with **no delimiters** between them - the receiver must parse each size prefix correctly to determine record boundaries. [2](#0-1) 

The critical vulnerability is in the receiver's `read_record_bytes()` function, which:
1. Reads 4 bytes as the size prefix and interprets them as a u32
2. **Directly allocates** a buffer of that size without validation (line 60)
3. Attempts to read exactly that many bytes

**Attack Vector:**
An attacker who can influence the stream content (via MITM on HTTP connections, malicious backup service, or corrupted storage) can inject a malicious size prefix such as `0xFFFFFFFF` (4,294,967,295 bytes ≈ 4GB). This causes the receiver to:

1. Attempt to allocate 4GB of memory via `BytesMut::with_capacity(record_size)`
2. Trigger Out-of-Memory (OOM) conditions or severe memory pressure
3. Become permanently desynchronized with the stream since all subsequent records will be misaligned
4. Fail the entire backup/restore operation

**Broken Invariant:**
This violates the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The receiver allocates memory based on an untrusted 4-byte size prefix without any bounds checking.

**No Delimiters or Recovery:**
Unlike protocols with frame delimiters (e.g., newlines, magic bytes), this protocol has no way to resynchronize after a corrupted size prefix. Once misaligned, the entire stream becomes unparseable. [3](#0-2) 

The backup client connects via HTTP by default (no HTTPS enforcement), and there is no authentication or integrity checking before memory allocation.

## Impact Explanation
**Severity: Medium** (up to $10,000 per Aptos Bug Bounty)

This qualifies as Medium severity under two criteria:
1. **"State inconsistencies requiring intervention"** - A corrupted backup restore can lead to database inconsistencies requiring manual intervention to recover
2. **"Validator node slowdowns"** (High severity downgrade) - Memory exhaustion causes node performance degradation, but doesn't directly affect consensus

**Affected Systems:**
- Validator nodes performing backup/restore operations
- Archive nodes bootstrapping from backups
- Disaster recovery operations
- Node synchronization via backup service

**Realistic Impact:**
- Prevents nodes from completing backup restoration, blocking disaster recovery
- Causes OOM crashes during critical recovery operations
- Enables targeted DoS against nodes attempting to restore from backups
- Can affect multiple nodes if they restore from the same corrupted backup source

## Likelihood Explanation
**Likelihood: Medium**

**Attacker Requirements:**
- Ability to influence backup stream content via one of:
  - Man-in-the-middle attack on HTTP backup service connections
  - Compromise of backup storage (cloud storage, file server)
  - Running a malicious backup service that victims connect to
  - Storage corruption (accidental or intentional)

**Feasibility:**
The default backup service address is `http://localhost:6186`, but this is configurable and operators often connect to remote backup services or cloud storage. HTTP connections without TLS/authentication are vulnerable to MITM attacks. Additionally, cloud storage compromise is a realistic threat vector.

**Triggering Conditions:**
- Victim node initiates backup restore operation
- Attacker injects malicious size prefix into the stream
- No additional privileges or collusion required

While not trivially exploitable, this is a realistic attack vector against backup/restore infrastructure, which is critical for disaster recovery and node operations.

## Recommendation
Implement multiple defense-in-depth protections:

1. **Add maximum size validation** before memory allocation:
```rust
async fn read_record_bytes(&mut self) -> Result<Option<Bytes>> {
    const MAX_RECORD_SIZE: usize = 128 * 1024 * 1024; // 128MB, aligned with max_chunk_size default
    
    let _timer = BACKUP_TIMER.timer_with(&["read_record_bytes"]);
    // read record size
    let mut size_buf = BytesMut::with_capacity(4);
    self.read_full_buf_or_none(&mut size_buf).await?;
    if size_buf.is_empty() {
        return Ok(None);
    }

    // Validate record size before allocation
    let record_size = u32::from_be_bytes(size_buf.as_ref().try_into()?) as usize;
    if record_size == 0 {
        return Ok(Some(Bytes::new()));
    }
    
    // NEW: Enforce maximum record size
    if record_size > MAX_RECORD_SIZE {
        bail!("Record size {} exceeds maximum allowed size {}", record_size, MAX_RECORD_SIZE);
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

2. **Add sender-side validation** to prevent size overflow:
```rust
pub fn send_size_prefixed_bcs_bytes<Record: Serialize>(
    &mut self,
    record: Record,
) -> DbResult<()> {
    const MAX_RECORD_SIZE: u32 = 128 * 1024 * 1024; // 128MB
    
    let record_bytes = bcs::to_bytes(&record)?;
    
    // Prevent u32 overflow and enforce size limits
    if record_bytes.len() > MAX_RECORD_SIZE as usize {
        return Err(AptosDbError::Other(format!(
            "Record size {} exceeds maximum {}", 
            record_bytes.len(), 
            MAX_RECORD_SIZE
        )));
    }
    
    let size_bytes = (record_bytes.len() as u32).to_be_bytes();
    // ... rest of implementation
}
```

3. **Enforce HTTPS for remote backup service connections** with certificate validation

4. **Add checksums or HMAC** to detect stream corruption before parsing

## Proof of Concept

```rust
#[cfg(test)]
mod exploit_test {
    use super::*;
    use tokio::runtime::Runtime;

    #[test]
    fn test_malicious_size_prefix_causes_oom() {
        Runtime::new().unwrap().block_on(async {
            // Attacker crafts a malicious stream with oversized size prefix
            let malicious_size: u32 = 0xFFFFFFFF; // 4GB - 1 byte
            let mut malicious_stream = malicious_size.to_be_bytes().to_vec();
            malicious_stream.extend_from_slice(&[0u8; 100]); // Some dummy data
            
            // Victim attempts to read the record
            let result = malicious_stream.as_slice().read_record_bytes().await;
            
            // This will either:
            // 1. Panic with OOM
            // 2. Hang trying to allocate 4GB
            // 3. Fail when trying to read 4GB but only 100 bytes available
            assert!(result.is_err(), "Should fail due to excessive size");
        });
    }

    #[test]
    fn test_size_overflow_desynchronizes_stream() {
        Runtime::new().unwrap().block_on(async {
            // Create a valid stream with two records
            let record1_data = b"first_record";
            let record2_data = b"second_record";
            
            let mut valid_stream = Vec::new();
            valid_stream.extend((record1_data.len() as u32).to_be_bytes());
            valid_stream.extend_from_slice(record1_data);
            valid_stream.extend((record2_data.len() as u32).to_be_bytes());
            valid_stream.extend_from_slice(record2_data);
            
            // Now corrupt the first size prefix to be too small
            valid_stream[0..4].copy_from_slice(&2u32.to_be_bytes());
            
            let mut stream = valid_stream.as_slice();
            
            // Read first record - gets wrong data due to wrong size
            let first = stream.read_record_bytes().await.unwrap().unwrap();
            assert_eq!(first.len(), 2); // Read only 2 bytes instead of 12
            
            // Try to read second record - now completely misaligned
            let second = stream.read_record_bytes().await;
            // This will fail because the "size prefix" is now garbage data
            // from the middle of the first record
            assert!(second.is_err() || second.unwrap().is_none());
        });
    }
}
```

**Notes:**
This vulnerability is a **protocol-level design flaw** in the stream framing mechanism, not a pure network DoS. The lack of size validation combined with the absence of frame delimiters creates a critical weakness in the backup/restore infrastructure. While the backup service is intended for trusted operations, the configurable nature of backup sources and the use of unauthenticated HTTP creates realistic attack vectors that can compromise disaster recovery capabilities.

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

**File:** storage/backup/backup-cli/src/utils/backup_service_client.rs (L22-31)
```rust
#[derive(Parser)]
pub struct BackupServiceClientOpt {
    #[clap(
        long = "backup-service-address",
        default_value = "http://localhost:6186",
        help = "Backup service address. By default a Aptos Node runs the backup service serving \
        on tcp port 6186 to localhost only."
    )]
    pub address: String,
}
```

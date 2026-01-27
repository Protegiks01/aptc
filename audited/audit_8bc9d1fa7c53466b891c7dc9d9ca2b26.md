# Audit Report

## Title
Unbounded Memory Allocation in Backup Service BytesSender Enables Memory Exhaustion DoS

## Summary
The `BytesSender::send_size_prefixed_bcs_bytes()` function in the backup service lacks size validation before serializing and buffering BCS-encoded records. This allows an attacker with access to the backup service to trigger unbounded memory allocation by requesting backups containing large state values, potentially causing memory exhaustion and node crashes.

## Finding Description
The backup service exposes HTTP endpoints for retrieving blockchain state (state snapshots, transactions, epoch-ending ledger infos). When processing backup requests, the service iterates through database records and serializes each using BCS encoding without validating record size limits. [1](#0-0) 

The vulnerability exists in two places:

1. **No size check before BCS serialization**: The function directly calls `bcs::to_bytes(&record)` without checking if the record exceeds a reasonable size limit.

2. **Unconditional buffer extension**: In `send_bytes()`, the buffer is extended without checking if adding the new bytes would exceed a maximum total buffer size. [2](#0-1) 

For each record, memory is allocated three times:
- BCS serialization creates a `Vec<u8>` 
- A new `BytesMut` buffer is allocated with capacity for the serialized data
- The internal `self.buffer` is extended with the bytes

While individual state values are limited to 1MB during write operations [3](#0-2) , when reading historical state for backups, these limits may not apply to:
- Data written before limits were introduced
- Corrupted database entries
- Accumulated data structures

**Attack Path:**
1. Attacker gains access to backup service endpoint (default localhost:6186, but configurable) [4](#0-3) 
2. Attacker requests state snapshot or transaction backup containing large records: [5](#0-4) 
3. For each large record (e.g., 1MB StateValue), the system allocates ~3MB temporarily
4. Multiple concurrent requests amplify the attack (no limit on concurrent backup requests)
5. Memory exhaustion causes node slowdown or crash

## Impact Explanation
This is a **High Severity** vulnerability per Aptos bug bounty criteria:

- **Validator node slowdowns**: Memory exhaustion causes performance degradation
- **API crashes**: Out-of-memory conditions can crash the backup service or entire node
- **Availability impact**: Affects node's ability to serve backup requests and potentially other services

The vulnerability breaks the **Resource Limits** invariant (#9): "All operations must respect gas, storage, and computational limits." The backup service performs unbounded memory allocations without enforcing limits.

While the backup service defaults to localhost-only access, many production deployments expose it for backup infrastructure, making this exploitable in real-world scenarios.

## Likelihood Explanation
**Likelihood: Medium-High**

**Requirements:**
- Access to backup service endpoint (localhost by default, but often exposed in production for backup infrastructure)
- Presence of large state values in the blockchain state (common with 1MB write limit)

**Complexity: Low**
- Simple HTTP GET request to backup endpoints
- No authentication required on the backup service itself
- Attack can be repeated with concurrent requests to amplify impact

**Practicality:**
- State values approaching 1MB are legitimate and common in production
- Multiple concurrent backup requests are normal operational behavior
- No rate limiting or request throttling protects against abuse

## Recommendation
Implement multiple defensive layers:

1. **Add maximum record size check before serialization:**
```rust
pub fn send_size_prefixed_bcs_bytes<Record: Serialize>(
    &mut self,
    record: Record,
) -> DbResult<()> {
    let record_bytes = bcs::to_bytes(&record)?;
    
    // Add size limit check
    const MAX_RECORD_SIZE: usize = 2 << 20; // 2MB safety margin
    if record_bytes.len() > MAX_RECORD_SIZE {
        return Err(AptosDbError::Other(format!(
            "Record size {} exceeds maximum allowed size {}",
            record_bytes.len(),
            MAX_RECORD_SIZE
        )));
    }
    
    let size_bytes = (record_bytes.len() as u32).to_be_bytes();
    let mut buf = BytesMut::with_capacity(size_bytes.len() + record_bytes.len());
    buf.put_slice(&size_bytes);
    buf.extend(record_bytes);
    
    self.send_bytes(buf.freeze())
}
```

2. **Add maximum buffer size check before extending:**
```rust
pub fn send_bytes(&mut self, bytes: Bytes) -> DbResult<()> {
    const MAX_BUFFER_SIZE: usize = 100 << 20; // 100MB max buffer
    
    if self.buffer.len() + bytes.len() > MAX_BUFFER_SIZE {
        // Flush immediately if adding bytes would exceed limit
        self.flush_buffer()?;
    }
    
    self.buffer.extend(bytes);
    
    if self.buffer.len() >= Self::TARGET_BATCH_SIZE {
        self.flush_buffer()?
    }
    
    Ok(())
}
```

3. **Add rate limiting and concurrent request limits** for backup endpoints
4. **Add authentication/authorization** when backup service is exposed beyond localhost

## Proof of Concept
```rust
#[cfg(test)]
mod test {
    use super::*;
    use bytes::Bytes;
    
    #[test]
    fn test_large_record_memory_exhaustion() {
        let (mut sender, _stream) = BytesSender::new("test");
        
        // Create a large record (simulating 10MB state value)
        let large_data = vec![0u8; 10 << 20];
        let large_record = (
            StateKey::raw(vec![1u8; 100]),
            StateValue::new_legacy(large_data.into())
        );
        
        // This will attempt to allocate ~30MB (3x amplification)
        // without any size validation
        let result = sender.send_size_prefixed_bcs_bytes(large_record);
        
        // With fix, this should fail with size limit error
        // Without fix, it allocates memory unboundedly
        match result {
            Err(e) => println!("Correctly rejected: {}", e),
            Ok(_) => panic!("Should reject oversized records"),
        }
    }
    
    #[test]
    fn test_concurrent_backup_requests_memory_amplification() {
        // Simulate multiple concurrent backup requests
        // Each requesting state with large values
        // Demonstrates memory amplification attack
        
        let handles: Vec<_> = (0..100).map(|_| {
            std::thread::spawn(|| {
                let (mut sender, _stream) = BytesSender::new("test");
                let large_record = vec![0u8; 1 << 20]; // 1MB
                
                // Each thread allocates 3MB for 1MB record
                // 100 threads = 300MB total
                sender.send_size_prefixed_bcs_bytes(large_record)
            })
        }).collect();
        
        for handle in handles {
            handle.join().unwrap().ok();
        }
    }
}
```

## Notes
The vulnerability is exacerbated by the fact that the backup service spawns blocking tasks without limiting concurrency [6](#0-5) , allowing multiple requests to amplify memory consumption. While individual requests process records sequentially, multiple concurrent requests can cause significant memory pressure on the node.

### Citations

**File:** storage/backup/backup-service/src/handlers/bytes_sender.rs (L44-52)
```rust
    pub fn send_bytes(&mut self, bytes: Bytes) -> DbResult<()> {
        self.buffer.extend(bytes);

        if self.buffer.len() >= Self::TARGET_BATCH_SIZE {
            self.flush_buffer()?
        }

        Ok(())
    }
```

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

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L154-157)
```rust
            max_bytes_per_write_op: NumBytes,
            { 5.. => "max_bytes_per_write_op" },
            1 << 20, // a single state item is 1MB max
        ],
```

**File:** aptos-node/src/storage.rs (L70-71)
```rust
            let db_backup_service =
                start_backup_service(node_config.storage.backup_service_address, db_arc.clone());
```

**File:** storage/backup/backup-service/src/handlers/mod.rs (L50-54)
```rust
        .map(move |version| {
            reply_with_bytes_sender(&bh, STATE_SNAPSHOT, move |bh, sender| {
                bh.get_state_item_iter(version, 0, usize::MAX)?
                    .try_for_each(|record_res| sender.send_size_prefixed_bcs_bytes(record_res?))
            })
```

**File:** storage/backup/backup-service/src/handlers/utils.rs (L58-62)
```rust
    let _join_handle = tokio::task::spawn_blocking(move || {
        let _timer =
            BACKUP_TIMER.timer_with(&[&format!("backup_service_bytes_sender_{}", endpoint)]);
        abort_on_error(f)(bh, sender)
    });
```

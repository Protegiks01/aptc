# Audit Report

## Title
Concurrent Decompression Memory Exhaustion in Network Message Deserialization

## Summary
The network layer's concurrent message deserialization lacks global memory limits, allowing attackers to exhaust node memory by sending many compressed messages that expand to maximum size during decompression. While each message respects individual size limits, concurrent processing multiplies memory usage without back-pressure mechanisms.

## Finding Description

The vulnerability exists in the network message deserialization pipeline where compressed messages are processed concurrently without global memory accounting.

**Attack Flow:**

1. Attacker establishes multiple inbound connections (up to `MAX_INBOUND_CONNECTIONS = 100`) [1](#0-0) 

2. Attacker sends highly compressed messages exploiting compression amplification:
   - Small compressed payload (e.g., 1 MiB of repetitive data)
   - Decompresses to `MAX_APPLICATION_MESSAGE_SIZE` (~61.9 MiB) [2](#0-1) 

3. Messages are queued in channels with capacity `NETWORK_CHANNEL_SIZE = 1024` per (PeerId, ProtocolId) [3](#0-2) 

4. Deserialization occurs concurrently via `spawn_blocking` with concurrency limited to `num_cpus::get()` (typically 16-32 on servers) [4](#0-3) 

5. Each deserialization task calls `ProtocolId::from_bytes()` which for compressed protocols invokes decompression [5](#0-4) 

6. Decompression allocates a buffer of the full decompressed size: `let mut raw_data = vec![0u8; decompressed_size];` [6](#0-5) 

7. The decompressed size is only validated against `max_size` (MAX_APPLICATION_MESSAGE_SIZE), not against global memory limits [7](#0-6) 

**Memory Amplification:**
- Concurrent deserialization tasks: `num_cpus::get()` (e.g., 16)
- Memory per decompression: ~61.9 MiB
- Total concurrent decompression memory: 16 × 61.9 MiB ≈ 990 MiB
- Plus BCS-deserialized objects, queued messages, and other allocations

**Compression Amplification Bypass:**
The attacker bypasses rate limiting (100 KiB/s per IP) by sending small compressed payloads that expand dramatically. A 1 MiB compressed message takes only 10 seconds to send but allocates 61.9 MiB during decompression—a 61.9× amplification. [8](#0-7) 

**Missing Protection:**
The network layer configures concurrent deserialization tasks but provides no memory-based back-pressure: [9](#0-8) 

No global memory limit exists to prevent excessive concurrent allocations during decompression.

## Impact Explanation

**High Severity** - Validator Node Slowdowns/Crashes:

- **Memory Exhaustion**: Concurrent decompression of maximum-size messages consumes ~1 GB+ of memory
- **Node Instability**: Combined with normal operations, can trigger OOM conditions
- **Performance Degradation**: Heavy memory allocation/deallocation causes GC pressure and slowdowns
- **Availability Impact**: If multiple validators are targeted simultaneously, could affect network liveness

This meets the **High Severity** criteria from the Aptos bug bounty program: "Validator node slowdowns" and "Significant protocol violations" (violation of resource limit invariants).

## Likelihood Explanation

**Medium-High Likelihood:**

**Attacker Requirements:**
- Ability to establish network connections (up to 100 from different IPs)
- Craft highly compressible data (trivial: repetitive byte sequences)
- Basic understanding of protocol message formats

**Execution Complexity:**
- Low: Standard network programming tools
- No authentication bypass required
- No validator privileges needed

**Detection Difficulty:**
- Moderate: High memory usage and deserialization backlog visible in metrics
- Attack distributed across multiple peers may blend with legitimate traffic

**Mitigating Factors:**
- Rate limiting slows (but doesn't prevent) the attack
- Requires sustained connection to multiple peers
- Modern servers have substantial RAM (32-64 GB)

However, the lack of back-pressure means the attack is fundamentally viable.

## Recommendation

Implement global memory-aware back-pressure for concurrent deserialization:

**Solution 1: Memory-Based Semaphore**
Track estimated memory usage across all concurrent deserialization tasks and apply back-pressure when approaching limits:

```rust
// In NetworkConfig
pub max_deserialization_memory_bytes: Option<usize>,

// In NetworkEvents::new()
let max_memory = max_deserialization_memory_bytes
    .unwrap_or(MAX_APPLICATION_MESSAGE_SIZE * max_parallel_deserialization_tasks);

// Use a weighted semaphore where each task acquires permits equal to its estimated size
let memory_semaphore = Arc::new(Semaphore::new(max_memory / 1024)); // Track in KB

// Before decompression, acquire permits based on compressed size * expansion factor
let estimated_size = compressed_size * MAX_COMPRESSION_RATIO;
let permits = estimated_size / 1024;
let _permit = semaphore.acquire_many(permits).await;
```

**Solution 2: Compression Ratio Validation**
Reject messages with excessive compression ratios:

```rust
// In decompress()
const MAX_COMPRESSION_RATIO: usize = 10; // Conservative limit

let compression_ratio = decompressed_size / compressed_data.len();
if compression_ratio > MAX_COMPRESSION_RATIO {
    return Err(DecompressionError(format!(
        "Compression ratio too high: {} (max: {})",
        compression_ratio, MAX_COMPRESSION_RATIO
    )));
}
```

**Solution 3: Per-Peer Memory Quotas**
Track memory consumption per peer and throttle peers exceeding quotas.

## Proof of Concept

```rust
#[cfg(test)]
mod memory_exhaustion_test {
    use super::*;
    use lz4::block::compress;
    
    #[tokio::test]
    async fn test_concurrent_decompression_memory_exhaustion() {
        // Create highly compressible data that expands to MAX_APPLICATION_MESSAGE_SIZE
        let repetitive_data = vec![0u8; MAX_APPLICATION_MESSAGE_SIZE];
        let compressed = compress(&repetitive_data, None, true).unwrap();
        
        println!("Compressed size: {} bytes", compressed.len());
        println!("Decompressed size: {} bytes", MAX_APPLICATION_MESSAGE_SIZE);
        println!("Compression ratio: {}:1", 
                 MAX_APPLICATION_MESSAGE_SIZE / compressed.len());
        
        // Simulate concurrent deserialization
        let num_concurrent = num_cpus::get();
        let mut handles = vec![];
        
        for _ in 0..num_concurrent {
            let compressed_clone = compressed.clone();
            let handle = tokio::task::spawn_blocking(move || {
                // This allocates ~61.9 MiB per task
                let decompressed = aptos_compression::decompress(
                    &compressed_clone,
                    CompressionClient::Consensus,
                    MAX_APPLICATION_MESSAGE_SIZE
                ).unwrap();
                decompressed.len()
            });
            handles.push(handle);
        }
        
        // Wait for all tasks - this demonstrates concurrent memory allocation
        let mut total_memory = 0;
        for handle in handles {
            total_memory += handle.await.unwrap();
        }
        
        println!("Total concurrent memory allocated: {} MB", 
                 total_memory / (1024 * 1024));
        assert!(total_memory > (num_concurrent * MAX_APPLICATION_MESSAGE_SIZE * 9 / 10));
    }
}
```

**Notes**

This vulnerability exploits the gap between per-message limits and aggregate resource consumption. The compression amplification attack is particularly effective because:

1. Small compressed messages pass rate limits quickly
2. Decompression happens after rate limiting checks
3. No global memory accounting exists across concurrent tasks
4. The `buffer_unordered`/`buffered` concurrency control only limits task count, not memory

The issue violates the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." While individual messages respect size limits, the system fails to enforce aggregate memory limits during concurrent processing.

### Citations

**File:** config/src/config/network_config.rs (L37-37)
```rust
pub const NETWORK_CHANNEL_SIZE: usize = 1024;
```

**File:** config/src/config/network_config.rs (L44-44)
```rust
pub const MAX_INBOUND_CONNECTIONS: usize = 100;
```

**File:** config/src/config/network_config.rs (L47-48)
```rust
pub const MAX_APPLICATION_MESSAGE_SIZE: usize =
    (MAX_MESSAGE_SIZE - MAX_MESSAGE_METADATA_SIZE) - MESSAGE_PADDING_SIZE; /* The message size that applications should check against */
```

**File:** config/src/config/network_config.rs (L52-53)
```rust
pub const IP_BYTE_BUCKET_RATE: usize = 102400 /* 100 KiB */;
pub const IP_BYTE_BUCKET_SIZE: usize = IP_BYTE_BUCKET_RATE;
```

**File:** config/src/config/network_config.rs (L183-183)
```rust
            self.max_parallel_deserialization_tasks = Some(num_cpus::get());
```

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L233-242)
```rust
            Encoding::CompressedBcs(limit) => {
                let compression_client = self.get_compression_client();
                let raw_bytes = aptos_compression::decompress(
                    &bytes.to_vec(),
                    compression_client,
                    MAX_APPLICATION_MESSAGE_SIZE,
                )
                .map_err(|e| anyhow! {"{:?}", e})?;
                self.bcs_decode(&raw_bytes, limit)
            },
```

**File:** crates/aptos-compression/src/lib.rs (L108-108)
```rust
    let mut raw_data = vec![0u8; decompressed_size];
```

**File:** crates/aptos-compression/src/lib.rs (L176-180)
```rust
    if size > max_size {
        return Err(DecompressionError(format!(
            "Parsed size prefix in buffer is too big: {} > {}",
            size, max_size
        )));
```

**File:** network/framework/src/protocols/network/mod.rs (L217-228)
```rust
        let data_event_stream = peer_mgr_notifs_rx.map(|notification| {
            tokio::task::spawn_blocking(move || received_message_to_event(notification))
        });

        let data_event_stream: Pin<
            Box<dyn Stream<Item = Event<TMessage>> + Send + Sync + 'static>,
        > = if allow_out_of_order_delivery {
            Box::pin(
                data_event_stream
                    .buffer_unordered(max_parallel_deserialization_tasks)
                    .filter_map(|res| future::ready(res.expect("JoinError from spawn blocking"))),
            )
```

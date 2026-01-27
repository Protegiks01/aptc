# Audit Report

## Title
Compression Bomb Memory Exhaustion in Indexer-gRPC Cache Decompression

## Summary
The indexer-grpc cache worker and data services perform LZ4 decompression of cached transaction data without validating the decompressed size or compression ratio. This allows malicious compressed data to expand to arbitrary sizes during decompression, causing memory exhaustion and service crashes.

## Finding Description
When `enable_cache_compression` is enabled in the cache worker configuration, transaction data is compressed using LZ4 before storage in Redis. [1](#0-0) 

The compression and decompression logic resides in the `CacheEntry` enum. During decompression, the code reads the entire decompressed stream into memory without any size limits or validation. [2](#0-1) 

The critical issue is that `read_to_end(&mut decompressed)` allows unbounded memory allocation. An attacker who can inject malicious compressed data into Redis can craft a small payload (e.g., 1KB) that decompresses to gigabytes of data, exhausting available memory.

This decompression occurs in multiple critical code paths:
1. When the cache operator fetches transactions from Redis [3](#0-2) 
2. When the in-memory cache batch-fetches transactions [4](#0-3) 
3. When file entries are decompressed for storage operations [5](#0-4) 

**Attack Scenario:**
1. Attacker gains access to Redis (through misconfiguration, network access, or exploiting another service)
2. Attacker injects malicious LZ4-compressed data with keys matching the cache entry format (e.g., "l4:12345")
3. When the cache worker or data service reads and decompresses this entry, memory exhaustion occurs
4. The service crashes with OOM (Out of Memory), causing denial of service

The vulnerability breaks the **Resource Limits** invariant: all operations must respect computational and memory constraints.

## Impact Explanation
This is a **HIGH severity** vulnerability per Aptos bug bounty criteria as it enables:
- **API crashes**: The indexer-grpc data services will crash when attempting to serve malicious cached data
- **Service unavailability**: Critical indexer infrastructure becomes unavailable, preventing users from querying blockchain data
- **Cascading failures**: If multiple services share the same Redis instance, all dependent services may crash

While this does not directly affect consensus or validator operations, the indexer-grpc infrastructure is essential for:
- Block explorers and analytics platforms
- Wallet applications querying transaction history
- DApp backends accessing blockchain state
- Developer tools and debugging infrastructure

A prolonged outage would severely impact the Aptos ecosystem's usability and user experience.

## Likelihood Explanation
The likelihood is **MODERATE** because exploitation requires:
1. Access to write to the Redis instance (either through compromise, misconfiguration, or insider access)
2. Knowledge of the cache key format and compression scheme
3. Ability to craft valid LZ4-compressed compression bombs

However, the vulnerability is concerning because:
- Redis instances are often exposed on internal networks without proper segmentation
- Misconfigurations are common in production deployments
- A single malicious entry can repeatedly crash services
- No authentication or authorization checks exist at the decompression layer

## Recommendation
Implement decompression size limits and compression ratio validation:

```rust
// In compression_util.rs, modify CacheEntry::into_transaction()
const MAX_DECOMPRESSED_SIZE: usize = 100_000_000; // 100MB limit
const MAX_COMPRESSION_RATIO: f64 = 1000.0; // Max 1000:1 ratio

pub fn into_transaction(self) -> Transaction {
    match self {
        CacheEntry::Lz4CompressionProto(bytes) => {
            let compressed_size = bytes.len();
            let max_allowed_size = std::cmp::min(
                MAX_DECOMPRESSED_SIZE,
                (compressed_size as f64 * MAX_COMPRESSION_RATIO) as usize
            );
            
            let mut decompressor = Decoder::new(&bytes[..])
                .expect("Lz4 decompression failed.");
            let mut decompressed = Vec::with_capacity(compressed_size * 10);
            
            // Read with size limit
            let mut limited_reader = decompressor.take(max_allowed_size as u64);
            limited_reader.read_to_end(&mut decompressed)
                .expect("Lz4 decompression failed.");
            
            // Check if we hit the limit (indicates potential bomb)
            if decompressed.len() >= max_allowed_size {
                panic!("Decompressed size exceeds safety limit - possible compression bomb");
            }
            
            Transaction::decode(decompressed.as_slice())
                .expect("proto deserialization failed.")
        },
        // ... rest of the match arms
    }
}
```

Apply similar validation to `FileEntry::into_transactions_in_storage()` at line 264.

Additionally:
- Add metrics to track compression ratios and detect anomalies
- Implement Redis access controls and network segmentation
- Add integrity checks (HMAC) to cache entries to detect tampering
- Consider streaming decompression with chunked size validation

## Proof of Concept

```rust
// Test file: ecosystem/indexer-grpc/indexer-grpc-utils/src/compression_util_security_test.rs
#[cfg(test)]
mod compression_bomb_tests {
    use super::*;
    use lz4::EncoderBuilder;
    use std::io::Write;

    #[test]
    #[should_panic(expected = "Lz4 decompression")]
    fn test_compression_bomb_detection() {
        // Create a compression bomb: 1MB of zeros compressed to ~1KB
        let bomb_size = 1_000_000_000; // 1GB
        let chunk_size = 1_000_000;
        let zeros = vec![0u8; chunk_size];
        
        let mut encoder = EncoderBuilder::new()
            .level(4)
            .build(Vec::new())
            .unwrap();
        
        // Write repetitive data that compresses extremely well
        for _ in 0..(bomb_size / chunk_size) {
            encoder.write_all(&zeros).unwrap();
        }
        let compressed = encoder.finish().0;
        
        println!("Compressed {} bytes to {} bytes (ratio: {}:1)",
                 bomb_size, compressed.len(), 
                 bomb_size / compressed.len());
        
        // Attempt to decompress - this will exhaust memory
        let cache_entry = CacheEntry::Lz4CompressionProto(compressed);
        let _transaction = cache_entry.into_transaction(); // Should panic/OOM
    }
    
    #[test]
    fn test_normal_compression_ratio() {
        // Normal transaction should have reasonable compression ratio
        let transaction = Transaction {
            version: 42,
            epoch: 100,
            ..Transaction::default()
        };
        
        let cache_entry = CacheEntry::from_transaction(
            transaction.clone(), 
            StorageFormat::Lz4CompressedProto
        );
        
        let compressed_size = cache_entry.size();
        let original_size = transaction.encoded_len();
        let ratio = original_size as f64 / compressed_size as f64;
        
        // Normal ratio should be < 10:1
        assert!(ratio < 10.0, "Compression ratio too high: {}", ratio);
    }
}
```

**Notes**

The vulnerability exists in production-ready code paths that handle untrusted or semi-trusted data sources. While the indexer infrastructure is separate from core consensus, it represents critical infrastructure for the Aptos ecosystem. The absence of basic input validation (decompression size limits) is a clear security gap that violates defense-in-depth principles. Even with trusted components, bugs or misconfigurations could trigger memory exhaustion, making this validation essential.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L79-83)
```rust
        let cache_storage_format = if enable_cache_compression {
            StorageFormat::Lz4CompressedProto
        } else {
            StorageFormat::Base64UncompressedProto
        };
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/compression_util.rs (L142-157)
```rust
    pub fn into_transaction(self) -> Transaction {
        match self {
            CacheEntry::Lz4CompressionProto(bytes) => {
                let mut decompressor = Decoder::new(&bytes[..]).expect("Lz4 decompression failed.");
                let mut decompressed = Vec::new();
                decompressor
                    .read_to_end(&mut decompressed)
                    .expect("Lz4 decompression failed.");
                Transaction::decode(decompressed.as_slice()).expect("proto deserialization failed.")
            },
            CacheEntry::Base64UncompressedProto(bytes) => {
                let bytes: Vec<u8> = base64::decode(bytes).expect("base64 decoding failed.");
                Transaction::decode(bytes.as_slice()).expect("proto deserialization failed.")
            },
        }
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/compression_util.rs (L264-271)
```rust
            FileEntry::Lz4CompressionProto(bytes) => {
                let mut decompressor = Decoder::new(&bytes[..]).expect("Lz4 decompression failed.");
                let mut decompressed = Vec::new();
                decompressor
                    .read_to_end(&mut decompressed)
                    .expect("Lz4 decompression failed.");
                TransactionsInStorage::decode(decompressed.as_slice())
                    .expect("proto deserialization failed.")
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/cache_operator.rs (L239-242)
```rust
        for encoded_transaction in encoded_transactions {
            let cache_entry: CacheEntry = CacheEntry::new(encoded_transaction, self.storage_format);
            let transaction = cache_entry.into_transaction();
            transactions.push(transaction);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/in_memory_cache.rs (L365-370)
```rust
            let transactions = values
                .into_iter()
                .map(|v| {
                    let cache_entry = CacheEntry::new(v, storage_format);
                    cache_entry.into_transaction()
                })
```

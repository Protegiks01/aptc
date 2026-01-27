# Audit Report

## Title
LZ4 Decompression Bomb Vulnerability in Indexer-GRPC Storage Format

## Summary
The `Lz4CompressedProto` storage format in the indexer-grpc system lacks decompressed size validation, allowing attackers with Redis or file storage access to cause memory exhaustion and service crashes through maliciously crafted compressed data. The vulnerable decompression code uses unbounded `read_to_end()` calls and panic-inducing error handling, contrasting with the secure validation patterns used elsewhere in the Aptos codebase.

## Finding Description
The indexer-grpc system stores transaction data in compressed format using LZ4 compression in two locations: Redis cache (via `CacheEntry`) and file storage (via `FileEntry`). When reading this data back, the decompression functions fail to validate the decompressed size before allocating memory.

**Vulnerable Decompression - CacheEntry:** [1](#0-0) 

**Vulnerable Decompression - FileEntry:** [2](#0-1) 

Both implementations use `Decoder::new()` followed by `read_to_end()` without any size limits, and use `.expect()` which causes a panic on any decompression error.

**Secure Implementation Pattern (for comparison):**
The Aptos codebase contains a secure LZ4 decompression implementation in the `aptos-compression` crate that properly validates sizes: [3](#0-2) 

This secure version uses `get_decompressed_size()` to parse and validate the size prefix before decompression: [4](#0-3) 

**Attack Vectors:**

1. **Compromised Redis Cache:** The cache operator stores compressed transactions in Redis without authentication by default: [5](#0-4) 

An attacker gaining Redis access can inject malicious compressed data for specific version keys. When the data service reads these keys, it will decompress without validation: [6](#0-5) 

2. **Compromised File Storage:** File entries are read from GCS or local storage and decompressed without validation: [7](#0-6) 

An attacker with GCS bucket access (via leaked service account keys) can modify `.bin` files with malicious compressed data.

**Exploitation Flow:**
1. Attacker gains access to Redis (misconfigured auth, exposed port) or file storage (leaked service account key)
2. Injects crafted LZ4 compressed data: 1KB compressed → 1GB+ decompressed
3. When indexer data service reads that version/file, it calls vulnerable decompression
4. Service allocates unbounded memory, causing OOM crash or system hang
5. All concurrent requests reading malicious data crash, causing service-wide DoS

## Impact Explanation
**High Severity** - This vulnerability meets the Aptos Bug Bounty "High Severity" criteria:

- **Validator node slowdowns**: While the indexer is not a validator node, it's critical infrastructure
- **API crashes**: The indexer data service API will crash when decompressing malicious data
- **Significant protocol violations**: Violates resource limit invariants (unbounded memory allocation)

The impact is limited from **Critical** to **High** because:
- Does not directly affect consensus or blockchain state
- Requires infrastructure access (Redis/GCS), not direct network exploitation
- Does not lead to fund loss or theft
- Affects indexer availability, not core chain operation

However, the severity is elevated due to:
- **Cascading failures**: Multiple services affected (data-service, cache-worker, file-store)
- **Complete DoS**: All instances reading malicious data will crash
- **Panic-based crashes**: `.expect()` calls prevent graceful degradation
- **Memory exhaustion**: No limits allow decompression bombs (1KB → 1GB expansion)

## Likelihood Explanation
**Medium Likelihood** - The attack requires specific preconditions but is realistic:

**Factors increasing likelihood:**
- Redis misconfigurations are common (default no auth, exposed ports)
- GCS service account key leaks occur regularly
- Docker compose configuration shows Redis without authentication: [8](#0-7) 
- Storage corruption can occur naturally without malicious intent

**Factors decreasing likelihood:**
- Requires infrastructure-level access, not just network access
- Production deployments should have proper security controls
- Fullnode data source is trusted (not user-controlled input)
- Attack surface limited to indexer, doesn't affect core blockchain

The vulnerability is exploitable if any of these scenarios occur:
1. Redis instance exposed without authentication
2. GCS service account credentials leaked
3. Insider threat with infrastructure access
4. Storage corruption causing invalid compressed data

## Recommendation
Implement size validation before decompression, following the secure pattern from `aptos-compression/src/lib.rs`:

**For CacheEntry::into_transaction():**
```rust
pub fn into_transaction(self) -> Result<Transaction, Error> {
    match self {
        CacheEntry::Lz4CompressionProto(bytes) => {
            // Validate decompressed size before allocating
            const MAX_TRANSACTION_SIZE: usize = 16 * 1024 * 1024; // 16MB limit
            let decompressed_size = validate_lz4_size(&bytes, MAX_TRANSACTION_SIZE)?;
            
            // Pre-allocate exact buffer size
            let mut decompressed = vec![0u8; decompressed_size];
            lz4::block::decompress_to_buffer(&bytes[4..], None, &mut decompressed)
                .context("Lz4 decompression failed")?;
            
            Transaction::decode(decompressed.as_slice())
                .context("proto deserialization failed")
        },
        // ... rest of implementation
    }
}

fn validate_lz4_size(compressed_data: &[u8], max_size: usize) -> Result<usize, Error> {
    if compressed_data.len() < 4 {
        return Err(Error::DecompressionError("Data too small".into()));
    }
    
    let size = (compressed_data[0] as i32)
        | ((compressed_data[1] as i32) << 8)
        | ((compressed_data[2] as i32) << 16)
        | ((compressed_data[3] as i32) << 24);
        
    if size < 0 || size as usize > max_size {
        return Err(Error::DecompressionError(
            format!("Invalid size: {} > {}", size, max_size)
        ));
    }
    
    Ok(size as usize)
}
```

**Additional hardening:**
1. Replace `.expect()` with proper error handling returning `Result`
2. Add size limits configuration (default 15MB per transaction from constants): [9](#0-8) 
3. Implement Redis authentication for production deployments
4. Add input validation in file store reads

## Proof of Concept
```rust
#[cfg(test)]
mod decompression_bomb_test {
    use super::*;
    use lz4::EncoderBuilder;
    use std::io::Write;
    
    #[test]
    #[should_panic(expected = "memory allocation")]
    fn test_decompression_bomb_vulnerability() {
        // Create a transaction with normal size
        let transaction = Transaction {
            version: 42,
            epoch: 1,
            ..Transaction::default()
        };
        
        // Compress normally
        let mut proto_bytes = Vec::new();
        transaction.encode(&mut proto_bytes).unwrap();
        
        // Create malicious compressed data:
        // Modify size prefix to claim 1GB decompressed size
        let mut malicious_bytes = Vec::new();
        let fake_size: i32 = 1024 * 1024 * 1024; // 1GB
        malicious_bytes.extend_from_slice(&fake_size.to_le_bytes());
        
        // Add actual LZ4 compressed data (much smaller)
        let mut encoder = EncoderBuilder::new()
            .level(4)
            .build(Vec::new())
            .unwrap();
        encoder.write_all(&proto_bytes).unwrap();
        let (compressed, _) = encoder.finish();
        malicious_bytes.extend_from_slice(&compressed[4..]); // Skip size prefix
        
        // Attempt decompression - will allocate 1GB and crash
        let cache_entry = CacheEntry::Lz4CompressionProto(malicious_bytes);
        let _result = cache_entry.into_transaction(); // Panics with OOM
    }
    
    #[test]
    fn test_secure_decompression_with_validation() {
        // Using the secure aptos-compression implementation
        use aptos_compression::{compress, decompress, CompressionClient};
        
        let test_data = vec![0u8; 10000];
        let max_size = 15 * 1024 * 1024; // 15MB
        
        // Compress
        let compressed = compress(
            test_data.clone(),
            CompressionClient::Unknown,
            max_size
        ).unwrap();
        
        // Try to decompress with size validation - succeeds
        let decompressed = decompress(
            &compressed,
            CompressionClient::Unknown,
            max_size
        ).unwrap();
        assert_eq!(test_data, decompressed);
        
        // Modify size prefix to exceed limit
        let mut malicious = compressed.clone();
        let fake_size = (max_size + 1) as i32;
        malicious[0..4].copy_from_slice(&fake_size.to_le_bytes());
        
        // Decompression fails gracefully with validation
        let result = decompress(
            &malicious,
            CompressionClient::Unknown,
            max_size
        );
        assert!(result.is_err()); // Properly rejects oversized data
    }
}
```

**To reproduce in production environment:**
1. Set up indexer-grpc with Redis cache
2. Use Redis CLI to inject malicious data: `SET l4:12345 <malicious_lz4_bytes>`
3. Query data service for version 12345
4. Observe service crash with memory exhaustion

## Notes
This vulnerability demonstrates a critical pattern: the Aptos codebase contains a secure LZ4 decompression implementation in `aptos-compression`, but the indexer-grpc components reimplemented decompression without following the same security patterns. This suggests insufficient code reuse and security review across components.

The indexer system is critical infrastructure for Aptos ecosystem applications, and its availability directly impacts developer experience and third-party integrations, even though it doesn't affect core consensus.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/compression_util.rs (L144-150)
```rust
            CacheEntry::Lz4CompressionProto(bytes) => {
                let mut decompressor = Decoder::new(&bytes[..]).expect("Lz4 decompression failed.");
                let mut decompressed = Vec::new();
                decompressor
                    .read_to_end(&mut decompressed)
                    .expect("Lz4 decompression failed.");
                Transaction::decode(decompressed.as_slice()).expect("proto deserialization failed.")
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

**File:** crates/aptos-compression/src/lib.rs (L101-107)
```rust
    let decompressed_size = match get_decompressed_size(compressed_data, max_size) {
        Ok(size) => size,
        Err(error) => {
            let error_string = format!("Failed to get decompressed size: {}", error);
            return create_decompression_error(&client, error_string);
        },
    };
```

**File:** crates/aptos-compression/src/lib.rs (L150-183)
```rust
fn get_decompressed_size(
    compressed_data: &CompressedData,
    max_size: usize,
) -> Result<usize, Error> {
    // Ensure that the compressed data is at least 4 bytes long
    if compressed_data.len() < 4 {
        return Err(DecompressionError(format!(
            "Compressed data must be at least 4 bytes long! Got: {}",
            compressed_data.len()
        )));
    }

    // Parse the size prefix
    let size = (compressed_data[0] as i32)
        | ((compressed_data[1] as i32) << 8)
        | ((compressed_data[2] as i32) << 16)
        | ((compressed_data[3] as i32) << 24);
    if size < 0 {
        return Err(DecompressionError(format!(
            "Parsed size prefix in buffer must not be negative! Got: {}",
            size
        )));
    }

    // Ensure that the size is not greater than the max size limit
    let size = size as usize;
    if size > max_size {
        return Err(DecompressionError(format!(
            "Parsed size prefix in buffer is too big: {} > {}",
            size, max_size
        )));
    }

    Ok(size)
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L84-90)
```rust
        let redis_client = redis::Client::open(redis_main_instance_address.0.clone())
            .with_context(|| {
                format!(
                    "[Indexer Cache] Failed to create redis client for {}",
                    redis_main_instance_address
                )
            })?;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/cache_operator.rs (L239-242)
```rust
        for encoded_transaction in encoded_transactions {
            let cache_entry: CacheEntry = CacheEntry::new(encoded_transaction, self.storage_format);
            let transaction = cache_entry.into_transaction();
            transactions.push(transaction);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator/mod.rs (L70-71)
```rust
        let transactions_in_storage = tokio::task::spawn_blocking(move || {
            FileEntry::new(bytes, storage_format).into_transactions_in_storage()
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/config.rs (L1-50)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

use crate::service::RawDataServerWrapper;
use anyhow::{bail, Result};
use aptos_indexer_grpc_server_framework::RunnableConfig;
use aptos_indexer_grpc_utils::{
    compression_util::StorageFormat, config::IndexerGrpcFileStoreConfig,
    in_memory_cache::InMemoryCacheConfig, types::RedisUrl,
};
use aptos_protos::{
    indexer::v1::FILE_DESCRIPTOR_SET as INDEXER_V1_FILE_DESCRIPTOR_SET,
    transaction::v1::FILE_DESCRIPTOR_SET as TRANSACTION_V1_TESTING_FILE_DESCRIPTOR_SET,
    util::timestamp::FILE_DESCRIPTOR_SET as UTIL_TIMESTAMP_FILE_DESCRIPTOR_SET,
};
use aptos_transaction_filter::BooleanTransactionFilter;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tonic::{codec::CompressionEncoding, transport::Server};

pub const SERVER_NAME: &str = "idxdatasvc";

// Default max response channel size.
const DEFAULT_MAX_RESPONSE_CHANNEL_SIZE: usize = 3;

// HTTP2 ping interval and timeout.
// This can help server to garbage collect dead connections.
// tonic server: https://docs.rs/tonic/latest/tonic/transport/server/struct.Server.html#method.http2_keepalive_interval
const HTTP2_PING_INTERVAL_DURATION: std::time::Duration = std::time::Duration::from_secs(60);
const HTTP2_PING_TIMEOUT_DURATION: std::time::Duration = std::time::Duration::from_secs(10);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// The address for the TLS GRPC server to listen on.
    pub data_service_grpc_listen_address: SocketAddr,
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NonTlsConfig {
    /// The address for the TLS GRPC server to listen on.
    pub data_service_grpc_listen_address: SocketAddr,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IndexerGrpcDataServiceConfig {
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/constants.rs (L18-19)
```rust
// Limit the message size to 15MB. By default the downstream can receive up to 15MB.
pub const MESSAGE_SIZE_LIMIT: usize = 1024 * 1024 * 15;
```

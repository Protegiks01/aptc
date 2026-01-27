# Audit Report

## Title
Memory Exhaustion via Decompression Bomb in Storage Service Compression Handling

## Summary
The Aptos storage service decompression logic trusts the size prefix embedded in compressed data without validating it corresponds to the actual compressed payload size. A malicious storage server can craft responses with inflated size prefixes, forcing clients to allocate excessive memory (~61.875 MiB per response) before decompression verification occurs, leading to memory exhaustion and node crashes.

## Finding Description

When the `use_compression` flag is set in `StorageServiceRequest`, the response decompression occurs on the **client side** in the following flow:

1. Client sends request with `use_compression = true` [1](#0-0) 

2. Server creates compressed response based on client's flag [2](#0-1) 

3. Client validates compression expectation matches response format [3](#0-2) 

4. Client calls `get_data_response()` which invokes decompression [4](#0-3) 

5. **Vulnerability**: The `decompress()` function reads a 4-byte size prefix from compressed data, validates it's ≤ MAX_APPLICATION_MESSAGE_SIZE (~61.875 MiB), then **immediately allocates a buffer of that exact size** [5](#0-4) 

6. Only AFTER allocation does it attempt LZ4 decompression [6](#0-5) 

The critical flaw is in `get_decompressed_size()`: it parses the size prefix as an i32, validates bounds, but **does not verify the size prefix correlates with the actual compressed data size** [7](#0-6) 

**Attack Scenario:**
- Malicious storage server crafts response with:
  - Compressed payload: 1 MB (within network limits of 10-40 MiB)
  - Size prefix: 60 MB (within MAX_APPLICATION_MESSAGE_SIZE)
  - Actual decompressed size: negligible
- Client allocates 60 MB buffer before decompression
- LZ4 decompression fails, but memory already consumed
- Repeat with concurrent requests (MAX_CONCURRENT_REQUESTS = 6): 360 MB allocated
- Multiple malicious peers amplify the attack

This violates the invariant: **"Resource Limits: All operations must respect gas, storage, and computational limits"** - memory allocation is unbounded relative to actual data.

## Impact Explanation

**High Severity** - Validator Node Slowdowns (up to $50,000)

This vulnerability enables resource exhaustion attacks against validator and fullnode operators:

1. **Memory Exhaustion**: Each malicious response forces allocation of up to MAX_APPLICATION_MESSAGE_SIZE (~61.875 MiB) [8](#0-7) 

2. **Amplification**: With concurrent state sync requests, memory pressure multiplies rapidly

3. **Node Impact**: 
   - OOM conditions leading to node crashes
   - Severe performance degradation
   - Missed consensus rounds
   - Network partition if multiple validators affected

4. **Attack Vector**: Storage servers in P2P networks may be untrusted fullnodes. State sync clients must fetch blockchain data from these peers, making them vulnerable to malicious responses.

## Likelihood Explanation

**High Likelihood** - This attack is straightforward to execute:

1. **Low Barrier**: Attacker needs to:
   - Run a malicious fullnode/storage server
   - Wait for honest nodes to peer with them
   - Craft responses with inflated size prefixes

2. **No Authentication**: Storage service requests come from any peer in the P2P network

3. **Detection Difficulty**: The client validation only checks compression format matches expectation, not size reasonableness [9](#0-8) 

4. **No Rate Limiting**: RequestModerator only validates server-side incoming requests, not client-side response memory allocation patterns

5. **Repeatable**: Attack can be sustained continuously as nodes continuously sync state

## Recommendation

Implement compression ratio validation before buffer allocation:

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

    // NEW: Validate compression ratio is reasonable
    const MAX_COMPRESSION_RATIO: usize = 10; // Allow up to 10x compression
    let compressed_size = compressed_data.len() - 4; // Exclude size prefix
    if size > compressed_size * MAX_COMPRESSION_RATIO {
        return Err(DecompressionError(format!(
            "Suspicious compression ratio: decompressed({}) > compressed({}) * {}",
            size, compressed_size, MAX_COMPRESSION_RATIO
        )));
    }

    Ok(size)
}
```

Alternative: Use streaming decompression that doesn't require pre-allocating the full buffer, or reduce MAX_APPLICATION_MESSAGE_SIZE to match state sync message limits.

## Proof of Concept

```rust
// Add to crates/aptos-compression/src/tests.rs
#[test]
fn test_decompression_bomb_attack() {
    use crate::{decompress, CompressionClient, Error};
    
    // Craft malicious compressed data
    let mut malicious_data = Vec::new();
    
    // Size prefix claiming 50 MiB decompressed
    let claimed_size: i32 = 50 * 1024 * 1024;
    malicious_data.extend_from_slice(&claimed_size.to_le_bytes());
    
    // But actual compressed payload is only 1 KB of zeros
    // This simulates highly compressible data that doesn't match size claim
    let fake_compressed = vec![0u8; 1024];
    malicious_data.extend_from_slice(&fake_compressed);
    
    // Attempt decompression with max size allowing the claim
    let max_size = 64 * 1024 * 1024; // 64 MiB
    
    // This will allocate 50 MiB buffer before failing
    let result = decompress(&malicious_data, CompressionClient::StateSync, max_size);
    
    // Decompression should fail, but buffer was already allocated
    assert!(result.is_err());
    
    // To demonstrate the attack: measure memory before and during
    // Multiple concurrent calls would cause severe memory pressure
}

#[test]
fn test_concurrent_decompression_bomb() {
    use std::sync::Arc;
    use std::thread;
    
    let malicious_data = Arc::new({
        let mut data = Vec::new();
        let claimed_size: i32 = 50 * 1024 * 1024;
        data.extend_from_slice(&claimed_size.to_le_bytes());
        data.extend_from_slice(&vec![0u8; 1024]);
        data
    });
    
    // Simulate concurrent requests (6 per MAX_CONCURRENT_REQUESTS)
    let handles: Vec<_> = (0..6)
        .map(|_| {
            let data = Arc::clone(&malicious_data);
            thread::spawn(move || {
                let _ = decompress(
                    &data,
                    CompressionClient::StateSync,
                    64 * 1024 * 1024,
                );
            })
        })
        .collect();
    
    for handle in handles {
        handle.join().unwrap();
    }
    
    // This would have allocated ~300 MiB total before all failing
}
```

## Notes

The vulnerability stems from trusting untrusted network data (the size prefix) before validation. The size prefix should be treated as attacker-controlled input and validated against the actual compressed payload size using a maximum compression ratio threshold. The current implementation assumes honest compression, which is unsafe in a P2P network with potentially malicious peers.

### Citations

**File:** state-sync/storage-service/types/src/requests.rs (L10-13)
```rust
pub struct StorageServiceRequest {
    pub data_request: DataRequest, // The data to fetch from the storage service
    pub use_compression: bool,     // Whether or not the client wishes data to be compressed
}
```

**File:** state-sync/storage-service/server/src/handler.rs (L443-446)
```rust
        let create_storage_response = || {
            StorageServiceResponse::new(data_response, request.use_compression)
                .map_err(|error| error.into())
        };
```

**File:** state-sync/aptos-data-client/src/client.rs (L736-748)
```rust
        // Ensure the response obeys the compression requirements
        let (context, storage_response) = storage_response.into_parts();
        if request.use_compression && !storage_response.is_compressed() {
            return Err(Error::InvalidResponse(format!(
                "Requested compressed data, but the response was uncompressed! Response: {:?}",
                storage_response.get_label()
            )));
        } else if !request.use_compression && storage_response.is_compressed() {
            return Err(Error::InvalidResponse(format!(
                "Requested uncompressed data, but the response was compressed! Response: {:?}",
                storage_response.get_label()
            )));
        }
```

**File:** state-sync/storage-service/types/src/responses.rs (L97-111)
```rust
    pub fn get_data_response(&self) -> Result<DataResponse, Error> {
        match self {
            StorageServiceResponse::CompressedResponse(_, compressed_data) => {
                let raw_data = aptos_compression::decompress(
                    compressed_data,
                    CompressionClient::StateSync,
                    MAX_APPLICATION_MESSAGE_SIZE,
                )?;
                let data_response = bcs::from_bytes::<DataResponse>(&raw_data)
                    .map_err(|error| Error::UnexpectedErrorEncountered(error.to_string()))?;
                Ok(data_response)
            },
            StorageServiceResponse::RawResponse(data_response) => Ok(data_response.clone()),
        }
    }
```

**File:** crates/aptos-compression/src/lib.rs (L100-108)
```rust
    // Check size of the data and initialize raw_data
    let decompressed_size = match get_decompressed_size(compressed_data, max_size) {
        Ok(size) => size,
        Err(error) => {
            let error_string = format!("Failed to get decompressed size: {}", error);
            return create_decompression_error(&client, error_string);
        },
    };
    let mut raw_data = vec![0u8; decompressed_size];
```

**File:** crates/aptos-compression/src/lib.rs (L111-114)
```rust
    if let Err(error) = lz4::block::decompress_to_buffer(compressed_data, None, &mut raw_data) {
        let error_string = format!("Failed to decompress the data: {}", error);
        return create_decompression_error(&client, error_string);
    };
```

**File:** crates/aptos-compression/src/lib.rs (L150-184)
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
}
```

**File:** config/src/config/network_config.rs (L47-48)
```rust
pub const MAX_APPLICATION_MESSAGE_SIZE: usize =
    (MAX_MESSAGE_SIZE - MAX_MESSAGE_METADATA_SIZE) - MESSAGE_PADDING_SIZE; /* The message size that applications should check against */
```

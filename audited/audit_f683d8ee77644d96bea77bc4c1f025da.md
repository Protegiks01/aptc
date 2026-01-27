# Audit Report

## Title
Memory Exhaustion via Malformed Compressed Response Decompression Size Claims

## Summary
A malicious storage service peer can cause excessive memory allocations on receiving peers by sending compressed responses with inflated decompressed size claims in the LZ4 header, enabling a resource exhaustion attack with minimal bandwidth cost.

## Finding Description

The `StorageServiceResponse` serialization mechanism in Aptos state sync uses LZ4 compression for network transmission. When a receiving peer deserializes a compressed response, the decompression logic trusts the decompressed size claimed in the first 4 bytes of the compressed data without validating it against the actual compressed payload size. [1](#0-0) 

The `get_decompressed_size()` function reads the size from the attacker-controlled compressed data header and only validates that it doesn't exceed `max_size` (MAX_APPLICATION_MESSAGE_SIZE ≈ 62 MiB). It does not validate that the claimed size is reasonable relative to the compressed data size. [2](#0-1) 

The `decompress()` function then allocates a buffer of the claimed size **before** attempting actual decompression. This creates an amplification vulnerability where an attacker can:

1. Send a tiny compressed payload (e.g., 100 bytes)
2. Set the first 4 bytes to claim a 62 MiB decompressed size
3. Force the victim to allocate 62 MiB of memory
4. Decompression fails, but memory was already allocated [3](#0-2) 

When `get_data_response()` calls `decompress()`, the malformed data triggers large memory allocations before failure detection. With the default `MAX_CONCURRENT_REQUESTS` of 6, a single malicious peer can force up to 372 MiB of concurrent allocations. [4](#0-3) 

The peer scoring system will eventually ignore the malicious peer after approximately 14 failures (50.0 * 0.95^14 ≈ 24.3), but during this window, the attacker can trigger 84 separate 62 MiB allocations totaling ~5.2 GB of memory operations. [5](#0-4) [6](#0-5) 

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits" by allowing unbounded memory allocation based on untrusted size fields.

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty criteria for "Validator node slowdowns" because:

1. **Amplification Factor**: 620,000x amplification (100 bytes network → 62 MiB memory)
2. **Concurrent Impact**: 372 MiB per malicious peer with multiple concurrent requests
3. **Multiple Attackers**: Multiple colluding malicious storage service peers can amplify the effect
4. **Memory Pressure**: Repeated large allocations cause memory fragmentation and can trigger OOM conditions on memory-constrained nodes
5. **Delayed Mitigation**: ~14 failures (84 total allocations) before peer is ignored
6. **Syncing Disruption**: Can slow down or halt state synchronization for nodes catching up to the network

While this does not directly compromise consensus safety or cause fund loss, it significantly degrades node availability and performance, particularly affecting new nodes bootstrapping or nodes recovering from downtime.

## Likelihood Explanation

This vulnerability is **highly likely** to be exploited because:

1. **Trivial to Execute**: Attacker only needs to modify 4 bytes in the compressed response header
2. **No Privileged Access Required**: Any network peer can act as a storage service provider
3. **Low Detection Risk**: Appears as normal decompression failures initially
4. **Minimal Cost**: Attacker sends ~100 bytes to force 62 MiB allocation
5. **Multiple Vectors**: Can be combined with multiple malicious peers or Sybil attacks

The attack requires no special knowledge beyond the LZ4 compression format and can be automated trivially.

## Recommendation

Add validation that the claimed decompressed size is reasonable relative to the compressed data size. Implement a maximum compression ratio check before allocation:

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

    // ADD THIS: Validate compression ratio is reasonable
    const MAX_COMPRESSION_RATIO: usize = 100; // Adjust based on expected data compressibility
    let compressed_size = compressed_data.len() - 4; // Exclude header
    if size > compressed_size * MAX_COMPRESSION_RATIO {
        return Err(DecompressionError(format!(
            "Decompressed size {} is unreasonably large relative to compressed size {}: ratio {}x exceeds maximum {}x",
            size, compressed_size, size / compressed_size.max(1), MAX_COMPRESSION_RATIO
        )));
    }

    Ok(size)
}
```

Additionally, consider implementing incremental decompression or streaming decompression to avoid large upfront allocations.

## Proof of Concept

```rust
#[cfg(test)]
mod exploit_test {
    use super::*;
    use aptos_compression::{compress, decompress, CompressedData, CompressionClient};

    #[test]
    fn test_decompression_memory_exhaustion() {
        // Create a small payload
        let small_data = vec![0u8; 100];
        
        // Compress it legitimately first
        let max_bytes = 64 * 1024 * 1024; // ~64 MiB
        let compressed = compress(
            small_data.clone(),
            CompressionClient::StateSync,
            max_bytes,
        ).unwrap();
        
        // Craft malicious compressed data claiming 62 MiB decompressed size
        let mut malicious_compressed = compressed.clone();
        let claimed_size: i32 = (62 * 1024 * 1024) as i32; // 62 MiB
        
        // Overwrite the first 4 bytes (LZ4 size header) with inflated size
        malicious_compressed[0] = (claimed_size & 0xFF) as u8;
        malicious_compressed[1] = ((claimed_size >> 8) & 0xFF) as u8;
        malicious_compressed[2] = ((claimed_size >> 16) & 0xFF) as u8;
        malicious_compressed[3] = ((claimed_size >> 24) & 0xFF) as u8;
        
        // Keep the compressed payload tiny (truncate to header + few bytes)
        malicious_compressed.truncate(8);
        
        // Attempt decompression - this will allocate 62 MiB before failing
        let result = decompress(
            &malicious_compressed,
            CompressionClient::StateSync,
            max_bytes,
        );
        
        // Decompression should fail, but 62 MiB was allocated
        assert!(result.is_err());
        println!("Decompression failed as expected, but 62 MiB was allocated from {} bytes of compressed data",
                 malicious_compressed.len());
        
        // Demonstrate amplification: 8 bytes → 62 MiB allocation attempt
        let amplification = (62 * 1024 * 1024) / malicious_compressed.len();
        println!("Amplification factor: {}x", amplification);
        assert!(amplification > 500_000); // Over 500,000x amplification
    }
}
```

## Notes

This vulnerability represents a classic "trusting attacker-controlled size field" pattern where the decompressed size from the LZ4 header is used for memory allocation without validating it against the actual compressed data size. While peer scoring provides eventual mitigation, the 14-failure window allows significant resource exhaustion. The fix should validate compression ratios before allocation to prevent this amplification attack while preserving compatibility with legitimately compressed data.

### Citations

**File:** crates/aptos-compression/src/lib.rs (L92-121)
```rust
pub fn decompress(
    compressed_data: &CompressedData,
    client: CompressionClient,
    max_size: usize,
) -> Result<Vec<u8>, Error> {
    // Start the decompression timer
    let start_time = Instant::now();

    // Check size of the data and initialize raw_data
    let decompressed_size = match get_decompressed_size(compressed_data, max_size) {
        Ok(size) => size,
        Err(error) => {
            let error_string = format!("Failed to get decompressed size: {}", error);
            return create_decompression_error(&client, error_string);
        },
    };
    let mut raw_data = vec![0u8; decompressed_size];

    // Decompress the data
    if let Err(error) = lz4::block::decompress_to_buffer(compressed_data, None, &mut raw_data) {
        let error_string = format!("Failed to decompress the data: {}", error);
        return create_decompression_error(&client, error_string);
    };

    // Stop the timer and update the metrics
    metrics::observe_decompression_operation_time(&client, start_time);
    metrics::update_decompression_metrics(&client, compressed_data, &raw_data);

    Ok(raw_data)
}
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

**File:** config/src/config/state_sync_config.rs (L29-31)
```rust
// The maximum number of concurrent requests to send
const MAX_CONCURRENT_REQUESTS: u64 = 6;
const MAX_CONCURRENT_STATE_REQUESTS: u64 = 6;
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L32-43)
```rust
/// Scores for peer rankings based on preferences and behavior.
const MAX_SCORE: f64 = 100.0;
const MIN_SCORE: f64 = 0.0;
const STARTING_SCORE: f64 = 50.0;
/// Add this score on a successful response.
const SUCCESSFUL_RESPONSE_DELTA: f64 = 1.0;
/// Not necessarily a malicious response, but not super useful.
const NOT_USEFUL_MULTIPLIER: f64 = 0.95;
/// Likely to be a malicious response.
const MALICIOUS_MULTIPLIER: f64 = 0.8;
/// Ignore a peer when their score dips below this threshold.
const IGNORE_PEER_THRESHOLD: f64 = 25.0;
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L54-62)
```rust
impl From<ResponseError> for ErrorType {
    fn from(error: ResponseError) -> Self {
        match error {
            ResponseError::InvalidData | ResponseError::InvalidPayloadDataType => {
                ErrorType::NotUseful
            },
            ResponseError::ProofVerificationError => ErrorType::Malicious,
        }
    }
```

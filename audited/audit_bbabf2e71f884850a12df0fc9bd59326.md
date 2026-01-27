# Audit Report

## Title
DirectSendMsg Compressed Payload Bomb Causes Memory Exhaustion via Malicious Size Prefix

## Summary
A malicious peer can send `DirectSendMsg` messages with compressed protocols containing a fraudulent decompression size prefix, causing the receiving node to allocate massive amounts of memory (up to ~62 GiB) before decompression validation occurs. This leads to memory exhaustion, node slowdowns, and potential crashes.

## Finding Description

The vulnerability exists in the compressed message deserialization flow for network protocols. When a `DirectSendMsg` with a compressed protocol ID (e.g., `ConsensusDirectSendCompressed`, `MempoolDirectSend`, `DKGDirectSendCompressed`) is received, the following occurs: [1](#0-0) 

The `raw_msg` field contains the compressed payload, limited by wire-level `MAX_FRAME_SIZE` (4 MiB). However, during application-level processing, this payload undergoes decompression: [2](#0-1) 

For compressed protocols, the decompression path is triggered: [3](#0-2) 

The critical vulnerability lies in the `decompress()` function which reads an attacker-controlled size prefix and **allocates memory before validating the actual decompressed content**: [4](#0-3) 

The size prefix is parsed directly from the compressed data: [5](#0-4) 

**Attack Flow:**

1. Malicious peer sends `DirectSendMsg` with compressed protocol ID
2. The `raw_msg` contains: `[4-byte size prefix claiming 62 MiB][<4 MiB of garbage/minimal compressed data]`
3. Wire-level validation passes (frame ≤ 4 MiB per `MAX_FRAME_SIZE`)
4. Message is queued in upstream handler channel (capacity: 1024 messages) [6](#0-5) 

5. Application processes messages via `NetworkEvents` stream, calling `to_message()`: [7](#0-6) 

6. Decompression allocates **62 MiB per message** based on the fraudulent size prefix (line 108 in lib.rs)
7. With 1024 queued messages: **1024 × 62 MiB = 63,488 MiB ≈ 62 GiB** of memory allocation
8. Even if decompression fails, memory was already allocated; error is only logged

The allocation happens **before** actual LZ4 decompression validation, so even invalid/garbage compressed data triggers memory exhaustion.

## Impact Explanation

**High Severity** per Aptos Bug Bounty criteria: **"Validator node slowdowns"**

- **Direct Impact**: Memory exhaustion causes validator nodes to slow down significantly or crash via OOM killer
- **Consensus Impact**: Slowed/crashed validators cannot participate in consensus, reducing network capacity
- **Scale**: Each malicious peer can target multiple validators simultaneously
- **Recovery**: Requires node restart and peer disconnection
- **Attack Cost**: Zero - any network peer can send these messages without authentication/stake

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits" - the decompression allocates memory without validating the actual decompressed content size first.

## Likelihood Explanation

**High Likelihood:**

- **Attacker Requirements**: Any network peer with P2P connectivity to validators
- **Complexity**: Simple to craft - just set size prefix to maximum allowed value
- **Detection Difficulty**: Appears as legitimate compressed network traffic until processing
- **Channel Capacity**: 1024 messages × 62 MiB = 62 GiB allows single-connection attack
- **No Rate Limiting**: No per-peer message rate limiting on decompression operations
- **Multiple Vectors**: Works across multiple protocol IDs (Consensus, Mempool, DKG, JWK, etc.)

## Recommendation

Implement defense-in-depth mitigations:

**1. Validate compressed data size BEFORE allocation:**
```rust
// In decompress() function before line 108
let actual_compressed_size = compressed_data.len();
let claimed_ratio = decompressed_size / actual_compressed_size;
const MAX_REASONABLE_COMPRESSION_RATIO: usize = 10; // e.g., 10x expansion

if claimed_ratio > MAX_REASONABLE_COMPRESSION_RATIO {
    return create_decompression_error(&client, 
        format!("Suspicious compression ratio: {}x", claimed_ratio));
}
```

**2. Implement incremental/streaming decompression** instead of pre-allocating full buffer

**3. Add per-peer rate limiting** on decompression operations (bytes/second limit)

**4. Add monitoring metrics** for decompression failures and memory allocation patterns

**5. Consider protocol-specific tighter limits** - consensus messages shouldn't need 62 MiB

## Proof of Concept

```rust
// Proof of Concept: Malicious DirectSendMsg construction
use network::protocols::wire::messaging::v1::{DirectSendMsg, NetworkMessage};
use network::protocols::wire::handshake::v1::ProtocolId;
use aptos_compression::compress;

fn create_payload_bomb() -> DirectSendMsg {
    // Create small payload (1 KB)
    let small_data = vec![0u8; 1024];
    
    // Compress it legitimately first to get valid LZ4 format
    let compressed = compress(
        small_data,
        CompressionClient::Consensus,
        4 * 1024 * 1024
    ).unwrap();
    
    // Now replace the size prefix with fraudulent maximum value
    let mut malicious_payload = compressed.clone();
    
    // Size prefix claiming 61 MB (MAX_APPLICATION_MESSAGE_SIZE)
    let fake_size: i32 = 61 * 1024 * 1024;
    malicious_payload[0] = (fake_size & 0xFF) as u8;
    malicious_payload[1] = ((fake_size >> 8) & 0xFF) as u8;
    malicious_payload[2] = ((fake_size >> 16) & 0xFF) as u8;
    malicious_payload[3] = ((fake_size >> 24) & 0xFF) as u8;
    
    // The rest stays as minimal compressed data
    // Wire-level size: ~1 KB, claimed decompressed: 61 MB
    
    DirectSendMsg {
        protocol_id: ProtocolId::ConsensusDirectSendCompressed,
        priority: 0,
        raw_msg: malicious_payload,
    }
}

// Attack: Send 1024 such messages to fill the channel
// Total memory allocated: 1024 * 61 MB = ~62 GB
// Actual wire traffic: 1024 * 1 KB = 1 MB
```

**To reproduce:**
1. Create malicious peer that sends 1024 `DirectSendMsg` with fraudulent size prefixes
2. Target validator node's network endpoint
3. Monitor validator node memory consumption - should spike to ~62 GB
4. Node will slow down or crash with OOM error
5. Error logs will show decompression failures, but damage already done

## Notes

The vulnerability affects all compressed protocol variants:
- `ConsensusDirectSendCompressed`
- `ConsensusRpcCompressed`
- `MempoolDirectSend` 
- `DKGDirectSendCompressed` / `DKGRpcCompressed`
- `JWKConsensusDirectSendCompressed` / `JWKConsensusRpcCompressed`
- `ConsensusObserver`

The root cause is trusting the attacker-controlled size prefix in compressed data before validation, violating the principle of "never allocate resources based on untrusted input before validation."

### Citations

**File:** network/framework/src/protocols/wire/messaging/v1/mod.rs (L153-163)
```rust
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct DirectSendMsg {
    /// `protocol_id` is a variant of the ProtocolId enum.
    pub protocol_id: ProtocolId,
    /// Message priority in the range 0..=255.
    pub priority: Priority,
    /// Message payload.
    #[serde(with = "serde_bytes")]
    pub raw_msg: Vec<u8>,
}
```

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L226-252)
```rust
    pub fn from_bytes<T: DeserializeOwned>(&self, bytes: &[u8]) -> anyhow::Result<T> {
        // Start the deserialization timer
        let deserialization_timer = start_serialization_timer(*self, DESERIALIZATION_LABEL);

        // Deserialize the message
        let result = match self.encoding() {
            Encoding::Bcs(limit) => self.bcs_decode(bytes, limit),
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
            Encoding::Json => serde_json::from_slice(bytes).map_err(|e| anyhow!("{:?}", e)),
        };

        // Only record the duration if deserialization was successful
        if result.is_ok() {
            deserialization_timer.observe_duration();
        }

        result
    }
```

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

**File:** config/src/config/network_config.rs (L37-50)
```rust
pub const NETWORK_CHANNEL_SIZE: usize = 1024;
pub const PING_INTERVAL_MS: u64 = 10_000;
pub const PING_TIMEOUT_MS: u64 = 20_000;
pub const PING_FAILURES_TOLERATED: u64 = 3;
pub const CONNECTIVITY_CHECK_INTERVAL_MS: u64 = 5000;
pub const MAX_CONNECTION_DELAY_MS: u64 = 60_000; /* 1 minute */
pub const MAX_FULLNODE_OUTBOUND_CONNECTIONS: usize = 6;
pub const MAX_INBOUND_CONNECTIONS: usize = 100;
pub const MAX_MESSAGE_METADATA_SIZE: usize = 128 * 1024; /* 128 KiB: a buffer for metadata that might be added to messages by networking */
pub const MESSAGE_PADDING_SIZE: usize = 2 * 1024 * 1024; /* 2 MiB: a safety buffer to allow messages to get larger during serialization */
pub const MAX_APPLICATION_MESSAGE_SIZE: usize =
    (MAX_MESSAGE_SIZE - MAX_MESSAGE_METADATA_SIZE) - MESSAGE_PADDING_SIZE; /* The message size that applications should check against */
pub const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024; /* 4 MiB large messages will be chunked into multiple frames and streamed */
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
```

**File:** network/framework/src/protocols/network/mod.rs (L294-320)
```rust
        NetworkMessage::DirectSendMsg(request) => {
            crate::counters::inbound_queue_delay_observe(request.protocol_id, dt_seconds);
            request_to_network_event(peer_id, &request).map(|msg| Event::Message(peer_id, msg))
        },
        _ => None,
    }
}

/// Converts a `SerializedRequest` into a network `Event` for sending to other nodes
fn request_to_network_event<TMessage: Message, Request: IncomingRequest>(
    peer_id: PeerId,
    request: &Request,
) -> Option<TMessage> {
    match request.to_message() {
        Ok(msg) => Some(msg),
        Err(err) => {
            let data = request.data();
            warn!(
                SecurityEvent::InvalidNetworkEvent,
                error = ?err,
                remote_peer_id = peer_id.short_str(),
                protocol_id = request.protocol_id(),
                data_prefix = hex::encode(&data[..min(16, data.len())]),
            );
            None
        },
    }
```

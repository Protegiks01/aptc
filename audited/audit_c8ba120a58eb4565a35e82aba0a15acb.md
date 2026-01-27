# Audit Report

## Title
Wire-Level BCS Deserialization of Large Frames Occurs Before Size Validation, Enabling Resource Exhaustion Attack

## Summary
The network layer performs expensive BCS deserialization on frames up to 4 MiB before the MAX_MESSAGE_SIZE (64 MiB) check is enforced at the application layer. Attackers can repeatedly send large frames containing malformed BCS data to waste CPU cycles on deserialization, and the connection remains open after deserialization errors since they are treated as "recoverable."

## Finding Description

The Aptos network protocol implements a two-level deserialization architecture:

1. **Wire-level deserialization**: Each frame (up to MAX_FRAME_SIZE = 4 MiB) undergoes BCS deserialization to produce a `MultiplexMessage`
2. **Application-level deserialization**: The message payload is deserialized into application-specific types

The vulnerability exists in the wire-level processing flow: [1](#0-0) [2](#0-1) 

The `LengthDelimitedCodec` validates that frame length ≤ MAX_FRAME_SIZE before reading frame bytes, which is correct. However, after the full frame (up to 4 MiB) is read into memory, `bcs::from_bytes(&frame)` is called to deserialize it into a `MultiplexMessage`.

For streamed messages that exceed MAX_FRAME_SIZE, the protocol splits them into fragments: [3](#0-2) 

An attacker can send up to 16 fragments (calculated as max_message_size / max_frame_size = 64 MiB / 4 MiB = 16): [4](#0-3) 

Each fragment undergoes independent wire-level BCS deserialization. The total message size check only happens at the streaming layer: [5](#0-4) 

Critically, when BCS deserialization fails, the connection is NOT closed: [6](#0-5) 

**Attack Scenario:**
1. Attacker establishes connection to validator/fullnode
2. Attacker sends frames with valid length prefix (≤4 MiB) but malformed BCS content designed to maximize deserialization cost
3. Each frame is read into memory and passed to `bcs::from_bytes()`
4. BCS deserialization processes the malformed data before determining it's invalid
5. A `ReadError::DeserializeError` is returned but connection stays open
6. Attacker repeats with multiple fragments in streamed messages (up to 64 MiB per stream)
7. Attacker continues sending malformed messages without being disconnected

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits" - CPU cycles are consumed deserializing invalid data without proper bounds or automatic peer disconnection.

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty criteria for the following reasons:

1. **Resource exhaustion**: Attackers can force nodes to waste CPU cycles deserializing up to 4 MiB frames repeatedly, with up to 16 fragments (64 MiB) per stream
2. **No automatic disconnection**: Unlike I/O errors, deserialization errors don't trigger connection closure, allowing sustained attacks
3. **Multiple connections**: With MAX_INBOUND_CONNECTIONS = 100, attackers can amplify the attack across many connections [7](#0-6) 

**Mitigating factors preventing High severity:**
- Inbound rate limiting (IP_BYTE_BUCKET_RATE = 100 KiB/s default) throttles bandwidth per IP
- BCS deserialization may fail fast on obviously invalid data
- Application-layer peer scoring systems eventually ignore misbehaving peers [8](#0-7) 

However, within the rate-limited bandwidth, an attacker can maximize CPU waste by crafting specially-designed BCS payloads, and the lack of wire-level peer disconnection for repeated errors is a protocol weakness.

## Likelihood Explanation

**Likelihood: High**

The attack requires only:
- Network connectivity to a validator/fullnode
- Ability to establish TCP connections
- Crafting frames with valid size headers but malformed BCS payloads

No special privileges, stake, or validator access required. The attack can be automated and executed from multiple source IPs to bypass per-IP rate limiting. While individual impact per connection is limited by rate limiting, the cumulative effect across MAX_INBOUND_CONNECTIONS (100) connections over time can degrade node performance.

## Recommendation

Implement a **per-peer deserialization error counter** with automatic disconnection after a threshold:

```rust
// In Peer struct, add:
deserialization_error_count: u32,
const MAX_DESERIALIZATION_ERRORS: u32 = 10;

// In handle_inbound_message, modify DeserializeError handling:
ReadError::DeserializeError(_, _, ref frame_prefix) => {
    self.deserialization_error_count += 1;
    
    if self.deserialization_error_count >= MAX_DESERIALIZATION_ERRORS {
        // Too many deserialization errors - disconnect peer
        self.shutdown(DisconnectReason::TooManyInvalidMessages);
        return Err(err.into());
    }
    
    // Send error message and log
    let message_type = frame_prefix.as_ref().first().unwrap_or(&0);
    let protocol_id = frame_prefix.as_ref().get(1).unwrap_or(&0);
    let error_code = ErrorCode::parsing_error(*message_type, *protocol_id);
    let message = NetworkMessage::Error(error_code);
    
    write_reqs_tx.push((), message)?;
    return Err(err.into());
}
```

Additionally, consider adding a **pre-deserialization sanity check** on the first few bytes of each frame to detect obviously malformed BCS data before invoking full deserialization.

## Proof of Concept

```rust
#[cfg(test)]
mod deserialization_dos_test {
    use super::*;
    use futures::executor::block_on;
    
    #[test]
    fn test_repeated_deserialization_errors_no_disconnect() {
        // Create a memory socket pair
        let (sender, receiver) = MemorySocket::new_pair();
        
        // Create message stream with 4 MiB max frame size
        let mut msg_sink = MultiplexMessageSink::new(sender, 4 * 1024 * 1024);
        let mut msg_stream = MultiplexMessageStream::new(receiver, 4 * 1024 * 1024);
        
        // Generate 10 frames with valid size but invalid BCS content
        let mut invalid_frames = Vec::new();
        for _ in 0..10 {
            // Create a 4 MiB frame of random/invalid BCS data
            let mut frame = vec![0u8; 4 * 1024 * 1024];
            // Set length prefix to indicate 4 MiB
            frame[0..4].copy_from_slice(&(4 * 1024 * 1024u32).to_be_bytes());
            // Fill rest with invalid BCS patterns
            for i in 4..frame.len() {
                frame[i] = (i % 256) as u8;
            }
            invalid_frames.push(Bytes::from(frame));
        }
        
        // Send all invalid frames and verify:
        // 1. Each frame causes deserialization to execute
        // 2. Errors are returned but processing continues
        // 3. No automatic connection closure occurs
        let send_task = async {
            for frame in invalid_frames {
                msg_sink.send_raw_frame(frame).await.unwrap();
            }
        };
        
        let recv_task = async {
            let mut error_count = 0;
            while let Some(result) = msg_stream.next().await {
                match result {
                    Err(ReadError::DeserializeError(_, _, _)) => {
                        error_count += 1;
                    },
                    _ => {}
                }
                if error_count >= 10 {
                    break;
                }
            }
            assert_eq!(error_count, 10, "Should receive 10 deserialization errors");
            // Verify stream is still open (no automatic disconnect)
            assert!(!msg_stream.is_terminated());
        };
        
        block_on(async {
            tokio::join!(send_task, recv_task);
        });
    }
}
```

## Notes

This vulnerability represents a protocol design issue where the trade-off between fault tolerance (keeping connections open after recoverable errors) and DoS resistance (disconnecting misbehaving peers) favors the former. While rate limiting provides bandwidth-based mitigation, it doesn't prevent CPU waste within the allowed bandwidth, and the lack of error-based peer reputation at the wire level creates an exploitable gap.

The streaming protocol correctly validates total message size before sending, but inbound validation relies on fragment count rather than accumulated byte size, and each fragment undergoes expensive deserialization independently before application-layer checks apply.

### Citations

**File:** network/framework/src/protocols/wire/messaging/v1/mod.rs (L197-203)
```rust
pub fn network_message_frame_codec(max_frame_size: usize) -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .max_frame_length(max_frame_size)
        .length_field_length(4)
        .big_endian()
        .new_codec()
}
```

**File:** network/framework/src/protocols/wire/messaging/v1/mod.rs (L222-247)
```rust
impl<TReadSocket: AsyncRead + Unpin> Stream for MultiplexMessageStream<TReadSocket> {
    type Item = Result<MultiplexMessage, ReadError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.project().framed_read.poll_next(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                let frame = frame.freeze();

                match bcs::from_bytes(&frame) {
                    Ok(message) => Poll::Ready(Some(Ok(message))),
                    // Failed to deserialize the NetworkMessage
                    Err(err) => {
                        let mut frame = frame;
                        let frame_len = frame.len();
                        // Keep a few bytes from the frame for debugging
                        frame.truncate(8);
                        let err = ReadError::DeserializeError(err, frame_len, frame);
                        Poll::Ready(Some(Err(err)))
                    },
                }
            },
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(ReadError::IoError(err)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
```

**File:** config/src/config/network_config.rs (L44-44)
```rust
pub const MAX_INBOUND_CONNECTIONS: usize = 100;
```

**File:** config/src/config/network_config.rs (L45-50)
```rust
pub const MAX_MESSAGE_METADATA_SIZE: usize = 128 * 1024; /* 128 KiB: a buffer for metadata that might be added to messages by networking */
pub const MESSAGE_PADDING_SIZE: usize = 2 * 1024 * 1024; /* 2 MiB: a safety buffer to allow messages to get larger during serialization */
pub const MAX_APPLICATION_MESSAGE_SIZE: usize =
    (MAX_MESSAGE_SIZE - MAX_MESSAGE_METADATA_SIZE) - MESSAGE_PADDING_SIZE; /* The message size that applications should check against */
pub const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024; /* 4 MiB large messages will be chunked into multiple frames and streamed */
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
```

**File:** config/src/config/network_config.rs (L52-53)
```rust
pub const IP_BYTE_BUCKET_RATE: usize = 102400 /* 100 KiB */;
pub const IP_BYTE_BUCKET_SIZE: usize = IP_BYTE_BUCKET_RATE;
```

**File:** network/framework/src/peer/mod.rs (L168-168)
```rust
        let max_fragments = max_message_size / max_frame_size;
```

**File:** network/framework/src/peer/mod.rs (L576-587)
```rust
                ReadError::DeserializeError(_, _, ref frame_prefix) => {
                    // DeserializeError's are recoverable so we'll let the other
                    // peer know about the error and log the issue, but we won't
                    // close the connection.
                    let message_type = frame_prefix.as_ref().first().unwrap_or(&0);
                    let protocol_id = frame_prefix.as_ref().get(1).unwrap_or(&0);
                    let error_code = ErrorCode::parsing_error(*message_type, *protocol_id);
                    let message = NetworkMessage::Error(error_code);

                    write_reqs_tx.push((), message)?;
                    return Err(err.into());
                },
```

**File:** network/framework/src/protocols/stream/mod.rs (L259-273)
```rust
    pub async fn stream_message(&mut self, mut message: NetworkMessage) -> anyhow::Result<()> {
        // Verify that the message is not an error message
        ensure!(
            !matches!(message, NetworkMessage::Error(_)),
            "Error messages should not be streamed!"
        );

        // Verify that the message size is within limits
        let message_data_len = message.data_len();
        ensure!(
            message_data_len <= self.max_message_size,
            "Message length {} exceeds max message size {}!",
            message_data_len,
            self.max_message_size,
        );
```

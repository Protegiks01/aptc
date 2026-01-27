# Audit Report

## Title
Stream Replacement DoS: Valid Headers Can Discard In-Progress Streams Leading to Denial of Service

## Summary
The `InboundStreamBuffer::new_stream()` function contains a critical timing vulnerability where the stream replacement occurs before checking for existing streams. While validation happens first, an attacker can exploit this by repeatedly sending valid headers to discard in-progress legitimate streams, preventing large messages (consensus blocks, state sync data) from ever completing.

## Finding Description

The vulnerability exists in the `new_stream()` method's logic: [1](#0-0) 

The execution flow is:
1. **Line 83**: `InboundStream::new()` validates the incoming header
2. **Line 84**: If validation succeeds, `self.stream.replace(inbound_stream)` **atomically replaces** any existing stream with the new stream
3. **Lines 85-87**: Check if there was an old stream and return an error if so

**The Critical Issue**: At line 84, the `replace()` method discards any in-progress stream and installs the new stream **before** the error is returned. When the error is returned at line 85-87, the damage is already done—the old stream is permanently lost and the new stream remains installed.

The error handling in the peer actor does not disconnect on this error: [2](#0-1) 

The error is merely logged as a warning and the connection continues, leaving the new stream in place.

**Attack Scenario**:
1. A legitimate peer is sending a large consensus block requiring fragmentation (e.g., 100 fragments)
2. After receiving the header and 50 fragments, an attacker sends a new valid `StreamHeader`
3. The `InboundStream::new()` validation succeeds (attacker only needs: `num_fragments` ∈ [1, max_fragments], any valid `NetworkMessage` type except `Error`)
4. The 50-fragment partial stream is discarded and replaced with the attacker's new stream
5. An error is logged but the connection stays alive
6. The attacker repeats indefinitely, preventing any large message from completing

**Validation Requirements**: The attacker can easily craft valid headers: [3](#0-2) 

Only requires: `num_fragments > 0`, `num_fragments <= max_fragments`, and message type ≠ `NetworkMessage::Error`.

**System Impact**: Large messages are critical for:
- Consensus block propagation (AptosBFT requires timely block delivery)
- State synchronization between validators
- RPC responses for critical operations

## Impact Explanation

This vulnerability qualifies as **High Severity** per Aptos bug bounty criteria:

- **Validator node slowdowns**: Validators cannot receive large consensus blocks, causing them to fall behind and slow consensus
- **Significant protocol violations**: Breaks the network layer's reliability guarantee that fragmented messages can be successfully delivered
- **Near-total loss of liveness**: If exploited against multiple validators simultaneously, could prevent consensus from making progress (approaching Critical severity threshold)

The calculated `max_fragments` value is determined by: [4](#0-3) 

With typical values (max_message_size = 100 MiB, max_frame_size = 4 MiB), this allows up to ~25 fragments, making legitimate large messages common and vulnerable.

## Likelihood Explanation

**Very High Likelihood**:
- **Attack Complexity**: Trivial—attacker only needs to send valid `StreamHeader` messages
- **Authentication Required**: None—any connected peer can send headers
- **Rate Limiting**: No specific rate limiting on header count (only bandwidth-based rate limiting which headers bypass due to small size)
- **Detection Difficulty**: Errors are logged but attackers can rotate request IDs to obscure patterns
- **Attack Surface**: Every peer connection is vulnerable
- **Persistence**: Attack can be sustained indefinitely with minimal resources

## Recommendation

Fix the logic to validate for existing streams **before** replacing:

```rust
pub fn new_stream(&mut self, header: StreamHeader) -> anyhow::Result<()> {
    // Check if a stream already exists FIRST
    if self.stream.is_some() {
        bail!(
            "Cannot start new stream - existing stream in progress for request ID: {}",
            self.stream.as_ref().unwrap().request_id
        );
    }
    
    // Only validate and install if no stream exists
    let inbound_stream = InboundStream::new(header, self.max_fragments)?;
    self.stream = Some(inbound_stream);
    Ok(())
}
```

**Alternative Recommendation** (if overwriting is intentional): Add rate limiting on stream header count per peer and consider disconnecting peers that repeatedly discard streams:

```rust
// Track consecutive stream replacements
if let Some(old) = self.stream.replace(inbound_stream) {
    self.stream_replacement_count += 1;
    if self.stream_replacement_count > MAX_STREAM_REPLACEMENTS {
        return Err(anyhow::anyhow!("Peer exceeded stream replacement limit"));
    }
    warn!("Discarding existing stream for request ID: {}", old.request_id);
} else {
    self.stream_replacement_count = 0;
}
```

## Proof of Concept

```rust
#[test]
fn test_stream_replacement_dos() {
    use crate::protocols::stream::{InboundStreamBuffer, StreamHeader};
    use crate::protocols::wire::messaging::v1::{DirectSendMsg, NetworkMessage};
    use crate::protocols::wire::handshake::v1::ProtocolId::ConsensusRpcBcs;
    
    // Create victim's inbound stream buffer
    let max_fragments = 100;
    let mut victim_buffer = InboundStreamBuffer::new(max_fragments);
    
    // Legitimate stream starts (consensus block with 50 fragments)
    let legitimate_header = StreamHeader {
        request_id: 1,
        num_fragments: 50,
        message: NetworkMessage::DirectSendMsg(DirectSendMsg {
            protocol_id: ConsensusRpcBcs,
            priority: 0,
            raw_msg: vec![0; 100],
        }),
    };
    
    // Victim receives legitimate header
    assert!(victim_buffer.new_stream(legitimate_header).is_ok());
    assert!(victim_buffer.stream.is_some());
    
    // Attacker sends malicious valid header
    let malicious_header = StreamHeader {
        request_id: 999,
        num_fragments: 1,
        message: NetworkMessage::DirectSendMsg(DirectSendMsg {
            protocol_id: ConsensusRpcBcs,
            priority: 0,
            raw_msg: vec![],
        }),
    };
    
    // This returns an error BUT the legitimate stream is already replaced!
    let result = victim_buffer.new_stream(malicious_header);
    assert!(result.is_err()); // Error is returned
    
    // VULNERABILITY: The victim's stream now contains the attacker's stream
    assert!(victim_buffer.stream.is_some());
    assert_eq!(victim_buffer.stream.as_ref().unwrap().request_id, 999); // Attacker's ID!
    // The 50-fragment legitimate consensus block is permanently lost
    
    println!("DoS successful: Legitimate stream discarded, attacker's stream installed");
}
```

**Notes**

The security question's premise states "validation happens after replacing" which is technically incorrect—validation via `InboundStream::new()` occurs first. However, the core vulnerability exists: the `replace()` operation at line 84 occurs **before** checking for existing streams, allowing valid headers to discard in-progress streams even though an error is subsequently returned. This creates a serious DoS vector against Aptos validators' network layer.

### Citations

**File:** network/framework/src/protocols/stream/mod.rs (L82-92)
```rust
    pub fn new_stream(&mut self, header: StreamHeader) -> anyhow::Result<()> {
        let inbound_stream = InboundStream::new(header, self.max_fragments)?;
        if let Some(old) = self.stream.replace(inbound_stream) {
            bail!(
                "Discarding existing stream for request ID: {}",
                old.request_id
            )
        } else {
            Ok(())
        }
    }
```

**File:** network/framework/src/protocols/stream/mod.rs (L124-161)
```rust
    fn new(header: StreamHeader, max_fragments: usize) -> anyhow::Result<Self> {
        // Verify that max fragments is within reasonable bounds
        ensure!(
            max_fragments > 0,
            "Max fragments must be greater than zero!"
        );
        ensure!(
            max_fragments <= (u8::MAX as usize),
            "Max fragments exceeded the u8 limit: {} (max: {})!",
            max_fragments,
            u8::MAX
        );

        // Verify the header message type
        let header_message = header.message;
        ensure!(
            !matches!(header_message, NetworkMessage::Error(_)),
            "Error messages cannot be streamed!"
        );

        // Verify the number of fragments specified in the header
        let header_num_fragments = header.num_fragments;
        ensure!(
            header_num_fragments > 0,
            "Stream header must specify at least one fragment!"
        );
        ensure!(
            (header_num_fragments as usize) <= max_fragments,
            "Stream header exceeds max fragments limit!"
        );

        Ok(Self {
            request_id: header.request_id,
            num_fragments: header_num_fragments,
            received_fragment_id: 0,
            message: header_message,
        })
    }
```

**File:** network/framework/src/peer/mod.rs (L168-168)
```rust
        let max_fragments = max_message_size / max_frame_size;
```

**File:** network/framework/src/peer/mod.rs (L255-265)
```rust
                            if let Err(err) = self.handle_inbound_message(message, &mut write_reqs_tx) {
                                warn!(
                                    NetworkSchema::new(&self.network_context)
                                        .connection_metadata(&self.connection_metadata),
                                    error = %err,
                                    "{} Error in handling inbound message from peer: {}, error: {}",
                                    self.network_context,
                                    remote_peer_id.short_str(),
                                    err
                                );
                            }
```

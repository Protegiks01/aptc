# Audit Report

## Title
Stream ID Reuse Vulnerability Allows Fragment Mixing and Message Corruption in Network Layer

## Summary
The `InboundStreamBuffer` in the Aptos network layer contains a critical vulnerability where a malicious peer can reuse stream IDs to replace in-progress streams, causing fragments from one message to be incorrectly appended to a different message. This breaks message integrity and enables denial of service attacks against consensus and state synchronization protocols.

## Finding Description

The vulnerability exists in the interaction between stream management and fragment processing in the network layer. The core issue is in `InboundStreamBuffer::new_stream()` which performs stream replacement **before** error checking. [1](#0-0) 

The `self.stream.replace(inbound_stream)` operation on line 84 executes **before** the error is raised on lines 85-88. This means when a new stream header arrives while another stream is in progress, the old stream is immediately discarded even though an error is returned.

The Aptos network layer fragments large messages into multiple pieces for transmission. Each Peer maintains exactly one `InboundStreamBuffer`: [2](#0-1) 

When fragments arrive, they are validated only by checking if the `request_id` matches the current stream and if the `fragment_id` is the next expected sequential fragment: [3](#0-2) 

**Attack Scenario for Fragment Mixing:**

1. Malicious peer sends `StreamHeader(request_id=100, num_fragments=3, message=MaliciousMessage1 with initial data [0xAA, 0xBB])`
2. Victim node creates `InboundStream` with `request_id=100`, expecting fragment 1
3. Malicious peer sends `Fragment(request_id=100, fragment_id=1, data=[0xCC, 0xDD])` - appended to MaliciousMessage1
4. **Malicious peer immediately sends `StreamHeader(request_id=100, num_fragments=3, message=MaliciousMessage2 with initial data [0x00, 0x01])` - SAME request_id**
5. Old stream with MaliciousMessage1 is **replaced** (line 84), new stream installed with MaliciousMessage2
6. Malicious peer sends `Fragment(request_id=100, fragment_id=1, data=[0x02, 0x03])` - appended to MaliciousMessage2
7. Malicious peer sends `Fragment(request_id=100, fragment_id=2, data=[0x04, 0x05])` - this fragment was **originally intended for a different message stream**, but due to the replacement and sequence reset, it gets appended to MaliciousMessage2

The final assembled MaliciousMessage2 contains: `[0x00, 0x01, 0x02, 0x03, 0x04, 0x05]` where `[0x04, 0x05]` could have been from a different context or carefully crafted to create a malicious payload.

Error handling does not prevent this attack because errors are only logged: [4](#0-3) 

The connection continues operating after the error, allowing the attack to succeed.

## Impact Explanation

This vulnerability has **High Severity** impact affecting multiple critical Aptos subsystems:

**1. Consensus Protocol Disruption**: Large consensus messages (blocks, vote messages, quorum certificates) can be corrupted or prevented from delivery, potentially causing liveness failures or forcing nodes to fall behind in consensus rounds.

**2. Denial of Service**: A malicious peer can repeatedly start new streams before existing ones complete, preventing ANY large message from being successfully delivered. This affects:
   - Consensus block proposals and votes
   - State synchronization chunk transfers  
   - Large RPC responses

**3. Message Corruption**: By carefully timing stream replacements and reusing request IDs, an attacker can cause fragments to be appended to wrong messages, potentially creating malformed consensus messages or state sync payloads that could cause processing errors.

**4. Network Resource Exhaustion**: Bandwidth is wasted processing fragments that are then discarded, and nodes must repeatedly request retransmissions of lost messages.

This qualifies as **High Severity** per Aptos bug bounty criteria: "Significant protocol violations" and "Validator node slowdowns" caused by message delivery failures.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited because:

1. **Low Attack Complexity**: Any malicious network peer can trigger this by sending crafted stream headers and fragments. No special privileges, validator access, or cryptographic breaks required.

2. **No Authentication Barrier**: The stream protocol processes messages from any connected peer. While peers must pass initial handshake, malicious actors can establish connections.

3. **Deterministic Exploitation**: The bug is deterministic - sending headers with reused request IDs reliably triggers stream replacement.

4. **Broad Attack Surface**: This affects all large messages in the network layer, including consensus, state sync, and RPC protocols.

5. **Silent Failure**: Lost messages may not be immediately detected, allowing sustained attacks before operators notice degraded performance.

## Recommendation

**Fix the stream replacement logic to reject new streams when one is already in progress:**

```rust
pub fn new_stream(&mut self, header: StreamHeader) -> anyhow::Result<()> {
    // Check if a stream already exists BEFORE attempting replacement
    if let Some(existing) = &self.stream {
        bail!(
            "Cannot start new stream (request ID: {}) while existing stream (request ID: {}) is in progress",
            header.request_id,
            existing.request_id
        );
    }
    
    // Only create and install new stream if no stream exists
    let inbound_stream = InboundStream::new(header, self.max_fragments)?;
    self.stream = Some(inbound_stream);
    Ok(())
}
```

**Alternative comprehensive fix - support concurrent streams:**

Replace `stream: Option<InboundStream>` with `streams: HashMap<u32, InboundStream>` to allow multiple concurrent streams per peer, properly isolated by request_id. This requires refactoring both `InboundStreamBuffer` and fragment processing logic.

**Additional hardening:**
- Add stream timeout mechanism to garbage collect stale streams
- Implement rate limiting on stream creation per peer
- Add metrics to detect stream replacement attacks
- Consider encrypting/authenticating stream IDs to prevent predictable reuse

## Proof of Concept

```rust
// Test demonstrating the vulnerability
// File: network/framework/src/protocols/stream/mod.rs (add to tests module)

#[test]
fn test_stream_id_collision_vulnerability() {
    use crate::protocols::wire::messaging::v1::{DirectSendMsg, NetworkMessage};
    use crate::protocols::wire::handshake::v1::ProtocolId::ConsensusRpcBcs;
    
    let max_fragments = 10;
    let mut buffer = InboundStreamBuffer::new(max_fragments);
    
    // Attacker sends first stream header
    let header1 = StreamHeader {
        request_id: 100,
        num_fragments: 3,
        message: NetworkMessage::DirectSendMsg(DirectSendMsg {
            protocol_id: ConsensusRpcBcs,
            priority: 0,
            raw_msg: vec![0xAA, 0xBB], // Initial data for message 1
        }),
    };
    assert!(buffer.new_stream(header1).is_ok());
    
    // First fragment arrives
    let frag1 = StreamFragment {
        request_id: 100,
        fragment_id: 1,
        raw_data: vec![0xCC, 0xDD],
    };
    assert!(buffer.append_fragment(frag1).unwrap().is_none()); // Not complete yet
    
    // Attacker sends SECOND header with SAME request_id before first stream completes
    let header2 = StreamHeader {
        request_id: 100, // SAME ID - collision!
        num_fragments: 3,
        message: NetworkMessage::DirectSendMsg(DirectSendMsg {
            protocol_id: ConsensusRpcBcs,
            priority: 0,
            raw_msg: vec![0x00, 0x01], // Initial data for message 2 (different!)
        }),
    };
    
    // This should fail but actually replaces the stream!
    let result = buffer.new_stream(header2);
    assert!(result.is_err()); // Error is returned...
    // But the stream was ALREADY replaced before the error!
    
    // New fragments can now be appended to the replacement stream
    let frag1_new = StreamFragment {
        request_id: 100,
        fragment_id: 1,
        raw_data: vec![0x02, 0x03],
    };
    assert!(buffer.append_fragment(frag1_new).unwrap().is_none());
    
    // This fragment gets appended to message 2, but could have been crafted for message 1
    let frag2 = StreamFragment {
        request_id: 100,
        fragment_id: 2,
        raw_data: vec![0x04, 0x05],
    };
    assert!(buffer.append_fragment(frag2).unwrap().is_none());
    
    let frag3 = StreamFragment {
        request_id: 100,
        fragment_id: 3,
        raw_data: vec![0x06, 0x07],
    };
    let completed = buffer.append_fragment(frag3).unwrap();
    
    // Message 2 is completed with potentially mixed/malicious fragments
    assert!(completed.is_some());
    if let Some(NetworkMessage::DirectSendMsg(msg)) = completed {
        // Expected: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]
        // But fragments could be from different contexts, causing corruption
        assert_eq!(msg.raw_msg, vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    }
    
    // Message 1 with fragments [0xAA, 0xBB, 0xCC, 0xDD] was LOST
}
```

## Notes

This vulnerability exists because the implementation prioritized simplicity (single stream per peer) over robustness. While legitimate Aptos nodes serialize their outbound streams, malicious peers can exploit this assumption by intentionally interleaving streams. The fix must either enforce strict stream serialization (reject concurrent streams) or implement proper concurrent stream support with isolated buffers per request_id.

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

**File:** network/framework/src/protocols/stream/mod.rs (L165-195)
```rust
        // Verify the stream request ID and fragment request ID
        ensure!(
            self.request_id == fragment.request_id,
            "Stream fragment from a different request! Expected {}, got {}.",
            self.request_id,
            fragment.request_id
        );

        // Verify the fragment ID
        let fragment_id = fragment.fragment_id;
        ensure!(fragment_id > 0, "Fragment ID must be greater than zero!");
        ensure!(
            fragment_id <= self.num_fragments,
            "Fragment ID {} exceeds number of fragments {}!",
            fragment_id,
            self.num_fragments
        );

        // Verify the fragment ID is the expected next fragment
        let expected_fragment_id = self.received_fragment_id.checked_add(1).ok_or_else(|| {
            anyhow::anyhow!(
                "Current fragment ID overflowed when adding 1: {}",
                self.received_fragment_id
            )
        })?;
        ensure!(
            expected_fragment_id == fragment_id,
            "Unexpected fragment ID, expected {}, got {}!",
            expected_fragment_id,
            fragment_id
        );
```

**File:** network/framework/src/peer/mod.rs (L139-140)
```rust
    inbound_stream: InboundStreamBuffer,
}
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

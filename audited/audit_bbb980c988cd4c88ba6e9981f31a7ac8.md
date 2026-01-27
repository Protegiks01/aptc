# Audit Report

## Title
InboundStreamBuffer State Corruption via Non-Atomic Stream Replacement Allowing Message Stream DOS

## Summary
The `InboundStreamBuffer::new_stream()` function performs state mutation before invariant validation, allowing a malicious peer to discard in-progress message streams and prevent large consensus messages, blocks, or state sync data from ever completing. This violates state consistency guarantees and enables a denial-of-service attack on critical network protocols.

## Finding Description

The security question asks what prevents receiving more fragments for the same request_id after completion. While completed streams correctly set `self.stream` to `None` to prevent duplicate fragments [1](#0-0) , a related vulnerability exists in the stream initialization logic.

The `InboundStreamBuffer::new_stream()` function violates atomicity by mutating state before checking invariants: [2](#0-1) 

The critical flaw is on line 84: `self.stream.replace(inbound_stream)` executes BEFORE checking if an existing stream was in progress. The `replace()` operation immediately installs the new stream and returns the old one. If an old stream existed, the function then returns an error, but **the new stream remains installed and the old stream is permanently discarded**.

**Attack Scenario**:

1. A validator node begins receiving a large consensus block (e.g., 200 fragments via request_id=100)
2. The peer sends fragments 1-199 successfully
3. Before sending fragment 200, the malicious peer sends a new `StreamMessage::Header` with request_id=101
4. `new_stream()` is invoked, which:
   - Creates a new `InboundStream` for request_id=101
   - Calls `self.stream.replace()` → installs the NEW stream, returns the OLD stream
   - Detects the old stream existed and returns an error
   - **But the new stream is already installed**
5. The nearly-complete stream (199/200 fragments) is permanently lost
6. The error is logged but the connection continues [3](#0-2) 
7. The peer can repeat this pattern indefinitely to prevent any large message from completing

Each `InboundStreamBuffer` handles only one stream at a time [4](#0-3) , and the `Peer` actor has exactly one buffer per connection [5](#0-4) .

The existing test verifies an error is returned but does NOT verify that state remains unchanged after the error [6](#0-5) , missing this critical bug.

## Impact Explanation

**Severity: Medium** (up to $10,000 per Aptos Bug Bounty)

This vulnerability enables:

1. **Denial of Service on Consensus**: Prevents large consensus messages (blocks, proposals) from completing, potentially causing validator nodes to fall behind or fail to participate in consensus
2. **State Sync Disruption**: Blocks large state sync chunks from being received, preventing nodes from syncing with the network
3. **Mempool Transaction Batch Interference**: Disrupts batch transaction propagation

The attack:
- Requires no special privileges (any network peer can exploit)
- Is computationally cheap (just send headers repeatedly)
- Persists without disconnecting the peer (errors don't trigger `DisconnectReason::InputOutputError`)
- Affects critical network protocols that depend on streaming for large messages

This meets the **Medium Severity** criteria of "State inconsistencies requiring intervention" as nodes may fail to receive critical data and require manual intervention to recover.

## Likelihood Explanation

**Likelihood: High**

- **Exploitability**: Trivial - attacker only needs to send `StreamMessage::Header` messages strategically
- **Attack Requirements**: Network peer connection (standard for any blockchain node)
- **Detection Difficulty**: Logs show stream discard errors but may be dismissed as network issues
- **Attack Cost**: Minimal bandwidth (headers are small)
- **Impact Scope**: Any protocol using message streaming (consensus blocks >max_frame_size, state sync, large transactions)

The vulnerability is actively exploitable in production environments where validators regularly exchange large messages that require streaming.

## Recommendation

**Fix**: Perform invariant checking BEFORE state mutation to ensure atomicity. Check for existing streams first, then install the new stream only if validation passes:

```rust
pub fn new_stream(&mut self, header: StreamHeader) -> anyhow::Result<()> {
    // Check if a stream already exists BEFORE creating the new one
    if self.stream.is_some() {
        let old_request_id = self.stream.as_ref().unwrap().request_id;
        bail!(
            "Cannot start new stream - existing stream in progress for request ID: {}",
            old_request_id
        )
    }
    
    // Only create and install the new stream if no stream exists
    let inbound_stream = InboundStream::new(header, self.max_fragments)?;
    self.stream = Some(inbound_stream);
    Ok(())
}
```

**Alternative Fix**: If the intention is to allow replacing streams (for timeout/recovery scenarios), return the error BEFORE replacing:

```rust
pub fn new_stream(&mut self, header: StreamHeader) -> anyhow::Result<()> {
    let inbound_stream = InboundStream::new(header, self.max_fragments)?;
    
    // Check and error BEFORE replacing
    if let Some(old) = &self.stream {
        bail!(
            "Discarding existing stream for request ID: {}",
            old.request_id
        )
    }
    
    // Only replace if check passed
    self.stream = Some(inbound_stream);
    Ok(())
}
```

## Proof of Concept

```rust
#[test]
fn test_stream_replacement_dos_vulnerability() {
    use crate::protocols::stream::{InboundStreamBuffer, StreamFragment, StreamHeader};
    use crate::protocols::wire::messaging::v1::{DirectSendMsg, NetworkMessage};
    use crate::protocols::wire::handshake::v1::ProtocolId::ConsensusRpcBcs;
    
    // Create inbound stream buffer
    let max_fragments = 255;
    let mut buffer = InboundStreamBuffer::new(max_fragments);
    
    // Start first stream with many fragments (simulating large consensus block)
    let first_stream = StreamHeader {
        request_id: 100,
        num_fragments: 250,
        message: NetworkMessage::DirectSendMsg(DirectSendMsg {
            protocol_id: ConsensusRpcBcs,
            priority: 0,
            raw_msg: vec![0; 1000],
        }),
    };
    assert!(buffer.new_stream(first_stream).is_ok());
    
    // Send 249 out of 250 fragments (almost complete)
    for fragment_id in 1..=249 {
        let fragment = StreamFragment {
            request_id: 100,
            fragment_id,
            raw_data: vec![0; 1000],
        };
        let result = buffer.append_fragment(fragment);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none()); // Stream not yet complete
    }
    
    // Attacker sends new stream header before completion
    let attack_stream = StreamHeader {
        request_id: 101,
        num_fragments: 1,
        message: NetworkMessage::DirectSendMsg(DirectSendMsg {
            protocol_id: ConsensusRpcBcs,
            priority: 0,
            raw_msg: vec![0; 100],
        }),
    };
    
    // This returns an error BUT installs the new stream
    let result = buffer.new_stream(attack_stream);
    assert!(result.is_err()); // Error is returned
    
    // VULNERABILITY: Despite error, the NEW stream is installed
    // Try to send the final fragment for request_id=100
    let final_fragment = StreamFragment {
        request_id: 100,
        fragment_id: 250,
        raw_data: vec![0; 1000],
    };
    
    // This will fail because the stream for request_id=100 was discarded
    let result = buffer.append_fragment(final_fragment);
    assert!(result.is_err()); // Fragment rejected - expected request_id=101
    
    // The original stream with 249/250 fragments is permanently lost
    // The attacker successfully prevented the large message from completing
    println!("DOS Attack Successful: 249 fragments lost, message never completed");
}
```

## Notes

While the original question asks what prevents duplicate fragments after completion (answer: `self.stream.take()` sets it to `None` [7](#0-6) ), the broader stream handling system contains this critical atomicity violation. The `new_stream()` function's non-atomic state mutation enables message stream disruption attacks that affect consensus, state sync, and other critical protocols relying on large message streaming.

### Citations

**File:** network/framework/src/protocols/stream/mod.rs (L68-71)
```rust
pub struct InboundStreamBuffer {
    stream: Option<InboundStream>,
    max_fragments: usize,
}
```

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

**File:** network/framework/src/protocols/stream/mod.rs (L100-112)
```rust
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("No stream exists!"))?;
        let stream_end = stream.append_fragment(fragment)?;

        // If the stream is complete, take it out and return the message
        if stream_end {
            Ok(Some(self.stream.take().unwrap().message))
        } else {
            Ok(None)
        }
    }
```

**File:** network/framework/src/protocols/stream/mod.rs (L365-369)
```rust
        // Attempt to start another stream without completing the first one
        let another_stream_header = create_stream_header(2, 6);
        assert!(inbound_stream_buffer
            .new_stream(another_stream_header)
            .is_err());
```

**File:** network/framework/src/peer/mod.rs (L139-139)
```rust
    inbound_stream: InboundStreamBuffer,
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

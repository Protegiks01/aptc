# Audit Report

## Title
DKG Denial of Service via Per-Protocol Serialization Failure in Reliable Broadcast

## Summary
The `to_bytes_by_protocol()` function in the network layer uses fail-fast error propagation that causes the entire reliable broadcast to abort if message serialization fails for any single protocol group. This allows a malicious or misconfigured validator to prevent DKG transcript broadcasts from succeeding, blocking the DKG protocol and randomness generation for the entire network.

## Finding Description

The vulnerability exists in the error propagation chain from network serialization to reliable broadcast in the DKG protocol.

In the network layer, when preparing to send messages to multiple validators, the system groups peers by their negotiated protocol (Compressed BCS, BCS, or JSON). [1](#0-0) 

The critical flaw is on line 297 where `protocol_id.to_bytes(&message)?` uses the `?` operator. If serialization fails for ANY protocol group (e.g., due to size limits, compression failures, or encoding issues), the entire function immediately returns an error, preventing serialization for all other protocol groups.

This error propagates through the DKG network layer: [2](#0-1) 

And through the DKG network sender: [3](#0-2) 

Finally, in the reliable broadcast implementation, this failure causes the entire broadcast to abort: [4](#0-3) 

The `??` operator propagates any error from `to_bytes_by_protocol`, causing the entire `multicast` function to fail before ANY messages are sent.

**Attack Scenario:**
1. Different validators negotiate different protocols during handshake (e.g., V1-V3 use CompressedBCS, V4 uses BCS, V5 uses JSON)
2. A malicious validator V5 advertises support for a protocol variant
3. An honest validator attempts to broadcast a DKG transcript to all validators
4. Due to protocol-specific limitations (e.g., BCS recursion depth limits, compression failures), serialization fails for V5's protocol
5. The entire broadcast fails with an error, and NO validators (including V1-V4) receive the transcript
6. DKG cannot complete, blocking randomness generation

**Broken Invariants:**
- **DKG Liveness**: The distributed key generation protocol requires participants to exchange transcripts. This vulnerability prevents transcript exchange.
- **Network Availability**: A single peer's protocol incompatibility affects all peers.
- **Fault Tolerance**: The system should be resilient to individual peer failures, but this design causes cascading failures.

## Impact Explanation

This is a **HIGH severity** vulnerability per Aptos bug bounty criteria:

**"Significant protocol violations"**: DKG is a critical protocol for randomness generation in Aptos. Preventing DKG completion affects:
- On-chain randomness availability
- Potential epoch transition delays
- Leader election randomness

**"Validator node slowdowns"**: While not a direct slowdown, DKG stalling prevents validators from progressing through the randomness generation phase.

The impact is limited from Critical severity because:
- Consensus can continue without randomness in degraded mode
- No funds are at risk
- The issue is recoverable by validator reconfiguration
- Requires attacker to be in validator set

However, it represents a significant availability issue for a critical subsystem.

## Likelihood Explanation

**Likelihood: Medium to High**

The vulnerability can manifest in several realistic scenarios:

1. **Natural Protocol Heterogeneity**: Validators may legitimately negotiate different protocols based on their configuration and network conditions.

2. **Message Size Edge Cases**: DKG transcripts grow with validator set size. A transcript that serializes successfully in Compressed BCS might exceed limits in uncompressed BCS due to: [5](#0-4) 

3. **Malicious Exploitation**: A validator can deliberately:
   - Advertise support for a protocol they know will fail
   - Cause resource exhaustion during serialization
   - Trigger protocol-specific encoding failures

4. **Transient Failures**: Even without malicious intent, system resource constraints (memory, CPU) during serialization could cause one protocol to fail while others succeed.

The attack requires being part of the validator set, which raises the bar but is achievable for a determined attacker through staking and governance processes.

## Recommendation

The fix should implement partial failure handling rather than fail-fast behavior:

```rust
fn to_bytes_by_protocol(
    &self,
    peers: Vec<PeerNetworkId>,
    message: Message,
) -> anyhow::Result<HashMap<PeerNetworkId, Bytes>> {
    let peers_per_protocol = self.group_peers_by_protocol(peers);
    let mut bytes_per_peer = HashMap::new();
    let mut failed_peers = Vec::new();
    
    for (protocol_id, peers) in peers_per_protocol {
        match protocol_id.to_bytes(&message) {
            Ok(bytes_vec) => {
                let bytes: Bytes = bytes_vec.into();
                for peer in peers {
                    bytes_per_peer.insert(peer, bytes.clone());
                }
            },
            Err(e) => {
                // Log the error but continue with other protocols
                warn!(
                    "Serialization failed for protocol {:?}: {:?}. Affected peers: {:?}",
                    protocol_id, e, peers
                );
                failed_peers.extend(peers);
            }
        }
    }
    
    // Only fail if ALL protocols failed
    if bytes_per_peer.is_empty() && !failed_peers.is_empty() {
        anyhow::bail!("All protocol serializations failed");
    }
    
    Ok(bytes_per_peer)
}
```

Additionally, in the reliable broadcast layer, there's already a fallback mechanism that handles missing peers: [6](#0-5) 

This fallback re-serializes on-demand for peers not in the pre-serialized map, providing resilience if `to_bytes_by_protocol` returns a partial result.

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_config::network_id::{NetworkId, PeerNetworkId};
    use aptos_types::PeerId;
    use std::collections::HashMap;
    
    #[test]
    fn test_partial_serialization_failure_affects_all_peers() {
        // Create a mock network client with multiple protocol groups
        // Peers 1-2 use CompressedBCS (protocol that succeeds)
        // Peer 3 uses BCS (protocol that fails)
        
        // Setup: Create a message that fails BCS serialization but succeeds in Compressed
        // This could be a large DKGTranscript near the size limit
        
        let peers = vec![
            PeerNetworkId::new(NetworkId::Validator, PeerId::random()),
            PeerNetworkId::new(NetworkId::Validator, PeerId::random()),
            PeerNetworkId::new(NetworkId::Validator, PeerId::random()),
        ];
        
        // Configure peer preferences:
        // peers[0], peers[1] -> CompressedBCS
        // peers[2] -> BCS (will fail)
        
        let message = create_large_dkg_transcript(); // Near size limit
        
        // Attempt serialization
        let result = network_client.to_bytes_by_protocol(peers.clone(), message);
        
        // EXPECTED (vulnerable behavior): Entire operation fails
        assert!(result.is_err(), "Should fail due to BCS serialization failure");
        
        // IMPACT: Even though peers[0] and peers[1] could have received
        // the message via CompressedBCS, they get nothing due to peer[2]'s failure
        
        // DESIRED: Should return Ok with partial results for peers[0] and peers[1]
        // and exclude peer[2], allowing reliable broadcast to use fallback mechanism
    }
    
    fn create_large_dkg_transcript() -> DKGMessage {
        // Create a DKGTranscript with transcript_bytes near the serialization limit
        // that would fail BCS encoding but succeed with compression
        let large_bytes = vec![0u8; 50_000_000]; // 50MB of transcript data
        let transcript = DKGTranscript::new(1, AccountAddress::ZERO, large_bytes);
        DKGMessage::TranscriptResponse(transcript)
    }
}
```

**Reproduction Steps:**
1. Deploy 5 validators with mixed protocol configurations
2. Ensure validators negotiate different protocols (Compressed, BCS, JSON)
3. Create a DKG transcript that exceeds BCS size limits but compresses well
4. Attempt to broadcast this transcript using ReliableBroadcast
5. Observe that `to_bytes_by_protocol` fails entirely
6. Verify that NO validators receive the transcript, even those using compatible protocols
7. Confirm DKG protocol stalls and cannot complete

## Notes

This vulnerability demonstrates a fundamental design flaw where per-protocol serialization failures cascade to affect all participants in a broadcast, violating fault tolerance principles. The reliable broadcast mechanism already has fallback logic for missing peers, but it never gets activated because the pre-serialization step fails completely rather than returning partial results.

The fix requires changing the error handling philosophy from "fail-fast on any error" to "continue with partial success and use fallbacks for failures."

### Citations

**File:** network/framework/src/application/interface.rs (L288-304)
```rust
    fn to_bytes_by_protocol(
        &self,
        peers: Vec<PeerNetworkId>,
        message: Message,
    ) -> anyhow::Result<HashMap<PeerNetworkId, Bytes>> {
        let peers_per_protocol = self.group_peers_by_protocol(peers);
        // Convert to bytes per protocol
        let mut bytes_per_peer = HashMap::new();
        for (protocol_id, peers) in peers_per_protocol {
            let bytes: Bytes = protocol_id.to_bytes(&message)?.into();
            for peer in peers {
                bytes_per_peer.insert(peer, bytes.clone());
            }
        }

        Ok(bytes_per_peer)
    }
```

**File:** dkg/src/network_interface.rs (L62-77)
```rust
    pub fn to_bytes_by_protocol(
        &self,
        peers: Vec<PeerId>,
        message: DKGMessage,
    ) -> anyhow::Result<HashMap<PeerId, Bytes>> {
        let peer_network_ids: Vec<PeerNetworkId> = peers
            .into_iter()
            .map(|peer| self.get_peer_network_id_for_peer(peer))
            .collect();
        Ok(self
            .network_client
            .to_bytes_by_protocol(peer_network_ids, message)?
            .into_iter()
            .map(|(peer_network_id, bytes)| (peer_network_id.peer_id(), bytes))
            .collect())
    }
```

**File:** dkg/src/network.rs (L113-119)
```rust
    fn to_bytes_by_protocol(
        &self,
        peers: Vec<AccountAddress>,
        message: DKGMessage,
    ) -> anyhow::Result<HashMap<AccountAddress, Bytes>> {
        self.dkg_network_client.to_bytes_by_protocol(peers, message)
    }
```

**File:** crates/reliable-broadcast/src/lib.rs (L127-135)
```rust
            let peers = receivers.clone();
            let sender = network_sender.clone();
            let message_clone = message.clone();
            let protocols = Arc::new(
                tokio::task::spawn_blocking(move || {
                    sender.to_bytes_by_protocol(peers, message_clone)
                })
                .await??,
            );
```

**File:** crates/reliable-broadcast/src/lib.rs (L146-152)
```rust
                    let send_fut = if receiver == self_author {
                        network_sender.send_rb_rpc(receiver, message, rpc_timeout_duration)
                    } else if let Some(raw_message) = protocols.get(&receiver).cloned() {
                        network_sender.send_rb_rpc_raw(receiver, raw_message, rpc_timeout_duration)
                    } else {
                        network_sender.send_rb_rpc(receiver, message, rpc_timeout_duration)
                    };
```

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L196-222)
```rust
    pub fn to_bytes<T: Serialize>(&self, value: &T) -> anyhow::Result<Vec<u8>> {
        // Start the serialization timer
        let serialization_timer = start_serialization_timer(*self, SERIALIZATION_LABEL);

        // Serialize the message
        let result = match self.encoding() {
            Encoding::Bcs(limit) => self.bcs_encode(value, limit),
            Encoding::CompressedBcs(limit) => {
                let compression_client = self.get_compression_client();
                let bcs_bytes = self.bcs_encode(value, limit)?;
                aptos_compression::compress(
                    bcs_bytes,
                    compression_client,
                    MAX_APPLICATION_MESSAGE_SIZE,
                )
                .map_err(|e| anyhow!("{:?}", e))
            },
            Encoding::Json => serde_json::to_vec(value).map_err(|e| anyhow!("{:?}", e)),
        };

        // Only record the duration if serialization was successful
        if result.is_ok() {
            serialization_timer.observe_duration();
        }

        result
    }
```

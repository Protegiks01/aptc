# Audit Report

## Title
Protocol Confusion in DKG Reliable Broadcast Causes Encoding Mismatch Between DIRECT_SEND and RPC Protocols

## Summary
The DKG (Distributed Key Generation) module uses ReliableBroadcast which incorrectly mixes DIRECT_SEND protocol encodings with RPC protocol delivery, causing deserialization failures when peers support asymmetric protocol sets. Messages are serialized using DIRECT_SEND protocol preferences but sent via RPC using different protocol preferences, leading to encoding mismatches that break request-response semantics.

## Finding Description
The vulnerability exists in the interaction between the ReliableBroadcast pattern and the NetworkClient's protocol selection logic. [1](#0-0) 

The ReliableBroadcast `multicast()` method first calls `to_bytes_by_protocol()` to pre-serialize messages for all peers using their preferred DIRECT_SEND protocols. [2](#0-1) 

The `to_bytes_by_protocol()` method uses `group_peers_by_protocol()` which selects protocols from `direct_send_protocols_and_preferences`: [3](#0-2) 

Then ReliableBroadcast sends these pre-serialized bytes via RPC: [4](#0-3) 

The `send_rb_rpc_raw()` eventually calls `send_to_peer_rpc_raw()` which selects protocols from `rpc_protocols_and_preferences`: [5](#0-4) 

**The Critical Flaw**: If a peer supports different encoding types for DIRECT_SEND vs RPC protocols, a mismatch occurs: [6](#0-5) 

For example:
- Peer supports only `DKGDirectSendBcs` (uses `Bcs` encoding)
- Peer supports only `DKGRpcCompressed` (uses `CompressedBcs` encoding)

Flow:
1. `to_bytes_by_protocol()` selects `DKGDirectSendBcs` → serializes with plain BCS
2. `send_to_peer_rpc_raw()` selects `DKGRpcCompressed` → creates RPC request with `protocol_id = DKGRpcCompressed`
3. Receiver deserializes using `DKGRpcCompressed` encoding (CompressedBcs): [7](#0-6) 

4. Decompression fails on plain BCS data → deserialization error → RPC timeout

The protocol confusion breaks the request-response semantics because the encoding used for serialization does not match the encoding expected for deserialization.

## Impact Explanation
**High Severity** - This constitutes a "Significant protocol violation" per Aptos bug bounty criteria.

Impact:
- **DKG Protocol Failure**: DKG relies on reliable broadcast to collect transcripts from validators [8](#0-7) 

- **Validator Operational Disruption**: Failed DKG prevents proper distributed key generation, affecting validator set operations and potentially requiring manual intervention

- **Network Availability**: Widespread protocol confusion during version upgrades could impact network-wide DKG completion, degrading validator coordination

While not achieving Critical severity (no direct fund loss or consensus split), this breaks protocol correctness guarantees and can cause validator node disruptions.

## Likelihood Explanation
**Medium-High Likelihood** during:

1. **Protocol Upgrades**: When validators run different software versions with different protocol support (e.g., old nodes lacking compressed protocols, new nodes supporting all variants)

2. **Misconfiguration**: Validators with incorrectly configured protocol advertisements

3. **Asymmetric Handshake**: No validation enforces symmetric DIRECT_SEND/RPC protocol encoding alignment - peers can legitimately advertise any subset of protocols

While current homogeneous deployments advertise all 6 DKG protocols uniformly, the protocol design lacks safeguards against asymmetry, making this exploitable during transition periods or network heterogeneity.

## Recommendation
**Fix 1: Enforce Protocol Encoding Symmetry**

Add validation in `NetworkClient::to_bytes_by_protocol()` to ensure selected DIRECT_SEND protocol uses the same encoding as the peer's preferred RPC protocol:

```rust
fn to_bytes_by_protocol(
    &self,
    peers: Vec<PeerNetworkId>,
    message: Message,
) -> anyhow::Result<HashMap<PeerNetworkId, Bytes>> {
    let peers_per_protocol = self.group_peers_by_protocol(peers);
    let mut bytes_per_peer = HashMap::new();
    
    for (direct_send_protocol, peers) in peers_per_protocol {
        // NEW: Validate encoding compatibility with RPC protocol
        for peer in &peers {
            if let Ok(rpc_protocol) = self.get_preferred_protocol_for_peer(peer, &self.rpc_protocols_and_preferences) {
                if !encodings_compatible(direct_send_protocol, rpc_protocol) {
                    return Err(anyhow!("Protocol encoding mismatch for peer {:?}: DIRECT_SEND={:?}, RPC={:?}", 
                        peer, direct_send_protocol, rpc_protocol));
                }
            }
        }
        
        let bytes: Bytes = direct_send_protocol.to_bytes(&message)?.into();
        for peer in peers {
            bytes_per_peer.insert(peer, bytes.clone());
        }
    }
    Ok(bytes_per_peer)
}

fn encodings_compatible(p1: ProtocolId, p2: ProtocolId) -> bool {
    matches!(
        (p1.encoding(), p2.encoding()),
        (Encoding::Bcs(_), Encoding::Bcs(_)) |
        (Encoding::CompressedBcs(_), Encoding::CompressedBcs(_)) |
        (Encoding::Json, Encoding::Json)
    )
}
```

**Fix 2: Use RPC Protocol for Serialization in ReliableBroadcast**

Modify ReliableBroadcast to serialize using RPC protocol preferences instead of DIRECT_SEND:

```rust
// In reliable broadcast, use RPC-compatible serialization
let protocols = Arc::new(
    tokio::task::spawn_blocking(move || {
        // Change: serialize with RPC protocol preferences
        sender.to_bytes_by_rpc_protocol(peers, message_clone)
    })
    .await??,
);
```

Add corresponding method to NetworkClient that uses `rpc_protocols_and_preferences` for serialization.

## Proof of Concept

```rust
// Simulated test demonstrating the protocol confusion
#[tokio::test]
async fn test_dkg_protocol_confusion() {
    // Setup: Create two peers with asymmetric protocol support
    let peer1_protocols = ProtocolIdSet::from([
        ProtocolId::DKGDirectSendBcs,      // Bcs encoding
        ProtocolId::DKGRpcCompressed,       // CompressedBcs encoding
    ]);
    
    let peer2_protocols = ProtocolIdSet::from([
        ProtocolId::DKGDirectSendCompressed,
        ProtocolId::DKGRpcCompressed,
        ProtocolId::DKGDirectSendBcs,
        ProtocolId::DKGRpcBcs,
    ]);
    
    // Peer1 advertises asymmetric protocols during handshake
    // (This would be done via HandshakeMsg but simplified here)
    
    // Create DKG message
    let dkg_msg = DKGMessage::TranscriptRequest(
        DKGTranscriptRequest::new(1)
    );
    
    // Simulate ReliableBroadcast flow:
    // 1. to_bytes_by_protocol selects DKGDirectSendBcs for peer1
    let direct_send_bytes = ProtocolId::DKGDirectSendBcs
        .to_bytes(&dkg_msg)
        .expect("serialization should succeed");
    
    // 2. send_rb_rpc_raw uses DKGRpcCompressed for peer1
    // Creates RpcRequest with protocol_id = DKGRpcCompressed
    // but raw_request = direct_send_bytes (Bcs encoded)
    
    // 3. Receiver attempts deserialization
    let result = ProtocolId::DKGRpcCompressed
        .from_bytes::<DKGMessage>(&direct_send_bytes);
    
    // EXPECTED: Deserialization failure due to encoding mismatch
    assert!(result.is_err(), "Decompression should fail on plain BCS data");
    
    // This causes RPC timeout and DKG failure
}
```

**Notes**

The vulnerability demonstrates a fundamental flaw in protocol layering where DIRECT_SEND and RPC protocol selections are independent, allowing encoding mismatches. While unlikely in homogeneous production deployments, the lack of encoding validation makes the system fragile during upgrades or misconfigurations. The fix requires either enforcing encoding compatibility checks or unifying the serialization protocol selection between the two code paths.

### Citations

**File:** crates/reliable-broadcast/src/lib.rs (L130-135)
```rust
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

**File:** network/framework/src/application/interface.rs (L160-177)
```rust
    fn group_peers_by_protocol(
        &self,
        peers: Vec<PeerNetworkId>,
    ) -> HashMap<ProtocolId, Vec<PeerNetworkId>> {
        // Sort peers by protocol
        let mut peers_per_protocol = HashMap::new();
        let mut peers_without_a_protocol = vec![];
        for peer in peers {
            match self
                .get_preferred_protocol_for_peer(&peer, &self.direct_send_protocols_and_preferences)
            {
                Ok(protocol) => peers_per_protocol
                    .entry(protocol)
                    .or_insert_with(Vec::new)
                    .push(peer),
                Err(_) => peers_without_a_protocol.push(peer),
            }
        }
```

**File:** network/framework/src/application/interface.rs (L274-286)
```rust
    async fn send_to_peer_rpc_raw(
        &self,
        message: Bytes,
        rpc_timeout: Duration,
        peer: PeerNetworkId,
    ) -> Result<Message, Error> {
        let network_sender = self.get_sender_for_network_id(&peer.network_id())?;
        let rpc_protocol_id =
            self.get_preferred_protocol_for_peer(&peer, &self.rpc_protocols_and_preferences)?;
        Ok(network_sender
            .send_rpc_raw(peer.peer_id(), rpc_protocol_id, message, rpc_timeout)
            .await?)
    }
```

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

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L156-172)
```rust
    fn encoding(self) -> Encoding {
        match self {
            ProtocolId::ConsensusDirectSendJson | ProtocolId::ConsensusRpcJson => Encoding::Json,
            ProtocolId::ConsensusDirectSendCompressed | ProtocolId::ConsensusRpcCompressed => {
                Encoding::CompressedBcs(RECURSION_LIMIT)
            },
            ProtocolId::ConsensusObserver => Encoding::CompressedBcs(RECURSION_LIMIT),
            ProtocolId::DKGDirectSendCompressed | ProtocolId::DKGRpcCompressed => {
                Encoding::CompressedBcs(RECURSION_LIMIT)
            },
            ProtocolId::JWKConsensusDirectSendCompressed
            | ProtocolId::JWKConsensusRpcCompressed => Encoding::CompressedBcs(RECURSION_LIMIT),
            ProtocolId::MempoolDirectSend => Encoding::CompressedBcs(USER_INPUT_RECURSION_LIMIT),
            ProtocolId::MempoolRpc => Encoding::Bcs(USER_INPUT_RECURSION_LIMIT),
            _ => Encoding::Bcs(RECURSION_LIMIT),
        }
    }
```

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L231-244)
```rust
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
```

**File:** dkg/src/agg_trx_producer.rs (L64-67)
```rust
            let agg_trx = rb
                .broadcast(req, agg_state)
                .await
                .expect("broadcast cannot fail");
```

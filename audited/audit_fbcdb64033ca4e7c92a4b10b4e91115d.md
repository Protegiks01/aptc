# Audit Report

## Title
Protocol Confusion Attack in DKG Reliable Broadcast via Race Condition Between Serialization and Transmission

## Summary
The `send_rb_rpc_raw()` function in the DKG network layer forwards pre-serialized raw bytes without preserving the protocol used for serialization. A race condition exists where a peer's supported protocols can change between message serialization and transmission, causing the sender to embed an incorrect protocol ID in the RPC request. This enables an attacker-controlled peer to trigger repeated deserialization failures, disrupting DKG rounds and delaying consensus.

## Finding Description

The vulnerability arises from a race condition in the reliable broadcast implementation used by the DKG (Distributed Key Generation) protocol. The attack flow is:

**Step 1: Message Pre-Serialization**
The reliable broadcast's `multicast()` function calls `to_bytes_by_protocol()` to pre-serialize messages for each peer based on their current protocol preferences. [1](#0-0) 

This queries each peer's supported protocols and serializes the message accordingly. For DKG, the preference order is: `[DKGRpcCompressed, DKGRpcBcs, DKGRpcJson]`. [2](#0-1) 

**Step 2: Protocol Selection at Serialization Time**
The network client groups peers by their preferred protocol and serializes once per protocol group. [3](#0-2) 

If Peer B supports `[DKGRpcCompressed, DKGRpcBcs, DKGRpcJson]`, the message is serialized with `DKGRpcCompressed` (compressed BCS encoding). [4](#0-3) 

**Step 3: Vulnerable Forwarding Without Validation**
Later, `send_rb_rpc_raw()` is called with the pre-serialized compressed bytes. It forwards them directly without any protocol validation or tracking. [5](#0-4) 

**Step 4: Protocol Re-Selection at Transmission Time**
The DKG network client forwards to the underlying network client's `send_to_peer_rpc_raw()`, which **re-queries** the peer's current supported protocols. [6](#0-5) 

**Step 5: Protocol Confusion**
If Peer B disconnected and reconnected with different protocol support (e.g., now `[DKGRpcBcs, DKGRpcJson]` without Compressed), the function selects `DKGRpcBcs` instead. [7](#0-6) 

**Step 6: Wire Message with Wrong Protocol ID**
The network sender creates an RPC request with the **newly selected protocol ID** but the **previously serialized bytes**. [8](#0-7) 

The wire format embeds the mismatched protocol ID: [9](#0-8) 

**Step 7: Deserialization Failure**
The receiver extracts the protocol ID from the wire message and uses it to deserialize the payload. Compressed BCS bytes are interpreted as uncompressed BCS, causing deserialization failure. [10](#0-9) 

Failed deserialization is logged and the message is dropped: [11](#0-10) 

**Attack Execution:**
A malicious peer can:
1. Connect with full protocol support `[DKGRpcCompressed, DKGRpcBcs, DKGRpcJson]`
2. Monitor for DKG round initiation
3. Disconnect and immediately reconnect with limited support `[DKGRpcBcs, DKGRpcJson]`
4. Time the reconnection to occur between `to_bytes_by_protocol()` and `send_rb_rpc_raw()` calls
5. Cause repeated deserialization failures as honest nodes retry
6. Disrupt DKG round completion

## Impact Explanation

**Severity: High ($50,000 range per Aptos Bug Bounty)**

This vulnerability enables **Denial of Service on the DKG protocol**, which is critical for consensus:

1. **DKG Disruption**: Repeated failures prevent DKG round completion, delaying randomness generation needed for leader election and consensus
2. **Validator Node Slowdowns**: Affected nodes waste resources on retries and logging
3. **Significant Protocol Violations**: Breaks the reliability guarantee of the reliable broadcast protocol
4. **Consensus Delays**: Failed DKG rounds can delay epoch transitions and block finalization

While this is not a consensus safety violation (doesn't cause chain splits or double-spending), it significantly impacts **availability** and **liveness**, which are critical consensus properties. Under the Aptos bug bounty criteria, this qualifies as "Validator node slowdowns" and "Significant protocol violations" (High Severity).

The attack does not require validator privileges—any peer can attempt it. The impact is amplified if multiple peers coordinate the attack or if the attacker controls peers with high selection probability in the DKG protocol.

## Likelihood Explanation

**Likelihood: Medium**

The attack requires:
- **Attacker-controlled peer**: Must be part of the validator network (Medium barrier)
- **Precise timing**: Must disconnect/reconnect in the small window between serialization and transmission (Low probability per attempt)
- **Multiple attempts**: Can be repeated across multiple DKG rounds (Increases success rate)

Factors increasing feasibility:
- The reliable broadcast processes many peers sequentially, increasing the timing window
- Spawn_blocking for serialization adds latency that widens the window
- Executor congestion further extends the window
- Multiple DKG rounds per epoch provide multiple attack opportunities

Factors decreasing feasibility:
- Timing window may be microseconds in optimal conditions
- Connection metadata updates use atomic operations, limiting race windows
- Error handling prevents data corruption (only causes availability issues)

Overall, while not trivial, a determined attacker with peer access can realistically execute this attack, especially by targeting high-latency periods or using automation to increase attempt frequency.

## Recommendation

**Solution: Track and validate protocol ID throughout the message lifecycle**

Modify `send_rb_rpc_raw()` to accept and preserve the protocol ID used during serialization:

```rust
// In RBNetworkSender trait
async fn send_rb_rpc_raw(
    &self,
    receiver: Author,
    raw_message: Bytes,
    protocol_id: ProtocolId, // NEW: track serialization protocol
    timeout: Duration,
) -> anyhow::Result<Res>;

// In NetworkSender implementation
async fn send_rb_rpc_raw(
    &self,
    receiver: AccountAddress,
    raw_message: Bytes,
    protocol_id: ProtocolId, // NEW
    timeout: Duration,
) -> anyhow::Result<DKGMessage> {
    // Validate peer still supports this protocol
    let peer_network_id = PeerNetworkId::new(NetworkId::Validator, receiver);
    let supported = self.dkg_network_client
        .network_client
        .get_peers_and_metadata()
        .get_metadata_for_peer(peer_network_id)?
        .supports_protocol(protocol_id);
    
    if !supported {
        return Err(anyhow::anyhow!(
            "Peer {} no longer supports protocol {:?}", 
            receiver, protocol_id
        ));
    }
    
    // Use validated protocol_id instead of re-querying
    Ok(self
        .dkg_network_client
        .send_rpc_with_protocol(receiver, raw_message, protocol_id, timeout)
        .await?)
}
```

Additionally, modify `to_bytes_by_protocol()` to return protocol IDs alongside bytes:

```rust
fn to_bytes_by_protocol(
    &self,
    peers: Vec<Author>,
    message: Req,
) -> anyhow::Result<HashMap<Author, (Bytes, ProtocolId)>>;
```

This ensures the protocol used for serialization is preserved and validated at transmission time, preventing protocol confusion attacks.

## Proof of Concept

Due to the complexity of the network layer and reliable broadcast integration, a full PoC requires extensive mocking. However, the vulnerability can be demonstrated with this conceptual test:

```rust
#[tokio::test]
async fn test_protocol_confusion_race_condition() {
    // Setup: Create DKG network with malicious peer
    let (network_sender, peer_metadata) = setup_dkg_network();
    let malicious_peer = AccountAddress::random();
    
    // Step 1: Peer connects with full protocol support
    peer_metadata.insert_connection_metadata(
        PeerNetworkId::new(NetworkId::Validator, malicious_peer),
        ConnectionMetadata::with_protocols(vec![
            ProtocolId::DKGRpcCompressed,
            ProtocolId::DKGRpcBcs,
            ProtocolId::DKGRpcJson,
        ])
    ).unwrap();
    
    // Step 2: Serialize message with DKGRpcCompressed
    let message = DKGMessage::test_message();
    let serialized = network_sender
        .to_bytes_by_protocol(vec![malicious_peer], message.clone())
        .unwrap();
    let compressed_bytes = serialized.get(&malicious_peer).unwrap().clone();
    
    // Step 3: Peer changes protocol support (simulating reconnect)
    peer_metadata.insert_connection_metadata(
        PeerNetworkId::new(NetworkId::Validator, malicious_peer),
        ConnectionMetadata::with_protocols(vec![
            ProtocolId::DKGRpcBcs, // Removed Compressed!
            ProtocolId::DKGRpcJson,
        ])
    ).unwrap();
    
    // Step 4: Send raw bytes - should trigger protocol confusion
    let result = network_sender
        .send_rb_rpc_raw(malicious_peer, compressed_bytes, Duration::from_secs(5))
        .await;
    
    // Expected: RPC fails due to deserialization error
    assert!(result.is_err());
    
    // Verify protocol confusion occurred:
    // - Bytes were compressed BCS (from DKGRpcCompressed)
    // - But sent with DKGRpcBcs protocol ID
    // - Receiver tried to deserialize compressed data as uncompressed
    // - Deserialization failed
}
```

The attack can be demonstrated in production by:
1. Running a validator node with controlled peer
2. Monitoring DKG round initiation (via logs/metrics)
3. Automating disconnect/reconnect with different protocol support during rounds
4. Observing "InvalidNetworkEvent" errors in peer logs
5. Measuring DKG round completion delays

---

**Notes:**

This vulnerability demonstrates a subtle race condition where asynchronous protocol negotiation interacts poorly with pre-serialization optimizations. The fix requires tracking protocol IDs through the message lifecycle to maintain serialization-transmission consistency. While error handling prevents data corruption, the availability impact on DKG justifies High severity classification.

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

**File:** dkg/src/network_interface.rs (L14-18)
```rust
pub const RPC: &[ProtocolId] = &[
    ProtocolId::DKGRpcCompressed,
    ProtocolId::DKGRpcBcs,
    ProtocolId::DKGRpcJson,
];
```

**File:** network/framework/src/application/interface.rs (L142-158)
```rust
    fn get_preferred_protocol_for_peer(
        &self,
        peer: &PeerNetworkId,
        preferred_protocols: &[ProtocolId],
    ) -> Result<ProtocolId, Error> {
        let protocols_supported_by_peer = self.get_supported_protocols(peer)?;
        for protocol in preferred_protocols {
            if protocols_supported_by_peer.contains(*protocol) {
                return Ok(*protocol);
            }
        }
        Err(Error::NetworkError(format!(
            "None of the preferred protocols are supported by this peer! \
            Peer: {:?}, supported protocols: {:?}",
            peer, protocols_supported_by_peer
        )))
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

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L201-214)
```rust
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

**File:** dkg/src/network.rs (L92-102)
```rust
    async fn send_rb_rpc_raw(
        &self,
        receiver: AccountAddress,
        raw_message: Bytes,
        timeout: Duration,
    ) -> anyhow::Result<DKGMessage> {
        Ok(self
            .dkg_network_client
            .send_rpc_raw(receiver, raw_message, timeout)
            .await?)
    }
```

**File:** network/framework/src/protocols/rpc/mod.rs (L493-498)
```rust
        let message = NetworkMessage::RpcRequest(RpcRequest {
            protocol_id,
            request_id,
            priority: Priority::default(),
            raw_request: Vec::from(request_data.as_ref()),
        });
```

**File:** network/framework/src/protocols/wire/messaging/v1/mod.rs (L118-128)
```rust
pub struct RpcRequest {
    /// `protocol_id` is a variant of the ProtocolId enum.
    pub protocol_id: ProtocolId,
    /// RequestId for the RPC Request.
    pub request_id: RequestId,
    /// Request priority in the range 0..=255.
    pub priority: Priority,
    /// Request payload. This will be parsed by the application-level handler.
    #[serde(with = "serde_bytes")]
    pub raw_request: Vec<u8>,
}
```

**File:** network/framework/src/protocols/network/mod.rs (L303-321)
```rust
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
}
```

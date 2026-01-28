# Audit Report

## Title
Protocol Serialization TOCTOU Race Condition in Reliable Broadcast Leading to Consensus Disruption

## Summary
A Time-of-Check-Time-of-Use (TOCTOU) race condition exists between protocol selection for message serialization and protocol selection for message transmission in the reliable broadcast mechanism. When a peer's connection metadata changes between these two operations, messages are sent with mismatched protocol identifiers, causing deserialization failures that disrupt consensus message delivery.

## Finding Description

The vulnerability stems from a race condition in the network layer's message serialization and transmission flow, specifically affecting reliable broadcast used for consensus messages.

**Serialization Phase (Time T1):**
The `to_bytes_by_protocol()` function groups peers by their preferred protocol and serializes the message once per protocol group. [1](#0-0) 

During grouping, it queries each peer's supported protocols via `get_preferred_protocol_for_peer()`, which reads from the peer's connection metadata. [2](#0-1) 

The protocol selection queries the peer's current supported protocols from cached metadata. [3](#0-2) 

**Transmission Phase (Time T2):**
Later, when `send_to_peer_rpc_raw()` is called with the pre-serialized bytes, it queries the peer's preferred protocol AGAIN. [4](#0-3) 

**Race Window:**
Between T1 and T2, a peer's connection metadata can be updated when the peer reconnects with different advertised protocols. [5](#0-4) 

**Protocol Mismatch:**
The RPC request is constructed with the protocol_id from T2, but contains payload bytes serialized with the protocol from T1. [6](#0-5) 

**Different Encoding Formats:**
Aptos supports fundamentally different protocol encodings (BCS, CompressedBCS, JSON) with incompatible serialization formats. [7](#0-6) 

When the receiver deserializes using the protocol_id from the RpcRequest (T2), but the bytes are in the format from T1, deserialization fails. [8](#0-7) 

**Consensus Impact:**
This affects reliable broadcast of critical consensus messages including commit votes. [9](#0-8) 

The reliable broadcast mechanism with exponential backoff retry provides a larger attack window (seconds to minutes). [10](#0-9) 

## Impact Explanation

This vulnerability causes **HIGH severity** impact according to Aptos bug bounty criteria:

**Validator Node Slowdowns:** When protocol mismatch occurs, RPC requests fail deserialization, causing repeated retries with exponential backoff. This creates significant performance degradation in consensus message delivery, particularly for commit vote broadcasting which is critical for block finalization.

The impact is NOT total network liveness loss because:
- Only affects communication with specific peers that reconnect during operations
- Retry logic eventually succeeds once peer connection stabilizes
- Other validator communications remain unaffected
- Byzantine fault tolerance (up to 1/3) remains intact

The "state divergence" claim is unsubstantiated - compressed bytes interpreted as plain BCS will almost always fail deserialization rather than produce a valid but different message.

## Likelihood Explanation

**Likelihood: MEDIUM**

The vulnerability requires:
1. A peer's connection metadata to change between serialization (T1) and transmission (T2)
2. This can occur when a peer reconnects with different advertised protocols
3. In reliable broadcast, initial attempts have minimal race window, but retry attempts with exponential backoff provide larger windows (seconds to minutes)
4. A malicious validator can intentionally disconnect/reconnect during consensus critical phases to trigger this condition
5. Natural network instability can also trigger this condition without malicious intent

The race window exists in production code and the conditions are achievable.

## Recommendation

Implement atomic protocol selection by storing the chosen protocol_id alongside the serialized bytes:

```rust
// Modify to_bytes_by_protocol to return protocol_id with bytes
pub struct SerializedMessage {
    pub protocol_id: ProtocolId,
    pub bytes: Bytes,
}

fn to_bytes_by_protocol(
    &self,
    peers: Vec<PeerNetworkId>,
    message: Message,
) -> anyhow::Result<HashMap<PeerNetworkId, SerializedMessage>>

// Use the stored protocol_id in send_to_peer_rpc_raw instead of querying again
async fn send_to_peer_rpc_raw(
    &self,
    serialized: SerializedMessage,
    rpc_timeout: Duration,
    peer: PeerNetworkId,
) -> Result<Message, Error> {
    let network_sender = self.get_sender_for_network_id(&peer.network_id())?;
    // Use serialized.protocol_id instead of querying peer metadata again
    Ok(network_sender
        .send_rpc_raw(peer.peer_id(), serialized.protocol_id, serialized.bytes, rpc_timeout)
        .await?)
}
```

## Proof of Concept

A complete PoC was not provided in the report. To demonstrate this vulnerability, one would need to:

1. Set up a test network with validators using different protocol preferences
2. Trigger reliable broadcast of a consensus message
3. Simulate a peer reconnection with different advertised protocols during the broadcast
4. Observe RPC deserialization failures in the logs
5. Measure the impact on consensus message delivery timing

The vulnerability is technically valid based on code analysis, though practical exploitation requires specific timing and network conditions.

## Notes

While this is a legitimate protocol implementation bug with real security implications, the severity assessment in the original report was overstated. The vulnerability causes temporary message delivery delays rather than total consensus failure or state divergence. The system's retry mechanisms and Byzantine fault tolerance provide resilience against this issue, though it can still cause performance degradation during consensus operations. The lack of a working proof of concept is a weakness in the report, but the technical analysis is sound and the code evidence supports the existence of the TOCTOU race condition.

### Citations

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

**File:** network/framework/src/application/interface.rs (L160-191)
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

        // We only periodically log any unavailable peers (to prevent log spamming)
        if !peers_without_a_protocol.is_empty() {
            sample!(
                SampleRate::Duration(Duration::from_secs(10)),
                warn!(
                    "[sampled] Unavailable peers (without a common network protocol): {:?}",
                    peers_without_a_protocol
                )
            );
        }

        peers_per_protocol
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

**File:** network/framework/src/application/storage.rs (L186-213)
```rust
    pub fn insert_connection_metadata(
        &self,
        peer_network_id: PeerNetworkId,
        connection_metadata: ConnectionMetadata,
    ) -> Result<(), Error> {
        // Grab the write lock for the peer metadata
        let mut peers_and_metadata = self.peers_and_metadata.write();

        // Fetch the peer metadata for the given network
        let peer_metadata_for_network =
            get_peer_metadata_for_network(&peer_network_id, &mut peers_and_metadata)?;

        // Update the metadata for the peer or insert a new entry
        peer_metadata_for_network
            .entry(peer_network_id.peer_id())
            .and_modify(|peer_metadata| {
                peer_metadata.connection_metadata = connection_metadata.clone()
            })
            .or_insert_with(|| PeerMetadata::new(connection_metadata.clone()));

        // Update the cached peers and metadata
        self.set_cached_peers_and_metadata(peers_and_metadata.clone());

        let event =
            ConnectionNotification::NewPeer(connection_metadata, peer_network_id.network_id());
        self.broadcast(event);

        Ok(())
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

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L226-250)
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

```

**File:** consensus/src/pipeline/commit_reliable_broadcast.rs (L114-133)
```rust
    async fn send_rb_rpc_raw(
        &self,
        receiver: Author,
        raw_message: Bytes,
        timeout_duration: Duration,
    ) -> anyhow::Result<CommitMessage> {
        let response = match self
            .consensus_network_client
            .send_rpc_raw(receiver, raw_message, timeout_duration)
            .await?
        {
            ConsensusMsg::CommitMessage(resp) if matches!(*resp, CommitMessage::Ack(_)) => *resp,
            ConsensusMsg::CommitMessage(resp) if matches!(*resp, CommitMessage::Nack) => {
                bail!("Received nack, will retry")
            },
            _ => bail!("Invalid response to request"),
        };

        Ok(response)
    }
```

**File:** crates/reliable-broadcast/src/lib.rs (L130-156)
```rust
            let protocols = Arc::new(
                tokio::task::spawn_blocking(move || {
                    sender.to_bytes_by_protocol(peers, message_clone)
                })
                .await??,
            );

            let send_message = |receiver, sleep_duration: Option<Duration>| {
                let network_sender = network_sender.clone();
                let time_service = time_service.clone();
                let message = message.clone();
                let protocols = protocols.clone();
                async move {
                    if let Some(duration) = sleep_duration {
                        time_service.sleep(duration).await;
                    }
                    let send_fut = if receiver == self_author {
                        network_sender.send_rb_rpc(receiver, message, rpc_timeout_duration)
                    } else if let Some(raw_message) = protocols.get(&receiver).cloned() {
                        network_sender.send_rb_rpc_raw(receiver, raw_message, rpc_timeout_duration)
                    } else {
                        network_sender.send_rb_rpc(receiver, message, rpc_timeout_duration)
                    };
                    (receiver, send_fut.await)
                }
                .boxed()
            };
```

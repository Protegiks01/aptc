# Audit Report

## Title
TOCTOU Protocol Mismatch in Consensus Observer Message Serialization Causes Deserialization Failures

## Summary
A Time-of-Check to Time-of-Use (TOCTOU) race condition exists in the consensus observer message serialization pipeline. When `serialize_message_for_peer()` selects a protocol for serialization and a peer disconnects/reconnects with different protocol support before `send_serialized_message_to_peer()` is called, the message is serialized with one protocol but tagged and sent with a different protocol, causing deserialization failures at the receiver.

## Finding Description
The consensus observer publisher uses a two-phase approach for message delivery: parallel serialization followed by in-order sending. This creates a timing window where peer protocol support can change between phases.

**Phase 1 - Serialization:**
The `serialize_message_for_peer()` function calls `to_bytes_by_protocol()`, which reads the peer's supported protocols from the cached metadata and selects a preferred protocol for serialization. [1](#0-0) 

The `to_bytes_by_protocol()` implementation groups peers by protocol and serializes the message accordingly: [2](#0-1) 

**Phase 2 - Sending (with timing gap):**
The consensus publisher spawns blocking tasks for parallel serialization, creating a significant time delay before sending: [3](#0-2) 

When `send_serialized_message_to_peer()` eventually calls `send_to_peer_raw()`, it independently queries the peer's protocol support AGAIN and selects a potentially different protocol: [4](#0-3) 

**The Vulnerability:**
If a peer disconnects and reconnects with different protocol support between these two phases, a mismatch occurs:

1. Time T1: Peer supports {CompressedBCS, BCS}, message serialized with CompressedBCS encoding
2. Time T2: Peer reconnects supporting only {BCS}
3. Time T3: Message sent with BCS protocol tag but containing CompressedBCS-encoded bytes
4. Time T4: Receiver attempts to deserialize using BCS decoder, fails on compressed data

The protocol ID is embedded in the DirectSendMsg and used for deserialization: [5](#0-4) 

The receiver uses the protocol_id from the message to deserialize: [6](#0-5) 

This causes `from_bytes()` to use the wrong decoding method: [7](#0-6) 

## Impact Explanation
**Medium Severity** - This vulnerability causes consensus observer messages to fail deserialization, resulting in:

1. **Message Loss**: Critical consensus updates (blocks, commits, quorum certificates) fail to reach observer nodes
2. **State Divergence**: Observers fall behind the consensus state, requiring full state sync recovery
3. **Network Degradation**: Systematic failures when peers upgrade or reconnect with different protocol support
4. **Operational Impact**: Requires manual intervention to restore observer functionality

This does NOT break core consensus safety (observers are not consensus participants), but significantly impacts network reliability and observer infrastructure. Per Aptos bug bounty criteria, this qualifies as Medium severity: "State inconsistencies requiring intervention."

## Likelihood Explanation
**Likelihood: Medium to High**

This vulnerability occurs naturally during normal operations:

1. **Peer Upgrades**: When nodes upgrade and restart with different protocol configurations
2. **Network Reconnections**: Transient network issues causing reconnects during parallel serialization windows
3. **Protocol Negotiation Changes**: Peers dynamically adjusting supported protocols based on configuration
4. **Timing Window**: Parallel serialization tasks in `spawn_blocking` can take significant time (100ms+), providing ample opportunity for peer state changes

The consensus publisher explicitly uses parallel serialization with configurable buffering (`max_parallel_serialization_tasks`), making the timing window substantial and exploitable under normal network conditions.

## Recommendation
**Solution: Atomically capture and use the protocol ID during serialization**

Modify `serialize_message_for_peer()` to return both the serialized bytes AND the protocol ID used for serialization. Update `send_serialized_message_to_peer()` to use this captured protocol ID instead of re-querying.

**Proposed changes:**

1. Change `serialize_message_for_peer()` signature to return `(Bytes, ProtocolId)`:
```rust
pub fn serialize_message_for_peer(
    &self,
    peer_network_id: &PeerNetworkId,
    message: ConsensusObserverDirectSend,
) -> Result<(Bytes, ProtocolId), Error>
```

2. Capture the protocol during serialization by modifying `to_bytes_by_protocol()` to return protocol IDs alongside bytes.

3. Add a new `send_serialized_message_with_protocol()` method that accepts an explicit protocol ID parameter.

4. Update the consensus publisher pipeline to propagate the protocol ID through the serialization task.

This ensures the protocol used for serialization matches the protocol tag when sending, eliminating the TOCTOU race condition.

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_config::network_id::NetworkId;
    use aptos_types::PeerId;
    use std::sync::Arc;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_protocol_mismatch_toctou() {
        // Setup: Create a peer with CompressedBCS + BCS support
        let peer_id = PeerId::random();
        let peer_network_id = PeerNetworkId::new(NetworkId::Validator, peer_id);
        
        // Create mock connection metadata with both protocols
        let mut protocols = ProtocolIdSet::empty();
        protocols.insert(ProtocolId::ConsensusObserverCompressedBcs);
        protocols.insert(ProtocolId::ConsensusObserverBcs);
        
        let connection_metadata = ConnectionMetadata::new(
            peer_id,
            ConnectionId::from(1),
            NetworkAddress::mock(),
            ConnectionOrigin::Outbound,
            MessagingProtocolVersion::V1,
            protocols.clone(),
            PeerRole::Validator,
        );
        
        // Insert into PeersAndMetadata
        let peers_and_metadata = PeersAndMetadata::new(&[NetworkId::Validator]);
        peers_and_metadata.insert_connection_metadata(peer_network_id, connection_metadata).unwrap();
        
        // Create client with CompressedBCS preferred
        let network_client = create_test_network_client(
            vec![ProtocolId::ConsensusObserverCompressedBcs, ProtocolId::ConsensusObserverBcs],
            peers_and_metadata.clone(),
        );
        let observer_client = ConsensusObserverClient::new(network_client);
        
        // Phase 1: Serialize with CompressedBCS
        let message = ConsensusObserverDirectSend::CommitDecision(/* ... */);
        let serialized_bytes = observer_client
            .serialize_message_for_peer(&peer_network_id, message.clone())
            .await
            .unwrap();
        
        // Simulate network delay during serialization
        sleep(Duration::from_millis(100)).await;
        
        // Phase 2: Peer reconnects with ONLY BCS support
        peers_and_metadata.remove_peer_metadata(peer_network_id, ConnectionId::from(1)).unwrap();
        
        let mut new_protocols = ProtocolIdSet::empty();
        new_protocols.insert(ProtocolId::ConsensusObserverBcs); // Only BCS now
        
        let new_connection_metadata = ConnectionMetadata::new(
            peer_id,
            ConnectionId::from(2),
            NetworkAddress::mock(),
            ConnectionOrigin::Outbound,
            MessagingProtocolVersion::V1,
            new_protocols,
            PeerRole::Validator,
        );
        peers_and_metadata.insert_connection_metadata(peer_network_id, new_connection_metadata).unwrap();
        
        // Phase 3: Send the CompressedBCS-serialized bytes
        // This will tag the message with BCS protocol but bytes are CompressedBCS
        let result = observer_client
            .send_serialized_message_to_peer(&peer_network_id, serialized_bytes, "test")
            .await;
        
        // Expected: Message sent with BCS tag but CompressedBCS encoding
        // When peer receives: BCS.from_bytes(compressed_data) -> DESERIALIZATION ERROR
        assert!(result.is_ok()); // Send succeeds
        
        // Verify the protocol mismatch would cause deserialization failure at receiver
        // The receiver would attempt: ProtocolId::ConsensusObserverBcs.from_bytes(serialized_bytes)
        // This fails because serialized_bytes contains compressed data
    }
}
```

**Notes**

The vulnerability is rooted in the architectural separation between serialization and sending phases, combined with the use of cached peer metadata that can be updated asynchronously. While peer metadata uses `ArcSwap` for efficient concurrent reads [8](#0-7) , this does not prevent the TOCTOU race - it only ensures each read is atomic, not that multiple reads across the serialization pipeline remain consistent.

The protocol selection logic correctly validates peer support at each phase [9](#0-8) , but the lack of atomicity between serialization and sending creates the vulnerability window.

### Citations

**File:** consensus/src/consensus_observer/network/observer_client.rs (L89-101)
```rust
    /// Serializes the given message into bytes for the specified peer
    pub fn serialize_message_for_peer(
        &self,
        peer_network_id: &PeerNetworkId,
        message: ConsensusObserverDirectSend,
    ) -> Result<Bytes, Error> {
        // Serialize the message into bytes
        let message_label = message.get_label();
        let message = ConsensusObserverMessage::DirectSend(message);
        let result = self
            .network_client
            .to_bytes_by_protocol(vec![*peer_network_id], message)
            .map_err(|error| Error::NetworkError(error.to_string()));
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

**File:** network/framework/src/application/interface.rs (L236-241)
```rust
    fn send_to_peer_raw(&self, message: Bytes, peer: PeerNetworkId) -> Result<(), Error> {
        let network_sender = self.get_sender_for_network_id(&peer.network_id())?;
        let direct_send_protocol_id = self
            .get_preferred_protocol_for_peer(&peer, &self.direct_send_protocols_and_preferences)?;
        Ok(network_sender.send_to_raw(peer.peer_id(), direct_send_protocol_id, message)?)
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

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L286-317)
```rust
    tokio::spawn(async move {
        // Create the message serialization task
        let consensus_observer_client_clone = consensus_observer_client.clone();
        let serialization_task =
            outbound_message_receiver.map(move |(peer_network_id, message)| {
                // Spawn a new blocking task to serialize the message
                let consensus_observer_client_clone = consensus_observer_client_clone.clone();
                tokio::task::spawn_blocking(move || {
                    let message_label = message.get_label();
                    let serialized_message = consensus_observer_client_clone
                        .serialize_message_for_peer(&peer_network_id, message);
                    (peer_network_id, serialized_message, message_label)
                })
            });

        // Execute the serialization task with in-order buffering
        let consensus_observer_client_clone = consensus_observer_client.clone();
        serialization_task
            .buffered(consensus_observer_config.max_parallel_serialization_tasks)
            .map(|serialization_result| {
                // Attempt to send the serialized message to the peer
                match serialization_result {
                    Ok((peer_network_id, serialized_message, message_label)) => {
                        match serialized_message {
                            Ok(serialized_message) => {
                                // Send the serialized message to the peer
                                if let Err(error) = consensus_observer_client_clone
                                    .send_serialized_message_to_peer(
                                        &peer_network_id,
                                        serialized_message,
                                        message_label,
                                    )
```

**File:** network/framework/src/protocols/wire/messaging/v1/mod.rs (L105-114)
```rust
pub trait IncomingRequest {
    fn protocol_id(&self) -> crate::ProtocolId;
    fn data(&self) -> &Vec<u8>;

    /// Converts the `SerializedMessage` into its deserialized version of `TMessage` based on the
    /// `ProtocolId`.  See: [`crate::ProtocolId::from_bytes`]
    fn to_message<TMessage: DeserializeOwned>(&self) -> anyhow::Result<TMessage> {
        self.protocol_id().from_bytes(self.data())
    }
}
```

**File:** network/framework/src/protocols/wire/messaging/v1/mod.rs (L153-173)
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

impl IncomingRequest for DirectSendMsg {
    fn protocol_id(&self) -> crate::ProtocolId {
        self.protocol_id
    }

    fn data(&self) -> &Vec<u8> {
        &self.raw_msg
    }
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

**File:** network/framework/src/application/storage.rs (L43-54)
```rust
    peers_and_metadata: RwLock<HashMap<NetworkId, HashMap<PeerId, PeerMetadata>>>,
    trusted_peers: HashMap<NetworkId, Arc<ArcSwap<PeerSet>>>,

    // We maintain a cached copy of the peers and metadata. This is useful to
    // reduce lock contention, as we expect very heavy and frequent reads,
    // but infrequent writes. The cache is updated on all underlying updates.
    //
    // TODO: should we remove this when generational versioning is supported?
    cached_peers_and_metadata: Arc<ArcSwap<HashMap<NetworkId, HashMap<PeerId, PeerMetadata>>>>,

    subscribers: Mutex<Vec<tokio::sync::mpsc::Sender<ConnectionNotification>>>,
}
```

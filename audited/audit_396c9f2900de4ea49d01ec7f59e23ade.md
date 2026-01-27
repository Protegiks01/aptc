# Audit Report

## Title
Race Condition in Protocol Metadata Updates During Peer Reconnection Leads to Silent Message Drops

## Summary
A race condition exists during peer reconnection where stale protocol metadata can cause consensus messages to be routed to unsupported protocols, resulting in silent message drops without error notification to the sender.

## Finding Description

The vulnerability exists in the network layer's protocol selection mechanism during peer reconnection scenarios. When validators reconnect (especially during simultaneous dial scenarios), there is a race condition between:

1. Adding the peer to `active_peers` 
2. Updating the peer's protocol metadata in `PeersAndMetadata`
3. Other threads reading the cached metadata for message routing

The core issue is that `get_supported_protocols()` [1](#0-0)  reads from a cached snapshot of peer metadata [2](#0-1) , which may contain stale protocol information if the read occurs before the cache update completes.

**Attack Scenario:**

1. Validator A and Validator B are connected with protocols `[ConsensusRpcCompressed, ConsensusRpcBcs, ConsensusRpcJson]`
2. Network disruption causes reconnection where Validator B now only supports `[ConsensusRpcJson]` (due to configuration change or version downgrade)
3. During simultaneous dial handling [3](#0-2) , the old peer is removed and new peer is added
4. Race condition: Thread A reads cached metadata showing old protocols while Thread B updates with new protocols
5. Validator A sends consensus vote using `send_to_peer()` [4](#0-3) 
6. `get_preferred_protocol_for_peer()` [5](#0-4)  selects `ConsensusRpcCompressed` based on stale metadata
7. Message is serialized and sent with this protocol
8. Validator B receives the message but has no handler for `ConsensusRpcCompressed`
9. Message is **silently dropped** [6](#0-5)  with only a counter increment - no error sent to sender
10. Validator A believes message was delivered successfully (returns `Ok(())`)
11. Consensus vote is lost, potentially causing round timeout

The protocol metadata is stored in `ConnectionMetadata.application_protocols` [7](#0-6)  and is set once during connection establishment [8](#0-7)  via handshake negotiation [9](#0-8) .

## Impact Explanation

This vulnerability has **Medium Severity** impact:

- **Consensus Availability**: While individual message drops are unlikely to halt consensus entirely (due to retry mechanisms and timeouts), repeated drops during critical rounds can cause significant delays and temporary liveness degradation
- **Silent Failures**: The lack of error notification means the sender cannot detect and retry immediately, exacerbating the impact
- **State Inconsistencies**: Prolonged message drops could cause validators to temporarily fall out of sync, requiring state synchronization intervention

This does NOT meet Critical severity because:
- The race window is transient (microseconds during reconnection)
- Consensus has built-in timeout and retry mechanisms
- Once metadata cache is updated, subsequent messages route correctly
- Does not cause permanent network partition or total liveness loss

## Likelihood Explanation

**Likelihood: Medium-Low**

The vulnerability requires specific conditions:
- Network disruption causing peer reconnection
- Configuration/version mismatch between peers resulting in different supported protocols
- Precise timing where message send occurs during the metadata update race window
- The race window is very small (between active_peers insert and metadata update)

However, in production networks with hundreds of validators experiencing frequent network fluctuations, the probability of this occurring increases. The silent failure nature means it may go undetected until causing noticeable consensus delays.

## Recommendation

Implement atomic metadata validation at message send time:

```rust
fn send_to_peer(&self, message: Message, peer: PeerNetworkId) -> Result<(), Error> {
    let network_sender = self.get_sender_for_network_id(&peer.network_id())?;
    
    // Get current supported protocols with double-check mechanism
    let supported_protocols = self.get_supported_protocols(&peer)?;
    let direct_send_protocol_id = self
        .get_preferred_protocol_for_peer(&peer, &self.direct_send_protocols_and_preferences)?;
    
    // Validate protocol is still supported immediately before sending
    if !supported_protocols.contains(direct_send_protocol_id) {
        return Err(Error::NetworkError(format!(
            "Selected protocol {:?} is not supported by peer {:?}. Supported: {:?}",
            direct_send_protocol_id, peer, supported_protocols
        )));
    }
    
    Ok(network_sender.send_to(peer.peer_id(), direct_send_protocol_id, message)?)
}
```

Additionally:
1. **Add error notification**: When receiver drops message due to unsupported protocol, send error response back to sender
2. **Synchronize metadata update**: Ensure `insert_connection_metadata()` completes before peer is marked as available in `active_peers`
3. **Add monitoring**: Increment high-priority alerts (not just counters) when messages are dropped due to protocol mismatch

## Proof of Concept

```rust
#[tokio::test]
async fn test_stale_metadata_message_drop() {
    // Setup: Create two validators with network clients
    let (validator_a_client, validator_a_metadata) = setup_validator("A");
    let (validator_b_client, validator_b_metadata) = setup_validator("B");
    
    // Step 1: Connect validators with full protocol support
    let protocols_v1 = ProtocolIdSet::from_iter([
        ProtocolId::ConsensusRpcCompressed,
        ProtocolId::ConsensusRpcBcs,
        ProtocolId::ConsensusRpcJson,
    ]);
    establish_connection(&validator_a_metadata, "B", protocols_v1.clone());
    establish_connection(&validator_b_metadata, "A", protocols_v1.clone());
    
    // Step 2: Simulate Validator B restart with limited protocols
    let protocols_v2 = ProtocolIdSet::from_iter([ProtocolId::ConsensusRpcJson]);
    disconnect_peer(&validator_b_metadata, "A");
    
    // Step 3: Trigger reconnection + message send race
    let reconnect_handle = tokio::spawn(async move {
        establish_connection(&validator_b_metadata, "A", protocols_v2);
    });
    
    // Small delay to hit race window
    tokio::time::sleep(Duration::from_micros(10)).await;
    
    // Step 4: Send consensus message from A to B during reconnection
    let vote_msg = ConsensusMsg::VoteMsg(Box::new(create_test_vote()));
    let send_result = validator_a_client.send_to_peer(
        vote_msg,
        PeerNetworkId::new(NetworkId::Validator, peer_id("B"))
    );
    
    // Step 5: Verify message was sent successfully from A's perspective
    assert!(send_result.is_ok(), "Send should succeed");
    
    // Step 6: Verify message was dropped on B's side
    let received_messages = validator_b_client.get_received_messages().await;
    assert!(
        received_messages.is_empty(),
        "Message should be dropped due to protocol mismatch"
    );
    
    // Step 7: Verify UNKNOWN_LABEL counter was incremented (silent drop)
    let unknown_count = get_counter_value("direct_send_messages", "unknown");
    assert!(unknown_count > 0, "Unknown protocol counter should increment");
    
    reconnect_handle.await.unwrap();
}
```

## Notes

While the core metadata update mechanism is sound (using `and_modify` to replace connection_metadata [10](#0-9) ), the use of `arc_swap` for caching [11](#0-10)  introduces snapshot consistency semantics that create the transient race window. This is a classic trade-off between performance (lock-free reads) and consistency guarantees.

### Citations

**File:** network/framework/src/application/interface.rs (L133-138)
```rust
    fn get_supported_protocols(&self, peer: &PeerNetworkId) -> Result<ProtocolIdSet, Error> {
        let peers_and_metadata = self.get_peers_and_metadata();
        peers_and_metadata
            .get_metadata_for_peer(*peer)
            .map(|peer_metadata| peer_metadata.get_supported_protocols())
    }
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

**File:** network/framework/src/application/interface.rs (L229-234)
```rust
    fn send_to_peer(&self, message: Message, peer: PeerNetworkId) -> Result<(), Error> {
        let network_sender = self.get_sender_for_network_id(&peer.network_id())?;
        let direct_send_protocol_id = self
            .get_preferred_protocol_for_peer(&peer, &self.direct_send_protocols_and_preferences)?;
        Ok(network_sender.send_to(peer.peer_id(), direct_send_protocol_id, message)?)
    }
```

**File:** network/framework/src/application/storage.rs (L49-51)
```rust
    //
    // TODO: should we remove this when generational versioning is supported?
    cached_peers_and_metadata: Arc<ArcSwap<HashMap<NetworkId, HashMap<PeerId, PeerMetadata>>>>,
```

**File:** network/framework/src/application/storage.rs (L151-169)
```rust
    pub fn get_metadata_for_peer(
        &self,
        peer_network_id: PeerNetworkId,
    ) -> Result<PeerMetadata, Error> {
        // Get the cached peers and metadata
        let cached_peers_and_metadata = self.cached_peers_and_metadata.load();

        // Fetch the peers and metadata for the given network
        let network_id = peer_network_id.network_id();
        let peer_metadata_for_network = cached_peers_and_metadata
            .get(&network_id)
            .ok_or_else(|| missing_network_metadata_error(&network_id))?;

        // Get the metadata for the peer
        peer_metadata_for_network
            .get(&peer_network_id.peer_id())
            .cloned()
            .ok_or_else(|| missing_peer_metadata_error(&peer_network_id))
    }
```

**File:** network/framework/src/application/storage.rs (L199-204)
```rust
        peer_metadata_for_network
            .entry(peer_network_id.peer_id())
            .and_modify(|peer_metadata| {
                peer_metadata.connection_metadata = connection_metadata.clone()
            })
            .or_insert_with(|| PeerMetadata::new(connection_metadata.clone()));
```

**File:** network/framework/src/peer_manager/mod.rs (L626-655)
```rust
        if let Entry::Occupied(active_entry) = self.active_peers.entry(peer_id) {
            let (curr_conn_metadata, _) = active_entry.get();
            if Self::simultaneous_dial_tie_breaking(
                self.network_context.peer_id(),
                peer_id,
                curr_conn_metadata.origin,
                conn_meta.origin,
            ) {
                let (_, peer_handle) = active_entry.remove();
                // Drop the existing connection and replace it with the new connection
                drop(peer_handle);
                info!(
                    NetworkSchema::new(&self.network_context).remote_peer(&peer_id),
                    "{} Closing existing connection with Peer {} to mitigate simultaneous dial",
                    self.network_context,
                    peer_id.short_str()
                );
                send_new_peer_notification = false;
            } else {
                info!(
                    NetworkSchema::new(&self.network_context).remote_peer(&peer_id),
                    "{} Closing incoming connection with Peer {} to mitigate simultaneous dial",
                    self.network_context,
                    peer_id.short_str()
                );
                // Drop the new connection and keep the one already stored in active_peers
                self.disconnect(connection);
                return Ok(());
            }
        }
```

**File:** network/framework/src/peer/mod.rs (L459-464)
```rust
                match self.upstream_handlers.get(&direct.protocol_id) {
                    None => {
                        counters::direct_send_messages(&self.network_context, UNKNOWN_LABEL).inc();
                        counters::direct_send_bytes(&self.network_context, UNKNOWN_LABEL)
                            .inc_by(data_len as u64);
                    },
```

**File:** network/framework/src/transport/mod.rs (L100-108)
```rust
pub struct ConnectionMetadata {
    pub remote_peer_id: PeerId,
    pub connection_id: ConnectionId,
    pub addr: NetworkAddress,
    pub origin: ConnectionOrigin,
    pub messaging_protocol: MessagingProtocolVersion,
    pub application_protocols: ProtocolIdSet,
    pub role: PeerRole,
}
```

**File:** network/framework/src/transport/mod.rs (L307-331)
```rust
    // try to negotiate common aptosnet version and supported application protocols
    let (messaging_protocol, application_protocols) = handshake_msg
        .perform_handshake(&remote_handshake)
        .map_err(|err| {
            let err = format!(
                "handshake negotiation with peer {} failed: {}",
                remote_peer_id.short_str(),
                err
            );
            add_pp_addr(proxy_protocol_enabled, io::Error::other(err), &addr)
        })?;

    // return successful connection
    Ok(Connection {
        socket,
        metadata: ConnectionMetadata::new(
            remote_peer_id,
            CONNECTION_ID_GENERATOR.next(),
            addr,
            origin,
            messaging_protocol,
            application_protocols,
            peer_role,
        ),
    })
```

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L431-465)
```rust
    pub fn perform_handshake(
        &self,
        other: &HandshakeMsg,
    ) -> Result<(MessagingProtocolVersion, ProtocolIdSet), HandshakeError> {
        // verify that both peers are on the same chain
        if self.chain_id != other.chain_id {
            return Err(HandshakeError::InvalidChainId(
                other.chain_id,
                self.chain_id,
            ));
        }

        // verify that both peers are on the same network
        if self.network_id != other.network_id {
            return Err(HandshakeError::InvalidNetworkId(
                other.network_id,
                self.network_id,
            ));
        }

        // find the greatest common MessagingProtocolVersion where we both support
        // at least one common ProtocolId.
        for (our_handshake_version, our_protocols) in self.supported_protocols.iter().rev() {
            if let Some(their_protocols) = other.supported_protocols.get(our_handshake_version) {
                let common_protocols = our_protocols.intersect(their_protocols);

                if !common_protocols.is_empty() {
                    return Ok((*our_handshake_version, common_protocols));
                }
            }
        }

        // no intersection found
        Err(HandshakeError::NoCommonProtocols)
    }
```

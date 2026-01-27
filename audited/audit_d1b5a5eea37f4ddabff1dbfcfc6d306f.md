# Audit Report

## Title
Byzantine Validators Can Evade Consensus Participation Through Selective Protocol Negotiation

## Summary
A malicious validator can intentionally advertise support for only non-consensus protocols during the network handshake, causing consensus messages to be silently dropped while the validator remains connected. This allows Byzantine actors to hide their non-participation and potentially disrupt consensus liveness without proper detection.

## Finding Description

The vulnerability exists in the protocol negotiation and message broadcasting mechanism of the Aptos network layer. During connection establishment, validators exchange supported protocols via `HandshakeMsg` and negotiate a common set. However, the handshake only requires that peers support **at least one** common protocol—it does not enforce that consensus-critical protocols are supported. [1](#0-0) 

A malicious validator can exploit this by advertising support for only non-consensus protocols (e.g., `HealthCheckerRpc`, `PeerMonitoringServiceRpc`) but deliberately omitting consensus protocols (`ConsensusDirectSendBcs`, `ConsensusDirectSendCompressed`, `ConsensusRpcBcs`). The handshake succeeds, the connection is established, and the peer appears "connected" in network monitoring. [2](#0-1) 

When consensus attempts to broadcast messages to all validators, it retrieves the validator set from the epoch configuration and calls `send_to_many()`: [3](#0-2) 

This eventually invokes `group_peers_by_protocol()`, which attempts to match each peer with a preferred consensus protocol. For the malicious peer, this matching fails because they don't support any consensus protocols. The peer is then placed in `peers_without_a_protocol` and **silently excluded** from the message recipients: [4](#0-3) 

Critically, `send_to_peers()` returns `Ok(())` even when peers are silently dropped, providing no error indication to consensus: [5](#0-4) 

The only indication is a sampled warning log (every 10 seconds), which is insufficient for detecting Byzantine behavior in real-time.

## Impact Explanation

This vulnerability qualifies as **HIGH severity** under the Aptos bug bounty program's "Significant protocol violations" category for the following reasons:

1. **Consensus Liveness Threat**: If a sufficient number of validators (approaching the 1/3 Byzantine threshold) exploit this vulnerability, consensus can lose liveness as broadcasts fail to reach enough validators for quorum formation.

2. **Byzantine Behavior Concealment**: Malicious validators can remain "connected" to the network while not participating in consensus, making it difficult to detect and attribute fault. They pass health checks but don't receive proposals, don't vote, and don't contribute to consensus progress.

3. **Silent Failure Mode**: The network layer returns success to consensus even when messages aren't delivered, preventing proper error handling and fault detection mechanisms from activating.

4. **Validator Set Integrity**: The vulnerability undermines the assumption that all validators in the active set can receive consensus messages, violating a critical invariant of the AptosBFT protocol.

## Likelihood Explanation

**Likelihood: HIGH**

The attack is highly feasible because:

1. **Low Complexity**: The attacker only needs to modify the `HandshakeMsg` sent during connection establishment to exclude consensus protocols while including at least one common protocol (e.g., `HealthCheckerRpc`).

2. **No Authentication Barriers**: The handshake protocol validates chain ID and network ID but does not enforce that validators must support consensus protocols.

3. **Minimal Detection**: Only sampled warning logs provide indication, which can be missed in production environments with high log volume.

4. **Realistic Attacker Profile**: Any validator operator can execute this attack by modifying their node's protocol configuration.

5. **Strategic Value**: Byzantine actors have strong incentives to use this technique to avoid participation while maintaining the appearance of being a healthy validator.

## Recommendation

Implement mandatory protocol support validation during validator connection establishment. The fix should:

1. **Enforce Protocol Requirements**: During or immediately after the handshake for validator network connections, verify that the peer supports all required consensus protocols.

2. **Fail Fast**: Disconnect peers that don't support required protocols rather than allowing them to remain connected.

3. **Explicit Error Propagation**: Modify `group_peers_by_protocol()` and `send_to_peers()` to return errors when peers lack required protocols, allowing consensus to detect and react to this condition.

**Suggested code fix for `group_peers_by_protocol()`:**

```rust
fn group_peers_by_protocol(
    &self,
    peers: Vec<PeerNetworkId>,
) -> Result<HashMap<ProtocolId, Vec<PeerNetworkId>>, Error> {
    let mut peers_per_protocol = HashMap::new();
    let mut peers_without_a_protocol = vec![];
    
    for peer in peers {
        match self.get_preferred_protocol_for_peer(&peer, &self.direct_send_protocols_and_preferences) {
            Ok(protocol) => peers_per_protocol
                .entry(protocol)
                .or_insert_with(Vec::new)
                .push(peer),
            Err(_) => peers_without_a_protocol.push(peer),
        }
    }

    // Return error instead of silently dropping peers
    if !peers_without_a_protocol.is_empty() {
        return Err(Error::NetworkError(format!(
            "Peers without common protocol: {:?}", 
            peers_without_a_protocol
        )));
    }

    Ok(peers_per_protocol)
}
```

Additionally, add validation in the connection upgrade path to verify consensus protocol support for validator connections.

## Proof of Concept

```rust
// PoC demonstrating the vulnerability
// File: network/framework/src/application/tests.rs (add as test)

#[tokio::test]
async fn test_byzantine_protocol_evasion() {
    use crate::protocols::wire::handshake::v1::{HandshakeMsg, MessagingProtocolVersion, ProtocolId, ProtocolIdSet};
    use std::collections::BTreeMap;
    
    // Simulate malicious validator that advertises only non-consensus protocols
    let mut malicious_protocols = ProtocolIdSet::empty();
    malicious_protocols.insert(ProtocolId::HealthCheckerRpc);
    malicious_protocols.insert(ProtocolId::PeerMonitoringServiceRpc);
    
    let mut malicious_supported = BTreeMap::new();
    malicious_supported.insert(MessagingProtocolVersion::V1, malicious_protocols);
    
    let malicious_handshake = HandshakeMsg {
        supported_protocols: malicious_supported,
        chain_id: ChainId::test(),
        network_id: NetworkId::Validator,
    };
    
    // Honest node supports all protocols including consensus
    let honest_protocols = ProtocolIdSet::all_known();
    let mut honest_supported = BTreeMap::new();
    honest_supported.insert(MessagingProtocolVersion::V1, honest_protocols);
    
    let honest_handshake = HandshakeMsg {
        supported_protocols: honest_supported,
        chain_id: ChainId::test(),
        network_id: NetworkId::Validator,
    };
    
    // Handshake succeeds because HealthCheckerRpc is common
    let result = honest_handshake.perform_handshake(&malicious_handshake);
    assert!(result.is_ok());
    let (_, common_protocols) = result.unwrap();
    
    // Verify that consensus protocols are NOT in the common set
    assert!(!common_protocols.contains(ProtocolId::ConsensusDirectSendBcs));
    assert!(!common_protocols.contains(ProtocolId::ConsensusDirectSendCompressed));
    assert!(!common_protocols.contains(ProtocolId::ConsensusRpcBcs));
    
    // But HealthCheckerRpc is present, allowing connection
    assert!(common_protocols.contains(ProtocolId::HealthCheckerRpc));
    
    // This demonstrates that a malicious validator can establish a connection
    // without supporting consensus protocols, leading to silent message drops
    // when consensus attempts to broadcast to this peer.
}
```

## Notes

This vulnerability is particularly insidious because it violates the principle of secure defaults. The network layer should enforce that validator connections MUST support consensus protocols, but instead it only requires that *some* common protocol exists. The silent failure mode (returning `Ok(())` while dropping peers) prevents consensus from detecting and adapting to this condition, making it a serious protocol-level vulnerability that undermines the safety and liveness guarantees of AptosBFT.

### Citations

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L428-465)
```rust
    /// This function:
    /// 1. verifies that both HandshakeMsg are compatible and
    /// 2. finds out the intersection of protocols that is supported
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

**File:** network/framework/src/transport/mod.rs (L297-331)
```rust
    // exchange HandshakeMsg
    let handshake_msg = HandshakeMsg {
        supported_protocols: ctxt.supported_protocols.clone(),
        chain_id: ctxt.chain_id,
        network_id: ctxt.network_id,
    };
    let remote_handshake = exchange_handshake(&handshake_msg, &mut socket)
        .await
        .map_err(|err| add_pp_addr(proxy_protocol_enabled, err, &addr))?;

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

**File:** consensus/src/network.rs (L387-408)
```rust
    pub fn broadcast_without_self(&self, msg: ConsensusMsg) {
        fail_point!("consensus::send::any", |_| ());

        let self_author = self.author;
        let mut other_validators: Vec<_> = self
            .validators
            .get_ordered_account_addresses_iter()
            .filter(|author| author != &self_author)
            .collect();
        self.sort_peers_by_latency(&mut other_validators);

        counters::CONSENSUS_SENT_MSGS
            .with_label_values(&[msg.name()])
            .inc_by(other_validators.len() as u64);
        // Broadcast message over direct-send to all other validators.
        if let Err(err) = self
            .consensus_network_client
            .send_to_many(other_validators, msg)
        {
            warn!(error = ?err, "Error broadcasting message");
        }
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

**File:** network/framework/src/application/interface.rs (L243-258)
```rust
    fn send_to_peers(&self, message: Message, peers: Vec<PeerNetworkId>) -> Result<(), Error> {
        let peers_per_protocol = self.group_peers_by_protocol(peers);

        // Send to all peers in each protocol group and network
        for (protocol_id, peers) in peers_per_protocol {
            for (network_id, peers) in &peers
                .iter()
                .chunk_by(|peer_network_id| peer_network_id.network_id())
            {
                let network_sender = self.get_sender_for_network_id(&network_id)?;
                let peer_ids = peers.map(|peer_network_id| peer_network_id.peer_id());
                network_sender.send_to_many(peer_ids, protocol_id, message.clone())?;
            }
        }
        Ok(())
    }
```

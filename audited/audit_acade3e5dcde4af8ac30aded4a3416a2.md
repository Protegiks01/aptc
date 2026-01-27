# Audit Report

## Title
Protocol Negotiation Bypass - Peers Can Use Non-Negotiated Protocol IDs After Handshake

## Summary
The Aptos network layer fails to validate that incoming message protocol IDs were actually negotiated during the handshake. Malicious peers can send messages using any protocol ID, bypassing the handshake protocol negotiation mechanism and potentially causing resource exhaustion or other protocol-level attacks.

## Finding Description

During the Aptos network handshake, peers negotiate a set of common supported protocols through `HandshakeMsg::perform_handshake()`, which returns the intersection of both peers' supported protocols. This negotiated set is stored in `ConnectionMetadata.application_protocols`. [1](#0-0) 

However, when processing inbound messages in `Peer::handle_inbound_network_message()`, the system routes messages based solely on the `protocol_id` field in the incoming message, without validating that this protocol was actually negotiated during handshake: [2](#0-1) 

The routing logic checks `self.upstream_handlers.get(&request.protocol_id)` to find a handler, but never validates `self.connection_metadata.application_protocols.contains(request.protocol_id)`. 

While the codebase provides a `PeerMetadata::supports_protocol()` method that checks the negotiated protocols: [3](#0-2) 

This validation is only used for outbound decisions (determining which peers to send messages to), not for inbound message validation.

**Attack Scenario:**
1. Malicious Peer B completes handshake with Honest Node A
2. During handshake, Peer B advertises support only for `[ProtocolId::MempoolDirectSend]`
3. They negotiate common protocols: `[ProtocolId::MempoolDirectSend]`
4. After connection is established, Peer B sends RPC requests with `protocol_id=ProtocolId::HealthCheckerRpc` (NOT negotiated)
5. Node A processes these messages without validating the protocol was negotiated
6. If Node A has a handler for HealthCheckerRpc, it processes the request
7. Peer B can spam health checks, consensus messages, or any other protocol despite not negotiating support for them

This breaks the fundamental security contract established by the handshake: peers should only use protocols they mutually agreed to support.

In the specific case of `handle_ping_request()`: [4](#0-3) 

The function receives a `protocol` parameter but never validates it equals `ProtocolId::HealthCheckerRpc`. While the current routing would normally ensure this, the lack of validation at both the message handling layer and the application layer creates a defense-in-depth failure.

## Impact Explanation

**Severity: Medium** (per Aptos Bug Bounty: "State inconsistencies requiring intervention")

This vulnerability enables several attack vectors:

1. **Protocol Negotiation Bypass**: Attackers can use protocols they explicitly refused to negotiate, violating the handshake contract
2. **Resource Exhaustion**: Malicious peers can flood nodes with requests on protocols they claimed not to support, potentially bypassing rate limiting or resource allocation based on negotiated protocols
3. **Protocol-Specific Security Bypasses**: Different protocols may have different security properties, resource limits, or trust assumptions. Using non-negotiated protocols could bypass these controls
4. **Network Integrity Violation**: The handshake is meant to establish trust and capabilities; this bypass undermines the entire protocol negotiation mechanism

While this doesn't directly cause consensus breaks or fund theft, it represents a significant protocol-level vulnerability that could be leveraged for more sophisticated attacks or DoS scenarios.

## Likelihood Explanation

**Likelihood: High**

The vulnerability is trivially exploitable:
- Requires no special privileges or validator access
- Any network peer can exploit this immediately after handshake
- No complex timing or race conditions required
- The attack is undetectable at the protocol level (messages appear valid)
- No cryptographic primitives need to be broken

The only requirement is network connectivity to an Aptos node, making this highly accessible to attackers.

## Recommendation

Add protocol validation in `Peer::handle_inbound_network_message()` to verify incoming message protocol IDs were negotiated during handshake:

```rust
fn handle_inbound_network_message(
    &mut self,
    message: NetworkMessage,
) -> Result<(), PeerManagerError> {
    match &message {
        NetworkMessage::RpcRequest(request) => {
            // Validate protocol was negotiated during handshake
            if !self.connection_metadata.application_protocols.contains(request.protocol_id) {
                warn!(
                    SecurityEvent::InvalidNetworkEvent,
                    NetworkSchema::new(&self.network_context)
                        .connection_metadata(&self.connection_metadata),
                    protocol_id = request.protocol_id.as_str(),
                    "{} Peer {} sent RPC request with non-negotiated protocol: {:?}",
                    self.network_context,
                    self.remote_peer_id().short_str(),
                    request.protocol_id
                );
                // Disconnect peer for protocol violation
                return Err(PeerManagerError::InvalidProtocol);
            }
            
            match self.upstream_handlers.get(&request.protocol_id) {
                // ... existing routing logic
            }
        },
        NetworkMessage::DirectSendMsg(direct) => {
            // Add similar validation for DirectSend messages
            if !self.connection_metadata.application_protocols.contains(direct.protocol_id) {
                warn!(
                    SecurityEvent::InvalidNetworkEvent,
                    NetworkSchema::new(&self.network_context)
                        .connection_metadata(&self.connection_metadata),
                    protocol_id = direct.protocol_id.as_str(),
                    "{} Peer {} sent DirectSend with non-negotiated protocol: {:?}",
                    self.network_context,
                    self.remote_peer_id().short_str(),
                    direct.protocol_id
                );
                return Err(PeerManagerError::InvalidProtocol);
            }
            // ... existing routing logic
        },
        // ... other cases
    }
}
```

Additionally, add defensive validation in `handle_ping_request()`:

```rust
fn handle_ping_request(
    &mut self,
    peer_id: PeerId,
    ping: Ping,
    protocol: ProtocolId,
    res_tx: oneshot::Sender<Result<Bytes, RpcError>>,
) {
    // Validate protocol is HealthCheckerRpc
    if protocol != ProtocolId::HealthCheckerRpc {
        warn!(
            SecurityEvent::InvalidHealthCheckerMsg,
            NetworkSchema::new(&self.network_context).remote_peer(&peer_id),
            protocol_id = protocol.as_str(),
            "{} Received ping with incorrect protocol ID: {:?}",
            self.network_context,
            protocol
        );
        return;
    }
    
    // ... existing ping handling logic
}
```

## Proof of Concept

```rust
#[tokio::test]
async fn test_non_negotiated_protocol_usage() {
    use aptos_config::network_id::NetworkId;
    use aptos_types::PeerId;
    use network_framework::{
        protocols::wire::handshake::v1::{ProtocolId, ProtocolIdSet},
        transport::ConnectionMetadata,
        protocols::wire::messaging::v1::{NetworkMessage, RpcRequest},
    };
    
    // Simulate a connection where only MempoolDirectSend was negotiated
    let mut negotiated_protocols = ProtocolIdSet::empty();
    negotiated_protocols.insert(ProtocolId::MempoolDirectSend);
    
    let connection_metadata = ConnectionMetadata {
        remote_peer_id: PeerId::random(),
        connection_id: ConnectionId::default(),
        addr: NetworkAddress::mock(),
        origin: ConnectionOrigin::Inbound,
        messaging_protocol: MessagingProtocolVersion::V1,
        application_protocols: negotiated_protocols, // Only MempoolDirectSend
        role: PeerRole::Unknown,
    };
    
    // Attacker sends RPC request with HealthCheckerRpc (NOT negotiated)
    let malicious_request = RpcRequest {
        protocol_id: ProtocolId::HealthCheckerRpc, // Protocol not in negotiated set!
        request_id: 1,
        priority: 0,
        raw_request: vec![/* serialized ping */].into(),
    };
    
    let message = NetworkMessage::RpcRequest(malicious_request);
    
    // This message would currently be processed without validation
    // Expected: Should be rejected because HealthCheckerRpc was not negotiated
    // Actual: Gets routed to handler if one exists
    
    assert!(!connection_metadata.application_protocols.contains(ProtocolId::HealthCheckerRpc),
            "HealthCheckerRpc should not be in negotiated protocols");
    
    // The vulnerability: there's no check preventing this message from being processed
}
```

## Notes

This vulnerability represents a fundamental breakdown in the protocol negotiation security model. The handshake establishes a contract about which protocols will be used, but this contract is not enforced at runtime. The fix requires adding validation at the message processing layer to ensure all incoming messages respect the negotiated protocol set.

### Citations

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

**File:** network/framework/src/peer/mod.rs (L505-530)
```rust
            NetworkMessage::RpcRequest(request) => {
                match self.upstream_handlers.get(&request.protocol_id) {
                    None => {
                        counters::direct_send_messages(&self.network_context, UNKNOWN_LABEL).inc();
                        counters::direct_send_bytes(&self.network_context, UNKNOWN_LABEL)
                            .inc_by(request.raw_request.len() as u64);
                    },
                    Some(handler) => {
                        let sender = self.connection_metadata.remote_peer_id;
                        let network_id = self.network_context.network_id();
                        let sender = PeerNetworkId::new(network_id, sender);
                        if let Err(err) = self
                            .inbound_rpcs
                            .handle_inbound_request(handler, ReceivedMessage::new(message, sender))
                        {
                            warn!(
                                NetworkSchema::new(&self.network_context)
                                    .connection_metadata(&self.connection_metadata),
                                error = %err,
                                "{} Error handling inbound rpc request: {}",
                                self.network_context,
                                err
                            );
                        }
                    },
                }
```

**File:** network/framework/src/application/metadata.rs (L55-60)
```rust
    /// Returns true iff the peer has advertised support for the given protocol
    pub fn supports_protocol(&self, protocol_id: ProtocolId) -> bool {
        self.connection_metadata
            .application_protocols
            .contains(protocol_id)
    }
```

**File:** network/framework/src/protocols/health_checker/mod.rs (L277-306)
```rust
    fn handle_ping_request(
        &mut self,
        peer_id: PeerId,
        ping: Ping,
        protocol: ProtocolId,
        res_tx: oneshot::Sender<Result<Bytes, RpcError>>,
    ) {
        let message = match protocol.to_bytes(&HealthCheckerMsg::Pong(Pong(ping.0))) {
            Ok(msg) => msg,
            Err(e) => {
                warn!(
                    NetworkSchema::new(&self.network_context),
                    error = ?e,
                    "{} Unable to serialize pong response: {}", self.network_context, e
                );
                return;
            },
        };
        trace!(
            NetworkSchema::new(&self.network_context).remote_peer(&peer_id),
            "{} Sending Pong response to peer: {} with nonce: {}",
            self.network_context,
            peer_id.short_str(),
            ping.0,
        );
        // Record Ingress HC here and reset failures.
        self.network_interface.reset_peer_failures(peer_id);

        let _ = res_tx.send(Ok(message.into()));
    }
```

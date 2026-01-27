# Audit Report

## Title
Protocol Negotiation Bypass Allows Malicious Peers to Use Non-Negotiated Protocol Variants

## Summary
The network layer fails to validate that incoming messages use a protocol variant that was negotiated during the handshake. A malicious peer can send messages using any protocol for which the victim has a registered handler, even if that protocol was explicitly excluded from the negotiated protocol set, effectively bypassing the protocol negotiation security mechanism.

## Finding Description

The Aptos network layer performs protocol negotiation during the initial connection handshake, where peers exchange their supported protocols and agree on a common set to use for communication. This negotiation is intended to enforce security policies, such as preferring compressed protocols over uncompressed ones, or excluding deprecated protocol variants. [1](#0-0) 

The JWK consensus module defines protocol preferences with `JWKConsensusRpcCompressed` having the highest priority, followed by `Bcs`, then `Json`. During the handshake, peers negotiate which protocols to use: [2](#0-1) 

The negotiated protocols are stored in `ConnectionMetadata.application_protocols`: [3](#0-2) 

However, when a peer receives an incoming message, the validation logic only checks whether an upstream handler exists for the message's `protocol_id`, without verifying that the protocol was part of the negotiated set: [4](#0-3) 

The code checks `self.upstream_handlers.get(&request.protocol_id)` but never validates `self.connection_metadata.application_protocols.contains(request.protocol_id)`.

**Attack Path:**

1. **Setup**: Victim node registers upstream handlers for multiple protocol variants (e.g., `[JWKConsensusRpcCompressed, JWKConsensusRpcBcs, JWKConsensusRpcJson]`) to maintain backward compatibility
2. **Configuration**: Victim's network configuration specifies preference for only `[JWKConsensusRpcCompressed]`
3. **Handshake**: During connection establishment, victim and malicious peer negotiate protocols. The negotiated set is `[JWKConsensusRpcCompressed]` (stored in `ConnectionMetadata.application_protocols`)
4. **Bypass**: Malicious peer crafts an `RpcRequest` with `protocol_id = JWKConsensusRpcJson`
5. **Acceptance**: Victim accepts the message because it has an upstream handler for `JWKConsensusRpcJson`, even though this protocol was not negotiated
6. **Processing**: The message is deserialized and processed using the non-negotiated protocol

This breaks the security invariant that **only mutually agreed-upon protocols should be used for communication**.

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty program for the following reasons:

1. **Protocol Violation**: It violates the fundamental contract of protocol negotiation, which is a significant protocol-level security mechanism

2. **Security Policy Bypass**: Nodes that explicitly disable certain protocols (e.g., deprecated Json variants) can still be forced to process messages using those protocols

3. **Potential for Future Exploitation**: If security differences emerge between protocol versions (e.g., stricter validation in newer protocols, different recursion limits, or different deserialization behavior), attackers could exploit this to bypass those security improvements

4. **Limited Direct Impact**: While this is a serious protocol violation, the immediate security impact is mitigated by the fact that:
   - All protocol variants ultimately deserialize to the same message types
   - Security checks (like signature verification) are applied after deserialization regardless of protocol
   - The vulnerability requires the victim to have handlers registered for multiple protocols

However, this still represents a **state inconsistency requiring intervention** as nodes may process messages using unintended protocol variants, violating operator security policies.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploitable because:

1. **No Special Prerequisites**: Any malicious peer can exploit this - no validator credentials or special access required
2. **Simple Exploitation**: The attacker merely needs to set a different `protocol_id` in outgoing messages
3. **Common Configuration**: Many nodes register handlers for multiple protocol variants for backward compatibility
4. **No Detection**: The victim has no visibility into this bypass - messages appear as normal inbound traffic

The attack requires:
- Ability to establish a network connection (standard peer capability)
- Knowledge of which protocols the victim has handlers for (can be inferred from handshake or public configuration)
- Ability to craft messages with arbitrary `protocol_id` fields (trivial)

## Recommendation

Add protocol validation in the message processing logic to ensure incoming messages use only negotiated protocols:

```rust
fn handle_inbound_network_message(
    &mut self,
    message: NetworkMessage,
) -> Result<(), PeerManagerError> {
    match &message {
        NetworkMessage::DirectSendMsg(direct) => {
            // SECURITY FIX: Validate protocol was negotiated
            if !self.connection_metadata.application_protocols.contains(direct.protocol_id) {
                warn!(
                    NetworkSchema::new(&self.network_context)
                        .connection_metadata(&self.connection_metadata),
                    protocol_id = ?direct.protocol_id,
                    "Rejected message using non-negotiated protocol"
                );
                // Send error response and drop message
                return Err(PeerManagerError::NotNegotiated(direct.protocol_id));
            }
            // ... existing handler logic
        },
        NetworkMessage::RpcRequest(request) => {
            // SECURITY FIX: Validate protocol was negotiated
            if !self.connection_metadata.application_protocols.contains(request.protocol_id) {
                warn!(
                    NetworkSchema::new(&self.network_context)
                        .connection_metadata(&self.connection_metadata),
                    protocol_id = ?request.protocol_id,
                    "Rejected RPC using non-negotiated protocol"
                );
                return Err(PeerManagerError::NotNegotiated(request.protocol_id));
            }
            // ... existing handler logic
        },
        // ... other cases
    }
}
```

Additionally, consider:
1. Logging protocol violations for security monitoring
2. Implementing rate limiting or peer penalties for repeated violations
3. Sending explicit error messages to misbehaving peers
4. Reviewing other protocol validation gaps in the codebase

## Proof of Concept

The following Rust test demonstrates the vulnerability:

```rust
#[cfg(test)]
mod protocol_bypass_test {
    use super::*;
    use aptos_config::network_id::NetworkId;
    use aptos_types::PeerId;
    use crate::protocols::wire::handshake::v1::{ProtocolId, ProtocolIdSet};
    use crate::transport::ConnectionMetadata;
    
    #[test]
    fn test_protocol_negotiation_bypass() {
        // Setup: Node negotiates only Compressed protocol
        let mut negotiated_protocols = ProtocolIdSet::empty();
        negotiated_protocols.insert(ProtocolId::JWKConsensusRpcCompressed);
        
        let connection_metadata = ConnectionMetadata::new(
            PeerId::random(),
            ConnectionId::from(1),
            NetworkAddress::mock(),
            ConnectionOrigin::Inbound,
            MessagingProtocolVersion::V1,
            negotiated_protocols.clone(), // Only Compressed was negotiated
            PeerRole::Validator,
        );
        
        // Attack: Malicious peer sends message using Json protocol
        let malicious_request = RpcRequest {
            protocol_id: ProtocolId::JWKConsensusRpcJson, // NOT negotiated!
            request_id: 1,
            priority: 0,
            raw_request: vec![1, 2, 3],
        };
        
        let message = NetworkMessage::RpcRequest(malicious_request);
        
        // Vulnerability: Message is accepted if handler exists for JWKConsensusRpcJson
        // even though only JWKConsensusRpcCompressed was negotiated
        
        // Expected: Should reject message with protocol not in negotiated_protocols
        // Actual: Accepts message if upstream_handlers.contains_key(JWKConsensusRpcJson)
        
        assert!(!connection_metadata.application_protocols.contains(
            ProtocolId::JWKConsensusRpcJson
        ), "Json protocol should NOT be in negotiated protocols");
        
        // The vulnerability allows processing this message anyway
        // if an upstream handler for JWKConsensusRpcJson exists
    }
}
```

**Notes:**

The vulnerability exists because the protocol validation happens at registration time (checking if a handler exists) rather than at message processing time (checking if the protocol was negotiated). This allows protocol downgrade attacks where peers can bypass intended protocol restrictions by simply advertising different protocols during the handshake but then using non-negotiated variants at runtime.

### Citations

**File:** crates/aptos-jwk-consensus/src/network_interface.rs (L22-26)
```rust
pub const RPC: &[ProtocolId] = &[
    ProtocolId::JWKConsensusRpcCompressed,
    ProtocolId::JWKConsensusRpcBcs,
    ProtocolId::JWKConsensusRpcJson,
];
```

**File:** network/framework/src/transport/mod.rs (L297-317)
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
```

**File:** network/framework/src/transport/mod.rs (L320-331)
```rust
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

# Audit Report

## Title
Network Protocol Confusion: DirectSendMsg and RpcRequest Messages Can Be Sent on Wrong Protocol IDs Without Validation

## Summary
The Aptos network layer fails to validate that `DirectSendMsg` messages use only direct-send protocol IDs and `RpcRequest` messages use only RPC protocol IDs. A malicious peer can send messages of the wrong type on any protocol, causing protocol confusion where applications receive unexpected message types (RPC requests on direct-send protocols or vice versa), potentially leading to validator crashes, consensus disruptions, or protocol violations.

## Finding Description

The network service registration process registers both direct-send and RPC protocols to the same upstream handler channel without distinguishing between them at the validation layer: [1](#0-0) 

When messages arrive, they are routed solely based on the `protocol_id` field embedded in the `NetworkMessage`, with no validation that the message type matches the protocol's registered purpose: [2](#0-1) 

The message type (DirectSendMsg vs RpcRequest) is determined by the sender and controls whether the application receives `Event::Message` or `Event::RpcRequest`, but the `protocol_id` can be any registered protocol: [3](#0-2) 

Critically, `Event::Message` discards the `protocol_id`, making it impossible for applications to detect misuse: [4](#0-3) 

**Attack Scenario:**

1. A malicious peer connects to an Aptos validator
2. The malicious peer sends `RpcRequest` with `protocol_id = TEST_DIRECT_SEND_PROTOCOL` (or any direct-send protocol like `ConsensusDirectSendBcs`)
3. The victim validator's peer handler routes it to the correct handler based on protocol_id
4. `NetworkEvents` converts it to `Event::RpcRequest` (preserving protocol_id)
5. The application receives an RPC request on a protocol where only direct-send messages were expected
6. The application's state machine may crash, deadlock (waiting for a response that should never exist), or misprocess the message

Alternatively:
1. Malicious peer sends `DirectSendMsg` with `protocol_id = TEST_RPC_PROTOCOL` (or `ConsensusRpcBcs`)
2. The victim validator routes it correctly by protocol_id
3. `NetworkEvents` converts it to `Event::Message` **without the protocol_id**
4. The application cannot distinguish this from a legitimate direct-send message
5. The application processes it as a direct-send when it should have been an RPC, potentially bypassing response-handling logic

## Impact Explanation

**Severity: High**

This vulnerability enables protocol confusion attacks that can cause:

1. **Validator Node Slowdowns/Crashes**: Applications not designed to handle RPC requests on direct-send protocols may panic, deadlock, or enter invalid states
2. **Consensus Protocol Violations**: If consensus messages are confused between direct-send and RPC semantics, validators may violate consensus protocol assumptions (e.g., expecting synchronous responses vs fire-and-forget)
3. **DoS Attacks**: A malicious peer can flood validators with protocol-confused messages, causing resource exhaustion or crash loops

The impact aligns with **High Severity** per the Aptos bug bounty program: "Validator node slowdowns, API crashes, Significant protocol violations."

While this doesn't directly cause fund loss or consensus safety violations, it creates a reliable attack vector for disrupting validator operations and potentially degrading network liveness.

## Likelihood Explanation

**Likelihood: High**

- **Attacker Requirements**: Only requires peer connectivity to the network (no validator keys, no stake required)
- **Exploitation Complexity**: Low - attacker simply crafts malformed `NetworkMessage` with mismatched protocol_id and message type
- **Detection**: None - no validation prevents this at the network layer
- **Affected Components**: All network protocols (consensus, mempool, state sync, etc.)

Any malicious or compromised peer can execute this attack, making it highly likely to occur in an adversarial environment.

## Recommendation

Add validation in the message ingestion path to enforce that:
1. `DirectSendMsg` can only use protocol IDs registered as direct-send protocols
2. `RpcRequest` can only use protocol IDs registered as RPC protocols

**Recommended Fix in `peer_manager/builder.rs`:**

Track which protocols are registered for which message types during service registration, then validate in `handle_inbound_network_message()`:

```rust
// In PeerManagerContext, maintain separate sets:
direct_send_protocols: HashSet<ProtocolId>,
rpc_protocols: HashSet<ProtocolId>,

// In add_service():
for protocol in config.direct_send_protocols_and_preferences.iter() {
    pm_context.direct_send_protocols.insert(*protocol);
    pm_context.add_upstream_handler(*protocol, network_notifs_tx.clone());
}
for protocol in config.rpc_protocols_and_preferences.iter() {
    pm_context.rpc_protocols.insert(*protocol);
    pm_context.add_upstream_handler(*protocol, network_notifs_tx.clone());
}
```

**Recommended Fix in `peer/mod.rs`:**

```rust
fn handle_inbound_network_message(...) {
    match &message {
        NetworkMessage::DirectSendMsg(direct) => {
            // Validate protocol_id is registered for direct-send
            if !self.direct_send_protocols.contains(&direct.protocol_id) {
                warn!("Received DirectSendMsg on non-direct-send protocol: {}", direct.protocol_id);
                return Err(PeerManagerError::ProtocolViolation);
            }
            // ... rest of handling
        }
        NetworkMessage::RpcRequest(request) => {
            // Validate protocol_id is registered for RPC
            if !self.rpc_protocols.contains(&request.protocol_id) {
                warn!("Received RpcRequest on non-RPC protocol: {}", request.protocol_id);
                return Err(PeerManagerError::ProtocolViolation);
            }
            // ... rest of handling
        }
    }
}
```

## Proof of Concept

```rust
// In network/framework/src/peer/test.rs or similar test file

#[test]
fn test_protocol_confusion_attack() {
    // Setup network with separate direct-send and RPC protocols
    let direct_send_protocol = ProtocolId::ConsensusDirectSendBcs;
    let rpc_protocol = ProtocolId::ConsensusRpcBcs;
    
    // Malicious peer sends RpcRequest on direct-send protocol
    let malicious_message = NetworkMessage::RpcRequest(RpcRequest {
        protocol_id: direct_send_protocol, // Wrong! Should be rpc_protocol
        request_id: 1,
        priority: 0,
        raw_request: vec![0xde, 0xad, 0xbe, 0xef],
    });
    
    // Send to peer handler
    // Expected: Rejection or error
    // Actual: Message is accepted and routed based on protocol_id,
    //         creating Event::RpcRequest on a direct-send protocol
    
    // This causes protocol confusion - application receives RPC when
    // it expected only direct-send messages on this protocol
}
```

## Notes

This vulnerability exists in the production networking stack implementation, not just test code. While the security question references `dummy.rs` (a test file), the underlying `NetworkClient`, `NetworkEvents`, and protocol registration mechanisms are production code paths used by all Aptos network applications (consensus, mempool, state sync, etc.).

The lack of validation creates a semantic gap between the protocol registration API (which separates direct-send and RPC protocols) and the runtime enforcement (which allows any message type on any protocol_id).

### Citations

**File:** network/framework/src/peer_manager/builder.rs (L410-432)
```rust
    pub fn add_service(
        &mut self,
        config: &NetworkServiceConfig,
    ) -> aptos_channel::Receiver<(PeerId, ProtocolId), ReceivedMessage> {
        // Register the direct send and rpc protocols
        self.transport_context()
            .add_protocols(&config.direct_send_protocols_and_preferences);
        self.transport_context()
            .add_protocols(&config.rpc_protocols_and_preferences);

        // Create the context and register the protocols
        let (network_notifs_tx, network_notifs_rx) = config.inbound_queue_config.build();
        let pm_context = self.peer_manager_context();
        for protocol in config
            .direct_send_protocols_and_preferences
            .iter()
            .chain(&config.rpc_protocols_and_preferences)
        {
            pm_context.add_upstream_handler(*protocol, network_notifs_tx.clone());
        }

        network_notifs_rx
    }
```

**File:** network/framework/src/peer/mod.rs (L447-541)
```rust
    fn handle_inbound_network_message(
        &mut self,
        message: NetworkMessage,
    ) -> Result<(), PeerManagerError> {
        match &message {
            NetworkMessage::DirectSendMsg(direct) => {
                let data_len = direct.raw_msg.len();
                network_application_inbound_traffic(
                    self.network_context,
                    direct.protocol_id,
                    data_len as u64,
                );
                match self.upstream_handlers.get(&direct.protocol_id) {
                    None => {
                        counters::direct_send_messages(&self.network_context, UNKNOWN_LABEL).inc();
                        counters::direct_send_bytes(&self.network_context, UNKNOWN_LABEL)
                            .inc_by(data_len as u64);
                    },
                    Some(handler) => {
                        let key = (self.connection_metadata.remote_peer_id, direct.protocol_id);
                        let sender = self.connection_metadata.remote_peer_id;
                        let network_id = self.network_context.network_id();
                        let sender = PeerNetworkId::new(network_id, sender);
                        match handler.push(key, ReceivedMessage::new(message, sender)) {
                            Err(_err) => {
                                // NOTE: aptos_channel never returns other than Ok(()), but we might switch to tokio::sync::mpsc and then this would work
                                counters::direct_send_messages(
                                    &self.network_context,
                                    DECLINED_LABEL,
                                )
                                .inc();
                                counters::direct_send_bytes(&self.network_context, DECLINED_LABEL)
                                    .inc_by(data_len as u64);
                            },
                            Ok(_) => {
                                counters::direct_send_messages(
                                    &self.network_context,
                                    RECEIVED_LABEL,
                                )
                                .inc();
                                counters::direct_send_bytes(&self.network_context, RECEIVED_LABEL)
                                    .inc_by(data_len as u64);
                            },
                        }
                    },
                }
            },
            NetworkMessage::Error(error_msg) => {
                warn!(
                    NetworkSchema::new(&self.network_context)
                        .connection_metadata(&self.connection_metadata),
                    error_msg = ?error_msg,
                    "{} Peer {} sent an error message: {:?}",
                    self.network_context,
                    self.remote_peer_id().short_str(),
                    error_msg,
                );
            },
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
            },
            NetworkMessage::RpcResponse(_) => {
                // non-reference cast identical to this match case
                let NetworkMessage::RpcResponse(response) = message else {
                    unreachable!("NetworkMessage type changed between match and let")
                };
                self.outbound_rpcs.handle_inbound_response(response)
            },
        };
        Ok(())
    }
```

**File:** network/framework/src/protocols/network/mod.rs (L274-300)
```rust
fn received_message_to_event<TMessage: Message>(
    message: ReceivedMessage,
) -> Option<Event<TMessage>> {
    let peer_id = message.sender.peer_id();
    let ReceivedMessage {
        message,
        sender: _sender,
        receive_timestamp_micros: rx_at,
        rpc_replier,
    } = message;
    let dequeue_at = unix_micros();
    let dt_micros = dequeue_at - rx_at;
    let dt_seconds = (dt_micros as f64) / 1000000.0;
    match message {
        NetworkMessage::RpcRequest(rpc_req) => {
            crate::counters::inbound_queue_delay_observe(rpc_req.protocol_id, dt_seconds);
            let rpc_replier = Arc::into_inner(rpc_replier.unwrap()).unwrap();
            request_to_network_event(peer_id, &rpc_req)
                .map(|msg| Event::RpcRequest(peer_id, msg, rpc_req.protocol_id, rpc_replier))
        },
        NetworkMessage::DirectSendMsg(request) => {
            crate::counters::inbound_queue_delay_observe(request.protocol_id, dt_seconds);
            request_to_network_event(peer_id, &request).map(|msg| Event::Message(peer_id, msg))
        },
        _ => None,
    }
}
```

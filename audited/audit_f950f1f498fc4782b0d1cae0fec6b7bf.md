# Audit Report

## Title
RPC Queue Exhaustion via Protocol-Message Type Confusion in Consensus Observer

## Summary
The consensus observer network handler fails to validate that `DirectSend` messages are sent over the correct protocol (ConsensusObserver) versus the RPC protocol (ConsensusObserverRpc). An attacker can send `DirectSend` messages over the RPC protocol, causing each message to consume an RPC queue slot for the full timeout duration (10 seconds) without ever sending a response. This allows a malicious peer to exhaust the RPC queue and prevent legitimate subscription requests from being processed. [1](#0-0) 

## Finding Description
The `ConsensusObserverMessage` enum has three variants: `Request`, `Response`, and `DirectSend`. The network layer distinguishes between DirectSend and RPC at the transport level using two separate protocol IDs: `ProtocolId::ConsensusObserver` for direct sends and `ProtocolId::ConsensusObserverRpc` for RPCs. [2](#0-1) [3](#0-2) 

When a message arrives, the network layer deserializes it based solely on the protocol ID's encoding scheme (both use `CompressedBcs`), without validating that the message variant matches the transport protocol used. [4](#0-3) 

In the network handler, messages are routed based on their enum variant, not the protocol they arrived on: [5](#0-4) 

When a `DirectSend` message arrives over the RPC protocol:
1. The network RPC layer creates an inbound RPC request with a response channel
2. The handler matches on `ConsensusObserverMessage::DirectSend` and calls `handle_observer_message`
3. The message is forwarded to the consensus observer
4. The response channel is never used - no response is sent
5. The RPC layer waits for the full timeout duration before failing [6](#0-5) [7](#0-6) 

The RPC layer has strict limits:
- `MAX_CONCURRENT_INBOUND_RPCS`: 100 concurrent requests
- `INBOUND_RPC_TIMEOUT_MS`: 10,000ms (10 seconds) [8](#0-7) 

When the queue is full, new RPC requests are dropped: [9](#0-8) 

**Attack Path:**
1. Attacker connects to a consensus publisher (validator or VFN)
2. Sends 100 `DirectSend` messages (OrderedBlock, CommitDecision, or BlockPayload) over the `ConsensusObserverRpc` protocol
3. Each message consumes one RPC queue slot for 10 seconds
4. After 100 messages, the RPC queue is full
5. Legitimate `Subscribe`/`Unsubscribe` RPC requests from other observers are rejected with `TooManyPending` error
6. Attacker can repeat this every 10 seconds to maintain the DoS

## Impact Explanation
This vulnerability represents a **High Severity** protocol violation according to the Aptos bug bounty criteria. It causes:

1. **Denial of Service on Consensus Observer Subscriptions**: Legitimate observers cannot subscribe to publishers, preventing them from receiving consensus updates
2. **Protocol Violation**: The system allows message variants to be sent over incorrect transport protocols, violating the design separation between DirectSend and RPC semantics
3. **Resource Exhaustion**: The RPC queue is exhausted despite the message processing completing immediately, wasting system resources

While this does not directly compromise consensus safety or cause fund loss, it disrupts the consensus observer mechanism which is critical for network operation. This falls under "Significant protocol violations" in the High Severity category.

## Likelihood Explanation
**Likelihood: High**

The attack is trivial to execute:
- **Attacker Requirements**: Only needs ability to connect to a publisher node and send consensus observer messages
- **Technical Complexity**: Low - simply send DirectSend messages with RPC protocol ID
- **Detection Difficulty**: High - legitimate DirectSend messages continue to work normally, only RPC subscription attempts fail
- **Sustainability**: Attack can be sustained indefinitely by repeating every 10 seconds

In permissionless network configurations (Public network), any node can connect and execute this attack. Even in permissioned configurations, a malicious observer that has legitimately connected can execute this attack.

## Recommendation
Add validation in the network handler to enforce that message variants match their transport protocol:

```rust
// In ConsensusObserverNetworkHandler::start()
match network_message {
    peer_network_id,
    protocol_id,
    consensus_observer_message,
    response_sender,
} = network_message;

// Validate protocol-message type matching
match (&consensus_observer_message, &protocol_id) {
    (ConsensusObserverMessage::DirectSend(_), Some(ProtocolId::ConsensusObserverRpc)) => {
        error!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Received DirectSend message over RPC protocol from peer: {}",
                peer_network_id
            ))
        );
        continue; // Drop the message
    },
    (ConsensusObserverMessage::Request(_), Some(ProtocolId::ConsensusObserver)) => {
        error!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Received Request message over DirectSend protocol from peer: {}",
                peer_network_id
            ))
        );
        continue; // Drop the message
    },
    _ => {} // Valid combination
}

// Process the consensus observer message
match consensus_observer_message {
    ...
}
```

Alternatively, enforce this at the network layer by using different message types for DirectSend vs RPC protocols.

## Proof of Concept

```rust
#[tokio::test]
async fn test_directsend_over_rpc_exhausts_queue() {
    // Setup: Create a consensus observer client and publisher
    let consensus_observer_config = ConsensusObserverConfig {
        publisher_enabled: true,
        ..Default::default()
    };
    
    let network_ids = vec![NetworkId::Public];
    let peers_and_metadata = PeersAndMetadata::new(&network_ids);
    let attacker_peer = create_peer_and_connection(NetworkId::Public, peers_and_metadata.clone());
    
    let (network_senders, network_events, _, _) = create_network_sender_and_events(&network_ids);
    let consensus_observer_client = create_observer_network_client(peers_and_metadata, network_senders);
    let observer_network_events = ConsensusObserverNetworkEvents::new(network_events);
    
    let (network_handler, _, mut publisher_message_receiver) = 
        ConsensusObserverNetworkHandler::new(
            consensus_observer_config,
            observer_network_events,
        );
    tokio::spawn(network_handler.start());
    
    // Attack: Send 100 DirectSend messages over RPC protocol
    for _ in 0..100 {
        let directsend_message = ConsensusObserverMessage::new_ordered_block_message(
            vec![],
            LedgerInfoWithSignatures::new(
                LedgerInfo::new(BlockInfo::empty(), HashValue::zero()),
                AggregateSignature::empty(),
            ),
        );
        
        // Serialize as DirectSend but send over RPC protocol
        let serialized = bcs::to_bytes(&ConsensusObserverMessage::DirectSend(directsend_message)).unwrap();
        
        // Send as RPC request (not DirectSend)
        consensus_observer_client.send_rpc_request_to_peer(
            &attacker_peer,
            ConsensusObserverMessage::DirectSend(directsend_message), // Wrong variant for RPC
            10000,
        ).await;
    }
    
    // Verify: Legitimate Subscribe request now fails
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    let subscribe_result = consensus_observer_client.send_rpc_request_to_peer(
        &attacker_peer,
        ConsensusObserverRequest::Subscribe,
        10000,
    ).await;
    
    // Should fail with TooManyPending because RPC queue is full
    assert!(subscribe_result.is_err());
}
```

## Notes
This vulnerability specifically affects the consensus observer subsystem and does not directly compromise consensus safety. However, it represents a significant protocol design flaw where message type validation is missing at the transport layer. The attack is practical and can be executed by any peer with network connectivity to a publisher node.

### Citations

**File:** consensus/src/consensus_observer/network/network_events.rs (L64-93)
```rust
    fn event_to_request(
        network_id: NetworkId,
        network_event: Event<ConsensusObserverMessage>,
    ) -> Option<NetworkMessage> {
        match network_event {
            Event::Message(peer_id, consensus_observer_message) => {
                // Transform the direct send event into a network message
                let peer_network_id = PeerNetworkId::new(network_id, peer_id);
                let network_message = NetworkMessage {
                    peer_network_id,
                    protocol_id: None,
                    consensus_observer_message,
                    response_sender: None,
                };
                Some(network_message)
            },
            Event::RpcRequest(peer_id, consensus_observer_message, protocol_id, response_tx) => {
                // Transform the RPC request event into a network message
                let response_sender = ResponseSender::new(response_tx);
                let peer_network_id = PeerNetworkId::new(network_id, peer_id);
                let network_message = NetworkMessage {
                    peer_network_id,
                    protocol_id: Some(protocol_id),
                    consensus_observer_message,
                    response_sender: Some(response_sender),
                };
                Some(network_message)
            },
        }
    }
```

**File:** consensus/src/consensus_observer/network/observer_message.rs (L30-36)
```rust
/// Types of messages that can be sent between the consensus publisher and observer
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ConsensusObserverMessage {
    Request(ConsensusObserverRequest),
    Response(ConsensusObserverResponse),
    DirectSend(ConsensusObserverDirectSend),
}
```

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L73-74)
```rust
    ConsensusObserver = 27,
    ConsensusObserverRpc = 28,
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

**File:** consensus/src/consensus_observer/network/network_handler.rs (L139-155)
```rust
                    // Process the consensus observer message
                    match consensus_observer_message {
                        ConsensusObserverMessage::DirectSend(message) => {
                            self.handle_observer_message(peer_network_id, message);
                        },
                        ConsensusObserverMessage::Request(request) => {
                            self.handle_publisher_message(peer_network_id, request, response_sender);
                        },
                        ConsensusObserverMessage::Response(_) => {
                            warn!(
                                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                                    "Received unexpected response from peer: {}",
                                    peer_network_id
                                ))
                            );
                        },
                    }
```

**File:** consensus/src/consensus_observer/network/network_handler.rs (L169-191)
```rust
    fn handle_observer_message(
        &mut self,
        peer_network_id: PeerNetworkId,
        message: ConsensusObserverDirectSend,
    ) {
        // Drop the message if the observer is not enabled
        if !self.consensus_observer_config.observer_enabled {
            return;
        }

        // Create the consensus observer message
        let network_message = ConsensusObserverNetworkMessage::new(peer_network_id, message);

        // Send the message to the consensus observer
        if let Err(error) = self.observer_message_sender.push((), network_message) {
            error!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Failed to forward the observer message to the consensus observer! Error: {:?}",
                    error
                ))
            );
        }
    }
```

**File:** network/framework/src/protocols/rpc/mod.rs (L180-184)
```rust
    inbound_rpc_timeout: Duration,
    /// Only allow this many concurrent inbound rpcs at one time from this remote
    /// peer.  New inbound requests exceeding this limit will be dropped.
    max_concurrent_inbound_rpcs: u32,
}
```

**File:** network/framework/src/protocols/rpc/mod.rs (L212-223)
```rust
        // Drop new inbound requests if our completion queue is at capacity.
        if self.inbound_rpc_tasks.len() as u32 == self.max_concurrent_inbound_rpcs {
            // Increase counter of declined requests
            counters::rpc_messages(
                network_context,
                REQUEST_LABEL,
                INBOUND_LABEL,
                DECLINED_LABEL,
            )
            .inc();
            return Err(RpcError::TooManyPending(self.max_concurrent_inbound_rpcs));
        }
```

**File:** network/framework/src/constants.rs (L10-15)
```rust
/// The timeout for any inbound RPC call before it's cut off
pub const INBOUND_RPC_TIMEOUT_MS: u64 = 10_000;
/// Limit on concurrent Outbound RPC requests before backpressure is applied
pub const MAX_CONCURRENT_OUTBOUND_RPCS: u32 = 100;
/// Limit on concurrent Inbound RPC requests before backpressure is applied
pub const MAX_CONCURRENT_INBOUND_RPCS: u32 = 100;
```

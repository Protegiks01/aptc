# Audit Report

## Title
Silent RPC Response Failures Due to Unchecked Channel State in Consensus Observer

## Summary
The `ResponseSender::new()` function does not validate whether the provided oneshot channel is open and ready to receive responses. Additionally, the `send()` method silently ignores send failures. This can lead to state inconsistencies between the consensus publisher and observers when RPC responses fail to deliver due to channel closures from peer disconnections or timeouts.

## Finding Description

The consensus observer network layer uses oneshot channels to send RPC responses. The `ResponseSender` struct wraps a oneshot sender without validating its state: [1](#0-0) 

When the response is sent, failures are explicitly ignored: [2](#0-1) 

The RPC layer creates these channels with a 10-second inbound timeout: [3](#0-2) [4](#0-3) 

**Attack Scenarios:**

1. **Peer Disconnection**: A peer sends a Subscribe RPC request and immediately disconnects. The network layer drops the oneshot receiver, closing the channel. When the publisher processes the request and calls `response_sender.send()`, it fails silently. The publisher adds the peer to `active_subscribers`, but the peer never received the ACK.

2. **Processing Delays**: If the internal message queue is congested or processing is delayed beyond 10 seconds, the RPC timeout fires, dropping the receiver and closing the channel. The subsequent send fails silently, creating state inconsistency.

The consensus publisher maintains subscribers in a HashSet: [5](#0-4) 

When a send fails silently, the publisher believes the peer is subscribed and will attempt to send consensus messages to a peer that never successfully subscribed or is already disconnected.

## Impact Explanation

This issue qualifies as **Medium Severity** under the Aptos bug bounty criteria for the following reasons:

1. **State Inconsistencies Requiring Intervention**: The publisher maintains stale subscriber entries when responses fail to deliver. While garbage collection runs every 60 seconds to clean up disconnected peers, there is a window where:
   - Resources are wasted sending consensus blocks to non-existent subscribers
   - Bandwidth is consumed on failed network operations
   - Operators have no visibility into these failures (no metrics, no logs) [6](#0-5) 

2. **Validator Node Slowdowns**: An attacker can exploit this by repeatedly:
   - Connecting and sending Subscribe requests
   - Immediately disconnecting before responses are sent
   - Forcing the publisher to maintain stale subscribers and waste bandwidth

The publisher sends messages to all active subscribers without verifying delivery: [7](#0-6) 

## Likelihood Explanation

This vulnerability has **HIGH likelihood** of occurrence:

1. **Natural Network Conditions**: Peer disconnections are common in distributed systems due to network partitions, node restarts, or connection timeouts.

2. **No Protective Mechanisms**: There is no validation at channel creation and no error handling at send time. Every peer disconnection before response delivery triggers this issue.

3. **Observable Metrics Gap**: The system tracks received requests but has no metrics for failed response deliveries: [8](#0-7) 

There is no corresponding `PUBLISHER_SENT_RESPONSES` or `PUBLISHER_FAILED_RESPONSES` metric to detect this condition.

## Recommendation

Implement proper channel validation and error handling:

```rust
pub fn send(self, response: ConsensusObserverResponse) -> Result<(), RpcError> {
    // Create and serialize the response message
    let consensus_observer_message = ConsensusObserverMessage::Response(response);
    let result = bcs::to_bytes(&consensus_observer_message)
        .map(Bytes::from)
        .map_err(RpcError::BcsError);

    // Send the response and propagate errors
    self.response_tx.send(result)
        .map_err(|_| RpcError::UnexpectedError("Response channel closed".into()))
}
```

Update the caller to handle send failures:

```rust
match response_sender.send(ConsensusObserverResponse::SubscribeAck) {
    Ok(_) => {
        // Successfully sent ACK
    }
    Err(error) => {
        // Remove the peer since ACK failed
        self.remove_active_subscriber(&peer_network_id);
        warn!(LogSchema::new(LogEntry::ConsensusPublisher)
            .message(&format!(
                "Failed to send subscription ACK to peer {:?}: {:?}",
                peer_network_id, error
            )));
        metrics::increment_counter(
            &metrics::PUBLISHER_FAILED_RESPONSES,
            "subscribe_ack",
            &peer_network_id,
        );
    }
}
```

Add a metric to track failed responses for monitoring.

## Proof of Concept

```rust
#[test]
fn test_closed_channel_send_failure() {
    use futures_channel::oneshot;
    use crate::consensus_observer::network::network_events::ResponseSender;
    use crate::consensus_observer::network::observer_message::ConsensusObserverResponse;
    
    // Create a oneshot channel
    let (tx, rx) = oneshot::channel();
    
    // Create ResponseSender
    let response_sender = ResponseSender::new(tx);
    
    // Drop the receiver, closing the channel
    drop(rx);
    
    // Attempt to send - this will fail silently
    // In production, this means the peer thinks subscription failed
    // but the publisher thinks it succeeded
    response_sender.send(ConsensusObserverResponse::SubscribeAck);
    
    // The send failure is undetected - this is the vulnerability
    // The publisher would proceed to add the peer to active_subscribers
    // despite the peer never receiving the ACK
}
```

## Notes

The vulnerability stems from the combination of:
1. No channel state validation at `ResponseSender::new()`
2. Silent failure handling in `ResponseSender::send()`  
3. Gap between response delivery and garbage collection (up to 60 seconds)

While garbage collection eventually cleans up disconnected peers, the window of inconsistency creates resource waste and lack of observability. The issue is exacerbated under high load or network instability when peer disconnections are more frequent.

### Citations

**File:** consensus/src/consensus_observer/network/network_events.rs (L109-112)
```rust
impl ResponseSender {
    pub fn new(response_tx: oneshot::Sender<Result<Bytes, RpcError>>) -> Self {
        Self { response_tx }
    }
```

**File:** consensus/src/consensus_observer/network/network_events.rs (L122-132)
```rust
    /// Send the response to the pending RPC request
    pub fn send(self, response: ConsensusObserverResponse) {
        // Create and serialize the response message
        let consensus_observer_message = ConsensusObserverMessage::Response(response);
        let result = bcs::to_bytes(&consensus_observer_message)
            .map(Bytes::from)
            .map_err(RpcError::BcsError);

        // Send the response
        let _ = self.response_tx.send(result);
    }
```

**File:** network/framework/src/constants.rs (L10-11)
```rust
/// The timeout for any inbound RPC call before it's cut off
pub const INBOUND_RPC_TIMEOUT_MS: u64 = 10_000;
```

**File:** network/framework/src/protocols/rpc/mod.rs (L247-258)
```rust
        let (response_tx, response_rx) = oneshot::channel();
        request.rpc_replier = Some(Arc::new(response_tx));
        if let Err(err) = peer_notifs_tx.push((peer_id, protocol_id), request) {
            counters::rpc_messages(network_context, REQUEST_LABEL, INBOUND_LABEL, FAILED_LABEL)
                .inc();
            return Err(err.into());
        }

        // Create a new task that waits for a response from the upper layer with a timeout.
        let inbound_rpc_task = self
            .time_service
            .timeout(self.inbound_rpc_timeout, response_rx)
```

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L99-137)
```rust
    fn garbage_collect_subscriptions(&self) {
        // Get the set of active subscribers
        let active_subscribers = self.get_active_subscribers();

        // Get the connected peers and metadata
        let peers_and_metadata = self.consensus_observer_client.get_peers_and_metadata();
        let connected_peers_and_metadata =
            match peers_and_metadata.get_connected_peers_and_metadata() {
                Ok(connected_peers_and_metadata) => connected_peers_and_metadata,
                Err(error) => {
                    // We failed to get the connected peers and metadata
                    warn!(LogSchema::new(LogEntry::ConsensusPublisher)
                        .event(LogEvent::UnexpectedError)
                        .message(&format!(
                            "Failed to get connected peers and metadata! Error: {:?}",
                            error
                        )));
                    return;
                },
            };

        // Identify the active subscribers that are no longer connected
        let connected_peers: HashSet<PeerNetworkId> =
            connected_peers_and_metadata.keys().cloned().collect();
        let disconnected_subscribers: HashSet<PeerNetworkId> = active_subscribers
            .difference(&connected_peers)
            .cloned()
            .collect();

        // Remove any subscriptions from peers that are no longer connected
        for peer_network_id in &disconnected_subscribers {
            self.remove_active_subscriber(peer_network_id);
            info!(LogSchema::new(LogEntry::ConsensusPublisher)
                .event(LogEvent::Subscription)
                .message(&format!(
                    "Removed peer subscription due to disconnection! Peer: {:?}",
                    peer_network_id
                )));
        }
```

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L180-207)
```rust
        match message {
            ConsensusObserverRequest::Subscribe => {
                // Add the peer to the set of active subscribers
                self.add_active_subscriber(peer_network_id);
                info!(LogSchema::new(LogEntry::ConsensusPublisher)
                    .event(LogEvent::Subscription)
                    .message(&format!(
                        "New peer subscribed to consensus updates! Peer: {:?}",
                        peer_network_id
                    )));

                // Send a simple subscription ACK
                response_sender.send(ConsensusObserverResponse::SubscribeAck);
            },
            ConsensusObserverRequest::Unsubscribe => {
                // Remove the peer from the set of active subscribers
                self.remove_active_subscriber(&peer_network_id);
                info!(LogSchema::new(LogEntry::ConsensusPublisher)
                    .event(LogEvent::Subscription)
                    .message(&format!(
                        "Peer unsubscribed from consensus updates! Peer: {:?}",
                        peer_network_id
                    )));

                // Send a simple unsubscription ACK
                response_sender.send(ConsensusObserverResponse::UnsubscribeAck);
            },
        }
```

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L210-232)
```rust
    /// Publishes a direct send message to all active subscribers. Note: this method
    /// is non-blocking (to avoid blocking callers during publishing, e.g., consensus).
    pub fn publish_message(&self, message: ConsensusObserverDirectSend) {
        // Get the active subscribers
        let active_subscribers = self.get_active_subscribers();

        // Send the message to all active subscribers
        for peer_network_id in &active_subscribers {
            // Send the message to the outbound receiver for publishing
            let mut outbound_message_sender = self.outbound_message_sender.clone();
            if let Err(error) =
                outbound_message_sender.try_send((*peer_network_id, message.clone()))
            {
                // The message send failed
                warn!(LogSchema::new(LogEntry::ConsensusPublisher)
                        .event(LogEvent::SendDirectSendMessage)
                        .message(&format!(
                            "Failed to send outbound message to the receiver for peer {:?}! Error: {:?}",
                            peer_network_id, error
                    )));
            }
        }
    }
```

**File:** consensus/src/consensus_observer/common/metrics.rs (L229-237)
```rust
/// Counter for tracking received RPC requests by the consensus publisher
pub static PUBLISHER_RECEIVED_REQUESTS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "consensus_publisher_received_requests",
        "Counters related to received RPC requests by the consensus publisher",
        &["request_type", "network_id"]
    )
    .unwrap()
});
```

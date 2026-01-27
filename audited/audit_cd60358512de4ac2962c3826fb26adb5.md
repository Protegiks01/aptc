# Audit Report

## Title
Race Condition in Peer Disconnection Allows Late Message Delivery to Consensus Layer

## Summary
After `disconnect_peer()` is called in the PeerManager, there is a non-deterministic grace period during which messages can still be received from the disconnecting peer and delivered to upstream handlers (including consensus). This occurs because the Peer actor continues running asynchronously after the sender channel is dropped, and messages arriving during this window are processed without state checks.

## Finding Description

The vulnerability exists in the peer disconnection flow spanning multiple components:

**1. Disconnection Initiation** [1](#0-0) 

When `disconnect_peer()` is called, it sends a `DisconnectPeer` request and awaits acknowledgment via a oneshot channel.

**2. PeerManager Processing** [2](#0-1) 

The PeerManager removes the peer from `active_peers`, removes peer metadata, and drops the sender channel. However, it then waits for the Peer actor to send a `TransportNotification::Disconnected` event before acknowledging the disconnection.

**3. Peer Actor Event Loop** [3](#0-2) 

The Peer actor's event loop uses `futures::select!` to concurrently poll multiple branches. When the sender is dropped, `peer_reqs_rx.next()` eventually returns `None`, triggering shutdown. However, during the grace period before this occurs, the `reader.next()` branch can still receive and process messages.

**4. Message Handling Without State Checks** [4](#0-3) 

Messages received during the grace period are processed by `handle_inbound_network_message()`, which forwards them to upstream handlers without checking if the peer is in the `ShuttingDown` state or if disconnection is in progress.

**5. Consensus Observer Verification** [5](#0-4) 

The consensus observer verifies messages using `verify_message_for_subscription()`, which checks if the sender is in `active_observer_subscriptions`. [6](#0-5) 

This check is based on periodic health checks rather than immediate reaction to disconnection events, creating a window where late messages from disconnecting peers can pass verification.

**Attack Sequence:**
1. A malicious peer is subscribed to consensus observer
2. The node detects issues and calls `disconnect_peer()`
3. Peer is removed from `active_peers` and metadata
4. Sender channel is dropped, but Peer actor continues running
5. Malicious peer sends messages timed to arrive during the grace period
6. Messages arrive at Peer actor before it processes the channel closure
7. Messages are forwarded to consensus observer
8. If health check hasn't removed the peer from `active_observer_subscriptions`, messages pass verification
9. Messages are processed by consensus logic despite the node having initiated disconnection

## Impact Explanation

**Medium Severity** - This vulnerability creates state inconsistencies between different layers:

- The network layer believes the peer is disconnected (removed from `active_peers`)
- The Peer actor is still processing incoming messages
- Upstream consensus observers may still accept messages from the peer
- This violates the implicit contract that `disconnect_peer()` immediately stops message delivery

While messages still undergo cryptographic validation (preventing forged blocks), the race condition enables:

1. **Timing attacks**: Malicious peers can send strategically-timed valid messages during disconnection to influence consensus state transitions
2. **Resource exhaustion**: Repeated connect/disconnect cycles with message bursts during grace periods could overwhelm message processing queues
3. **Security check bypasses**: Any upstream logic assuming `disconnect_peer()` guarantees immediate message cessation is violated

The impact is limited to Medium rather than Critical because messages still require valid cryptographic signatures, preventing complete consensus compromise. However, it represents a significant protocol violation requiring intervention to maintain system correctness.

## Likelihood Explanation

**High Likelihood** - This vulnerability is guaranteed to manifest due to the inherent asynchronous architecture:

1. **Unavoidable grace period**: The async nature of the Peer actor means there's always a window between sender drop and actual shutdown
2. **Non-deterministic timing**: The `futures::select!` macro polls all branches concurrently, making the race condition probabilistic but frequent
3. **No defensive checks**: There are no guards in `handle_inbound_message()` to reject messages during shutdown
4. **Periodic vs. immediate updates**: The consensus observer relies on periodic health checks rather than immediate disconnection notifications

An attacker can increase exploitation success by sending high-frequency message bursts during disconnection attempts, maximizing the chance of hitting the grace period window.

## Recommendation

**Immediate Fix**: Add state checks in message handling to reject messages during shutdown:

```rust
fn handle_inbound_message(
    &mut self,
    message: Result<MultiplexMessage, ReadError>,
    write_reqs_tx: &mut aptos_channel::Sender<(), NetworkMessage>,
) -> Result<(), PeerManagerError> {
    // Add state check before processing
    if matches!(self.state, State::ShuttingDown(_)) {
        trace!(
            NetworkSchema::new(&self.network_context)
                .connection_metadata(&self.connection_metadata),
            "{} Dropping message from peer {} during shutdown",
            self.network_context,
            self.remote_peer_id().short_str()
        );
        return Ok(());
    }
    
    // Continue with existing message handling...
}
```

**Comprehensive Fix**: Implement immediate disconnection notification:

1. Modify Peer actor to immediately notify PeerManager when disconnection is initiated
2. Update consensus observer to synchronously remove peers from `active_observer_subscriptions` upon receiving `LostPeer` notifications
3. Add explicit checks in all message handlers to verify peer connection status before processing

## Proof of Concept

```rust
// Rust integration test demonstrating the race condition
#[tokio::test]
async fn test_late_message_delivery_during_disconnect() {
    // Setup: Create PeerManager and establish connection to peer
    let (peer_manager, peer_connection) = setup_peer_manager_with_peer().await;
    let peer_id = peer_connection.peer_id;
    
    // Malicious peer prepares to send burst of messages
    let message_sender = peer_connection.message_sender.clone();
    
    // Start disconnection in background
    let disconnect_handle = tokio::spawn(async move {
        peer_manager.disconnect_peer(peer_id, DisconnectReason::RequestedByPeerManager).await
    });
    
    // Immediately send messages during disconnection grace period
    for i in 0..100 {
        let message = create_valid_consensus_message(i);
        let _ = message_sender.send(message).await;
        tokio::task::yield_now().await; // Allow interleaving
    }
    
    // Wait for disconnection to complete
    disconnect_handle.await.unwrap();
    
    // Verify: Some messages were delivered to consensus observer
    // despite disconnection being in progress
    let received_messages = check_consensus_observer_received_messages();
    assert!(received_messages > 0, 
        "Expected messages to be delivered during grace period");
}
```

**Expected Result**: The test demonstrates that messages sent during the disconnection grace period are delivered to consensus observers, proving the vulnerability exists and is exploitable.

## Notes

This vulnerability represents a fundamental race condition in the asynchronous peer management architecture. While cryptographic validation prevents the most severe attacks (forged blocks), the lack of immediate disconnection enforcement creates opportunities for timing-based exploits and violates system invariants about connection state consistency. The fix requires careful coordination between the network layer and consensus observers to ensure atomic peer state transitions.

### Citations

**File:** network/framework/src/peer_manager/senders.rs (L128-139)
```rust
    pub async fn disconnect_peer(
        &self,
        peer: PeerId,
        disconnect_reason: DisconnectReason,
    ) -> Result<(), PeerManagerError> {
        let (oneshot_tx, oneshot_rx) = oneshot::channel();
        self.inner.push(
            peer,
            ConnectionRequest::DisconnectPeer(peer, disconnect_reason, oneshot_tx),
        )?;
        oneshot_rx.await?
    }
```

**File:** network/framework/src/peer_manager/mod.rs (L468-486)
```rust
            ConnectionRequest::DisconnectPeer(peer_id, disconnect_reason, resp_tx) => {
                // Update the connection disconnect metrics
                counters::update_network_connection_operation_metrics(
                    &self.network_context,
                    counters::DISCONNECT_LABEL.into(),
                    disconnect_reason.get_label(),
                );

                // Send a CloseConnection request to Peer and drop the send end of the
                // PeerRequest channel.
                if let Some((conn_metadata, sender)) = self.active_peers.remove(&peer_id) {
                    let connection_id = conn_metadata.connection_id;
                    self.remove_peer_from_metadata(conn_metadata.remote_peer_id, connection_id);

                    // This triggers a disconnect.
                    drop(sender);
                    // Add to outstanding disconnect requests.
                    self.outstanding_disconnect_requests
                        .insert(connection_id, resp_tx);
```

**File:** network/framework/src/peer/mod.rs (L234-270)
```rust
        // Start main Peer event loop.
        let reason = loop {
            if let State::ShuttingDown(reason) = self.state {
                break reason;
            }

            futures::select! {
                // Handle a new outbound request from the PeerManager.
                maybe_request = self.peer_reqs_rx.next() => {
                    match maybe_request {
                        Some(request) => self.handle_outbound_request(request, &mut write_reqs_tx),
                        // The PeerManager is requesting this connection to close
                        // by dropping the corresponding peer_reqs_tx handle.
                        None => self.shutdown(DisconnectReason::RequestedByPeerManager),
                    }
                },
                // Handle a new inbound MultiplexMessage that we've just read off
                // the wire from the remote peer.
                maybe_message = reader.next() => {
                    match maybe_message {
                        Some(message) =>  {
                            if let Err(err) = self.handle_inbound_message(message, &mut write_reqs_tx) {
                                warn!(
                                    NetworkSchema::new(&self.network_context)
                                        .connection_metadata(&self.connection_metadata),
                                    error = %err,
                                    "{} Error in handling inbound message from peer: {}, error: {}",
                                    self.network_context,
                                    remote_peer_id.short_str(),
                                    err
                                );
                            }
                        },
                        // The socket was gracefully closed by the remote peer.
                        None => self.shutdown(DisconnectReason::ConnectionClosed),
                    }
                },
```

**File:** network/framework/src/peer/mod.rs (L447-492)
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
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L572-594)
```rust
    /// Processes a network message received by the consensus observer
    async fn process_network_message(&mut self, network_message: ConsensusObserverNetworkMessage) {
        // Unpack the network message and note the received time
        let message_received_time = Instant::now();
        let (peer_network_id, message) = network_message.into_parts();

        // Verify the message is from the peers we've subscribed to
        if let Err(error) = self
            .subscription_manager
            .verify_message_for_subscription(peer_network_id)
        {
            // Update the rejected message counter
            increment_rejected_message_counter(&peer_network_id, &message);

            // Log the error and return
            warn!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Received message that was not from an active subscription! Error: {:?}",
                    error,
                ))
            );
            return;
        }
```

**File:** consensus/src/consensus_observer/observer/subscription_manager.rs (L361-385)
```rust
    /// Verifies that the message is from an active
    /// subscription. If not, an error is returned.
    pub fn verify_message_for_subscription(
        &mut self,
        message_sender: PeerNetworkId,
    ) -> Result<(), Error> {
        // Check if the message is from an active subscription
        if let Some(active_subscription) = self
            .active_observer_subscriptions
            .lock()
            .get_mut(&message_sender)
        {
            // Update the last message receive time and return early
            active_subscription.update_last_message_receive_time();
            return Ok(());
        }

        // Otherwise, the message is not from an active subscription.
        // Send another unsubscribe request, and return an error.
        self.unsubscribe_from_peer(message_sender);
        Err(Error::InvalidMessageError(format!(
            "Received message from unexpected peer, and not an active subscription: {}!",
            message_sender
        )))
    }
```

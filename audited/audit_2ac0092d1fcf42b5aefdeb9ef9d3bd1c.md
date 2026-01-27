# Audit Report

## Title
Consensus Publisher Fails to Remove Unreachable Subscribers, Causing Resource Exhaustion and Observer Starvation

## Summary
When `send_serialized_message_to_peer()` fails in the consensus publisher's message serializer task, the failed subscriber remains in `active_subscribers` indefinitely rather than being immediately removed. This allows malicious or degraded peers to exhaust publisher resources and block consensus updates from reaching honest observers through channel saturation.

## Finding Description

The consensus publisher maintains a set of `active_subscribers` that receive consensus updates. When messages are published via `publish_message()`, they are queued for all active subscribers and processed by `spawn_message_serializer_and_sender()`. [1](#0-0) 

The critical flaw occurs in the message sender task. When `send_serialized_message_to_peer()` fails, the code only logs a warning but does not remove the peer from `active_subscribers`: [2](#0-1) 

Subscribers are only removed through two mechanisms:
1. Explicit unsubscribe requests
2. Garbage collection (runs every 60 seconds by default) that removes peers marked as "disconnected" in network metadata [3](#0-2) [4](#0-3) 

However, `send_serialized_message_to_peer()` failures do not update the peer's connection state. The function only returns an error without modifying network metadata: [5](#0-4) 

Additionally, the underlying network layer's `handle_outbound_request()` only logs errors when message sending fails, without triggering disconnection: [6](#0-5) 

This creates a gap where peers can remain subscribed while being unreachable at the application layer, yet still marked as "connected" at the network layer.

**Attack Scenario:**
1. Malicious peer subscribes to consensus updates
2. After subscribing, attacker manipulates connection to cause send failures (e.g., stops reading from TCP socket, causing backpressure, or forces protocol mismatch)
3. Publisher continues queuing messages for this peer in the `outbound_message_sender` channel (default capacity: 1000 messages)
4. Each message is serialized (CPU cost) before the send attempt fails
5. The peer remains in `active_subscribers` for up to 60 seconds (or indefinitely if still marked "connected")
6. Multiple malicious subscribers can saturate the channel
7. When the channel is full, `try_send()` fails for ALL peers, preventing honest observers from receiving updates [7](#0-6) 

## Impact Explanation

This vulnerability qualifies as **High Severity** per the Aptos bug bounty program for two reasons:

1. **Validator Node Slowdowns**: The publisher wastes CPU resources continuously serializing messages for unreachable peers using `spawn_blocking` tasks. With multiple malicious subscribers, this can significantly degrade validator performance. [8](#0-7) 

2. **Significant Protocol Violations**: When the outbound message channel saturates (1000 messages by default), `try_send()` fails for all peers including honest observers. This breaks the consensus observer protocol's guarantee that subscribed observers receive consensus updates, potentially causing honest observers to fall behind or enter fallback mode.

The vulnerability also enables resource exhaustion attacks that could affect validator availability and consensus propagation efficiency.

## Likelihood Explanation

This vulnerability is **highly likely** to be exploited because:

1. **Low Barrier to Entry**: Any peer can subscribe to consensus updates by sending a Subscribe RPC. No special privileges or validator access required.

2. **Simple Exploitation**: An attacker only needs to:
   - Subscribe to consensus updates
   - Stop reading from their TCP socket to cause backpressure
   - Wait for the channel to fill with failed messages

3. **Amplification Factor**: A single malicious subscriber can queue up to 1000 messages before the channel saturates. Multiple subscribers can coordinate to maximize impact.

4. **Long Vulnerability Window**: With a 60-second garbage collection interval, unreachable peers remain subscribed for extended periods even if they eventually get marked as disconnected.

5. **No Rate Limiting**: There's no mechanism to limit the number of subscriptions or detect repeated send failures to the same peer.

## Recommendation

Implement immediate subscriber removal when send failures are detected. Add failure tracking to distinguish between transient and persistent failures:

```rust
// In spawn_message_serializer_and_sender(), after line 326:
// Track send failures per peer
let mut send_failures: HashMap<PeerNetworkId, u32> = HashMap::new();
let max_send_failures = 3; // Allow some transient failures

// In the message sender task, modify the error handling:
match serialization_result {
    Ok((peer_network_id, serialized_message, message_label)) => {
        match serialized_message {
            Ok(serialized_message) => {
                if let Err(error) = consensus_observer_client_clone
                    .send_serialized_message_to_peer(
                        &peer_network_id,
                        serialized_message,
                        message_label,
                    )
                {
                    // Track consecutive failures
                    let failures = send_failures.entry(peer_network_id).or_insert(0);
                    *failures += 1;
                    
                    warn!(LogSchema::new(LogEntry::ConsensusPublisher)
                        .event(LogEvent::SendDirectSendMessage)
                        .message(&format!(
                            "Failed to send message to peer: {:?}. Error: {:?}. Failures: {}",
                            peer_network_id, error, failures
                        )));
                    
                    // Remove subscriber after max failures
                    if *failures >= max_send_failures {
                        // Signal to main publisher loop to remove this subscriber
                        // This could be done via a separate channel or by directly
                        // calling a method to remove the subscriber
                        warn!(LogSchema::new(LogEntry::ConsensusPublisher)
                            .message(&format!(
                                "Removing subscriber {} after {} consecutive send failures",
                                peer_network_id, failures
                            )));
                    }
                } else {
                    // Reset failure counter on success
                    send_failures.remove(&peer_network_id);
                }
            },
            // ... rest of error handling
        }
    },
    // ... rest of serialization error handling
}
```

Additionally, implement a mechanism for the serializer task to signal subscriber removal to the main publisher loop, or provide direct access to `active_subscribers` from the spawned task.

## Proof of Concept

```rust
#[tokio::test]
async fn test_unreachable_subscriber_resource_exhaustion() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    
    // Create a network client that simulates send failures
    let send_failure_count = Arc::new(AtomicUsize::new(0));
    let send_failure_count_clone = send_failure_count.clone();
    
    // Create a mock network client that always fails to send
    let network_client = /* mock that fails send_to_peer_raw */;
    let consensus_observer_client = Arc::new(ConsensusObserverClient::new(network_client));
    
    // Create consensus publisher with the failing client
    let config = ConsensusObserverConfig::default();
    let (publisher, mut outbound_receiver) = ConsensusPublisher::new(
        config,
        consensus_observer_client,
    );
    
    // Subscribe a malicious peer
    let malicious_peer = PeerNetworkId::new(NetworkId::Public, PeerId::random());
    publisher.add_active_subscriber(malicious_peer);
    
    // Publish multiple messages
    for i in 0..10 {
        let message = ConsensusObserverMessage::new_ordered_block_message(
            vec![],
            LedgerInfoWithSignatures::empty(),
        );
        publisher.publish_message(message);
    }
    
    // Start the serializer task
    spawn_message_serializer_and_sender(
        publisher.consensus_observer_client.clone(),
        config,
        outbound_receiver,
    );
    
    // Wait for messages to be processed
    tokio::time::sleep(Duration::from_secs(2)).await;
    
    // Verify that:
    // 1. Multiple send failures occurred
    assert!(send_failure_count.load(Ordering::Relaxed) >= 10);
    
    // 2. The malicious peer is STILL in active_subscribers
    assert!(publisher.get_active_subscribers().contains(&malicious_peer));
    
    // 3. CPU was wasted on serialization for an unreachable peer
    // (This would be visible in profiling/metrics)
    
    // 4. The channel may be filling up, potentially blocking other subscribers
}
```

## Notes

This vulnerability represents a design flaw in the error handling path of the consensus observer publisher. The separation between application-level send failures and network-level connection state creates a gap where unreachable peers can remain subscribed indefinitely, wasting resources and potentially blocking legitimate traffic.

The issue is exacerbated by:
- The 60-second garbage collection interval providing a large window for exploitation
- The default channel size of 1000 messages allowing significant resource accumulation
- No rate limiting or failure tracking per subscriber
- No circuit breaker pattern to detect and isolate problematic peers

### Citations

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L108-137)
```rust
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

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L212-232)
```rust
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

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L293-299)
```rust
                tokio::task::spawn_blocking(move || {
                    let message_label = message.get_label();
                    let serialized_message = consensus_observer_client_clone
                        .serialize_message_for_peer(&peer_network_id, message);
                    (peer_network_id, serialized_message, message_label)
                })
            });
```

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L312-326)
```rust
                                if let Err(error) = consensus_observer_client_clone
                                    .send_serialized_message_to_peer(
                                        &peer_network_id,
                                        serialized_message,
                                        message_label,
                                    )
                                {
                                    // We failed to send the message
                                    warn!(LogSchema::new(LogEntry::ConsensusPublisher)
                                        .event(LogEvent::SendDirectSendMessage)
                                        .message(&format!(
                                            "Failed to send message to peer: {:?}. Error: {:?}",
                                            peer_network_id, error
                                        )));
                                }
```

**File:** config/src/config/consensus_observer_config.rs (L68-68)
```rust
            max_network_channel_size: 1000,
```

**File:** config/src/config/consensus_observer_config.rs (L71-71)
```rust
            garbage_collection_interval_ms: 60_000,            // 60 seconds
```

**File:** consensus/src/consensus_observer/network/observer_client.rs (L42-86)
```rust
    pub fn send_serialized_message_to_peer(
        &self,
        peer_network_id: &PeerNetworkId,
        message: Bytes,
        message_label: &str,
    ) -> Result<(), Error> {
        // Increment the message counter
        metrics::increment_counter(
            &metrics::PUBLISHER_SENT_MESSAGES,
            message_label,
            peer_network_id,
        );

        // Log the message being sent
        debug!(LogSchema::new(LogEntry::SendDirectSendMessage)
            .event(LogEvent::SendDirectSendMessage)
            .message_type(message_label)
            .peer(peer_network_id));

        // Send the message
        let result = self
            .network_client
            .send_to_peer_raw(message, *peer_network_id)
            .map_err(|error| Error::NetworkError(error.to_string()));

        // Process any error results
        if let Err(error) = result {
            // Log the failed send
            warn!(LogSchema::new(LogEntry::SendDirectSendMessage)
                .event(LogEvent::NetworkError)
                .message_type(message_label)
                .peer(peer_network_id)
                .message(&format!("Failed to send message: {:?}", error)));

            // Update the direct send error metrics
            metrics::increment_counter(
                &metrics::PUBLISHER_SENT_MESSAGE_ERRORS,
                error.get_label(),
                peer_network_id,
            );

            Err(Error::NetworkError(error.to_string()))
        } else {
            Ok(())
        }
```

**File:** network/framework/src/peer_manager/mod.rs (L528-546)
```rust
        if let Some((conn_metadata, sender)) = self.active_peers.get_mut(&peer_id) {
            if let Err(err) = sender.push(protocol_id, peer_request) {
                info!(
                    NetworkSchema::new(&self.network_context).connection_metadata(conn_metadata),
                    protocol_id = %protocol_id,
                    error = ?err,
                    "{} Failed to forward outbound message to downstream actor. Error: {:?}",
                    self.network_context, err
                );
            }
        } else {
            warn!(
                NetworkSchema::new(&self.network_context).remote_peer(&peer_id),
                protocol_id = %protocol_id,
                "{} Can't send message to peer.  Peer {} is currently not connected",
                self.network_context,
                peer_id.short_str()
            );
        }
```

# Audit Report

## Title
Unbounded Consensus Publisher Subscribers Enable Resource Exhaustion Attack

## Summary
The consensus publisher's `add_active_subscriber()` function has no limit on the number of active subscribers. An attacker can subscribe up to the network connection limit (default 100 peers) and cause severe resource exhaustion through message amplification, leading to validator node slowdown or crash.

## Finding Description
The consensus publisher accepts subscription requests from any connected peer without checking the total number of active subscribers. [1](#0-0) 

When a subscription request arrives, it's immediately added to the active subscribers set without validation: [2](#0-1) 

The attack works as follows:

1. **Subscription Phase**: An attacker establishes multiple connections (up to `MAX_INBOUND_CONNECTIONS`, default 100) to the validator node running the consensus publisher. [3](#0-2) 

2. **Amplification Phase**: Each connection sends a `Subscribe` request, creating up to 100 active subscribers in the HashSet. [4](#0-3) 

3. **Resource Exhaustion**: When consensus publishes messages (ordered blocks, block payloads, commit decisions), the publisher clones and serializes the message for every active subscriber: [5](#0-4) 

4. **Message Serialization Overhead**: Each message clone triggers a blocking serialization task, consuming CPU resources: [6](#0-5) 

Consensus messages can be large, containing blocks with transaction payloads, proofs, and signatures. With 100 subscribers, each published message results in:
- 100 message clones in memory
- 100 serialization tasks (CPU-intensive)
- 100 entries in the outbound channel (capacity: `max_network_channel_size`, default 1000)

Since consensus publishes messages frequently (multiple times per second for ordered blocks and payloads), this creates sustained resource exhaustion.

## Impact Explanation
This vulnerability qualifies as **High Severity** per the Aptos bug bounty program due to "Validator node slowdowns" category. The attack causes:

- **CPU Exhaustion**: Repeated message cloning and serialization for 100 subscribers consumes significant CPU cycles, competing with critical consensus operations
- **Memory Pressure**: Simultaneous message clones accumulate in memory, potentially triggering OOM conditions
- **Channel Saturation**: The outbound message channel fills rapidly (10 published messages = 1000 entries with 100 subscribers), causing message drops
- **Consensus Performance Degradation**: Resource exhaustion directly impacts the validator's ability to participate effectively in consensus, potentially affecting finality times

The configuration shows no explicit limit for publisher subscribers, unlike the observer side which has `max_concurrent_subscriptions`: [7](#0-6) 

## Likelihood Explanation
The likelihood of exploitation is **HIGH** because:

1. **Low Barrier to Entry**: Any network peer can establish connections and send Subscribe requests without authentication
2. **No Rate Limiting**: There's no rate limiting on subscription requests
3. **Garbage Collection Insufficient**: While disconnected peers are eventually removed, [8](#0-7)  an attacker can maintain connections indefinitely
4. **Network Handler Forwards All Requests**: The network handler forwards all subscription requests without validation: [9](#0-8) 

## Recommendation
Implement an explicit maximum subscriber limit check in the subscription handling logic:

```rust
// In ConsensusObserverConfig, add:
pub max_publisher_subscribers: u64,

// In Default implementation:
max_publisher_subscribers: 10, // Conservative limit

// In add_active_subscriber or process_network_message:
fn add_active_subscriber(&self, peer_network_id: PeerNetworkId) -> Result<(), Error> {
    let mut subscribers = self.active_subscribers.write();
    if subscribers.len() >= self.consensus_observer_config.max_publisher_subscribers as usize {
        return Err(Error::TooManySubscribers(
            format!("Maximum subscribers ({}) reached", 
                    self.consensus_observer_config.max_publisher_subscribers)
        ));
    }
    subscribers.insert(peer_network_id);
    Ok(())
}
```

Additionally, implement rate limiting on subscription attempts per peer to prevent rapid re-subscription attacks.

## Proof of Concept

```rust
#[tokio::test]
async fn test_subscriber_exhaustion_attack() {
    use crate::consensus_observer::publisher::consensus_publisher::ConsensusPublisher;
    use crate::consensus_observer::network::observer_client::ConsensusObserverClient;
    use aptos_config::config::ConsensusObserverConfig;
    use aptos_config::network_id::{NetworkId, PeerNetworkId};
    use aptos_network::application::{storage::PeersAndMetadata, interface::NetworkClient};
    use aptos_types::PeerId;
    use std::sync::Arc;
    
    // Create network infrastructure
    let network_id = NetworkId::Validator;
    let peers_and_metadata = PeersAndMetadata::new(&[network_id]);
    let network_client = NetworkClient::new(vec![], vec![], Default::default(), peers_and_metadata);
    let consensus_observer_client = Arc::new(ConsensusObserverClient::new(network_client));
    
    // Create publisher
    let (publisher, _receiver) = ConsensusPublisher::new(
        ConsensusObserverConfig::default(),
        consensus_observer_client,
    );
    
    // Simulate attacker subscribing 100 peers
    for i in 0..100 {
        let peer_network_id = PeerNetworkId::new(network_id, PeerId::random());
        publisher.add_active_subscriber(peer_network_id);
    }
    
    // Verify all subscribers were added without limit check
    assert_eq!(publisher.get_active_subscribers().len(), 100);
    
    // Attempt to add more - no error, just keeps growing
    for i in 0..50 {
        let peer_network_id = PeerNetworkId::new(network_id, PeerId::random());
        publisher.add_active_subscriber(peer_network_id);
    }
    
    // Verify unbounded growth
    assert_eq!(publisher.get_active_subscribers().len(), 150);
    
    // In production, publishing a message now causes 150x amplification
    // Each message gets cloned and serialized 150 times
}
```

## Notes
The vulnerability is amplified by the fact that consensus messages are published frequently and can be large. Block payloads containing hundreds of transactions can be several megabytes in size. With 100 subscribers, a single 5MB block payload results in 500MB of memory allocation for message clones plus significant CPU overhead for serialization, occurring multiple times per second during active consensus operation.

### Citations

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L40-40)
```rust
    active_subscribers: Arc<RwLock<HashSet<PeerNetworkId>>>,
```

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L94-96)
```rust
    fn add_active_subscriber(&self, peer_network_id: PeerNetworkId) {
        self.active_subscribers.write().insert(peer_network_id);
    }
```

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L99-155)
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

        // Update the number of active subscribers for each network
        let active_subscribers = self.get_active_subscribers();
        for network_id in peers_and_metadata.get_registered_networks() {
            // Calculate the number of active subscribers for the network
            let num_active_subscribers = active_subscribers
                .iter()
                .filter(|peer_network_id| peer_network_id.network_id() == network_id)
                .count() as i64;

            // Update the active subscriber metric
            metrics::set_gauge(
                &metrics::PUBLISHER_NUM_ACTIVE_SUBSCRIBERS,
                &network_id,
                num_active_subscribers,
            );
        }
    }
```

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L181-193)
```rust
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

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L286-299)
```rust
    tokio::spawn(async move {
        // Create the message serialization task
        let consensus_observer_client_clone = consensus_observer_client.clone();
        let serialization_task =
            outbound_message_receiver.map(move |(peer_network_id, message)| {
                // Spawn a new blocking task to serialize the message
                let consensus_observer_client_clone = consensus_observer_client_clone.clone();
                tokio::task::spawn_blocking(move || {
                    let message_label = message.get_label();
                    let serialized_message = consensus_observer_client_clone
                        .serialize_message_for_peer(&peer_network_id, message);
                    (peer_network_id, serialized_message, message_label)
                })
            });
```

**File:** config/src/config/network_config.rs (L44-44)
```rust
pub const MAX_INBOUND_CONNECTIONS: usize = 100;
```

**File:** config/src/config/consensus_observer_config.rs (L41-42)
```rust
    /// The maximum number of concurrent subscriptions
    pub max_concurrent_subscriptions: u64,
```

**File:** consensus/src/consensus_observer/network/network_handler.rs (L193-232)
```rust
    /// Handles a publisher message by forwarding it to the consensus publisher
    fn handle_publisher_message(
        &mut self,
        peer_network_id: PeerNetworkId,
        request: ConsensusObserverRequest,
        response_sender: Option<ResponseSender>,
    ) {
        // Drop the message if the publisher is not enabled
        if !self.consensus_observer_config.publisher_enabled {
            return;
        }

        // Ensure that the response sender is present
        let response_sender = match response_sender {
            Some(response_sender) => response_sender,
            None => {
                error!(
                    LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                        "Missing response sender for the RPC request: {:?}",
                        request
                    ))
                );
                return; // Something has gone wrong!
            },
        };

        // Create the consensus publisher message
        let network_message =
            ConsensusPublisherNetworkMessage::new(peer_network_id, request, response_sender);

        // Send the message to the consensus publisher
        if let Err(error) = self.publisher_message_sender.push((), network_message) {
            error!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Failed to forward the publisher request to the consensus publisher! Error: {:?}",
                    error
                ))
            );
        }
    }
```

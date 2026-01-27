# Audit Report

## Title
Unbounded Subscriber Growth and Rate Limiting Bypass in Consensus Publisher

## Summary
The `ConsensusPublisher::process_network_message()` function lacks proper protection against subscription flooding attacks. An attacker with authenticated peer connections can exploit two vulnerabilities: (1) unbounded memory growth through unlimited unique subscribers, and (2) CPU/network resource exhaustion through rapid repeated subscription requests that bypass application-level rate limiting.

## Finding Description

The consensus publisher handles Subscribe requests in the `process_network_message()` function without implementing critical security controls: [1](#0-0) 

**Vulnerability 1: Unbounded Subscriber Growth**

The `active_subscribers` HashSet has no maximum size limit: [2](#0-1) 

An attacker controlling multiple authenticated peer identities can subscribe all of them, causing unbounded memory growth. The garbage collection mechanism only removes disconnected peers, not based on a maximum subscriber count: [3](#0-2) 

**Vulnerability 2: Rate Limiting Bypass**

While the network RPC layer enforces a per-peer concurrency limit of 100 concurrent requests: [4](#0-3) 

This limit only applies to CONCURRENT requests. Since Subscribe requests complete quickly (just a HashSet insert and immediate SubscribeAck response), an attacker can send thousands of SEQUENTIAL requests per second from a single peer. Each duplicate subscription request is fully processed: [5](#0-4) 

The `add_active_subscriber()` function acquires a write lock on every request, even for already-subscribed peers: [6](#0-5) 

**Vulnerability 3: Channel Overflow Impact**

The publisher message channel has a limited capacity (default 1000): [7](#0-6) 

When this channel fills due to subscription flooding, the `aptos_channel` implementation drops old messages to make room for new ones: [8](#0-7) 

This means legitimate Subscribe/Unsubscribe requests from honest peers can be silently dropped during an attack.

## Impact Explanation

This vulnerability qualifies as **High Severity** per Aptos bug bounty criteria ("Validator node slowdowns, API crashes, Significant protocol violations"):

1. **Validator Node Resource Exhaustion**: An attacker can cause significant CPU usage through rapid lock acquisition, logging I/O, metrics updates, and network responses for thousands of duplicate subscription requests per second.

2. **Consensus Observer Denial of Service**: Legitimate observers cannot subscribe when the channel is saturated with attacker requests, disrupting the consensus observer mechanism that helps fullnodes stay synchronized.

3. **Memory Exhaustion**: While each `PeerNetworkId` entry is small (~40-50 bytes), an attacker controlling thousands of authenticated peers can cause unbounded memory growth (10,000 peers = ~500KB, 100,000 peers = ~5MB, 1 million peers = ~50MB).

4. **Degraded Network Performance**: The node must send SubscribeAck responses for every duplicate request, wasting outbound bandwidth.

While this does not directly compromise consensus safety, it significantly impacts validator node performance and the availability of the consensus observer feature, which is critical for network efficiency.

## Likelihood Explanation

**Likelihood: High**

The attack is easily executable:
- Requires only authenticated peer connections (available to any fullnode operator or compromised node)
- No special permissions or validator status needed
- Simple attack: repeatedly send Subscribe RPC requests
- Fast response times enable thousands of requests per second per peer
- Multiple peers can amplify the attack

The only barrier is the NoiseIK handshake requirement for peer authentication, but malicious fullnode operators or compromised nodes can trivially launch this attack.

## Recommendation

Implement three layers of protection:

**1. Add Maximum Subscriber Limit**

```rust
// In ConsensusObserverConfig
pub max_active_subscribers: u64, // Default: 1000

// In ConsensusPublisher::process_network_message()
ConsensusObserverRequest::Subscribe => {
    // Check subscriber limit before adding
    if self.active_subscribers.read().len() >= self.consensus_observer_config.max_active_subscribers as usize {
        warn!(LogSchema::new(LogEntry::ConsensusPublisher)
            .event(LogEvent::Subscription)
            .message(&format!(
                "Rejected subscription from peer {:?}: maximum subscribers ({}) reached",
                peer_network_id,
                self.consensus_observer_config.max_active_subscribers
            )));
        response_sender.send(ConsensusObserverResponse::SubscriptionRejected);
        return;
    }
    
    self.add_active_subscriber(peer_network_id);
    // ... rest of code
}
```

**2. Add Duplicate Subscription Detection**

```rust
ConsensusObserverRequest::Subscribe => {
    // Check if already subscribed to avoid redundant processing
    let already_subscribed = self.active_subscribers.read().contains(&peer_network_id);
    
    if already_subscribed {
        // Don't process duplicate, just acknowledge
        response_sender.send(ConsensusObserverResponse::SubscribeAck);
        return;
    }
    
    // ... check limits and add subscriber
}
```

**3. Add Per-Peer Request Rate Limiting**

```rust
// Add to ConsensusPublisher struct
per_peer_rate_limiters: Arc<RwLock<HashMap<PeerNetworkId, TokenBucket>>>,

// In process_network_message()
// Check rate limit before processing
if !self.check_rate_limit(&peer_network_id) {
    warn!(LogSchema::new(LogEntry::ConsensusPublisher)
        .message(&format!("Rate limit exceeded for peer {:?}", peer_network_id)));
    response_sender.send(ConsensusObserverResponse::RateLimitExceeded);
    return;
}
```

## Proof of Concept

```rust
#[tokio::test]
async fn test_subscription_flood_attack() {
    use std::time::Instant;
    
    // Create consensus publisher
    let network_id = NetworkId::Public;
    let peers_and_metadata = PeersAndMetadata::new(&[network_id]);
    let network_client = NetworkClient::new(vec![], vec![], hashmap![], peers_and_metadata.clone());
    let consensus_observer_client = Arc::new(ConsensusObserverClient::new(network_client));
    let (consensus_publisher, _) = ConsensusPublisher::new(
        ConsensusObserverConfig::default(),
        consensus_observer_client,
    );
    
    // Attack 1: Flood with duplicate subscriptions from same peer
    let attacker_peer = PeerNetworkId::new(network_id, PeerId::random());
    let start = Instant::now();
    
    for i in 0..10000 {
        let network_message = ConsensusPublisherNetworkMessage::new(
            attacker_peer,
            ConsensusObserverRequest::Subscribe,
            ResponseSender::new_for_test(),
        );
        consensus_publisher.process_network_message(network_message);
    }
    
    let elapsed = start.elapsed();
    println!("Processed 10,000 duplicate subscriptions in {:?}", elapsed);
    
    // Verify only one entry exists (HashSet dedup works)
    assert_eq!(consensus_publisher.get_active_subscribers().len(), 1);
    
    // Attack 2: Unbounded growth with many unique peers
    for i in 0..100000 {
        let unique_peer = PeerNetworkId::new(network_id, PeerId::random());
        let network_message = ConsensusPublisherNetworkMessage::new(
            unique_peer,
            ConsensusObserverRequest::Subscribe,
            ResponseSender::new_for_test(),
        );
        consensus_publisher.process_network_message(network_message);
    }
    
    // Verify unbounded growth - no limit enforced!
    assert_eq!(consensus_publisher.get_active_subscribers().len(), 100001);
    println!("Successfully added 100,000 unique subscribers - no limit enforced!");
}
```

**Notes**

The vulnerability exists because the consensus publisher was designed for a cooperative network environment but lacks defensive mechanisms against malicious peers. The RPC layer's concurrency limit provides partial mitigation but cannot prevent sequential request flooding or unbounded subscriber accumulation. The issue is particularly concerning because the consensus observer feature is enabled by default on validators and validator fullnodes, making it a viable attack vector against critical network infrastructure.

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

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L168-208)
```rust
    fn process_network_message(&self, network_message: ConsensusPublisherNetworkMessage) {
        // Unpack the network message
        let (peer_network_id, message, response_sender) = network_message.into_parts();

        // Update the RPC request counter
        metrics::increment_counter(
            &metrics::PUBLISHER_RECEIVED_REQUESTS,
            message.get_label(),
            &peer_network_id,
        );

        // Handle the message
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
    }
```

**File:** network/framework/src/constants.rs (L14-15)
```rust
/// Limit on concurrent Inbound RPC requests before backpressure is applied
pub const MAX_CONCURRENT_INBOUND_RPCS: u32 = 100;
```

**File:** config/src/config/consensus_observer_config.rs (L68-68)
```rust
            max_network_channel_size: 1000,
```

**File:** crates/channel/src/aptos_channel.rs (L101-107)
```rust
        let dropped = shared_state.internal_queue.push(key, (message, status_ch));
        // If this or an existing message had to be dropped because of the queue being full, we
        // notify the corresponding status channel if it was registered.
        if let Some((dropped_val, Some(dropped_status_ch))) = dropped {
            // Ignore errors.
            let _err = dropped_status_ch.send(ElementStatus::Dropped(dropped_val));
        }
```

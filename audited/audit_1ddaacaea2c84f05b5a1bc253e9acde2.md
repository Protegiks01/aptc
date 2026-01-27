# Audit Report

## Title
Consensus Observer Subscriber Amplification: Lack of Rate Limiting Enables Resource Exhaustion on Validators

## Summary
The consensus observer publisher accepts unlimited subscriptions from any connected peer without authentication or authorization checks. An attacker can exploit this by creating multiple subscriber connections, causing validators to broadcast consensus updates to an unbounded number of observers, exhausting network bandwidth, channel capacity, and CPU resources that are shared with critical consensus traffic.

## Finding Description
The consensus observer system allows any fullnode to subscribe to consensus updates from validators and VFNs. However, the publisher implementation has no limits on the number of subscribers it will accept, and no authentication mechanism to verify subscription requests. [1](#0-0) 

When a `Subscribe` request is received, the publisher immediately adds the peer to the active subscriber set without any checks. The publisher then broadcasts all consensus updates to every active subscriber: [2](#0-1) 

This creates several attack vectors:

1. **Subscriber Amplification**: An attacker can open many peer connections (using different peer IDs or IP addresses) and subscribe each one. The publisher will send consensus updates to all of them, multiplying the outbound traffic by the number of attackers.

2. **Shared Rate Limits**: Network rate limits are configured per-IP at the connection level, not per-protocol. The `ConsensusObserver` protocol shares the same rate limit budget as regular `Consensus` protocols: [3](#0-2) [4](#0-3) 

Both `ProtocolId::ConsensusObserver` and regular consensus protocols are registered on the same network with the same `network_config`, meaning they share IP-based rate limits: [5](#0-4) 

3. **Channel Saturation**: Messages are queued in a bounded channel with `max_network_channel_size` (default: 1000). With N subscribers, each consensus update generates N channel messages, potentially filling the channel: [6](#0-5) 

4. **CPU Resource Consumption**: Each message requires serialization, consuming CPU resources bounded only by `max_parallel_serialization_tasks`: [7](#0-6) 

There is no maximum subscriber limit enforced on the publisher side (the `max_concurrent_subscriptions` config only limits how many subscriptions an observer creates, not how many a publisher accepts): [8](#0-7) 

## Impact Explanation
This vulnerability allows an attacker to degrade validator performance, qualifying as **High Severity** under the "Validator node slowdowns" category. By subscribing many peers to a validator's consensus observer publisher, an attacker can:

1. Exhaust the validator's outbound network bandwidth by forcing it to send consensus updates to many observers
2. Saturate the outbound message channel, causing legitimate messages to be dropped
3. Consume CPU resources for message serialization
4. Since observer traffic shares IP-based rate limits with consensus traffic, high observer traffic volume can impact the validator's ability to send/receive consensus messages efficiently

While the non-blocking `try_send` prevents complete validator lockup, the cumulative effect of serving many observers degrades overall consensus performance across the network.

## Likelihood Explanation
This attack is **highly likely** to occur because:

1. **No Authentication Required**: Any peer that can establish a network connection can send a subscription request
2. **Low Barrier to Entry**: Attackers don't need validator credentials, stake, or special permissions
3. **Easy to Execute**: Simply opening multiple peer connections and sending RPC Subscribe requests
4. **Amplification Factor**: Each malicious subscriber multiplies the validator's outbound traffic
5. **Default Configuration Vulnerable**: No subscriber limits are enforced by default

The attack requires only:
- Network connectivity to a validator or VFN that has publisher enabled
- Ability to establish multiple peer connections
- Sending standard `ConsensusObserverRequest::Subscribe` RPC messages

## Recommendation
Implement the following protections:

1. **Add Maximum Subscriber Limit**: Introduce a `max_subscribers_per_publisher` configuration parameter and enforce it when processing subscription requests:

```rust
// In ConsensusObserverConfig
pub max_subscribers_per_publisher: u64, // Default: 100

// In ConsensusPublisher::process_network_message
ConsensusObserverRequest::Subscribe => {
    if self.get_active_subscribers().len() >= self.consensus_observer_config.max_subscribers_per_publisher as usize {
        warn!("Maximum subscriber limit reached, rejecting subscription from {:?}", peer_network_id);
        response_sender.send(ConsensusObserverResponse::SubscribeError);
        return;
    }
    self.add_active_subscriber(peer_network_id);
    // ... rest of handling
}
```

2. **Implement Subscription Authentication**: Verify that subscribers meet certain criteria (e.g., are known VFNs, have sufficient stake, or are on an allowlist) before accepting subscriptions.

3. **Per-Protocol Rate Limiting**: Implement separate rate limit configurations for ConsensusObserver vs regular Consensus protocols, ensuring observer traffic cannot exhaust resources needed for consensus.

4. **Subscriber Health Monitoring**: Implement stricter health checks and automatically remove subscribers that exhibit suspicious behavior (e.g., excessive request rates, connection churn).

## Proof of Concept

```rust
// Simulated attack demonstrating subscriber amplification
// This would be run as an integration test in consensus/src/consensus_observer/publisher/

use consensus_observer::publisher::ConsensusPublisher;
use aptos_config::config::ConsensusObserverConfig;
use aptos_network::application::interface::NetworkClient;

#[tokio::test]
async fn test_unbounded_subscriber_attack() {
    // Create a publisher
    let config = ConsensusObserverConfig::default();
    let (publisher, _) = ConsensusPublisher::new(config, /* network client */);
    
    // Simulate 10,000 malicious subscribers
    let num_attackers = 10_000;
    for i in 0..num_attackers {
        let attacker_peer = create_malicious_peer(i);
        
        // Send subscribe request - will be accepted without limit
        let subscribe_request = ConsensusObserverRequest::Subscribe;
        // Publisher accepts all without checking limits
        publisher.process_subscription(attacker_peer, subscribe_request);
    }
    
    // Verify all attackers were accepted
    assert_eq!(publisher.get_active_subscribers().len(), num_attackers);
    
    // Now publish a consensus update
    let consensus_update = create_test_consensus_update();
    publisher.publish_message(consensus_update);
    
    // This will attempt to send to all 10,000 subscribers
    // Causing channel saturation and resource exhaustion
    // Demonstrating the vulnerability
}
```

## Notes

The vulnerability specifically addresses the question of whether ConsensusObserver can be exploited to degrade consensus performance. While the attacker doesn't "bypass" rate limits in the strict sense, they can consume the shared rate limit budget by subscribing many peers and forcing the validator to send high volumes of observer traffic. This degrades the validator's ability to efficiently participate in consensus, as both observer and consensus traffic share the same IP-based network rate limits.

The lack of subscriber limits and authentication creates an asymmetric resource consumption attack where the attacker's cost (establishing connections) is much lower than the defender's cost (broadcasting to all subscribers).

### Citations

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L181-192)
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

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L304-304)
```rust
            .buffered(consensus_observer_config.max_parallel_serialization_tasks)
```

**File:** config/src/config/network_config.rs (L116-119)
```rust
    /// Inbound rate limiting configuration, if not specified, no rate limiting
    pub inbound_rate_limit_config: Option<RateLimitConfig>,
    /// Outbound rate limiting configuration, if not specified, no rate limiting
    pub outbound_rate_limit_config: Option<RateLimitConfig>,
```

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L162-162)
```rust
            ProtocolId::ConsensusObserver => Encoding::CompressedBcs(RECURSION_LIMIT),
```

**File:** aptos-node/src/network.rs (L336-358)
```rust
        // Register consensus observer (both client and server) with the network
        if node_config
            .consensus_observer
            .is_observer_or_publisher_enabled()
        {
            // Create the network handle for this network type
            let network_handle = register_client_and_service_with_network(
                &mut network_builder,
                network_id,
                &network_config,
                consensus_observer_network_configuration(node_config),
                false,
            );

            // Add the network handle to the set of handles
            if let Some(consensus_observer_network_handles) =
                &mut consensus_observer_network_handles
            {
                consensus_observer_network_handles.push(network_handle);
            } else {
                consensus_observer_network_handles = Some(vec![network_handle]);
            }
        }
```

**File:** config/src/config/consensus_observer_config.rs (L41-42)
```rust
    /// The maximum number of concurrent subscriptions
    pub max_concurrent_subscriptions: u64,
```

**File:** config/src/config/consensus_observer_config.rs (L68-68)
```rust
            max_network_channel_size: 1000,
```

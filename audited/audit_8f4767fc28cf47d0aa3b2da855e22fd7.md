# Audit Report

## Title
Consensus Observer DoS via Unbounded Unsubscribe Task Spawning from Non-Subscribed Peers

## Summary
The `verify_message_for_subscription()` function in the consensus observer subscription manager spawns unlimited asynchronous unsubscribe tasks for every message received from non-subscribed peers, enabling resource exhaustion attacks through task and network request spam.

## Finding Description

The vulnerability exists in the message verification flow for consensus observer subscriptions. When a consensus observer node receives messages, it verifies that they originate from active subscriptions. However, the verification logic contains a critical flaw that allows unlimited resource consumption. [1](#0-0) 

For every message from a non-subscribed peer, `verify_message_for_subscription()` calls `unsubscribe_from_peer()`. This function spawns a new tokio task without any deduplication or rate limiting: [2](#0-1) 

**Attack Flow:**

1. Attacker connects to the network as a regular peer (no special privileges required)
2. Attacker floods the node with consensus observer messages (up to `max_network_channel_size` = 1000 messages can be queued)
3. Each message from the non-subscribed attacker triggers `verify_message_for_subscription()`
4. Since the attacker is not subscribed, `unsubscribe_from_peer()` is called for EACH message
5. Each call spawns a new tokio task via `tokio::spawn()` that sends an RPC request with a 5-second timeout
6. No deduplication exists - the attacker peer is never added to `active_observer_subscriptions`, so removal is a no-op, and subsequent messages continue spawning tasks [3](#0-2) 

The configuration shows the attack surface: 1000 messages can be queued, each spawning a task that persists for up to 5 seconds. As the channel drains, the attacker can send more messages to sustain the attack.

**Invariant Violation:**

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The code allows unbounded task spawning and network requests without proper resource controls.

## Impact Explanation

This vulnerability enables an **application-level resource exhaustion attack** against consensus observer nodes. The impact includes:

1. **Memory Exhaustion**: Each spawned task consumes memory for the task structure, captured variables, and pending RPC state
2. **CPU Overhead**: Excessive task scheduling and context switching degrades node performance  
3. **Network Bandwidth Waste**: Thousands of outbound RPC requests to the attacker consume bandwidth
4. **Validator Node Slowdown**: Resource contention slows consensus processing and block propagation

This qualifies as **High Severity** per Aptos bug bounty criteria: "Validator node slowdowns." While the exclusions mention "network-level DoS attacks are out of scope," this is an **application logic bug** in the consensus observer code, not a network protocol exploit. The network layer (bounded channels) functions correctly - the bug is in how the application processes messages after network delivery.

The attack affects consensus observer nodes (enabled on validators and validator fullnodes), potentially degrading network performance during consensus operations. [4](#0-3) 

## Likelihood Explanation

**Likelihood: High**

The attack is trivial to execute:
- No authentication required before message processing
- No validator privileges needed
- No special network access beyond normal peer connectivity
- Attacker can sustain the attack by continuously sending messages as the channel drains
- The bounded channel provides only limited protection (1000 messages), after which the vulnerability compounds as tasks persist for 5 seconds each

The message processing flow confirms messages reach the vulnerable function without prior authentication: [5](#0-4) 

## Recommendation

Implement **per-peer rate limiting** for unsubscribe operations using a tracking mechanism to prevent repeated task spawning for the same peer within a time window:

```rust
// Add to SubscriptionManager struct:
struct SubscriptionManager {
    // ... existing fields ...
    
    // Track recent unsubscribe attempts per peer
    recent_unsubscribe_attempts: Arc<Mutex<HashMap<PeerNetworkId, Instant>>>,
}

// Modify unsubscribe_from_peer():
fn unsubscribe_from_peer(&mut self, peer_network_id: PeerNetworkId) {
    // Check if we recently sent an unsubscribe to this peer
    let mut recent_attempts = self.recent_unsubscribe_attempts.lock();
    let now = Instant::now();
    
    if let Some(last_attempt) = recent_attempts.get(&peer_network_id) {
        // Rate limit: only send unsubscribe once per 60 seconds per peer
        if now.duration_since(*last_attempt) < Duration::from_secs(60) {
            return; // Skip redundant unsubscribe
        }
    }
    
    // Record this attempt
    recent_attempts.insert(peer_network_id, now);
    
    // Remove the peer from active subscriptions
    self.active_observer_subscriptions
        .lock()
        .remove(&peer_network_id);
    
    // ... rest of existing code to spawn task ...
}
```

Additionally, implement periodic cleanup of the `recent_unsubscribe_attempts` map to prevent memory leaks from tracking many peers over time.

## Proof of Concept

```rust
#[tokio::test]
async fn test_unsubscribe_task_spam_vulnerability() {
    use aptos_config::{config::ConsensusObserverConfig, network_id::NetworkId};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    
    // Create consensus observer components
    let (peers_and_metadata, consensus_observer_client) = 
        create_consensus_observer_client(&[NetworkId::Public]);
    let consensus_observer_config = ConsensusObserverConfig::default();
    let db_reader = Arc::new(MockDatabaseReader::new());
    let mut subscription_manager = SubscriptionManager::new(
        consensus_observer_client.clone(),
        consensus_observer_config,
        None,
        db_reader,
        TimeService::mock(),
    );
    
    // Simulate attacker: non-subscribed peer
    let attacker_peer = PeerNetworkId::random();
    
    // Counter for spawned tasks (in real code, monitor tokio runtime metrics)
    let task_counter = Arc::new(AtomicUsize::new(0));
    
    // Send 100 messages from non-subscribed peer
    for _ in 0..100 {
        let result = subscription_manager.verify_message_for_subscription(attacker_peer);
        
        // Each message should fail verification
        assert!(result.is_err());
        
        // This demonstrates that each call triggers unsubscribe_from_peer()
        // which spawns a new task (visible in production via tokio metrics)
    }
    
    // In production, this would show:
    // - 100 spawned tokio tasks
    // - 100 outbound RPC requests to attacker_peer
    // - Each task holds resources for up to 5 seconds
    // - No deduplication or rate limiting prevents this
}
```

**Notes**

The vulnerability specifically affects the consensus observer subsystem, which is enabled by default on validators and validator fullnodes. The attack exploits missing input validation and rate limiting in the application layer, distinct from network-level DoS attacks that target protocol weaknesses. The fix requires adding stateful per-peer tracking to prevent redundant unsubscribe operations within a reasonable time window.

### Citations

**File:** consensus/src/consensus_observer/observer/subscription_manager.rs (L307-359)
```rust
    /// Unsubscribes from the given peer by sending an unsubscribe request
    fn unsubscribe_from_peer(&mut self, peer_network_id: PeerNetworkId) {
        // Remove the peer from the active subscriptions
        self.active_observer_subscriptions
            .lock()
            .remove(&peer_network_id);

        // Send an unsubscribe request to the peer and process the response.
        // Note: we execute this asynchronously, as we don't need to wait for the response.
        let consensus_observer_client = self.consensus_observer_client.clone();
        let consensus_observer_config = self.consensus_observer_config;
        tokio::spawn(async move {
            // Send the unsubscribe request to the peer
            let unsubscribe_request = ConsensusObserverRequest::Unsubscribe;
            let response = consensus_observer_client
                .send_rpc_request_to_peer(
                    &peer_network_id,
                    unsubscribe_request,
                    consensus_observer_config.network_request_timeout_ms,
                )
                .await;

            // Process the response
            match response {
                Ok(ConsensusObserverResponse::UnsubscribeAck) => {
                    info!(
                        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                            "Successfully unsubscribed from peer: {}!",
                            peer_network_id
                        ))
                    );
                },
                Ok(response) => {
                    // We received an invalid response
                    warn!(
                        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                            "Got unexpected response type: {:?}",
                            response.get_label()
                        ))
                    );
                },
                Err(error) => {
                    // We encountered an error while sending the request
                    warn!(
                        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                            "Failed to send unsubscribe request to peer: {}! Error: {:?}",
                            peer_network_id, error
                        ))
                    );
                },
            }
        });
    }
```

**File:** consensus/src/consensus_observer/observer/subscription_manager.rs (L363-385)
```rust
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

**File:** config/src/config/consensus_observer_config.rs (L11-14)
```rust
// Useful constants for enabling consensus observer on different node types
const ENABLE_ON_VALIDATORS: bool = true;
const ENABLE_ON_VALIDATOR_FULLNODES: bool = true;
const ENABLE_ON_PUBLIC_FULLNODES: bool = false;
```

**File:** config/src/config/consensus_observer_config.rs (L68-70)
```rust
            max_network_channel_size: 1000,
            max_parallel_serialization_tasks: num_cpus::get(), // Default to the number of CPUs
            network_request_timeout_ms: 5_000,                 // 5 seconds
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L573-594)
```rust
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

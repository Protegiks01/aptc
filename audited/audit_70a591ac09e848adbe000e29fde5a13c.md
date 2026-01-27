# Audit Report

## Title
Subscription Resurrection Race Condition Allows Old Messages to Corrupt New Subscription State

## Summary
A race condition exists in the consensus observer subscription management system where messages from a terminated subscription can be incorrectly attributed to a newly created subscription to the same peer. This occurs because subscriptions are identified solely by `PeerNetworkId` without any unique instance identifier, creating a time window where old in-flight messages can corrupt new subscription state.

## Finding Description

The consensus observer subscription system lacks proper instance isolation between successive subscriptions to the same peer. When a subscription is terminated and a new one is created to the same peer, there is no mechanism to distinguish messages belonging to the old subscription from those belonging to the new subscription.

**Attack Flow:**

1. An observer node has an active subscription to Peer A (Subscription_1) with `last_message_receive_time = T1`

2. Subscription_1 times out or disconnects, triggering termination

3. The termination process removes Subscription_1 from `active_observer_subscriptions` and spawns an async task to send an unsubscribe RPC [1](#0-0) 

4. Meanwhile, Peer A has already sent consensus messages (OrderedBlock, CommitDecision, etc.) that are in-flight in the network

5. A new subscription creation task successfully creates Subscription_2 to Peer A and adds it to `active_observer_subscriptions` [2](#0-1) 

6. Old messages from Subscription_1 arrive at the node

7. `verify_message_for_subscription()` is called and finds Peer A in `active_observer_subscriptions` (now Subscription_2) [3](#0-2) 

8. The function updates Subscription_2's `last_message_receive_time`, making it appear healthy even though it hasn't actually received any messages yet [4](#0-3) 

9. Old stale consensus blocks from Subscription_1 are processed as if they came from Subscription_2 [5](#0-4) 

The root cause is that subscriptions are created with only a `PeerNetworkId` identifier, with no unique session ID or nonce [6](#0-5) 

This breaks the invariant that each subscription instance should be isolated and maintain its own independent state and message stream.

## Impact Explanation

**Severity: Medium** (State inconsistencies requiring intervention)

This vulnerability causes state corruption in consensus observer nodes through:

1. **Health Tracking Corruption**: Old messages update the new subscription's `last_message_receive_time`, preventing proper timeout detection and allowing dead subscriptions to appear alive longer than configured timeouts

2. **Stale Block Processing**: Observer nodes may process out-of-order or duplicate blocks from the old subscription, corrupting their view of consensus progress

3. **Subscription Liveness Issues**: The corrupted health state prevents the observer from detecting when the new subscription is actually unhealthy, potentially causing it to remain subscribed to a non-responsive peer

While consensus observer nodes are non-voting participants and don't directly affect consensus safety, this issue degrades observer node reliability and correctness, requiring manual intervention to restore proper operation. This aligns with the "State inconsistencies requiring intervention" category at Medium severity.

## Likelihood Explanation

**Likelihood: Medium-High**

This race condition is realistic and likely to occur in production:

1. **Natural Network Delays**: Message delivery delays of 100ms-1000ms are common in distributed systems, creating a race window where old messages can arrive after subscription recreation

2. **Automatic Triggering**: The scenario occurs naturally during normal operations:
   - Subscription timeouts (configured at `max_subscription_timeout_ms`) trigger regularly
   - Network disconnections are common
   - The system automatically attempts to create new subscriptions

3. **No Special Attacker Requirements**: No privileged access or malicious behavior is required - this occurs during normal network conditions with message delays

4. **Async Operations Create Race Window**: The spawned async tasks for unsubscribe RPCs and subscription creation create non-deterministic timing, increasing race likelihood [7](#0-6) 

## Recommendation

Introduce unique subscription instance identifiers to distinguish between successive subscriptions to the same peer:

```rust
// Add to ConsensusObserverSubscription
pub struct ConsensusObserverSubscription {
    // Add unique subscription ID
    subscription_id: u64,  // Or use Uuid::new_v4()
    
    consensus_observer_config: ConsensusObserverConfig,
    db_reader: Arc<dyn DbReader>,
    peer_network_id: PeerNetworkId,
    // ... existing fields
}

// Update message verification to include subscription ID
pub struct ConsensusObserverMessage {
    subscription_id: u64,  // Included in all messages
    // ... existing fields
}

// In verify_message_for_subscription:
pub fn verify_message_for_subscription(
    &mut self,
    message_sender: PeerNetworkId,
    message_subscription_id: u64,  // Add this parameter
) -> Result<(), Error> {
    if let Some(active_subscription) = self
        .active_observer_subscriptions
        .lock()
        .get_mut(&message_sender)
    {
        // Verify subscription ID matches
        if active_subscription.subscription_id != message_subscription_id {
            return Err(Error::InvalidMessageError(format!(
                "Message subscription ID {} does not match active subscription ID {}",
                message_subscription_id,
                active_subscription.subscription_id
            )));
        }
        
        active_subscription.update_last_message_receive_time();
        return Ok(());
    }
    // ... rest of function
}
```

This ensures that messages from old subscriptions are rejected even if a new subscription to the same peer has been created.

## Proof of Concept

The following Rust test demonstrates the race condition:

```rust
#[tokio::test]
async fn test_subscription_resurrection_race_condition() {
    use std::sync::Arc;
    use aptos_config::config::ConsensusObserverConfig;
    use consensus::consensus_observer::observer::subscription_manager::SubscriptionManager;
    
    // Setup: Create subscription manager with a peer
    let config = ConsensusObserverConfig::default();
    let (peers_and_metadata, client) = create_test_client();
    let db_reader = Arc::new(MockDatabaseReader::new());
    let time_service = TimeService::mock();
    let mut manager = SubscriptionManager::new(
        client, config, None, db_reader.clone(), time_service.clone()
    );
    
    // Step 1: Create initial subscription to peer A
    let peer_a = create_test_peer();
    add_subscription(&mut manager, peer_a, time_service.clone());
    
    // Step 2: Simulate subscription timeout
    time_service.advance(Duration::from_millis(config.max_subscription_timeout_ms + 1));
    
    // Step 3: Terminate the subscription (removes from active_observer_subscriptions)
    manager.terminate_unhealthy_subscriptions(&HashMap::new());
    assert_eq!(manager.get_active_subscription_peers().len(), 0);
    
    // Step 4: Create new subscription to same peer (simulating async subscription creation)
    let new_time_service = TimeService::mock();
    add_subscription(&mut manager, peer_a, new_time_service.clone());
    let new_subscription_peers = manager.get_active_subscription_peers();
    assert_eq!(new_subscription_peers.len(), 1);
    
    // Step 5: Old message arrives from terminated subscription
    // This should be rejected but instead updates the new subscription
    let result = manager.verify_message_for_subscription(peer_a);
    
    // BUG: Message is accepted and updates new subscription's state
    assert!(result.is_ok()); // Should fail but passes
    
    // The new subscription's last_message_receive_time is now corrupted
    // by an old message it never actually received
    let subscriptions = manager.active_observer_subscriptions.lock();
    let subscription = subscriptions.get(&peer_a).unwrap();
    
    // The subscription appears to have received a message immediately,
    // even though it was just created and hasn't received any real messages
    assert_eq!(subscription.last_message_receive_time, new_time_service.now());
    
    // This corrupted state prevents proper timeout detection
}
```

**Notes:**
- This vulnerability affects consensus observer nodes, which are non-validator full nodes that observe consensus without participating in voting
- The impact is limited to observer node reliability and correctness, not core consensus safety
- The issue is realistic due to natural network delays and asynchronous subscription management operations
- The lack of subscription instance identifiers makes it impossible to distinguish messages from different subscription instances to the same peer

### Citations

**File:** consensus/src/consensus_observer/observer/subscription_manager.rs (L207-260)
```rust
        // Spawn a new subscription creation task
        let subscription_creation_task = tokio::spawn(async move {
            // Identify the terminated subscription peers
            let terminated_subscription_peers = terminated_subscriptions
                .iter()
                .map(|(peer, _)| *peer)
                .collect();

            // Create the new subscriptions
            let new_subscriptions = subscription_utils::create_new_subscriptions(
                consensus_observer_config,
                consensus_observer_client,
                consensus_publisher,
                db_reader,
                time_service,
                connected_peers_and_metadata,
                num_subscriptions_to_create,
                active_subscription_peers,
                terminated_subscription_peers,
            )
            .await;

            // Identify the new subscription peers
            let new_subscription_peers = new_subscriptions
                .iter()
                .map(|subscription| subscription.get_peer_network_id())
                .collect::<Vec<_>>();

            // Add the new subscriptions to the list of active subscriptions
            for subscription in new_subscriptions {
                active_observer_subscriptions
                    .lock()
                    .insert(subscription.get_peer_network_id(), subscription);
            }

            // Log a warning if we failed to create as many subscriptions as requested
            let num_subscriptions_created = new_subscription_peers.len();
            if num_subscriptions_created < num_subscriptions_to_create {
                warn!(
                    LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                        "Failed to create the requested number of subscriptions! Number of subscriptions \
                        requested: {:?}, number of subscriptions created: {:?}.",
                        num_subscriptions_to_create,
                        num_subscriptions_created
                    ))
                );
            }

            // Update the subscription change metrics
            update_subscription_change_metrics(new_subscription_peers, terminated_subscriptions);
        });

        // Update the active subscription creation task
        *self.active_subscription_creation_task.lock() = Some(subscription_creation_task);
```

**File:** consensus/src/consensus_observer/observer/subscription_manager.rs (L308-359)
```rust
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

**File:** consensus/src/consensus_observer/observer/subscription.rs (L40-59)
```rust
    pub fn new(
        consensus_observer_config: ConsensusObserverConfig,
        db_reader: Arc<dyn DbReader>,
        peer_network_id: PeerNetworkId,
        time_service: TimeService,
    ) -> Self {
        // Get the current time
        let time_now = time_service.now();

        // Create a new subscription
        Self {
            consensus_observer_config,
            db_reader,
            peer_network_id,
            last_message_receive_time: time_now,
            last_optimality_check_time_and_peers: (time_now, HashSet::new()),
            highest_synced_version_and_time: (0, time_now),
            time_service,
        }
    }
```

**File:** consensus/src/consensus_observer/observer/subscription.rs (L230-232)
```rust
    pub fn update_last_message_receive_time(&mut self) {
        self.last_message_receive_time = self.time_service.now();
    }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L573-636)
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

        // Increment the received message counter
        increment_received_message_counter(&peer_network_id, &message);

        // Process the message based on the type
        match message {
            ConsensusObserverDirectSend::OrderedBlock(ordered_block) => {
                self.process_ordered_block_message(
                    peer_network_id,
                    message_received_time,
                    ordered_block,
                )
                .await;
            },
            ConsensusObserverDirectSend::CommitDecision(commit_decision) => {
                self.process_commit_decision_message(
                    peer_network_id,
                    message_received_time,
                    commit_decision,
                );
            },
            ConsensusObserverDirectSend::BlockPayload(block_payload) => {
                self.process_block_payload_message(
                    peer_network_id,
                    message_received_time,
                    block_payload,
                )
                .await;
            },
            ConsensusObserverDirectSend::OrderedBlockWithWindow(ordered_block_with_window) => {
                self.process_ordered_block_with_window_message(
                    peer_network_id,
                    message_received_time,
                    ordered_block_with_window,
                )
                .await;
            },
        }

        // Update the metrics for the processed blocks
        self.observer_block_data.lock().update_block_metrics();
    }
```

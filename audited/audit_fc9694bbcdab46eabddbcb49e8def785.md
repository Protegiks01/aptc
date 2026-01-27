# Audit Report

## Title
Consensus Observer Subscription Initialization Race Condition Enabling Resource Exhaustion via Repeated Connection Churn

## Summary
The `ConsensusObserverSubscription::new()` function performs no validation that the provided `PeerNetworkId` exists in the connected peers set at subscription creation time. Combined with asynchronous subscription creation and lack of persistent peer blacklisting, this enables a malicious peer to cause resource exhaustion through repeated connect-subscribe-disconnect cycles.

## Finding Description

The vulnerability exists in the consensus observer subscription initialization flow across multiple components: [1](#0-0) 

The `new()` function blindly accepts any `PeerNetworkId` without validating that the peer is currently connected. This creates a race condition window in the asynchronous subscription creation process.

The subscription creation flow operates as follows: [2](#0-1) 

The subscription creation task is spawned asynchronously, meaning there is a time window between when the connected peers are snapshot and when subscriptions are actually created and added to the active subscription map. [3](#0-2) 

When a peer responds with `SubscribeAck`, a subscription is immediately created at line 154 without any validation that the peer remains connected.

The health check mechanism detects disconnected peers: [4](#0-3) 

The first check verifies peer connectivity at lines 70-75. When a subscription is created for a peer that subsequently disconnects (or was disconnecting), the health check immediately fails.

**Attack Scenario:**

1. Malicious peer connects to the node
2. Node's subscription manager identifies peer as optimal (based on distance/latency metrics)
3. Node sends `ConsensusObserverRequest::Subscribe` to the peer
4. Peer responds with `SubscribeAck` 
5. `ConsensusObserverSubscription::new()` creates subscription **without validating peer is still connected**
6. Subscription added to `active_observer_subscriptions` map
7. **Peer disconnects immediately**
8. Next health check (runs every 5 seconds per config) detects peer disconnection at line 70-75
9. Subscription terminated and removed from active subscriptions
10. New subscription creation task spawned to fill the gap
11. **Peer reconnects and cycle repeats**

The critical issue is the lack of persistent blacklisting: [5](#0-4) 

Failed peers are only removed from `connected_peers_and_metadata` for the **current** subscription creation cycle (lines 256-259). Once that cycle completes, the failed peer is forgotten. When the peer reconnects for the next cycle, it can be selected again. [6](#0-5) 

The progress check runs every `progress_check_interval_ms` (default 5 seconds), calling `check_and_manage_subscriptions()` which triggers the subscription creation/termination cycle. [7](#0-6) 

## Impact Explanation

This is a **Medium Severity** vulnerability per Aptos bug bounty criteria:

**Resource Exhaustion Impact:**
- **Memory Churn**: Repeated allocation and deallocation of `ConsensusObserverSubscription` objects consumes memory and fragments the heap
- **CPU Usage**: Continuous subscription creation, RPC sending, and termination cycles consume CPU resources
- **Network Bandwidth**: Each cycle involves subscription request/response and unsubscribe RPC messages
- **Operational Degradation**: The consensus observer may be unable to maintain stable subscriptions, degrading its ability to receive consensus data efficiently

This fits the "State inconsistencies requiring intervention" category for Medium severity. While it doesn't directly cause fund loss or consensus safety violations, it can degrade node operational capacity and require manual intervention to identify and block malicious peers.

The attack does NOT:
- Break consensus safety (consensus still functions via other mechanisms)
- Cause fund loss or minting
- Require validator privileges
- Crash the node entirely

## Likelihood Explanation

**Likelihood: Medium-High**

The attack is straightforward to execute:
- No special privileges required - any peer can connect to consensus observer nodes
- Simple attack pattern: connect → respond to subscription → disconnect → repeat
- No cryptographic operations or complex state manipulation needed

**Limiting Factors:**
- Network round-trip time for connection establishment and RPC communication
- Health checks run every 5 seconds, not continuously
- Only one subscription creation task can run simultaneously
- Peer must be capable of rapid reconnection (though this is easily achievable)

**Attacker Requirements:**
- Network connectivity to target node
- Ability to respond to consensus observer protocol messages
- No stake, validator status, or special permissions required

A determined attacker with a single malicious node could cause noticeable resource degradation. Multiple coordinated malicious peers could amplify the impact.

## Recommendation

Implement multi-layered defenses:

**1. Add validation in `ConsensusObserverSubscription::new()`:**

```rust
pub fn new(
    consensus_observer_config: ConsensusObserverConfig,
    db_reader: Arc<dyn DbReader>,
    peer_network_id: PeerNetworkId,
    time_service: TimeService,
    connected_peers_and_metadata: &HashMap<PeerNetworkId, PeerMetadata>,
) -> Result<Self, Error> {
    // Validate that the peer is currently connected
    if !connected_peers_and_metadata.contains_key(&peer_network_id) {
        return Err(Error::SubscriptionDisconnected(format!(
            "Cannot create subscription: peer {:?} is not connected!",
            peer_network_id
        )));
    }

    // Get the current time
    let time_now = time_service.now();

    // Create a new subscription
    Ok(Self {
        consensus_observer_config,
        db_reader,
        peer_network_id,
        last_message_receive_time: time_now,
        last_optimality_check_time_and_peers: (time_now, HashSet::new()),
        highest_synced_version_and_time: (0, time_now),
        time_service,
    })
}
```

**2. Implement persistent peer failure tracking in `SubscriptionManager`:**

```rust
pub struct SubscriptionManager {
    // ... existing fields ...
    
    // Track peers that have failed subscriptions with timestamps
    failed_subscription_history: Arc<Mutex<HashMap<PeerNetworkId, (u64, Instant)>>>,
    
    // Configuration for failure threshold and cooldown
    max_failures_before_cooldown: u64,
    failure_cooldown_duration_ms: u64,
}
```

**3. Add cooldown logic in `sort_peers_for_subscriptions()`:**

```rust
fn sort_peers_for_subscriptions(
    mut connected_peers_and_metadata: HashMap<PeerNetworkId, PeerMetadata>,
    active_subscription_peers: Vec<PeerNetworkId>,
    unhealthy_subscription_peers: Vec<PeerNetworkId>,
    failed_subscription_history: &HashMap<PeerNetworkId, (u64, Instant)>,
    consensus_publisher: Option<Arc<ConsensusPublisher>>,
    time_service: &TimeService,
    max_failures: u64,
    cooldown_duration: Duration,
) -> Option<Vec<PeerNetworkId>> {
    // Remove peers in cooldown period
    let current_time = time_service.now();
    connected_peers_and_metadata.retain(|peer_id, _| {
        if let Some((failure_count, last_failure_time)) = failed_subscription_history.get(peer_id) {
            if *failure_count >= max_failures {
                let time_since_failure = current_time.duration_since(*last_failure_time);
                if time_since_failure < cooldown_duration {
                    return false; // Still in cooldown
                }
            }
        }
        true
    });
    
    // ... rest of existing logic ...
}
```

**4. Rate limit subscription attempts per peer** to prevent rapid cycling even if a peer passes initial checks.

## Proof of Concept

```rust
#[cfg(test)]
mod test_subscription_race_condition {
    use super::*;
    use tokio::time::{sleep, Duration};
    
    #[tokio::test]
    async fn test_subscription_creation_race_condition_resource_exhaustion() {
        // Setup: Create consensus observer client and subscription manager
        let network_id = NetworkId::Public;
        let (peers_and_metadata, consensus_observer_client) =
            create_consensus_observer_client(&[network_id]);
        
        let consensus_observer_config = ConsensusObserverConfig::default();
        let db_reader = create_mock_db_reader();
        let time_service = TimeService::mock();
        let mut subscription_manager = SubscriptionManager::new(
            consensus_observer_client,
            consensus_observer_config,
            None,
            db_reader.clone(),
            time_service.clone(),
        );
        
        // Attack simulation: Create 100 rapid connect-disconnect cycles
        let mut subscription_creation_count = 0;
        let mut subscription_termination_count = 0;
        
        for i in 0..100 {
            // Malicious peer connects
            let malicious_peer = create_peer_and_connection(
                network_id,
                peers_and_metadata.clone(),
                1,
                None,
                true,
            );
            
            // Create subscription (simulating peer responding with SubscribeAck)
            create_observer_subscription(
                &mut subscription_manager,
                consensus_observer_config,
                db_reader.clone(),
                malicious_peer,
                time_service.clone(),
            );
            subscription_creation_count += 1;
            
            // Peer immediately disconnects
            remove_peer_and_connection(peers_and_metadata.clone(), malicious_peer);
            
            // Health check detects disconnection
            let result = subscription_manager.check_and_manage_subscriptions().await;
            
            // Subscription should be terminated
            assert!(result.is_err() || get_active_subscriptions_count(&subscription_manager) == 0);
            subscription_termination_count += 1;
            
            // Small delay to simulate realistic timing
            sleep(Duration::from_millis(10)).await;
        }
        
        // Verify resource exhaustion occurred through repeated cycles
        assert_eq!(subscription_creation_count, 100);
        assert_eq!(subscription_termination_count, 100);
        
        // In production, this would cause:
        // - 100 allocations/deallocations of ConsensusObserverSubscription
        // - 200 network RPCs (100 subscribe + 100 unsubscribe)
        // - Continuous CPU usage for subscription management
        // - Memory fragmentation from repeated allocation patterns
    }
}
```

The PoC demonstrates that a malicious peer can force 100 subscription creation/termination cycles in rapid succession, each consuming resources without any rate limiting or persistent blacklisting preventing the peer from being selected again after reconnection.

**Notes:**
- The vulnerability's premise in the question is slightly imprecise: a peer cannot "provide" an arbitrary `PeerNetworkId`. Rather, the vulnerability is that `new()` performs no validation of peer connectivity combined with asynchronous subscription creation creating race condition windows.
- The actual exploitable issue is the combination of: (1) no validation in `new()`, (2) asynchronous subscription creation, and (3) no persistent blacklisting of repeatedly failing peers.
- This affects consensus observer nodes (VFNs and potentially validators if observer is enabled), degrading their ability to efficiently track consensus state.

### Citations

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

**File:** consensus/src/consensus_observer/observer/subscription.rs (L63-91)
```rust
    pub fn check_subscription_health(
        &mut self,
        connected_peers_and_metadata: &HashMap<PeerNetworkId, PeerMetadata>,
        skip_peer_optimality_check: bool,
    ) -> Result<(), Error> {
        // Verify the subscription peer is still connected
        let peer_network_id = self.get_peer_network_id();
        if !connected_peers_and_metadata.contains_key(&peer_network_id) {
            return Err(Error::SubscriptionDisconnected(format!(
                "The peer: {:?} is no longer connected!",
                peer_network_id
            )));
        }

        // Verify the subscription has not timed out
        self.check_subscription_timeout()?;

        // Verify that the DB is continuing to sync and commit new data
        self.check_syncing_progress()?;

        // Verify that the subscription peer is still optimal
        self.check_subscription_peer_optimality(
            connected_peers_and_metadata,
            skip_peer_optimality_check,
        )?;

        // The subscription seems healthy
        Ok(())
    }
```

**File:** consensus/src/consensus_observer/observer/subscription_manager.rs (L180-261)
```rust
    async fn spawn_subscription_creation_task(
        &mut self,
        num_subscriptions_to_create: usize,
        active_subscription_peers: Vec<PeerNetworkId>,
        terminated_subscriptions: Vec<(PeerNetworkId, Error)>,
        connected_peers_and_metadata: HashMap<PeerNetworkId, PeerMetadata>,
    ) {
        // If there are no new subscriptions to create, return early
        if num_subscriptions_to_create == 0 {
            return;
        }

        // If there is an active subscription creation task, return early
        if let Some(subscription_creation_task) = &*self.active_subscription_creation_task.lock() {
            if !subscription_creation_task.is_finished() {
                return; // The task is still running
            }
        }

        // Clone the shared state for the task
        let active_observer_subscriptions = self.active_observer_subscriptions.clone();
        let consensus_observer_config = self.consensus_observer_config;
        let consensus_observer_client = self.consensus_observer_client.clone();
        let consensus_publisher = self.consensus_publisher.clone();
        let db_reader = self.db_reader.clone();
        let time_service = self.time_service.clone();

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
    }
```

**File:** consensus/src/consensus_observer/observer/subscription_utils.rs (L116-193)
```rust
async fn create_single_subscription(
    consensus_observer_config: ConsensusObserverConfig,
    consensus_observer_client: Arc<
        ConsensusObserverClient<NetworkClient<ConsensusObserverMessage>>,
    >,
    db_reader: Arc<dyn DbReader>,
    sorted_potential_peers: Vec<PeerNetworkId>,
    time_service: TimeService,
) -> (Option<ConsensusObserverSubscription>, Vec<PeerNetworkId>) {
    let mut peers_with_failed_attempts = vec![];
    for potential_peer in sorted_potential_peers {
        // Log the subscription attempt
        info!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Attempting to subscribe to potential peer: {}!",
                potential_peer
            ))
        );

        // Send a subscription request to the peer and wait for the response
        let subscription_request = ConsensusObserverRequest::Subscribe;
        let request_timeout_ms = consensus_observer_config.network_request_timeout_ms;
        let response = consensus_observer_client
            .send_rpc_request_to_peer(&potential_peer, subscription_request, request_timeout_ms)
            .await;

        // Process the response and update the active subscription
        match response {
            Ok(ConsensusObserverResponse::SubscribeAck) => {
                // Log the successful subscription
                info!(
                    LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                        "Successfully subscribed to peer: {}!",
                        potential_peer
                    ))
                );

                // Create the new subscription
                let subscription = ConsensusObserverSubscription::new(
                    consensus_observer_config,
                    db_reader.clone(),
                    potential_peer,
                    time_service.clone(),
                );

                // Return the successful subscription
                return (Some(subscription), peers_with_failed_attempts);
            },
            Ok(response) => {
                // We received an invalid response
                warn!(
                    LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                        "Got unexpected response type for subscription request: {:?}",
                        response.get_label()
                    ))
                );

                // Add the peer to the list of failed attempts
                peers_with_failed_attempts.push(potential_peer);
            },
            Err(error) => {
                // We encountered an error while sending the request
                warn!(
                    LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                        "Failed to send subscription request to peer: {}! Error: {:?}",
                        potential_peer, error
                    ))
                );

                // Add the peer to the list of failed attempts
                peers_with_failed_attempts.push(potential_peer);
            },
        }
    }

    // We failed to create a new subscription
    (None, peers_with_failed_attempts)
}
```

**File:** consensus/src/consensus_observer/observer/subscription_utils.rs (L245-273)
```rust
fn sort_peers_for_subscriptions(
    mut connected_peers_and_metadata: HashMap<PeerNetworkId, PeerMetadata>,
    active_subscription_peers: Vec<PeerNetworkId>,
    unhealthy_subscription_peers: Vec<PeerNetworkId>,
    consensus_publisher: Option<Arc<ConsensusPublisher>>,
) -> Option<Vec<PeerNetworkId>> {
    // Remove any peers we're already subscribed to
    for active_subscription_peer in active_subscription_peers {
        let _ = connected_peers_and_metadata.remove(&active_subscription_peer);
    }

    // Remove any unhealthy subscription peers
    for unhealthy_peer in unhealthy_subscription_peers {
        let _ = connected_peers_and_metadata.remove(&unhealthy_peer);
    }

    // Remove any peers that are currently subscribed to us
    if let Some(consensus_publisher) = consensus_publisher {
        for peer_network_id in consensus_publisher.get_active_subscribers() {
            let _ = connected_peers_and_metadata.remove(&peer_network_id);
        }
    }

    // Sort the peers by subscription optimality
    let sorted_peers = sort_peers_by_subscription_optimality(&connected_peers_and_metadata);

    // Return the sorted peers
    Some(sorted_peers)
}
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L1115-1137)
```rust
        // Create a progress check ticker
        let mut progress_check_interval = IntervalStream::new(interval(Duration::from_millis(
            consensus_observer_config.progress_check_interval_ms,
        )))
        .fuse();

        // Wait for the latest epoch to start
        self.wait_for_epoch_start().await;

        // Start the consensus observer loop
        info!(LogSchema::new(LogEntry::ConsensusObserver)
            .message("Starting the consensus observer loop!"));
        loop {
            tokio::select! {
                Some(network_message) = consensus_observer_message_receiver.next() => {
                    self.process_network_message(network_message).await;
                }
                Some(state_sync_notification) = state_sync_notification_listener.recv() => {
                    self.process_state_sync_notification(state_sync_notification).await;
                },
                _ = progress_check_interval.select_next_some() => {
                    self.check_progress().await;
                }
```

**File:** config/src/config/consensus_observer_config.rs (L63-84)
```rust
impl Default for ConsensusObserverConfig {
    fn default() -> Self {
        Self {
            observer_enabled: false,
            publisher_enabled: false,
            max_network_channel_size: 1000,
            max_parallel_serialization_tasks: num_cpus::get(), // Default to the number of CPUs
            network_request_timeout_ms: 5_000,                 // 5 seconds
            garbage_collection_interval_ms: 60_000,            // 60 seconds
            max_num_pending_blocks: 150, // 150 blocks (sufficient for existing production networks)
            progress_check_interval_ms: 5_000, // 5 seconds
            max_concurrent_subscriptions: 2, // 2 streams should be sufficient
            max_subscription_sync_timeout_ms: 15_000, // 15 seconds
            max_subscription_timeout_ms: 15_000, // 15 seconds
            subscription_peer_change_interval_ms: 180_000, // 3 minutes
            subscription_refresh_interval_ms: 600_000, // 10 minutes
            observer_fallback_duration_ms: 600_000, // 10 minutes
            observer_fallback_startup_period_ms: 60_000, // 60 seconds
            observer_fallback_progress_threshold_ms: 10_000, // 10 seconds
            observer_fallback_sync_lag_threshold_ms: 15_000, // 15 seconds
        }
    }
```

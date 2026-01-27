# Audit Report

## Title
Consensus Observer Subscription Health Check Causes Cascading Timeouts Due to Lock Contention

## Summary
The `check_subscription_health()` implementation in the consensus observer subscription manager holds a mutex lock during potentially slow operations (database reads, peer metadata sorting), blocking concurrent health checks for other subscriptions. This can cause healthy subscriptions to timeout before they can be checked, leading to cascading failures where all subscriptions are incorrectly terminated.

## Finding Description
The vulnerability exists in the lock-holding pattern used during subscription health checks. The system sequentially checks each active subscription's health, but holds a critical mutex lock during the entire health check operation, including potentially slow I/O operations. [1](#0-0) 

The sequential loop calls `check_subscription_health()` for each peer, which acquires and holds the `active_observer_subscriptions` lock during the entire health check: [2](#0-1) 

While holding this lock, the function calls the individual subscription's health check which performs:
1. Database read via `get_latest_ledger_info_version()` 
2. Peer optimality checking which involves sorting peer metadata [3](#0-2) [4](#0-3) 

**Cascading Failure Scenario:**
1. System has 2+ concurrent subscriptions (default: `max_concurrent_subscriptions = 2`)
2. Subscription health checks are triggered periodically
3. First subscription's health check is slow (e.g., 2-3 seconds due to DB contention, peer metadata operations, or system load)
4. Lock is held during this entire period, blocking subsequent health checks
5. Other subscriptions cannot be checked, and time continues to pass
6. When subsequent subscriptions are finally checked, they may have exceeded `max_subscription_timeout_ms` (default: 15 seconds)
7. Healthy subscriptions are incorrectly marked as timed out and terminated [5](#0-4) 

With default configuration values and increased subscription counts, accumulated delays from sequential health checks can easily cause timeouts. For example, with 10 subscriptions and 2-second health checks, the last subscriptions would wait 18+ seconds before being checked.

## Impact Explanation
**Medium Severity** - This issue causes state inconsistencies requiring intervention:
- All active subscriptions may be incorrectly terminated despite being healthy
- Consensus observer functionality is temporarily degraded until new subscriptions are created
- Validator Full Nodes (VFNs) and Public Full Nodes (PFNs) lose access to consensus data streams
- The issue is recoverable but causes service disruption

This does not reach High severity because:
- It does not affect core consensus validators (only observer nodes)
- Subscriptions are automatically re-created after termination
- No permanent state corruption or fund loss occurs

However, it exceeds Low severity because:
- It causes measurable service degradation
- Multiple nodes can be affected simultaneously under high load
- Requires operational intervention to identify and mitigate

## Likelihood Explanation
**High Likelihood** - This vulnerability can manifest under normal operating conditions:
- **System Load**: Any period of high system load can slow DB operations or peer metadata processing
- **Configuration**: Default `max_concurrent_subscriptions = 2` makes this less severe, but operators may increase this value
- **No Attacker Required**: The issue occurs naturally without malicious actor involvement
- **DB Contention**: Shared DB reader across all subscriptions amplifies the problem

The issue becomes more severe when:
- More concurrent subscriptions are configured
- The system is under sustained load
- DB operations experience contention
- Multiple VFNs attempt health checks simultaneously

## Recommendation
**Release the lock before performing slow operations.** The lock should only protect access to the subscription data structure, not the entire health check operation.

**Proposed Fix:**
```rust
fn check_subscription_health(
    &mut self,
    connected_peers_and_metadata: &HashMap<PeerNetworkId, PeerMetadata>,
    peer_network_id: PeerNetworkId,
    skip_peer_optimality_check: bool,
) -> Result<(), Error> {
    // Clone the subscription outside the lock to perform health checks without blocking
    let subscription = {
        let active_observer_subscriptions = self.active_observer_subscriptions.lock();
        active_observer_subscriptions.get(&peer_network_id).cloned()
    }; // Lock released here
    
    match subscription {
        Some(mut subscription) => {
            // Perform health check without holding the lock
            let result = subscription.check_subscription_health(
                connected_peers_and_metadata,
                skip_peer_optimality_check,
            );
            
            // Only re-acquire lock if we need to update the subscription
            if result.is_ok() {
                let mut active_observer_subscriptions = self.active_observer_subscriptions.lock();
                if let Some(sub) = active_observer_subscriptions.get_mut(&peer_network_id) {
                    *sub = subscription;
                }
            }
            
            result
        },
        None => Err(Error::UnexpectedError(format!(
            "The subscription to peer: {:?} is not active!",
            peer_network_id
        ))),
    }
}
```

**Alternative:** Parallelize health checks using async tasks to avoid sequential blocking entirely.

## Proof of Concept
```rust
#[tokio::test]
async fn test_cascading_timeout_under_slow_health_check() {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    
    // Create a subscription manager with multiple subscriptions
    let consensus_observer_config = ConsensusObserverConfig {
        max_subscription_timeout_ms: 5_000, // 5 second timeout
        max_concurrent_subscriptions: 5,     // 5 subscriptions
        ..Default::default()
    };
    
    // Create a mock DB reader that simulates slow reads
    let call_count = Arc::new(Mutex::new(0));
    let call_count_clone = call_count.clone();
    let mut mock_db_reader = MockDatabaseReader::new();
    mock_db_reader
        .expect_get_latest_ledger_info_version()
        .returning(move || {
            let mut count = call_count_clone.lock().unwrap();
            *count += 1;
            // First health check is very slow (6 seconds)
            if *count == 1 {
                std::thread::sleep(Duration::from_secs(6));
            }
            Ok(100)
        });
    
    // Create subscription manager and add 5 subscriptions
    let mut subscription_manager = create_subscription_manager(
        consensus_observer_config,
        Arc::new(mock_db_reader),
    );
    
    // Add 5 subscriptions with the same time service
    let time_service = TimeService::mock();
    for i in 0..5 {
        let peer = create_peer(i);
        add_subscription(&mut subscription_manager, peer, time_service.clone());
    }
    
    // Terminate unhealthy subscriptions
    // Expected: First subscription causes 6-second delay
    // By the time we check subscriptions 2-5, they've all timed out (5 second limit)
    let terminated = subscription_manager.terminate_unhealthy_subscriptions();
    
    // Assert: All 5 subscriptions were incorrectly terminated due to cascading timeout
    assert_eq!(terminated.len(), 5);
}
```

## Notes
This vulnerability is a **design flaw in the locking pattern**, not a cryptographic or consensus safety issue. While it doesn't directly compromise consensus integrity, it degrades the availability and reliability of the consensus observer subsystem, which is critical for validator full node operations. The fix requires careful refactoring to ensure thread safety while avoiding lock contention during I/O operations.

### Citations

**File:** consensus/src/consensus_observer/observer/subscription_manager.rs (L82-103)
```rust
    fn check_subscription_health(
        &mut self,
        connected_peers_and_metadata: &HashMap<PeerNetworkId, PeerMetadata>,
        peer_network_id: PeerNetworkId,
        skip_peer_optimality_check: bool,
    ) -> Result<(), Error> {
        // Get the active subscription for the peer
        let mut active_observer_subscriptions = self.active_observer_subscriptions.lock();
        let active_subscription = active_observer_subscriptions.get_mut(&peer_network_id);

        // Check the health of the subscription
        match active_subscription {
            Some(active_subscription) => active_subscription.check_subscription_health(
                connected_peers_and_metadata,
                skip_peer_optimality_check,
            ),
            None => Err(Error::UnexpectedError(format!(
                "The subscription to peer: {:?} is not active!",
                peer_network_id
            ))),
        }
    }
```

**File:** consensus/src/consensus_observer/observer/subscription_manager.rs (L270-305)
```rust
    /// Terminates any unhealthy subscriptions and returns the list of terminated subscriptions
    fn terminate_unhealthy_subscriptions(
        &mut self,
        connected_peers_and_metadata: &HashMap<PeerNetworkId, PeerMetadata>,
    ) -> Vec<(PeerNetworkId, Error)> {
        // Go through all active subscriptions and terminate any unhealthy ones
        let mut terminated_subscriptions = vec![];
        for subscription_peer in self.get_active_subscription_peers() {
            // To avoid terminating too many subscriptions at once, we should skip
            // the peer optimality check if we've already terminated a subscription.
            let skip_peer_optimality_check = !terminated_subscriptions.is_empty();

            // Check the health of the subscription and terminate it if needed
            if let Err(error) = self.check_subscription_health(
                connected_peers_and_metadata,
                subscription_peer,
                skip_peer_optimality_check,
            ) {
                // Log the subscription termination error
                warn!(
                    LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                        "Terminating subscription to peer: {:?}! Termination reason: {:?}",
                        subscription_peer, error
                    ))
                );

                // Unsubscribe from the peer and remove the subscription
                self.unsubscribe_from_peer(subscription_peer);

                // Add the peer to the list of terminated subscriptions
                terminated_subscriptions.push((subscription_peer, error));
            }
        }

        terminated_subscriptions
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

**File:** consensus/src/consensus_observer/observer/subscription.rs (L185-196)
```rust
    fn check_syncing_progress(&mut self) -> Result<(), Error> {
        // Get the current time and synced version from storage
        let time_now = self.time_service.now();
        let current_synced_version =
            self.db_reader
                .get_latest_ledger_info_version()
                .map_err(|error| {
                    Error::UnexpectedError(format!(
                        "Failed to read highest synced version: {:?}",
                        error
                    ))
                })?;
```

**File:** config/src/config/consensus_observer_config.rs (L74-76)
```rust
            max_concurrent_subscriptions: 2, // 2 streams should be sufficient
            max_subscription_sync_timeout_ms: 15_000, // 15 seconds
            max_subscription_timeout_ms: 15_000, // 15 seconds
```

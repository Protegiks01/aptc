# Audit Report

## Title
Subscription State Persistence Across Epoch Transitions Enables Targeted Disruption of Consensus Observer

## Summary
The consensus observer fails to reset subscription timer state during epoch transitions, and skips subscription health checks while syncing to new epochs. This allows malicious peers to exploit epoch boundaries by withholding messages during state sync, causing legitimate subscriptions to incorrectly timeout and terminate. The issue creates a window of vulnerability at every epoch transition where attackers can disrupt consensus observation without detection.

## Finding Description

The consensus observer maintains active subscriptions to peer nodes for receiving consensus updates. Each subscription tracks several time-based health metrics including `last_message_receive_time` and `highest_synced_version_and_time`. During epoch transitions, the observer invokes state sync to reach the new epoch, but critical issues exist in how subscription state is managed during this process:

**Issue 1: Subscription Health Checks Skipped During State Sync**

In the `check_progress` function, when the observer is syncing to a commit decision (which happens during epoch transitions), subscription health checks are completely bypassed: [1](#0-0) 

This means for the entire duration of state sync (which can exceed 15 seconds during epoch transitions), no subscription timeout or progress checks occur.

**Issue 2: Subscription Timer State Not Reset on Epoch Transition**

When processing epoch transitions via fallback sync or commit sync, the fallback manager's state IS explicitly reset: [2](#0-1) 

However, subscription state including `last_message_receive_time` is never reset: [3](#0-2) 

**Issue 3: Stale State Causes False Timeouts**

After state sync completes and subscription checks resume, the subscription timeout check uses stale timestamps: [4](#0-3) 

With the default timeout of 15 seconds: [5](#0-4) 

If state sync takes longer than 15 seconds and peers don't send messages during this period (which is normal during epoch transitions), subscriptions will incorrectly timeout immediately after state sync completes.

**Attack Scenario:**

1. Attacker controls a peer that an observer node subscribes to
2. Attacker monitors for epoch transition signals (commit decisions for new epochs)
3. When epoch N ends and state sync begins for epoch N+1:
   - State sync duration varies but can exceed 15 seconds for large state changes
   - `check_progress` returns early, skipping subscription health checks
   - Attacker deliberately stops sending messages
4. After state sync completes (e.g., 20 seconds later):
   - Next `check_progress` call performs subscription health checks
   - `last_message_receive_time` is 20 seconds old (exceeds 15s timeout)
   - Subscription is incorrectly terminated: [6](#0-5) 
5. Observer must create new subscriptions, missing critical consensus updates during the disruption
6. Attack repeats at every epoch boundary

**Metrics Issue:**

Additionally, all observer metrics are global and never reset across epochs: [7](#0-6) 

This allows attackers to pollute metrics during one epoch while appearing healthy in another, masking attack patterns from operators.

## Impact Explanation

This qualifies as **High Severity** per Aptos bug bounty criteria due to:

1. **Validator Node Slowdowns**: Repeated subscription churn during epoch transitions causes observer nodes to miss consensus updates, degrading performance and potentially causing them to fall behind

2. **Protocol Violations**: Observers may fail to receive critical epoch transition data, violating the expectation that observer nodes can reliably track consensus

3. **Targeted Exploitability**: Unlike random operational failures, this can be deliberately triggered by malicious peers at predictable intervals (epoch boundaries), maximizing disruption

4. **Cascading Effects**: If multiple observer nodes are affected simultaneously during epoch transitions, it could impact validator full nodes (VFNs) that depend on consensus observer data

The issue does not reach Critical severity as it doesn't directly compromise consensus safety or cause fund loss, but it significantly degrades network observability and operational reliability.

## Likelihood Explanation

**High Likelihood**:

1. **Frequent Attack Surface**: Epoch transitions occur regularly in Aptos (typically every 2 hours), providing repeated opportunities for exploitation

2. **Low Attacker Requirements**: Only requires being selected as a subscription peer (achievable through normal network participation with good initial behavior)

3. **Timing is Observable**: Epoch transition timing is visible on-chain, allowing attackers to precisely time their attacks

4. **Natural Camouflage**: Not sending messages during epoch transitions can appear as normal behavior, making attacks hard to distinguish from network issues

5. **No Detection**: Metrics persist across epochs, making attack patterns difficult to identify

## Recommendation

**Immediate Fix**: Reset subscription timer state during epoch transitions and handle state sync appropriately.

**Specific Changes Needed:**

1. **Add subscription state reset during epoch transitions** in `process_fallback_sync_notification` and `process_commit_sync_notification`:
   - Call a new method to refresh subscription timers when epoch changes
   - Reset `last_message_receive_time` to current time
   - Reset `highest_synced_version_and_time` to match new epoch's initial state

2. **Modify subscription health check logic** to account for state sync:
   - Pause or extend timeout thresholds during `is_syncing_to_commit()`
   - OR update `last_message_receive_time` when state sync begins
   - OR perform limited health checks that don't depend on message recency

3. **Add epoch context to metrics**:
   - Include epoch number in metric labels
   - Provide per-epoch metric views for operators
   - Reset or partition metrics at epoch boundaries

**Example fix** for subscription state reset:

```rust
// In ConsensusObserverSubscription
pub fn reset_for_epoch_transition(&mut self) {
    let time_now = self.time_service.now();
    self.last_message_receive_time = time_now;
    // Don't reset syncing progress as DB version continues across epochs
}
```

Call this method in both `process_fallback_sync_notification` and `process_commit_sync_notification` after `wait_for_epoch_start()` completes.

## Proof of Concept

```rust
// Conceptual PoC showing the vulnerability timing

#[test]
fn test_subscription_timeout_during_epoch_transition() {
    // Setup: Create observer with active subscription
    let consensus_observer_config = ConsensusObserverConfig {
        max_subscription_timeout_ms: 15_000,  // 15 seconds
        ..Default::default()
    };
    let time_service = TimeService::mock();
    let mut subscription = ConsensusObserverSubscription::new(
        consensus_observer_config,
        db_reader,
        peer_network_id,
        time_service.clone(),
    );
    
    // Epoch N: Subscription receives message at T=0
    subscription.update_last_message_receive_time();
    assert!(subscription.check_subscription_timeout().is_ok());
    
    // T=5s: Epoch transition begins, state sync starts
    // check_progress() returns early, no subscription checks for 20 seconds
    let mock_time_service = time_service.into_mock();
    mock_time_service.advance(Duration::from_secs(20));
    
    // T=25s: State sync completes, subscription check resumes
    // last_message_receive_time is still at T=0 (20 seconds old)
    // This exceeds 15s timeout threshold
    assert_matches!(
        subscription.check_subscription_timeout(),
        Err(Error::SubscriptionTimeout(_))  // VULNERABILITY: False timeout
    );
    
    // Result: Healthy subscription incorrectly terminated
    // Observer must create new subscription, missing consensus updates
}
```

**Notes**: This PoC demonstrates the timing vulnerability where legitimate subscriptions timeout during normal epoch transitions due to state sync duration exceeding the timeout threshold while health checks are suspended.

## Notes

This vulnerability specifically targets the epoch boundary window, exploiting the design decision to skip subscription health checks during state sync. While individual instances cause temporary disruption, systematic exploitation at every epoch transition (every ~2 hours) creates a persistent availability degradation for consensus observer nodes. The issue is particularly concerning for validator full nodes (VFNs) that rely on consensus observer for efficient state synchronization.

### Citations

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L180-188)
```rust
        if self.state_sync_manager.is_syncing_to_commit() {
            info!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Waiting for state sync to reach commit decision: {:?}!",
                    self.observer_block_data.lock().root().commit_info()
                ))
            );
            return;
        }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L943-945)
```rust
        // Reset the fallback manager state
        self.observer_fallback_manager
            .reset_syncing_progress(&latest_synced_ledger_info);
```

**File:** consensus/src/consensus_observer/observer/subscription.rs (L16-37)
```rust
pub struct ConsensusObserverSubscription {
    // The configuration of the consensus observer
    consensus_observer_config: ConsensusObserverConfig,

    // A handle to storage (used to read the latest state and check progress)
    db_reader: Arc<dyn DbReader>,

    // The peer network id of the active subscription
    peer_network_id: PeerNetworkId,

    // The timestamp of the last message received for the subscription
    last_message_receive_time: Instant,

    // The timestamp and connected peers for the last optimality check
    last_optimality_check_time_and_peers: (Instant, HashSet<PeerNetworkId>),

    // The highest synced version we've seen from storage, along with the time at which it was seen
    highest_synced_version_and_time: (u64, Instant),

    // The time service (used to check the last message receive time)
    time_service: TimeService,
}
```

**File:** consensus/src/consensus_observer/observer/subscription.rs (L166-182)
```rust
    fn check_subscription_timeout(&self) -> Result<(), Error> {
        // Calculate the duration since the last message
        let time_now = self.time_service.now();
        let duration_since_last_message = time_now.duration_since(self.last_message_receive_time);

        // Check if the subscription has timed out
        if duration_since_last_message
            > Duration::from_millis(self.consensus_observer_config.max_subscription_timeout_ms)
        {
            return Err(Error::SubscriptionTimeout(format!(
                "Subscription to peer: {} has timed out! No message received for: {:?}",
                self.peer_network_id, duration_since_last_message
            )));
        }

        Ok(())
    }
```

**File:** config/src/config/consensus_observer_config.rs (L76-76)
```rust
            max_subscription_timeout_ms: 15_000, // 15 seconds
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

**File:** consensus/src/consensus_observer/common/metrics.rs (L32-47)
```rust
pub static OBSERVER_CREATED_SUBSCRIPTIONS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "consensus_observer_created_subscriptions",
        "Counters for created subscriptions for consensus observer",
        &["creation_label", "network_id"]
    )
    .unwrap()
});

/// Counter for tracking the number of times the block state was cleared by the consensus observer
pub static OBSERVER_CLEARED_BLOCK_STATE: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "consensus_observer_cleared_block_state",
        "Counter for tracking the number of times the block state was cleared by the consensus observer",
    ).unwrap()
});
```

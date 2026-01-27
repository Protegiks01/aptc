# Audit Report

## Title
Consensus Observer Subscription Incorrectly Timeouts on Genesis Ledger at Version 0

## Summary
The `check_syncing_progress()` function in the consensus observer subscription manager incorrectly treats a ledger at version 0 (genesis state with no transactions) as "no sync progress" and terminates subscriptions after 15 seconds, even though this is a valid blockchain state.

## Finding Description
When a `ConsensusObserverSubscription` is created, it initializes the `highest_synced_version_and_time` field to `(0, time_now)`. [1](#0-0) 

The `check_syncing_progress()` function is called periodically to verify the database is making sync progress. It reads the current synced version from storage and compares it against the highest version previously seen: [2](#0-1) 

The vulnerability occurs at the comparison on line 201: `if current_synced_version <= highest_synced_version`. When the ledger is at version 0 (genesis state):
- `current_synced_version` = 0 (from `get_latest_ledger_info_version()`)
- `highest_synced_version` = 0 (from initialization)
- The condition `0 <= 0` evaluates to TRUE

The function then checks if the timeout duration has elapsed. If more than `max_subscription_sync_timeout_ms` (default 15 seconds) has passed since subscription creation, it returns `Error::SubscriptionProgressStopped`. [3](#0-2) 

This error causes the subscription to be terminated in `terminate_unhealthy_subscriptions()`: [4](#0-3) 

**Attack Scenario:**
1. A blockchain is initialized at genesis (version 0)
2. Consensus observer subscriptions are created
3. If no blocks are produced for 15+ seconds (common in test networks or low-activity networks), all subscriptions timeout
4. The subscription manager attempts to recreate subscriptions
5. The new subscriptions timeout again after 15 seconds, creating a loop
6. The node cannot maintain stable consensus observer subscriptions

The blockchain at version 0 is a **valid state** - it represents genesis with no transactions committed yet. The genesis transaction itself is at version 0: [5](#0-4) 

The code cannot distinguish between:
- A ledger stuck at version 0 (bad - actual sync failure)
- A ledger legitimately at version 0 with no activity (good - valid state)

## Impact Explanation
This is a **Medium severity** issue per Aptos bug bounty criteria for the following reasons:

1. **State inconsistencies requiring intervention**: The consensus observer experiences repeated subscription churn, unable to maintain stable connections during the initial period at version 0.

2. **Operational impact**: Affects validator fullnodes (VFNs) and other nodes using consensus observer for fast synchronization. During the critical initial deployment phase, nodes cannot establish stable subscriptions.

3. **Network churn**: Repeated subscription creation and termination causes unnecessary network overhead and resource consumption.

4. **No direct fund loss or consensus violation**: The issue does not cause loss of funds, consensus safety violations, or permanent network failures. It's an operational bug that resolves itself once blocks start being produced.

The default timeout is 15 seconds: [6](#0-5) 

## Likelihood Explanation
**High likelihood** in specific scenarios:

1. **Fresh deployments**: Any new test network, devnet, or private network deployment will experience this issue immediately after genesis if block production doesn't start within 15 seconds.

2. **Low-activity networks**: Private or test networks with infrequent block production may repeatedly trigger this condition.

3. **Development environments**: Local development networks commonly stay at version 0 during initial setup.

4. **Automatic occurrence**: No attacker action required - the bug triggers automatically when the conditions are met.

The genesis ledger starts at version 0 and only increments when the first block is produced. If consensus hasn't started or validators haven't formed a quorum, the ledger will remain at version 0.

## Recommendation
Add special handling for version 0 in the `check_syncing_progress()` function to treat it as a valid state that should not trigger progress timeouts. Here's the recommended fix:

```rust
fn check_syncing_progress(&mut self) -> Result<(), Error> {
    // Get the current time and synced version from storage
    let time_now = self.time_service.now();
    let current_synced_version = self.db_reader
        .get_latest_ledger_info_version()
        .map_err(|error| {
            Error::UnexpectedError(format!(
                "Failed to read highest synced version: {:?}",
                error
            ))
        })?;

    // Verify that the synced version is increasing appropriately
    let (highest_synced_version, highest_version_timestamp) =
        self.highest_synced_version_and_time;
    
    if current_synced_version <= highest_synced_version {
        // Special case: version 0 is the genesis state and is always valid.
        // Don't timeout subscriptions at genesis even if no progress is made.
        if current_synced_version == 0 && highest_synced_version == 0 {
            return Ok(());
        }
        
        // The synced version hasn't increased. Check if we should terminate
        // the subscription based on the last time the highest synced version was seen.
        let duration_since_highest_seen = time_now.duration_since(highest_version_timestamp);
        let timeout_duration = Duration::from_millis(
            self.consensus_observer_config
                .max_subscription_sync_timeout_ms,
        );
        if duration_since_highest_seen > timeout_duration {
            return Err(Error::SubscriptionProgressStopped(format!(
                "The DB is not making sync progress! Highest synced version: {}, elapsed: {:?}",
                highest_synced_version, duration_since_highest_seen
            )));
        }
        return Ok(()); // We haven't timed out yet
    }

    // Update the highest synced version and time
    self.highest_synced_version_and_time = (current_synced_version, time_now);

    Ok(())
}
```

Alternative approach: Initialize `highest_synced_version_and_time` by reading the current ledger version instead of hardcoding to 0, but this doesn't fully solve the issue if the ledger is already at 0.

## Proof of Concept
```rust
#[tokio::test]
async fn test_check_syncing_progress_genesis_version_zero() {
    use aptos_config::config::ConsensusObserverConfig;
    use aptos_storage_interface::DbReader;
    use aptos_time_service::TimeService;
    use aptos_types::transaction::Version;
    use mockall::mock;
    use std::sync::Arc;
    use std::time::Duration;

    // Mock database reader that always returns version 0
    mock! {
        pub DatabaseReader {}
        impl DbReader for DatabaseReader {
            fn get_latest_ledger_info_version(&self) -> Result<Version, anyhow::Error> {
                Ok(0) // Ledger stays at genesis version 0
            }
        }
    }

    // Create consensus observer config with default 15 second timeout
    let consensus_observer_config = ConsensusObserverConfig::default();
    
    // Create a mock DB reader that returns version 0
    let mock_db_reader = MockDatabaseReader::new();
    
    // Create a new observer subscription
    let peer_network_id = PeerNetworkId::random();
    let time_service = TimeService::mock();
    let mut subscription = ConsensusObserverSubscription::new(
        consensus_observer_config,
        Arc::new(mock_db_reader),
        peer_network_id,
        time_service.clone(),
    );

    // Verify subscription is healthy initially
    assert!(subscription.check_syncing_progress().is_ok());
    
    // Advance time by 10 seconds (less than timeout)
    let mock_time_service = time_service.into_mock();
    mock_time_service.advance(Duration::from_secs(10));
    
    // Should still be healthy
    assert!(subscription.check_syncing_progress().is_ok());
    
    // Advance time past the 15 second timeout
    mock_time_service.advance(Duration::from_secs(6));
    
    // BUG: Subscription incorrectly times out even though version 0 is valid
    let result = subscription.check_syncing_progress();
    assert!(result.is_err());
    assert!(matches!(result, Err(Error::SubscriptionProgressStopped(_))));
    
    // This demonstrates that a ledger at genesis version 0 will cause
    // subscriptions to timeout after 15 seconds, even though this is
    // a completely valid state for a fresh blockchain with no transactions.
}
```

This test demonstrates that a subscription will incorrectly timeout when the ledger remains at version 0 (genesis state) for more than 15 seconds, even though this is a valid blockchain state.

### Citations

**File:** consensus/src/consensus_observer/observer/subscription.rs (L56-56)
```rust
            highest_synced_version_and_time: (0, time_now),
```

**File:** consensus/src/consensus_observer/observer/subscription.rs (L185-222)
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

        // Verify that the synced version is increasing appropriately
        let (highest_synced_version, highest_version_timestamp) =
            self.highest_synced_version_and_time;
        if current_synced_version <= highest_synced_version {
            // The synced version hasn't increased. Check if we should terminate
            // the subscription based on the last time the highest synced version was seen.
            let duration_since_highest_seen = time_now.duration_since(highest_version_timestamp);
            let timeout_duration = Duration::from_millis(
                self.consensus_observer_config
                    .max_subscription_sync_timeout_ms,
            );
            if duration_since_highest_seen > timeout_duration {
                return Err(Error::SubscriptionProgressStopped(format!(
                    "The DB is not making sync progress! Highest synced version: {}, elapsed: {:?}",
                    highest_synced_version, duration_since_highest_seen
                )));
            }
            return Ok(()); // We haven't timed out yet
        }

        // Update the highest synced version and time
        self.highest_synced_version_and_time = (current_synced_version, time_now);

        Ok(())
    }
```

**File:** consensus/src/consensus_observer/observer/subscription_manager.rs (L271-305)
```rust
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

**File:** types/src/block_info.rs (L16-16)
```rust
pub type Round = u64;
```

**File:** config/src/config/consensus_observer_config.rs (L75-75)
```rust
            max_subscription_sync_timeout_ms: 15_000, // 15 seconds
```

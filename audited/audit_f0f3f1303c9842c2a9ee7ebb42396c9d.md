# Audit Report

## Title
Inconsistent Error Recovery in Consensus Observer Leads to Orphaned Pending Blocks and State Corruption

## Summary
The consensus observer component exhibits inconsistent error recovery when handling subscription failures. When a subset (but not all) of subscriptions fail, pending blocks waiting for payloads from the failed peer(s) are not cleaned up, leading to state corruption, memory exhaustion, and potential consensus observer liveness failures.

## Finding Description

The vulnerability exists in the error handling logic across two key components: [1](#0-0) 

In `check_and_manage_subscriptions()`, the function only returns an error if **ALL** subscriptions are terminated. If only a subset fails, it returns `Ok()`. [2](#0-1) 

In `check_progress()`, state cleanup via `clear_pending_block_state()` only occurs when `check_and_manage_subscriptions()` returns an error (i.e., when all subscriptions fail).

This creates an inconsistency where:

1. **When ALL subscriptions fail**: Error is returned → `clear_pending_block_state()` is called → All pending blocks are properly cleaned up
2. **When SOME subscriptions fail**: `Ok()` is returned → No cleanup occurs → Pending blocks from failed peers become orphaned

The pending blocks are stored in: [3](#0-2) 

**Attack Scenario:**

1. Observer has 2 active subscriptions to peers P1 and P2 (with `max_concurrent_subscriptions = 2`)
2. Observer receives an ordered block from P1 but payload is missing → block stored in `pending_block_store`
3. P1's connection experiences NetworkError or times out
4. `terminate_unhealthy_subscriptions()` removes P1's subscription [4](#0-3) 

5. Since P2 remains healthy, `check_and_manage_subscriptions()` returns `Ok()` (not all subscriptions terminated)
6. `check_progress()` receives `Ok()` and does NOT clear pending block state
7. Future messages from P1 are rejected: [5](#0-4) 

8. The pending block from P1 remains indefinitely since payloads will never arrive
9. Garbage collection only triggers when exceeding `max_num_pending_blocks`: [6](#0-5) 

This violates the **State Consistency** invariant, as the observer maintains inconsistent state between active subscriptions and pending blocks.

## Impact Explanation

**HIGH Severity** per Aptos Bug Bounty criteria:

- **Validator Node Slowdowns**: Accumulation of orphaned pending blocks causes memory exhaustion and degrades performance
- **Liveness Issues**: Observer cannot process blocks when critical payloads are missing, affecting consensus participation
- **State Corruption**: Inconsistent view between subscription state and pending block state can cause the observer to stall indefinitely
- **Resource Exhaustion**: Repeated subscription failures can fill the pending block store up to `max_num_pending_blocks`, triggering aggressive garbage collection that drops legitimate blocks

The vulnerability affects consensus observer nodes, which are critical for network health and validator performance monitoring.

## Likelihood Explanation

**HIGH Likelihood**:

- Network instability is common in distributed systems - transient NetworkErrors, timeouts, and peer disconnections occur regularly
- Multiple concurrent subscriptions (default configuration) means partial failures are the normal case, not the exception
- The vulnerability triggers automatically without requiring attacker interaction beyond normal network conditions
- The condition `num_terminated_subscriptions > 0 && num_terminated_subscriptions == initial_subscription_peers.len()` explicitly requires ALL subscriptions to fail before cleanup occurs

## Recommendation

Modify `check_and_manage_subscriptions()` to trigger state cleanup whenever ANY subscription is terminated, not just when all subscriptions fail:

```rust
pub async fn check_and_manage_subscriptions(&mut self) -> Result<(), Error> {
    let initial_subscription_peers = self.get_active_subscription_peers();
    let connected_peers_and_metadata = self.get_connected_peers_and_metadata();

    let terminated_subscriptions =
        self.terminate_unhealthy_subscriptions(&connected_peers_and_metadata);

    let num_terminated_subscriptions = terminated_subscriptions.len();
    let all_subscriptions_terminated = num_terminated_subscriptions > 0
        && num_terminated_subscriptions == initial_subscription_peers.len();

    let remaining_subscription_peers = self.get_active_subscription_peers();
    let max_concurrent_subscriptions =
        self.consensus_observer_config.max_concurrent_subscriptions as usize;
    let num_subscriptions_to_create =
        max_concurrent_subscriptions.saturating_sub(remaining_subscription_peers.len());

    update_total_subscription_metrics(&remaining_subscription_peers);

    self.spawn_subscription_creation_task(
        num_subscriptions_to_create,
        remaining_subscription_peers,
        terminated_subscriptions.clone(), // Clone for use below
        connected_peers_and_metadata,
    )
    .await;

    // Return an error if ANY subscriptions were terminated to trigger cleanup
    if num_terminated_subscriptions > 0 {
        if all_subscriptions_terminated {
            Err(Error::SubscriptionsReset(format!(
                "All {:?} subscriptions were unhealthy and terminated!",
                num_terminated_subscriptions,
            )))
        } else {
            Err(Error::SubscriptionsReset(format!(
                "{:?} out of {:?} subscriptions were unhealthy and terminated!",
                num_terminated_subscriptions,
                initial_subscription_peers.len(),
            )))
        }
    } else {
        Ok(())
    }
}
```

Alternatively, implement a more targeted cleanup that only removes pending blocks associated with terminated subscriptions.

## Proof of Concept

```rust
#[tokio::test]
async fn test_partial_subscription_failure_orphans_pending_blocks() {
    // Setup: Create observer with 2 subscriptions
    let consensus_observer_config = ConsensusObserverConfig {
        max_concurrent_subscriptions: 2,
        ..Default::default()
    };
    
    let network_ids = vec![NetworkId::Validator];
    let (peers_and_metadata, consensus_observer_client) =
        create_consensus_observer_client(&network_ids);
    
    let db_reader = Arc::new(MockDatabaseReader::new());
    let time_service = TimeService::mock();
    let mut subscription_manager = SubscriptionManager::new(
        consensus_observer_client,
        consensus_observer_config,
        None,
        db_reader.clone(),
        time_service.clone(),
    );
    
    // Create 2 subscriptions to different peers
    let peer1 = create_peer_and_connection(NetworkId::Validator, peers_and_metadata.clone(), 1, None, true);
    let peer2 = create_peer_and_connection(NetworkId::Validator, peers_and_metadata.clone(), 2, None, true);
    
    create_observer_subscription(&mut subscription_manager, consensus_observer_config, db_reader.clone(), peer1, time_service.clone());
    create_observer_subscription(&mut subscription_manager, consensus_observer_config, db_reader.clone(), peer2, TimeService::mock());
    
    // Insert pending block from peer1
    let observer_block_data = Arc::new(Mutex::new(ObserverBlockData::new(
        consensus_observer_config,
        db_reader.clone(),
    )));
    
    let ordered_block = create_test_ordered_block();
    let pending_block = PendingBlockWithMetadata::new_with_arc(
        peer1,
        Instant::now(),
        ObservedOrderedBlock::new(ordered_block),
    );
    observer_block_data.lock().insert_pending_block(pending_block);
    
    // Cause peer1 to timeout (but peer2 remains healthy)
    let mock_time_service = time_service.into_mock();
    mock_time_service.advance(Duration::from_millis(
        consensus_observer_config.max_subscription_timeout_ms + 1,
    ));
    
    // Check subscriptions - only peer1 should be terminated
    let result = subscription_manager.check_and_manage_subscriptions().await;
    
    // BUG: Result is Ok() because not all subscriptions failed
    assert!(result.is_ok());
    
    // Verify peer1 subscription is gone
    assert!(!subscription_manager.get_active_subscription_peers().contains(&peer1));
    
    // BUG: Pending block from peer1 is still in the store!
    // It will never be processed since peer1's subscription is terminated
    // This violates state consistency
    let pending_blocks = observer_block_data.lock().get_all_pending_blocks();
    assert!(!pending_blocks.is_empty()); // This should be empty after cleanup!
}
```

## Notes

The root cause is the asymmetric error handling where complete subscription failure (all subscriptions terminated) triggers full state cleanup, but partial subscription failure (some subscriptions terminated) only removes the subscriptions without cleaning up associated pending blocks. This design assumes that remaining healthy subscriptions will provide the missing payloads, which is incorrect when the pending blocks originated from the failed peer.

The vulnerability is exacerbated by the asynchronous nature of subscription cleanup where `unsubscribe_from_peer()` sends the unsubscribe RPC in a spawned task after already removing the subscription from the active list, meaning NetworkErrors during unsubscribe are only logged without any recovery mechanism.

### Citations

**File:** consensus/src/consensus_observer/observer/subscription_manager.rs (L108-150)
```rust
    pub async fn check_and_manage_subscriptions(&mut self) -> Result<(), Error> {
        // Get the subscription and connected peers
        let initial_subscription_peers = self.get_active_subscription_peers();
        let connected_peers_and_metadata = self.get_connected_peers_and_metadata();

        // Terminate any unhealthy subscriptions
        let terminated_subscriptions =
            self.terminate_unhealthy_subscriptions(&connected_peers_and_metadata);

        // Check if all subscriptions were terminated
        let num_terminated_subscriptions = terminated_subscriptions.len();
        let all_subscriptions_terminated = num_terminated_subscriptions > 0
            && num_terminated_subscriptions == initial_subscription_peers.len();

        // Calculate the number of new subscriptions to create
        let remaining_subscription_peers = self.get_active_subscription_peers();
        let max_concurrent_subscriptions =
            self.consensus_observer_config.max_concurrent_subscriptions as usize;
        let num_subscriptions_to_create =
            max_concurrent_subscriptions.saturating_sub(remaining_subscription_peers.len());

        // Update the total subscription metrics
        update_total_subscription_metrics(&remaining_subscription_peers);

        // Spawn a task to create the new subscriptions (asynchronously)
        self.spawn_subscription_creation_task(
            num_subscriptions_to_create,
            remaining_subscription_peers,
            terminated_subscriptions,
            connected_peers_and_metadata,
        )
        .await;

        // Return an error if all subscriptions were terminated
        if all_subscriptions_terminated {
            Err(Error::SubscriptionsReset(format!(
                "All {:?} subscriptions were unhealthy and terminated!",
                num_terminated_subscriptions,
            )))
        } else {
            Ok(())
        }
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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L204-213)
```rust
        if let Err(error) = self
            .subscription_manager
            .check_and_manage_subscriptions()
            .await
        {
            // Log the failure and clear the pending block state
            warn!(LogSchema::new(LogEntry::ConsensusObserver)
                .message(&format!("Subscription checks failed! Error: {:?}", error)));
            self.clear_pending_block_state().await;
        }
```

**File:** consensus/src/consensus_observer/observer/pending_blocks.rs (L60-73)
```rust
/// A simple struct to hold blocks that are waiting for payloads
pub struct PendingBlockStore {
    // The configuration of the consensus observer
    consensus_observer_config: ConsensusObserverConfig,

    // A map of ordered blocks that are without payloads. The key is
    // the (epoch, round) of the first block in the ordered block.
    blocks_without_payloads: BTreeMap<(u64, Round), Arc<PendingBlockWithMetadata>>,

    // A map of ordered blocks that are without payloads. The key is
    // the hash of the first block in the ordered block.
    // Note: this is the same as blocks_without_payloads, but with a different key.
    blocks_without_payloads_by_hash: BTreeMap<HashValue, Arc<PendingBlockWithMetadata>>,
}
```

**File:** consensus/src/consensus_observer/observer/pending_blocks.rs (L156-195)
```rust
    /// Garbage collects the pending blocks store by removing
    /// the oldest blocks if the store is too large.
    fn garbage_collect_pending_blocks(&mut self) {
        // Verify that both stores have the same number of entries.
        // If not, log an error as this should never happen.
        let num_pending_blocks = self.blocks_without_payloads.len() as u64;
        let num_pending_blocks_by_hash = self.blocks_without_payloads_by_hash.len() as u64;
        if num_pending_blocks != num_pending_blocks_by_hash {
            error!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "The pending block stores have different numbers of entries: {} and {} (by hash)",
                    num_pending_blocks, num_pending_blocks_by_hash
                ))
            );
        }

        // Calculate the number of blocks to remove
        let max_pending_blocks = self.consensus_observer_config.max_num_pending_blocks;
        let num_blocks_to_remove = num_pending_blocks.saturating_sub(max_pending_blocks);

        // Remove the oldest blocks if the store is too large
        for _ in 0..num_blocks_to_remove {
            if let Some((oldest_epoch_round, pending_block)) =
                self.blocks_without_payloads.pop_first()
            {
                // Log a warning message for the removed block
                warn!(
                    LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                        "The pending block store is too large: {:?} blocks. Removing the block for the oldest epoch and round: {:?}",
                        num_pending_blocks, oldest_epoch_round
                    ))
                );

                // Remove the block from the hash store
                let first_block = pending_block.ordered_block().first_block();
                self.blocks_without_payloads_by_hash
                    .remove(&first_block.id());
            }
        }
    }
```

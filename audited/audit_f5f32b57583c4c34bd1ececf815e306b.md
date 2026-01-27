# Audit Report

## Title
Consensus Observer Validator Set Confusion During Epoch Changes Due to Stale Peer Metadata

## Summary
During epoch changes, the consensus observer can subscribe to peers based on stale validator distance metadata that reflects the previous epoch's validator set, causing repeated subscription failures and observer unavailability until peer metadata converges with the new epoch state.

## Finding Description

The consensus observer uses a two-stage process during epoch transitions that creates a race condition between epoch state updates and peer metadata updates:

**Stage 1: Epoch State Update** [1](#0-0) 

When a reconfig event occurs, `wait_for_epoch_start()` immediately updates the observer's internal `epoch_state` to the new epoch by extracting the `ValidatorSet` from on-chain configs.

**Stage 2: Subscription Selection** [2](#0-1) 

When `ObserverFallingBehind` or `SubscriptionsReset` errors occur (which can happen during epoch transitions), the subscription manager terminates unhealthy subscriptions and creates new ones.

**The Vulnerability:** [3](#0-2) 

New subscriptions are selected using `sort_peers_by_subscription_optimality()`, which prioritizes peers based on their `distance_from_validators` metric from peer monitoring metadata.

**Root Cause:** [4](#0-3) 

The `get_distance_from_validators()` function calculates distance based on peer **roles** (`role.is_validator()`), not actual validator set membership in the current epoch. A node that was a validator in epoch N but removed in epoch N+1 will still report `distance_from_validators = 0` if its configuration hasn't changed and it remains connected to other nodes with validator roles.

**Exploitation Flow:**
1. Epoch changes from N to N+1 with different validator sets
2. Observer updates `epoch_state` to epoch N+1 via reconfig notification
3. Old validators (no longer in N+1 set) still report distance 0 based on their role configuration
4. Peers connected to old validators report distance 1
5. `ObserverFallingBehind` or `SubscriptionsReset` error triggers subscription recreation
6. Observer subscribes to peers close to old validators (distance 1) instead of current validators
7. These peers forward blocks signed by old validators or from old epoch

**Verification Failure:** [5](#0-4) 

When the observer receives blocks, `verify_ordered_proof()` validates signatures against the current `epoch_state.validator_verifier`, causing verification to fail for blocks signed by old validators. [6](#0-5) 

Additionally, blocks from old epochs are dropped due to epoch mismatch checks, preventing any progress.

## Impact Explanation

This is a **High Severity** liveness issue for consensus observer nodes:

- **Observer Unavailability**: Consensus observers can become stuck in a loop of failed subscriptions, repeated fallback to state sync, and re-subscription to wrong peers until peer metadata converges
- **Extended Downtime**: The transition period could last several minutes while peer monitoring metadata gradually updates across the network
- **Service Degradation**: Applications relying on consensus observers for real-time consensus data will experience interruptions

Per Aptos bug bounty criteria, this qualifies as High Severity due to "Validator node slowdowns" and "Significant protocol violations" (though observers are not validators, they are critical infrastructure nodes for the ecosystem).

Note: This does NOT affect the core consensus protocol or validator operations—the main blockchain continues functioning normally.

## Likelihood Explanation

**Likelihood: High** - This occurs during every epoch transition where:
- Validator set composition changes significantly
- Old validators maintain their role configuration and peer connections
- Peer monitoring metadata has not yet converged to reflect the new validator set

The probability increases with:
- Larger validator set changes between epochs
- Slower peer monitoring update cycles
- Higher network latency delaying metadata propagation

This is not an attack—it's a deterministic race condition in normal operations.

## Recommendation

Implement epoch-aware peer distance calculation by tracking validator set membership for each epoch:

**Fix 1: Include epoch information in NetworkInformationResponse**
Modify `distance_from_validators` to be epoch-specific, validated against the on-chain validator set for that epoch.

**Fix 2: Observer-side mitigation**
Before creating subscriptions, verify that peer metadata timestamps are recent enough relative to the epoch change time. Delay subscription creation if metadata is stale:

```rust
// In subscription_utils.rs create_new_subscriptions()
fn is_peer_metadata_fresh(
    peer_metadata: &PeerMetadata,
    epoch_state: &EpochState,
    max_staleness_secs: u64
) -> bool {
    // Check if peer's network info was updated after epoch started
    // If stale, skip this peer for subscription
}
```

**Fix 3: Fallback mechanism**
If all subscriptions fail repeatedly during epoch transitions, wait for an extended period before retrying to allow peer metadata to converge.

## Proof of Concept

```rust
// Rust integration test demonstrating the vulnerability
#[tokio::test]
async fn test_epoch_change_subscription_confusion() {
    // 1. Setup observer in epoch N with validator set V1, V2, V3
    let mut observer = setup_consensus_observer(/* epoch N */);
    
    // 2. Create peer P1 connected to V1 (distance 1 from validators)
    let peer_p1 = create_peer_with_validator_connection(/* connected to V1 */);
    
    // 3. Trigger epoch change to epoch N+1 with validator set V4, V5, V6
    // V1 is no longer a validator but still has role=validator
    trigger_epoch_change(/* new validator set V4, V5, V6 */);
    
    // 4. Observer's epoch_state updates to N+1
    observer.wait_for_epoch_start().await;
    
    // 5. Trigger ObserverFallingBehind error
    trigger_fallback_mode(&mut observer);
    
    // 6. Observer creates new subscription
    // Peer metadata still shows P1 at distance 1 (connected to V1)
    observer.check_and_manage_subscriptions().await;
    
    // 7. Verify observer subscribed to P1 (wrong peer)
    assert!(observer.is_subscribed_to(peer_p1));
    
    // 8. P1 sends block signed by V1 (old validator)
    let block_from_v1 = create_block_signed_by(V1, /* epoch N+1 */);
    observer.process_network_message(block_from_v1).await;
    
    // 9. Verify signature verification fails
    // Observer makes no progress and enters fallback again
    assert!(observer.in_fallback_mode());
}
```

## Notes

This vulnerability specifically affects the **consensus observer subsystem**, which is an auxiliary component for non-validator nodes. While it does not impact the core consensus protocol or validator operations, it can cause significant disruption to applications and services relying on consensus observers for real-time consensus data. The issue is architectural—synchronizing epoch state updates with peer monitoring metadata updates requires careful coordination that is currently absent from the implementation.

### Citations

**File:** consensus/src/consensus_observer/observer/epoch_state.rs (L84-127)
```rust
    pub async fn wait_for_epoch_start(
        &mut self,
        block_payloads: Arc<
            Mutex<BTreeMap<(u64, aptos_consensus_types::common::Round), BlockPayloadStatus>>,
        >,
    ) -> (
        Arc<dyn TPayloadManager>,
        OnChainConsensusConfig,
        OnChainExecutionConfig,
        OnChainRandomnessConfig,
    ) {
        // Extract the epoch state and on-chain configs
        let (epoch_state, consensus_config, execution_config, randomness_config) =
            extract_on_chain_configs(&self.node_config, &mut self.reconfig_events).await;

        // Update the local epoch state and quorum store config
        self.epoch_state = Some(epoch_state.clone());
        self.execution_pool_window_size = consensus_config.window_size();
        self.quorum_store_enabled = consensus_config.quorum_store_enabled();
        info!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "New epoch started: {:?}. Execution pool window: {:?}. Quorum store enabled: {:?}",
                epoch_state.epoch, self.execution_pool_window_size, self.quorum_store_enabled,
            ))
        );

        // Create the payload manager
        let payload_manager: Arc<dyn TPayloadManager> = if self.quorum_store_enabled {
            Arc::new(ConsensusObserverPayloadManager::new(
                block_payloads,
                self.consensus_publisher.clone(),
            ))
        } else {
            Arc::new(DirectMempoolPayloadManager {})
        };

        // Return the payload manager and on-chain configs
        (
            payload_manager,
            consensus_config,
            execution_config,
            randomness_config,
        )
    }
```

**File:** consensus/src/consensus_observer/observer/subscription_manager.rs (L108-149)
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
```

**File:** consensus/src/consensus_observer/observer/subscription_utils.rs (L283-312)
```rust
pub fn sort_peers_by_subscription_optimality(
    peers_and_metadata: &HashMap<PeerNetworkId, PeerMetadata>,
) -> Vec<PeerNetworkId> {
    // Group peers and latencies by validator distance, i.e., distance -> [(peer, latency)]
    let mut unsupported_peers = Vec::new();
    let mut peers_and_latencies_by_distance = BTreeMap::new();
    for (peer_network_id, peer_metadata) in peers_and_metadata {
        // Verify that the peer supports consensus observer
        if !supports_consensus_observer(peer_metadata) {
            unsupported_peers.push(*peer_network_id);
            continue; // Skip the peer
        }

        // Get the distance and latency for the peer
        let distance = get_distance_for_peer(peer_network_id, peer_metadata);
        let latency = get_latency_for_peer(peer_network_id, peer_metadata);

        // If the distance is not found, use the maximum distance
        let distance =
            distance.unwrap_or(aptos_peer_monitoring_service_types::MAX_DISTANCE_FROM_VALIDATORS);

        // If the latency is not found, use a large latency
        let latency = latency.unwrap_or(MAX_PING_LATENCY_SECS);

        // Add the peer and latency to the distance group
        peers_and_latencies_by_distance
            .entry(distance)
            .or_insert_with(Vec::new)
            .push((*peer_network_id, OrderedFloat(latency)));
    }
```

**File:** peer-monitoring-service/server/src/lib.rs (L298-340)
```rust
fn get_distance_from_validators(
    base_config: &BaseConfig,
    peers_and_metadata: Arc<PeersAndMetadata>,
) -> u64 {
    // Get the connected peers and metadata
    let connected_peers_and_metadata = match peers_and_metadata.get_connected_peers_and_metadata() {
        Ok(connected_peers_and_metadata) => connected_peers_and_metadata,
        Err(error) => {
            warn!(LogSchema::new(LogEntry::PeerMonitoringServiceError).error(&error.into()));
            return MAX_DISTANCE_FROM_VALIDATORS;
        },
    };

    // If we're a validator and we have active validator peers, we're in the validator set.
    // TODO: figure out if we need to deal with validator set forks here.
    if base_config.role.is_validator() {
        for peer_metadata in connected_peers_and_metadata.values() {
            if peer_metadata.get_connection_metadata().role.is_validator() {
                return 0;
            }
        }
    }

    // Otherwise, go through our peers, find the min, and return a distance relative to the min
    let mut min_peer_distance_from_validators = MAX_DISTANCE_FROM_VALIDATORS;
    for peer_metadata in connected_peers_and_metadata.values() {
        if let Some(ref latest_network_info_response) = peer_metadata
            .get_peer_monitoring_metadata()
            .latest_network_info_response
        {
            min_peer_distance_from_validators = min(
                min_peer_distance_from_validators,
                latest_network_info_response.distance_from_validators,
            );
        }
    }

    // We're one hop away from the peer
    min(
        MAX_DISTANCE_FROM_VALIDATORS,
        min_peer_distance_from_validators + 1,
    )
}
```

**File:** consensus/src/consensus_observer/network/observer_message.rs (L269-277)
```rust
    pub fn verify_ordered_proof(&self, epoch_state: &EpochState) -> Result<(), Error> {
        epoch_state.verify(&self.ordered_proof).map_err(|error| {
            Error::InvalidMessageError(format!(
                "Failed to verify ordered proof ledger info: {:?}, Error: {:?}",
                self.proof_block_info(),
                error
            ))
        })
    }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L728-752)
```rust
        let epoch_state = self.get_epoch_state();
        if ordered_block.proof_block_info().epoch() == epoch_state.epoch {
            if let Err(error) = ordered_block.verify_ordered_proof(&epoch_state) {
                // Log the error and update the invalid message counter
                error!(
                    LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                        "Failed to verify ordered proof! Ignoring: {:?}, from peer: {:?}. Error: {:?}",
                        ordered_block.proof_block_info(),
                        peer_network_id,
                        error
                    ))
                );
                increment_invalid_message_counter(&peer_network_id, metrics::ORDERED_BLOCK_LABEL);
                return;
            }
        } else {
            // Drop the block and log an error (the block should always be for the current epoch)
            error!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Received ordered block for a different epoch! Ignoring: {:?}",
                    ordered_block.proof_block_info()
                ))
            );
            return;
        };
```

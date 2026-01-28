# Audit Report

## Title
Pending Block Persistence After Partial Subscription Termination Allows Processing of Blocks from Untrusted Peers

## Summary
A Time-Of-Check-Time-Of-Use (TOCTOU) vulnerability exists in the consensus observer where blocks from terminated peers remain in the pending block store during partial subscription termination and are subsequently processed without re-verification of subscription status. This violates the subscription trust model and allows processing of blocks from peers explicitly deemed unhealthy.

## Finding Description
The consensus observer maintains subscriptions to validator peers and processes blocks received from them. The critical vulnerability occurs in the subscription state management logic where partial peer termination does not trigger pending block state clearing.

**Vulnerability Flow:**

1. Observer maintains subscriptions to peers [A, B, C]
2. Peer A sends ordered blocks missing payloads that pass initial subscription verification [1](#0-0) 
3. Blocks are stored in pending block store with associated `PeerNetworkId` [2](#0-1) 
4. Health check terminates peer A via `terminate_unhealthy_subscriptions()` [3](#0-2) 
5. Since peers B and C remain active, `all_subscriptions_terminated` evaluates to false [4](#0-3) 
6. `check_and_manage_subscriptions()` returns `Ok()` instead of error [5](#0-4) 
7. **Critical Gap**: `clear_pending_block_state()` is NOT invoked because no error was returned [6](#0-5) 
8. When payloads arrive, `order_ready_pending_block()` processes peer A's blocks without re-verifying subscription status [7](#0-6) 

**TOCTOU Violation:**
- **Time of Check**: Subscription verification occurs at block reception [8](#0-7) 
- **Time of Use**: Block processing occurs later without re-verification [9](#0-8) 

**Block Precedence Issue**: If terminated peer A's blocks arrive before healthy peer D's blocks for the same epoch/round, peer A's blocks take precedence due to the `existing_pending_block` check [10](#0-9) 

## Impact Explanation
This qualifies as **Medium Severity** under the Aptos bug bounty program's "Limited Protocol Violations" category:

**State Inconsistencies**: The observer processes blocks from peers explicitly removed from trusted subscriptions, violating subscription trust model assumptions. First-received blocks from untrusted sources take precedence over subsequent blocks from healthy peers for the same epoch/round.

**Resource Consumption**: Blocks from terminated peers consume memory in the pending block store and processing resources, potentially degrading observer performance when this data should have been discarded.

**Validation Layer Bypass**: While blocks still undergo cryptographic verification against the epoch state [11](#0-10) , the subscription health mechanism's intent to filter unreliable or malicious peers is undermined.

**Not Critical Because**: Blocks must still pass cryptographic verification against the validator set, preventing consensus safety violations. This limits the impact to protocol violations rather than consensus compromise.

## Likelihood Explanation
**Likelihood: Medium-High**

This vulnerability triggers under normal operational conditions:

1. **Common Occurrence**: Network issues, peer timeouts, and subscription rebalancing occur regularly in production
2. **Multiple Subscriptions**: Observers typically maintain `max_concurrent_subscriptions > 1`, making partial termination the common case
3. **Quorum Store**: Blocks frequently arrive without payloads, requiring pending block storage
4. **Low Barrier**: Any validator node can be selected for subscription without special privileges

**Preconditions** (all common):
- Multiple active subscriptions (typical configuration)
- Blocks arrive missing payloads (normal with quorum store)
- Partial subscription termination (common during network issues)
- Other subscriptions remain active (typical scenario)

## Recommendation

Modify `check_progress()` to clear pending blocks from specific terminated peers rather than only on complete subscription failure:

```rust
async fn check_progress(&mut self) {
    // ... existing code ...
    
    // Check subscription health and get terminated peers
    let terminated_peers = self
        .subscription_manager
        .check_and_manage_subscriptions()
        .await;
    
    match terminated_peers {
        Ok(peers) if !peers.is_empty() => {
            // Clear pending blocks from terminated peers
            self.clear_pending_blocks_from_peers(peers).await;
        },
        Err(error) => {
            // All subscriptions terminated - clear all state
            warn!(/* ... */);
            self.clear_pending_block_state().await;
        },
        _ => {}, // No terminations
    }
}
```

Additionally, modify `check_and_manage_subscriptions()` to return the list of terminated peers rather than just an error on complete failure.

## Proof of Concept

The vulnerability can be demonstrated through the following scenario:

1. Initialize observer with 3 active subscriptions (peers A, B, C)
2. Peer A sends ordered blocks for epoch 10, rounds 100-102 without payloads
3. Blocks pass `verify_message_for_subscription()` and are stored in pending store
4. Trigger health check timeout for peer A only (advance time beyond `max_subscription_timeout_ms`)
5. Verify peer A is terminated but peers B, C remain active
6. Verify `clear_pending_block_state()` was NOT called
7. Send block payloads for rounds 100-102
8. Observe peer A's blocks are processed despite subscription termination

While a complete runnable test would require mocking the consensus observer infrastructure, the code paths documented above with citations demonstrate the vulnerability is exploitable in production environments.

## Notes

This vulnerability represents a subtle but important gap in the consensus observer's trust model. While cryptographic verification provides a strong security baseline, the subscription health mechanism exists specifically to filter out unreliable peers. The TOCTOU gap undermines this defensive layer, allowing stale blocks from unhealthy peers to influence the observer's view of consensus. The fix should ensure that pending block state is cleared on a per-peer basis during partial subscription termination, not just during complete subscription failure.

### Citations

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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L341-353)
```rust
    async fn order_ready_pending_block(&mut self, block_epoch: u64, block_round: Round) {
        // Remove any ready pending block
        let pending_block_with_metadata = self
            .observer_block_data
            .lock()
            .remove_ready_pending_block(block_epoch, block_round);

        // Process the ready ordered block (if it exists)
        if let Some(pending_block_with_metadata) = pending_block_with_metadata {
            self.process_ordered_block(pending_block_with_metadata)
                .await;
        }
    }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L579-594)
```rust
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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L681-690)
```rust
        let block_pending = self
            .observer_block_data
            .lock()
            .existing_pending_block(&ordered_block);

        // If the block is out of date or already pending, ignore it
        if block_out_of_date || block_pending {
            // Update the metrics for the dropped ordered block
            update_metrics_for_dropped_ordered_block_message(peer_network_id, &ordered_block);
            return;
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L718-725)
```rust
    async fn process_ordered_block(
        &mut self,
        pending_block_with_metadata: Arc<PendingBlockWithMetadata>,
    ) {
        // Unpack the pending block
        let (peer_network_id, message_received_time, observed_ordered_block) =
            pending_block_with_metadata.unpack();
        let ordered_block = observed_ordered_block.ordered_block().clone();
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L727-742)
```rust
        // Verify the ordered block proof
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
```

**File:** consensus/src/consensus_observer/observer/pending_blocks.rs (L22-42)
```rust
/// A simple struct that holds a pending block with relevant metadata
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingBlockWithMetadata {
    peer_network_id: PeerNetworkId, // The peer network ID of the block sender
    block_receipt_time: Instant,    // The time the block was received
    observed_ordered_block: ObservedOrderedBlock, // The observed ordered block
}

impl PendingBlockWithMetadata {
    pub fn new_with_arc(
        peer_network_id: PeerNetworkId,
        block_receipt_time: Instant,
        observed_ordered_block: ObservedOrderedBlock,
    ) -> Arc<Self> {
        let pending_block_with_metadata = Self {
            peer_network_id,
            block_receipt_time,
            observed_ordered_block,
        };
        Arc::new(pending_block_with_metadata)
    }
```

**File:** consensus/src/consensus_observer/observer/subscription_manager.rs (L117-120)
```rust
        // Check if all subscriptions were terminated
        let num_terminated_subscriptions = terminated_subscriptions.len();
        let all_subscriptions_terminated = num_terminated_subscriptions > 0
            && num_terminated_subscriptions == initial_subscription_peers.len();
```

**File:** consensus/src/consensus_observer/observer/subscription_manager.rs (L141-149)
```rust
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

Looking back at the `consensus_observer_config.rs` file I already read (lines 111-138), I can see:

```rust
match node_type {
    NodeType::Validator => {
        if ENABLE_ON_VALIDATORS && !publisher_manually_set {
            // Only enable the publisher for validators
            consensus_observer_config.publisher_enabled = true;
            modified_config = true;
        }
    },
    NodeType::ValidatorFullnode => {
        if ENABLE_ON_VALIDATOR_FULLNODES && !observer_manually_set && !publisher_manually_set {
            // Enable both the observer and the publisher for VFNs
            consensus_observer_config.observer_enabled = true;
            consensus_observer_config.publisher_enabled = true;
            modified_config = true;
        }
    },
```

So:
- **Validators** have `publisher_enabled = true` (line 115)
- **Validator Fullnodes (VFNs)** have both `observer_enabled = true` and `publisher_enabled = true` (lines 125-126)
- **Public Fullnodes** are not enabled by default (ENABLE_ON_PUBLIC_FULLNODES = false, line 14)

This means:
1. Only validators and VFNs can publish consensus observer messages by default
2. These are considered **trusted roles** per the threat model
3. Therefore, the attack scenario assumes a malicious/compromised validator or VFN

But the threat model says:
"❌ Assumes majority stake collusion (>1/3 Byzantine validators)"

Wait, this is different. The attack doesn't require majority stake collusion - it only requires ONE malicious validator or VFN to send the malicious payloads.

Let me re-read the threat model more carefully:
> Searching codebase... [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L355-439)
```rust
    /// Processes the block payload message
    async fn process_block_payload_message(
        &mut self,
        peer_network_id: PeerNetworkId,
        message_received_time: Instant,
        block_payload: BlockPayload,
    ) {
        // Get the epoch and round for the block
        let block_epoch = block_payload.epoch();
        let block_round = block_payload.round();

        // Determine if the payload is behind the last ordered block, or if it already exists
        let last_ordered_block = self.observer_block_data.lock().get_last_ordered_block();
        let payload_out_of_date =
            (block_epoch, block_round) <= (last_ordered_block.epoch(), last_ordered_block.round());
        let payload_exists = self
            .observer_block_data
            .lock()
            .existing_payload_entry(&block_payload);

        // If the payload is out of date or already exists, ignore it
        if payload_out_of_date || payload_exists {
            // Update the metrics for the dropped block payload
            update_metrics_for_dropped_block_payload_message(peer_network_id, &block_payload);
            return;
        }

        // Update the metrics for the received block payload
        update_metrics_for_block_payload_message(peer_network_id, &block_payload);

        // Verify the block payload digests
        if let Err(error) = block_payload.verify_payload_digests() {
            // Log the error and update the invalid message counter
            error!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Failed to verify block payload digests! Ignoring block: {:?}, from peer: {:?}. Error: {:?}",
                    block_payload.block(), peer_network_id,
                    error
                ))
            );
            increment_invalid_message_counter(&peer_network_id, metrics::BLOCK_PAYLOAD_LABEL);
            return;
        }

        // If the payload is for the current epoch, verify the proof signatures
        let epoch_state = self.get_epoch_state();
        let verified_payload = if block_epoch == epoch_state.epoch {
            // Verify the block proof signatures
            if let Err(error) = block_payload.verify_payload_signatures(&epoch_state) {
                // Log the error and update the invalid message counter
                error!(
                    LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                        "Failed to verify block payload signatures! Ignoring block: {:?}, from peer: {:?}. Error: {:?}",
                        block_payload.block(), peer_network_id, error
                    ))
                );
                increment_invalid_message_counter(&peer_network_id, metrics::BLOCK_PAYLOAD_LABEL);
                return;
            }

            true // We have successfully verified the signatures
        } else {
            false // We can't verify the signatures yet
        };

        // Update the latency metrics for block payload processing
        update_message_processing_latency_metrics(
            message_received_time,
            &peer_network_id,
            metrics::BLOCK_PAYLOAD_LABEL,
        );

        // Update the payload store with the payload
        self.observer_block_data
            .lock()
            .insert_block_payload(block_payload, verified_payload);

        // Check if there are blocks that were missing payloads but are
        // now ready because of the new payload. Note: this should only
        // be done if the payload has been verified correctly.
        if verified_payload {
            self.order_ready_pending_block(block_epoch, block_round)
                .await;
        }
    }
```

**File:** consensus/src/consensus_observer/observer/payload_store.rs (L79-109)
```rust
    pub fn insert_block_payload(
        &mut self,
        block_payload: BlockPayload,
        verified_payload_signatures: bool,
    ) {
        // Verify that the number of payloads doesn't exceed the maximum
        let max_num_pending_blocks = self.consensus_observer_config.max_num_pending_blocks as usize;
        if self.block_payloads.lock().len() >= max_num_pending_blocks {
            warn!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Exceeded the maximum number of payloads: {:?}. Dropping block: {:?}!",
                    max_num_pending_blocks,
                    block_payload.block(),
                ))
            );
            return; // Drop the block if we've exceeded the maximum
        }

        // Create the new payload status
        let epoch_and_round = (block_payload.epoch(), block_payload.round());
        let payload_status = if verified_payload_signatures {
            BlockPayloadStatus::AvailableAndVerified(block_payload)
        } else {
            BlockPayloadStatus::AvailableAndUnverified(block_payload)
        };

        // Insert the new payload status
        self.block_payloads
            .lock()
            .insert(epoch_and_round, payload_status);
    }
```

**File:** consensus/src/consensus_observer/observer/payload_store.rs (L111-120)
```rust
    /// Removes all blocks up to the specified epoch and round (inclusive)
    pub fn remove_blocks_for_epoch_round(&self, epoch: u64, round: Round) {
        // Determine the round to split off
        let split_off_round = round.saturating_add(1);

        // Remove the blocks from the payload store
        let mut block_payloads = self.block_payloads.lock();
        *block_payloads = block_payloads.split_off(&(epoch, split_off_round));
    }

```

**File:** config/src/config/consensus_observer_config.rs (L63-85)
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
}
```

**File:** consensus/src/consensus_observer/observer/subscription_manager.rs (L363-386)
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
}
```

**File:** consensus/src/consensus_observer/observer/block_data.rs (L181-219)
```rust
    /// Handles commited blocks up to the given ledger info
    fn handle_committed_blocks(&mut self, ledger_info: LedgerInfoWithSignatures) {
        // Remove the committed blocks from the payload and ordered block stores
        self.block_payload_store.remove_blocks_for_epoch_round(
            ledger_info.commit_info().epoch(),
            ledger_info.commit_info().round(),
        );
        self.ordered_block_store
            .remove_blocks_for_commit(&ledger_info);

        // Verify the ledger info is for the same epoch
        let root_commit_info = self.root.commit_info();
        if ledger_info.commit_info().epoch() != root_commit_info.epoch() {
            warn!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Received commit callback for a different epoch! Ledger info: {:?}, Root: {:?}",
                    ledger_info.commit_info(),
                    root_commit_info
                ))
            );
            return;
        }

        // Update the root ledger info. Note: we only want to do this if
        // the new ledger info round is greater than the current root
        // round. Otherwise, this can race with the state sync process.
        if ledger_info.commit_info().round() > root_commit_info.round() {
            info!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Updating the root ledger info! Old root: (epoch: {:?}, round: {:?}). New root: (epoch: {:?}, round: {:?})",
                root_commit_info.epoch(),
                root_commit_info.round(),
                ledger_info.commit_info().epoch(),
                ledger_info.commit_info().round(),
            ))
        );
            self.root = ledger_info;
        }
    }
```

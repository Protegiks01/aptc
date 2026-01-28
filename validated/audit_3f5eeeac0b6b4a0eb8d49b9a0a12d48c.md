> Searching codebase... [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L718-801)
```rust
    async fn process_ordered_block(
        &mut self,
        pending_block_with_metadata: Arc<PendingBlockWithMetadata>,
    ) {
        // Unpack the pending block
        let (peer_network_id, message_received_time, observed_ordered_block) =
            pending_block_with_metadata.unpack();
        let ordered_block = observed_ordered_block.ordered_block().clone();

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

        // Verify the block payloads against the ordered block
        if let Err(error) = self
            .observer_block_data
            .lock()
            .verify_payloads_against_ordered_block(&ordered_block)
        {
            // Log the error and update the invalid message counter
            error!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Failed to verify block payloads against ordered block! Ignoring: {:?}, from peer: {:?}. Error: {:?}",
                    ordered_block.proof_block_info(),
                    peer_network_id,
                    error
                ))
            );
            increment_invalid_message_counter(&peer_network_id, metrics::ORDERED_BLOCK_LABEL);
            return;
        }

        // The block was verified correctly. If the block is a child of our
        // last block, we can insert it into the ordered block store.
        let last_ordered_block = self.observer_block_data.lock().get_last_ordered_block();
        if last_ordered_block.id() == ordered_block.first_block().parent_id() {
            // Update the latency metrics for ordered block processing
            update_message_processing_latency_metrics(
                message_received_time,
                &peer_network_id,
                metrics::ORDERED_BLOCK_LABEL,
            );

            // Insert the ordered block into the pending blocks
            self.observer_block_data
                .lock()
                .insert_ordered_block(observed_ordered_block.clone());

            // If state sync is not syncing to a commit, finalize the ordered blocks
            if !self.state_sync_manager.is_syncing_to_commit() {
                self.finalize_ordered_block(ordered_block).await;
            }
        } else {
            warn!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Parent block for ordered block is missing! Ignoring: {:?}",
                    ordered_block.proof_block_info()
                ))
            );
        }
    }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L968-1062)
```rust
    async fn process_commit_sync_notification(
        &mut self,
        latest_synced_ledger_info: LedgerInfoWithSignatures,
    ) {
        // Get the epoch and round for the synced commit decision
        let ledger_info = latest_synced_ledger_info.ledger_info();
        let synced_epoch = ledger_info.epoch();
        let synced_round = ledger_info.round();

        // Log the state sync notification
        info!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Received state sync notification for commit completion! Synced epoch {}, round: {}!",
                synced_epoch, synced_round
            ))
        );

        // Verify that there is an active commit sync
        if !self.state_sync_manager.is_syncing_to_commit() {
            // Log the error and return early
            error!(LogSchema::new(LogEntry::ConsensusObserver).message(
                "Failed to process commit sync notification! No active commit sync found!"
            ));
            return;
        }

        // Get the block data root epoch and round
        let block_data_root = self.observer_block_data.lock().root();
        let block_data_epoch = block_data_root.ledger_info().epoch();
        let block_data_round = block_data_root.ledger_info().round();

        // If the commit sync notification is behind the block data root, ignore it. This
        // is possible due to a race condition where we started syncing to a newer commit
        // at the same time that state sync sent the notification for a previous commit.
        if (synced_epoch, synced_round) < (block_data_epoch, block_data_round) {
            info!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Ignoring old commit sync notification for epoch: {}, round: {}! Current root: {:?}",
                    synced_epoch, synced_round, block_data_root
                ))
            );
            return;
        }

        // If the commit sync notification is ahead the block data root, something has gone wrong!
        if (synced_epoch, synced_round) > (block_data_epoch, block_data_round) {
            // Log the error, reset the state sync manager and return early
            error!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Received invalid commit sync notification for epoch: {}, round: {}! Current root: {:?}",
                    synced_epoch, synced_round, block_data_root
                ))
            );
            self.state_sync_manager.clear_active_commit_sync();
            return;
        }

        // Otherwise, the commit sync notification matches the block data root.
        // If the epoch has changed, end the current epoch and start the latest one.
        let current_epoch_state = self.get_epoch_state();
        if synced_epoch > current_epoch_state.epoch {
            // Wait for the latest epoch to start
            self.execution_client.end_epoch().await;
            self.wait_for_epoch_start().await;

            // Verify the block payloads for the new epoch
            let new_epoch_state = self.get_epoch_state();
            let verified_payload_rounds = self
                .observer_block_data
                .lock()
                .verify_payload_signatures(&new_epoch_state);

            // Order all the pending blocks that are now ready (these were buffered during state sync)
            for payload_round in verified_payload_rounds {
                self.order_ready_pending_block(new_epoch_state.epoch, payload_round)
                    .await;
            }
        };

        // Reset the state sync manager for the synced commit decision
        self.state_sync_manager.clear_active_commit_sync();

        // Process all the newly ordered blocks
        let all_ordered_blocks = self.observer_block_data.lock().get_all_ordered_blocks();
        for (_, (observed_ordered_block, commit_decision)) in all_ordered_blocks {
            // Finalize the ordered block
            let ordered_block = observed_ordered_block.consume_ordered_block();
            self.finalize_ordered_block(ordered_block).await;

            // If a commit decision is available, forward it to the execution pipeline
            if let Some(commit_decision) = commit_decision {
                self.forward_commit_decision(commit_decision.clone());
            }
        }
    }
```

**File:** consensus/src/consensus_observer/observer/block_data.rs (L231-235)
```rust
    /// Inserts the observed ordered block into the ordered blocks
    pub fn insert_ordered_block(&mut self, observed_ordered_block: ObservedOrderedBlock) {
        self.ordered_block_store
            .insert_ordered_block(observed_ordered_block);
    }
```

**File:** consensus/src/consensus_observer/observer/block_data.rs (L323-333)
```rust
/// Creates and returns a commit callback. This will update the
/// root ledger info and remove the blocks from the given stores.
pub fn create_commit_callback(
    observer_block_data: Arc<Mutex<ObserverBlockData>>,
) -> Box<dyn FnOnce(WrappedLedgerInfo, LedgerInfoWithSignatures) + Send + Sync> {
    Box::new(move |_, ledger_info: LedgerInfoWithSignatures| {
        observer_block_data
            .lock()
            .handle_committed_blocks(ledger_info);
    })
}
```

**File:** consensus/src/consensus_observer/observer/ordered_blocks.rs (L76-108)
```rust
    pub fn insert_ordered_block(&mut self, observed_ordered_block: ObservedOrderedBlock) {
        // Verify that the number of ordered blocks doesn't exceed the maximum
        let max_num_ordered_blocks = self.consensus_observer_config.max_num_pending_blocks as usize;
        if self.ordered_blocks.len() >= max_num_ordered_blocks {
            warn!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Exceeded the maximum number of ordered blocks: {:?}. Dropping block: {:?}.",
                    max_num_ordered_blocks,
                    observed_ordered_block.ordered_block().proof_block_info()
                ))
            );
            return; // Drop the block if we've exceeded the maximum
        }

        // Otherwise, we can add the block to the ordered blocks
        debug!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Adding ordered block to the ordered blocks: {:?}",
                observed_ordered_block.ordered_block().proof_block_info()
            ))
        );

        // Get the epoch and round of the last ordered block
        let last_block = observed_ordered_block.ordered_block().last_block();
        let last_block_epoch = last_block.epoch();
        let last_block_round = last_block.round();

        // Insert the ordered block
        self.ordered_blocks.insert(
            (last_block_epoch, last_block_round),
            (observed_ordered_block, None),
        );
    }
```

**File:** consensus/src/pipeline/execution_client.rs (L590-624)
```rust
    async fn finalize_order(
        &self,
        blocks: Vec<Arc<PipelinedBlock>>,
        ordered_proof: WrappedLedgerInfo,
    ) -> ExecutorResult<()> {
        assert!(!blocks.is_empty());
        let mut execute_tx = match self.handle.read().execute_tx.clone() {
            Some(tx) => tx,
            None => {
                debug!("Failed to send to buffer manager, maybe epoch ends");
                return Ok(());
            },
        };

        for block in &blocks {
            block.set_insertion_time();
            if let Some(tx) = block.pipeline_tx().lock().as_mut() {
                tx.order_proof_tx
                    .take()
                    .map(|tx| tx.send(ordered_proof.clone()));
            }
        }

        if execute_tx
            .send(OrderedBlocks {
                ordered_blocks: blocks,
                ordered_proof: ordered_proof.ledger_info().clone(),
            })
            .await
            .is_err()
        {
            debug!("Failed to send to buffer manager, maybe epoch ends");
        }
        Ok(())
    }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L380-424)
```rust
    /// process incoming ordered blocks
    /// push them into the buffer and update the roots if they are none.
    async fn process_ordered_blocks(&mut self, ordered_blocks: OrderedBlocks) {
        let OrderedBlocks {
            ordered_blocks,
            ordered_proof,
        } = ordered_blocks;

        info!(
            "Receive {} ordered block ends with [epoch: {}, round: {}, id: {}], the queue size is {}",
            ordered_blocks.len(),
            ordered_proof.commit_info().epoch(),
            ordered_proof.commit_info().round(),
            ordered_proof.commit_info().id(),
            self.buffer.len() + 1,
        );

        let request = self.create_new_request(ExecutionRequest {
            ordered_blocks: ordered_blocks.clone(),
        });
        if let Some(consensus_publisher) = &self.consensus_publisher {
            let message = ConsensusObserverMessage::new_ordered_block_message(
                ordered_blocks.clone(),
                ordered_proof.clone(),
            );
            consensus_publisher.publish_message(message);
        }
        self.execution_schedule_phase_tx
            .send(request)
            .await
            .expect("Failed to send execution schedule request");

        let mut unverified_votes = HashMap::new();
        if let Some(block) = ordered_blocks.last() {
            if let Some(votes) = self.pending_commit_votes.remove(&block.round()) {
                for (_, vote) in votes {
                    if vote.commit_info().id() == block.id() {
                        unverified_votes.insert(vote.author(), vote);
                    }
                }
            }
        }
        let item = BufferItem::new_ordered(ordered_blocks, ordered_proof, unverified_votes);
        self.buffer.push_back(item);
    }
```

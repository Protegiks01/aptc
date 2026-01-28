> Searching codebase... [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** consensus/src/payload_manager/co_payload_manager.rs (L29-76)
```rust
async fn get_transactions_for_observer(
    block: &Block,
    block_payloads: &Arc<Mutex<BTreeMap<(u64, Round), BlockPayloadStatus>>>,
    consensus_publisher: &Option<Arc<ConsensusPublisher>>,
) -> ExecutorResult<(Vec<SignedTransaction>, Option<u64>, Option<u64>)> {
    // The data should already be available (as consensus observer will only ever
    // forward a block to the executor once the data has been received and verified).
    let block_payload = match block_payloads.lock().entry((block.epoch(), block.round())) {
        Entry::Occupied(mut value) => match value.get_mut() {
            BlockPayloadStatus::AvailableAndVerified(block_payload) => block_payload.clone(),
            BlockPayloadStatus::AvailableAndUnverified(_) => {
                // This shouldn't happen (the payload should already be verified)
                let error = format!(
                    "Payload data for block epoch {}, round {} is unverified!",
                    block.epoch(),
                    block.round()
                );
                return Err(InternalError { error });
            },
        },
        Entry::Vacant(_) => {
            // This shouldn't happen (the payload should already be present)
            let error = format!(
                "Missing payload data for block epoch {}, round {}!",
                block.epoch(),
                block.round()
            );
            return Err(InternalError { error });
        },
    };

    // If the payload is valid, publish it to any downstream observers
    let transaction_payload = block_payload.transaction_payload();
    if let Some(consensus_publisher) = consensus_publisher {
        let message = ConsensusObserverMessage::new_block_payload_message(
            block.gen_block_info(HashValue::zero(), 0, None),
            transaction_payload.clone(),
        );
        consensus_publisher.publish_message(message);
    }

    // Return the transactions and the transaction limit
    Ok((
        transaction_payload.transactions(),
        transaction_payload.transaction_limit(),
        transaction_payload.gas_limit(),
    ))
}
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L613-648)
```rust
    /// Precondition: Block is inserted into block tree (all ancestors are available)
    /// What it does: Wait for all data becomes available and verify transaction signatures
    async fn materialize(
        preparer: Arc<BlockPreparer>,
        block: Arc<Block>,
        qc_rx: oneshot::Receiver<Arc<QuorumCert>>,
    ) -> TaskResult<MaterializeResult> {
        let mut tracker = Tracker::start_waiting("materialize", &block);
        tracker.start_working();

        let qc_rx = async {
            match qc_rx.await {
                Ok(qc) => Some(qc),
                Err(_) => {
                    warn!("[BlockPreparer] qc tx cancelled for block {}", block.id());
                    None
                },
            }
        }
        .shared();
        // the loop can only be abort by the caller
        let result = loop {
            match preparer.materialize_block(&block, qc_rx.clone()).await {
                Ok(input_txns) => break input_txns,
                Err(e) => {
                    warn!(
                        "[BlockPreparer] failed to prepare block {}, retrying: {}",
                        block.id(),
                        e
                    );
                    tokio::time::sleep(Duration::from_millis(100)).await;
                },
            }
        };
        Ok(result)
    }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L700-714)
```rust
            message_received_time,
            observed_ordered_block,
        );

        // If all payloads exist, process the block. Otherwise, store it
        // in the pending block store and wait for the payloads to arrive.
        if self.all_payloads_exist(pending_block_with_metadata.ordered_block().blocks()) {
            self.process_ordered_block(pending_block_with_metadata)
                .await;
        } else {
            self.observer_block_data
                .lock()
                .insert_pending_block(pending_block_with_metadata);
        }
    }
```

**File:** consensus/src/consensus_observer/observer/block_data.rs (L182-219)
```rust
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

**File:** consensus/src/consensus_observer/observer/payload_store.rs (L112-119)
```rust
    pub fn remove_blocks_for_epoch_round(&self, epoch: u64, round: Round) {
        // Determine the round to split off
        let split_off_round = round.saturating_add(1);

        // Remove the blocks from the payload store
        let mut block_payloads = self.block_payloads.lock();
        *block_payloads = block_payloads.split_off(&(epoch, split_off_round));
    }
```

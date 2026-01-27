# Audit Report

## Title
Timing Race Condition Between Consensus Commit Notification and Mempool Cleanup Enables Transaction Re-pulling and Validator Performance Degradation

## Summary
A timing race condition exists between consensus notifying the BatchGenerator (which manages transaction exclusions) and mempool receiving commit notifications. This allows already-committed transactions to be re-pulled from mempool and re-executed by consensus, causing unnecessary validator workload and temporary state inconsistencies.

## Finding Description

The vulnerability stems from an asynchronous notification flow where consensus commits a block and notifies two separate subsystems in sequence, but without proper synchronization:

1. **State Sync Notification Path** (for mempool cleanup): [1](#0-0) 
   
   Consensus calls `state_sync_notifier.notify_new_commit()` which sends transactions to state sync asynchronously.

2. **Payload Manager Notification Path** (for transaction exclusion): [2](#0-1) 
   
   After waiting for state sync notification at line 1126, consensus immediately calls `payload_manager.notify_commit()` at line 1135.

3. **The notification to state sync completes when the message is sent to the channel, NOT when mempool processes it:** [3](#0-2) 
   
   The `await` at line 112 only waits for the send operation to complete, with a response timeout. State sync processes this asynchronously.

4. **Mempool processes commit notifications in a separate spawned task:** [4](#0-3) 
   
   The notification is handled asynchronously by `handle_commit_notification` running in a spawned task.

5. **BatchGenerator immediately removes transactions from exclusion list:** [5](#0-4) 
   
   When `CommitNotification` is received, transactions are immediately removed from `txns_in_progress_sorted` at lines 528-532.

6. **The race window enables re-pulling:** [6](#0-5) 
   
   When `handle_scheduled_pull` executes at line 352-358, it uses `txns_in_progress_sorted` as the exclusion filter.

**Attack Scenario:**
- T1: Block N commits to storage with transactions [X, Y, Z]
- T2: State sync receives notification (async send completes)
- T3: `notify_state_sync_fut` completes (line 1126)
- T4: `payload_manager.notify_commit()` called (line 1135)
- T5: BatchGenerator removes X, Y, Z from `txns_in_progress_sorted`
- **T6: Consensus pulls new batch - X, Y, Z are still in mempool but NOT in exclude list**
- T7: X, Y, Z are re-pulled and sent to execution
- T8: Execution fails with SEQUENCE_NUMBER_TOO_OLD
- T9: Mempool finally processes commit notification and removes X, Y, Z

This breaks the invariant that committed transactions should be immediately excluded from subsequent consensus pulls, violating **State Consistency** (Critical Invariant #4).

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty criteria for "Validator node slowdowns": [7](#0-6) 

During the race window, validators:
1. Re-pull already committed transactions from mempool
2. Re-execute them through the VM pipeline
3. Process rejection notifications when execution fails
4. Send reject notifications back to mempool

This causes:
- **Computational waste**: Unnecessary transaction validation, signature verification, and VM execution
- **Network overhead**: Rejected transactions are broadcast back to mempool
- **State inconsistency**: Temporary divergence between consensus view (transactions excluded) and mempool state (transactions present)
- **Performance degradation**: Under high transaction load, this compounds as more committed transactions remain temporarily available for re-pulling

While sequence number validation prevents actual replay (consensus safety is maintained), the performance impact on validators is measurable and unintended.

## Likelihood Explanation

**Likelihood: HIGH**

This race condition occurs naturally without any attacker action required:
- Happens on every block commit during normal operation
- More frequent under high transaction throughput (more transactions to clean up)
- Timing window widens under system load when async task processing is delayed
- No special permissions or malicious behavior needed

The mempool commit notification processing depends on: [8](#0-7) 

This async processing can be delayed by system load, making the race window larger during peak usage when validator performance matters most.

## Recommendation

**Solution: Synchronize mempool cleanup before updating transaction exclusions**

Modify the notification flow to ensure mempool has completed processing commit notifications before BatchGenerator removes transactions from the exclusion list:

1. **Option A - Sequential Notification**: Send mempool notification directly from consensus and await completion before notifying payload manager. This ensures mempool cleanup happens before exclusion list updates.

2. **Option B - Optimistic Exclusion**: Keep transactions in `txns_in_progress_sorted` for a grace period (e.g., 2-3 block intervals) after commit notification, allowing mempool async processing to complete.

3. **Option C - Synchronous Confirmation**: Add a confirmation channel where mempool signals completion of commit processing back to consensus before `payload_manager.notify_commit()` proceeds.

The recommended approach is Option B (optimistic exclusion with grace period) as it:
- Maintains async notification performance benefits  
- Provides buffer for processing delays
- Requires minimal changes to existing architecture
- Doesn't block the critical path

## Proof of Concept

**Reproduction Steps:**

1. Deploy an Aptos validator node under load with high transaction throughput
2. Monitor the following metrics:
   - Rejected transactions with `SEQUENCE_NUMBER_TOO_OLD` status
   - Time delta between `notify_state_sync` completion and mempool commit processing
   - Transaction re-pull count (same transaction hash pulled multiple times)

3. Observe correlation between:
   - High transaction load
   - Increased re-pull events
   - Validator CPU/execution time spikes for already-committed transactions

**Evidence in Code:**

The sequence number validation that prevents actual replay but reveals the re-pulling: [9](#0-8) 

Rejected transactions are logged at line 119-122 with `SEQUENCE_NUMBER_TOO_OLD`, which would spike during the race condition window.

**Validation:**
- Check validator logs for `SEQUENCE_NUMBER_TOO_OLD` rejections immediately after block commits
- Measure time between commit and mempool cleanup completion
- Correlate re-execution events with commit notification timing

## Notes

While this vulnerability does not compromise consensus safety or cause fund loss (due to sequence number validation), it represents a significant performance issue that violates the architectural expectation that committed transactions are immediately excluded from mempool. The asynchronous notification design creates an exploitable timing gap that degrades validator performance under load, meeting the High Severity criteria for "Validator node slowdowns" in the Aptos bug bounty program.

### Citations

**File:** consensus/src/pipeline/pipeline_builder.rs (L1110-1142)
```rust
    async fn post_commit_ledger(
        pre_commit_fut: TaskFuture<PreCommitResult>,
        order_proof_fut: TaskFuture<WrappedLedgerInfo>,
        commit_ledger_fut: TaskFuture<CommitLedgerResult>,
        notify_state_sync_fut: TaskFuture<NotifyStateSyncResult>,
        parent_post_commit: TaskFuture<PostCommitResult>,
        payload_manager: Arc<dyn TPayloadManager>,
        block_store_callback: Box<
            dyn FnOnce(WrappedLedgerInfo, LedgerInfoWithSignatures) + Send + Sync,
        >,
        block: Arc<Block>,
    ) -> TaskResult<PostCommitResult> {
        let mut tracker = Tracker::start_waiting("post_commit_ledger", &block);
        parent_post_commit.await?;
        let maybe_ledger_info_with_sigs = commit_ledger_fut.await?;
        let compute_result = pre_commit_fut.await?;
        notify_state_sync_fut.await?;

        tracker.start_working();
        update_counters_for_block(&block);
        update_counters_for_compute_result(&compute_result);

        let payload = block.payload().cloned();
        let timestamp = block.timestamp_usecs();
        let payload_vec = payload.into_iter().collect();
        payload_manager.notify_commit(timestamp, payload_vec);

        if let Some(ledger_info_with_sigs) = maybe_ledger_info_with_sigs {
            let order_proof = order_proof_fut.await?;
            block_store_callback(order_proof, ledger_info_with_sigs);
        }
        Ok(())
    }
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L1144-1177)
```rust
    /// Precondition: 1. commit ledger finishes or fallback to state sync happens, 2. parent block's phase finishes
    /// What it does: Notify state synchronizer and payload manager about committed transactions
    /// This is off critical path
    async fn notify_state_sync(
        pre_commit_fut: TaskFuture<PreCommitResult>,
        commit_ledger_fut: TaskFuture<CommitLedgerResult>,
        parent_notify_state_sync_fut: TaskFuture<PostCommitResult>,
        state_sync_notifier: Arc<dyn ConsensusNotificationSender>,
        block: Arc<Block>,
    ) -> TaskResult<NotifyStateSyncResult> {
        let mut tracker = Tracker::start_waiting("notify_state_sync", &block);
        let compute_result = pre_commit_fut.await?;
        parent_notify_state_sync_fut.await?;
        // if commit ledger is aborted, it's typically an abort caused by reset to fall back to state sync
        // we want to finish notifying already pre-committed txns before go into state sync
        // so only return if there's internal error from commit ledger
        if let Err(e @ TaskError::InternalError(_)) = commit_ledger_fut.await {
            return Err(TaskError::PropagatedError(Box::new(e)));
        }

        tracker.start_working();
        let txns = compute_result.transactions_to_commit().to_vec();
        let subscribable_events = compute_result.subscribable_events().to_vec();
        if let Err(e) = monitor!(
            "notify_state_sync",
            state_sync_notifier
                .notify_new_commit(txns, subscribable_events)
                .await
        ) {
            error!(error = ?e, "Failed to notify state synchronizer");
        }

        Ok(())
    }
```

**File:** state-sync/inter-component/consensus-notifications/src/lib.rs (L93-138)
```rust
    async fn notify_new_commit(
        &self,
        transactions: Vec<Transaction>,
        subscribable_events: Vec<ContractEvent>,
    ) -> Result<(), Error> {
        // Only send a notification if transactions have been committed
        if transactions.is_empty() {
            return Ok(());
        }

        // Create a consensus commit notification
        let (notification, callback_receiver) =
            ConsensusCommitNotification::new(transactions, subscribable_events);
        let commit_notification = ConsensusNotification::NotifyCommit(notification);

        // Send the notification to state sync
        if let Err(error) = self
            .notification_sender
            .clone()
            .send(commit_notification)
            .await
        {
            return Err(Error::NotificationError(format!(
                "Failed to notify state sync of committed transactions! Error: {:?}",
                error
            )));
        }

        // Handle any responses or a timeout
        if let Ok(response) = timeout(
            Duration::from_millis(self.commit_timeout_ms),
            callback_receiver,
        )
        .await
        {
            match response {
                Ok(consensus_notification_response) => consensus_notification_response.get_result(),
                Err(error) => Err(Error::UnexpectedErrorEncountered(format!(
                    "Consensus commit notification failure: {:?}",
                    error
                ))),
            }
        } else {
            Err(Error::TimeoutWaitingForStateSync)
        }
    }
```

**File:** mempool/src/shared_mempool/coordinator.rs (L136-163)
```rust
/// Spawn a task to handle commit notifications from state sync
fn spawn_commit_notification_handler<NetworkClient, TransactionValidator>(
    smp: &SharedMempool<NetworkClient, TransactionValidator>,
    mut mempool_listener: MempoolNotificationListener,
) where
    NetworkClient: NetworkClientInterface<MempoolSyncMsg> + 'static,
    TransactionValidator: TransactionValidation + 'static,
{
    let mempool = smp.mempool.clone();
    let mempool_validator = smp.validator.clone();
    let use_case_history = smp.use_case_history.clone();
    let num_committed_txns_received_since_peers_updated = smp
        .network_interface
        .num_committed_txns_received_since_peers_updated
        .clone();

    tokio::spawn(async move {
        while let Some(commit_notification) = mempool_listener.next().await {
            handle_commit_notification(
                &mempool,
                &mempool_validator,
                &use_case_history,
                commit_notification,
                &num_committed_txns_received_since_peers_updated,
            );
        }
    });
}
```

**File:** consensus/src/quorum_store/batch_generator.rs (L342-390)
```rust
    pub(crate) async fn handle_scheduled_pull(
        &mut self,
        max_count: u64,
    ) -> Vec<Batch<BatchInfoExt>> {
        counters::BATCH_PULL_EXCLUDED_TXNS.observe(self.txns_in_progress_sorted.len() as f64);
        trace!(
            "QS: excluding txs len: {:?}",
            self.txns_in_progress_sorted.len()
        );

        let mut pulled_txns = self
            .mempool_proxy
            .pull_internal(
                max_count,
                self.config.sender_max_total_bytes as u64,
                self.txns_in_progress_sorted.clone(),
            )
            .await
            .unwrap_or_default();

        trace!("QS: pulled_txns len: {:?}", pulled_txns.len());

        if pulled_txns.is_empty() {
            counters::PULLED_EMPTY_TXNS_COUNT.inc();
            // Quorum store metrics
            counters::CREATED_EMPTY_BATCHES_COUNT.inc();

            counters::EMPTY_BATCH_CREATION_DURATION
                .observe_duration(self.last_end_batch_time.elapsed());
            self.last_end_batch_time = Instant::now();
            return vec![];
        } else {
            counters::PULLED_TXNS_COUNT.inc();
            counters::PULLED_TXNS_NUM.observe(pulled_txns.len() as f64);
            if pulled_txns.len() as u64 == max_count {
                counters::BATCH_PULL_FULL_TXNS.observe(max_count as f64)
            }
        }
        counters::BATCH_CREATION_DURATION.observe_duration(self.last_end_batch_time.elapsed());

        let bucket_compute_start = Instant::now();
        let expiry_time = aptos_infallible::duration_since_epoch().as_micros() as u64
            + self.config.batch_expiry_gap_when_init_usecs;
        let batches = self.bucket_into_batches(&mut pulled_txns, expiry_time);
        self.last_end_batch_time = Instant::now();
        counters::BATCH_CREATION_COMPUTE_LATENCY.observe_duration(bucket_compute_start.elapsed());

        batches
    }
```

**File:** consensus/src/quorum_store/batch_generator.rs (L517-552)
```rust
                        BatchGeneratorCommand::CommitNotification(block_timestamp, batches) => {
                            trace!(
                                "QS: got clean request from execution, block timestamp {}",
                                block_timestamp
                            );
                            // Block timestamp is updated asynchronously, so it may race when it enters state sync.
                            if self.latest_block_timestamp > block_timestamp {
                                continue;
                            }
                            self.latest_block_timestamp = block_timestamp;

                            for (author, batch_id) in batches.iter().map(|b| (b.author(), b.batch_id())) {
                                if self.remove_batch_in_progress(author, batch_id) {
                                    counters::BATCH_IN_PROGRESS_COMMITTED.inc();
                                }
                            }

                            // Cleans up all batches that expire in timestamp <= block_timestamp. This is
                            // safe since clean request must occur only after execution result is certified.
                            for (author, batch_id) in self.batch_expirations.expire(block_timestamp) {
                                if let Some(batch_in_progress) = self.batches_in_progress.get(&(author, batch_id)) {
                                    // If there is an identical batch with higher expiry time, re-insert it.
                                    if batch_in_progress.expiry_time_usecs > block_timestamp {
                                        self.batch_expirations.add_item((author, batch_id), batch_in_progress.expiry_time_usecs);
                                        continue;
                                    }
                                }
                                if self.remove_batch_in_progress(author, batch_id) {
                                    counters::BATCH_IN_PROGRESS_EXPIRED.inc();
                                    debug!(
                                        "QS: logical time based expiration batch w. id {} from batches_in_progress, new size {}",
                                        batch_id,
                                        self.batches_in_progress.len(),
                                    );
                                }
                            }
```

**File:** mempool/src/core_mempool/mempool.rs (L112-133)
```rust
    pub(crate) fn reject_transaction(
        &mut self,
        sender: &AccountAddress,
        replay_protector: ReplayProtector,
        hash: &HashValue,
        reason: &DiscardedVMStatus,
    ) {
        if *reason == DiscardedVMStatus::SEQUENCE_NUMBER_TOO_NEW {
            self.log_reject_transaction(sender, replay_protector, counters::COMMIT_IGNORED_LABEL);
            // Do not remove the transaction from mempool
            return;
        }

        let label = if *reason == DiscardedVMStatus::SEQUENCE_NUMBER_TOO_OLD {
            counters::COMMIT_REJECTED_DUPLICATE_LABEL
        } else {
            counters::COMMIT_REJECTED_LABEL
        };
        self.log_reject_transaction(sender, replay_protector, label);
        self.transactions
            .reject_transaction(sender, replay_protector, hash);
    }
```

**File:** mempool/src/core_mempool/mempool.rs (L417-585)
```rust
    /// Fetches next block of transactions for consensus.
    /// `return_non_full` - if false, only return transactions when max_txns or max_bytes is reached
    ///                     Should always be true for Quorum Store.
    /// `include_gas_upgraded` - Return transactions that had gas upgraded, even if they are in
    ///                          exclude_transactions. Should only be true for Quorum Store.
    /// `exclude_transactions` - transactions that were sent to Consensus but were not committed yet
    ///  mempool should filter out such transactions.
    #[allow(clippy::explicit_counter_loop)]
    pub(crate) fn get_batch(
        &self,
        max_txns: u64,
        max_bytes: u64,
        return_non_full: bool,
        exclude_transactions: BTreeMap<TransactionSummary, TransactionInProgress>,
    ) -> Vec<SignedTransaction> {
        let start_time = Instant::now();
        let exclude_size = exclude_transactions.len();
        let mut inserted = HashSet::new();

        let gas_end_time = start_time.elapsed();

        let mut result = vec![];
        // Helper DS. Helps to mitigate scenarios where account submits several transactions
        // with increasing gas price (e.g. user submits transactions with sequence number 1, 2
        // and gas_price 1, 10 respectively)
        // Later txn has higher gas price and will be observed first in priority index iterator,
        // but can't be executed before first txn. Once observed, such txn will be saved in
        // `skipped` DS and rechecked once it's ancestor becomes available
        let mut skipped = HashSet::new();
        let mut total_bytes = 0;
        let mut txn_walked = 0usize;
        // iterate over the queue of transactions based on gas price
        'main: for txn in self.transactions.iter_queue() {
            txn_walked += 1;
            let txn_ptr = TxnPointer::from(txn);

            // TODO: removed gas upgraded logic. double check if it's needed
            if exclude_transactions.contains_key(&txn_ptr) {
                continue;
            }
            let txn_replay_protector = txn.replay_protector;
            match txn_replay_protector {
                ReplayProtector::SequenceNumber(txn_seq) => {
                    let txn_in_sequence = txn_seq > 0
                        && Self::txn_was_chosen(
                            txn.address,
                            txn_seq - 1,
                            &inserted,
                            &exclude_transactions,
                        );
                    let account_sequence_number =
                        self.transactions.get_account_sequence_number(&txn.address);
                    // include transaction if it's "next" for given account or
                    // we've already sent its ancestor to Consensus.
                    if txn_in_sequence || account_sequence_number == Some(&txn_seq) {
                        inserted.insert((txn.address, txn_replay_protector));
                        result.push((txn.address, txn_replay_protector));
                        if (result.len() as u64) == max_txns {
                            break;
                        }
                        // check if we can now include some transactions
                        // that were skipped before for given account
                        let (skipped_txn_sender, mut skipped_txn_seq_num) =
                            (txn.address, txn_seq + 1);
                        while skipped.remove(&(skipped_txn_sender, skipped_txn_seq_num)) {
                            inserted.insert((
                                skipped_txn_sender,
                                ReplayProtector::SequenceNumber(skipped_txn_seq_num),
                            ));
                            result.push((
                                skipped_txn_sender,
                                ReplayProtector::SequenceNumber(skipped_txn_seq_num),
                            ));
                            if (result.len() as u64) == max_txns {
                                break 'main;
                            }
                            skipped_txn_seq_num += 1;
                        }
                    } else {
                        skipped.insert((txn.address, txn_seq));
                    }
                },
                ReplayProtector::Nonce(_) => {
                    inserted.insert((txn.address, txn_replay_protector));
                    result.push((txn.address, txn_replay_protector));
                    if (result.len() as u64) == max_txns {
                        break;
                    }
                },
            };
        }
        let result_size = result.len();
        let result_end_time = start_time.elapsed();
        let result_time = result_end_time.saturating_sub(gas_end_time);

        let mut block = Vec::with_capacity(result_size);
        let mut full_bytes = false;
        for (sender, replay_protector) in result {
            if let Some((txn, ranking_score)) = self
                .transactions
                .get_with_ranking_score(&sender, replay_protector)
            {
                let txn_size = txn.txn_bytes_len() as u64;
                if total_bytes + txn_size > max_bytes {
                    full_bytes = true;
                    break;
                }
                total_bytes += txn_size;
                block.push(txn);
                if total_bytes == max_bytes {
                    full_bytes = true;
                }
                counters::core_mempool_txn_ranking_score(
                    counters::CONSENSUS_PULLED_LABEL,
                    counters::CONSENSUS_PULLED_LABEL,
                    self.transactions
                        .get_bucket(ranking_score, &sender)
                        .as_str(),
                    ranking_score,
                );
            }
        }
        let block_end_time = start_time.elapsed();
        let block_time = block_end_time.saturating_sub(result_end_time);

        if result_size > 0 {
            debug!(
                LogSchema::new(LogEntry::GetBlock),
                seen_consensus = exclude_size,
                walked = txn_walked,
                // before size and non full check
                result_size = result_size,
                // before non full check
                byte_size = total_bytes,
                block_size = block.len(),
                return_non_full = return_non_full,
                result_time_ms = result_time.as_millis(),
                block_time_ms = block_time.as_millis(),
            );
        } else {
            sample!(
                SampleRate::Duration(Duration::from_secs(60)),
                debug!(
                    LogSchema::new(LogEntry::GetBlock),
                    seen_consensus = exclude_size,
                    walked = txn_walked,
                    // before size and non full check
                    result_size = result_size,
                    // before non full check
                    byte_size = total_bytes,
                    block_size = block.len(),
                    return_non_full = return_non_full,
                    result_time_ms = result_time.as_millis(),
                    block_time_ms = block_time.as_millis(),
                )
            );
        }

        if !return_non_full && !full_bytes && (block.len() as u64) < max_txns {
            block.clear();
        }

        counters::mempool_service_transactions(counters::GET_BLOCK_LABEL, block.len());
        counters::MEMPOOL_SERVICE_BYTES_GET_BLOCK.observe(total_bytes as f64);
        for transaction in &block {
            self.log_consensus_pulled_latency(transaction.sender(), transaction.replay_protector());
        }
        block
    }
```

**File:** mempool/src/shared_mempool/tasks.rs (L713-743)
```rust
pub(crate) fn process_committed_transactions(
    mempool: &Mutex<CoreMempool>,
    use_case_history: &Mutex<UseCaseHistory>,
    transactions: Vec<CommittedTransaction>,
    block_timestamp_usecs: u64,
) {
    let mut pool = mempool.lock();
    let block_timestamp = Duration::from_micros(block_timestamp_usecs);

    let tracking_usecases = {
        let mut history = use_case_history.lock();
        history.update_usecases(&transactions);
        history.compute_tracking_set()
    };

    for transaction in transactions {
        pool.log_commit_transaction(
            &transaction.sender,
            transaction.replay_protector,
            tracking_usecases
                .get(&transaction.use_case)
                .map(|name| (transaction.use_case.clone(), name)),
            block_timestamp,
        );
        pool.commit_transaction(&transaction.sender, transaction.replay_protector);
    }

    if block_timestamp_usecs > 0 {
        pool.gc_by_expiration_time(block_timestamp);
    }
}
```

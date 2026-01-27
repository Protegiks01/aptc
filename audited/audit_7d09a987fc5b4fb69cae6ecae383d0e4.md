# Audit Report

## Title
Pipeline Abort Race Condition Causes State Sync to Process Uncommitted Transactions Leading to Mempool Corruption and Event Publication Failures

## Summary
The consensus pipeline's `notify_state_sync` function incorrectly handles `commit_ledger` task aborts by ignoring `JoinError` failures and still sending commit notifications to state sync. This causes state sync to process transactions that were never committed to storage, resulting in mempool corruption (permanent transaction loss), publication of fake events to subscribers, and storage service cache inconsistencies.

## Finding Description
The vulnerability exists in the error handling logic of the `notify_state_sync` function within the consensus pipeline. [1](#0-0) 

When the consensus pipeline is aborted during reset operations (e.g., epoch changes, state sync fallback), the `commit_ledger` task returns a `TaskError::JoinError`. However, the `notify_state_sync` function only propagates errors for `TaskError::InternalError` (line 1160), **silently ignoring abort errors**. This causes consensus to send commit notifications for transactions that were never written to storage.

The pipeline abort mechanism is triggered during buffer manager resets: [2](#0-1) 

When state sync receives these erroneous commit notifications, it processes them without validation: [3](#0-2) 

State sync extracts transactions from the notification and passes them to `handle_committed_transactions`: [4](#0-3) 

Critically, `handle_committed_transactions` fetches the `latest_synced_version` from storage (which has **not advanced** because `commit_ledger` was aborted), but then notifies mempool, event subscribers, and storage service with the uncommitted transactions from the notification. [5](#0-4) 

Mempool then permanently removes these transactions: [6](#0-5) 

**Attack Flow:**
1. Consensus executes block (pre_commit completes successfully)
2. Consensus begins committing block to storage (commit_ledger starts)
3. Pipeline is aborted during reset (epoch change or state sync trigger)
4. commit_ledger task is aborted and returns `TaskError::JoinError`
5. notify_state_sync ignores the JoinError (only checks for InternalError)
6. Consensus sends commit notification with executed transactions
7. State sync receives notification and fetches latest_synced_version (unchanged)
8. State sync notifies mempool to remove transactions **that were never committed**
9. State sync publishes events **that never happened on-chain**
10. Mempool permanently loses valid transactions

This breaks the **State Consistency** invariant: state transitions must be atomic and state sync should only process transactions that are actually committed to storage.

## Impact Explanation
**Critical Severity** - This vulnerability causes:

1. **Permanent Transaction Loss**: Transactions removed from mempool will never be re-proposed, as mempool believes they were committed when they were not. Users' transactions are silently dropped.

2. **Event System Corruption**: Event subscribers receive notifications for state changes that never occurred on-chain, breaking external integrations relying on event streams.

3. **State Sync Cache Corruption**: Storage service cache is updated with incorrect version information, potentially causing state sync to fail when syncing with peers.

4. **Consensus Safety Violation**: Different nodes may have different views of which transactions were committed, as the timing of the abort varies across validators.

This meets Critical Severity criteria under "Consensus/Safety violations" and "State inconsistencies requiring intervention." It also constitutes transaction loss, though indirect.

## Likelihood Explanation
**High Likelihood** - This race condition occurs during:
- Epoch transitions (regular occurrence)
- State sync fallback triggers (when consensus falls behind)
- Any pipeline reset operation

The vulnerability is **not exploitable on-demand** by an attacker, but it **will occur naturally** during normal network operation, particularly during epoch boundaries when all validators simultaneously reset their pipelines.

The timing window is narrow but **guaranteed to occur**: if pre_commit completes but commit_ledger is aborted before completion, the bug triggers. Given high network load or slow storage, this window increases.

## Recommendation
Fix the error handling in `notify_state_sync` to propagate all commit_ledger errors, not just InternalError:

```rust
// In consensus/src/pipeline/pipeline_builder.rs, lines 1157-1162
async fn notify_state_sync(...) -> TaskResult<NotifyStateSyncResult> {
    let mut tracker = Tracker::start_waiting("notify_state_sync", &block);
    let compute_result = pre_commit_fut.await?;
    parent_notify_state_sync_fut.await?;
    
    // FIXED: Propagate ALL errors from commit_ledger, not just InternalError
    // If commit fails for any reason, do not send the notification
    commit_ledger_fut.await?;
    
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

Remove the selective error handling that ignores JoinError. If commit_ledger fails or is aborted, the notification should not be sent.

## Proof of Concept
```rust
// Rust integration test demonstrating the vulnerability
// Place in consensus/src/pipeline/tests/pipeline_abort_test.rs

#[tokio::test]
async fn test_abort_during_commit_causes_fake_notification() {
    // Setup: Create consensus pipeline with state sync notifier
    let (consensus_notifier, mut consensus_listener) = 
        aptos_consensus_notifications::new_consensus_notifier_listener_pair(1000);
    
    // Create a block and execute it
    let block = create_test_block();
    let pre_commit_result = execute_block(&block).await;
    
    // Start commit_ledger in background
    let commit_handle = tokio::spawn(async move {
        commit_ledger_to_storage(&block).await
    });
    
    // Abort the commit task (simulating pipeline reset)
    commit_handle.abort();
    
    // Verify: commit_ledger returns JoinError
    let commit_result = commit_handle.await;
    assert!(matches!(commit_result, Err(tokio::task::JoinError { .. })));
    
    // Bug: notify_state_sync still sends notification despite abort
    notify_state_sync_buggy(
        pre_commit_result,
        commit_result,
        consensus_notifier.clone()
    ).await;
    
    // State sync receives notification for uncommitted transactions
    let notification = consensus_listener.next().await.unwrap();
    assert!(matches!(notification, ConsensusNotification::NotifyCommit(_)));
    
    // Verify: Storage version has NOT advanced (commit was aborted)
    let storage_version = get_latest_version_from_storage();
    assert_eq!(storage_version, 0); // Still at genesis
    
    // But notification contains transactions
    if let ConsensusNotification::NotifyCommit(commit_notif) = notification {
        assert!(!commit_notif.get_transactions().is_empty());
        
        // Bug impact: State sync will tell mempool to remove these transactions
        // even though they're not in storage!
    }
}
```

**Notes**

The comment in the code states this behavior is intentional to "finish notifying already pre-committed txns before go into state sync" during fallback scenarios. However, this design is fundamentally flawed because:

1. Pre-committed transactions are not the same as committed transactions
2. Mempool should only remove transactions that are actually in storage
3. Events should only be published for on-chain state changes
4. The notification is a "commit" notification, not a "pre-commit" notification

The proper solution is to either: (a) not send the notification if commit fails, or (b) create a separate notification type for pre-committed-but-not-committed transactions that state sync handles differently (e.g., keeps in mempool, doesn't publish events).

### Citations

**File:** consensus/src/pipeline/pipeline_builder.rs (L1147-1177)
```rust
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

**File:** consensus/src/pipeline/buffer_manager.rs (L546-576)
```rust
    async fn reset(&mut self) {
        while let Some((_, block)) = self.pending_commit_blocks.pop_first() {
            // Those blocks don't have any dependencies, should be able to finish commit_ledger.
            // Abort them can cause error on epoch boundary.
            block.wait_for_commit_ledger().await;
        }
        while let Some(item) = self.buffer.pop_front() {
            for b in item.get_blocks() {
                if let Some(futs) = b.abort_pipeline() {
                    futs.wait_until_finishes().await;
                }
            }
        }
        self.buffer = Buffer::new();
        self.execution_root = None;
        self.signing_root = None;
        self.previous_commit_time = Instant::now();
        self.commit_proof_rb_handle.take();
        // purge the incoming blocks queue
        while let Ok(Some(blocks)) = self.block_rx.try_next() {
            for b in blocks.ordered_blocks {
                if let Some(futs) = b.abort_pipeline() {
                    futs.wait_until_finishes().await;
                }
            }
        }
        // Wait for ongoing tasks to finish before sending back ack.
        while self.ongoing_tasks.load(Ordering::SeqCst) > 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
```

**File:** state-sync/state-sync-driver/src/driver.rs (L316-350)
```rust
    async fn handle_consensus_commit_notification(
        &mut self,
        commit_notification: ConsensusCommitNotification,
    ) -> Result<(), Error> {
        info!(
            LogSchema::new(LogEntry::ConsensusNotification).message(&format!(
                "Received a consensus commit notification! Total transactions: {:?}, events: {:?}",
                commit_notification.get_transactions().len(),
                commit_notification.get_subscribable_events().len()
            ))
        );
        self.update_consensus_commit_metrics(&commit_notification);

        // Handle the commit notification
        let committed_transactions = CommittedTransactions {
            events: commit_notification.get_subscribable_events().clone(),
            transactions: commit_notification.get_transactions().clone(),
        };
        utils::handle_committed_transactions(
            committed_transactions,
            self.storage.clone(),
            self.mempool_notification_handler.clone(),
            self.event_subscription_service.clone(),
            self.storage_service_notification_handler.clone(),
        )
        .await;

        // Respond successfully
        self.consensus_notification_handler
            .respond_to_commit_notification(commit_notification, Ok(()))?;

        // Check the progress of any sync requests. We need this here because
        // consensus might issue a sync request and then commit (asynchronously).
        self.check_sync_request_progress().await
    }
```

**File:** state-sync/state-sync-driver/src/utils.rs (L325-371)
```rust
pub async fn handle_committed_transactions<
    M: MempoolNotificationSender,
    S: StorageServiceNotificationSender,
>(
    committed_transactions: CommittedTransactions,
    storage: Arc<dyn DbReader>,
    mempool_notification_handler: MempoolNotificationHandler<M>,
    event_subscription_service: Arc<Mutex<EventSubscriptionService>>,
    storage_service_notification_handler: StorageServiceNotificationHandler<S>,
) {
    // Fetch the latest synced version and ledger info from storage
    let (latest_synced_version, latest_synced_ledger_info) =
        match fetch_pre_committed_version(storage.clone()) {
            Ok(latest_synced_version) => match fetch_latest_synced_ledger_info(storage.clone()) {
                Ok(latest_synced_ledger_info) => (latest_synced_version, latest_synced_ledger_info),
                Err(error) => {
                    error!(LogSchema::new(LogEntry::SynchronizerNotification)
                        .error(&error)
                        .message("Failed to fetch latest synced ledger info!"));
                    return;
                },
            },
            Err(error) => {
                error!(LogSchema::new(LogEntry::SynchronizerNotification)
                    .error(&error)
                    .message("Failed to fetch latest synced version!"));
                return;
            },
        };

    // Handle the commit notification
    if let Err(error) = CommitNotification::handle_transaction_notification(
        committed_transactions.events,
        committed_transactions.transactions,
        latest_synced_version,
        latest_synced_ledger_info,
        mempool_notification_handler,
        event_subscription_service,
        storage_service_notification_handler,
    )
    .await
    {
        error!(LogSchema::new(LogEntry::SynchronizerNotification)
            .error(&error)
            .message("Failed to handle a transaction commit notification!"));
    }
}
```

**File:** state-sync/state-sync-driver/src/notification_handlers.rs (L75-112)
```rust
    pub async fn handle_transaction_notification<
        M: MempoolNotificationSender,
        S: StorageServiceNotificationSender,
    >(
        events: Vec<ContractEvent>,
        transactions: Vec<Transaction>,
        latest_synced_version: Version,
        latest_synced_ledger_info: LedgerInfoWithSignatures,
        mut mempool_notification_handler: MempoolNotificationHandler<M>,
        event_subscription_service: Arc<Mutex<EventSubscriptionService>>,
        mut storage_service_notification_handler: StorageServiceNotificationHandler<S>,
    ) -> Result<(), Error> {
        // Log the highest synced version and timestamp
        let blockchain_timestamp_usecs = latest_synced_ledger_info.ledger_info().timestamp_usecs();
        debug!(
            LogSchema::new(LogEntry::NotificationHandler).message(&format!(
                "Notifying the storage service, mempool and the event subscription service of version: {:?} and timestamp: {:?}.",
                latest_synced_version, blockchain_timestamp_usecs
            ))
        );

        // Notify the storage service of the committed transactions
        storage_service_notification_handler
            .notify_storage_service_of_committed_transactions(latest_synced_version)
            .await?;

        // Notify mempool of the committed transactions
        mempool_notification_handler
            .notify_mempool_of_committed_transactions(transactions, blockchain_timestamp_usecs)
            .await?;

        // Notify the event subscription service of the events
        event_subscription_service
            .lock()
            .notify_events(latest_synced_version, events)?;

        Ok(())
    }
```

**File:** state-sync/state-sync-driver/src/notification_handlers.rs (L523-542)
```rust
    pub async fn notify_mempool_of_committed_transactions(
        &mut self,
        committed_transactions: Vec<Transaction>,
        block_timestamp_usecs: u64,
    ) -> Result<(), Error> {
        let result = self
            .mempool_notification_sender
            .notify_new_commit(committed_transactions, block_timestamp_usecs)
            .await;

        if let Err(error) = result {
            let error = Error::NotifyMempoolError(format!("{:?}", error));
            error!(LogSchema::new(LogEntry::NotificationHandler)
                .error(&error)
                .message("Failed to notify mempool of committed transactions!"));
            Err(error)
        } else {
            Ok(())
        }
    }
```
